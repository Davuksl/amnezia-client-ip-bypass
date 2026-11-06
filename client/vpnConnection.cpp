#include "vpnConnection.h"

#include "core/utils/warpBuildConfig.h"
#include "core/utils/warpUnderlay.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QObject>
#include <QScopeGuard>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <utility>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
    #include <QRemoteObjectPendingCallWatcher>
#endif

#ifdef Q_OS_WIN
    #include "core/protocols/xrayProtocol.h"
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

VpnConnection::VpnConnection(SecureServersRepository *serversRepository,
                             SecureAppSettingsRepository *appSettingsRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_checkTimer(this),
      m_underlayTimer(this),
      m_connectionState(Vpn::ConnectionState::Disconnected)
{
    m_underlayTimer.setSingleShot(true);
    m_underlayTimer.setInterval(30000);
    connect(&m_underlayTimer, &QTimer::timeout, this, [this]() {
        if (!m_useWarpUnderlay || m_disconnecting || m_underlayStopping) {
            return;
        }
        retryWarpUnderlay(ErrorCode::ApiConfigTimeoutError);
    });
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    const quint64 generation = m_generation;
    const auto protocol = m_vpnProtocol;
    const auto isCurrent = [this, generation, protocol, state]() {
        return generation == m_generation && protocol == m_vpnProtocol && state == m_connectionState;
    };
    if (state == Vpn::ConnectionState::Connected && !protocol) {
        return;
    }

    const QString defaultServerId = m_serversRepository->defaultServerId();
    DockerContainer container = DockerContainer::None;
    switch (m_serversRepository->serverKind(defaultServerId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        break;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        break;
    }

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        if (!isCurrent()) {
            return;
        }
        switch (state) {
        case Vpn::ConnectionState::Connected: {
            iface->resetIpStack();

            auto flushDns = iface->flushDns();
            if (flushDns.waitForFinished() && flushDns.returnValue())
                qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
            else
                qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";
            if (!isCurrent()) {
                return;
            }

            if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

    #ifdef Q_OS_MACOS
                if (!m_appSettingsRepository->isSitesSplitTunnelingEnabled()
                    || m_appSettingsRepository->routeMode() != amnezia::RouteMode::VpnAllExceptSites) {
                    iface->routeAddList(protocol->vpnGateway(), QStringList() << dns1 << dns2);
                }
    #else
                iface->routeAddList(protocol->vpnGateway(), QStringList() << dns1 << dns2);
    #endif

                if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
                    iface->routeDeleteList(protocol->vpnGateway(), QStringList() << "0.0.0.0");
                    RouteMode routeMode = m_appSettingsRepository->routeMode();
                    if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                        QTimer::singleShot(1000, this, [this, generation, routeMode, gateway = protocol->vpnGateway()]() {
                            if (generation == m_generation && m_connectionState == Vpn::ConnectionState::Connected) {
                                addSitesRoutes(gateway, routeMode);
                            }
                        });
                    } else if (routeMode == amnezia::RouteMode::VpnAllExceptSites) {
                        iface->routeAddList(protocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                        iface->routeAddList(protocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                        if (!m_useWarpUnderlay) {
                            iface->routeAddList(protocol->routeGateway(), QStringList() << remoteAddress());
                        }
    #ifdef Q_OS_MACOS
                        iface->routeAddList(protocol->routeGateway(), QStringList() << dns1 << dns2);
    #endif
                        addSitesRoutes(protocol->routeGateway(), routeMode);
                    }
                }
            }
        } break;
        case Vpn::ConnectionState::Disconnected:
        case Vpn::ConnectionState::Error: {
            auto flushDns = iface->flushDns();
            if (flushDns.waitForFinished() && flushDns.returnValue())
                qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
            else
                qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";
            if (!isCurrent()) {
                return;
            }

            auto clearSavedRoutes = iface->clearSavedRoutes();
            if (clearSavedRoutes.waitForFinished() && clearSavedRoutes.returnValue())
                qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
            else
                qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
        } break;
        default: break;
        }
    });
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }
    const quint64 generation = m_generation;

    QStringList ips;
    QStringList sites;
    const QVariantMap &m = m_appSettingsRepository->vpnSites(mode);
    for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            ips.append(i.key());
        } else {
            const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
            for (const QString &ip : siteIps) {
                if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                    ips.append(ip);
                }
            }
            sites.append(i.key());
        }
    }
    ips.removeDuplicates();

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        if (generation == m_generation && m_connectionState == Vpn::ConnectionState::Connected) {
            iface->routeAddList(gw, ips);
        }
    });
    if (generation != m_generation || m_connectionState != Vpn::ConnectionState::Connected) {
        return;
    }

    auto remainingLookups = QSharedPointer<int>::create(sites.size());
    auto needFlush = QSharedPointer<bool>::create(false);

    // re-resolve domains
    for (const QString &site : sites) {
        const auto &cbResolv = [this, generation, site, gw, mode, ips, remainingLookups,
                                needFlush](const QHostInfo &hostInfo) {
            if (generation != m_generation || m_connectionState != Vpn::ConnectionState::Connected) {
                return;
            }
            QStringList resolvedIps;
            for (const QHostAddress &addr : hostInfo.addresses()) {
                if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
                    resolvedIps.append(addr.toString());
                }
            }
            resolvedIps.removeDuplicates();
            qDebug() << "[SplitTunneling] addSitesRoutes resolved" << site << "->" << resolvedIps;

            QStringList newIps;
            for (const QString &ip : resolvedIps) {
                if (!ips.contains(ip)) {
                    IpcClient::withInterface([this, generation, gw, ip](QSharedPointer<IpcInterfaceReplica> iface) {
                        if (generation == m_generation && m_connectionState == Vpn::ConnectionState::Connected) {
                            iface->routeAddList(gw, QStringList() << ip);
                        }
                    });
                    if (generation != m_generation || m_connectionState != Vpn::ConnectionState::Connected) {
                        return;
                    }
                    newIps.append(ip);
                }
            }

            if (!newIps.isEmpty()) {
                m_appSettingsRepository->addVpnSite(mode, site, newIps);
                *needFlush = true;
            }

            if (--(*remainingLookups) > 0)
                return;

            if (!*needFlush)
                return;

            // Async flush: never waitForFinished() here — that re-enters the event loop and
            // can re-enter this QHostInfo callback until the stack overflows (0xc00000fd).
            IpcClient::withInterface([this, generation](QSharedPointer<IpcInterfaceReplica> iface) {
                if (generation != m_generation || m_connectionState != Vpn::ConnectionState::Connected) {
                    return;
                }
                QRemoteObjectPendingReply<bool> reply = iface->flushDns();
                auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
                QObject::connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                        [](QRemoteObjectPendingCallWatcher *call) {
                            if (call->error() != QRemoteObjectPendingCall::NoError
                                || !call->returnValue().toBool()) {
                                qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                            }
                            call->deleteLater();
                        });
            });
        };
        QHostInfo::lookupHost(site, this, cbResolv);
    }
#endif
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_disconnectError != ErrorCode::NoError) {
        return m_disconnectError;
    }

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

#ifdef AMNEZIA_DESKTOP
    if (m_activeOperations > 0 || m_disconnecting || m_vpnProtocol || m_underlayProtocol) {
        m_pendingConnection = [this, serverId, container, vpnConfiguration]() {
            connectToVpn(serverId, container, vpnConfiguration);
        };
        stopProtocols();
        return;
    }
#endif
    const quint64 generation = ++m_generation;
    m_pendingConnection = { };
    ++m_activeOperations;
    const auto preparation = qScopeGuard([this]() { finishProtocolOperation(); });
    m_disconnectError = ErrorCode::NoError;

    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    if (generation != m_generation) {
        return;
    }
    setConnectionState(Vpn::ConnectionState::Connecting);
    if (generation != m_generation) {
        return;
    }

    m_vpnConfiguration = vpnConfiguration;
    m_container = container;
#ifdef AMNEZIA_BUILD_TESTS
    m_warpUnderlayInterfaceName = vpnConfiguration.value(QStringLiteral("testWarpUnderlayInterfaceName"))
                                          .toString(amnezia::warpUnderlayInterfaceName);
    m_warpUnderlaySocketPath =
            vpnConfiguration.value(QStringLiteral("testWarpUnderlaySocketPath")).toString(amnezia::warpUnderlaySocketPath);
#endif
    m_useWarpUnderlay = false;
    m_mainProtocolStarted = false;

#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig();
#endif

    appendSplitTunnelingConfig();

#if defined(Q_OS_WIN) || defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    m_vpnConfiguration.remove(configKey::underlayEndpoint);
    m_vpnConfiguration.remove(configKey::underlayAddress);
    m_vpnConfiguration.remove(configKey::underlayServerAddress);
    m_vpnConfiguration.remove(configKey::underlayInterface);
    m_vpnConfiguration.remove(configKey::warpUnderlay);
    bool warpUnderlaySupported = WarpUnderlay::supportsProtocol(container)
            && !build_config::warpRegistrationEndpoints.trimmed().isEmpty()
            && !build_config::warpAwgInitPacket.trimmed().isEmpty();
    #ifdef AMNEZIA_BUILD_TESTS
    warpUnderlaySupported |= m_vpnConfiguration.value(QStringLiteral("forceWarpAvailable")).toBool();
    const bool forceWarpUnderlay = m_vpnConfiguration.value(QStringLiteral("forceWarpUnderlay")).toBool();
    #else
    const bool forceWarpUnderlay = false;
    #endif
    const bool warpUnderlayEnabled =
            warpUnderlaySupported && (forceWarpUnderlay || m_appSettingsRepository->isIpBlockBypassEnabled());
    bool directServerReachable = !warpUnderlayEnabled;
    if (warpUnderlaySupported && !forceWarpUnderlay) {
    #ifdef Q_OS_WIN
        const bool directRangeAlreadyAllowed = IpcClient::withInterface(
                [this](QSharedPointer<IpcInterfaceReplica> iface) {
                    auto reply = iface->isKillSwitchAllowedRange(m_remoteAddress);
                    return reply.waitForFinished(1000) && reply.returnValue();
                },
                []() { return false; });
        if (!directRangeAlreadyAllowed) {
            const bool directRangeAdded = IpcClient::withInterface(
                    [this](QSharedPointer<IpcInterfaceReplica> iface) {
                        auto reply = iface->addKillSwitchAllowedRange(QStringList { m_remoteAddress });
                        return reply.waitForFinished(1000) && reply.returnValue();
                    },
                    []() { return false; });
            if (directRangeAdded) {
                m_directServerAllowedRange = m_remoteAddress;
            }
        }
    #endif
        const bool isXrayTransport = container == DockerContainer::Xray || container == DockerContainer::SSXray;
        if (warpUnderlayEnabled && isXrayTransport) {
            QJsonObject xrayConfiguration =
                    m_vpnConfiguration.value(ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
            if (xrayConfiguration.isEmpty()) {
                xrayConfiguration =
                        m_vpnConfiguration.value(ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
            }
            const QJsonObject nativeConfig =
                    QJsonDocument::fromJson(xrayConfiguration.value(configKey::config).toString().toUtf8()).object();
            directServerReachable = WarpUnderlay::isXrayServerReachableDirectly(
                    nativeConfig, m_vpnConfiguration.value(configKey::hostName).toString(), m_remoteAddress,
                    [this, generation]() { return generation != m_generation; });
        }
        if (generation != m_generation) {
    #ifdef Q_OS_WIN
            clearDirectServerAllowedRange();
    #endif
            return;
        }
    #ifdef Q_OS_WIN
        if (!directServerReachable && !clearDirectServerAllowedRange()) {
            stopProtocols(ErrorCode::AmneziaServiceConnectionFailed);
            return;
        }
    #endif
    }
    const bool useWarpUnderlay = warpUnderlayEnabled && !directServerReachable;
    #ifdef Q_OS_WIN
    m_useWarpUnderlay = useWarpUnderlay;
    #endif
    if (useWarpUnderlay) {
        const bool prepared = prepareWarpUnderlay(generation);
        if (generation != m_generation) {
            return;
        }
    #ifdef Q_OS_WIN
        if (container == DockerContainer::WireGuard || container == DockerContainer::Awg
            || container == DockerContainer::Awg2) {
            m_vpnConfiguration.insert(QStringLiteral("hopType"), QStringLiteral("MultiHopExit"));
        }
    #endif
        if (!prepared) {
            qCritical() << "Failed to prepare the WARP underlay";
    #ifdef AMNEZIA_DESKTOP
            stopProtocols(ErrorCode::ApiConfigDownloadError);
    #else
            setConnectionState(Vpn::ConnectionState::Error);
            emit vpnProtocolError(ErrorCode::ApiConfigDownloadError);
    #endif
            return;
        }
    }
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    const QSharedPointer<VpnProtocol> createdProtocol(VpnProtocol::factory(container, m_vpnConfiguration),
                                                      &QObject::deleteLater);
    if (generation != m_generation) {
        if (createdProtocol) {
            createdProtocol->stop();
        }
        return;
    }
    m_vpnProtocol = createdProtocol;
    if (!m_vpnProtocol) {
        stopProtocols(ErrorCode::InternalError);
        return;
    }
    createProtocolConnections();
    if (generation != m_generation || !m_vpnProtocol) {
        return;
    }
    const auto protocol = m_vpnProtocol;
    const ErrorCode preparationError = protocol->prepare();
    if (generation != m_generation || protocol != m_vpnProtocol) {
        return;
    }
    if (preparationError != ErrorCode::NoError) {
        stopProtocols(preparationError);
        return;
    }
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
    createProtocolConnections();
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    if (generation != m_generation) {
        return;
    }

    if (m_useWarpUnderlay) {
        startWarpUnderlay();
    } else {
        startPreparedProtocol();
    }
}

void VpnConnection::createProtocolConnections()
{
    auto *protocol = m_vpnProtocol.data();
    connect(protocol, &VpnProtocol::protocolError, this, [this, protocol](ErrorCode error) {
        if (protocol != m_vpnProtocol.data() || m_disconnecting) {
            return;
        }
        if (m_useWarpUnderlay) {
            stopProtocols(error);
        } else {
            emit vpnProtocolError(error);
        }
    });
    connect(protocol, &VpnProtocol::connectionStateChanged, this, [this, protocol](Vpn::ConnectionState state) {
        if (protocol == m_vpnProtocol.data()) {
            onProtocolStateChanged(state);
        }
    });
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));

#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        const auto connectionType = static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection);
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, connectionType);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, connectionType);
    });
#endif
}

void VpnConnection::startPreparedProtocol()
{
    if (!m_vpnProtocol || m_mainProtocolStarted || m_disconnecting) {
        return;
    }
    const auto protocol = m_vpnProtocol;
    const quint64 generation = m_generation;
    ++m_activeOperations;
    const auto operation = qScopeGuard([this]() { finishProtocolOperation(); });
    m_mainProtocolStarted = true;
    const ErrorCode err = protocol->start();
    if (generation != m_generation || protocol != m_vpnProtocol) {
        return;
    }
    if (err != ErrorCode::NoError) {
#ifdef AMNEZIA_DESKTOP
        stopProtocols(err);
#else
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
#endif
    }
}

void VpnConnection::startWarpUnderlay()
{
#ifdef Q_OS_WIN
    if (!m_useWarpUnderlay || m_underlayConfiguration.isEmpty() || m_underlayProtocol || m_disconnecting) {
        return;
    }
    ++m_activeOperations;
    const auto operation = qScopeGuard([this]() { finishProtocolOperation(); });
    m_underlayStopping = false;
    m_underlayRestartPending = false;
    m_underlayProtocol.reset(new WireguardProtocol(m_underlayConfiguration, m_warpUnderlaySocketPath),
                             &QObject::deleteLater);
    auto *protocol = m_underlayProtocol.data();
    connect(protocol, &VpnProtocol::protocolError, this, [this, protocol](ErrorCode error) {
        if (protocol == m_underlayProtocol.data()) {
            retryWarpUnderlay(error, 5000);
        }
    });
    connect(protocol, &VpnProtocol::connectionStateChanged, this, [this, protocol](Vpn::ConnectionState state) {
        if (protocol == m_underlayProtocol.data()) {
            onUnderlayStateChanged(state);
        }
    });
    m_underlayTimer.start();
    const auto underlay = m_underlayProtocol;
    if (ErrorCode err = underlay->start(); err != ErrorCode::NoError && underlay == m_underlayProtocol) {
        retryWarpUnderlay(err, 5000);
    }
#endif
}

void VpnConnection::stopWarpUnderlay()
{
    m_underlayTimer.stop();
    if (!m_underlayProtocol) {
        if (m_disconnecting) {
            finishDisconnect();
        }
        return;
    }
    if (m_underlayStopping) {
        return;
    }
    m_underlayStopping = true;
    const auto protocol = m_underlayProtocol;
    protocol->stop();
    if (protocol == m_underlayProtocol && protocol->connectionState() == Vpn::ConnectionState::Disconnected) {
        onUnderlayStateChanged(Vpn::ConnectionState::Disconnected);
    }
}

void VpnConnection::retryWarpUnderlay(ErrorCode error, int delay)
{
    if (!m_useWarpUnderlay || m_disconnecting || m_underlayStopping || m_underlayRestartPending) {
        return;
    }
    m_underlayTimer.stop();
    if (m_mainProtocolStarted && m_container != DockerContainer::Xray && m_container != DockerContainer::SSXray) {
        stopProtocols(error);
        return;
    }
    QJsonObject awg = m_underlayConfiguration.value(QStringLiteral("awg_config_data")).toObject();
    if (awg.value(configKey::port).toInt() == 500 && !m_mainProtocolStarted) {
        stopProtocols(error);
        return;
    }
    awg.insert(configKey::port, awg.value(configKey::port).toInt() == 500 ? 2408 : 500);
    m_underlayConfiguration.insert(QStringLiteral("awg_config_data"), awg);
    const quint64 generation = ++m_generation;
    m_recoveringUnderlay = m_mainProtocolStarted;
    m_underlayRestartPending = true;
    m_underlayRestartDelay = delay;
    if (m_recoveringUnderlay) {
        setConnectionState(Vpn::ConnectionState::Reconnecting);
    }
    if (generation != m_generation || m_disconnecting) {
        return;
    }
    stopWarpUnderlay();
}

void VpnConnection::onUnderlayStateChanged(Vpn::ConnectionState state)
{
    if (state == Vpn::ConnectionState::Disconnected && m_underlayStopping) {
        disconnect(m_underlayProtocol.data(), nullptr, this, nullptr);
        m_underlayProtocol.reset();
        m_underlayStopping = false;
        if (m_disconnecting) {
            finishDisconnect();
        } else if (m_underlayRestartPending) {
            const quint64 generation = m_generation;
            QTimer::singleShot(m_underlayRestartDelay, this, [this, generation]() {
                if (generation == m_generation && m_underlayRestartPending && !m_disconnecting) {
                    startWarpUnderlay();
                }
            });
        }
        return;
    }
    if (m_underlayStopping || m_disconnecting) {
        return;
    }
    if (state == Vpn::ConnectionState::Connected) {
        m_underlayTimer.stop();
#ifdef Q_OS_WIN
        if (m_recoveringUnderlay && m_vpnProtocol) {
            if (m_activeOperations > 0) {
                return;
            }
            const auto protocol = m_vpnProtocol;
            const quint64 generation = m_generation;
            ++m_activeOperations;
            const auto operation = qScopeGuard([this]() { finishProtocolOperation(); });
            const ErrorCode error = static_cast<XrayProtocol *>(protocol.data())->restartTransport();
            if (generation != m_generation || m_disconnecting) {
                return;
            }
            if (error != ErrorCode::NoError) {
                retryWarpUnderlay(error, 5000);
                return;
            }
            setConnectionState(Vpn::ConnectionState::Connected);
            if (generation == m_generation && !m_disconnecting) {
                m_recoveringUnderlay = false;
            }
            return;
        }
#endif
        startPreparedProtocol();
    } else if (state == Vpn::ConnectionState::Disconnected || state == Vpn::ConnectionState::Error) {
        retryWarpUnderlay(ErrorCode::AmneziaServiceConnectionFailed, 5000);
    }
}

void VpnConnection::onProtocolStateChanged(Vpn::ConnectionState state)
{
    if (m_disconnecting) {
        if (state == Vpn::ConnectionState::Disconnected) {
            disconnect(m_vpnProtocol.data(), nullptr, this, nullptr);
            m_vpnProtocol.reset();
            m_mainProtocolStarted = false;
            stopWarpUnderlay();
            finishDisconnect();
        }
        return;
    }
    if (state == Vpn::ConnectionState::Disconnected && m_mainRestartPending) {
        m_mainProtocolStarted = false;
        if (m_activeOperations > 0) {
            return;
        }
        m_mainRestartPending = false;
        const quint64 generation = m_generation;
        QTimer::singleShot(0, this, [this, generation]() {
            if (generation == m_generation && !m_disconnecting) {
                startPreparedProtocol();
            }
        });
        return;
    }
    if (m_useWarpUnderlay && (state == Vpn::ConnectionState::Disconnected || state == Vpn::ConnectionState::Error)) {
        const ErrorCode error = m_vpnProtocol->lastError();
        stopProtocols(error == ErrorCode::NoError ? ErrorCode::XrayExecutableCrashed : error);
        return;
    }
    if (m_useWarpUnderlay && state == Vpn::ConnectionState::Connected
        && (m_underlayStopping || m_underlayRestartPending || !m_underlayProtocol
            || m_underlayProtocol->connectionState() != Vpn::ConnectionState::Connected)) {
        return;
    }
#ifdef Q_OS_WIN
    if (!m_useWarpUnderlay && state == Vpn::ConnectionState::Connected && !clearDirectServerAllowedRange()) {
        qWarning() << "Failed to remove the temporary direct server firewall range";
    }
#endif
    setConnectionState(state);
}

void VpnConnection::stopProtocols(ErrorCode error)
{
    ++m_activeOperations;
    const auto operation = qScopeGuard([this]() { finishProtocolOperation(); });
    const quint64 generation = ++m_generation;
    m_disconnectError = error;
    m_disconnecting = true;
    m_mainRestartPending = false;
    m_underlayRestartPending = false;
    m_recoveringUnderlay = false;
    m_underlayTimer.stop();
    setConnectionState(Vpn::ConnectionState::Disconnecting);
    if (generation != m_generation || !m_disconnecting) {
        return;
    }
    if (m_vpnProtocol) {
        const auto protocol = m_vpnProtocol;
        protocol->stop();
        if (protocol == m_vpnProtocol && protocol->connectionState() == Vpn::ConnectionState::Disconnected) {
            onProtocolStateChanged(Vpn::ConnectionState::Disconnected);
        }
    } else {
        stopWarpUnderlay();
    }
    finishDisconnect();
}

void VpnConnection::finishDisconnect()
{
    if (!m_disconnecting || m_activeOperations > 0 || m_vpnProtocol || m_underlayProtocol) {
        return;
    }
    m_disconnecting = false;
    m_useWarpUnderlay = false;
    m_mainProtocolStarted = false;
    m_underlayConfiguration = { };
    m_container = DockerContainer::None;
    if (!clearDirectServerAllowedRange()) {
        qWarning() << "Failed to remove the temporary direct server firewall range";
    }
    const quint64 generation = m_generation;
    setConnectionState(m_disconnectError == ErrorCode::NoError ? Vpn::ConnectionState::Disconnected
                                                               : Vpn::ConnectionState::Error);
    if (generation != m_generation) {
        return;
    }
    if (m_disconnectError != ErrorCode::NoError) {
        emit vpnProtocolError(m_disconnectError);
    }
    if (generation == m_generation && m_pendingConnection) {
        auto pending = std::exchange(m_pendingConnection, { });
        QTimer::singleShot(0, this, [this, generation, pending]() {
            if (generation == m_generation) {
                pending();
            }
        });
    }
}

bool VpnConnection::clearDirectServerAllowedRange()
{
#ifdef Q_OS_WIN
    if (m_directServerAllowedRange.isEmpty()) {
        return true;
    }
    const bool removed = IpcClient::withInterface(
            [this](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->removeKillSwitchAllowedRange(QStringList { m_directServerAllowedRange });
                return reply.waitForFinished(1000) && reply.returnValue();
            },
            []() { return false; });
    if (removed) {
        m_directServerAllowedRange.clear();
    }
    return removed;
#else
    m_directServerAllowedRange.clear();
    return true;
#endif
}

void VpnConnection::finishProtocolOperation()
{
    --m_activeOperations;
    if (m_activeOperations > 0) {
        return;
    }
    if (m_disconnecting) {
        finishDisconnect();
    } else if (m_mainRestartPending && m_vpnProtocol
               && m_vpnProtocol->connectionState() == Vpn::ConnectionState::Disconnected) {
        onProtocolStateChanged(Vpn::ConnectionState::Disconnected);
    } else if (m_recoveringUnderlay && !m_underlayStopping && m_underlayProtocol
               && m_underlayProtocol->connectionState() == Vpn::ConnectionState::Connected) {
        const quint64 generation = m_generation;
        QTimer::singleShot(0, this, [this, generation]() {
            if (generation == m_generation && m_recoveringUnderlay && !m_disconnecting && !m_underlayStopping
                && m_underlayProtocol && m_underlayProtocol->connectionState() == Vpn::ConnectionState::Connected) {
                onUnderlayStateChanged(Vpn::ConnectionState::Connected);
            }
        });
    }
}

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            m_vpnConfiguration.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto allowedIpsString = line.split("=", Qt::KeepEmptyParts);
                if (allowedIpsString.size() >= 2 && allowedIpsString.first().trimmed() == QStringLiteral("AllowedIPs")) {
                    QJsonArray allowedIpsJsonArray;
                    const QString allowedIps = allowedIpsString.mid(1).join(QStringLiteral("=")).trimmed();
                    for (const QString &allowedIp : allowedIps.split(",", Qt::SkipEmptyParts)) {
                        allowedIpsJsonArray.append(allowedIp.trimmed());
                    }
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto persistentKeepaliveString = line.split("=", Qt::KeepEmptyParts);
                if (persistentKeepaliveString.size() >= 2
                        && persistentKeepaliveString.first().trimmed() == QStringLiteral("PersistentKeepalive")) {
                    configData.insert(configKey::persistentKeepAlive,
                                      persistentKeepaliveString.mid(1).join(QStringLiteral("=")).trimmed());
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                } else {
                    const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
                    for (const QString &ip : siteIps) {
                        if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                            sites.append(ip);
                        }
                    }
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            }
        }
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

bool VpnConnection::prepareWarpUnderlay(quint64 generation)
{
    if (!m_appSettingsRepository) {
        return false;
    }

    std::optional<WarpUnderlayConfig> underlay;
    const QByteArray stored = m_appSettingsRepository->warpUnderlayRegistration();
    if (!stored.isEmpty()) {
        QJsonParseError error;
        const QJsonDocument document = QJsonDocument::fromJson(stored, &error);
        if (error.error == QJsonParseError::NoError && document.isObject()) {
            underlay = WarpUnderlayConfig::fromJson(document.object());
        }
    }

    if (!underlay) {
        const QStringList apiBases = build_config::warpRegistrationEndpoints.split(QLatin1Char('|'), Qt::SkipEmptyParts);
        underlay = WarpUnderlay::registerDevice(apiBases, [this, generation]() { return generation != m_generation; });
        if (!underlay || generation != m_generation) {
            return false;
        }
        m_appSettingsRepository->setWarpUnderlayRegistration(
                QJsonDocument(underlay->toJson()).toJson(QJsonDocument::Compact));
    }

    const QUrl endpoint(QStringLiteral("udp://") + underlay->endpoint);
    QString outerAddress;
    QHostAddress literalAddress(endpoint.host());
    if (literalAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        outerAddress = literalAddress.toString();
    } else if (literalAddress.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol) {
        const QList<QHostAddress> addresses = QHostInfo::fromName(endpoint.host()).addresses();
        for (const QHostAddress &address : addresses) {
            if (address.protocol() == QAbstractSocket::IPv4Protocol) {
                outerAddress = address.toString();
                break;
            }
        }
    }
    if (outerAddress.isEmpty() || generation != m_generation) {
        return false;
    }
    const QString vpnServerAddress = m_remoteAddress;
    const auto underlayConfiguration =
            WarpUnderlay::createAwgConfig(*underlay, outerAddress, vpnServerAddress, build_config::warpAwgInitPacket);
    if (!underlayConfiguration) {
        return false;
    }
    m_underlayConfiguration = *underlayConfiguration;
#ifdef Q_OS_WIN
    m_remoteAddress = outerAddress;
    m_vpnConfiguration.insert(configKey::underlayEndpoint, outerAddress);
    m_vpnConfiguration.insert(configKey::underlayAddress, underlay->ipv4Address.section(QLatin1Char('/'), 0, 0));
    m_vpnConfiguration.insert(configKey::underlayServerAddress, vpnServerAddress);
    m_vpnConfiguration.insert(configKey::underlayInterface, m_warpUnderlayInterfaceName);
#elif defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    m_underlayConfiguration.insert(configKey::underlayServerHost, m_vpnConfiguration.value(configKey::hostName));
    m_underlayConfiguration.insert(configKey::underlayServerAddress, vpnServerAddress);
    m_vpnConfiguration.insert(configKey::warpUnderlay, m_underlayConfiguration);
#endif
    return true;
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn()
{
    if (m_vpnProtocol.isNull())
        return;

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    ++m_activeOperations;
    const auto operation = qScopeGuard([this]() { finishProtocolOperation(); });
    const quint64 generation = ++m_generation;
    setConnectionState(Vpn::ConnectionState::Reconnecting);
    if (generation != m_generation || m_disconnecting || !m_vpnProtocol) {
        return;
    }

    if (m_useWarpUnderlay) {
        m_recoveringUnderlay = true;
        m_underlayRestartPending = true;
        m_underlayRestartDelay = 0;
        stopWarpUnderlay();
    } else {
        m_mainRestartPending = true;
        const auto protocol = m_vpnProtocol;
        protocol->stop();
        if (m_mainRestartPending && protocol == m_vpnProtocol
            && protocol->connectionState() == Vpn::ConnectionState::Disconnected) {
            onProtocolStateChanged(Vpn::ConnectionState::Disconnected);
        }
    }
}

void VpnConnection::disconnectFromVpn()
{
#ifdef AMNEZIA_DESKTOP
    m_pendingConnection = { };
    stopProtocols();
#else
    ++m_generation;
    #if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    #endif

    if (m_vpnProtocol.isNull() && m_underlayProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

    #ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
    #endif

    if (m_vpnProtocol && m_mainProtocolStarted) {
        m_vpnProtocol->stop();
    }
    m_mainProtocolStarted = false;
    stopWarpUnderlay();

    #if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
    #endif

    m_vpnProtocol = nullptr;
    m_useWarpUnderlay = false;
    if (m_connectionState != Vpn::ConnectionState::Disconnected) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
    }
#endif
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state)
{
    if (state == m_connectionState) {
        return;
    }
    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting && !m_disconnecting) {
        return;
    }

    const quint64 generation = m_generation;
    m_connectionState = state;
    if (state != Vpn::ConnectionState::Connected || !m_recoveringUnderlay) {
        onConnectionStateChanged(state);
    }
    if (generation == m_generation && state == m_connectionState) {
        emit connectionStateChanged(state);
    }
}
