#include "xrayProtocol.h"

#include "core/models/protocols/xrayProtocolConfig.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/ipcClient.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/serialization/serialization.h"
#include "core/utils/warpUnderlay.h"
#include "ipc.h"

#ifdef Q_OS_WIN
    #include "platforms/windows/daemon/wireguardutilswindows.h"
#endif

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QRemoteObjectPendingCallWatcher>
#include <QTimer>
#include <QtCore/qlogging.h>
#include <QtCore/qobjectdefs.h>
#include <QtCore/qprocess.h>

#include <exception>
#include <utility>

#ifdef Q_OS_MACOS
static const QString tunName = "utun22";
#else
static const QString tunName = "tun2";
#endif

XrayProtocol::XrayProtocol(const QJsonObject &configuration, QObject *parent) : VpnProtocol(configuration, parent)
{
    m_vpnGateway = amnezia::protocols::xray::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::xray::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<amnezia::RouteMode>(configuration.value(amnezia::configKey::splitTunnelType).toInt());
    QString remoteHost = m_rawConfig.value(amnezia::configKey::hostName).toString();
#ifdef Q_OS_WIN
    remoteHost = m_rawConfig.value(amnezia::configKey::underlayEndpoint).toString(remoteHost);
#endif
    m_remoteAddress = NetworkUtilities::getIPAddress(remoteHost);

    const QString primaryDns = configuration.value(amnezia::configKey::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::configKey::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    QJsonObject xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
    if (xrayConfiguration.isEmpty()) {
        xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
    }

    if (xrayConfiguration.isEmpty()) {
        qWarning() << "Xray config wrapper is empty";
        m_xrayConfig = {};
    }

    m_xrayConfig = QJsonDocument::fromJson(xrayConfiguration.value(amnezia::configKey::config).toString().toUtf8()).object();
    if (m_xrayConfig.isEmpty()) {
        qWarning() << "Xray config string is not a valid JSON object";
        m_xrayConfig = {};
    }
}

XrayProtocol::~XrayProtocol()
{
    qDebug() << "XrayProtocol::~XrayProtocol()";
    XrayProtocol::stop();
}

ErrorCode XrayProtocol::start()
{
    resetStopGuard();
    const quint64 generation = ++m_generation;
    m_tun2socksRetryCount = 0;
    setConnectionState(Vpn::ConnectionState::Connecting);
    if (m_stopped || generation != m_generation) {
        return ErrorCode::NoError;
    }

    qDebug() << "XrayProtocol::start()";
    const ErrorCode error = startTransport();
    if (error != ErrorCode::NoError || m_stopped || generation != m_generation) {
        return error;
    }
    return startTun2Socks();
}

ErrorCode XrayProtocol::startTransport()
{
    const quint64 generation = m_generation;

#ifdef Q_OS_WIN
    if (m_rawConfig.contains(configKey::underlayEndpoint)) {
        const QString sourceAddress = m_rawConfig.value(configKey::underlayAddress).toString();
        const QString interfaceName = WireguardUtilsWindows::s_interfaceName();
        bool underlayAvailable = false;
        for (const auto &networkInterface : QNetworkInterface::allInterfaces()) {
            if (networkInterface.humanReadableName() != interfaceName
                || !networkInterface.flags().testFlag(QNetworkInterface::IsUp)) {
                continue;
            }
            for (const auto &entry : networkInterface.addressEntries()) {
                underlayAvailable |= entry.ip() == QHostAddress(sourceAddress);
            }
        }
        if (!underlayAvailable) {
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        const auto boundConfig = WarpUnderlay::bindXrayConfig(
                m_xrayConfig, sourceAddress, interfaceName, m_rawConfig.value(configKey::hostName).toString(),
                m_rawConfig.value(configKey::underlayServerAddress).toString());
        if (!boundConfig) {
            return ErrorCode::InternalError;
        }
        m_xrayConfig = *boundConfig;
    }
#endif

    // Inject SOCKS5 auth into the inbound before starting xray.
    // Re-uses existing credentials if the config already has them (e.g. imported config).
    amnezia::serialization::inbounds::InboundCredentials creds;
    try {
        creds = m_tun2socksProcess ? amnezia::serialization::inbounds::GetInboundCredentials(m_xrayConfig)
                                   : amnezia::serialization::inbounds::EnsureInboundAuth(m_xrayConfig);
    } catch (const std::exception &e) {
        qCritical() << "EnsureInboundAuth failed:" << e.what();
        return ErrorCode::InternalError;
    }
    m_socksUser = creds.username;
    m_socksPassword = creds.password;
    m_socksPort = creds.port;

    QString xrayConfigStr = QJsonDocument(m_xrayConfig).toJson(QJsonDocument::Compact);
    if (xrayConfigStr.isEmpty()) {
        qCritical() << "Xray config is empty";
        return ErrorCode::XrayExecutableCrashed;
    }

    xrayConfigStr = amnezia::sanitizeNativeConfig(xrayConfigStr);

    return IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
                auto xrayStart = iface->xrayStartOwned(xrayConfigStr);
                const bool finished = xrayStart.waitForFinished();
                if (!finished) {
                    auto *watcher = new QRemoteObjectPendingCallWatcher(xrayStart, iface.data());
                    connect(watcher, &QRemoteObjectPendingCallWatcher::finished, iface.data(),
                            [iface](QRemoteObjectPendingCallWatcher *call) {
                                const qint64 token = call->returnValue().toLongLong();
                                if (call->error() == QRemoteObjectPendingCall::NoError && token != 0) {
                                    iface->xrayStopOwned(token);
                                }
                                call->deleteLater();
                            });
                }
                if (m_stopped || generation != m_generation) {
                    if (finished && xrayStart.returnValue() != 0) {
                        iface->xrayStopOwned(xrayStart.returnValue()).waitForFinished();
                    }
                    return ErrorCode::NoError;
                }
                if (!finished || xrayStart.returnValue() == 0) {
                    qCritical() << "Failed to start xray";
                    return ErrorCode::XrayExecutableCrashed;
                }
                m_xrayToken = xrayStart.returnValue();
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}

ErrorCode XrayProtocol::restartTransport()
{
    if (m_stopped || !m_tun2socksProcess) {
        return ErrorCode::InternalError;
    }
    const quint64 generation = m_generation;
    return IpcClient::withInterface(
            [this, generation](QSharedPointer<IpcInterfaceReplica> iface) {
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
                if (m_xrayToken != 0) {
                    auto reply = iface->xrayStopOwned(std::exchange(m_xrayToken, 0));
                    const bool finished = reply.waitForFinished();
                    if (m_stopped || generation != m_generation) {
                        return ErrorCode::NoError;
                    }
                    if (!finished || !reply.returnValue()) {
                        return ErrorCode::XrayExecutableCrashed;
                    }
                }
                return startTransport();
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}

void XrayProtocol::stop()
{
    if (guardStop()) {
        return;
    }
    ++m_generation;
    setConnectionState(Vpn::ConnectionState::Disconnecting);

    if (m_xrayToken == 0 && !m_tun2socksProcess) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    qDebug() << "XrayProtocol::stop()";

    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> iface) {
        auto disableKillSwitch = iface->disableKillSwitch();
        if (!disableKillSwitch.waitForFinished() || !disableKillSwitch.returnValue())
            qWarning() << "Failed to disable killswitch";

        auto StartRoutingIpv6 = iface->StartRoutingIpv6();
        if (!StartRoutingIpv6.waitForFinished() || !StartRoutingIpv6.returnValue())
            qWarning() << "Failed to start routing ipv6";

        auto restoreResolvers = iface->restoreResolvers();
        if (!restoreResolvers.waitForFinished() || !restoreResolvers.returnValue())
            qWarning() << "Failed to restore resolvers";

        auto deleteTun = iface->deleteTun(tunName);
        if (!deleteTun.waitForFinished() || !deleteTun.returnValue())
            qWarning() << "Failed to delete tun";

        auto xrayStop = iface->xrayStopOwned(std::exchange(m_xrayToken, 0));
        if (!xrayStop.waitForFinished() || !xrayStop.returnValue())
            qWarning() << "Failed to stop xray";
    });

    if (m_tun2socksProcess) {
        m_tun2socksProcess->blockSignals(true);

#ifndef Q_OS_WIN
        m_tun2socksProcess->terminate();
        auto waitForFinished = m_tun2socksProcess->waitForFinished(1000);
        if (!waitForFinished.waitForFinished() || !waitForFinished.returnValue()) {
            qWarning() << "Failed to terminate tun2socks. Killing the process...";
            m_tun2socksProcess->kill();
        }
#else
        // terminate does not do anything useful on Windows
        // so just kill the process
        m_tun2socksProcess->kill();
        auto waitForFinished = m_tun2socksProcess->waitForFinished(5000);
        if (!waitForFinished.waitForFinished() || !waitForFinished.returnValue()) {
            qWarning() << "Failed to wait for tun2socks shutdown";
        }
#endif

        m_tun2socksProcess->close();
        m_tun2socksProcess.reset();
    }

    setConnectionState(Vpn::ConnectionState::Disconnected);
}

ErrorCode XrayProtocol::startTun2Socks()
{
    const quint64 generation = m_generation;
    const auto process = IpcClient::CreatePrivilegedProcess();
    const bool ready = process && process->waitForSource();
    if (m_stopped || generation != m_generation) {
        if (process && ready) {
            process->close();
        }
        return ErrorCode::NoError;
    }
    if (!ready) {
        return ErrorCode::AmneziaServiceConnectionFailed;
    }
    if (m_tun2socksProcess) {
        m_tun2socksProcess->disconnect(this);
        m_tun2socksProcess->close();
    }
    m_tun2socksProcess = process;
    auto *processIdentity = process.data();

    const QString proxyUrl = QString("socks5://%1:%2@127.0.0.1:%3").arg(m_socksUser, m_socksPassword, QString::number(m_socksPort));

    m_tun2socksProcess->setProgram(PermittedProcess::Tun2Socks);
    m_tun2socksProcess->setArguments({ "-device", QString("tun://%1").arg(tunName), "-proxy", proxyUrl });

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this,
            [this, generation, processIdentity]() {
                if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                    return;
                }
                auto readAllStandardError = m_tun2socksProcess->readAllStandardError();
                if (!readAllStandardError.waitForFinished()) {
                    qWarning() << "Failed to read output from tun2socks";
                    return;
                }
                if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                    return;
                }

                const QString line = readAllStandardError.returnValue();

                if (!line.contains("[TCP]") && !line.contains("[UDP]") && !line.contains("socks5://"))
                    qDebug() << "[tun2socks]:" << line;

                if (line.contains("[STACK] tun://") && line.contains("<-> socks5://")) {
                    disconnect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this,
                               nullptr);

                    const ErrorCode res = setupRouting();
                    if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                        return;
                    }
                    if (res != ErrorCode::NoError) {
                        setLastError(res);
                        stop();
                    } else {
                        setConnectionState(Vpn::ConnectionState::Connected);
                    }
                }
            },
            Qt::QueuedConnection);

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this, generation, processIdentity](int exitCode, QProcess::ExitStatus exitStatus) {
                if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                    return;
                }
                // Check stdout for "resource busy" — the TUN device was not yet released
                // by the previous tun2socks instance. Retry after a short delay.
                bool resourceBusy = false;
                if (m_tun2socksProcess) {
                    auto readOut = m_tun2socksProcess->readAllStandardOutput();
                    if (readOut.waitForFinished()) {
                        resourceBusy = readOut.returnValue().contains("resource busy");
                    }
                }
                if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                    return;
                }

                if (resourceBusy && m_tun2socksRetryCount < maxTun2SocksRetries) {
                    m_tun2socksRetryCount++;
                    qWarning() << QString("Tun2socks: TUN resource busy, retrying (%1/%2) in %3ms...")
                                      .arg(m_tun2socksRetryCount)
                                      .arg(maxTun2SocksRetries)
                                      .arg(tun2socksRetryDelayMs);
                    QTimer::singleShot(tun2socksRetryDelayMs, this, [this, generation, processIdentity]() {
                        if (m_stopped || generation != m_generation || m_tun2socksProcess.data() != processIdentity) {
                            return;
                        }
                        if (ErrorCode err = startTun2Socks();
                            err != ErrorCode::NoError && !m_stopped && generation == m_generation) {
                            setLastError(err);
                            stop();
                        }
                    });
                    return;
                }

                m_tun2socksRetryCount = 0;

                if (exitStatus == QProcess::ExitStatus::CrashExit) {
                    qCritical() << "Tun2socks process crashed!";
                } else {
                    qCritical() << QString("Tun2socks process was closed with %1 exit code").arg(exitCode);
                }
                setLastError(ErrorCode::Tun2SockExecutableCrashed);
                stop();
            },
            Qt::QueuedConnection);

    m_tun2socksProcess->start();
    return ErrorCode::NoError;
}

ErrorCode XrayProtocol::setupRouting()
{
    const quint64 generation = m_generation;
    return IpcClient::withInterface(
            [this, generation](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
#ifdef Q_OS_WIN
                const int inetAdapterIndex = NetworkUtilities::AdapterIndexTo(QHostAddress(m_remoteAddress));
#endif
                auto createTun = iface->createTun(tunName, amnezia::protocols::xray::defaultLocalAddr);
                const bool tunCreated = createTun.waitForFinished() && createTun.returnValue();
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
                if (!tunCreated) {
                    qCritical() << "Failed to assign IP address for TUN";
                    return ErrorCode::InternalError;
                }

                auto updateResolvers = iface->updateResolvers(tunName, m_dnsServers);
                const bool resolversUpdated = updateResolvers.waitForFinished() && updateResolvers.returnValue();
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
                if (!resolversUpdated) {
                    qCritical() << "Failed to set DNS resolvers for TUN";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                for (auto &netInterface : netInterfaces) {
                    for (auto &address : netInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString())
                            vpnAdapterIndex = netInterface.index();
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                const bool killSwitchEnabled = QVariant(m_rawConfig.value(configKey::killSwitchOption).toString()).toBool();
                if (killSwitchEnabled) {
                    if (vpnAdapterIndex != -1) {
                        QJsonObject config = m_rawConfig;
                        config.insert("vpnServer", m_remoteAddress);

                        auto enableKillSwitch = iface->enableKillSwitch(config, vpnAdapterIndex);
                        const bool killSwitchReady = enableKillSwitch.waitForFinished() && enableKillSwitch.returnValue();
                        if (m_stopped || generation != m_generation) {
                            return ErrorCode::NoError;
                        }
                        if (!killSwitchReady) {
                            qCritical() << "Failed to enable killswitch";
                            return ErrorCode::InternalError;
                        }
                    } else
                        qWarning() << "Failed to get vpnAdapterIndex. Killswitch disabled";
                }

                if (m_routeMode == amnezia::RouteMode::VpnAllSites) {
                    static const QStringList subnets = { "1.0.0.0/8",  "2.0.0.0/7",  "4.0.0.0/6",  "8.0.0.0/5",
                                                         "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1" };

                    auto routeAddList = iface->routeAddList(m_vpnGateway, subnets);
                    const bool routesAdded =
                            routeAddList.waitForFinished() && routeAddList.returnValue() == subnets.count();
                    if (m_stopped || generation != m_generation) {
                        return ErrorCode::NoError;
                    }
                    if (!routesAdded) {
                        qCritical() << "Failed to set routes for TUN";
                        return ErrorCode::InternalError;
                    }
                }

                auto StopRoutingIpv6 = iface->StopRoutingIpv6();
                const bool ipv6Blocked = StopRoutingIpv6.waitForFinished() && StopRoutingIpv6.returnValue();
                if (m_stopped || generation != m_generation) {
                    return ErrorCode::NoError;
                }
                if (!ipv6Blocked) {
                    qCritical() << "Failed to disable IPv6 routing";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert("inetAdapterIndex", inetAdapterIndex);
                    config.insert("vpnAdapterIndex", vpnAdapterIndex);
                    config.insert("vpnGateway", m_vpnGateway);
                    config.insert("vpnServer", m_remoteAddress);

                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    const bool peerTrafficEnabled =
                            enablePeerTraffic.waitForFinished() && enablePeerTraffic.returnValue();
                    if (m_stopped || generation != m_generation) {
                        return ErrorCode::NoError;
                    }
                    if (!peerTrafficEnabled) {
                        qCritical() << "Failed to enable peer traffic";
                        return ErrorCode::InternalError;
                    }
                } else
                    qWarning() << "Failed to get adapter indexes. Split-tunneling disabled";
#endif
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}
