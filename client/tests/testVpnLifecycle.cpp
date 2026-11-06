#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTest>
#include <QThread>
#include <QTimer>
#include <QUrl>

#include "core/protocols/xrayProtocol.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/serialization/serialization.h"
#include "utils/ipcTestService.h"
#include "vpnConnection.h"

class AcknowledgedProtocol : public VpnProtocol
{
public:
    AcknowledgedProtocol() : VpnProtocol({ })
    {
    }

    ErrorCode start() override
    {
        resetStopGuard();
        ++starts;
        setConnectionState(Vpn::Connecting);
        if (duringStart) {
            duringStart();
        }
        return ErrorCode::NoError;
    }

    void stop() override
    {
        if (guardStop()) {
            return;
        }
        ++stops;
        setConnectionState(Vpn::Disconnecting);
        if (immediateCleanup) {
            setConnectionState(Vpn::Disconnected);
        }
    }

    int starts = 0;
    int stops = 0;
    bool immediateCleanup = false;
    std::function<void()> duringStart;
};

namespace
{
    QJsonObject xrayConfig()
    {
        const QJsonObject native { { "inbounds",
                                     QJsonArray { QJsonObject { { "protocol", "socks" },
                                                                { "listen", "127.0.0.1" },
                                                                { "port", 10989 },
                                                                { "settings", QJsonObject { { "udp", true } } } } } },
                                   { "outbounds", QJsonArray { QJsonObject { { "protocol", "freedom" } } } } };
        return { { "hostName", "198.51.100.10" },
                 { "dns1", "192.0.2.53" },
                 { "killSwitchOption", "false" },
                 { "xray_config_data", QJsonObject { { "config", QString::fromUtf8(QJsonDocument(native).toJson()) } } } };
    }
}

class TestVpnLifecycle : public QObject
{
    Q_OBJECT

private:
    std::unique_ptr<IpcTestService> ipc;
    std::unique_ptr<SecureQSettings> settings;
    std::unique_ptr<SecureServersRepository> servers;
    std::unique_ptr<SecureAppSettingsRepository> appSettings;

    void attachMain(VpnConnection &connection, const QSharedPointer<VpnProtocol> &protocol, bool started = true)
    {
        connection.m_vpnProtocol = protocol;
        connection.m_mainProtocolStarted = started;
        connection.createProtocolConnections();
    }

    void attachUnderlay(VpnConnection &connection, const QSharedPointer<VpnProtocol> &protocol)
    {
        connection.m_underlayProtocol = protocol;
        connect(protocol.data(), &VpnProtocol::connectionStateChanged, &connection,
                [&connection, identity = protocol.data()](Vpn::ConnectionState state) {
                    if (identity == connection.m_underlayProtocol.data()) {
                        connection.onUnderlayStateChanged(state);
                    }
                });
    }

private slots:
    void init()
    {
        ipc = std::make_unique<IpcTestService>();
        QVERIFY(ipc->enabled);
        QVERIFY(IpcClient::Interface());
        settings = std::make_unique<SecureQSettings>(
                QStringLiteral("AmneziaLifecycleTest-%1").arg(QUuid::createUuid().toString()), QStringLiteral("test"),
                nullptr, false);
        servers = std::make_unique<SecureServersRepository>(settings.get());
        appSettings = std::make_unique<SecureAppSettingsRepository>(settings.get());
    }

    void cleanup()
    {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        settings->clearSettings();
        appSettings.reset();
        servers.reset();
        settings.reset();
        ipc.reset();
    }

    void cancelsBeforePreparingTransport()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        connect(&connection, &VpnConnection::connectionStateChanged, &connection, [&](Vpn::ConnectionState state) {
            if (state == Vpn::Connecting) {
                connection.disconnectFromVpn();
            }
        });
        connection.connectToVpn(QStringLiteral("test"), DockerContainer::Xray, xrayConfig());
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QVERIFY(!connection.vpnProtocol());
        QCOMPARE(connection.m_activeOperations, 0);
        QVERIFY(!ipc->source.calls.contains("startXray"));
        QVERIFY(!ipc->source.calls.contains("createProcess"));
    }

    void reachableServerBypassesUnderlayWithStrictKillSwitch()
    {
        QTcpServer entry;
        QVERIFY(entry.listen(QHostAddress::LocalHost));
        QJsonObject config = xrayConfig();
        QJsonObject native =
                QJsonDocument::fromJson(config.value("xray_config_data").toObject().value("config").toString().toUtf8())
                        .object();
        const QJsonObject server { { "address", "127.0.0.1" }, { "port", entry.serverPort() } };
        const QJsonObject settings { { "vnext", QJsonArray { server } } };
        const QJsonObject outbound { { "protocol", "vless" }, { "settings", settings } };
        native.insert("outbounds", QJsonArray { outbound });
        config.insert("hostName", "127.0.0.1");
        config.insert("forceWarpAvailable", true);
        QJsonObject wrapper = config.value("xray_config_data").toObject();
        wrapper.insert("config", QString::fromUtf8(QJsonDocument(native).toJson()));
        config.insert("xray_config_data", wrapper);

        VpnConnection connection(servers.get(), appSettings.get());
        connection.connectToVpn(QStringLiteral("test"), DockerContainer::Xray, config);
        QVERIFY(!connection.m_useWarpUnderlay);
        QVERIFY(!connection.m_underlayProtocol);
        QVERIFY(ipc->source.calls.contains("allowRange"));
        QVERIFY(!connection.m_directServerAllowedRange.isEmpty());
        QVERIFY(connection.clearDirectServerAllowedRange());
        QVERIFY(ipc->source.calls.contains("removeRange"));
        connection.disconnectFromVpn();
    }

    void disabledIpBlockBypassSkipsUnderlay()
    {
        appSettings->setIpBlockBypassEnabled(false);
        QJsonObject config = xrayConfig();
        config.insert("forceWarpAvailable", true);
        VpnConnection connection(servers.get(), appSettings.get());
        connection.connectToVpn(QStringLiteral("test"), DockerContainer::Xray, config);
        QVERIFY(!connection.m_useWarpUnderlay);
        QVERIFY(!connection.m_underlayProtocol);
        QVERIFY(ipc->source.calls.contains("allowRange"));
        connection.disconnectFromVpn();
    }

    void waitsForBothCleanupAcknowledgments()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto main = QSharedPointer<AcknowledgedProtocol>::create();
        auto underlay = QSharedPointer<AcknowledgedProtocol>::create();
        main->setConnectionState(Vpn::Connected);
        underlay->setConnectionState(Vpn::Connected);
        attachMain(connection, main);
        attachUnderlay(connection, underlay);
        connection.m_useWarpUnderlay = true;
        connection.m_connectionState = Vpn::Connected;
        connection.disconnectFromVpn();
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        QCOMPARE(main->stops, 1);
        QCOMPARE(underlay->stops, 0);
        main->setConnectionState(Vpn::Disconnected);
        QCOMPARE(underlay->stops, 1);
        QVERIFY(!ipc->source.calls.contains("clearRoutes"));
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        underlay->setConnectionState(Vpn::Disconnected);
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QVERIFY(ipc->source.calls.contains("clearRoutes"));
        main->setConnectionState(Vpn::Connected);
        underlay->setConnectionState(Vpn::Connected);
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
    }

    void defersReplacementUntilStartUnwinds()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto protocol = QSharedPointer<AcknowledgedProtocol>::create();
        protocol->immediateCleanup = true;
        attachMain(connection, protocol, false);
        protocol->duringStart = [&]() {
            connection.connectToVpn(QStringLiteral("replacement"), DockerContainer::None, xrayConfig());
            QCoreApplication::processEvents();
            QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
            QVERIFY(connection.m_pendingConnection);
            QVERIFY(connection.m_activeOperations > 0);
        };
        connection.startPreparedProtocol();
        QTRY_COMPARE(connection.connectionState(), Vpn::Error);
        QCOMPARE(protocol->starts, 1);
        QCOMPARE(protocol->stops, 1);
        QCOMPARE(connection.m_activeOperations, 0);
    }

    void cancelsQueuedReplacement()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto protocol = QSharedPointer<AcknowledgedProtocol>::create();
        protocol->setConnectionState(Vpn::Connected);
        attachMain(connection, protocol);
        connection.connectToVpn(QStringLiteral("replacement"), DockerContainer::None, xrayConfig());
        protocol->setConnectionState(Vpn::Disconnected);
        connection.disconnectFromVpn();
        QTest::qWait(75);
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QVERIFY(!connection.vpnProtocol());
    }

    void reconnectWaitsForCleanup()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto protocol = QSharedPointer<AcknowledgedProtocol>::create();
        protocol->setConnectionState(Vpn::Connected);
        attachMain(connection, protocol);
        connection.m_connectionState = Vpn::Connected;
        connection.reconnectToVpn();
        QCOMPARE(protocol->stops, 1);
        QCOMPARE(protocol->starts, 0);
        protocol->setConnectionState(Vpn::Disconnected);
        QTRY_COMPARE(protocol->starts, 1);
        QCOMPARE(connection.connectionState(), Vpn::Connecting);
        protocol->immediateCleanup = true;
        connection.disconnectFromVpn();
    }

    void fallbackWaitsForCleanupAndFailsClosed()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto main = QSharedPointer<AcknowledgedProtocol>::create();
        auto firstUnderlay = QSharedPointer<AcknowledgedProtocol>::create();
        main->immediateCleanup = true;
        attachMain(connection, main, false);
        attachUnderlay(connection, firstUnderlay);
        connection.m_useWarpUnderlay = true;
        connection.m_underlayConfiguration = { { "awg_config_data", QJsonObject { { "port", 2408 } } } };
        connection.retryWarpUnderlay(ErrorCode::ApiConfigTimeoutError, 60000);
        QCOMPARE(connection.m_underlayConfiguration.value("awg_config_data").toObject().value("port").toInt(), 500);
        QCOMPARE(main->starts, 0);
        QCOMPARE(firstUnderlay->stops, 1);
        QCOMPARE(connection.m_underlayProtocol.data(), firstUnderlay.data());
        firstUnderlay->setConnectionState(Vpn::Disconnected);
        QVERIFY(!connection.m_underlayProtocol);
        connection.m_underlayRestartPending = false;
        auto secondUnderlay = QSharedPointer<AcknowledgedProtocol>::create();
        attachUnderlay(connection, secondUnderlay);
        connection.retryWarpUnderlay(ErrorCode::ApiConfigTimeoutError);
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        secondUnderlay->setConnectionState(Vpn::Disconnected);
        QCOMPARE(connection.connectionState(), Vpn::Error);
        QCOMPARE(connection.lastError(), ErrorCode::ApiConfigTimeoutError);
        QCOMPARE(main->starts, 0);
    }

    void recoveryRetainsMainTunAndRestartsOnlyTransport()
    {
        using amnezia::serialization::inbounds::GetInboundCredentials;
        VpnConnection connection(servers.get(), appSettings.get());
        auto main = QSharedPointer<XrayProtocol>::create(xrayConfig());
        QCOMPARE(main->start(), ErrorCode::NoError);
        QTRY_COMPARE(ipc->process.starts, 1);
        const auto credentials =
                GetInboundCredentials(QJsonDocument::fromJson(ipc->source.xrayConfiguration.toUtf8()).object());
        const auto processArguments = ipc->process.arguments;
        QVERIFY(processArguments.contains("-proxy"));
        const QUrl proxy(processArguments.value(processArguments.indexOf("-proxy") + 1));
        QCOMPARE(proxy.scheme(), QStringLiteral("socks5"));
        QCOMPARE(proxy.host(), QStringLiteral("127.0.0.1"));
        QCOMPARE(proxy.port(), credentials.port);
        QVERIFY(!credentials.username.isEmpty() && proxy.userName() == credentials.username);
        QVERIFY(!credentials.password.isEmpty() && proxy.password() == credentials.password);
        QTcpServer reservedSocksEndpoint;
        QVERIFY(reservedSocksEndpoint.listen(QHostAddress::LocalHost, credentials.port));
        auto firstUnderlay = QSharedPointer<AcknowledgedProtocol>::create();
        firstUnderlay->setConnectionState(Vpn::Connected);
        attachMain(connection, main);
        attachUnderlay(connection, firstUnderlay);
        connection.m_useWarpUnderlay = true;
        connection.m_connectionState = Vpn::Connected;
        const auto process = main->m_tun2socksProcess;
        const auto token = main->m_xrayToken;
        ipc->source.calls.clear();
        connection.reconnectToVpn();
        QCOMPARE(connection.connectionState(), Vpn::Reconnecting);
        QCOMPARE(firstUnderlay->stops, 1);
        QCOMPARE(main->m_tun2socksProcess, process);
        QCOMPARE(main->m_xrayToken, token);
        QVERIFY(ipc->source.calls.isEmpty());
        firstUnderlay->setConnectionState(Vpn::Disconnected);
        auto recovered = QSharedPointer<AcknowledgedProtocol>::create();
        recovered->immediateCleanup = true;
        connection.m_underlayRestartPending = false;
        attachUnderlay(connection, recovered);
        recovered->setConnectionState(Vpn::Connected);
        QCOMPARE(connection.connectionState(), Vpn::Connected);
        QCOMPARE(main->m_tun2socksProcess, process);
        QCOMPARE(ipc->process.kills, 0);
        QCOMPARE(ipc->process.starts, 1);
        QCOMPARE(ipc->source.calls, QStringList({ "stopXray", "startXray" }));
        QCOMPARE(ipc->source.stoppedTokens.last(), token);
        QVERIFY(main->m_xrayToken != token);
        const auto recoveredCredentials =
                GetInboundCredentials(QJsonDocument::fromJson(ipc->source.xrayConfiguration.toUtf8()).object());
        connection.disconnectFromVpn();
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QCOMPARE(recoveredCredentials.port, proxy.port());
        QVERIFY(recoveredCredentials.username == proxy.userName());
        QVERIFY(recoveredCredentials.password == proxy.password());
        QVERIFY(ipc->process.arguments == processArguments);
    }

    void nonXrayUnderlayFailureStopsBothProtocols()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto main = QSharedPointer<AcknowledgedProtocol>::create();
        auto underlay = QSharedPointer<AcknowledgedProtocol>::create();
        main->setConnectionState(Vpn::Connected);
        underlay->setConnectionState(Vpn::Connected);
        attachMain(connection, main);
        attachUnderlay(connection, underlay);
        connection.m_container = DockerContainer::OpenVpn;
        connection.m_useWarpUnderlay = true;
        connection.m_connectionState = Vpn::Connected;
        connection.retryWarpUnderlay(ErrorCode::AmneziaServiceConnectionFailed);
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        QCOMPARE(main->stops, 1);
        QCOMPARE(underlay->stops, 0);
        main->setConnectionState(Vpn::Disconnected);
        QCOMPARE(underlay->stops, 1);
        underlay->setConnectionState(Vpn::Disconnected);
        QCOMPARE(connection.connectionState(), Vpn::Error);
    }

    void cancelsLateNativeStartWithoutStartingTun()
    {
        XrayProtocol protocol(xrayConfig());
        ipc->source.beforeReply = [&](const QString &call) {
            if (call == QStringLiteral("startXray")) {
                QTimer::singleShot(0, &protocol, [&]() { protocol.stop(); });
            }
        };
        QCOMPARE(protocol.start(), ErrorCode::NoError);
        QCOMPARE(protocol.connectionState(), Vpn::Disconnected);
        QCOMPARE(ipc->source.stoppedTokens, QList<qint64> { ipc->source.lastToken });
        QCOMPARE(ipc->process.starts, 0);
        QVERIFY(!ipc->source.calls.contains("createProcess"));
    }

    void cancelsLateProcessCreation()
    {
        XrayProtocol protocol(xrayConfig());
        ipc->source.beforeReply = [&](const QString &call) {
            if (call == QStringLiteral("createProcess")) {
                QTimer::singleShot(0, &protocol, [&]() { protocol.stop(); });
            }
        };
        QCOMPARE(protocol.start(), ErrorCode::NoError);
        QTRY_COMPARE(ipc->process.closes, 1);
        QCOMPARE(ipc->process.starts, 0);
        QCOMPARE(protocol.connectionState(), Vpn::Disconnected);
    }

    void closesProcessAfterReplicaTimeout()
    {
        QVERIFY(ipc->processHost.disableRemoting(&ipc->process));
        QTimer::singleShot(30500, this, [this]() { QVERIFY(ipc->processHost.enableRemoting(&ipc->process)); });
        XrayProtocol protocol(xrayConfig());
        QCOMPARE(protocol.start(), ErrorCode::AmneziaServiceConnectionFailed);
        protocol.stop();
        QTRY_COMPARE_WITH_TIMEOUT(ipc->process.closes, 1, 2000);
        QCOMPARE(ipc->process.starts, 0);
    }

    void closesProcessAfterCreationTimeout()
    {
        const QUrl url(QStringLiteral("local:AmneziaDelayedIpc-%1").arg(QUuid::createUuid().toString(QUuid::Id128)));
        ipc.reset();
        ipc = std::make_unique<IpcTestService>(url);
        QThread worker;
        auto *context = new QObject;
        context->moveToThread(&worker);
        connect(&worker, &QThread::finished, context, &QObject::deleteLater);
        worker.start();
        const auto cleanup = qScopeGuard([&]() {
            worker.quit();
            worker.wait();
        });
        bool enabled = false;
        QMetaObject::invokeMethod(
                context,
                [&]() {
                    auto *host = new QRemoteObjectHost(url, context);
                    auto *source = new IpcTestInterface;
                    source->setParent(host);
                    source->processId = ipc->source.processId;
                    source->beforeReply = [](const QString &call) {
                        if (call == QStringLiteral("createProcess")) {
                            QThread::msleep(31000);
                        }
                    };
                    enabled = host->enableRemoting(source);
                },
                Qt::BlockingQueuedConnection);
        QVERIFY(enabled);
        XrayProtocol protocol(xrayConfig());
        QCOMPARE(protocol.start(), ErrorCode::AmneziaServiceConnectionFailed);
        protocol.stop();
        QTRY_COMPARE_WITH_TIMEOUT(ipc->process.closes, 1, 2000);
        QCOMPARE(ipc->process.starts, 0);
    }

    void ignoresProcessCallbacksAfterStop()
    {
        XrayProtocol protocol(xrayConfig());
        QCOMPARE(protocol.start(), ErrorCode::NoError);
        QTRY_COMPARE(ipc->process.starts, 1);
        protocol.stop();
        QTRY_COMPARE(ipc->process.kills, 1);
        QVERIFY(ipc->process.waits > 0);
        ipc->process.standardOutput = "resource busy";
        emit ipc->process.finished(1, QProcess::CrashExit);
        ipc->process.standardError = "[STACK] tun://test <-> socks5://test";
        emit ipc->process.readyReadStandardError();
        QTest::qWait(500);
        QCOMPARE(ipc->process.starts, 1);
        QCOMPARE(protocol.connectionState(), Vpn::Disconnected);
        QVERIFY(!ipc->source.calls.contains("createTun"));
    }

    void rejectsConnectedWorkAfterIpcCancellation()
    {
        VpnConnection connection(servers.get(), appSettings.get());
        auto protocol = QSharedPointer<AcknowledgedProtocol>::create();
        protocol->immediateCleanup = true;
        attachMain(connection, protocol);
        bool cancelled = false;
        ipc->source.beforeReply = [&](const QString &call) {
            if (!cancelled && call == QStringLiteral("flushDns")) {
                cancelled = true;
                QTimer::singleShot(0, &connection, &VpnConnection::disconnectFromVpn);
            }
        };
        QSignalSpy states(&connection, &VpnConnection::connectionStateChanged);
        protocol->setConnectionState(Vpn::Connected);
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QVERIFY(cancelled);
        QVERIFY(!ipc->source.calls.contains("addRoutes"));
        for (const auto &event : states) {
            QVERIFY(event.first().value<Vpn::ConnectionState>() != Vpn::Connected);
        }
    }

    void cancelsDelayedSplitRoutes()
    {
        appSettings->setSitesSplitTunnelingEnabled(true);
        appSettings->setRouteMode(RouteMode::VpnOnlyForwardSites);
        appSettings->addVpnSite(RouteMode::VpnOnlyForwardSites, QStringLiteral("192.0.2.42"));
        VpnConnection connection(servers.get(), appSettings.get());
        auto protocol = QSharedPointer<AcknowledgedProtocol>::create();
        protocol->immediateCleanup = true;
        attachMain(connection, protocol);
        protocol->setConnectionState(Vpn::Connected);
        connection.disconnectFromVpn();
        ipc->source.calls.clear();
        QTest::qWait(1150);
        QVERIFY(!ipc->source.calls.contains("addRoutes"));
    }
};

QTEST_GUILESS_MAIN(TestVpnLifecycle)

#include "testVpnLifecycle.moc"
