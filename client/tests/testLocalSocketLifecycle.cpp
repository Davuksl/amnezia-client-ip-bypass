#include <QJsonArray>
#include <QSignalSpy>
#include <QTest>

#include "core/utils/warpUnderlay.h"
#include "mozilla/localsocketcontroller.h"
#include "utils/localSocketTestPeer.h"

namespace
{
    QJsonObject routeOnlyConfig(char peer = '\x22')
    {
        const amnezia::WarpUnderlayConfig registration { QString::fromLatin1(QByteArray(32, '\x11').toBase64()),
                                                         QString::fromLatin1(QByteArray(32, peer).toBase64()),
                                                         QStringLiteral("172.16.0.2"), QStringLiteral("2001:db8::2"),
                                                         QStringLiteral("192.0.2.1:2408") };
        return *amnezia::WarpUnderlay::createAwgConfig(registration, QStringLiteral("192.0.2.1"),
                                                       QStringLiteral("198.51.100.10"), QStringLiteral("<b 0x0102>"));
    }

    QJsonObject status(bool connected = false)
    {
        return { { "type", "status" }, { "connected", connected } };
    }

    QJsonObject connectedMessage(char peer = '\x22')
    {
        return { { "type", "connected" }, { "pubkey", QString::fromLatin1(QByteArray(32, peer).toBase64()) } };
    }
}

class TestLocalSocketLifecycle : public QObject
{
    Q_OBJECT

private slots:
    void supportsNumericAndLegacyStringPorts_data()
    {
        QTest::addColumn<QJsonValue>("port");
        QTest::newRow("numeric") << QJsonValue(500);
        QTest::newRow("legacy-string") << QJsonValue(QStringLiteral("500"));
    }

    void supportsNumericAndLegacyStringPorts()
    {
        QFETCH(QJsonValue, port);
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        auto config = routeOnlyConfig();
        auto awg = config.value("awg_config_data").toObject();
        awg.insert("port", port);
        config.insert("awg_config_data", awg);
        controller.activate(config);
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        QCOMPARE(peer.last("activate").value("serverPort").toInt(), 500);
    }

    void queuesActivationUntilInitialization()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        QCOMPARE(peer.count("activate"), 0);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        const auto request = peer.last("activate");
        QCOMPARE(request.value("hopType").toString(), QStringLiteral("MultiHopEntry"));
        QCOMPARE(request.value("serverPort").toInt(), 2408);
        QVERIFY(!request.contains("deviceIpv6Address"));
        QVERIFY(!request.contains("primaryDnsServer"));
        QCOMPARE(request.value("I1").toString(), QStringLiteral("<b 0x0102>"));
        QCOMPARE(request.value("allowedIPAddressRanges").toArray().size(), 1);
    }

    void forwardsIndependentUnderlayConfiguration()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QJsonObject config = routeOnlyConfig();
        config.insert("hopType", "MultiHopExit");
        config.insert("underlayEndpoint", "192.0.2.1");
        config.insert("underlayAddress", "172.16.0.2");
        config.insert("underlayServerAddress", "198.51.100.10");
        controller.activate(config);
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        const QJsonObject request = peer.last("activate");
        QCOMPARE(request.value("hopType").toString(), QStringLiteral("MultiHopExit"));
        QCOMPARE(request.value("underlayAddress").toString(), QStringLiteral("172.16.0.2"));
        QCOMPARE(request.value("underlayServerAddress").toString(), QStringLiteral("198.51.100.10"));
        QVERIFY(request.value("excludedAddresses").toArray().isEmpty());
    }

    void cancelsInitialization()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy disconnected(&controller, &ControllerImpl::disconnected);
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        controller.deactivate();
        QCOMPARE(disconnected.count(), 1);
        peer.send(status());
        QTest::qWait(75);
        QCOMPARE(peer.count("activate"), 0);
        QCOMPARE(peer.count("deactivate"), 0);
    }

    void waitsForCleanupAcknowledgment()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy disconnected(&controller, &ControllerImpl::disconnected);
        QSignalSpy connected(&controller, &ControllerImpl::connected);
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        controller.deactivate();
        QTRY_COMPARE(peer.count("deactivate"), 1);
        peer.send(connectedMessage());
        QTest::qWait(75);
        QCOMPARE(disconnected.count(), 0);
        QCOMPARE(connected.count(), 0);
        controller.deactivate();
        QCOMPARE(peer.count("deactivate"), 1);
        peer.send({ { "type", "disconnected" } });
        QTRY_COMPARE(disconnected.count(), 1);
        peer.send({ { "type", "disconnected" } });
        QTest::qWait(75);
        QCOMPARE(disconnected.count(), 1);
    }

    void queuesReplacementUntilCleanup()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        controller.deactivate();
        controller.activate(routeOnlyConfig('\x33'));
        QTRY_COMPARE(peer.count("deactivate"), 1);
        QCOMPARE(peer.count("activate"), 1);
        peer.send({ { "type", "disconnected" } });
        QTRY_COMPARE(peer.count("activate"), 2);
        QCOMPARE(peer.last("activate").value("serverPublicKey").toString(),
                 QString::fromLatin1(QByteArray(32, '\x33').toBase64()));
    }

    void filtersStaleAndDuplicateHandshakes()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy connected(&controller, &ControllerImpl::connected);
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        peer.send(connectedMessage('\x33'));
        QTest::qWait(75);
        QCOMPARE(connected.count(), 0);
        peer.send(connectedMessage());
        QTRY_COMPARE(connected.count(), 1);
        peer.send(connectedMessage());
        QTest::qWait(75);
        QCOMPARE(connected.count(), 1);
        QTRY_VERIFY_WITH_TIMEOUT(peer.count("status") >= 3, 3000);
        peer.send(status());
        QTRY_COMPARE(peer.count("deactivate"), 1);
    }

    void suppressesHandshakeAfterReentrantCancellation()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy connected(&controller, &ControllerImpl::connected);
        connect(&controller, &ControllerImpl::statusUpdated, &controller, [&]() { controller.deactivate(); });
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        peer.send(connectedMessage());
        QTRY_COMPARE(peer.count("deactivate"), 1);
        QCOMPARE(connected.count(), 0);
    }

    void reconnectsToFinishCleanupAfterSocketLoss()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy disconnected(&controller, &ControllerImpl::disconnected);
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        peer.sockets.last()->abort();
        QTRY_COMPARE_WITH_TIMEOUT(peer.count("status"), 2, 3000);
        QCOMPARE(disconnected.count(), 0);
        peer.send(status());
        QTRY_COMPARE(peer.count("deactivate"), 1);
        QCOMPARE(disconnected.count(), 0);
        peer.send({ { "type", "disconnected" } });
        QTRY_COMPARE(disconnected.count(), 1);
    }

    void retriesFailedCleanup()
    {
        LocalSocketTestPeer peer;
        QVERIFY(peer.listening);
        LocalSocketController controller(peer.server.fullServerName());
        QSignalSpy disconnected(&controller, &ControllerImpl::disconnected);
        controller.activate(routeOnlyConfig());
        QTRY_COMPARE(peer.count("status"), 1);
        peer.send(status());
        QTRY_COMPARE(peer.count("activate"), 1);
        controller.deactivate();
        QTRY_COMPARE(peer.count("deactivate"), 1);
        peer.send({ { "type", "backendFailure" }, { "errorCode", 1 } });
        QTRY_COMPARE_WITH_TIMEOUT(peer.count("deactivate"), 2, 6500);
        QCOMPARE(disconnected.count(), 0);
        peer.send({ { "type", "disconnected" } });
        QTRY_COMPARE(disconnected.count(), 1);
    }
};

QTEST_GUILESS_MAIN(TestLocalSocketLifecycle)

#include "testLocalSocketLifecycle.moc"
