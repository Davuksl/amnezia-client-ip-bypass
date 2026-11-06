#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <QTimer>

#include "core/utils/warpUnderlay.h"

using namespace amnezia;

namespace
{
    WarpUnderlayConfig underlay()
    {
        return {
            QString::fromLatin1(QByteArray(32, '\x11').toBase64()),
            QString::fromLatin1(QByteArray(32, '\x22').toBase64()),
            QStringLiteral("172.16.0.2"),
            QStringLiteral("2606:4700:110::2"),
            QStringLiteral("engage.example:2408"),
        };
    }

    QJsonObject xrayServerConfig(const QString &key, const QString &address, quint16 port)
    {
        const QJsonObject server { { "address", address }, { "port", port } };
        const QJsonObject settings { { key, QJsonArray { server } } };
        const QJsonObject outbound { { "settings", settings } };
        return { { "outbounds", QJsonArray { outbound } } };
    }
}

class TestWarpUnderlay : public QObject
{
    Q_OBJECT

private slots:
    void serializesRegistration();
    void supportsAllVpnProtocols();
    void createsRouteOnlyAwgConfig();
    void rejectsInvalidRegistration();
    void rejectsNonIpv4Endpoints();
    void rejectsInvalidInitPacket();
    void cancelsPendingRegistration();
    void detectsDirectlyReachableXrayServer();
    void rejectsUnreachableOrUnmatchedXrayServer();
    void bindsOpenVpnTransport();
    void bindsProxyTransportAndPreservesTls();
    void rejectsUnmatchedXrayServer();
};

void TestWarpUnderlay::serializesRegistration()
{
    const WarpUnderlayConfig expected = underlay();
    const auto actual = WarpUnderlayConfig::fromJson(expected.toJson());
    QVERIFY(actual.has_value());
    QCOMPARE(actual->privateKey, expected.privateKey);
    QCOMPARE(actual->peerPublicKey, expected.peerPublicKey);
    QCOMPARE(actual->ipv4Address, expected.ipv4Address);
    QCOMPARE(actual->ipv6Address, expected.ipv6Address);
    QCOMPARE(actual->endpoint, expected.endpoint);
}

void TestWarpUnderlay::supportsAllVpnProtocols()
{
    for (DockerContainer container :
         { DockerContainer::Xray, DockerContainer::SSXray, DockerContainer::OpenVpn, DockerContainer::WireGuard,
           DockerContainer::Awg, DockerContainer::Awg2, DockerContainer::Ipsec }) {
        QVERIFY(WarpUnderlay::supportsProtocol(container));
    }
    QVERIFY(!WarpUnderlay::supportsProtocol(DockerContainer::None));
    QVERIFY(!WarpUnderlay::supportsProtocol(DockerContainer::Dns));
}

void TestWarpUnderlay::createsRouteOnlyAwgConfig()
{
    const auto config = WarpUnderlay::createAwgConfig(underlay(), QStringLiteral("192.0.2.1"),
                                                      QStringLiteral("198.51.100.10"), QStringLiteral("<b 0x0102>"));
    QVERIFY(config.has_value());
    QCOMPARE(config->value(QStringLiteral("protocol")).toString(), QStringLiteral("awg"));
    QCOMPARE(config->value(QStringLiteral("hopType")).toString(), QStringLiteral("MultiHopEntry"));
    QCOMPARE(config->value(QStringLiteral("killSwitchOption")).toString(), QStringLiteral("false"));

    const QJsonObject awg = config->value(QStringLiteral("awg_config_data")).toObject();
    QCOMPARE(awg.value(QStringLiteral("hostName")).toString(), QStringLiteral("192.0.2.1"));
    QCOMPARE(awg.value(QStringLiteral("port")).toInt(), 2408);
    QCOMPARE(awg.value(QStringLiteral("allowed_ips")).toArray(), QJsonArray { QStringLiteral("198.51.100.10/32") });
    QCOMPARE(awg.value(QStringLiteral("I1")).toString(), QStringLiteral("<b 0x0102>"));
    QCOMPARE(awg.value(QStringLiteral("Jc")).toString(), QStringLiteral("120"));
}

void TestWarpUnderlay::rejectsInvalidRegistration()
{
    WarpUnderlayConfig invalid = underlay();
    invalid.privateKey.clear();
    QVERIFY(!WarpUnderlay::createAwgConfig(invalid, QStringLiteral("192.0.2.1"), QStringLiteral("198.51.100.10"),
                                           QStringLiteral("<b 0x0102>"))
                     .has_value());
}

void TestWarpUnderlay::rejectsNonIpv4Endpoints()
{
    QVERIFY(!WarpUnderlay::createAwgConfig(underlay(), QStringLiteral("2001:db8::1"), QStringLiteral("198.51.100.10"),
                                           QStringLiteral("<b 0x0102>"))
                     .has_value());
    QVERIFY(!WarpUnderlay::createAwgConfig(underlay(), QStringLiteral("192.0.2.1"), QStringLiteral("2001:db8::2"),
                                           QStringLiteral("<b 0x0102>"))
                     .has_value());
}

void TestWarpUnderlay::rejectsInvalidInitPacket()
{
    QVERIFY(!WarpUnderlay::createAwgConfig(underlay(), QStringLiteral("192.0.2.1"), QStringLiteral("198.51.100.10"),
                                           QStringLiteral("invalid"))
                     .has_value());
}

void TestWarpUnderlay::cancelsPendingRegistration()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    bool cancelled = false;
    bool accepted = false;
    connect(&server, &QTcpServer::newConnection, &server, [&]() {
        accepted = true;
        QTimer::singleShot(75, &server, [&]() { cancelled = true; });
    });
    QTimer watchdog;
    watchdog.setSingleShot(true);
    connect(&watchdog, &QTimer::timeout, &server, [&]() { cancelled = true; });
    watchdog.start(2000);
    QElapsedTimer elapsed;
    elapsed.start();
    const auto config = WarpUnderlay::registerDevice(
            { QStringLiteral("https://127.0.0.1:%1/").arg(server.serverPort()) }, [&]() { return cancelled; });
    QVERIFY(!config.has_value());
    QVERIFY(accepted);
    QVERIFY(elapsed.elapsed() < 1500);
    QVERIFY(!WarpUnderlay::registerDevice({ }, []() { return true; }).has_value());
}

void TestWarpUnderlay::detectsDirectlyReachableXrayServer()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    const QJsonObject config =
            xrayServerConfig(QStringLiteral("vnext"), QStringLiteral("entry.example"), server.serverPort());
    QVERIFY(WarpUnderlay::isXrayServerReachableDirectly(config, QStringLiteral("entry.example"),
                                                        QStringLiteral("127.0.0.1"), { }, 500));
}

void TestWarpUnderlay::rejectsUnreachableOrUnmatchedXrayServer()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    const quint16 closedPort = server.serverPort();
    server.close();
    const QJsonObject config = xrayServerConfig(QStringLiteral("servers"), QStringLiteral("entry.example"), closedPort);
    QVERIFY(!WarpUnderlay::isXrayServerReachableDirectly(config, QStringLiteral("entry.example"),
                                                         QStringLiteral("127.0.0.1"), { }, 100));
    QVERIFY(!WarpUnderlay::isXrayServerReachableDirectly(config, QStringLiteral("other.example"),
                                                         QStringLiteral("127.0.0.1"), { }, 100));
    QVERIFY(!WarpUnderlay::isXrayServerReachableDirectly(
            config, QStringLiteral("entry.example"), QStringLiteral("127.0.0.1"), []() { return true; }, 100));
}

void TestWarpUnderlay::bindsOpenVpnTransport()
{
    const QString config =
            QStringLiteral("client\nremote vpn.example 1194 udp\nredirect-gateway def1\nlocal 192.0.2.2\n");
    const QString bound =
            WarpUnderlay::bindOpenVpnConfig(config, QStringLiteral("198.51.100.10"), QStringLiteral("172.16.0.2"));
    QVERIFY(bound.contains(QStringLiteral("remote 198.51.100.10 1194 udp")));
    QVERIFY(bound.contains(QStringLiteral("redirect-gateway def1 local")));
    QCOMPARE(bound.count(QStringLiteral("local 172.16.0.2")), 1);
    QVERIFY(!bound.contains(QStringLiteral("local 192.0.2.2")));
}

void TestWarpUnderlay::bindsProxyTransportAndPreservesTls()
{
    const QJsonObject outbound {
        { "protocol", "vless" },
        { "settings",
          QJsonObject { { "vnext", QJsonArray { QJsonObject { { "address", "entry.example" }, { "port", 443 } } } } } },
        { "streamSettings",
          QJsonObject { { "security", "tls" },
                        { "tlsSettings", QJsonObject { { "serverName", "tls.example" } } },
                        { "sockopt", QJsonObject { { "tcpFastOpen", true } } } } }
    };
    const QJsonObject original { { "outbounds", QJsonArray { outbound } } };
    const auto bound = WarpUnderlay::bindXrayConfig(original, QStringLiteral("172.16.0.2"), QStringLiteral("test-awg"),
                                                    QStringLiteral("entry.example"), QStringLiteral("198.51.100.10"));
    QVERIFY(bound.has_value());
    const auto proxy = bound->value("outbounds").toArray().first().toObject();
    QCOMPARE(proxy.value("sendThrough").toString(), QStringLiteral("172.16.0.2"));
    const auto stream = proxy.value("streamSettings").toObject();
    QCOMPARE(stream.value("sockopt").toObject().value("interface").toString(), QStringLiteral("test-awg"));
    QVERIFY(stream.value("sockopt").toObject().value("tcpFastOpen").toBool());
    QCOMPARE(stream.value("tlsSettings"), outbound.value("streamSettings").toObject().value("tlsSettings"));
    QCOMPARE(proxy.value("settings").toObject().value("vnext").toArray().first().toObject().value("address").toString(),
             QStringLiteral("198.51.100.10"));
    QVERIFY(!original.value("outbounds").toArray().first().toObject().contains("sendThrough"));
}

void TestWarpUnderlay::rejectsUnmatchedXrayServer()
{
    const QJsonObject config { { "outbounds", QJsonArray { QJsonObject { { "protocol", "freedom" } } } } };
    QVERIFY(!WarpUnderlay::bindXrayConfig(config, QStringLiteral("172.16.0.2"), QStringLiteral("test-awg"),
                                          QStringLiteral("entry.example"), QStringLiteral("198.51.100.10")));
}

QTEST_GUILESS_MAIN(TestWarpUnderlay)

#include "testWarpUnderlay.moc"
