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
}

class TestWarpUnderlay : public QObject
{
    Q_OBJECT

private slots:
    void serializesRegistration();
    void createsRouteOnlyAwgConfig();
    void rejectsInvalidRegistration();
    void rejectsNonIpv4Endpoints();
    void rejectsInvalidInitPacket();
    void cancelsPendingRegistration();
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
    QCOMPARE(awg.value(QStringLiteral("port")).toInt(), 500);
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
