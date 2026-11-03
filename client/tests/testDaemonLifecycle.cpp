#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QSignalSpy>
#include <QTest>
#include <QUuid>

#include "daemon/daemon.h"
#include "daemon/daemonlocalserverconnection.h"

class TestWireguardBackend : public WireguardUtils
{
public:
    TestWireguardBackend() : WireguardUtils(nullptr)
    {
    }

    bool interfaceExists() override
    {
        return exists;
    }
    bool isInterfaceReady(const InterfaceConfig &) const override
    {
        return addressReady;
    }
    bool addInterface(const InterfaceConfig &) override
    {
        exists = true;
        return true;
    }
    bool deleteInterface() override
    {
        ++removalAttempts;
        if (removalSucceeds) {
            exists = false;
        }
        return removalSucceeds;
    }
    bool updatePeer(const InterfaceConfig &config) override
    {
        peers = { PeerStatus(config.m_serverPublicKey) };
        return true;
    }
    bool deletePeer(const InterfaceConfig &) override
    {
        peers.clear();
        return true;
    }
    QList<PeerStatus> getPeerStatus() override
    {
        return peers;
    }
    bool updateRoutePrefix(const IPAddress &) override
    {
        ++routeUpdates;
        return true;
    }
    bool deleteRoutePrefix(const IPAddress &) override
    {
        return true;
    }
    bool addExclusionRoute(const IPAddress &) override
    {
        return exclusionSucceeds;
    }
    bool deleteExclusionRoute(const IPAddress &) override
    {
        return true;
    }
    bool excludeLocalNetworks(const QList<IPAddress> &) override
    {
        return true;
    }

    bool exists = false;
    bool addressReady = true;
    bool removalSucceeds = true;
    bool exclusionSucceeds = true;
    int removalAttempts = 0;
    int routeUpdates = 0;
    QList<PeerStatus> peers;
};

class TestDnsBackend : public DnsUtils
{
public:
    TestDnsBackend() : DnsUtils(nullptr)
    {
    }
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override
    {
        ++updates;
        return true;
    }
    bool restoreResolvers() override
    {
        ++restores;
        return true;
    }
    int updates = 0;
    int restores = 0;
};

class TestDaemonBackend : public Daemon
{
public:
    TestDaemonBackend() : Daemon(nullptr)
    {
    }
    using Daemon::checkHandshake;
    using Daemon::m_handshakeTimer;
    WireguardUtils *wgutils() const override
    {
        return const_cast<TestWireguardBackend *>(&wireguard);
    }
    DnsUtils *dnsutils() override
    {
        return &dns;
    }
    TestWireguardBackend wireguard;
    TestDnsBackend dns;
};

namespace
{
    InterfaceConfig config(InterfaceConfig::HopType hop = InterfaceConfig::MultiHopEntry)
    {
        InterfaceConfig result;
        result.m_hopType = hop;
        result.m_privateKey = QString::fromLatin1(QByteArray(32, '\x11').toBase64());
        result.m_serverPublicKey = QString::fromLatin1(QByteArray(32, '\x22').toBase64());
        result.m_deviceIpv4Address = QStringLiteral("172.16.0.2");
        result.m_serverIpv4AddrIn = QStringLiteral("192.0.2.1");
        result.m_serverIpv4Gateway = QStringLiteral("192.0.2.1");
        result.m_serverPort = 500;
        result.m_primaryDnsServer = QStringLiteral("192.0.2.53");
        result.m_excludedAddresses = { QStringLiteral("192.0.2.1") };
        result.m_allowedIPAddressRanges = { IPAddress(QStringLiteral("198.51.100.10/32")) };
        return result;
    }
}

class TestDaemonLifecycle : public QObject
{
    Q_OBJECT

private slots:
    void acknowledgesOnlyRemovedInterface()
    {
        TestDaemonBackend daemon;
        QSignalSpy disconnected(&daemon, &Daemon::disconnected);
        QVERIFY(daemon.activate(config()));
        daemon.wireguard.removalSucceeds = false;
        QVERIFY(!daemon.deactivate());
        QCOMPARE(disconnected.count(), 0);
        QVERIFY(daemon.wireguard.exists);
        daemon.wireguard.removalSucceeds = true;
        QVERIFY(daemon.deactivate());
        QCOMPARE(disconnected.count(), 1);
        QCOMPARE(daemon.wireguard.removalAttempts, 2);
        QVERIFY(!daemon.wireguard.exists);
    }

    void waitsForHandshakeAndDetectsPeerLoss()
    {
        TestDaemonBackend daemon;
        QSignalSpy connected(&daemon, &Daemon::connected);
        QVERIFY(daemon.activate(config()));
        QVERIFY(!daemon.getStatus().value("connected").toBool());
        daemon.checkHandshake();
        QCOMPARE(connected.count(), 0);
        daemon.wireguard.peers.first().m_handshake = QDateTime::currentMSecsSinceEpoch();
        daemon.checkHandshake();
        QCOMPARE(connected.count(), 1);
        QVERIFY(daemon.getStatus().value("connected").toBool());
        daemon.wireguard.peers.clear();
        QVERIFY(!daemon.getStatus().value("connected").toBool());
        QVERIFY(daemon.deactivate());
    }

    void routeOnlyTunnelDoesNotOwnResolvers()
    {
        TestDaemonBackend daemon;
        QVERIFY(daemon.activate(config()));
        QCOMPARE(daemon.dns.updates, 0);
        QVERIFY(daemon.deactivate());
        QCOMPARE(daemon.dns.restores, 0);
        QVERIFY(daemon.activate(config(InterfaceConfig::SingleHop)));
        QCOMPARE(daemon.dns.updates, 1);
        QVERIFY(daemon.deactivate());
        QCOMPARE(daemon.dns.restores, 1);
    }

    void waitsForAddressReadinessAfterHandshake()
    {
        TestDaemonBackend daemon;
        QSignalSpy connected(&daemon, &Daemon::connected);
        QVERIFY(daemon.activate(config()));
        daemon.wireguard.addressReady = false;
        daemon.wireguard.peers.first().m_handshake = QDateTime::currentMSecsSinceEpoch();
        daemon.checkHandshake();
        QCOMPARE(connected.count(), 0);
        QVERIFY(!daemon.getStatus().value("connected").toBool());
        QVERIFY(daemon.m_handshakeTimer.isActive());
        daemon.wireguard.addressReady = true;
        QTRY_COMPARE(connected.count(), 1);
        QVERIFY(daemon.getStatus().value("connected").toBool());
        daemon.checkHandshake();
        QCOMPARE(connected.count(), 1);
        QVERIFY(daemon.deactivate());
    }

    void cancellationStopsAddressReadinessWait()
    {
        TestDaemonBackend daemon;
        QSignalSpy connected(&daemon, &Daemon::connected);
        QVERIFY(daemon.activate(config()));
        daemon.wireguard.addressReady = false;
        daemon.wireguard.peers.first().m_handshake = QDateTime::currentMSecsSinceEpoch();
        daemon.checkHandshake();
        QVERIFY(daemon.m_handshakeTimer.isActive());
        QVERIFY(daemon.deactivate());
        QVERIFY(!daemon.m_handshakeTimer.isActive());
        daemon.wireguard.addressReady = true;
        daemon.checkHandshake();
        QCOMPARE(connected.count(), 0);
        QVERIFY(!daemon.getStatus().value("connected").toBool());
    }

    void refusesActivationWithoutOuterRoute()
    {
        TestDaemonBackend daemon;
        QSignalSpy failure(&daemon, &Daemon::activationFailure);
        daemon.wireguard.exclusionSucceeds = false;
        QVERIFY(!daemon.activate(config()));
        QCOMPARE(failure.count(), 1);
        QCOMPARE(daemon.wireguard.routeUpdates, 0);
        QVERIFY(daemon.wireguard.peers.isEmpty());
        QVERIFY(daemon.deactivate());
        QVERIFY(!daemon.wireguard.exists);
    }

    void socketReportsFailedCleanup()
    {
        TestDaemonBackend daemon;
        QLocalServer server;
        QVERIFY(server.listen(QStringLiteral("AmneziaDaemonTest-%1").arg(QUuid::createUuid().toString(QUuid::Id128))));
        connect(&server, &QLocalServer::newConnection, &server, [&]() {
            auto *socket = server.nextPendingConnection();
            new DaemonLocalServerConnection(socket, socket);
        });
        QLocalSocket client;
        client.connectToServer(server.fullServerName());
        QTRY_VERIFY(server.isListening() && client.state() == QLocalSocket::ConnectedState);
        QVERIFY(daemon.activate(config()));
        daemon.wireguard.removalSucceeds = false;
        client.write("{\"type\":\"deactivate\"}\n");
        QTRY_VERIFY(client.canReadLine());
        QCOMPARE(QJsonDocument::fromJson(client.readLine()).object().value("type").toString(),
                 QStringLiteral("backendFailure"));
        QVERIFY(!client.canReadLine());
        daemon.wireguard.removalSucceeds = true;
        client.write("{\"type\":\"deactivate\"}\n");
        QTRY_VERIFY(client.canReadLine());
        QCOMPARE(QJsonDocument::fromJson(client.readLine()).object().value("type").toString(),
                 QStringLiteral("disconnected"));
    }
};

QTEST_GUILESS_MAIN(TestDaemonLifecycle)

#include "testDaemonLifecycle.moc"
