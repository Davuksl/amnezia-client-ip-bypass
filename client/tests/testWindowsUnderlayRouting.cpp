#include "platforms/windows/daemon/windowsroutemonitor.h"

#include <QTest>
#include <algorithm>
#include <cstdlib>

namespace RouteApi
{
    QList<MIB_IPFORWARD_ROW2> routes;
    QList<MIB_IPINTERFACE_ROW> adapters;
    QList<MIB_IPFORWARD_ROW2> created;
    QList<MIB_IPFORWARD_ROW2> deleted;
    DWORD creationResult = NO_ERROR;

    NETIO_STATUS getRoutes(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2 *table)
    {
        *table = static_cast<PMIB_IPFORWARD_TABLE2>(
                std::calloc(1, sizeof(MIB_IPFORWARD_TABLE2) + routes.size() * sizeof(MIB_IPFORWARD_ROW2)));
        (*table)->NumEntries = routes.size();
        std::copy(routes.cbegin(), routes.cend(), (*table)->Table);
        return NO_ERROR;
    }

    NETIO_STATUS getAdapters(ADDRESS_FAMILY, PMIB_IPINTERFACE_TABLE *table)
    {
        *table = static_cast<PMIB_IPINTERFACE_TABLE>(
                std::calloc(1, sizeof(MIB_IPINTERFACE_TABLE) + adapters.size() * sizeof(MIB_IPINTERFACE_ROW)));
        (*table)->NumEntries = adapters.size();
        std::copy(adapters.cbegin(), adapters.cend(), (*table)->Table);
        return NO_ERROR;
    }

    NETIO_STATUS add(const MIB_IPFORWARD_ROW2 *route)
    {
        created.append(*route);
        return creationResult;
    }

    NETIO_STATUS remove(const MIB_IPFORWARD_ROW2 *route)
    {
        deleted.append(*route);
        return NO_ERROR;
    }

    NETIO_STATUS notify(ADDRESS_FAMILY, PIPFORWARD_CHANGE_CALLBACK, PVOID, BOOLEAN, HANDLE *handle)
    {
        *handle = nullptr;
        return NO_ERROR;
    }

    NETIO_STATUS cancel(HANDLE)
    {
        return NO_ERROR;
    }

    MIB_IPFORWARD_ROW2 route(const QString &prefix, const QString &gateway, quint64 luid, ULONG metric)
    {
        const auto subnet = QHostAddress::parseSubnet(prefix);
        MIB_IPFORWARD_ROW2 result;
        InitializeIpForwardEntry(&result);
        result.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        result.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(subnet.first.toIPv4Address());
        result.DestinationPrefix.PrefixLength = subnet.second;
        result.NextHop.Ipv4.sin_family = AF_INET;
        result.NextHop.Ipv4.sin_addr.s_addr = htonl(QHostAddress(gateway).toIPv4Address());
        result.InterfaceLuid.Value = luid;
        result.Metric = metric;
        result.Protocol = MIB_IPPROTO_NETMGMT;
        return result;
    }
}

#define GetIpForwardTable2     RouteApi::getRoutes
#define GetIpInterfaceTable    RouteApi::getAdapters
#define FreeMibTable           std::free
#define CreateIpForwardEntry2  RouteApi::add
#define DeleteIpForwardEntry2  RouteApi::remove
#define NotifyRouteChange2     RouteApi::notify
#define CancelMibChangeNotify2 RouteApi::cancel
#include "../platforms/windows/daemon/windowsroutemonitor.cpp"
#undef GetIpForwardTable2
#undef GetIpInterfaceTable
#undef FreeMibTable
#undef CreateIpForwardEntry2
#undef DeleteIpForwardEntry2
#undef NotifyRouteChange2
#undef CancelMibChangeNotify2

class TestWindowsUnderlayRouting : public QObject
{
    Q_OBJECT

private slots:
    void init()
    {
        RouteApi::routes = { RouteApi::route("0.0.0.0/0", "192.0.2.1", 10, 25),
                             RouteApi::route("198.51.100.0/24", "192.0.2.2", 20, 1),
                             RouteApi::route("128.0.0.0/1", "192.0.2.2", 20, 1) };
        RouteApi::adapters.clear();
        for (quint64 luid : { 10, 20, 30 }) {
            MIB_IPINTERFACE_ROW adapter { };
            adapter.Family = AF_INET;
            adapter.InterfaceLuid.Value = luid;
            adapter.Connected = true;
            adapter.Metric = 10;
            RouteApi::adapters.append(adapter);
        }
        RouteApi::created.clear();
        RouteApi::deleted.clear();
        RouteApi::creationResult = NO_ERROR;
    }

    void selectsDefaultUplinkForUnderlay()
    {
        {
            WindowsRouteMonitor monitor(30, nullptr, true);
            QVERIFY(monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
            QCOMPARE(RouteApi::created.size(), 1);
            QCOMPARE(RouteApi::created.first().InterfaceLuid.Value, quint64(10));
            QCOMPARE(RouteApi::created.first().DestinationPrefix.PrefixLength, UCHAR(32));
            QCOMPARE(ntohl(RouteApi::created.first().NextHop.Ipv4.sin_addr.s_addr),
                     QHostAddress("192.0.2.1").toIPv4Address());
            QVERIFY(RouteApi::deleted.isEmpty());
        }
        QCOMPARE(RouteApi::deleted.size(), 1);
        QCOMPARE(RouteApi::deleted.first().InterfaceLuid.Value, quint64(10));
    }

    void preservesLongestPrefixForOrdinaryTunnel()
    {
        WindowsRouteMonitor monitor(30, nullptr);
        QVERIFY(monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
        QCOMPARE(RouteApi::created.first().InterfaceLuid.Value, quint64(20));
    }

    void neverDeletesExistingUnownedRoute()
    {
        RouteApi::creationResult = ERROR_OBJECT_ALREADY_EXISTS;
        {
            WindowsRouteMonitor monitor(30, nullptr, true);
            QVERIFY(monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
            QVERIFY(monitor.deleteExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
        }
        QVERIFY(RouteApi::deleted.isEmpty());
    }

    void neverOwnsFailedCreation()
    {
        RouteApi::creationResult = ERROR_ACCESS_DENIED;
        {
            WindowsRouteMonitor monitor(30, nullptr, true);
            QVERIFY(!monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
        }
        QVERIFY(RouteApi::deleted.isEmpty());
    }

    void recoversRouteAfterCreationFailure()
    {
        RouteApi::creationResult = ERROR_ACCESS_DENIED;
        {
            WindowsRouteMonitor monitor(30, nullptr, true);
            QVERIFY(!monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
            RouteApi::creationResult = NO_ERROR;
            monitor.routeChanged();
            QCOMPARE(RouteApi::created.size(), 2);
            QVERIFY(RouteApi::deleted.isEmpty());
        }
        QCOMPARE(RouteApi::deleted.size(), 1);
    }

    void removesOnlyOwnedRouteWhenUplinkDisappears()
    {
        WindowsRouteMonitor monitor(30, nullptr, true);
        QVERIFY(monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
        RouteApi::routes.removeFirst();
        monitor.routeChanged();
        QCOMPARE(RouteApi::deleted.size(), 1);
        QCOMPARE(RouteApi::deleted.first().InterfaceLuid.Value, quint64(10));
        monitor.flushExclusionRoutes();
        QCOMPARE(RouteApi::deleted.size(), 1);
    }

    void rejectsMissingDefaultUplink()
    {
        RouteApi::routes.removeFirst();
        WindowsRouteMonitor monitor(30, nullptr, true);
        QVERIFY(!monitor.addExclusionRoute(IPAddress(QStringLiteral("198.51.100.10"))));
        QVERIFY(RouteApi::created.isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestWindowsUnderlayRouting)

#include "testWindowsUnderlayRouting.moc"
