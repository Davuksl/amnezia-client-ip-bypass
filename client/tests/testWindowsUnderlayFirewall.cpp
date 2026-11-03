#include "killswitch.h"
#include "platforms/windows/daemon/windowsfirewall.h"

#include <QTest>
#include <utility>

namespace FirewallApi
{
    struct Condition
    {
        GUID key;
        FWP_MATCH_TYPE match;
        FWP_DATA_TYPE type;
        quint32 lower = 0;
        quint32 upper = 0;
    };

    struct Filter
    {
        quint64 id;
        QString name;
        GUID layer;
        FWP_ACTION_TYPE action;
        QList<Condition> conditions;
    };

    QList<Filter> active;
    QList<Filter> pending;
    QList<quint64> removed;
    int additions = 0;
    int failAddition = 0;
    int disables = 0;
    int aborts = 0;
    bool beginSucceeds = true;
    bool commitSucceeds = true;
    quint64 sequence = 0;

    DWORD open(PCWSTR, UINT32, SEC_WINNT_AUTH_IDENTITY_W *, const FWPM_SESSION0 *, HANDLE *handle)
    {
        *handle = INVALID_HANDLE_VALUE;
        return ERROR_SUCCESS;
    }

    DWORD close(HANDLE)
    {
        return ERROR_SUCCESS;
    }

    DWORD getSublayer(HANDLE, const GUID *, FWPM_SUBLAYER0 **layer)
    {
        static FWPM_SUBLAYER0 existing { };
        *layer = &existing;
        return ERROR_SUCCESS;
    }

    void freeMemory(void **)
    {
    }

    DWORD addSublayer(HANDLE, const FWPM_SUBLAYER0 *, PSECURITY_DESCRIPTOR)
    {
        return ERROR_SUCCESS;
    }

    DWORD begin(HANDLE, UINT32)
    {
        pending = active;
        return beginSucceeds ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
    }

    DWORD commit(HANDLE)
    {
        if (!commitSucceeds) {
            return ERROR_ACCESS_DENIED;
        }
        active = pending;
        return ERROR_SUCCESS;
    }

    DWORD abort(HANDLE)
    {
        ++aborts;
        pending = active;
        return ERROR_SUCCESS;
    }

    DWORD addFilter(HANDLE, const FWPM_FILTER0 *filter, PSECURITY_DESCRIPTOR, UINT64 *id)
    {
        if (++additions == failAddition) {
            return ERROR_ACCESS_DENIED;
        }
        *id = ++sequence;
        Filter captured {
            *id, QString::fromWCharArray(filter->displayData.name), filter->layerKey, filter->action.type, { }
        };
        for (UINT32 i = 0; i < filter->numFilterConditions; ++i) {
            const auto &condition = filter->filterCondition[i];
            Condition value { condition.fieldKey, condition.matchType, condition.conditionValue.type };
            if (value.type == FWP_UINT32) {
                value.lower = value.upper = condition.conditionValue.uint32;
            } else if (value.type == FWP_RANGE_TYPE && condition.conditionValue.rangeValue->valueLow.type == FWP_UINT32) {
                value.lower = condition.conditionValue.rangeValue->valueLow.uint32;
                value.upper = condition.conditionValue.rangeValue->valueHigh.uint32;
            }
            captured.conditions.append(value);
        }
        pending.append(captured);
        return ERROR_SUCCESS;
    }

    DWORD deleteFilter(HANDLE, UINT64 id)
    {
        removed.append(id);
        pending.removeIf([id](const Filter &filter) { return filter.id == id; });
        return ERROR_SUCCESS;
    }
}

class FirewallTestKillSwitch
{
public:
    static FirewallTestKillSwitch *instance()
    {
        static FirewallTestKillSwitch instance;
        return &instance;
    }

    bool disableKillSwitch()
    {
        ++FirewallApi::disables;
        FirewallApi::active.clear();
        return true;
    }
};

#undef FwpmTransactionBegin
#define FwpmEngineOpen0        FirewallApi::open
#define FwpmEngineClose0       FirewallApi::close
#define FwpmSubLayerGetByKey0  FirewallApi::getSublayer
#define FwpmSubLayerAdd0       FirewallApi::addSublayer
#define FwpmFreeMemory0        FirewallApi::freeMemory
#define FwpmTransactionBegin   FirewallApi::begin
#define FwpmTransactionCommit0 FirewallApi::commit
#define FwpmTransactionAbort0  FirewallApi::abort
#define FwpmFilterAdd0         FirewallApi::addFilter
#define FwpmFilterDeleteById0  FirewallApi::deleteFilter
#define KillSwitch             FirewallTestKillSwitch
#include "../platforms/windows/daemon/windowsfirewall.cpp"
#undef FwpmEngineOpen0
#undef FwpmEngineClose0
#undef FwpmSubLayerGetByKey0
#undef FwpmSubLayerAdd0
#undef FwpmFreeMemory0
#undef FwpmTransactionBegin
#undef FwpmTransactionCommit0
#undef FwpmTransactionAbort0
#undef FwpmFilterAdd0
#undef FwpmFilterDeleteById0
#undef KillSwitch

class TestWindowsUnderlayFirewall : public QObject
{
    Q_OBJECT

private:
    WindowsFirewall *firewall = nullptr;

    InterfaceConfig config()
    {
        InterfaceConfig result;
        result.m_serverPublicKey = QStringLiteral("test-peer");
        result.m_allowedIPAddressRanges = { IPAddress(QStringLiteral("0.0.0.0/0")), IPAddress(QStringLiteral("::/0")) };
        result.m_excludedAddresses = { QStringLiteral("192.0.2.1") };
        return result;
    }

private slots:
    void init()
    {
        FirewallApi::active.clear();
        FirewallApi::pending.clear();
        FirewallApi::removed.clear();
        FirewallApi::additions = 0;
        FirewallApi::failAddition = 0;
        FirewallApi::disables = 0;
        FirewallApi::aborts = 0;
        FirewallApi::beginSucceeds = true;
        FirewallApi::commitSucceeds = true;
        firewall = WindowsFirewall::create(nullptr);
        QVERIFY(firewall);
    }

    void cleanup()
    {
        delete std::exchange(s_instance, nullptr);
        firewall = nullptr;
    }

    void restrictsEntryPermissionToUnderlaySource()
    {
        const QHostAddress source(QStringLiteral("172.16.0.2"));
        const QHostAddress entry(QStringLiteral("198.51.100.10"));
        QVERIFY(firewall->enablePeerTraffic(config(), source, entry));
        int permissions = 0;
        for (const auto &filter : FirewallApi::active) {
            if (filter.name != QStringLiteral("Permit VPN transport through underlay")) {
                continue;
            }
            ++permissions;
            QCOMPARE(filter.action, FWP_ACTION_PERMIT);
            QCOMPARE(filter.conditions.size(), 2);
            QVERIFY(filter.layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || filter.layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
            const auto &remote = filter.conditions.at(0);
            QVERIFY(remote.key == FWPM_CONDITION_IP_REMOTE_ADDRESS);
            QCOMPARE(remote.match, FWP_MATCH_RANGE);
            QCOMPARE(remote.lower, entry.toIPv4Address());
            QCOMPARE(remote.upper, entry.toIPv4Address());
            const auto &local = filter.conditions.at(1);
            QVERIFY(local.key == FWPM_CONDITION_IP_LOCAL_ADDRESS);
            QCOMPARE(local.match, FWP_MATCH_EQUAL);
            QCOMPARE(local.type, FWP_UINT32);
            QCOMPARE(local.lower, source.toIPv4Address());
        }
        QCOMPARE(permissions, 2);
        QCOMPARE(FirewallApi::disables, 0);
    }

    void rejectsIncompleteOrNonIpv4Binding_data()
    {
        QTest::addColumn<QString>("source");
        QTest::addColumn<QString>("entry");
        QTest::newRow("missing-source") << QString() << QStringLiteral("198.51.100.10");
        QTest::newRow("missing-entry") << QStringLiteral("172.16.0.2") << QString();
        QTest::newRow("ipv6-source") << QStringLiteral("2001:db8::2") << QStringLiteral("198.51.100.10");
        QTest::newRow("ipv6-entry") << QStringLiteral("172.16.0.2") << QStringLiteral("2001:db8::10");
    }

    void rejectsIncompleteOrNonIpv4Binding()
    {
        QFETCH(QString, source);
        QFETCH(QString, entry);
        QVERIFY(!firewall->enablePeerTraffic(config(), QHostAddress(source), QHostAddress(entry)));
        QVERIFY(FirewallApi::active.isEmpty());
        QCOMPARE(FirewallApi::additions, 0);
    }

    void preservesExistingFiltersOnFailure_data()
    {
        QTest::addColumn<QString>("failure");
        QTest::newRow("begin") << QStringLiteral("begin");
        QTest::newRow("first-underlay-permit") << QStringLiteral("first");
        QTest::newRow("second-underlay-permit") << QStringLiteral("second");
        QTest::newRow("commit") << QStringLiteral("commit");
    }

    void preservesExistingFiltersOnFailure()
    {
        QFETCH(QString, failure);
        QVERIFY(firewall->enablePeerTraffic(config()));
        const auto baseline = FirewallApi::active;
        QVERIFY(!baseline.isEmpty());
        FirewallApi::beginSucceeds = failure != QStringLiteral("begin");
        FirewallApi::commitSucceeds = failure != QStringLiteral("commit");
        if (failure == QStringLiteral("first") || failure == QStringLiteral("second")) {
            FirewallApi::failAddition =
                    FirewallApi::additions + baseline.size() + (failure == QStringLiteral("first") ? 1 : 2);
        }
        QVERIFY(!firewall->enablePeerTraffic(config(), QHostAddress("172.16.0.2"), QHostAddress("198.51.100.10")));
        QCOMPARE(FirewallApi::disables, 0);
        QCOMPARE(FirewallApi::active.size(), baseline.size());
        for (qsizetype i = 0; i < baseline.size(); ++i) {
            QCOMPARE(FirewallApi::active.at(i).id, baseline.at(i).id);
        }
        FirewallApi::beginSucceeds = true;
        FirewallApi::commitSucceeds = true;
        QVERIFY(firewall->disablePeerTraffic(config().m_serverPublicKey));
        QVERIFY(FirewallApi::active.isEmpty());
        QCOMPARE(FirewallApi::removed.size(), baseline.size());
        for (const auto &filter : baseline) {
            QVERIFY(FirewallApi::removed.contains(filter.id));
        }
    }
};

QTEST_GUILESS_MAIN(TestWindowsUnderlayFirewall)

#include "testWindowsUnderlayFirewall.moc"
