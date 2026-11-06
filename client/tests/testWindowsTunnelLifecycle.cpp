#include "platforms/windows/daemon/windowstunnelservice.h"
#include "platforms/windows/windowscommons.h"
#include <QDir>
#include <QTemporaryDir>
#include <QTest>
#include <Windows.h>

namespace TunnelApi
{
    bool exists = false;
    bool descriptionSucceeds = true;
    bool startSucceeds = true;
    bool stopSucceeds = true;
    DWORD state = SERVICE_STOPPED;
    DWORD sid = 0;
    int deletions = 0;
    int closedServices = 0;
    int stopRequests = 0;
    QString serviceName;
    QString commandLine;
    QTemporaryDir logs;
    const SC_HANDLE scm = reinterpret_cast<SC_HANDLE>(quintptr(1));
    const SC_HANDLE service = reinterpret_cast<SC_HANDLE>(quintptr(2));

    SC_HANDLE openManager(LPCWSTR, LPCWSTR, DWORD)
    {
        return scm;
    }
    SC_HANDLE openService(SC_HANDLE, LPCWSTR, DWORD)
    {
        return exists ? service : nullptr;
    }
    SC_HANDLE createService(SC_HANDLE, LPCWSTR name, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR command, LPCWSTR,
                            LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR)
    {
        serviceName = QString::fromWCharArray(name);
        commandLine = QString::fromWCharArray(command);
        exists = true;
        state = SERVICE_STOPPED;
        return service;
    }
    BOOL changeConfig(SC_HANDLE, DWORD level, LPVOID value)
    {
        if (level == SERVICE_CONFIG_SERVICE_SID_INFO) {
            sid = static_cast<SERVICE_SID_INFO *>(value)->dwServiceSidType;
        }
        return level != SERVICE_CONFIG_DESCRIPTION || descriptionSucceeds;
    }
    BOOL startService(SC_HANDLE, DWORD, LPCWSTR *)
    {
        if (startSucceeds) {
            state = SERVICE_RUNNING;
        }
        return startSucceeds;
    }
    BOOL queryStatus(SC_HANDLE, LPSERVICE_STATUS status)
    {
        *status = { };
        status->dwCurrentState = state;
        return true;
    }
    BOOL controlService(SC_HANDLE, DWORD, LPSERVICE_STATUS status)
    {
        ++stopRequests;
        if (stopSucceeds) {
            state = SERVICE_STOPPED;
        }
        status->dwCurrentState = state;
        return stopSucceeds;
    }
    BOOL deleteService(SC_HANDLE)
    {
        ++deletions;
        exists = false;
        return true;
    }
    BOOL closeService(SC_HANDLE handle)
    {
        if (handle == service) {
            ++closedServices;
        }
        return true;
    }
    void wait(DWORD)
    {
    }
}

class TunnelTestPaths
{
public:
    static QString tunnelLogFile()
    {
        return TunnelApi::logs.filePath(QStringLiteral("unused.log"));
    }
};

#undef OpenSCManager
#undef OpenService
#undef CreateService
#undef ChangeServiceConfig2
#undef StartService
#define OpenSCManager        TunnelApi::openManager
#define OpenService          TunnelApi::openService
#define CreateService        TunnelApi::createService
#define ChangeServiceConfig2 TunnelApi::changeConfig
#define StartService         TunnelApi::startService
#define QueryServiceStatus   TunnelApi::queryStatus
#define ControlService       TunnelApi::controlService
#define DeleteService        TunnelApi::deleteService
#define CloseServiceHandle   TunnelApi::closeService
#define Sleep                TunnelApi::wait
#define WindowsCommons       TunnelTestPaths
#include "../platforms/windows/daemon/windowstunnelservice.cpp"
#undef OpenSCManager
#undef OpenService
#undef CreateService
#undef ChangeServiceConfig2
#undef StartService
#undef QueryServiceStatus
#undef ControlService
#undef DeleteService
#undef CloseServiceHandle
#undef Sleep
#undef WindowsCommons

class TestWindowsTunnelLifecycle : public QObject
{
    Q_OBJECT

private slots:
    void init()
    {
        TunnelApi::exists = false;
        TunnelApi::descriptionSucceeds = true;
        TunnelApi::startSucceeds = true;
        TunnelApi::stopSucceeds = true;
        TunnelApi::state = SERVICE_STOPPED;
        TunnelApi::sid = 0;
        TunnelApi::deletions = 0;
        TunnelApi::closedServices = 0;
        TunnelApi::stopRequests = 0;
        TunnelApi::serviceName.clear();
        TunnelApi::commandLine.clear();
    }

    void cleansUpFailedConfigurationAndCanRestart()
    {
        WindowsTunnelService tunnel;
        TunnelApi::descriptionSucceeds = false;
        QVERIFY(!tunnel.start(QStringLiteral("[Interface]\n")));
        QCOMPARE(TunnelApi::deletions, 1);
        QCOMPARE(TunnelApi::closedServices, 1);
        QVERIFY(!TunnelApi::exists);
        TunnelApi::descriptionSucceeds = true;
        QVERIFY(tunnel.start(QStringLiteral("[Interface]\n")));
        QCOMPARE(TunnelApi::sid, DWORD(SERVICE_SID_TYPE_UNRESTRICTED));
        QVERIFY(tunnel.isRunning());
        QVERIFY(tunnel.stop());
        QCOMPARE(TunnelApi::deletions, 2);
        QCOMPARE(TunnelApi::closedServices, 2);
    }

    void cleansUpFailedStart()
    {
        WindowsTunnelService tunnel;
        TunnelApi::startSucceeds = false;
        QVERIFY(!tunnel.start(QStringLiteral("[Interface]\n")));
        QCOMPARE(TunnelApi::deletions, 1);
        QCOMPARE(TunnelApi::closedServices, 1);
        QVERIFY(!TunnelApi::exists);
        QVERIFY(tunnel.stop());
        QCOMPARE(TunnelApi::deletions, 1);
    }

    void retainsOwnershipUntilServiceStops()
    {
        WindowsTunnelService tunnel;
        QVERIFY(tunnel.start(QStringLiteral("[Interface]\n")));
        TunnelApi::stopSucceeds = false;
        QVERIFY(!tunnel.stop());
        QCOMPARE(TunnelApi::deletions, 0);
        QCOMPARE(TunnelApi::closedServices, 0);
        QVERIFY(tunnel.isRunning());
        QVERIFY(!tunnel.start(QStringLiteral("[Interface]\n")));
        TunnelApi::stopSucceeds = true;
        QVERIFY(tunnel.stop());
        QCOMPARE(TunnelApi::deletions, 1);
        QCOMPARE(TunnelApi::closedServices, 1);
        QVERIFY(!tunnel.isRunning());
    }

    void usesIndependentInterfaceName()
    {
        WindowsTunnelService tunnel(QStringLiteral("AmneziaWARPUnderlay"));
        QVERIFY(tunnel.start(QStringLiteral("[Interface]\n")));
        QCOMPARE(TunnelApi::serviceName, QStringLiteral("AmneziaWGTunnel$AmneziaWARPUnderlay"));
        QVERIFY(TunnelApi::commandLine.endsWith(QStringLiteral("\"AmneziaWARPUnderlay\"")));
        QVERIFY(tunnel.stop());
    }
};

QTEST_GUILESS_MAIN(TestWindowsTunnelLifecycle)

#include "testWindowsTunnelLifecycle.moc"
