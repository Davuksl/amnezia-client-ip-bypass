#ifndef IPCTESTSERVICE_H
#define IPCTESTSERVICE_H

#include <QRemoteObjectHost>
#include <QUuid>
#include <functional>
#include <memory>

#include "core/utils/ipcClient.h"
#include "ipc.h"
#include "rep_ipc_interface_source.h"
#include "rep_ipc_process_interface_source.h"

class IpcTestProcess : public IpcProcessInterfaceSimpleSource
{
public:
    void start() override
    {
        ++starts;
        emit started();
    }
    void terminate() override
    {
        ++terminations;
    }
    void kill() override
    {
        ++kills;
    }
    void close() override
    {
        ++closes;
    }
    void setArguments(const QStringList &value) override
    {
        arguments = value;
    }
    void setInputChannelMode(QProcess::InputChannelMode) override
    {
    }
    void setNativeArguments(const QString &) override
    {
    }
    void setProcessChannelMode(QProcess::ProcessChannelMode) override
    {
    }
    void setProgram(int) override
    {
    }
    void setWorkingDirectory(const QString &) override
    {
    }
    QByteArray readAll() override
    {
        return { };
    }
    QByteArray readAllStandardError() override
    {
        return standardError;
    }
    QByteArray readAllStandardOutput() override
    {
        return standardOutput;
    }
    bool waitForFinished() override
    {
        return waitForFinished(30000);
    }
    bool waitForFinished(int) override
    {
        ++waits;
        return true;
    }
    bool waitForStarted() override
    {
        return true;
    }
    bool waitForStarted(int) override
    {
        return true;
    }

    int starts = 0;
    int kills = 0;
    int terminations = 0;
    int closes = 0;
    int waits = 0;
    QStringList arguments;
    QByteArray standardError;
    QByteArray standardOutput;
};

class IpcTestInterface : public IpcInterfaceSimpleSource
{
public:
    bool record(const QString &call)
    {
        calls.append(call);
        if (beforeReply) {
            beforeReply(call);
        }
        return !failures.contains(call);
    }

    int createPrivilegedProcess() override
    {
        record("createProcess");
        return processId;
    }
    int routeAddList(const QString &, const QStringList &ips) override
    {
        return record("addRoutes") ? ips.count() : 0;
    }
    bool clearSavedRoutes() override
    {
        return record("clearRoutes");
    }
    bool routeDeleteList(const QString &, const QStringList &) override
    {
        return record("deleteRoutes");
    }
    bool flushDns() override
    {
        return record("flushDns");
    }
    void resetIpStack() override
    {
        record("resetIpStack");
    }
    bool checkAndInstallDriver() override
    {
        return record("installDriver");
    }
    QStringList getTapList() override
    {
        return { };
    }
    void cleanUp() override
    {
        record("cleanup");
    }
    void setLogsEnabled(bool) override
    {
    }
    void clearLogs() override
    {
    }
    bool createTun(const QString &, const QString &) override
    {
        return record("createTun");
    }
    bool deleteTun(const QString &) override
    {
        return record("deleteTun");
    }
    bool StartRoutingIpv6() override
    {
        return record("enableIpv6");
    }
    bool StopRoutingIpv6() override
    {
        return record("disableIpv6");
    }
    bool disableKillSwitch() override
    {
        return record("disableKillSwitch");
    }
    bool disableAllTraffic() override
    {
        return record("disableAllTraffic");
    }
    bool refreshKillSwitch(bool) override
    {
        return record("refreshKillSwitch");
    }
    bool addKillSwitchAllowedRange(const QStringList) override
    {
        return record("allowRange");
    }
    bool resetKillSwitchAllowedRange(const QStringList) override
    {
        return record("resetRange");
    }
    bool enablePeerTraffic(const QJsonObject &) override
    {
        return record("enablePeerTraffic");
    }
    bool enableKillSwitch(const QJsonObject &, int) override
    {
        return record("enableKillSwitch");
    }
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override
    {
        return record("updateResolvers");
    }
    bool restoreResolvers() override
    {
        return record("restoreResolvers");
    }
    bool xrayStart(const QString &) override
    {
        return record("unownedStart");
    }
    bool xrayStop() override
    {
        return record("unownedStop");
    }
    qint64 xrayStartOwned(const QString &configuration) override
    {
        xrayConfiguration = configuration;
        return record("startXray") ? ++lastToken : 0;
    }
    bool xrayStopOwned(qint64 token) override
    {
        stoppedTokens.append(token);
        return record("stopXray");
    }
    qint64 xrayCurrentToken() override
    {
        return lastToken;
    }
    bool isTcpPortAvailable(int) override
    {
        return true;
    }
    bool startNetworkCheck(const QString &, const QString &) override
    {
        return record("startNetworkCheck");
    }
    bool stopNetworkCheck() override
    {
        return record("stopNetworkCheck");
    }

    QStringList calls;
    QStringList failures;
    QString xrayConfiguration;
    QList<qint64> stoppedTokens;
    std::function<void(const QString &)> beforeReply;
    qint64 lastToken = 40;
    int processId = 0;
};

class IpcTestService
{
public:
    explicit IpcTestService(const QUrl &serviceUrl = { })
        : url(QStringLiteral("local:AmneziaIpcTest-%1").arg(QUuid::createUuid().toString(QUuid::Id128))),
          host(url),
          client(nullptr, serviceUrl.isEmpty() ? url : serviceUrl)
    {
        static int sequence = 0;
        source.processId = 100000000 + static_cast<int>(QCoreApplication::applicationPid()) + ++sequence;
        processHost.setHostUrl(QUrl(QStringLiteral("local:") + amnezia::getIpcProcessUrl(source.processId)));
        enabled = host.enableRemoting(&source) && processHost.enableRemoting(&process);
        Q_ASSERT(!IpcClient::s_testInstance);
        IpcClient::s_testInstance = &client;
    }

    ~IpcTestService()
    {
        IpcClient::s_testInstance = nullptr;
    }

    QUrl url;
    IpcTestInterface source;
    IpcTestProcess process;
    QRemoteObjectHost host;
    QRemoteObjectHost processHost;
    IpcClient client;
    bool enabled = false;
};

#endif
