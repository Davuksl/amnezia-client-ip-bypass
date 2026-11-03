#ifndef IPCCLIENT_H
#define IPCCLIENT_H

#include <QLocalSocket>
#include <QObject>

#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"

class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject *parent = nullptr, const QUrl &serviceUrl = { });

    static IpcClient& Instance();

    static QSharedPointer<IpcInterfaceReplica> Interface();
    static QSharedPointer<IpcProcessInterfaceReplica> CreatePrivilegedProcess();

    template <typename Func>
    static auto withInterface(Func func)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));

        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            qWarning() << "IpcClient::withInterface(): Service is not running";

            if constexpr (std::is_void_v<ReturnType>)
                return;
            else
                return ReturnType{};
        }

        return func(iface);
    }

    template <typename OnSuccess, typename OnFailure>
    static auto withInterface(OnSuccess onSuccess, OnFailure onFailure)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            return onFailure();
        }

        return onSuccess(iface);
    }
signals:

private:
#ifdef AMNEZIA_BUILD_TESTS
    friend class IpcTestService;
    static IpcClient *s_testInstance;
#endif
    QRemoteObjectNode m_node;
    QSharedPointer<IpcInterfaceReplica> m_interface;
};

#endif // IPCCLIENT_H
