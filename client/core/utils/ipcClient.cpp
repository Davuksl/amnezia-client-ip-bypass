#include "ipcClient.h"
#include "ipc.h"
#include <QRemoteObjectNode>
#include <QRemoteObjectPendingCallWatcher>
#include <QtNetwork/qlocalsocket.h>

namespace
{
    QSharedPointer<IpcProcessInterfaceReplica> acquireProcessReplica(int pid)
    {
        auto *node = new QRemoteObjectNode();
        node->connectToNode(QUrl(QString("local:%1").arg(amnezia::getIpcProcessUrl(pid))));
        return QSharedPointer<IpcProcessInterfaceReplica>(node->acquire<IpcProcessInterfaceReplica>(),
                                                          [node](IpcProcessInterfaceReplica *replica) {
                                                              delete replica;
                                                              node->deleteLater();
                                                          });
    }

    void closeProcessWhenReady(const QSharedPointer<IpcProcessInterfaceReplica> &process, QObject *owner)
    {
        if (!process) {
            return;
        }
        if (process->isReplicaValid()) {
            process->close();
            return;
        }
        auto *cleanup = new QObject(owner);
        QObject::connect(process.data(), &QRemoteObjectReplica::stateChanged, cleanup,
                         [process, cleanup](QRemoteObjectReplica::State state) {
                             if (state == QRemoteObjectReplica::Valid) {
                                 process->close();
                                 cleanup->deleteLater();
                             }
                         });
    }
}

#ifdef AMNEZIA_BUILD_TESTS
IpcClient *IpcClient::s_testInstance = nullptr;
#endif

IpcClient::IpcClient(QObject *parent, const QUrl &serviceUrl) : QObject(parent)
{
    m_node.connectToNode(serviceUrl.isEmpty() ? QUrl("local:" + amnezia::getIpcServiceUrl()) : serviceUrl);
    m_interface.reset(m_node.acquire<IpcInterfaceReplica>());
}

IpcClient& IpcClient::Instance()
{
#ifdef AMNEZIA_BUILD_TESTS
    if (s_testInstance) {
        return *s_testInstance;
    }
#endif
    thread_local IpcClient ipcClient;
    return ipcClient;
}

QSharedPointer<IpcInterfaceReplica> IpcClient::Interface()
{
    QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
    if (rep.isNull()) {
        qCritical() << "IpcClient::Interface(): Failed to acquire replica";
        return nullptr;
    }
    if (!rep->waitForSource(1000)) {
        qCritical() << "IpcClient::Interface(): Failed to initialize replica";
        return nullptr;
    }
    if (!rep->isReplicaValid()) {
        qWarning() << "IpcClient::Interface(): Replica is invalid";
    }
    return rep;
}

QSharedPointer<IpcProcessInterfaceReplica> IpcClient::CreatePrivilegedProcess()
{
    return withInterface([](QSharedPointer<IpcInterfaceReplica> &iface) -> QSharedPointer<IpcProcessInterfaceReplica> {
        auto createPrivilegedProcess = iface->createPrivilegedProcess();
        if (!createPrivilegedProcess.waitForFinished()) {
            qCritical() << "Failed to create privileged process";
            auto *watcher = new QRemoteObjectPendingCallWatcher(createPrivilegedProcess, iface.data());
            connect(watcher, &QRemoteObjectPendingCallWatcher::finished, iface.data(),
                    [owner = iface.data()](QRemoteObjectPendingCallWatcher *call) {
                        const int pid = call->returnValue().toInt();
                        if (call->error() == QRemoteObjectPendingCall::NoError && pid > 0) {
                            closeProcessWhenReady(acquireProcessReplica(pid), owner);
                        }
                        call->deleteLater();
                    });
            return nullptr;
        }

        const int pid = createPrivilegedProcess.returnValue();

        const auto rep = acquireProcessReplica(pid);
        if (rep.isNull()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to acquire replica";
            return nullptr;
        }
        if (!rep->waitForSource()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to initialize replica";
            closeProcessWhenReady(rep, iface.data());
            return nullptr;
        }
        if (!rep->isReplicaValid()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Replica is invalid";
            closeProcessWhenReady(rep, iface.data());
            return nullptr;
        }

        return rep;
    },
    []() -> QSharedPointer<IpcProcessInterfaceReplica> {
        return nullptr;
    });
}
