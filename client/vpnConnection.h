#ifndef VPNCONNECTION_H
#define VPNCONNECTION_H

#include <QMetaObject>
#include <QObject>
#include <QRemoteObjectNode>
#include <QScopedPointer>
#include <QString>
#include <QTimer>
#include <functional>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"

#ifdef AMNEZIA_DESKTOP
#include "core/utils/ipcClient.h"
#endif

#ifdef Q_OS_ANDROID
#include "core/protocols/androidVpnProtocol.h"
#endif

using namespace amnezia;

class VpnConnection : public QObject
{
    Q_OBJECT

public:
    explicit VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject* parent = nullptr);
    ~VpnConnection() override;

    static QString bytesPerSecToText(quint64 bytes);

    ErrorCode lastError() const;
    Vpn::ConnectionState connectionState() const;

    QSharedPointer<VpnProtocol> vpnProtocol() const;

    const QString &remoteAddress() const;
    void addSitesRoutes(const QString &gw, amnezia::RouteMode mode);

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif

public slots:
    void setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository);
    void connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    void reconnectToVpn();
    void disconnectFromVpn();

    void onKillSwitchModeChanged(bool enabled);
    void disconnectSlots();

    void setConnectionState(Vpn::ConnectionState state);

signals:
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void connectionStateChanged(Vpn::ConnectionState state);
    void vpnProtocolError(amnezia::ErrorCode error);

    void serviceIsNotReady();

protected slots:
    void onBytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void onConnectionStateChanged(Vpn::ConnectionState state);

protected:
    QSharedPointer<VpnProtocol> m_vpnProtocol;

private:
#ifdef AMNEZIA_BUILD_TESTS
    friend class TestVpnLifecycle;
#endif
    QSharedPointer<VpnProtocol> m_underlayProtocol;
    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;

    QJsonObject m_vpnConfiguration;
    QJsonObject m_underlayConfiguration;
    QJsonObject m_routeMode;
    QString m_remoteAddress;

    // Only for iOS for now, check counters
    QTimer m_checkTimer;
    QTimer m_underlayTimer;

#ifdef Q_OS_ANDROID
   AndroidVpnProtocol* androidVpnProtocol = nullptr;

   AndroidVpnProtocol* createDefaultAndroidVpnProtocol();
   void createAndroidConnections();
#endif

   Vpn::ConnectionState m_connectionState;
   bool m_useWarpUnderlay = false;
   bool m_mainProtocolStarted = false;
   bool m_underlayStopping = false;
   int m_activeOperations = 0;
   bool m_disconnecting = false;
   bool m_mainRestartPending = false;
   bool m_underlayRestartPending = false;
   bool m_recoveringUnderlay = false;
   int m_underlayRestartDelay = 0;
   quint64 m_generation = 0;
   ErrorCode m_disconnectError = ErrorCode::NoError;
   std::function<void()> m_pendingConnection;

   void createProtocolConnections();
   void startPreparedProtocol();
   void startWarpUnderlay();
   void stopWarpUnderlay();
   void retryWarpUnderlay(ErrorCode error, int delay = 0);
   void onProtocolStateChanged(Vpn::ConnectionState state);
   void onUnderlayStateChanged(Vpn::ConnectionState state);
   void stopProtocols(ErrorCode error = ErrorCode::NoError);
   void finishDisconnect();
   void finishProtocolOperation();

   void appendSplitTunnelingConfig();
   void appendKillSwitchConfig();
   bool prepareWarpUnderlay(quint64 generation);
};

#endif // VPNCONNECTION_H
