#ifndef WARPUNDERLAY_H
#define WARPUNDERLAY_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <functional>
#include <optional>

namespace amnezia
{
    struct WarpUnderlayConfig
    {
        QString privateKey;
        QString peerPublicKey;
        QString ipv4Address;
        QString ipv6Address;
        QString endpoint;

        bool isValid() const;
        QJsonObject toJson() const;
        static std::optional<WarpUnderlayConfig> fromJson(const QJsonObject &json);
    };

    class WarpUnderlay
    {
    public:
        static std::optional<WarpUnderlayConfig> registerDevice(const QStringList &apiBases = { },
                                                                const std::function<bool()> &isCancelled = { });
        static std::optional<QJsonObject> createAwgConfig(const WarpUnderlayConfig &config,
                                                          const QString &warpEndpointAddress,
                                                          const QString &vpnServerAddress, const QString &initPacket);
        static std::optional<QJsonObject> bindXrayConfig(const QJsonObject &config, const QString &sourceAddress,
                                                         const QString &interfaceName, const QString &serverHost,
                                                         const QString &serverAddress);
    };
}

#endif // WARPUNDERLAY_H
