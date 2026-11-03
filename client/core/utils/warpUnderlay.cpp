#include "warpUnderlay.h"

#include <QDateTime>
#include <QEventLoop>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPair>
#include <QTimer>
#include <QUrl>

#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "cryptoUtils.h"

namespace
{
    constexpr char directApiBase[] = "https://api.cloudflareclient.com/v0i1909051800/";
    constexpr int requestTimeoutMs = 10000;

    struct ApiResponse
    {
        bool success = false;
        QJsonObject body;
    };

    ApiResponse apiRequest(QNetworkAccessManager &manager, const QString &apiBase, const QByteArray &method,
                           const QString &path, const QJsonObject &payload = { }, const QByteArray &token = { },
                           const std::function<bool()> &isCancelled = { })
    {
        if (isCancelled && isCancelled()) {
            return { };
        }
        QNetworkRequest request(QUrl(apiBase + path));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
        request.setRawHeader("User-Agent", "okhttp/3.12.1");
        if (!token.isEmpty()) {
            request.setRawHeader("Authorization", "Bearer " + token);
        }

        const QByteArray data = payload.isEmpty() ? QByteArray() : QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QNetworkReply *reply = nullptr;
        if (method == QByteArrayLiteral("POST")) {
            reply = manager.post(request, data);
        } else {
            reply = manager.sendCustomRequest(request, method, data);
        }

        QEventLoop loop;
        QTimer timeout;
        QTimer cancellation;
        timeout.setSingleShot(true);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
        if (isCancelled) {
            QObject::connect(&cancellation, &QTimer::timeout, &loop, [&]() {
                if (isCancelled()) {
                    reply->abort();
                    loop.quit();
                }
            });
            cancellation.start(50);
        }
        timeout.start(requestTimeoutMs);
        if (!reply->isFinished()) {
            loop.exec();
        }

        if (!reply->isFinished()) {
            reply->abort();
        }

        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray responseData = reply->readAll();
        const bool networkSuccess = timeout.isActive() && !(isCancelled && isCancelled())
                && reply->error() == QNetworkReply::NoError && status >= 200 && status < 300;
        reply->deleteLater();
        if (!networkSuccess) {
            return { };
        }

        if (responseData.isEmpty()) {
            return { true, { } };
        }

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(responseData, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            return { };
        }
        return { true, document.object() };
    }

    bool validBase64Key(const QString &value)
    {
        const QByteArray encoded = value.toLatin1();
        const QByteArray decoded = QByteArray::fromBase64(encoded);
        return decoded.size() == 32 && decoded.toBase64() == encoded;
    }

    bool validAddress(const QString &value, QAbstractSocket::NetworkLayerProtocol protocol)
    {
        return QHostAddress(value.section(QLatin1Char('/'), 0, 0)).protocol() == protocol;
    }

    bool validEndpoint(const QString &value)
    {
        const QUrl endpoint(QStringLiteral("wg://") + value);
        return !endpoint.host().isEmpty() && endpoint.port() > 0 && endpoint.port() <= 65535;
    }

    std::optional<QPair<QString, QString>> generateKeyPair()
    {
        QByteArray privateKey = CryptoUtils::generateRandomBytes(32);
        if (privateKey.size() != 32) {
            return std::nullopt;
        }
        privateKey[0] = static_cast<char>(static_cast<unsigned char>(privateKey[0]) & 248);
        privateKey[31] = static_cast<char>((static_cast<unsigned char>(privateKey[31]) & 127) | 64);

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
                EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                             reinterpret_cast<const unsigned char *>(privateKey.constData()),
                                             privateKey.size()),
                EVP_PKEY_free);
        if (!key) {
            OPENSSL_cleanse(privateKey.data(), privateKey.size());
            return std::nullopt;
        }

        QByteArray publicKey(32, Qt::Uninitialized);
        size_t publicKeySize = static_cast<size_t>(publicKey.size());
        if (EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char *>(publicKey.data()), &publicKeySize) != 1
            || publicKeySize != 32) {
            OPENSSL_cleanse(privateKey.data(), privateKey.size());
            return std::nullopt;
        }

        const QString privateKeyBase64 = QString::fromLatin1(privateKey.toBase64());
        const QString publicKeyBase64 = QString::fromLatin1(publicKey.toBase64());
        OPENSSL_cleanse(privateKey.data(), privateKey.size());
        return QPair<QString, QString>(privateKeyBase64, publicKeyBase64);
    }

    QString peerEndpoint(const QJsonObject &peer)
    {
        const QJsonValue endpoint = peer.value(QStringLiteral("endpoint"));
        if (endpoint.isString()) {
            return endpoint.toString();
        }
        return endpoint.toObject().value(QStringLiteral("host")).toString();
    }

    QString normalizedApiBase(const QString &value)
    {
        QUrl url(value.trimmed());
        if (!url.isValid() || url.scheme() != QLatin1String("https") || url.host().isEmpty()
            || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()) {
            return { };
        }
        QString base = url.toString(QUrl::FullyEncoded);
        if (!base.endsWith(QLatin1Char('/'))) {
            base.append(QLatin1Char('/'));
        }
        return base;
    }
}

namespace amnezia
{
    bool WarpUnderlayConfig::isValid() const
    {
        return validBase64Key(privateKey) && validBase64Key(peerPublicKey)
                && validAddress(ipv4Address, QAbstractSocket::IPv4Protocol)
                && validAddress(ipv6Address, QAbstractSocket::IPv6Protocol) && validEndpoint(endpoint);
    }

    QJsonObject WarpUnderlayConfig::toJson() const
    {
        return {
            { QStringLiteral("privateKey"), privateKey },   { QStringLiteral("peerPublicKey"), peerPublicKey },
            { QStringLiteral("ipv4Address"), ipv4Address }, { QStringLiteral("ipv6Address"), ipv6Address },
            { QStringLiteral("endpoint"), endpoint },
        };
    }

    std::optional<WarpUnderlayConfig> WarpUnderlayConfig::fromJson(const QJsonObject &json)
    {
        WarpUnderlayConfig config;
        config.privateKey = json.value(QStringLiteral("privateKey")).toString();
        config.peerPublicKey = json.value(QStringLiteral("peerPublicKey")).toString();
        config.ipv4Address = json.value(QStringLiteral("ipv4Address")).toString();
        config.ipv6Address = json.value(QStringLiteral("ipv6Address")).toString();
        config.endpoint = json.value(QStringLiteral("endpoint")).toString();
        if (!config.isValid()) {
            return std::nullopt;
        }
        return config;
    }

    std::optional<WarpUnderlayConfig> WarpUnderlay::registerDevice(const QStringList &apiBases,
                                                                   const std::function<bool()> &isCancelled)
    {
        if (isCancelled && isCancelled()) {
            return std::nullopt;
        }
        const auto keyPair = generateKeyPair();
        if (!keyPair) {
            return std::nullopt;
        }

        const QJsonObject registrationPayload {
            { QStringLiteral("install_id"), QString() },
            { QStringLiteral("tos"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate) },
            { QStringLiteral("key"), keyPair->second },
            { QStringLiteral("fcm_token"), QString() },
            { QStringLiteral("type"), QStringLiteral("ios") },
            { QStringLiteral("locale"), QStringLiteral("en_US") },
        };
        QStringList candidates;
        for (const QString &base : apiBases) {
            const QString normalized = normalizedApiBase(base);
            if (!normalized.isEmpty() && !candidates.contains(normalized)) {
                candidates.append(normalized);
            }
        }
        candidates.append(QString::fromLatin1(directApiBase));

        for (const QString &apiBase : candidates) {
            if (isCancelled && isCancelled()) {
                return std::nullopt;
            }
            QNetworkAccessManager manager;
            const ApiResponse registration = apiRequest(manager, apiBase, QByteArrayLiteral("POST"),
                                                        QStringLiteral("reg"), registrationPayload, { }, isCancelled);
            const QJsonObject registrationResult = registration.body.value(QStringLiteral("result")).toObject();
            const QString registrationId = registrationResult.value(QStringLiteral("id")).toString();
            const QByteArray token = registrationResult.value(QStringLiteral("token")).toString().toUtf8();
            if (!registration.success || registrationId.isEmpty() || token.isEmpty()) {
                continue;
            }

            const ApiResponse enabled =
                    apiRequest(manager, apiBase, QByteArrayLiteral("PATCH"), QStringLiteral("reg/") + registrationId,
                               { { QStringLiteral("warp_enabled"), true } }, token, isCancelled);
            const QJsonObject result = enabled.body.value(QStringLiteral("result")).toObject();
            const QJsonObject wireguard = result.value(QStringLiteral("config")).toObject();
            const QJsonObject addresses =
                    wireguard.value(QStringLiteral("interface")).toObject().value(QStringLiteral("addresses")).toObject();
            const QJsonArray peers = wireguard.value(QStringLiteral("peers")).toArray();
            if (!enabled.success || peers.isEmpty()) {
                apiRequest(manager, apiBase, QByteArrayLiteral("DELETE"), QStringLiteral("reg/") + registrationId, { },
                           token, isCancelled);
                continue;
            }

            const QJsonObject peer = peers.first().toObject();
            WarpUnderlayConfig config {
                keyPair->first,
                peer.value(QStringLiteral("public_key")).toString(),
                addresses.value(QStringLiteral("v4")).toString(),
                addresses.value(QStringLiteral("v6")).toString(),
                peerEndpoint(peer),
            };
            if (config.isValid()) {
                return config;
            }
            apiRequest(manager, apiBase, QByteArrayLiteral("DELETE"), QStringLiteral("reg/") + registrationId, { },
                       token, isCancelled);
        }
        return std::nullopt;
    }

    std::optional<QJsonObject> WarpUnderlay::createAwgConfig(const WarpUnderlayConfig &config,
                                                             const QString &warpEndpointAddress,
                                                             const QString &vpnServerAddress, const QString &initPacket)
    {
        const QHostAddress warpAddress(warpEndpointAddress);
        const QHostAddress serverAddress(vpnServerAddress);
        if (!config.isValid() || warpAddress.protocol() != QAbstractSocket::IPv4Protocol
            || serverAddress.protocol() != QAbstractSocket::IPv4Protocol
            || !initPacket.startsWith(QLatin1String("<b 0x")) || !initPacket.endsWith(QLatin1Char('>'))) {
            return std::nullopt;
        }

        const QJsonObject awgConfig {
            { QStringLiteral("client_priv_key"), config.privateKey },
            { QStringLiteral("client_ip"), config.ipv4Address.section(QLatin1Char('/'), 0, 0) },
            { QStringLiteral("server_pub_key"), config.peerPublicKey },
            { QStringLiteral("hostName"), warpEndpointAddress },
            { QStringLiteral("port"), 500 },
            { QStringLiteral("mtu"), QStringLiteral("1280") },
            { QStringLiteral("allowed_ips"), QJsonArray { vpnServerAddress + QStringLiteral("/32") } },
            { QStringLiteral("persistent_keep_alive"), QStringLiteral("25") },
            { QStringLiteral("S1"), QStringLiteral("0") },
            { QStringLiteral("S2"), QStringLiteral("0") },
            { QStringLiteral("Jc"), QStringLiteral("120") },
            { QStringLiteral("Jmin"), QStringLiteral("23") },
            { QStringLiteral("Jmax"), QStringLiteral("911") },
            { QStringLiteral("H1"), QStringLiteral("1") },
            { QStringLiteral("H2"), QStringLiteral("2") },
            { QStringLiteral("H3"), QStringLiteral("3") },
            { QStringLiteral("H4"), QStringLiteral("4") },
            { QStringLiteral("I1"), initPacket },
        };
        return QJsonObject {
            { QStringLiteral("protocol"), QStringLiteral("awg") },
            { QStringLiteral("hostName"), warpEndpointAddress },
            { QStringLiteral("splitTunnelType"), 1 },
            { QStringLiteral("splitTunnelSites"), QJsonArray { vpnServerAddress } },
            { QStringLiteral("appSplitTunnelType"), 0 },
            { QStringLiteral("splitTunnelApps"), QJsonArray { } },
            { QStringLiteral("allowedDnsServers"), QJsonArray { } },
            { QStringLiteral("killSwitchOption"), QStringLiteral("false") },
            { QStringLiteral("hopType"), QStringLiteral("MultiHopEntry") },
            { QStringLiteral("awg_config_data"), awgConfig },
        };
    }

    std::optional<QJsonObject> WarpUnderlay::bindXrayConfig(const QJsonObject &config, const QString &sourceAddress,
                                                            const QString &interfaceName, const QString &serverHost,
                                                            const QString &serverAddress)
    {
        if (QHostAddress(sourceAddress).protocol() != QAbstractSocket::IPv4Protocol || interfaceName.isEmpty()
            || serverHost.isEmpty() || QHostAddress(serverAddress).protocol() != QAbstractSocket::IPv4Protocol) {
            return std::nullopt;
        }

        QJsonArray outbounds = config.value(QStringLiteral("outbounds")).toArray();
        bool matchedServer = false;
        for (qsizetype i = 0; i < outbounds.size(); ++i) {
            QJsonObject outbound = outbounds.at(i).toObject();
            QJsonObject settings = outbound.value(QStringLiteral("settings")).toObject();
            bool hasServers = false;
            for (const QString &key : { QStringLiteral("vnext"), QStringLiteral("servers") }) {
                QJsonArray servers = settings.value(key).toArray();
                if (servers.isEmpty()) {
                    continue;
                }
                hasServers = true;
                for (qsizetype j = 0; j < servers.size(); ++j) {
                    QJsonObject server = servers.at(j).toObject();
                    const QString address = server.value(QStringLiteral("address")).toString();
                    if (address.compare(serverHost, Qt::CaseInsensitive) == 0 || address == serverAddress) {
                        server.insert(QStringLiteral("address"), serverAddress);
                        servers[j] = server;
                        matchedServer = true;
                    }
                }
                settings.insert(key, servers);
            }
            if (!hasServers) {
                continue;
            }

            QJsonObject stream = outbound.value(QStringLiteral("streamSettings")).toObject();
            QJsonObject sockopt = stream.value(QStringLiteral("sockopt")).toObject();
            sockopt.insert(QStringLiteral("interface"), interfaceName);
            stream.insert(QStringLiteral("sockopt"), sockopt);
            outbound.insert(QStringLiteral("settings"), settings);
            outbound.insert(QStringLiteral("streamSettings"), stream);
            outbound.insert(QStringLiteral("sendThrough"), sourceAddress);
            outbounds[i] = outbound;
        }
        if (!matchedServer) {
            return std::nullopt;
        }
        QJsonObject bound = config;
        bound.insert(QStringLiteral("outbounds"), outbounds);
        return bound;
    }
}
