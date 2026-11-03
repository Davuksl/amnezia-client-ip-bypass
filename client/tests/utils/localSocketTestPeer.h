#ifndef LOCALSOCKETTESTPEER_H
#define LOCALSOCKETTESTPEER_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QUuid>
#include <algorithm>

class LocalSocketTestPeer : public QObject
{
public:
    LocalSocketTestPeer()
    {
        QObject::connect(&server, &QLocalServer::newConnection, this, [this]() {
            while (server.hasPendingConnections()) {
                auto *socket = server.nextPendingConnection();
                sockets.append(socket);
                QObject::connect(socket, &QLocalSocket::readyRead, this, [this, socket]() {
                    auto &buffer = buffers[socket];
                    buffer.append(socket->readAll());
                    while (buffer.contains('\n')) {
                        const int end = buffer.indexOf('\n');
                        requests.append(QJsonDocument::fromJson(buffer.left(end)).object());
                        buffer.remove(0, end + 1);
                    }
                });
            }
        });
        listening = server.listen(QStringLiteral("AmneziaSocketTest-%1").arg(QUuid::createUuid().toString(QUuid::Id128)));
    }

    void send(const QJsonObject &message)
    {
        if (!sockets.isEmpty() && sockets.last()) {
            sockets.last()->write(QJsonDocument(message).toJson(QJsonDocument::Compact) + '\n');
            sockets.last()->flush();
        }
    }

    int count(const QString &type) const
    {
        return std::count_if(requests.cbegin(), requests.cend(), [&](const QJsonObject &request) {
            return request.value(QStringLiteral("type")).toString() == type;
        });
    }

    QJsonObject last(const QString &type) const
    {
        for (auto iterator = requests.crbegin(); iterator != requests.crend(); ++iterator) {
            if (iterator->value(QStringLiteral("type")).toString() == type) {
                return *iterator;
            }
        }
        return { };
    }

    QLocalServer server;
    QList<QPointer<QLocalSocket>> sockets;
    QHash<QLocalSocket *, QByteArray> buffers;
    QList<QJsonObject> requests;
    bool listening = false;
};

#endif
