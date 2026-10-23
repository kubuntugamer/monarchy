// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Smb2.h"

#include <QCryptographicHash>
#include <QDebug>
#include <QList>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>

#include "Gss.h"
#include "Ntlm.h"


namespace {

// The NTLMSSP mechanism OID, and the SPNEGO one, as SPNEGO carries them.
const QString kNtlmMech = QStringLiteral("1.3.6.1.4.1.311.2.2.10");

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

void putLe64(QByteArray &out, quint64 value)
{
    putLe32(out, quint32(value & 0xffffffffu));
    putLe32(out, quint32((value >> 32) & 0xffffffffu));
}

void putBe32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

quint16 readLe16(const QByteArray &data, int at)
{
    if (at < 0 || at + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(at)) | (quint16(quint8(data.at(at + 1))) << 8));
}

quint32 readLe32(const QByteArray &data, int at)
{
    if (at < 0 || at + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(at))) | (quint32(quint8(data.at(at + 1))) << 8)
           | (quint32(quint8(data.at(at + 2))) << 16)
           | (quint32(quint8(data.at(at + 3))) << 24);
}

quint64 readLe64(const QByteArray &data, int at)
{
    return quint64(readLe32(data, at)) | (quint64(readLe32(data, at + 4)) << 32);
}

void setLe16(QByteArray &data, int at, quint16 value)
{
    data[at] = char(value & 0xff);
    data[at + 1] = char((value >> 8) & 0xff);
}

void setLe32(QByteArray &data, int at, quint32 value)
{
    data[at] = char(value & 0xff);
    data[at + 1] = char((value >> 8) & 0xff);
    data[at + 2] = char((value >> 16) & 0xff);
    data[at + 3] = char((value >> 24) & 0xff);
}

QString fromUtf16(const QByteArray &bytes)
{
    QString text;
    text.reserve(bytes.size() / 2);
    for (int i = 0; i + 1 < bytes.size(); i += 2)
        text.append(QChar(quint16(quint8(bytes.at(i)) | (quint16(quint8(bytes.at(i + 1))) << 8))));
    return text;
}

QByteArray nbtFrame(const QByteArray &message)
{
    QByteArray framed;
    putBe32(framed, quint32(message.size()));
    framed[0] = 0; // session message type
    framed.append(message);
    return framed;
}

// An NTLMSSP AUTHENTICATE as session setup carries it: the fields the RPC
// authenticator verifies, read at the offsets MS-NLMP 2.2.1.3 defines.
bool parseAuthenticate(const QByteArray &token, Rpc::AuthRequest *request,
                       QByteArray *encryptedSessionKey)
{
    const QByteArray ntlm = Ntlm::embeddedToken(token);
    if (Ntlm::messageType(ntlm) != 3)
        return false;
    const auto field = [&ntlm](int at) {
        const int length = readLe16(ntlm, at);
        const int offset = int(readLe32(ntlm, at + 4));
        if (length <= 0 || offset < 0 || offset + length > ntlm.size())
            return QByteArray();
        return ntlm.mid(offset, length);
    };
    request->ntResponse = field(20);
    request->domain = fromUtf16(field(28));
    request->user = fromUtf16(field(36));
    if (encryptedSessionKey)
        *encryptedSessionKey = field(40); // EncryptedRandomSessionKey
    request->flags = readLe32(ntlm, 60);
    return !request->user.isEmpty() && !request->ntResponse.isEmpty();
}

} // namespace

struct Smb2Server::Connection {
    QTcpSocket *socket = nullptr;
    QByteArray buffer;
    quint64 sessionId = 0;
    bool authenticated = false;
    QString user;
    QByteArray challenge;
    // SMB2 session key: the NTLM export, which signs every message once the
    // session is authenticated (MS-SMB2 3.2.5.3.1, MS-NLMP 3.4.5.3).
    QByteArray sessionKey;

    struct Pipe {
        QString name;
        RpcServer::Channel *channel = nullptr;
        QByteArray pending;
    };
    QHash<quint64, Pipe> handles;
    QHash<quint32, QString> trees;

    quint64 nextSession = 0x00010000;
    quint64 nextTree = 0x00020000;
    quint64 nextHandle = 0x00030000;
};

Smb2Server::Smb2Server(QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
{
    connect(m_server, &QTcpServer::newConnection, this, &Smb2Server::onNewConnection);
}

Smb2Server::~Smb2Server()
{
    close();
}

void Smb2Server::addPipe(const QString &name, RpcServer *endpoint)
{
    m_pipes.insert(name.toLower(), endpoint);
}

void Smb2Server::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_authenticator = std::move(authenticator);
}

void Smb2Server::setDomainNames(const QString &domain, const QString &serverName,
                                const QString &dnsDomain)
{
    m_domain = domain;
    m_serverName = serverName;
    m_dnsDomain = dnsDomain;
}

bool Smb2Server::listen(quint16 port, const QHostAddress &address)
{
    return m_server->listen(address, port);
}

void Smb2Server::close()
{
    for (Connection *connection : m_connections) {
        for (auto &pipe : connection->handles)
            delete pipe.channel;
        delete connection;
    }
    m_connections.clear();
    if (m_server)
        m_server->close();
}

bool Smb2Server::isListening() const
{
    return m_server && m_server->isListening();
}

quint16 Smb2Server::serverPort() const
{
    return m_server ? m_server->serverPort() : 0;
}

void Smb2Server::onNewConnection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();
        auto *connection = new Connection;
        connection->socket = socket;
        m_connections.append(connection);
        connect(socket, &QTcpSocket::readyRead, this, &Smb2Server::onReadyRead);
        connect(socket, &QTcpSocket::disconnected, this, &Smb2Server::onDisconnected);
    }
}

void Smb2Server::onReadyRead()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    Connection *connection = nullptr;
    for (Connection *candidate : m_connections) {
        if (candidate->socket == socket) {
            connection = candidate;
            break;
        }
    }
    if (!connection)
        return;

    connection->buffer.append(socket->readAll());
    QByteArray out;
    while (connection->buffer.size() >= 4) {
        const quint32 length = (quint32(quint8(connection->buffer.at(1))) << 16)
                               | (quint32(quint8(connection->buffer.at(2))) << 8)
                               | quint32(quint8(connection->buffer.at(3)));
        if (length == 0) {
            connection->buffer.remove(0, 4); // keep-alive
            continue;
        }
        if (connection->buffer.size() < int(4 + length))
            break;
        const QByteArray message = connection->buffer.mid(4, int(length));
        connection->buffer.remove(0, int(4 + length));
        out.append(handleMessage(connection, message));
    }
    if (!out.isEmpty())
        socket->write(out);
}

void Smb2Server::onDisconnected()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    for (int i = 0; i < m_connections.size(); ++i) {
        if (m_connections[i]->socket == socket) {
            Connection *connection = m_connections[i];
            for (auto &pipe : connection->handles)
                delete pipe.channel;
            delete connection;
            m_connections.removeAt(i);
            break;
        }
    }
    socket->deleteLater();
}

// A headless connection, so a test can drive the whole handshake without a
// socket. `onReadyRead` and this share every byte of state and every handler.
QByteArray Smb2Server::feed(const QByteArray &nbss)
{
    static thread_local Connection scratch;
    QByteArray out;
    scratch.buffer.append(nbss);
    while (scratch.buffer.size() >= 4) {
        const quint32 length = (quint32(quint8(scratch.buffer.at(1))) << 16)
                               | (quint32(quint8(scratch.buffer.at(2))) << 8)
                               | quint32(quint8(scratch.buffer.at(3)));
        if (length == 0) {
            scratch.buffer.remove(0, 4);
            continue;
        }
        if (scratch.buffer.size() < int(4 + length))
            break;
        const QByteArray message = scratch.buffer.mid(4, int(length));
        scratch.buffer.remove(0, int(4 + length));
        out.append(handleMessage(&scratch, message));
    }
    return out;
}

QByteArray Smb2Server::handleMessage(Connection *connection, const QByteArray &message)
{
    if (message.size() < int(Smb2::kHeaderSize) || message.left(4) != QByteArray("\376SMB", 4))
        return QByteArray();

    const quint16 command = readLe16(message, 12);
    const quint64 messageId = readLe64(message, 24);
    // A signed request is verified before it is believed. The session key is only
    // known after session setup, which is itself unsigned.
    if ((readLe16(message, 16) & 0x0008) && !connection->sessionKey.isEmpty()) {
        QByteArray expected = message;
        const QByteArray signature = message.mid(48, 16);
        expected.replace(48, 16, QByteArray(16, '\0'));
        QMessageAuthenticationCode hmac(QCryptographicHash::Sha256, connection->sessionKey);
        hmac.addData(expected);
        if (hmac.result().left(16) != signature) {
            QByteArray refused = message.left(int(Smb2::kHeaderSize));
            setLe32(refused, 8, 0xc0000022u); // STATUS_ACCESS_DENIED
            setLe16(refused, 14, 1);
            setLe16(refused, 16,
                    quint16(readLe16(message, 16) | Smb2::kFlagsServerToRedirector));
            refused.replace(48, 16, QByteArray(16, '\0'));
            QByteArray body;
            putLe16(body, 9);
            body.append(QByteArray(7, '\0'));
            refused.append(body);
            return nbtFrame(refused);
        }
    }
    const quint32 treeId = readLe32(message, 36);
    quint32 status = Smb2::StatusSuccess;
    QByteArray body;

    switch (command) {
    case Smb2::CmdNegotiate:
        body = negotiate(connection, message.mid(int(Smb2::kHeaderSize)), status);
        break;
    case Smb2::CmdSessionSetup:
        body = sessionSetup(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdTreeConnect:
        body = treeConnect(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdCreate:
        body = create(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdWrite:
        body = write(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdRead:
        body = read(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdClose:
        body = closePipe(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdLogoff:
        connection->authenticated = false;
        connection->user.clear();
        putLe16(body, 4);
        putLe16(body, 0);
        break;
    case Smb2::CmdTreeDisconnect:
        connection->trees.remove(treeId);
        putLe16(body, 4);
        putLe16(body, 0);
        break;
    case Smb2::CmdEcho:
    case Smb2::CmdFlush:
        putLe16(body, 4);
        putLe16(body, 0);
        break;
    default:
        status = Smb2::StatusNotSupported;
        putLe16(body, 4);
        putLe16(body, 0);
        break;
    }

    QByteArray reply = message.left(int(Smb2::kHeaderSize));
    setLe32(reply, 8, status);
    setLe16(reply, 14, 1); // credit granted
    setLe16(reply, 16, quint16(readLe16(message, 16) | Smb2::kFlagsServerToRedirector));
    setLe32(reply, 20, 0); // no compound chain
    setLe32(reply, 44, treeId);
    // The response carries the session the request named once one exists.
    if (connection->sessionId) {
        for (int i = 0; i < 8; ++i)
            reply[40 + i] = char((connection->sessionId >> (8 * i)) & 0xff);
    }
    Q_UNUSED(messageId)
    reply.replace(48, 16, QByteArray(16, '\0'));
    reply.append(body);

    // Signing (MS-SMB2 3.2.5.3.1): HMAC-SHA256 over the whole message with the
    // signature field zeroed, truncated to 16 bytes, keyed by the session key.
    if (!connection->sessionKey.isEmpty()) {
        // The SIGNED flag is part of what the signature covers, so it is set
        // before the hash rather than after it.
        setLe16(reply, 16, quint16(readLe16(reply, 16) | 0x0008)); // SMB2_FLAGS_SIGNED
        reply.replace(48, 16, QByteArray(16, '\0'));
        QMessageAuthenticationCode hmac(QCryptographicHash::Sha256, connection->sessionKey);
        hmac.addData(reply);
        reply.replace(48, 16, hmac.result().left(16));
    }
    return nbtFrame(reply);
}

QByteArray Smb2Server::negotiate(Connection *connection, const QByteArray &body, quint32 status)
{
    Q_UNUSED(connection)
    Q_UNUSED(status)
    const quint16 count = readLe16(body, 2);
    quint16 dialect = Smb2::Dialect202;
    for (int i = 0; i < int(count); ++i) {
        const quint16 offered = readLe16(body, 36 + i * 2);
        if (offered == Smb2::Dialect210)
            dialect = Smb2::Dialect210;
    }

    emit requestReceived(QStringLiteral("SMB2 negotiate dialect 0x%1").arg(dialect, 4, 16, QLatin1Char('0')));

    QByteArray out;
    putLe16(out, 65);        // StructureSize
    putLe16(out, 0x0000);    // SecurityMode: signing disabled
    putLe16(out, dialect);
    putLe16(out, 0);         // NegotiateContextCount
    out.append(QByteArray::fromHex("8d9c2f4e6a1b4d7c9e0f1a2b3c4d5e6f")); // ServerGuid
    putLe32(out, 0);         // Capabilities
    putLe32(out, 65536);     // MaxTransactSize
    putLe32(out, 65536);     // MaxReadSize
    putLe32(out, 65536);     // MaxWriteSize
    putLe64(out, quint64(0)); // SystemTime
    putLe64(out, quint64(0)); // ServerStartTime
    putLe16(out, 128);       // SecurityBufferOffset
    putLe16(out, 0);         // SecurityBufferLength
    putLe32(out, 0);         // NegotiateContextOffset
    return out;
}

QByteArray Smb2Server::sessionSetup(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint16 securityOffset = readLe16(body, 12);
    const quint16 securityLength = readLe16(body, 14);
    QByteArray token;
    if (securityOffset >= Smb2::kHeaderSize && securityLength > 0) {
        const int at = int(securityOffset) - int(Smb2::kHeaderSize);
        token = body.mid(at, securityLength);
    }

    const int type = Ntlm::messageType(Ntlm::embeddedToken(token));
    QByteArray replyToken;
    if (type == 1) {
        connection->sessionId = ++connection->nextSession;
        connection->challenge = QByteArray(8, '\0');
        for (int i = 0; i < 8; ++i)
            connection->challenge[i] = char(QRandomGenerator::system()->generate() & 0xff);
        const QByteArray challenge = Ntlm::challengeToken(connection->challenge, m_domain,
                                                          m_serverName, m_dnsDomain);
        replyToken = Gss::spnegoResponse(1, kNtlmMech, challenge); // accept-incomplete
        *status = Smb2::StatusMoreProcessingRequired;
    } else if (type == 3) {
        Rpc::AuthRequest request;
        request.challenge = connection->challenge;
        QByteArray encryptedSessionKey;
        Ntlm::SessionKeys keys;
        if (parseAuthenticate(token, &request, &encryptedSessionKey) && m_authenticator
            && m_authenticator(request, &keys)) {
            connection->authenticated = true;
            // SMB2 signs with the exported session key: the session base key, or
            // — when the client negotiated key exchange, which it does by
            // default — that key's RC4 decryption of the EncryptedRandomSessionKey
            // it sent (MS-NLMP 3.4.5.3, MS-SMB2 3.2.5.3.1).
            constexpr quint32 kKeyExchange = 0x40000000u;
            if ((request.flags & kKeyExchange) && !encryptedSessionKey.isEmpty()) {
                Ntlm::Sealer rc4(keys.sessionBaseKey);
                connection->sessionKey = rc4.apply(encryptedSessionKey);
            } else {
                connection->sessionKey = keys.sessionBaseKey;
            }
            connection->user = request.domain.isEmpty()
                                   ? request.user
                                   : request.domain + QLatin1Char('\\') + request.user;
            replyToken = Gss::spnegoResponse(0, kNtlmMech, QByteArray()); // accept-completed
            *status = Smb2::StatusSuccess;
        } else {
            replyToken = Gss::spnegoResponse(2, kNtlmMech, QByteArray()); // reject
            *status = Smb2::StatusLogonFailure;
        }
    } else {
        *status = Smb2::StatusLogonFailure;
    }

    QByteArray out;
    putLe16(out, 9); // StructureSize
    putLe16(out, 0); // SessionFlags: no guest, no encryption
    // The security buffer follows the 8-byte fixed body, and its offset is from
    // the start of the SMB2 header.
    putLe16(out, quint16(Smb2::kHeaderSize + 8)); // SecurityBufferOffset
    putLe16(out, quint16(replyToken.size()));
    out.append(replyToken);
    if (!connection->sessionId)
        connection->sessionId = ++connection->nextSession;
    return out;
}

QByteArray Smb2Server::treeConnect(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint16 pathOffset = readLe16(body, 4);
    const quint16 pathLength = readLe16(body, 6);
    QString path;
    if (pathOffset >= Smb2::kHeaderSize && pathLength > 0)
        path = fromUtf16(body.mid(int(pathOffset) - int(Smb2::kHeaderSize), pathLength));

    const int slash = path.lastIndexOf(QLatin1Char('\\'));
    const QString share = slash >= 0 ? path.mid(slash + 1) : path;
    if (share.compare(QStringLiteral("IPC$"), Qt::CaseInsensitive) != 0) {
        *status = Smb2::StatusBadNetworkName;
        QByteArray out;
        putLe16(out, 16);
        out.append(QByteArray(14, '\0'));
        return out;
    }

    const quint32 treeId = quint32(++connection->nextTree);
    connection->trees.insert(treeId, share);

    QByteArray out;
    putLe16(out, 16);   // StructureSize
    out.append(char(2)); // ShareType: pipe
    out.append(char(0)); // Reserved
    putLe32(out, 0);    // ShareFlags
    putLe32(out, 0);    // Capabilities
    putLe32(out, 0x001f01ff); // MaximalAccess
    emit requestReceived(QStringLiteral("SMB2 tree connect %1").arg(share));
    return out;
}

QByteArray Smb2Server::create(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint16 nameOffset = readLe16(body, 44);
    const quint16 nameLength = readLe16(body, 46);
    QString name;
    if (nameOffset >= Smb2::kHeaderSize && nameLength > 0)
        name = fromUtf16(body.mid(int(nameOffset) - int(Smb2::kHeaderSize), nameLength));
    while (name.startsWith(QLatin1Char('\\')))
        name.remove(0, 1);

    RpcServer *endpoint = m_pipes.value(name.toLower());
    if (!endpoint) {
        *status = Smb2::StatusObjectNameNotFound;
        QByteArray out;
        putLe16(out, 89);
        out.append(QByteArray(87, '\0'));
        return out;
    }

    const quint64 id = ++connection->nextHandle;
    Connection::Pipe pipe;
    pipe.name = name;
    pipe.channel = endpoint->newChannel(QStringLiteral("smb2:%1").arg(name));
    // The session authenticated the principal; the pipe carries that identity to
    // the endpoint the same way a Windows DC does for \pipe\samr.
    if (connection->authenticated)
        pipe.channel->setTransportIdentity(connection->user);
    connection->handles.insert(id, pipe);

    QByteArray out;
    putLe16(out, 89);          // StructureSize
    out.append(char(0));       // OplockLevel
    out.append(char(0));       // Flags
    putLe32(out, 1);           // CreateAction: FILE_OPENED
    for (int i = 0; i < 4; ++i)
        putLe64(out, 0);       // the four timestamps
    putLe64(out, 0);           // AllocationSize
    putLe64(out, 0);           // EndOfFile
    putLe32(out, 0);           // FileAttributes
    putLe32(out, 0);           // Reserved
    putLe64(out, id);          // FileId.Persistent
    putLe64(out, id);          // FileId.Volatile
    putLe32(out, 0);           // CreateContextsOffset
    putLe32(out, 0);           // CreateContextsLength
    emit requestReceived(QStringLiteral("SMB2 open \\pipe\\%1").arg(name));
    return out;
}

QByteArray Smb2Server::write(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint16 dataOffset = readLe16(body, 2);
    const quint32 length = readLe32(body, 4);
    const quint64 id = readLe64(body, 16);

    auto it = connection->handles.find(id);
    if (it == connection->handles.end() || !it->channel) {
        *status = Smb2::StatusFileClosed;
        QByteArray out;
        putLe16(out, 17);
        out.append(QByteArray(15, '\0'));
        return out;
    }
    QByteArray data;
    if (dataOffset >= Smb2::kHeaderSize && length > 0)
        data = body.mid(int(dataOffset) - int(Smb2::kHeaderSize), int(length));

    // One write carries whole DCE/RPC PDUs; a client may pack more than one, so
    // they are split on frag_length the way the TCP path splits a stream.
    while (data.size() >= 16) {
        const quint16 fragLength = readLe16(data, 8);
        if (fragLength < 16 || data.size() < fragLength)
            break;
        const QByteArray pdu = data.left(fragLength);
        data.remove(0, fragLength);
        const QByteArray reply = it->channel->feed(pdu);
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("SMB2 pipe write %s pdu(%d)=%s reply(%d)=%s", qPrintable(it->name),
                     int(pdu.size()), pdu.toHex().constData(), int(reply.size()),
                     reply.toHex().constData());
        it->pending.append(reply);
    }

    QByteArray out;
    putLe16(out, 17);     // StructureSize
    putLe16(out, 0);      // Reserved
    putLe32(out, length); // Count
    putLe32(out, 0);      // Remaining
    putLe16(out, 0);      // WriteChannelInfoOffset
    putLe16(out, 0);      // WriteChannelInfoLength
    return out;
}

QByteArray Smb2Server::read(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint32 length = readLe32(body, 4);
    const quint64 id = readLe64(body, 16);

    auto it = connection->handles.find(id);
    if (it == connection->handles.end() || !it->channel) {
        *status = Smb2::StatusFileClosed;
        QByteArray out;
        putLe16(out, 17);
        out.append(QByteArray(15, '\0'));
        return out;
    }

    const int take = qMin(int(length), it->pending.size());
    const QByteArray data = it->pending.left(take);
    it->pending.remove(0, take);

    QByteArray out;
    putLe16(out, 17);   // StructureSize
    out.append(char(Smb2::kHeaderSize + 16)); // DataOffset
    out.append(char(0));                      // Reserved
    putLe32(out, quint32(data.size()));       // DataLength
    putLe32(out, quint32(it->pending.size())); // DataRemaining
    putLe32(out, 0);                          // Reserved2
    out.append(data);
    return out;
}

QByteArray Smb2Server::closePipe(Connection *connection, const QByteArray &body, quint32 *status)
{
    Q_UNUSED(status)
    const quint64 id = readLe64(body, 8);
    auto it = connection->handles.find(id);
    if (it != connection->handles.end()) {
        delete it->channel;
        it->channel = nullptr;
        connection->handles.erase(it);
    }
    QByteArray out;
    putLe16(out, 60);              // StructureSize
    putLe16(out, 0);               // Flags
    putLe32(out, 0);               // Reserved
    out.append(QByteArray(32, '\0')); // timestamps
    putLe64(out, 0);               // AllocationSize
    putLe64(out, 0);               // EndOfFile
    putLe32(out, 0);               // FileAttributes
    return out;
}
