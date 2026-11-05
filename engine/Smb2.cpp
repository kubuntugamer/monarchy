// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Smb2.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QList>
#include <QMessageAuthenticationCode>
#include <QPair>
#include <QRandomGenerator>
#include <QStorageInfo>
#include <QRegularExpression>
#include <QTcpServer>
#include <QTcpSocket>

#include "Gss.h"
#include "Ntlm.h"
#include "Smb1.h"
#include "SmbPaths.h"

using SmbPaths::resolveCaseInsensitive;
using SmbPaths::safeRelativeName;


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

// Windows FILETIME: 100-nanosecond ticks since 1601-01-01 UTC.
quint64 fileTime(const QDateTime &time)
{
    if (!time.isValid())
        return 0;
    return quint64((time.toMSecsSinceEpoch() + 11644473600000LL) * 10000LL);
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
    // EncryptedRandomSessionKey (MS-NLMP 2.2.1.3): the sixth security buffer,
    // after LM, NT, domain, user and workstation.
    if (encryptedSessionKey)
        *encryptedSessionKey = field(52);
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

    struct Tree {
        QString name;
        bool pipe = false;
        QString path;
        bool readOnly = true;
    };

    // A handle is either a named pipe (whole DCE/RPC PDUs in, answers out) or
    // an open file or directory inside a disk share.
    struct Handle {
        QString name;
        RpcServer::Channel *channel = nullptr;
        QByteArray pending;
        QFile *file = nullptr;
        bool directory = false;
        bool readOnly = true;
        // Absolute path of whatever this handle opened inside its share.
        QString path;
        // The directory listing, fetched when the query asks for it and
        // drained across calls by the file index.
        QList<QPair<QString, QFileInfo>> entries;
        QString pattern;
        int entriesServed = 0;
        bool listed = false;
    };
    QHash<quint64, Handle> handles;
    QHash<quint32, Tree> trees;
    // Windows 2000 and other SMB1-only clients keep their own session state on
    // the same connection; created on the first SMB1 message.
    Smb1::Session *smb1 = nullptr;

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

void Smb2Server::addShare(const QString &name, const QString &path, bool readOnly)
{
    const QFileInfo info(path);
    if (!info.isDir())
        return;
    m_shares.insert(name.toLower(), Share{ info.absoluteFilePath(), readOnly });
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
        for (auto &handle : connection->handles) {
            delete handle.channel;
            delete handle.file;
        }
        delete connection->smb1;
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
        const QByteArray wildcard = wildcardAnswer(connection, message);
        out.append(!wildcard.isEmpty() ? wildcard : handleMessage(connection, message));
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
            for (auto &handle : connection->handles) {
                delete handle.channel;
                delete handle.file;
            }
            delete connection->smb1;
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
        const QByteArray wildcard = wildcardAnswer(&scratch, message);
        out.append(!wildcard.isEmpty() ? wildcard : handleMessage(&scratch, message));
    }
    return out;
}

QByteArray Smb2Server::wildcardAnswer(Connection *connection, const QByteArray &message)
{
    // The classic SMB1 wildcard negotiate (\xffSMB -- "SMB 2.???"), the
    // opening packet of impacket, rpcclient and every older Samba. With SMB1
    // disabled this must still be answered — exactly as a Windows DC answers
    // it on 445 — with the raw SMB2 negotiate response on the same NBSS
    // session, which flips the client into speaking SMB2-only. Dropping this
    // packet makes such clients hang until timeout before their first bind
    // ever goes out; both the socket and the feed paths share this answer.
    if (message.left(4) != QByteArray("\377SMB", 4)
        || quint8(message.at(4)) != 0x72   // SMB_COM_NEGOTIATE
        || message.indexOf("SMB 2.???") < 0)
        return QByteArray();
    // A client that also offers the SMB1 NT dialect gets SMB1: answering the
    // SMB2 wildcard would strand an NT1-only session. Samba's client offers
    // both, and with client max protocol=NT1 expects the SMB1 answer.
    if (message.contains("NT LM 0.12") || message.contains("NT LANMAN"))
        return QByteArray();

    // A minimal (fake-client) SMB2 negotiate *body*, parsed by the very same
    // negotiate() the pure-SMB2 path uses, wrapped in an SMB2 header so it
    // flows through handleMessage as a normal packet.
    QByteArray smb2Body = QByteArray(64, '\0');
    setLe16(smb2Body, 0, 64);         // Negotiate StructureSize
    setLe16(smb2Body, 2, 2);          // DialectCount
    setLe16(smb2Body, 4, 1);          // SecurityMode
    setLe16(smb2Body, 36, Smb2::Dialect202);
    setLe16(smb2Body, 38, Smb2::Dialect210);
    QByteArray smb2Packet = QByteArray(int(Smb2::kHeaderSize), '\0');
    smb2Packet.replace(0, 4, QByteArray("\376SMB", 4)); // SMB2 ProtocolId
    // Command 0 = CmdNegotiate.
    smb2Packet.append(smb2Body);
    return handleMessage(connection, smb2Packet);
}

QByteArray Smb2Server::handleSmb1(Connection *connection, const QByteArray &message)
{
    if (!connection->smb1) {
        // SMB1 resolves the same share names against the same directories, so a
        // 2000 client and an SMB2 client read the same SYSVOL.
        QHash<QString, QString> shares;
        for (auto it = m_shares.constBegin(); it != m_shares.constEnd(); ++it)
            shares.insert(it.key().toLower(), it.value().path);
        connection->smb1 = new Smb1::Session(m_pipes, m_authenticator, m_domain, m_serverName,
                                             m_dnsDomain, shares);
        connection->smb1->setNotifier(
            [this](const QString &operation) { emit requestReceived(operation); });
    }
    return connection->smb1->feed(message);
}

QByteArray Smb2Server::handleMessage(Connection *connection, const QByteArray &message)
{
    if (Smb1::Session::isSmb1(message))
        return handleSmb1(connection, message);
    if (message.size() < int(Smb2::kHeaderSize) || message.left(4) != QByteArray("\376SMB", 4))
        return QByteArray();

    const quint16 command = readLe16(message, 12);
    const quint64 messageId = readLe64(message, 24);
    emit requestReceived(QStringLiteral("SMB2 cmd %1").arg(command));
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
    // The header's tree id is the request's, except on a tree connect, where it
    // is the id the server just allocated (MS-SMB2 3.3.5.6).
    quint32 responseTreeId = treeId;
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
        body = treeConnect(connection, message.mid(int(Smb2::kHeaderSize)), &status,
                           &responseTreeId);
        break;
    case Smb2::CmdCreate:
        body = create(connection, treeId, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdWrite:
        body = write(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdIoctl:
        body = ioctlMessage(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdRead:
        body = read(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdQueryDirectory:
        body = queryDirectory(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdQueryInfo:
        body = queryInfo(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdSetInfo:
        body = setInfo(connection, message.mid(int(Smb2::kHeaderSize)), &status);
        break;
    case Smb2::CmdClose:
        body = closeHandle(connection, message.mid(int(Smb2::kHeaderSize)), &status);
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
    setLe32(reply, 36, responseTreeId);
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
    if (!qEnvironmentVariableIsEmpty("MONARCHY_SMB_TRACE"))
        qWarning("SMB2 out cmd=%d status=0x%08x bytes=%d body=%s",
                 command, status, int(reply.size()),
                 qPrintable(reply.mid(int(Smb2::kHeaderSize)).left(160).toHex()));
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

QByteArray Smb2Server::treeConnect(Connection *connection, const QByteArray &body, quint32 *status,
                                  quint32 *treeIdOut)
{
    const quint16 pathOffset = readLe16(body, 4);
    const quint16 pathLength = readLe16(body, 6);
    QString path;
    if (pathOffset >= Smb2::kHeaderSize && pathLength > 0)
        path = fromUtf16(body.mid(int(pathOffset) - int(Smb2::kHeaderSize), pathLength));

    const int slash = path.lastIndexOf(QLatin1Char('\\'));
    const QString share = slash >= 0 ? path.mid(slash + 1) : path;

    Connection::Tree tree;
    tree.name = share;
    if (share.compare(QStringLiteral("IPC$"), Qt::CaseInsensitive) == 0) {
        tree.pipe = true;
    } else {
        const auto found = m_shares.constFind(share.toLower());
        // A share exists only for a principal the domain authenticated: an
        // anonymous session gets the same answer a Windows DC gives it.
        if (found == m_shares.constEnd() || !connection->authenticated) {
            *status = Smb2::StatusBadNetworkName;
            QByteArray out;
            putLe16(out, 16);
            out.append(QByteArray(14, '\0'));
            return out;
        }
        tree.path = found->path;
        tree.readOnly = found->readOnly;
    }

    const quint32 treeId = quint32(++connection->nextTree);
    connection->trees.insert(treeId, tree);
    if (treeIdOut)
        *treeIdOut = treeId;

    QByteArray out;
    putLe16(out, 16);     // StructureSize
    out.append(char(tree.pipe ? 2 : 1)); // ShareType: pipe or disk
    out.append(char(0));  // Reserved
    // A read-only disk share says so, so a client does not attempt writes it
    // would only have refused.
    putLe32(out, tree.pipe || !tree.readOnly ? 0u : 0x00000001u); // ShareFlags
    putLe32(out, 0);      // Capabilities
    putLe32(out, 0x001f01ff); // MaximalAccess
    emit requestReceived(QStringLiteral("SMB2 tree connect %1").arg(share));
    return out;
}

namespace {

// The 89-byte CREATE response, with everything but the file id left empty: the
// shape every refusal answer also uses.
QByteArray createResponse(quint64 id, quint32 attributes, quint64 endOfFile,
                          const QByteArray &times, quint32 createAction)
{
    QByteArray out;
    putLe16(out, 89);          // StructureSize
    out.append(char(0));       // OplockLevel
    out.append(char(0));       // Flags
    putLe32(out, createAction);
    out.append(times.left(32).leftJustified(32, '\0')); // four timestamps
    putLe64(out, (endOfFile + 4095) / 4096 * 4096);     // AllocationSize
    putLe64(out, endOfFile);                            // EndOfFile
    putLe32(out, attributes);
    putLe32(out, 0);           // Reserved2
    putLe64(out, id);          // FileId.Persistent
    putLe64(out, id);          // FileId.Volatile
    putLe32(out, 0);           // CreateContextsOffset
    putLe32(out, 0);           // CreateContextsLength
    return out;
}

} // namespace

QByteArray Smb2Server::create(Connection *connection, quint32 treeId, const QByteArray &body,
                              quint32 *status)
{
    const quint16 nameOffset = readLe16(body, 44);
    const quint16 nameLength = readLe16(body, 46);
    QString name;
    if (nameOffset >= Smb2::kHeaderSize && nameLength > 0)
        name = fromUtf16(body.mid(int(nameOffset) - int(Smb2::kHeaderSize), nameLength));
    while (name.startsWith(QLatin1Char('\\')))
        name.remove(0, 1);

    const auto treeIt = connection->trees.constFind(treeId);
    if (treeIt != connection->trees.constEnd() && !treeIt->pipe) {
        const Connection::Tree &tree = *treeIt;
        QString relative;
        if (!safeRelativeName(name, &relative)) {
            *status = Smb2::StatusObjectNameNotFound;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }
        // Every access that could change the share is refused by a read-only
        // share before the name is even resolved: data, attributes, delete,
        // ACLs. A client creating a new name gets access denied, not "not
        // found", exactly as a Windows read-only share answers it.
        constexpr quint32 kWriteAccess = 0x00000002u  // FILE_WRITE_DATA / FILE_ADD_FILE
                                         | 0x00000004u // FILE_APPEND_DATA / ADD_SUBDIRECTORY
                                         | 0x00000010u // FILE_WRITE_EA
                                         | 0x00000100u // FILE_WRITE_ATTRIBUTES
                                         | 0x00010000u // DELETE
                                         | 0x00040000u // WRITE_DAC
                                         | 0x00080000u; // WRITE_OWNER
        const quint32 desiredAccess = readLe32(body, 24);
        const quint32 createOptions = readLe32(body, 40);
        const quint32 createDisposition = readLe32(body, 36);
        if (tree.readOnly
            && ((desiredAccess & kWriteAccess) || createDisposition == 2 /* FILE_CREATE */
                || createDisposition == 5 /* FILE_OVERWRITE_IF */)) {
            *status = Smb2::StatusAccessDenied;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }

        const QString full = resolveCaseInsensitive(tree.path, relative);
        if (full.isEmpty()) {
            *status = Smb2::StatusObjectNameNotFound;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }
        const QFileInfo info(full);

        const quint64 id = ++connection->nextHandle;
        Connection::Handle handle;
        handle.name = relative;
        handle.path = full;
        handle.readOnly = tree.readOnly;
        QByteArray times;
        quint32 attributes = 0;
        quint64 endOfFile = 0;
        if (info.isDir()) {
            handle.directory = true;
            attributes = 0x00000010u; // FILE_ATTRIBUTE_DIRECTORY
        } else if (info.isFile()) {
            auto *file = new QFile(full);
            if (!file->open(QIODevice::ReadOnly)) {
                delete file;
                *status = Smb2::StatusAccessDenied;
                return createResponse(0, 0, 0, QByteArray(), 0);
            }
            handle.file = file;
            endOfFile = quint64(file->size());
            attributes = 0x00000080u; // FILE_ATTRIBUTE_NORMAL
            const QDateTime modified = info.lastModified();
            const QDateTime accessed = info.lastRead();
            const QDateTime changed = info.metadataChangeTime();
            for (const QDateTime &stamp : { info.birthTime(), accessed, modified, changed })
                putLe64(times, fileTime(stamp.isValid() ? stamp : modified));
        } else {
            *status = Smb2::StatusObjectNameNotFound;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }
        // FILE_DIRECTORY_FILE on a file (or its absence on a directory) is the
        // mismatch MS-SMB2 3.3.5.9 rejects rather than silently opening.
        if ((createOptions & 0x00000001u) && !handle.directory) {
            *status = Smb2::StatusNotADirectory;
            delete handle.file;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }
        if ((createOptions & 0x00000040u) && handle.directory) { // FILE_NON_DIRECTORY_FILE
            *status = Smb2::StatusInvalidParameter;
            return createResponse(0, 0, 0, QByteArray(), 0);
        }
        connection->handles.insert(id, handle);
        emit requestReceived(QStringLiteral("SMB2 open %1%2%3")
                                 .arg(tree.name, relative.isEmpty() ? QString()
                                                                  : QStringLiteral("\\"))
                                 .arg(relative));
        return createResponse(id, attributes, endOfFile, times, 1); // FILE_OPENED
    }

    RpcServer *endpoint = m_pipes.value(name.toLower());
    if (!endpoint) {
        *status = Smb2::StatusObjectNameNotFound;
        return createResponse(0, 0, 0, QByteArray(), 0);
    }

    const quint64 id = ++connection->nextHandle;
    Connection::Handle handle;
    handle.name = name;
    handle.channel = endpoint->newChannel(QStringLiteral("smb2:%1").arg(name));
    // The session authenticated the principal; the pipe carries that identity to
    // the endpoint the same way a Windows DC does for \pipe\samr.
    if (connection->authenticated)
        handle.channel->setTransportIdentity(connection->user);
    connection->handles.insert(id, handle);

    emit requestReceived(QStringLiteral("SMB2 open \\pipe\\%1").arg(name));
    return createResponse(id, 0, 0, QByteArray(), 1); // FILE_OPENED
}

QByteArray Smb2Server::write(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint16 dataOffset = readLe16(body, 2);
    const quint32 length = readLe32(body, 4);
    const quint64 id = readLe64(body, 16);

    auto it = connection->handles.find(id);
    if (it == connection->handles.end() || !it->channel) {
        // A disk share is read-only, so this is the refusal a write to it gets.
        *status = it != connection->handles.end() ? Smb2::StatusAccessDenied
                                                  : Smb2::StatusFileClosed;
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

// File-system controls a DC's SMB server must process (MS-SMB2 2.2.1.5): the
// named-pipe transceive clients use for every \pipe\ write+read, and the
// negotiate-validation fsctl modern Samba sends right after Negotiate.
constexpr quint32 kFsctlPipeTransceive = 0x0011c017u;
constexpr quint32 kFsctlValidateNegotiate = 0x00140204u;

QByteArray Smb2Server::ioctlMessage(Connection *connection, const QByteArray &body, quint32 *status)
{
    if (body.size() < 48) {
        *status = Smb2::StatusInvalidParameter;
        QByteArray out;
        putLe16(out, 49);
        out.append(QByteArray(46, '\0'));
        return out;
    }
    // Request (MS-SMB2 2.2.31): StructureSize(2)=57, Reserved(2), CtlCode(4),
    // FileId(16), InputOffset(4), InputCount(4), MaxInputResponse(4),
    // OutputOffset(4), OutputCount(4), MaxOutputResponse(4), Flags(4).
    const quint32 ctlCode = readLe32(body, 4);
    const QByteArray fileId = body.mid(8, 16);
    const quint32 inputOffset = readLe32(body, 24);
    const quint32 inputCount = readLe32(body, 28);
    const quint32 maxOutputResponse = readLe32(body, 44);
    emit requestReceived(QStringLiteral("SMB2 ioctl 0x%1")
                             .arg(ctlCode, 8, 16, QLatin1Char('0')));

    // Response (MS-SMB2 2.2.32): StructureSize(2)=49, Reserved(2), CtlCode(4),
    // FileId(16), InputOffset(4), InputCount(4), OutputOffset(4), OutputCount(4),
    // Flags(4), Reserved(4) — 48 bytes, so the reply buffer starts at header+48.
    QByteArray out;
    putLe16(out, 49);                 // StructureSize
    putLe16(out, 0);                  // Reserved
    putLe32(out, ctlCode);            // @4
    out.append(fileId);               // FileId: echo the request's persistent+volatile @8
    putLe32(out, 0);                  // InputOffset: no input in the response @24
    putLe32(out, 0);                  // InputCount @28
    putLe32(out, quint32(Smb2::kHeaderSize + 48)); // OutputOffset (from SMB2 header) @32
    // OutputCount @36, Flags @40 and Reserved @44 follow; for a transceive
    // they are followed by the reply data, which lands at header+48.

    switch (ctlCode) {
    case kFsctlPipeTransceive: {
        const quint64 id = readLe64(fileId, 0);
        auto it = connection->handles.find(id);
        if (it == connection->handles.end() || !it->channel) {
            *status = Smb2::StatusFileClosed;
            out.clear();
            putLe16(out, 49);
            out.append(QByteArray(46, '\0'));
            return out;
        }
        // Same hand-off as the Write path: incoming bytes may pack more than
        // one PDU, split on frag_length, answers queued for the read back.
        QByteArray data;
        if (inputOffset >= Smb2::kHeaderSize && inputCount > 0)
            data = body.mid(int(inputOffset) - int(Smb2::kHeaderSize), int(inputCount));
        while (data.size() >= 16) {
            const quint16 fragLength = readLe16(data, 8);
            if (fragLength < 16 || data.size() < fragLength)
                break;
            const QByteArray pdu = data.left(fragLength);
            data.remove(0, fragLength);
            it->pending.append(it->channel->feed(pdu));
        }
        const int take = int(qMin(maxOutputResponse > 0 ? maxOutputResponse : quint32(65536),
                                  quint32(it->pending.size())));
        const QByteArray outBytes = it->pending.left(take);
        it->pending.remove(0, take);

        putLe32(out, quint32(outBytes.size()));      // OutputCount
        putLe32(out, 0);                             // Flags
        putLe32(out, 0);                             // Reserved
        out.append(outBytes);
        *status = Smb2::StatusSuccess;
        emit requestReceived(QStringLiteral("SMB2 transceive %1 (%2 in, %3 out)")
                                 .arg(it->name).arg(inputCount).arg(outBytes.size()));
        return out;
    }
    case kFsctlValidateNegotiate:
        // The client asked to re-confirm the dialect. Windows answers that it
        // will not validate when support is absent, and Samba then trusts the
        // original negotiate — STATUS_NOT_SUPPORTED is the conforming reply.
        *status = Smb2::StatusNotSupported;
        out.clear();
        putLe16(out, 49);
        out.append(QByteArray(46, '\0'));
        return out;
    default:
        *status = Smb2::StatusNotSupported;
        QByteArray refused;
        putLe16(refused, 49);
        refused.append(QByteArray(46, '\0'));
        return refused;
    }
}

QByteArray Smb2Server::read(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint32 length = readLe32(body, 4);
    const quint64 offset = readLe64(body, 8);
    const quint64 id = readLe64(body, 16);

    auto it = connection->handles.find(id);
    if (it == connection->handles.end() || (!it->channel && !it->file)) {
        *status = Smb2::StatusFileClosed;
        QByteArray out;
        putLe16(out, 17);
        out.append(QByteArray(15, '\0'));
        return out;
    }

    QByteArray data;
    if (it->file) {
        // A file read is positional: the client says where, every time.
        if (!it->file->seek(qint64(offset))) {
            *status = Smb2::StatusEndOfFile;
            putLe16(data, 17);
            data.append(QByteArray(15, '\0'));
            return data;
        }
        data = it->file->read(qint64(length));
        // A client that asked for more than the file holds gets what is there
        // and no error: only a read that starts past the end is an EOF.
        if (data.isEmpty() && offset >= quint64(it->file->size()))
            *status = Smb2::StatusEndOfFile;
    } else {
        const int take = qMin(int(length), it->pending.size());
        data = it->pending.left(take);
        it->pending.remove(0, take);
    }

    QByteArray out;
    putLe16(out, 17);   // StructureSize
    out.append(char(Smb2::kHeaderSize + 16)); // DataOffset
    out.append(char(0));                      // Reserved
    putLe32(out, quint32(data.size()));       // DataLength
    putLe32(out, it->channel ? quint32(it->pending.size()) : 0u); // DataRemaining
    putLe32(out, 0);                          // Reserved2
    out.append(data);
    return out;
}

namespace {

QByteArray toUtf16Bytes(const QString &text)
{
    QByteArray out;
    out.reserve(text.size() * 2);
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
    return out;
}

quint32 shareAttributes(const QFileInfo &info)
{
    if (info.isDir())
        return 0x00000010u; // FILE_ATTRIBUTE_DIRECTORY
    return 0x00000080u;     // FILE_ATTRIBUTE_NORMAL
}

void appendShareTimes(QByteArray &out, const QFileInfo &info)
{
    const QDateTime modified = info.lastModified();
    for (const QDateTime &stamp : { info.birthTime(), info.lastRead(), modified,
                                    info.metadataChangeTime() })
        putLe64(out, fileTime(stamp.isValid() ? stamp : modified));
}

quint64 allocationSize(const QFileInfo &info)
{
    if (info.isDir() || info.size() <= 0)
        return 0;
    return quint64((info.size() + 4095) / 4096 * 4096);
}

// One directory entry in the class the client asked for (MS-FSCC 2.4.10 to
// 2.4.22). NextEntryOffset is left zero for the caller, which knows which
// entries are followed by another.
QByteArray directoryEntry(quint8 infoClass, const QFileInfo &info, const QString &name,
                          quint32 index, quint64 fileId)
{
    const QByteArray encoded = toUtf16Bytes(name);
    QByteArray out;
    putLe32(out, 0);     // NextEntryOffset
    putLe32(out, index); // FileIndex
    if (infoClass == 0x0c) { // FILE_NAMES_INFORMATION
        putLe32(out, quint32(encoded.size()));
        out.append(encoded);
        return out;
    }
    appendShareTimes(out, info);
    putLe64(out, quint64(info.isDir() ? 0 : qMax<qint64>(0, info.size()))); // EndOfFile
    putLe64(out, allocationSize(info));
    putLe32(out, shareAttributes(info));
    putLe32(out, quint32(encoded.size())); // FileNameLength
    switch (infoClass) {
    case 0x01: // FILE_DIRECTORY_INFORMATION
        break;
    case 0x02: // FILE_FULL_DIR_INFORMATION
        putLe32(out, 0); // EaSize
        break;
    case 0x03: // FILE_BOTH_DIR_INFORMATION
    case 0x25: // FILE_ID_BOTH_DIR_INFORMATION
        putLe32(out, 0);              // EaSize
        out.append(char(0));          // ShortNameLength
        out.append(char(0));          // Reserved, which keeps ShortName aligned
        out.append(QByteArray(24, '\0')); // ShortName
        if (infoClass == 0x25) {
            // FileId is a LARGE_INTEGER: Windows emits it 8-byte aligned,
            // which puts the name at 104 and is what redirectors parse.
            out.append(QByteArray(2, '\0'));
            putLe64(out, fileId);
        }
        break;
    case 0x26: // FILE_ID_FULL_DIR_INFORMATION
        putLe32(out, 0);
        putLe64(out, fileId);
        break;
    default:
        return QByteArray(); // not a class this server answers
    }
    out.append(encoded);
    return out;
}

QByteArray queryDirectoryResponse(quint32 status)
{
    QByteArray out;
    putLe16(out, 9);  // StructureSize
    putLe16(out, quint16(Smb2::kHeaderSize + 8)); // OutputBufferOffset
    putLe32(out, 0);  // OutputBufferLength
    return out;
}

} // namespace

// QUERY_DIRECTORY (MS-SMB2 2.2.27): a read-only share's listing, which is how
// a member enumerates the Policies directory of the domain's SYSVOL.
QByteArray Smb2Server::queryDirectory(Connection *connection, const QByteArray &body,
                                      quint32 *status)
{
    const quint8 infoClass = body.size() > 2 ? quint8(body.at(2)) : quint8(0);
    const quint8 flags = body.size() > 3 ? quint8(body.at(3)) : quint8(0);
    const quint16 nameOffset = readLe16(body, 24);
    const quint16 nameLength = readLe16(body, 26);
    const quint32 outputLength = readLe32(body, 28);
    const quint64 id = readLe64(body, 8);

    auto it = connection->handles.find(id);
    if (it == connection->handles.end()) {
        *status = Smb2::StatusFileClosed;
        return queryDirectoryResponse(*status);
    }
    if (!it->directory) {
        *status = Smb2::StatusNotADirectory;
        return queryDirectoryResponse(*status);
    }

    QString pattern;
    if (nameOffset >= Smb2::kHeaderSize && nameLength > 0)
        pattern = fromUtf16(body.mid(int(nameOffset) - int(Smb2::kHeaderSize), nameLength));

    constexpr quint8 kRestartScan = 0x01;
    constexpr quint8 kReturnSingleEntry = 0x02;
    constexpr quint8 kReopen = 0x10;
    if (!it->listed || (flags & (kRestartScan | kReopen)) || it->pattern != pattern) {
        it->entries.clear();
        it->entriesServed = 0;
        it->pattern = pattern;
        it->listed = true;
        const QFileInfo directory(it->path);
        QStringList filters;
        bool all = pattern.isEmpty() || pattern == QLatin1String("*") || pattern == QLatin1String("*.*");
        filters << (all ? QStringLiteral("*") : pattern);
        // Every real server lists the directory and its parent first; a
        // client that only asked for one name pattern gets just the matches.
        if (all) {
            it->entries.append(qMakePair(QStringLiteral("."), directory));
            const QString parentPath = directory.absolutePath();
            it->entries.append(qMakePair(QStringLiteral(".."),
                                         parentPath == directory.absoluteFilePath()
                                             ? directory
                                             : QFileInfo(parentPath)));
        }
        const QFileInfoList matches =
            QDir(it->path).entryInfoList(filters, QDir::AllEntries | QDir::Hidden
                                                     | QDir::NoDotAndDotDot,
                                         QDir::NoSort);
        for (const QFileInfo &entry : matches)
            it->entries.append(qMakePair(entry.fileName(), entry));
    }

    QByteArray buffer;
    QList<int> starts;
    while (it->entriesServed < it->entries.size()) {
        const QPair<QString, QFileInfo> &entry = it->entries.at(it->entriesServed);
        QByteArray bytes = directoryEntry(infoClass, entry.second, entry.first,
                                          quint32(it->entriesServed),
                                          quint64(qHash(it->path + QLatin1Char('/') + entry.first))
                                              | 1u);
        if (bytes.isEmpty()) {
            *status = Smb2::StatusInvalidParameter;
            return queryDirectoryResponse(*status);
        }
        const int padded = (bytes.size() + 7) & ~7;
        bytes.append(QByteArray(padded - bytes.size(), '\0'));
        if (outputLength > 0 && quint32(buffer.size() + bytes.size()) > outputLength) {
            // The first entry must fit whole, or the answer is that it did not.
            if (buffer.isEmpty()) {
                *status = Smb2::StatusBufferOverflow;
                return queryDirectoryResponse(*status);
            }
            break;
        }
        starts.append(buffer.size());
        buffer.append(bytes);
        ++it->entriesServed;
        if (flags & kReturnSingleEntry)
            break;
    }

    if (buffer.isEmpty()) {
        *status = it->entries.isEmpty() ? Smb2::StatusNoSuchFile : Smb2::StatusNoMoreFiles;
        return queryDirectoryResponse(*status);
    }
    // Each entry points at the next; the last one ends the chain.
    for (int i = 0; i < starts.size(); ++i) {
        const int next = i + 1 < starts.size() ? starts.at(i + 1) - starts.at(i) : 0;
        setLe32(buffer, starts.at(i), quint32(next));
    }

    QByteArray out;
    putLe16(out, 9);  // StructureSize
    putLe16(out, quint16(Smb2::kHeaderSize + 8)); // OutputBufferOffset
    putLe32(out, quint32(buffer.size()));
    out.append(buffer);
    *status = Smb2::StatusSuccess;
    emit requestReceived(QStringLiteral("SMB2 list %1%2%3 class 0x%4")
                             .arg(it->name).arg(it->name.isEmpty() ? QString()
                                                                  : QStringLiteral("\\"))
                             .arg(pattern)
                             .arg(infoClass, 2, 16, QLatin1Char('0')));
    return out;
}

// QUERY_INFO (MS-SMB2 2.2.37): file and filesystem attributes, which is what
// `smbclient` and every mount helper ask for right after opening a file.
QByteArray Smb2Server::queryInfo(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint8 infoType = body.size() > 2 ? quint8(body.at(2)) : quint8(0);
    const quint8 infoClass = body.size() > 3 ? quint8(body.at(3)) : quint8(0);
    const quint32 outputLength = readLe32(body, 4);
    const quint64 id = readLe64(body, 24);

    auto answer = [status](const QByteArray &buffer, quint32 outLength, quint32 answerStatus) {
        QByteArray out;
        putLe16(out, 9); // StructureSize
        putLe16(out, quint16(Smb2::kHeaderSize + 8)); // OutputBufferOffset
        if (outLength > 0 && buffer.size() > int(outLength)) {
            putLe32(out, 0);
            *status = Smb2::StatusBufferOverflow;
            return out;
        }
        putLe32(out, quint32(buffer.size()));
        out.append(buffer);
        *status = answerStatus;
        return out;
    };

    emit requestReceived(QStringLiteral("SMB2 query info type %1 class 0x%2")
                             .arg(infoType)
                             .arg(infoClass, 2, 16, QLatin1Char('0')));

    auto it = connection->handles.find(id);
    if (it == connection->handles.end() || it->channel) {
        *status = it == connection->handles.end() ? Smb2::StatusFileClosed
                                                  : Smb2::StatusNotSupported;
        QByteArray out;
        putLe16(out, 9);
        putLe16(out, quint16(Smb2::kHeaderSize + 8));
        putLe32(out, 0);
        return out;
    }

    const QFileInfo info(it->path);
    QByteArray buffer;
    if (infoType == 1) { // SMB2_0_INFO_FILE
        switch (infoClass) {
        case 0x04: // FILE_BASIC_INFORMATION
            appendShareTimes(buffer, info);
            putLe32(buffer, shareAttributes(info));
            putLe32(buffer, 0); // the structure is padded to 8 bytes
            break;
        case 0x05: // FILE_STANDARD_INFORMATION
            putLe64(buffer, allocationSize(info));
            putLe64(buffer, quint64(info.isDir() ? 0 : info.size()));
            putLe32(buffer, info.isDir() ? 0 : 1); // NumberOfLinks
            buffer.append(char(0));                // DeletePending
            buffer.append(char(info.isDir() ? 1 : 0));
            buffer.append(QByteArray(2, '\0'));
            break;
        case 0x06: // FILE_INTERNAL_INFORMATION
            putLe64(buffer, quint64(qHash(it->path)) | 1u);
            break;
        case 0x07: // FILE_EA_INFORMATION
            putLe32(buffer, 0);
            break;
        case 0x08: // FILE_ACCESS_INFORMATION
            putLe32(buffer, 0x00120089u); // read data, attributes, read attributes, synchronise
            break;
        case 0x09: // FILE_POSITION_INFORMATION
            putLe64(buffer, info.isDir() ? 0 : quint64(it->file ? it->file->pos() : 0));
            break;
        case 0x13: // FILE_MODE_INFORMATION
            putLe32(buffer, 0);
            break;
        case 0x22: // FILE_NETWORK_OPEN_INFORMATION
            appendShareTimes(buffer, info);
            putLe64(buffer, allocationSize(info));
            putLe64(buffer, quint64(info.isDir() ? 0 : info.size()));
            putLe32(buffer, shareAttributes(info));
            putLe32(buffer, 0);
            break;
        case 0x12: { // FILE_ALL_INFORMATION, which `smbclient` asks for
            appendShareTimes(buffer, info);
            putLe32(buffer, shareAttributes(info));
            putLe32(buffer, 0); // basic information is padded to 8 bytes
            putLe64(buffer, allocationSize(info));
            putLe64(buffer, quint64(info.isDir() ? 0 : info.size()));
            putLe32(buffer, info.isDir() ? 0 : 1); // NumberOfLinks
            buffer.append(char(0));                // DeletePending
            buffer.append(char(info.isDir() ? 1 : 0));
            buffer.append(QByteArray(2, '\0'));
            putLe64(buffer, quint64(qHash(it->path)) | 1u); // IndexNumber
            putLe32(buffer, 0);                             // EaSize
            putLe32(buffer, 0x00120089u);                   // Access
            putLe64(buffer, quint64(it->file ? it->file->pos() : 0)); // Position
            putLe32(buffer, 0);                             // Mode
            putLe32(buffer, 0);                             // Alignment
            const QByteArray fileName = toUtf16Bytes(info.fileName());
            putLe32(buffer, quint32(fileName.size()));
            buffer.append(fileName);
            break;
        }
        case 0x30: { // FILE_ID_INFORMATION
            putLe64(buffer, quint64(qHash(it->path.section(QLatin1Char('/'), 0, -2))) | 1u);
            const quint64 fileId = quint64(qHash(it->path)) | 1u;
            putLe64(buffer, fileId);
            putLe64(buffer, fileId);
            break;
        }
        default:
            *status = Smb2::StatusInvalidParameter;
            return answer(QByteArray(), 0, Smb2::StatusInvalidParameter);
        }
        return answer(buffer, outputLength, Smb2::StatusSuccess);
    }
    if (infoType == 2) { // SMB2_0_INFO_FILESYSTEM
        const QStorageInfo storage(it->path);
        const quint64 blockSize = 4096;
        const quint64 totalBytes = quint64(storage.bytesTotal() > 0 ? storage.bytesTotal() : 0);
        const quint64 freeBytes = quint64(storage.bytesAvailable() > 0 ? storage.bytesAvailable() : 0);
        switch (infoClass) {
        case 0x01: { // FILE_FS_VOLUME_INFORMATION
            putLe64(buffer, fileTime(QFileInfo(it->path).birthTime()));
            putLe32(buffer, quint32(qHash(it->path)) | 1u); // VolumeSerialNumber
            const QByteArray label = toUtf16Bytes(QStringLiteral("SYSVOL"));
            putLe32(buffer, quint32(label.size()));
            buffer.append(char(0)); // SupportsObjects
            buffer.append(char(0));
            buffer.append(label);
            break;
        }
        case 0x03: // FILE_FS_SIZE_INFORMATION
            putLe64(buffer, totalBytes / blockSize);
            putLe64(buffer, freeBytes / blockSize);
            putLe32(buffer, 1); // SectorsPerAllocationUnit
            putLe32(buffer, quint32(blockSize));
            break;
        case 0x05: { // FILE_FS_ATTRIBUTE_INFORMATION
            putLe32(buffer, 0x00000002u | 0x00000004u | 0x00080000u); // case preserved, case sensitive, unicode
            putLe32(buffer, 255); // MaximumComponentNameLength
            const QByteArray name = toUtf16Bytes(QStringLiteral("NTFS"));
            putLe32(buffer, quint32(name.size()));
            buffer.append(name);
            break;
        }
        case 0x07: // FILE_FS_FULL_SIZE_INFORMATION
            putLe64(buffer, totalBytes / blockSize);
            putLe64(buffer, freeBytes / blockSize);
            putLe64(buffer, freeBytes / blockSize);
            putLe32(buffer, 1);
            putLe32(buffer, quint32(blockSize));
            break;
        default:
            return answer(QByteArray(), 0, Smb2::StatusInvalidParameter);
        }
        return answer(buffer, outputLength, Smb2::StatusSuccess);
    }
    // Security and quota descriptors are not served by these shares.
    return answer(QByteArray(), 0, Smb2::StatusNotSupported);
}

// SET_INFO: every write to a read-only share, including the delete-on-close a
// client sends after opening a file it intended to remove, is refused.
QByteArray Smb2Server::setInfo(Connection *connection, const QByteArray &body, quint32 *status)
{
    const quint64 id = readLe64(body, 16);
    const auto it = connection->handles.constFind(id);
    *status = it == connection->handles.constEnd() || it->channel ? Smb2::StatusNotSupported
                                                                 : Smb2::StatusAccessDenied;
    QByteArray out;
    putLe16(out, 2); // StructureSize
    return out;
}

QByteArray Smb2Server::closeHandle(Connection *connection, const QByteArray &body, quint32 *status)
{
    Q_UNUSED(status)
    const quint64 id = readLe64(body, 8);
    auto it = connection->handles.find(id);
    if (it != connection->handles.end()) {
        delete it->channel;
        it->channel = nullptr;
        delete it->file;
        it->file = nullptr;
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
