// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SMB2_H
#define SMB2_H

#include <QByteArray>
#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QStringList>

#include "Rpc.h"

class QTcpServer;
class QTcpSocket;

// SMB2 (MS-SMB2) enough to carry DCE/RPC over named pipes and to serve the
// domain's file shares: negotiate, session setup with SPNEGO/NTLMSSP against the
// same authenticator SAMR and LSAD use, tree connect to IPC$ or a disk share,
// create, read, directory query, close. A client that reaches `\\dc\pipe\lsarpc`
// gets the same bind, authentication and dispatch it would get on `lsadPort`,
// because it is the same code; a client that reaches `\\dc\SYSVOL` gets the
// directory tree under the share root, which is how a member reads its GPOs.
namespace Smb2 {

// Command codes (MS-SMB2 §2.2.1).
enum Command : quint16 {
    CmdNegotiate = 0,
    CmdSessionSetup = 1,
    CmdLogoff = 2,
    CmdTreeConnect = 3,
    CmdTreeDisconnect = 4,
    CmdCreate = 5,
    CmdClose = 6,
    CmdFlush = 7,
    CmdRead = 8,
    CmdWrite = 9,
    CmdIoctl = 11,
    CmdEcho = 13,
    CmdQueryDirectory = 14,
    CmdQueryInfo = 16,
    CmdSetInfo = 17
};

// The dialects this server answers. 2.1 is offered without 3.x, whose preauth
// integrity would otherwise have to be computed for a session with no
// encryption keys.
enum Dialect : quint16 {
    Dialect202 = 0x0202,
    Dialect210 = 0x0210
};

enum Status : quint32 {
    StatusSuccess = 0x00000000u,
    StatusMoreProcessingRequired = 0xc0000016u,
    StatusLogonFailure = 0xc000006du,
    StatusBadNetworkName = 0xc00000ccu,
    StatusObjectNameNotFound = 0xc0000034u,
    StatusNotSupported = 0xc00000bbu,
    StatusInvalidParameter = 0xc000000du,
    StatusFileClosed = 0xc0000128u,
    StatusBufferOverflow = 0x80000005u,
    StatusNoSuchFile = 0xc000000fu,
    StatusAccessDenied = 0xc0000022u,
    StatusInvalidDeviceRequest = 0xc0000010u,
    StatusNotADirectory = 0xc0000103u,
    StatusNoMoreFiles = 0x80000006u,
    StatusEndOfFile = 0xc0000011u,
    StatusDiskFull = 0xc000007fu
};

constexpr quint32 kHeaderSize = 64;
constexpr quint32 kFlagsServerToRedirector = 0x00000001u;

} // namespace Smb2

class Smb2Server : public QObject
{
    Q_OBJECT

public:
    explicit Smb2Server(QObject *parent = nullptr);
    ~Smb2Server() override;

    // Registers a pipe name ("samr", "lsarpc") and the endpoint its PDUs go to.
    void addPipe(const QString &name, RpcServer *endpoint);
    // Exposes a directory as a disk share ("SYSVOL", "NETLOGON"). Only a
    // client with an authenticated session may connect; a read-only share
    // refuses every write, set-info and delete with access denied.
    void addShare(const QString &name, const QString &path, bool readOnly = true);
    // The same authenticator SAMR and LSAD use, so one directory credential
    // opens the pipes as well as the TCP endpoints.
    void setAuthenticator(Rpc::Authenticator authenticator);
    void setDomainNames(const QString &domain, const QString &serverName,
                        const QString &dnsDomain = QString());

    bool listen(quint16 port = 445, const QHostAddress &address = QHostAddress::Any);
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    // One NetBIOS-framed SMB2 message in, zero or more messages out. Tests use
    // this directly; the socket path differs only in who owns the bytes.
    QByteArray feed(const QByteArray &nbss);

signals:
    void requestReceived(const QString &operation);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();

private:
    struct Connection;

    QByteArray handleMessage(Connection *connection, const QByteArray &message);
    // SMB1 (MS-CIFS) for clients that never negotiate SMB2, such as Windows
    // 2000: it reuses this server's pipe map and authenticator.
    QByteArray handleSmb1(Connection *connection, const QByteArray &message);
    // The SMB2 negotiate response a classic SMB1 wildcard client must be
    // answered with ([MS-SMB2] 3.3.5.3.1, SMB1 disabled); empty when the
    // message is not that packet, in which case handleMessage takes it.
    QByteArray wildcardAnswer(Connection *connection, const QByteArray &message);
    QByteArray negotiate(Connection *connection, const QByteArray &body, quint32 status);
    QByteArray sessionSetup(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray treeConnect(Connection *connection, const QByteArray &body, quint32 *status,
                           quint32 *treeIdOut);
    QByteArray create(Connection *connection, quint32 treeId, const QByteArray &body,
                      quint32 *status);
    QByteArray write(Connection *connection, const QByteArray &body, quint32 *status);
    // FSCTL_PIPE_TRANSCEIVE (the write+read every client writes pipe PDUs with)
    // and friends; rpcclient uses it for every \pipe read and write.
    QByteArray ioctlMessage(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray read(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray queryDirectory(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray queryInfo(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray setInfo(Connection *connection, const QByteArray &body, quint32 *status);
    QByteArray closeHandle(Connection *connection, const QByteArray &body, quint32 *status);

    QTcpServer *m_server = nullptr;
    QList<Connection *> m_connections;
    QHash<QString, RpcServer *> m_pipes;
    struct Share {
        QString path;
        bool readOnly = true;
    };
    QHash<QString, Share> m_shares;
    Rpc::Authenticator m_authenticator;
    QString m_domain;
    QString m_serverName;
    QString m_dnsDomain;
};

#endif // SMB2_H
