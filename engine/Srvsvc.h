// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SRVSVC_H
#define SRVSVC_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>

#include "Rpc.h"

class RpcServer;

// The server service (MS-SRVS): what a client calls to ask a server which
// shares it offers. A Windows server answers it on \pipe\srvsvc; on this DC the
// shares are the same ones SMB2 serves out of the domain's SYSVOL tree, so the
// answer a client lists is the set it can then open.
namespace Srvsvc {

// Opnums from MS-SRVS 3.1.4. Samba's srvsvc.idl numbers them the same way in
// its `/* Function 0xNN */` comments.
enum Opnum : quint16 {
    OpNetrShareEnum = 15,
    // The same call with a sticky handle: Samba's rpcclient asks this one for
    // `netshareenum`, which is the client the gap was measured with.
    OpNetrShareEnumSticky = 36
};

// SHARE_TYPE_* (MS-SRVS 2.2.2.4).
constexpr quint32 kTypeDiskTree = 0x00000000u;
constexpr quint32 kTypePrintQueue = 0x00000001u;
constexpr quint32 kTypeDevice = 0x00000002u;
constexpr quint32 kTypeIpc = 0x00000003u;
constexpr quint32 kTypeSpecial = 0x80000000u;

// One share as both information levels carry it. Level 1 carries name, type and
// comment; level 2 adds the local path the share is served from.
struct Share {
    QString name;
    quint32 type = kTypeDiskTree;
    QString comment;
    QString path;
};

Rpc::Interface interface();

} // namespace Srvsvc

// The endpoint NetrShareEnum and NetrShareEnumSticky ride on.
class SrvsvcServer : public QObject
{
    Q_OBJECT

public:
    explicit SrvsvcServer(QObject *parent = nullptr);

    // The shares to report, in the order the answer lists them.
    void setShares(const QList<Srvsvc::Share> &shares) { m_shares = shares; }
    QList<Srvsvc::Share> shares() const { return m_shares; }

    // The same authenticator SAMR, LSAD and DRSR answer behind: a client that
    // binds over ncacn_ip_tcp authenticates with NTLMSSP, while a client that
    // reaches \pipe\srvsvc through an authenticated SMB session carries that
    // identity and needs no second exchange.
    void setAuthenticator(Rpc::Authenticator authenticator);

    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // One NDR request in, one response out, for the endpoint and the tests.
    QByteArray handleCall(quint16 opnum, const QByteArray &stub);

signals:
    void requestReceived(const QString &operation);

private:
    QByteArray enumerate(const QByteArray &stub);

    RpcServer *m_rpc = nullptr;
    QList<Srvsvc::Share> m_shares;
};

#endif // SRVSVC_H
