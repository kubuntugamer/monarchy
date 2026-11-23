// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef BROWSER_H
#define BROWSER_H

#include <QByteArray>
#include <QHostAddress>
#include <QObject>
#include <QString>

#include "Rpc.h"

class RpcServer;

// The browser service (MS-BRWS), which a Windows member calls over
// \pipe\browser to list the servers in its domain. A Windows 2000 member's logon
// enumerates the domain this way, and a DC that does not answer the pipe at all
// leaves that step failing with STATUS_OBJECT_NAME_NOT_FOUND before the client
// ever reaches Netlogon.
//
// This endpoint answers the bind and refuses the calls with ERROR_NOT_SUPPORTED
// rather than inventing an enumeration. That is a defined answer a client acts
// on — it has other ways to enumerate and takes one — while a fabricated
// SERVER_INFO container with a layout no Windows client sent us would be a
// protocol guess that only looks like progress. The refusal is measured: the
// client's logon continues past this step instead of failing to open the pipe.
namespace Browser {

// MS-BRWS 3.1.1: 6bffd098-a112-3610-9833-012892020162 v0.0.
Rpc::Interface interface();

// The opnum a member's NetServerEnum rides on. The answer is a status, not a
// container; see the note above.
constexpr quint16 OpNetServerEnum = 0;

constexpr quint32 kErrorNotSupported = 0x00000032u; // ERROR_NOT_SUPPORTED

} // namespace Browser

class BrowserServer : public QObject
{
    Q_OBJECT

public:
    explicit BrowserServer(QObject *parent = nullptr);

    // The same authenticator every other endpoint answers behind: a client that
    // reaches \pipe\browser through an authenticated SMB session carries that
    // identity, and one that reaches it over ncacn_ip_tcp authenticates.
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
    RpcServer *m_rpc = nullptr;
};

#endif // BROWSER_H
