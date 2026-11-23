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

// I_BrowserrServerEnum (opnum 0): a browser enumerating the servers in a domain.
// Refused by status; see the note above.
constexpr quint16 OpNetServerEnum = 0;

// I_BrowserrQueryOtherDomains (opnum 2): the PDC-emulator query a master browser
// makes for the domains this DC knows besides its own. MS-BRWS 3.1.4.1 requires
// an answer here — a SERVER_ENUM at level 100 holding one entry per name in
// OtherDomains — and a forest of one domain has no other domains, so the answer
// is an empty list and NERR_Success. Refusing it was the wrong shape as well as
// the wrong answer: the call's [in,out] SERVER_ENUM and [out] TotalEntries are
// marshalled back whatever the status, and a bare status word is a packet the
// dissector cannot read.
constexpr quint16 OpQueryOtherDomains = 2;

constexpr quint32 kErrorSuccess = 0u;            // NERR_Success
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
