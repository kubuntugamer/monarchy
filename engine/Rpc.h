// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef RPC_H
#define RPC_H

#include <QByteArray>
#include <QHostAddress>
#include <QObject>
#include <QString>

#include <functional>
#include <memory>

#include "Ntlm.h"

class QTcpServer;
class QTcpSocket;

// DCE/RPC connection-oriented endpoint over ncacn_ip_tcp (DCE 1.1 RPC,
// MS-RPCE §2.2.2): bind negotiation, request/response PDUs and faults. This is
// the transport the AD management interfaces (SAMR, LSAD, DRSR) ride on; NDR
// marshalling lives in Ndr.h.
namespace Rpc {

// The NDR 32-bit transfer syntax every AD interface negotiates.
extern const QByteArray kNdrSyntaxUuid;
extern const QByteArray kNdrsSyntaxUuid; // NDR64, accepted and declined

struct Interface {
    QByteArray uuid; // 16 bytes, wire order
    quint16 major = 0;
    quint16 minor = 0;
    QString name;    // for logs
};

// One accepted request. `stub` is the NDR payload that follows the request
// header; the handler returns the response stub.
struct Call {
    QString peer;
    // The principal the bind authenticated ("DOMAIN/user" for NTLMSSP, the
    // client principal for Kerberos); empty when the call came in unauthenticated.
    QString user;
    quint16 contextId = 0;
    quint16 opnum = 0;
    QByteArray stub;
    // NTLM session key the bind authenticated with, empty when the endpoint
    // serves unauthenticated calls. Interfaces that cipher their own payload
    // (SAMR password buffers) key it off this, never off anything on the wire.
    QByteArray sessionKey;
};

using Handler = std::function<QByteArray(const Call &call)>;

// One NTLMSSP AUTHENTICATE as an RPC bind delivers it: the client answers the
// eight-byte challenge the bind_ack carried.
struct AuthRequest {
    QString user;
    QString domain;
    QByteArray challenge;
    QByteArray ntResponse;
    quint32 flags = 0;
};

// Verifies that response against the directory and returns the NTLM session
// keys the security provider signs with. Returning false rejects the bind.
using Authenticator = std::function<bool(const AuthRequest &request, Ntlm::SessionKeys *keys)>;

// The GSS context a Kerberos bind establishes: who it authenticated, the key
// the per-PDU tokens are sealed under (the acceptor subkey), and where each
// direction starts counting.
struct KerberosContext {
    QString user;
    QByteArray key;         // acceptor subkey: the per-PDU tokens use this
    int etype = 0;
    // The service ticket's session key. RFC 4121 §7.1 seals the initiator's
    // closing AP-REP with the acceptor subkey, but clients that predate that
    // reading (impacket among them) use the key that protected this side's
    // AP-REP, so acceptance has to try both.
    QByteArray ticketKey;
    int ticketEtype = 0;
    QByteArray replyToken;  // the AP-REP the bind_ack carries
    quint32 recvSeq = 0;    // first sequence number the client sends
    quint32 sendSeq = 0;    // first sequence number this server sends
};

// Accepts the AP-REQ a Kerberos bind delivers (auth_type 16, or inside the
// SPNEGO token of auth_type 9) and fills in the context. Returning false
// rejects the bind with the reason it put in `error`.
using KerberosAcceptor =
    std::function<bool(const QByteArray &apReq, KerberosContext *context, QString *error)>;

// Consumes the initiator's closing AP-REP, which completes mutual
// authentication. The context's sendSeq is the number this server put in its
// own AP-REP, which that closing token has to echo.
using KerberosFinisher =
    std::function<bool(const QByteArray &token, const KerberosContext &context, QString *error)>;

} // namespace Rpc

// A single-interface RPC endpoint. Only one abstract syntax is served, which is
// how a DC exposes SAMR on its own port; clients that offer other transfer
// syntaxes are declined the way a Windows DC declines NDR64 for these calls.
class RpcServer : public QObject
{
    Q_OBJECT

public:
    explicit RpcServer(QObject *parent = nullptr);
    ~RpcServer() override;

    void setInterface(const Rpc::Interface &interface, Rpc::Handler handler);
    // `address` defaults to every interface; the management interfaces are
    // served on the loopback address until RPC authentication is installed.
    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::Any);
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    // NTLMSSP as the RPC security provider (auth_type 10, MS-RPCE §2.2.3): the
    // bind carries NEGOTIATE, the bind_ack answers with CHALLENGE, the client
    // follows with an AUTH3 PDU carrying AUTHENTICATE, and every later PDU is
    // signed (integrity) or sealed (privacy). Without an authenticator the
    // endpoint stays unauthenticated, as it was before.
    void setAuthenticator(Rpc::Authenticator authenticator);

    // Kerberos as the RPC security provider (auth_type 16, MS-RPCE §2.2.3): the
    // bind carries an AP-REQ, the bind_ack the AP-REP, and every later PDU a
    // GSS-API per-message token sealed under the acceptor subkey. DCE/RPC's
    // profile (RFC 4121 §7.1) is used, which is what a Windows DC speaks.
    void setKerberosAcceptor(Rpc::KerberosAcceptor acceptor, Rpc::KerberosFinisher finisher);
    // Names the CHALLENGE publishes: the NetBIOS domain and the DC's host name.
    void setDomainNames(const QString &domain, const QString &serverName,
                        const QString &dnsDomain = QString());

    // Builds a bind_ack / fault for tests and for the framing checks.
    static QByteArray faultPdu(quint32 callId, quint32 status);

    // A connection that owns no socket: the named-pipe transport creates one of
    // these per pipe instance and hands it complete PDUs. Bind negotiation,
    // NTLMSSP and Kerberos, signing and sealing, dispatch and faults are all the
    // socket path's, unmodified.
    struct ChannelState;
    class Channel
    {
    public:
        Channel();
        ~Channel();
        Channel(const Channel &) = delete;
        Channel &operator=(const Channel &) = delete;

        // Feeds one complete PDU and returns the bytes the endpoint wrote.
        QByteArray feed(const QByteArray &pdu);
        // The principal the bind authenticated, empty before it did.
        QString user() const;
        bool bound() const;
        // Marks the connection authenticated by the transport that carries it:
        // a named pipe reached through an authenticated SMB2 session has already
        // proven the principal, which is how Windows authorises these calls on
        // \\dc\pipe\... without a second NTLMSSP exchange inside the pipe.
        void setTransportIdentity(const QString &user);

    private:
        friend class RpcServer;
        RpcServer *m_server = nullptr;
        std::unique_ptr<ChannelState> m_state;
    };

    Channel *newChannel(const QString &peer = QStringLiteral("named-pipe"));

signals:
    void requestReceived(const QString &operation);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();

private:
    struct Client {
        QTcpSocket *socket = nullptr;
        // Where replies go when the connection is not a socket: a named-pipe
        // endpoint feeds whole PDUs in and collects what the endpoint wrote.
        // Everything above this (bind, NTLMSSP/Kerberos, dispatch, faults) is
        // shared, so a pipe endpoint is the TCP endpoint minus TCP.
        std::function<void(const QByteArray &)> sink;
        bool canWrite() const { return socket != nullptr || sink != nullptr; }
        void write(const QByteArray &data);
        QByteArray buffer;
        quint32 assocGroup = 0;
        QString peer;

        // NTLMSSP state for this connection.
        struct Security {
            quint8 type = 0;      // RPC_C_AUTHN_WINNT (10)
            quint8 level = 0;     // 1 connect, 2 integrity, 6 privacy
            quint32 contextId = 0;
            QByteArray challenge;
            Ntlm::SessionKeys keys;
            Ntlm::Sealer recvSealer;
            Ntlm::Sealer sendSealer;
            quint32 recvSeq = 0;
            quint32 sendSeq = 0;
            bool active = false;
            // The identity came from the transport (an authenticated SMB2
            // session carrying the pipe), not from an NTLMSSP/Kerberos bind, so
            // calls carry no verifier and none is required.
            bool transportOnly = false;
            bool privacy = false;
            bool rejected = false; // AUTHENTICATE did not verify; no more calls
            QString user;

            // Kerberos state for this connection (auth_type 9 with a Kerberos
            // mechanism, or 16).
            bool kerberos = false;
            Rpc::KerberosContext gss;
            bool awaitingFinal = false;
        } security;
    };

    // Splits a PDU that carries an auth verifier into its body end (before the
    // auth padding) and the verifier itself.
    struct Verifier {
        bool present = false;
        quint8 type = 0;
        quint8 level = 0;
        quint8 padLength = 0;
        quint32 contextId = 0;
        QByteArray token;
        int bodyEnd = 0; // end of the body/stub, padding excluded
    };

    void handlePdu(Client *client, const QByteArray &pdu);
    QByteArray handleBind(Client *client, const QByteArray &pdu, bool alterContext);
    void handleAuth3(Client *client, const QByteArray &pdu);
    // Verifies the NTLMSSP AUTHENTICATE a client sends as the second half of
    // the exchange. It can arrive in an AUTH3 PDU or, as Samba and Windows send
    // it, in an alter_context, so the verification is shared by both. On
    // success the session is marked authenticated; on failure it is closed.
    bool verifyAuthenticate(Client *client, const QByteArray &ntlmsspToken, quint8 level);
    // Accepts the AP-REQ a bind carries and answers with the AP-REP. Returns the
    // auth_value for the bind_ack, empty when no Kerberos token was presented.
    QByteArray acceptKerberosBind(Client *client, const Verifier &verifier);
    // Verifies an initiator's closing AP-REP (the third leg of a DCE-style bind).
    bool finishKerberos(Client *client, const QByteArray &token);
    // Checks the GSS token a request carries and, at privacy, unseals the stub.
    // The stub still carries the auth padding, which the caller strips.
    bool verifyKerberosRequest(Client *client, const Verifier &verifier, QByteArray *stub);
    static Verifier splitVerifier(const QByteArray &pdu);
    // Appends the sec_trailer and the verifier to a PDU whose body is complete.
    void appendVerifier(QByteArray &pdu, const Client::Security &security, quint8 padLength,
                        const QByteArray &token);

    QTcpServer *m_server = nullptr;
    Rpc::Interface m_interface;
    Rpc::Handler m_handler;
    Rpc::Authenticator m_authenticator;
    Rpc::KerberosAcceptor m_kerberosAcceptor;
    Rpc::KerberosFinisher m_kerberosFinisher;
    QString m_domain;
    QString m_serverName;
    QString m_dnsDomain;
    QList<Client *> m_clients;
};

#endif // RPC_H
