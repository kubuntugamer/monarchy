// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef KDC_H
#define KDC_H

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

#include <functional>

#include "Krb5.h"
#include "resultsmodel.h"

class QTcpServer;
class QUdpSocket;

// Realm parameters the KDC and the directory share.
struct KerberosRealmConfig {
    QString realm = QStringLiteral("MONARCHY.EXAMPLE.COM");
    QString netbios = QStringLiteral("MONARCHY");
    QString domainSid;
    QString dcHost;
};

// A Kerberos 5 KDC (RFC 4120) for the directory: password pre-authentication,
// TGT issuance, service-ticket issuance and AP-REQ verification for LDAP SASL
// GSSAPI. Accounts use the credential AD already stores — NTOWFv1 — so one
// password drives simple bind, NTLMv2 and Kerberos alike.
class Kdc : public QObject
{
    Q_OBJECT
public:
    explicit Kdc(QObject *parent = nullptr);
    ~Kdc() override;

    void setRealm(const KerberosRealmConfig &config);
    KerberosRealmConfig realm() const { return m_config; }

    // The directory can be supplied directly or through a provider, so a
    // password change is visible to the KDC immediately.
    void setObjects(const QList<DirectoryObject> &objects);
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);

    bool listen(quint16 port = 88);
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    struct ApResult {
        QString clientDn;
        QString clientPrincipal;
        QString servicePrincipal;
        QByteArray sessionKey;
        // GSS-API context key: the subkey the initiator proposed (which the
        // AP-REP echoes), otherwise the ticket's session key. Per-message
        // tokens are sealed with it.
        QByteArray contextKey;
        int contextEtype = 0;
        // GSS-API AP-REP token for mutual authentication.
        QByteArray replyToken;
        // First sequence number in each direction. A DCE/RPC context starts
        // from the initiator's value (sent in the authenticator) and one the
        // acceptor chooses for its own tokens.
        quint32 recvSeq = 0;
        quint32 sendSeq = 0;
        // The PAC carried by the service ticket, signature-verified.
        QByteArray pac;
    };

    // Accepts a Kerberos AP-REQ (bare or wrapped in a GSS-API initial context
    // token). Verifies the service ticket against the directory's service key
    // and the authenticator against the ticket's session key, including clock
    // skew and replay. Returns false with a reason on any failure.
    bool acceptApReq(const QByteArray &token, ApResult *out, QString *error);

    // The same acceptance with DCE/RPC's profile (RFC 4121 §7.1): the answer is
    // a bare AP-REP that carries a fresh acceptor subkey and both initial
    // sequence numbers, because that is what a bind's auth_value must hold and
    // what the per-PDU tokens are sealed under.
    bool acceptDceApReq(const QByteArray &token, ApResult *out, QString *error);

    // Consumes the initiator's closing AP-REP (what krb5_mk_rep_dce sends): it
    // echoes the acceptor's sequence number and carries no subkey. Windows and
    // MIT seal it with the acceptor subkey; clients that follow the older
    // reading use the ticket's session key, so both are tried.
    bool finishDceApReq(const QByteArray &token, const QByteArray &contextKey, int etype,
                        quint32 expectedSeq, QString *error);
    bool finishDceApReq(const QByteArray &token, const QByteArray &contextKey, int etype,
                        const QByteArray &ticketKey, int ticketEtype, quint32 expectedSeq,
                        QString *error);

    // One KDC message in, one reply out (AS-REQ, TGS-REQ, or a KRB-ERROR).
    QByteArray handleRequest(const QByteArray &request);

signals:
    void requestReceived(const QString &operation);

private slots:
    void onTcpConnection();
    void onUdpDatagram();

private:
    struct KdcRequest {
        QString realm;
        QString cname;
        QString sname;
        // Realm part of the requested service principal. It differs from ours
        // when a client asks for a service across a trust, which is what a
        // referral ticket answers.
        QString srealm;
        quint32 nonce = 0;
        quint32 options = 0;
        QList<int> etypes;
        bool hasEncTimestamp = false;
        QByteArray encTimestamp;
        bool hasApReq = false;
        QByteArray apReq;
    };

    struct OpenedTicket {
        QString realm;
        QString service;
        QString client;
        // Client realm from the ticket, which differs from ours when the ticket
        // came across a trust.
        QString crealm;
        QByteArray sessionKey;
        int sessionEtype = Krb5::kRc4Hmac;
        int ticketEtype = Krb5::kRc4Hmac;
        quint32 flags = 0;
        qint64 authtime = 0;
        qint64 endtime = 0;
        QByteArray authorizationData;
    };

    QList<DirectoryObject> directory() const;
    bool parseRequest(const QByteArray &der, quint8 expectedTag, KdcRequest *out,
                      QString *error) const;
    // Decrypts a ticket with whichever of the principal's long-term keys the
    // ticket names, and reports the encryption type of its session key.
    bool openTicket(const QByteArray &ticketDer, const Krb5::Principal &principal,
                    OpenedTicket *out, QString *error) const;
    // Strongest encryption type a principal has a key for.
    int preferredEtype(const Krb5::Principal &principal) const;
    // The fields of an AP-REQ authenticator, once its integrity is checked and
    // its timestamp accepted.
    struct AuthenticatorFields {
        qint64 ctime = 0;
        quint32 usec = 0;
        QByteArray subkey;   // the key the initiator proposed, if any
        int subkeyEtype = 0;
        quint32 seq = 0;     // where the initiator starts its own tokens
    };
    // `usage` is 7 for a TGS-REQ authenticator and 11 for an application
    // (LDAP, RPC) AP-REQ, per RFC 4120 §7.5.1.
    bool readAuthenticator(const QByteArray &apReqDer, const OpenedTicket &ticket, int usage,
                           AuthenticatorFields *out, QString *error);
    bool verifyAuthenticator(const QByteArray &apReqDer, const OpenedTicket &ticket,
                             int usage, QByteArray *replyToken, QString *error,
                             QByteArray *subkeyOut = nullptr,
                             int *subkeyEtypeOut = nullptr);
    // Opens the service ticket an AP-REQ carries against the directory.
    bool openApReq(const QByteArray &apReqDer, OpenedTicket *ticket, Krb5::Principal *service,
                   QString *serviceName, QString *error);
    // MS-PAC: a service verifies both signatures before trusting the PAC.
    bool verifyServicePac(const OpenedTicket &ticket, const Krb5::Principal &service,
                          QByteArray *pac, QString *error);

    QByteArray handleAsReq(const KdcRequest &request);
    QByteArray handleTgsReq(const KdcRequest &request);
    QByteArray preauthRequired(const KdcRequest &request, const QString &salt,
                               const QList<int> &etypes) const;
    QByteArray issueAsRep(const KdcRequest &request, const Krb5::Principal &client,
                          int etype, const QByteArray &timestamp) const;
    QByteArray issueTgsRep(const KdcRequest &request, const OpenedTicket &tgt,
                           const QByteArray &subkey, int subkeyEtype) const;
    QByteArray krbError(int code, const QString &realm, const QString &cname,
                        const QByteArray &eData = {}) const;

    void handleDatagram(QByteArray request, const QString &operation);
    QString principalForLookup(const QString &name) const;

    // Cross-realm support (RFC 4120 §3.3.3): the key a trust shares with
    // `peerRealm`, and whether the trust lets us issue tickets into it
    // (outbound) or accept tickets from it (inbound). Direction follows AD's
    // trustDirection: 1 inbound, 2 outbound, 3 both.
    Krb5::Principal trustPrincipal(const QString &peerRealm) const;
    quint32 trustDirection(const QString &peerRealm) const;
    // A TGT for the peer realm, sealed with the trust key, given a TGT of ours.
    QByteArray issueReferral(const KdcRequest &request, const OpenedTicket &tgt,
                             const Krb5::Principal &trust, const QString &peerRealm,
                             const QByteArray &subkey, int subkeyEtype) const;

    KerberosRealmConfig m_config;
    QList<DirectoryObject> m_objects;
    std::function<QList<DirectoryObject>()> m_provider;
    QTcpServer *m_tcp = nullptr;
    QUdpSocket *m_udp = nullptr;
    quint16 m_port = 0;
    // "client|ctime|cusec" of authenticators already accepted, with their
    // timestamp so the cache can be pruned.
    QHash<QString, qint64> m_replay;
};

#endif // KDC_H
