// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef LDAPSERVER_H
#define LDAPSERVER_H

#include <QObject>
#include <QDateTime>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QList>
#include <QMap>
#include <QString>

#include "Ntlm.h"
#include "Pac.h"
#include "resultsmodel.h"

class Kdc;
class LdapListener;

// A minimal in-process LDAP server (RFC 4511 subset) so Monarchy can act as a DC
// on this machine without root or external packages. Supports Bind (simple) and
// Search (base/one-level/subtree) over an in-memory store. Add/Modify/Delete
// to follow. Listens on a configurable port (default 1389 for dev).
class LdapServer : public QObject
{
    Q_OBJECT
public:
    explicit LdapServer(QObject *parent = nullptr);
    ~LdapServer() override;

    bool listen(quint16 port = 1389);

    // TLS for StartTLS (RFC 4511 §4.14.1). The listener accepts plaintext and
    // upgrades a connection in place when the client sends the StartTLS extended
    // request. With no credentials loaded the request is refused with
    // unavailable(52) instead of being answered with a success that would leave
    // the session unencrypted.
    bool setTlsCredentials(const QByteArray &certificatePem, const QByteArray &keyPem,
                           QString *error = nullptr);
    bool loadTlsCredentials(const QString &certPath, const QString &keyPath,
                            QString *error = nullptr);
    bool tlsAvailable() const { return m_tlsAvailable; }
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    // In-memory store.
    void setObjects(const QList<DirectoryObject> &objects);
    QList<DirectoryObject> objects() const { return m_objects; }
    bool loadFromFile(const QString &path);
    bool saveToFile(const QString &path) const;

    // Simple-bind credentials from a provisioned `private/secrets.json`.
    // While no credentials are loaded every bind succeeds (legacy behaviour).
    bool loadSecretsFromFile(const QString &path);
    void setCredential(const QString &dn, const QByteArray &salt, const QByteArray &hash);
    void clearCredentials();
    void addObject(const DirectoryObject &o) {
        DirectoryObject obj = o;
        obj.attributes.insert(QStringLiteral("uSNChanged"), QString::number(nextUsn()));
        obj.attributes.insert(QStringLiteral("whenCreated"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
        m_objects.append(obj);
        normalizeMembership();
        ensureRootDse();
    }
    bool removeObject(const QString &dn);
    bool modifyObject(const QString &dn, const QMap<QString, QString> &attrs);
    // Creates an account the way SAMR does: allocates the next relative id in
    // this domain's SID space, stamps objectSid, and stores the object. Refuses
    // a duplicate sAMAccountName so name-to-RID stays a function.
    bool addAccount(DirectoryObject *object, QString *error);
    quint32 nextRid() const;
    // Replaces an account's credential with an NT hash, the way a SAMR hash
    // set does: the hash becomes the credential of record for NTLM, RC4-HMAC
    // Kerberos and simple bind alike. The salted verifier and the AES keys
    // cannot be derived from a hash, so they are dropped rather than left
    // behind, which would keep the old password working.
    bool setNtHash(const QString &dn, const QByteArray &ntHash, QString *error);

    // Kerberos acceptor: SASL GSSAPI (and GSS-SPNEGO) binds are verified by the
    // KDC against the service principal keys stored in this directory.
    void setKdc(Kdc *kdc) { m_kdc = kdc; }
    Kdc *kdc() const { return m_kdc; }

    // A request control (RFC 4511 §4.1.11). Only paged results is implemented;
    // an unknown control that a client marks critical is refused with
    // unavailableCriticalExtension rather than silently ignored.
    struct Control {
        QString oid;
        bool criticality = false;
        QByteArray value;
    };

    // One attribute modification. `operation` follows RFC 4511 §4.6: 0 add,
    // 1 delete, 2 replace.
    struct ModifyChange {
        int operation = 2;
        QString type;
        QStringList values;
        // First value exactly as received, so binary-valued attributes
        // (unicodePwd is UTF-16LE) survive the trip.
        QByteArray rawValue;
    };
    // Returns an LDAP result code: 0 success, 19 constraintViolation when a
    // password does not meet policy, 32 noSuchObject.
    int applyModify(const QString &dn, const QList<ModifyChange> &changes);

    // Minimum password length the directory enforces. SAMR reports it as the
    // domain password policy too, so a client is told what is actually checked.
    static constexpr int kPasswordMinLength = 7;

    // Group membership is stored as distinguished names, exactly as AD stores
    // `member`, and every `memberOf` is derived from the groups' member lists.
    // Exposed so callers can assert the invariant after a load.
    void normalizeMembership();

signals:
    void clientConnected(const QString &peer);
    void requestReceived(const QString &op);

private slots:
    void onReadyRead();
    void onDisconnected();
    void onEncrypted();
    void onSslErrors(const QList<QSslError> &errors);

private:
    struct ClientState {
        // Plaintext until the client asks for StartTLS, then the same socket
        // carries TLS.
        QSslSocket *socket = nullptr;
        bool tlsActive = false;
        // A StartTLS response has been queued but the handshake has not started.
        bool tlsPending = false;
        QByteArray buffer;
        // Undecoded bytes: SASL-framed when a security layer is active.
        QByteArray raw;
        // NTLMv2 challenge issued to this connection, empty when no SASL bind
        // is in progress.
        QByteArray ntlmChallenge;
        QString authenticatedDn;
        // GSSAPI/SPNEGO context establishment: 0 = expecting the AP-REQ,
        // 1 = context established, 2 = expecting the security-layer choice.
        int saslStage = 0;
        QString gssClientDn;
        bool gssSpnego = false;
        // Negotiated GSS-API security layer (RFC 4752): 1 none, 2 integrity,
        // 4 confidentiality, with the key, enctype and sequence numbers the
        // per-message tokens are built from.
        int gssLayer = 1;
        QByteArray gssKey;
        int gssEtype = 0;
        quint32 gssMaxBuf = 0;
        quint64 gssSendSeq = 0;
        quint64 gssRecvSeq = 0;
        bool gssRecvSeqSeen = false;
        // The bind response that completes the negotiation travels unwrapped;
        // only what follows it uses the layer.
        bool gssBindResponse = false;
        // NTLM session security (MS-NLMP §3.4): 0 none, 2 integrity, 4
        // confidentiality, with the keys and RC4 states the tokens use.
        int ntlmLayer = 0;
        Ntlm::SessionKeys ntlmKeys;
        Ntlm::Sealer ntlmSendSealer;
        Ntlm::Sealer ntlmRecvSealer;
        quint32 ntlmSendSeq = 0;
        quint32 ntlmRecvSeq = 0;
        // Paged results (RFC 2696): the result set this connection is walking
        // through, so a cookie can resume it.
        struct PagedSearch {
            quint64 id = 0;
            int offset = 0;
            QList<DirectoryObject> results;
        };
        PagedSearch paged;
        // PAC from the AP-REQ's service ticket, held until the bind completes.
        QByteArray gssPac;
        // Identity the verified PAC carried, used to authorize writes.
        Pac::Identity gssIdentity;
        bool gssHasIdentity = false;
    };

    struct Credential {
        QByteArray salt;
        QByteArray hash;
    };

    friend class LdapListener;

    // Takes ownership of a freshly accepted descriptor. Called by the listener,
    // which hands us the fd directly so the socket can be a QSslSocket from the
    // start and upgraded in place later.
    void adoptDescriptor(qintptr descriptor);
    void handleConnection(QSslSocket *sock);
    ClientState *stateFor(QAbstractSocket *socket) const;
    // Drains whatever the socket has and processes every complete message.
    void pump(ClientState *st, QSslSocket *sock);
    // Forgets every negotiated credential and security layer. RFC 4511 makes the
    // connection anonymous after StartTLS, so nothing that authenticated or was
    // wrapped before the upgrade may survive it.
    void resetSecurityContext(ClientState *st);
    void processMessage(ClientState *st, const QByteArray &msg);
    QByteArray handleBind(ClientState *st, int msgId, const QByteArray &payload);
    QByteArray handleSaslBind(ClientState *st, int msgId, const QByteArray &payload);
    QByteArray handleGssapiBind(ClientState *st, int msgId, const QByteArray &credentials,
                                bool spnego);
    // RFC 4752 security layers: seal/unseal one per-message token and the
    // LDAP framing that carries them.
    QByteArray gssWrap(ClientState *st, const QByteArray &data, bool conf);
    bool gssUnwrap(ClientState *st, const QByteArray &token, QByteArray *data);
    QByteArray gssFrame(ClientState *st, const QByteArray &data);
    bool gssUnframe(ClientState *st, QByteArray *out);
    // NTLM per-message tokens (MS-NLMP §3.4.5.2) and the RFC 4422 framing that
    // carries them, the same way GSSAPI layers do.
    QByteArray ntlmWrap(ClientState *st, const QByteArray &data, bool conf);
    bool ntlmUnwrap(ClientState *st, const QByteArray &token, QByteArray *data);
    // Whichever layer this connection negotiated, if any.
    bool saslLayerActive(const ClientState *st) const
    {
        return st->gssLayer != 0x01 || st->ntlmLayer != 0;
    }
    QByteArray saslFrame(ClientState *st, const QByteArray &data);
    bool saslUnframe(ClientState *st, QByteArray *out);
    // NetBIOS domain and DC host name published in the NTLM challenge.
    QString ntlmDomainName() const;
    QString ntlmServerName() const;
    // Writes are authorized from the PAC when the session authenticated with
    // Kerberos: only Domain Admins (512), Enterprise Admins (519) and Schema
    // Admins (518) may modify the directory. Sessions that bound with simple or
    // NTLM credentials keep the pre-ACL behaviour.
    bool allowsWrite(const ClientState *st) const;
    QByteArray handleSearch(ClientState *st, int msgId, const QByteArray &payload,
                            const QList<Control> &controls);
    // Controls carried after the protocol op of one LDAPMessage.
    QList<Control> parseControls(const QByteArray &message, int pos) const;
    // The paged-results response control, already wrapped as the content of the
    // message's controls field.
    QByteArray pagedResultsControl(int total, const QByteArray &cookie) const;
    QByteArray handleModify(int msgId, const QByteArray &payload);
    QByteArray handleAdd(int msgId, const QByteArray &payload);
    QByteArray handleDelete(int msgId, const QByteArray &payload);
    QByteArray handleModifyDn(int msgId, const QByteArray &payload);
    QByteArray handleCompare(int msgId, const QByteArray &payload);
    // `startTls` is set when the request was accepted and the connection has to
    // be upgraded once its response is on the wire.
    QByteArray handleExtended(ClientState *st, int msgId, const QByteArray &payload,
                              bool *startTls);
    QByteArray makeBindResponse(int msgId, int resultCode, const QByteArray &saslCreds = {});
    QByteArray makeLdapResult(int msgId, int opTag, int resultCode);
    QByteArray makeExtendedResponse(int msgId, int resultCode, const QString &name, const QByteArray &value);
    QByteArray makeSearchEntry(int msgId, const DirectoryObject &o);
    QByteArray makeSearchDone(int msgId, int resultCode, const QByteArray &controls = QByteArray());

    // SID of the domain itself, taken from the objects already in the store.
    QString domainSidPrefix() const;
    long long nextUsn();
    quint64 m_nextPagedId = 1;
    void ensureRootDse();

    QTcpServer *m_server = nullptr;
    Kdc *m_kdc = nullptr;
    QSslCertificate m_tlsCertificate;
    QSslKey m_tlsKey;
    bool m_tlsAvailable = false;
    QList<DirectoryObject> m_objects;
    QList<ClientState *> m_clients;
    QMap<QString, Credential> m_credentials; // lower-cased DN -> verifier
    long long m_usn = 1000;
};

#endif // LDAPSERVER_H