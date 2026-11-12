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

    // What a Windows client learns about the DSA itself from the root DSE. Set
    // from dc.conf; while it is unset the root DSE publishes only the naming
    // contexts, so a bare store does not claim to be a domain controller.
    struct Identity {
        QString realm;
        QString netbios;
        QString dnsDomain;
        QString dcHost;
        QString siteName;
    };
    void setIdentity(const Identity &identity);
    Identity identity() const { return m_identity; }

    // The Global Catalog: the same store, offered on the port a client uses
    // when it wants a forest-wide view. It is the same LdapServer and the same
    // objects, so a write is visible on both ports with no replication step.
    bool listenGc(quint16 port = 3268);
    void closeGc();
    bool gcListening() const;
    quint16 gcServerPort() const;

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
    // Deleted objects, kept the way AD keeps them: the object survives as a
    // tombstone (isDeleted TRUE, whenChanged stamped, most attributes stripped,
    // its RDN mangled to `<rdn>\0ADEL:<guid>`) so replication can carry the
    // deletion to a partner. They are deliberately not part of objects(): LDAP
    // never returns them, and the original DN is free for a new object. They
    // live in memory with the rest of the store and are not purged.
    QList<DirectoryObject> tombstones() const { return m_tombstones; }
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
    // Apply one replication cycle from another DC. A live object is created or
    // updated in place (matched by objectGUID, then by DN); an isDeleted
    // entry removes the local copy and is kept as a tombstone. A live copy of
    // an object that is already a tombstone here is not resurrected, and
    // applying the same cycle twice changes nothing the second time. The root
    // DSE is derived, so it is never applied. Returns the objects acted on.
    int applyReplication(const QList<DirectoryObject> &incoming);
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

    // AD's domain password policy, as the domain object carries it: minPwdLength,
    // pwdHistoryLength, pwdProperties and the two ages. The ages keep AD's own
    // encoding — a delta time is a negative count of 100-nanosecond units — so
    // what a client reads over LDAP is what SAMR reports on the wire.
    struct PasswordPolicy {
        int minLength = kPasswordMinLength;
        int historyLength = kPasswordHistoryLength;
        quint32 properties = kPasswordComplex;
        qint64 maxAge = kPasswordMaxAge;
        qint64 minAge = kPasswordMinAge;
    };
    // What the domain object holds, falling back to AD's default domain policy
    // for anything it does not carry. Static so SAMR reads the same values.
    static PasswordPolicy passwordPolicyFrom(const DirectoryObject &domain);
    PasswordPolicy passwordPolicy() const;

    // pwdProperties bits this server acts on. MS-SAMR 2.2.3.5 defines the rest
    // (anonymous-change and clear-change rules, reversible encryption, locking
    // out the built-in Administrator), and they are reported but not enforced.
    static constexpr quint32 kPasswordComplex = 0x1;

    // AD's default domain policy, which is what a freshly promoted domain has:
    // 7 characters, 24 remembered passwords, complexity on, a password is good
    // for 42 days and cannot be changed again for a day.
    static constexpr int kPasswordMinLength = 7;
    static constexpr int kPasswordHistoryLength = 24;
    static constexpr qint64 kPasswordMaxAge = -36288000000000LL; // 42 days
    static constexpr qint64 kPasswordMinAge = -864000000000LL;   // 1 day

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
    // A bind name may be a DN, a UPN or `DOMAIN\user`; the last two are mapped
    // to the entry's id before the verifier lookup, which compares one form.
    QString resolveBindName(const QString &name) const;

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
            // RFC 4511 §4.5.1.8 sends the selection list once, with the first
            // page; later pages have to answer with the same attributes, so it
            // is kept here rather than re-read from a request that lacks it.
            QStringList attributes;
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
    // Returns false when the message closed the connection and freed `st`.
    bool processMessage(ClientState *st, const QByteArray &msg);
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
    // Whether a password passes the domain policy, and whether it is one of the
    // account's remembered passwords. `reason` says which rule refused it.
    bool passwordMeetsPolicy(const QString &password, QString *reason) const;
    bool passwordWasUsed(const DirectoryObject &object, const QString &password,
                         QString *reason) const;
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
    QByteArray makeSearchEntry(int msgId, const DirectoryObject &o,
                               const QStringList &requested);
    QByteArray makeSearchDone(int msgId, int resultCode, const QByteArray &controls = QByteArray());

    // SID of the domain itself, taken from the objects already in the store.
    QString domainSidPrefix() const;
    long long nextUsn();
    quint64 m_nextPagedId = 1;
    void ensureRootDse();

    QTcpServer *m_server = nullptr;
    QTcpServer *m_gcServer = nullptr;
    Identity m_identity;
    Kdc *m_kdc = nullptr;
    QSslCertificate m_tlsCertificate;
    QSslKey m_tlsKey;
    bool m_tlsAvailable = false;
    QList<DirectoryObject> m_objects;
    QList<DirectoryObject> m_tombstones;
    QList<ClientState *> m_clients;
    QMap<QString, Credential> m_credentials; // lower-cased DN -> verifier
    long long m_usn = 1000;
};

#endif // LDAPSERVER_H