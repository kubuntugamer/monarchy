// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETLOGON_H
#define NETLOGON_H

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

#include <functional>

#include "Rpc.h"
#include "resultsmodel.h"

// Netlogon (MS-NRPC): the secure channel a member server, a workstation or a
// trusting domain uses to prove it is the account it claims to be, and the call
// through which such a server asks the DC to validate a user's credentials.
//
// The session starts with NetrServerReqChallenge (the two eight-byte
// challenges) and is established by NetrServerAuthenticate3, which proves both
// sides know the machine account's password without sending it: the session key
// is derived from the machine NT hash and both challenges, and the first
// credential is that session key applied to the client's challenge. Later calls
// carry a Netlogon authenticator, the next credential in the same chain.
//
// AES, strong-key MD5, and legacy 64-bit DES channel derivations are supported
// so down-level Windows clients can negotiate the strength they implement.
namespace Netlogon {

struct Config {
    QString realm;      // CORP.EXAMPLE.COM
    QString netbios;    // CORP
    QString domainSid;  // "S-1-5-21-x-y-z"
    QString baseDn;     // "DC=corp,DC=example,DC=com"
    QString dnsDomain;  // "corp.example.com"
    QString dcName;     // DC's NetBIOS name, "DC1"
    QString dcHost;     // "dc1.corp.example.com"
    QString dcIp;       // the address the DC answers on
    QString siteName;   // "Default-First-Site-Name"
};

// The machine password write NetrServerPasswordSet2 performs. It is a hash
// write rather than a plaintext one because that is what crosses the wire: the
// 512-byte buffer is the new password under the session key, and the hash is
// all the directory ever keeps.
struct WriteBackend {
    std::function<bool(const QString &dn, const QByteArray &ntHash, QString *error)> setNtHash;
    // What a successful validation records on the account: lastLogon, the
    // replicated lastLogonTimestamp when it is due, and the logon count. A DC
    // that validates a logon but records nothing reports a stale directory.
    std::function<bool(const QString &dn, const QMap<QString, QString> &attributes,
                       QString *error)>
        updateAccount;
    // The trust-password write: NetrServerPasswordSet2 naming an interdomain
    // account rewrites the trust's incoming secret (and the inter-realm keys
    // derived from it) instead of an account's hash, because a trust is what
    // the channel was opened with.
    std::function<bool(const QString &dn, const QMap<QString, QString> &attributes,
                       QString *error)>
        updateTrust;
};

// Opnums from MS-NRPC (Samba's netlogon.idl carries the same numbering in its
// /* Function 0xNN */ comments).
enum Opnum : quint16 {
    OpLogonSamLogon = 2,
    OpServerReqChallenge = 4,
    OpServerAuthenticate = 5,
    OpGetDcName = 11,
    OpServerAuthenticate2 = 15,
    OpServerAuthenticate3 = 26,
    OpServerPasswordSet2 = 30,
    OpServerTrustPasswordsGet = 42,
    OpGetAnyDCName = 13,
    OpLogonGetCapabilities = 21,
    OpLogonGetTrustRid = 23,
    OpLogonGetDomainInfo = 29,
    OpDsRGetSiteName = 28,
    OpDsRGetDcNameEx2 = 34,
    OpLogonSamLogonEx = 39,
    OpDsrEnumerateDomainTrusts = 40,
    OpLogonSamLogonWithFlags = 45
};

// NETLOGON_NEG_* flags this server acts on (MS-NRPC 2.2.1.4.1).
constexpr quint32 kNegArcFour = 0x00000004u;
constexpr quint32 kNegStrongKeys = 0x00004000u;
constexpr quint32 kNegDnsDomainTrusts = 0x00010000u;
constexpr quint32 kNegPasswordSet2 = 0x00020000u;
constexpr quint32 kNegGetDomainInfo = 0x00040000u;
constexpr quint32 kNegSupportsAes = 0x01000000u;
// MS-NRPC 2.2.1.4.1: the server accepts Netlogon calls over a DCE/RPC
// connection sealed by the Netlogon security provider (auth type 0x44) with the
// channel's session key. The endpoint serves it (engine/Schannel.cpp), so the
// flag is negotiated: a client that takes it up rebinds `\pipe\netlogon` with
// auth type 0x44 and names its channel in the bind, and the channel's key is
// what seals every call after that.
constexpr quint32 kNegAuthenticatedRpc = 0x40000000u;

Rpc::Interface interface();

} // namespace Netlogon

class NetlogonServer : public QObject
{
    Q_OBJECT

public:
    explicit NetlogonServer(QObject *parent = nullptr);

    void setConfig(const Netlogon::Config &config);
    Netlogon::Config config() const { return m_config; }
    // The accounts the channel and the logon validation resolve against: the
    // same objects SAMR, LSAD and LDAP serve.
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);
    void setWriteBackend(Netlogon::WriteBackend backend);
    // AD's LmCompatibilityLevel, exactly as every other acceptor reads it from
    // dc.conf: 0-2 accept an NTLMv1 or NTLM2-session answer from a pre-NTLMv2
    // client, 3-5 require NTLMv2. The default is 3, the policy this pipe
    // enforced before the setting existed.
    void setLmCompatibilityLevel(int level) { m_lmCompatibilityLevel = level; }

    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // The channel `computer` established, for the pipe that channel now
    // authenticates: the session key its PDUs are sealed with, the flags that
    // decide the algorithms, and the account it belongs to. A channel of
    // another domain is declined.
    bool schannelCredentials(const QString &domain, const QString &computer,
                             Rpc::SchannelCredentials *credentials) const;

    // One NDR request in, one response out, for the endpoint and the tests.
    QByteArray handleCall(quint16 opnum, const QByteArray &stub,
                          const QString &clientUser = QString());

signals:
    void requestReceived(const QString &operation);

private:
    // The state NetrServerReqChallenge leaves behind for the authenticate call.
    struct Challenge {
        QByteArray client;
        QByteArray server;
    };

    // An established channel: what MS-NRPC 3.1.4.3 calls the credential state.
    // `client` and `server` are the current credentials in the chain and `seed`
    // is the value the next pair is derived from; `sequence` is the timestamp
    // the client put in the last authenticator.
    struct Channel {
        QByteArray sessionKey;
        QByteArray client;
        QByteArray server;
        QByteArray seed;
        quint32 sequence = 0;
        quint32 flags = 0;
        // The flags the client asked with, which NetrLogonGetCapabilities
        // reports for its query level 2.
        quint32 requestedFlags = 0;
        QString accountName;
        QString sid;
        // The computer and channel type the channel was established with.
        // NetrServerTrustPasswordsGet names both, and Samba refuses a call that
        // names a different computer or type than the channel holds; without
        // them a channel could be asked about an account it never proved.
        QString computerName;
        quint16 channelType = 0;
    };

    DirectoryObject findAccount(const QString &name) const;
    // The principal a partner DC authenticates as for an inbound trust. Its
    // credential is the trust secret, not a machine password.
    DirectoryObject findTrustPrincipal(const QString &name) const;
    QList<DirectoryObject> directory() const;
    // Gates the machine account the channel is opened for.
    bool machineCredential(const DirectoryObject &object, QByteArray *ntHash) const;

    QByteArray samLogon(const QByteArray &stub, bool withAuthenticator, bool withFlags);
    QByteArray serverReqChallenge(const QByteArray &stub);
    QByteArray serverAuthenticate(const QByteArray &stub, quint16 opnum);
    QByteArray serverPasswordSet2(const QByteArray &stub);
    QByteArray serverTrustPasswordsGet(const QByteArray &stub);
    QByteArray getAnyDcName(const QByteArray &stub);
    QByteArray dsrGetSiteName(const QByteArray &stub);
    QByteArray dsrEnumerateDomainTrusts(const QByteArray &stub);
    QByteArray logonGetTrustRid(const QByteArray &stub);
    QByteArray getDcName(const QByteArray &stub);
    QByteArray dsrGetDcNameEx2(const QByteArray &stub);

    // Applies the next authenticator in the chain to `channel` and returns the
    // server's reply credential, or an empty array when the proof is wrong.
    QByteArray logonGetCapabilities(const QByteArray &stub);
    QByteArray logonGetDomainInfo(const QByteArray &stub);
    bool stepAuthenticator(Channel *channel, quint32 timestamp, const QByteArray &credential,
                           QByteArray *reply);

    Netlogon::Config m_config;
    RpcServer *m_rpc = nullptr;
    std::function<QList<DirectoryObject>()> m_provider;
    Netlogon::WriteBackend m_writes;
    int m_lmCompatibilityLevel = 3; // Ntlm::kDefaultLmCompatibilityLevel
    QHash<QString, Challenge> m_challenges; // by computer name, lower case
    QHash<QString, Channel> m_channels;     // by account name, lower case
};

#endif // NETLOGON_H
