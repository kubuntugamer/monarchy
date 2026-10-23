// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETLOGON_H
#define NETLOGON_H

#include <QByteArray>
#include <QHash>
#include <QList>
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
    OpDsRGetDcNameEx2 = 34,
    OpLogonSamLogonEx = 39,
    OpLogonSamLogonWithFlags = 45
};

// NETLOGON_NEG_* flags this server acts on (MS-NRPC 2.2.1.4.1).
constexpr quint32 kNegArcFour = 0x00000004u;
constexpr quint32 kNegStrongKeys = 0x00004000u;
constexpr quint32 kNegDnsDomainTrusts = 0x00010000u;
constexpr quint32 kNegPasswordSet2 = 0x00020000u;
constexpr quint32 kNegGetDomainInfo = 0x00040000u;
constexpr quint32 kNegSupportsAes = 0x01000000u;

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

    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

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
        QString accountName;
        QString sid;
    };

    DirectoryObject findAccount(const QString &name) const;
    QList<DirectoryObject> directory() const;
    // Gates the machine account the channel is opened for.
    bool machineCredential(const DirectoryObject &object, QByteArray *ntHash) const;

    QByteArray samLogon(const QByteArray &stub, bool withAuthenticator, bool withFlags);
    QByteArray serverReqChallenge(const QByteArray &stub);
    QByteArray serverAuthenticate(const QByteArray &stub, quint16 opnum);
    QByteArray serverPasswordSet2(const QByteArray &stub);
    QByteArray getDcName(const QByteArray &stub);
    QByteArray dsrGetDcNameEx2(const QByteArray &stub);

    // Applies the next authenticator in the chain to `channel` and returns the
    // server's reply credential, or an empty array when the proof is wrong.
    bool stepAuthenticator(Channel *channel, quint32 timestamp, const QByteArray &credential,
                           QByteArray *reply);

    Netlogon::Config m_config;
    RpcServer *m_rpc = nullptr;
    std::function<QList<DirectoryObject>()> m_provider;
    Netlogon::WriteBackend m_writes;
    QHash<QString, Challenge> m_challenges; // by computer name, lower case
    QHash<QString, Channel> m_channels;     // by account name, lower case
};

#endif // NETLOGON_H
