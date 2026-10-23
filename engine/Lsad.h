// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef LSAD_H
#define LSAD_H

#include <QByteArray>
#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QStringList>

#include <functional>

#include "Rpc.h"
#include "Samr.h"

// LSAD (MS-LSAD), the Local Security Authority interface. A DC answers it on
// lsarpc: clients open the policy, translate names and SIDs, read and write
// account rights, enumerate the local accounts and privileges, read the policy
// information classes, and keep LSA secrets. Every call below is served from
// the same directory SAMR and LDAP serve, so a name translated here is the
// account a search returns and the rights written here are the rights the next
// query reports.
namespace Lsad {

// Opnum table from MS-LSAD (Samba's lsa.idl carries the same numbering in its
// /* Function: 0xNN */ comments). A call that has no meaning on a standalone DC
// is answered with the status the specification gives it, and calls that would
// describe state this server does not hold (a trust nothing authenticates
// through) report that state instead of inventing it.
enum Opnum : quint16 {
    OpClose = 0,
    OpEnumeratePrivileges = 2,
    OpQuerySecurityObject = 3,
    OpSetSecurityObject = 4,
    OpOpenPolicy = 6,
    OpQueryInformationPolicy = 7,
    OpSetInformationPolicy = 8,
    OpCreateAccount = 10,
    OpEnumAccounts = 11,
    OpCreateTrustedDomain = 12,
    OpEnumTrustDom = 13,
    OpLookupNames = 14,
    OpLookupSids = 15,
    OpCreateSecret = 16,
    OpOpenAccount = 17,
    OpEnumPrivsAccount = 18,
    OpAddPrivilegesToAccount = 19,
    OpRemovePrivilegesFromAccount = 20,
    OpGetSystemAccessAccount = 23,
    OpSetSystemAccessAccount = 24,
    OpOpenTrustedDomain = 25,
    OpQueryTrustedDomainInfo = 26,
    OpSetInformationTrustedDomain = 27,
    OpOpenSecret = 28,
    OpSetSecret = 29,
    OpQuerySecret = 30,
    OpLookupPrivValue = 31,
    OpLookupPrivName = 32,
    OpLookupPrivDisplayName = 33,
    OpDeleteObject = 34,
    OpEnumAccountsWithUserRight = 35,
    OpEnumAccountRights = 36,
    OpAddAccountRights = 37,
    OpRemoveAccountRights = 38,
    OpStorePrivateData = 42,
    OpRetrievePrivateData = 43,
    OpOpenPolicy2 = 44,
    OpGetUserName = 45,
    OpQueryInformationPolicy2 = 46,
    OpSetInformationPolicy2 = 47,
    OpEnumTrustedDomainsEx = 50,
    OpCreateTrustedDomainEx = 51,
    OpQueryDomainInfoPolicy = 53,
    OpSetDomainInfoPolicy = 54,
    OpOpenTrustedDomainByName = 55,
    OpLookupSids2 = 57,
    OpLookupNames2 = 58,
    OpCreateTrustedDomainEx2 = 59,
    OpLookupNames3 = 68,
    OpQueryForestTrustInfo = 73,
    OpLookupSids3 = 76,
    OpLookupNames4 = 77
};

// LSA_POLICY_INFORMATION_CLASS levels this server answers.
enum InfoClass : quint16 {
    InfoAuditLog = 1,
    InfoAuditEvents = 2,
    InfoPrimaryDomain = 3,
    InfoPdAccount = 4,
    InfoAccountDomain = 5,
    InfoServerRole = 6,
    InfoReplicaSource = 7,
    InfoQuota = 8,
    InfoModification = 9,
    InfoAuditFullSet = 10,
    InfoAuditFullQuery = 11,
    InfoDnsDomain = 12,
    InfoDnsDomainInt = 13,
    InfoLocalAccountDomain = 14
};

// LSA_DOMAIN_INFORMATION_CLASS levels (LsarQueryDomainInformationPolicy).
enum DomainInfoClass : quint16 {
    DomainQos = 1,
    DomainEfs = 2,
    DomainKerberos = 3
};

// The directory writes LSAD needs. Account rights are stored on the account
// object itself, so a right assigned over lsarpc is visible to LDAP and
// survives a restart the way the rest of the store does.
struct WriteBackend {
    std::function<bool(const QString &dn, const QStringList &rights, QString *error)> setRights;
};

Rpc::Interface interface();

} // namespace Lsad

class LsadServer : public QObject
{
    Q_OBJECT

public:
    explicit LsadServer(QObject *parent = nullptr);

    // realm, netbios and domainSid come from the same configuration the SAMR
    // endpoint uses, so both protocols report one identity.
    void setConfig(const Samr::Config &config);
    Samr::Config config() const { return m_config; }
    void setDomainNames(const QString &netbios, const QString &serverName,
                        const QString &dnsDomain, const QString &domainSid);
    // The accounts names and SIDs resolve against: the same objects SAMR and
    // LDAP serve.
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);
    void setWriteBackend(Lsad::WriteBackend backend);
    // NTLMSSP as the endpoint's security provider, shared with SAMR: the same
    // directory credential opens both.
    void setAuthenticator(Rpc::Authenticator authenticator);

    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // One NDR request in, one response out, for the endpoint and the tests.
    // `clientUser` is the bind's authenticated principal, which LsarGetUserName
    // reports.
    QByteArray handleCall(quint16 opnum, const QByteArray &stub,
                          const QString &clientUser = QString());

signals:
    void requestReceived(const QString &operation);

private:
    struct Handle {
        enum Kind { Policy, Account, Secret, TrustedDomain } kind = Policy;
        QString sid;   // Account
        QString name;  // Secret or trusted domain
        quint32 access = 0;
    };

    struct SecretValue {
        QByteArray current;
        QByteArray old;
        quint64 currentTime = 0;
        quint64 oldTime = 0;
    };

    QList<DirectoryObject> directory() const;
    DirectoryObject findAccount(const QString &sid) const;
    QStringList rightsFor(const QString &sid) const;
    bool storeRights(const QString &sid, const QStringList &rights, quint32 *status);
    QStringList accountsWithRights() const;

    QByteArray newHandle(Handle::Kind kind, const QString &sid = QString(),
                         const QString &name = QString(), quint32 access = 0);
    bool lookupHandle(const QByteArray &handle, Handle::Kind kind, Handle *out) const;
    void retireHandle(const QByteArray &handle);

    Samr::Config m_config;
    QString m_dnsDomain;
    RpcServer *m_rpc = nullptr;
    std::function<QList<DirectoryObject>()> m_provider;
    Lsad::WriteBackend m_writes;
    QHash<QByteArray, Handle> m_handles;
    // Rights of SIDs with no directory object behind them (well-known groups a
    // client grants a right to directly); directory accounts keep theirs on the
    // object.
    QHash<QString, QStringList> m_extraRights;
    QHash<QString, SecretValue> m_secrets;
    // LSAPR_SR_SECURITY_DESCRIPTOR the policy reports. A client that sets one
    // gets it back; the default grants Administrators full policy access and
    // Authenticated Users lookup and read.
    QByteArray m_policySd;
    quint64 m_modifiedId = 0;
    quint64 m_createdTime = 0;
    bool m_shutdownOnFull = false;
};

#endif // LSAD_H
