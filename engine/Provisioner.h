// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PROVISIONER_H
#define PROVISIONER_H

#include <QString>
#include <QStringList>

// Creates an AD-shaped domain tree from scratch. No Samba, no external
// directory server: the seed directory is produced by Monarchy itself and is
// loadable by engine/LdapServer, which then serves it over real LDAP.
struct ProvisionConfig {
    QString realm = QStringLiteral("MONARCHY.EXAMPLE.COM");
    QString netbiosDomain = QStringLiteral("MONARCHY");
    QString adminPassword;
    QString targetDir;
    // Address published in the domain's DNS zone for this DC.
    QString dcIp = QStringLiteral("127.0.0.1");
    // The ports the daemon serves. Provisioning defaults to AD's native
    // bindings — DNS 53, LDAP 389, Kerberos 88, SMB 445, the endpoint mapper
    // 135 and, like real DCs register SAMR/LSAD in Windows' dynamic-RPC
    // range, 49152/49153 — because a domain controller is a root service
    // with CAP_NET_BIND_SERVICE. `--dev-ports` provisions the unprivileged
    // set (1389/1053/8888/1035/1036; epm and SMB stay on 135/445) that a
    // rootless console or test run can bind instead.
    quint16 ldapPort = 389;
    quint16 dnsPort = 53;
    quint16 kdcPort = 88;
    quint16 samrPort = 49152;
    quint16 lsadPort = 49153;
    quint16 epmPort = 135;
    quint16 smbPort = 445;
    // Netlogon and DRSUAPI have no privileged variant, so they keep the same
    // number in both port sets. A host that already runs a DC still needs to
    // move them for a second instance, which is what the daemon reads back out
    // of dc.conf.
    quint16 netlogonPort = 1037;
    quint16 drsPort = 1038;
    bool devPorts = false;
    // Upstream resolvers for out-of-zone DNS (address or address:port). Empty
    // leaves detection to the host's resolv.conf at runtime.
    QStringList forwarders;
    // Optional domain controller host, as a host label ("dc01") or a full
    // FQDN ("dc01.example.com"). Empty keeps the legacy
    // <domain-label>DC1.<domain> name.
    QString dcHost;
    bool force = false;

    // Promote: a second DC for a domain that already exists, built from a copy
    // of that domain's directory the way AD's install-from-media build does.
    // `promoteFrom` names the existing DC's provisioned directory; the realm,
    // SID, naming contexts, site and the first DC's own objects are read from
    // it rather than invented, so the two stores agree on every identity a
    // domain has one of. The copy differs only in the objects that name this
    // DC, and in a dc.conf that makes it pull.
    QString promoteFrom;
    // The DC the copy came from, which this one pulls from. Empty reads the
    // source directory's dc.conf. `adminPassword` is the credential that pull
    // authenticates with, so it must be a password the source DC's store holds.
    QString replicaHost;
    quint16 replicaPort = 0; // 0 reads the source's drsPort
    QString replicaUser = QStringLiteral("Administrator");
};

struct ProvisionResult {
    bool ok = false;
    QString error;
    QString baseDn;
    QString dnsDomain;
    QString dcHost;
    QString domainSid;
    QString storePath;
    QString secretsPath;
    QString configPath;
    QString krb5ConfPath;
    QString sysvolPath;
    QString zonePath;
    // Self-signed TLS material for StartTLS/LDAPS. Empty when the provisioner
    // could not create it (no `openssl` binary); the domain is still created,
    // and the LDAP server then refuses StartTLS instead of claiming to upgrade.
    QString tlsCertPath;
    QString tlsKeyPath;
    QString tlsError;
    bool tlsEnabled = false;
    int objectCount = 0;
};

// "monarchy.example.com" -> "DC=monarchy,DC=example,DC=com"
QString realmToBaseDn(const QString &realm);
// "MONARCHY.EXAMPLE.COM" -> "monarchy.example.com"
QString realmToDnsDomain(const QString &realm);

bool validateRealm(const QString &realm, QString *error);
bool validateNetbiosDomain(const QString &domain, QString *error);

// Writes a self-signed certificate and its matching private key, in PEM, using
// the system `openssl`. Every DNS name in `names` becomes a subjectAltName; any
// entry that parses as an IP address becomes an IP subjectAltName instead. The
// certificate is its own trust anchor (CA:TRUE) so a client can pin it, which
// is what makes StartTLS usable against a dev DC without a public CA.
// Returns false and sets `error` when openssl is missing or the command fails.
bool generateSelfSignedCertificate(const QString &certPath, const QString &keyPath,
                                   const QString &commonName, const QStringList &names,
                                   QString *error);

// Provisions the domain described by `config` into `config.targetDir`.
// Refuses to overwrite an existing directory store unless `config.force` is set.
ProvisionResult provisionDomain(const ProvisionConfig &config);

// Promotes a second domain controller from a copy of an existing one's
// directory: `config.promoteFrom` is that directory, `config.targetDir` the new
// DC's. The copied store keeps everything a domain has exactly one of — SIDs,
// GUIDs, the domain object, the policies, krbtgt's key, the first DC's server
// and NTDS Settings objects — and gains this DC's server object, its NTDS
// Settings object and its computer account under a fresh RID. The resulting
// dc.conf points the pull at the source DC, so the KCC's next pass in this site
// takes changes from it without an administrator registering anything.
// Refuses to overwrite an existing directory store unless `config.force` is set.
ProvisionResult promoteDomain(const ProvisionConfig &config);

#endif // PROVISIONER_H
