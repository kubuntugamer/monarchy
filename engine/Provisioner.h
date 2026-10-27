// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PROVISIONER_H
#define PROVISIONER_H

#include <QString>

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
    bool devPorts = false;
    bool force = false;
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

#endif // PROVISIONER_H
