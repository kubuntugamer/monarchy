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
    // Port the KDC listens on (88 unless a test or a non-root run needs another).
    // 8888, not AD's well-known 88: the console is an unprivileged desktop app
    // and cannot bind a port below 1024. `--kdc-port 88` still serves the
    // faithful port when run with CAP_NET_BIND_SERVICE or root.
    quint16 kdcPort = 8888;
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
