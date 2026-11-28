// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Provisioner.h"

#include "DnsServer.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ntlm.h"
#include "ObjectGuid.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QHostAddress>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRandomGenerator>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>
#include <QUuid>

#include <algorithm>

namespace {

QString rdnEscape(const QString &value)
{
    QString out;
    for (int i = 0; i < value.size(); ++i) {
        const QChar c = value.at(i);
        if (c == QLatin1Char(',') || c == QLatin1Char('+') || c == QLatin1Char('"')
            || c == QLatin1Char('\\') || c == QLatin1Char('<') || c == QLatin1Char('>')
            || c == QLatin1Char(';'))
            out += QLatin1Char('\\');
        out += c;
    }
    if (!out.isEmpty() && (out.startsWith(QLatin1Char(' ')) || out.startsWith(QLatin1Char('#'))))
        out.prepend(QLatin1Char('\\'));
    return out;
}

QString domainSid()
{
    // S-1-5-21-<x>-<y>-<z>, three random 32-bit sub-authorities.
    quint32 a = 0, b = 0, c = 0;
    auto *rng = QRandomGenerator::system();
    while (a == 0) a = rng->generate();
    while (b == 0) b = rng->generate();
    while (c == 0) c = rng->generate();
    return QStringLiteral("S-1-5-21-%1-%2-%3").arg(a).arg(b).arg(c);
}

// Random long-term key, stored as an NT hash exactly like a password-derived
// one. Service and krbtgt accounts have keys but no password.
QString randomKeyHex()
{
    return QString::fromLatin1(Krb5::randomKey(Krb5::kRc4Hmac).toHex());
}

QByteArray passwordHash(const QByteArray &salt, const QString &password)
{
    QByteArray material = salt;
    material += password.toUtf8();
    material += salt;
    for (int i = 0; i < 1000; ++i)
        material = QCryptographicHash::hash(material, QCryptographicHash::Sha256);
    return material.toHex();
}

struct DomainBuilder {
    QString baseDn;
    QString dnsDomain;
    QString netbios;
    QString sid;
    QString dcName;
    QString whenCreated;
    QList<DirectoryObject> objects;
    long long usn = 1000;

    DirectoryObject &add(const QString &dn, const QString &name, const QString &type,
                         ObjectKind kind, const QString &container)
    {
        DirectoryObject object;
        object.id = dn;
        object.name = name;
        object.type = type;
        object.kind = kind;
        object.container = container;
        object.attributes.insert(QStringLiteral("distinguishedName"), dn);
        object.attributes.insert(QStringLiteral("whenCreated"), whenCreated);
        object.attributes.insert(QStringLiteral("uSNChanged"), QString::number(++usn));
        objects.append(object);
        return objects.last();
    }

    void objectClass(DirectoryObject &object, const QStringList &classes)
    {
        object.attributes.insert(QStringLiteral("objectClass"), joinAttributeValues(classes));
    }

    DirectoryObject &addUser(const QString &cn, qint32 rid, const QString &account,
                             quint32 uac, const QString &description)
    {
        const QString dn = QStringLiteral("CN=%1,CN=Users,%2").arg(cn, baseDn);
        DirectoryObject &user = add(dn, cn, QStringLiteral("User"), ObjectKind::User,
                                    QStringLiteral("Users"));
        objectClass(user, {QStringLiteral("top"), QStringLiteral("person"),
                           QStringLiteral("organizationalPerson"), QStringLiteral("user")});
        user.description = description;
        user.attributes.insert(QStringLiteral("cn"), cn);
        user.attributes.insert(QStringLiteral("sAMAccountName"), account);
        user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("%1-%2").arg(sid).arg(rid));
        user.attributes.insert(QStringLiteral("userAccountControl"), QString::number(uac));
        user.attributes.insert(QStringLiteral("primaryGroupID"), QStringLiteral("513"));
        user.attributes.insert(QStringLiteral("userPrincipalName"),
                               QStringLiteral("%1@%2").arg(account, dnsDomain));
        user.attributes.insert(QStringLiteral("description"), description);
        user.attributes.insert(QStringLiteral("badPwdCount"), QStringLiteral("0"));
        user.attributes.insert(QStringLiteral("badPasswordTime"), QStringLiteral("0"));
        user.attributes.insert(QStringLiteral("logonCount"), QStringLiteral("0"));
        user.attributes.insert(QStringLiteral("lastLogon"), QStringLiteral("0"));
        user.attributes.insert(QStringLiteral("pwdLastSet"), QStringLiteral("0"));
        return user;
    }

    DirectoryObject &addGroup(const QString &cn, qint32 rid, const QString &description,
                              const QStringList &members)
    {
        const QString dn = QStringLiteral("CN=%1,CN=Users,%2").arg(cn, baseDn);
        DirectoryObject &group = add(dn, cn, QStringLiteral("Security Group"),
                                     ObjectKind::Group, QStringLiteral("Groups"));
        objectClass(group, {QStringLiteral("top"), QStringLiteral("group")});
        group.description = description;
        group.members = members;
        group.attributes.insert(QStringLiteral("cn"), cn);
        group.attributes.insert(QStringLiteral("sAMAccountName"), cn);
        group.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("%1-%2").arg(sid).arg(rid));
        group.attributes.insert(QStringLiteral("groupType"), QStringLiteral("-2147483646")); // global security
        group.attributes.insert(QStringLiteral("description"), description);
        if (!members.isEmpty())
            group.attributes.insert(QStringLiteral("member"), joinAttributeValues(members));
        return group;
    }
};

bool writeFile(const QString &path, const QByteArray &contents, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error)
            *error = QStringLiteral("cannot write %1: %2").arg(path, file.errorString());
        return false;
    }
    if (file.write(contents) != contents.size()) {
        if (error)
            *error = QStringLiteral("short write to %1").arg(path);
        return false;
    }
    return true;
}

QString firstLabel(const QString &dnsDomain)
{
    return dnsDomain.section(QLatin1Char('.'), 0, 0);
}

bool validDnsLabel(const QString &label)
{
    if (label.isEmpty() || label.size() > 63)
        return false;
    if (label.startsWith(QLatin1Char('-')) || label.endsWith(QLatin1Char('-')))
        return false;
    for (const QChar c : label) {
        const ushort u = c.unicode();
        const bool alnum = (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z')
                           || (u >= '0' && u <= '9');
        if (!alnum && u != '-')
            return false;
    }
    return true;
}

} // namespace

bool generateSelfSignedCertificate(const QString &certPath, const QString &keyPath,
                                   const QString &commonName, const QStringList &names,
                                   QString *error)
{
    const QString openssl = QStandardPaths::findExecutable(QStringLiteral("openssl"));
    if (openssl.isEmpty()) {
        if (error)
            *error = QStringLiteral("openssl not found; provisioned without TLS");
        return false;
    }

    QStringList san;
    for (const QString &name : names) {
        if (name.isEmpty())
            continue;
        QHostAddress address;
        if (address.setAddress(name))
            san.append(QStringLiteral("IP:%1").arg(name));
        else
            san.append(QStringLiteral("DNS:%1").arg(name));
    }
    if (san.isEmpty())
        san.append(QStringLiteral("DNS:%1").arg(commonName));

    // 825 days is the longest a modern client accepts for a server certificate.
    // `-nodes` leaves the key unencrypted: the server starts unattended, so it
    // cannot be given a passphrase.
    const QStringList args = {
        QStringLiteral("req"),
        QStringLiteral("-x509"),
        QStringLiteral("-newkey"), QStringLiteral("rsa:2048"),
        QStringLiteral("-sha256"),
        QStringLiteral("-days"), QStringLiteral("825"),
        QStringLiteral("-nodes"),
        QStringLiteral("-keyout"), keyPath,
        QStringLiteral("-out"), certPath,
        QStringLiteral("-subj"), QStringLiteral("/CN=%1/O=Monarchy").arg(commonName),
        QStringLiteral("-addext"), QStringLiteral("subjectAltName=%1").arg(san.join(QLatin1Char(','))),
        // A single self-signed certificate has to be its own trust anchor for a
        // client to pin it, hence CA:TRUE alongside serverAuth.
        QStringLiteral("-addext"), QStringLiteral("basicConstraints=critical,CA:TRUE"),
        QStringLiteral("-addext"), QStringLiteral("keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign"),
        QStringLiteral("-addext"), QStringLiteral("extendedKeyUsage=serverAuth"),
    };

    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(openssl, args);
    if (!process.waitForStarted(10000) || !process.waitForFinished(30000)) {
        process.kill();
        if (error)
            *error = QStringLiteral("openssl did not finish while creating the TLS certificate");
        return false;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0
        || !QFile::exists(certPath) || !QFile::exists(keyPath)) {
        if (error) {
            *error = QStringLiteral("openssl failed: %1")
                         .arg(QString::fromLocal8Bit(process.readAll()).trimmed());
        }
        QFile::remove(certPath);
        QFile::remove(keyPath);
        return false;
    }
    QFile::setPermissions(keyPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QFile::setPermissions(certPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                       | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    return true;
}

QString realmToDnsDomain(const QString &realm)
{
    return realm.trimmed().toLower();
}

QString realmToBaseDn(const QString &realm)
{
    const QString dns = realmToDnsDomain(realm);
    QStringList parts;
    for (const QString &label : dns.split(QLatin1Char('.'), Qt::SkipEmptyParts))
        parts.append(QStringLiteral("DC=%1").arg(rdnEscape(label)));
    return parts.join(QLatin1Char(','));
}

bool validateRealm(const QString &realm, QString *error)
{
    const QString dns = realmToDnsDomain(realm);
    if (dns.isEmpty()) {
        if (error) *error = QStringLiteral("realm must not be empty");
        return false;
    }
    if (dns.contains(QLatin1Char('@')) || dns.contains(QLatin1Char('/'))
        || dns.contains(QLatin1Char(' '))) {
        if (error) *error = QStringLiteral("realm contains an invalid character");
        return false;
    }
    const QStringList labels = dns.split(QLatin1Char('.'));
    for (const QString &label : labels) {
        if (label.isEmpty()) {
            if (error) *error = QStringLiteral("realm has an empty label");
            return false;
        }
        for (const QChar c : label) {
            if (!(c.isLetterOrNumber() || c == QLatin1Char('-'))) {
                if (error) *error = QStringLiteral("realm label '%1' has an invalid character").arg(label);
                return false;
            }
        }
    }
    return true;
}

bool validateNetbiosDomain(const QString &domain, QString *error)
{
    if (domain.isEmpty()) {
        if (error) *error = QStringLiteral("NetBIOS domain must not be empty");
        return false;
    }
    if (domain.size() > 15) {
        if (error) *error = QStringLiteral("NetBIOS domain must be 15 characters or fewer");
        return false;
    }
    if (domain.contains(QLatin1Char('.')) || domain.contains(QLatin1Char(' '))) {
        if (error) *error = QStringLiteral("NetBIOS domain must not contain '.' or spaces");
        return false;
    }
    return true;
}

namespace {

// The ports a DC binds. `--dev-ports` selects the unprivileged binding set; a
// caller that set a port explicitly keeps it. The mapper (135) and SMB (445)
// are well-known and need CAP_NET_BIND_SERVICE, so a dev run moves them to
// 31035/31445 — 31000 is free of every well-known and every Windows dynamic
// port, so a second DC on the same host can take the whole set without meeting
// the first one. The Global Catalog (3268) is already unprivileged but is still
// a fixed binding two DCs on one host cannot share, so it moves with the rest.
// kpasswd is 464 on a real DC; a rootless dev run moves it too. srvsvc (1039)
// and Netlogon/DRS (1037/1038) have no privileged variant, but they are fixed
// numbers a second DC on the same host still collides on, so the set moves the
// enumerator with them.
struct ServicePorts {
    quint16 ldap = 389;
    quint16 dns = 53;
    quint16 kdc = 88;
    quint16 samr = 49152;
    quint16 lsad = 49153;
    quint16 gc = 3268;
    quint16 kpasswd = 464;
    quint16 epm = 135;
    quint16 smb = 445;
    quint16 srvsvc = 1039;
};

ServicePorts servicePorts(const ProvisionConfig &config)
{
    ServicePorts ports;
    ports.ldap = config.devPorts && config.ldapPort == 389 ? 1389 : config.ldapPort;
    ports.dns = config.devPorts && config.dnsPort == 53 ? 1053 : config.dnsPort;
    ports.kdc = config.devPorts && config.kdcPort == 88 ? 8888 : config.kdcPort;
    ports.samr = config.devPorts && config.samrPort == 49152 ? 1035 : config.samrPort;
    ports.lsad = config.devPorts && config.lsadPort == 49153 ? 1036 : config.lsadPort;
    ports.kpasswd = config.devPorts ? 1464 : 464;
    ports.gc = config.devPorts ? 13268 : 3268;
    ports.epm = config.devPorts && config.epmPort == 135 ? 31035 : config.epmPort;
    ports.smb = config.devPorts && config.smbPort == 445 ? 31445 : config.smbPort;
    ports.srvsvc = config.devPorts && config.srvsvcPort == 1039 ? 31036 : config.srvsvcPort;
    return ports;
}

// The DC's computer account, DNS records, TLS certificate and SPNs all use the
// same host. Callers may name it explicitly, as a host label or a full FQDN;
// otherwise keep the historical <domain-label>DC1 name.
bool resolveControllerHost(const QString &dnsDomain, const QString &requested,
                           QString *dcLabel, QString *dcHost, QString *error)
{
    const QString requestedHost = requested.trimmed().toLower();
    if (requestedHost.isEmpty()) {
        *dcLabel = firstLabel(dnsDomain).toUpper() + QStringLiteral("DC1");
        *dcHost = dcLabel->toLower() + QLatin1Char('.') + dnsDomain;
        return true;
    }
    const QString suffix = QLatin1Char('.') + dnsDomain;
    *dcHost = requestedHost.contains(QLatin1Char('.')) ? requestedHost
                                                       : requestedHost + suffix;
    if (!dcHost->endsWith(suffix)) {
        *error = QStringLiteral("domain controller FQDN %1 must end in %2")
                     .arg(requested, suffix);
        return false;
    }
    *dcLabel = dcHost->left(dcHost->size() - suffix.size());
    if (dcLabel->contains(QLatin1Char('.')) || !validDnsLabel(*dcLabel)) {
        *error = QStringLiteral("domain controller host must be one DNS label: %1")
                     .arg(requested);
        return false;
    }
    if (dcLabel->size() > 15) {
        *error = QStringLiteral("domain controller host must be 15 characters or fewer: %1")
                     .arg(requested);
        return false;
    }
    *dcLabel = dcLabel->toUpper();
    return true;
}

// A krb5.conf that points at one DC, so `kinit` needs no hand-written realm
// stanza. The KDC port is the one that machine actually serves.
bool writeKrb5Conf(const QString &path, const QString &realm, const QString &dnsDomain,
                   const QString &dcIp, quint16 kdcPort, quint16 kpasswdPort,
                   QString *error)
{
    const QString contents =
        QStringLiteral("[libdefaults]\n"
                       "    default_realm = %1\n"
                       "    dns_lookup_kdc = false\n"
                       "    dns_lookup_realm = false\n"
                       "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 "
                       "aes128-cts-hmac-sha1-96 rc4-hmac\n"
                       "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 "
                       "aes128-cts-hmac-sha1-96 rc4-hmac\n"
                       "    permitted_enctypes = aes256-cts-hmac-sha1-96 "
                       "aes128-cts-hmac-sha1-96 rc4-hmac\n"
                       "\n"
                       "[realms]\n"
                       "    %1 = {\n"
                       "        kdc = %2:%3\n"
                       "        kpasswd_server = %2:%5\n"
                       "    }\n"
                       "\n"
                       "[domain_realm]\n"
                       "    .%4 = %1\n"
                       "    %4 = %1\n")
            .arg(realm, dcIp)
            .arg(kdcPort)
            .arg(dnsDomain)
            .arg(kpasswdPort);
    return writeFile(path, contents.toUtf8(), error);
}

// Every file under `from`, at the same relative path under `to`. Symlinks are
// copied as the files they name, because a directory a client browses is not
// allowed to point outside the share.
bool copyTree(const QString &from, const QString &to, QString *error)
{
    const QDir source(from);
    if (!source.exists())
        return true;
    if (!QDir().mkpath(to)) {
        *error = QStringLiteral("cannot create directory %1").arg(to);
        return false;
    }
    const QFileInfoList entries =
        source.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo &entry : entries) {
        const QString destination = to + QLatin1Char('/') + entry.fileName();
        if (entry.isDir()) {
            if (!copyTree(entry.absoluteFilePath(), destination, error))
                return false;
            continue;
        }
        if (!QFile::copy(entry.absoluteFilePath(), destination)) {
            *error = QStringLiteral("cannot copy %1").arg(entry.absoluteFilePath());
            return false;
        }
    }
    return true;
}

} // namespace

ProvisionResult provisionDomain(const ProvisionConfig &config)
{
    ProvisionResult result;
    result.dnsDomain = realmToDnsDomain(config.realm);
    result.baseDn = realmToBaseDn(config.realm);

    QString error;
    if (!validateRealm(config.realm, &error)) {
        result.error = error;
        return result;
    }
    if (!validateNetbiosDomain(config.netbiosDomain, &error)) {
        result.error = error;
        return result;
    }
    if (config.adminPassword.isEmpty()) {
        result.error = QStringLiteral("administrator password must not be empty");
        return result;
    }
    const QString dcIp = config.dcIp.trimmed().isEmpty() ? QStringLiteral("127.0.0.1")
                                                         : config.dcIp.trimmed();
    if (QHostAddress(dcIp).isNull()) {
        result.error = QStringLiteral("invalid domain controller address: %1").arg(dcIp);
        return result;
    }

    // The DC's computer account, DNS records, TLS certificate and SPNs all use
    // the same host.
    QString dcLabel;
    QString dcHost;
    if (!resolveControllerHost(result.dnsDomain, config.dcHost, &dcLabel, &dcHost, &error)) {
        result.error = error;
        return result;
    }

    const ServicePorts ports = servicePorts(config);
    const quint16 ldapPort = ports.ldap;
    const quint16 dnsPort = ports.dns;
    const quint16 kdcPort = ports.kdc;
    const quint16 samrPort = ports.samr;
    const quint16 lsadPort = ports.lsad;
    const quint16 gcPort = ports.gc;
    const quint16 kpasswdPort = ports.kpasswd;

    QString target = config.targetDir;
    if (target.isEmpty()) {
        result.error = QStringLiteral("target directory must not be empty");
        return result;
    }
    target = QDir::cleanPath(QDir(target).absolutePath());

    const QString privateDir = target + QStringLiteral("/private");
    result.storePath = privateDir + QStringLiteral("/directory.json");
    result.secretsPath = privateDir + QStringLiteral("/secrets.json");
    result.configPath = target + QStringLiteral("/dc.conf");
    result.zonePath = privateDir + QStringLiteral("/dnszone.json");
    result.sysvolPath = target + QStringLiteral("/sysvol/") + result.dnsDomain;

    if (QFileInfo::exists(result.storePath) && !config.force) {
        result.error = QStringLiteral("%1 is already provisioned (use --force to overwrite)")
                           .arg(target);
        return result;
    }

    // Well-known policy GUIDs: every AD domain starts with these two GPOs.
    const QString defaultDomainPolicy =
        QStringLiteral("{31B2F340-016D-11D2-945F-00C04FB984F9}");
    const QString defaultDcPolicy =
        QStringLiteral("{6AC1786C-016F-11D2-945F-00C04fB984F9}");

    const QStringList dirs = {
        target,
        privateDir,
        target + QStringLiteral("/var"),
        target + QStringLiteral("/var/lib/monarchy"),
        result.sysvolPath,
        result.sysvolPath + QStringLiteral("/scripts"),
        result.sysvolPath + QStringLiteral("/Policies"),
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDomainPolicy,
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDomainPolicy + QStringLiteral("/Machine"),
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDomainPolicy + QStringLiteral("/User"),
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDcPolicy,
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDcPolicy + QStringLiteral("/Machine"),
        result.sysvolPath + QStringLiteral("/Policies/") + defaultDcPolicy + QStringLiteral("/User"),
    };
    for (const QString &dir : dirs) {
        if (!QDir().mkpath(dir)) {
            result.error = QStringLiteral("cannot create directory %1").arg(dir);
            return result;
        }
    }

    DomainBuilder b;
    b.baseDn = result.baseDn;
    b.dnsDomain = result.dnsDomain;
    b.netbios = config.netbiosDomain.toUpper();
    b.sid = domainSid();
    b.dcName = dcLabel;
    b.whenCreated = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    result.domainSid = b.sid;
    result.dcHost = dcHost;

    // --- Domain NC -------------------------------------------------------
    DirectoryObject &domain = b.add(result.baseDn, b.netbios, QStringLiteral("domainDNS"),
                                    ObjectKind::Domain, QStringLiteral("Console Root"));
    b.objectClass(domain, {QStringLiteral("top"), QStringLiteral("domain"),
                           QStringLiteral("domainDNS")});
    domain.description = QStringLiteral("%1 domain").arg(b.dnsDomain);
    domain.attributes.insert(QStringLiteral("dc"), firstLabel(b.dnsDomain));
    domain.attributes.insert(QStringLiteral("objectSid"), b.sid);
    domain.attributes.insert(QStringLiteral("instanceType"), QStringLiteral("5"));
    domain.attributes.insert(QStringLiteral("ms-DS-MachineAccountQuota"), QStringLiteral("10"));
    // The account lockout policy, in AD's own encoding: a threshold of zero
    // means a bad password is counted but never locks the account, and the two
    // intervals are negative 100-nanosecond values (30 minutes here).
    domain.attributes.insert(QStringLiteral("lockoutThreshold"), QStringLiteral("0"));
    domain.attributes.insert(QStringLiteral("lockoutDuration"), QStringLiteral("-18000000000"));
    domain.attributes.insert(QStringLiteral("lockoutObservationWindow"),
                             QStringLiteral("-18000000000"));
    // The password policy, under the attributes AD uses for it and with AD's
    // default domain policy: 7 characters, 24 remembered passwords, complexity
    // on, 42 days before a password expires and one day before it may change
    // again. The two ages are negative 100-nanosecond deltas, as AD stores
    // them, so LDAP and SAMR report the same numbers.
    domain.attributes.insert(QStringLiteral("minPwdLength"),
                             QString::number(LdapServer::kPasswordMinLength));
    domain.attributes.insert(QStringLiteral("pwdHistoryLength"),
                             QString::number(LdapServer::kPasswordHistoryLength));
    domain.attributes.insert(QStringLiteral("pwdProperties"),
                             QString::number(LdapServer::kPasswordComplex));
    domain.attributes.insert(QStringLiteral("maxPwdAge"),
                             QString::number(LdapServer::kPasswordMaxAge));
    domain.attributes.insert(QStringLiteral("minPwdAge"),
                             QString::number(LdapServer::kPasswordMinAge));
    domain.attributes.insert(
        QStringLiteral("gPLink"),
        QStringLiteral("[LDAP://CN=%1,CN=Policies,CN=System,%2;0]")
            .arg(defaultDomainPolicy, b.baseDn));
    domain.attributes.insert(QStringLiteral("fSMORoleOwner"),
                             QStringLiteral("CN=NTDS Settings,CN=%1,CN=Servers,"
                                            "CN=Default-First-Site-Name,CN=Sites,"
                                            "CN=Configuration,%2").arg(b.dcName, b.baseDn));

    // --- Containers ------------------------------------------------------
    for (const QString &cn : {QStringLiteral("Users"), QStringLiteral("Computers"),
                              QStringLiteral("System"),
                              QStringLiteral("ForeignSecurityPrincipals"),
                              QStringLiteral("Managed Service Accounts")}) {
        DirectoryObject &container = b.add(
            QStringLiteral("CN=%1,%2").arg(cn, b.baseDn), cn, QStringLiteral("Container"),
            ObjectKind::Container,
            cn == QLatin1String("Users") ? QStringLiteral("Users")
            : cn == QLatin1String("Computers") ? QStringLiteral("Computers")
                                               : QStringLiteral("Console Root"));
        b.objectClass(container, {QStringLiteral("top"), QStringLiteral("container")});
        container.attributes.insert(QStringLiteral("cn"), cn);
    }

    DirectoryObject &dcOu = b.add(
        QStringLiteral("OU=Domain Controllers,%1").arg(b.baseDn),
        QStringLiteral("Domain Controllers"), QStringLiteral("Organizational Unit"),
        ObjectKind::Container, QStringLiteral("Domain Controllers"));
    b.objectClass(dcOu, {QStringLiteral("top"), QStringLiteral("organizationalUnit")});
    dcOu.attributes.insert(QStringLiteral("ou"), QStringLiteral("Domain Controllers"));
    dcOu.description = QStringLiteral("Default container for domain controllers");
    dcOu.attributes.insert(
        QStringLiteral("gPLink"),
        QStringLiteral("[LDAP://CN=%1,CN=Policies,CN=System,%2;0]")
            .arg(defaultDcPolicy, b.baseDn));

    // --- Accounts --------------------------------------------------------
    DirectoryObject &admin = b.addUser(
        QStringLiteral("Administrator"), 500, QStringLiteral("Administrator"), 512,
        QStringLiteral("Built-in account for administering the domain"));
    admin.memberOf = {QStringLiteral("Domain Admins"), QStringLiteral("Domain Users"),
                      QStringLiteral("Enterprise Admins"), QStringLiteral("Schema Admins"),
                      QStringLiteral("Group Policy Creator Owners")};

    b.addUser(QStringLiteral("Guest"), 501, QStringLiteral("Guest"), 514,
              QStringLiteral("Built-in account for guest access to the domain"));

    DirectoryObject &krbtgt = b.addUser(
        QStringLiteral("krbtgt"), 502, QStringLiteral("krbtgt"), 514,
        QStringLiteral("Key distribution center service account"));
    krbtgt.attributes.insert(QStringLiteral("showInAdvancedViewOnly"), QStringLiteral("TRUE"));
    // The KDC's own long-term key. AD gives this account a random password that
    // nobody knows; the key alone is what signs TGTs.
    krbtgt.attributes.insert(QStringLiteral("ntHash"), randomKeyHex());
    Krb5::storeRandomKeys(krbtgt);
    krbtgt.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"), QStringLiteral("1"));

    // The service principal a client asks the KDC for before it can change a
    // password (RFC 3244 §2). Its key is random, like krbtgt's: nobody logs on
    // as the service, they only present a ticket for it.
    // NORMAL_ACCOUNT, not disabled: the KDC refuses an initial ticket for a
    // disabled principal, and this account exists only to hold the key.
    DirectoryObject &kadmin = b.addUser(
        QStringLiteral("kadmin"), 503, QStringLiteral("kadmin"), 512,
        QStringLiteral("Kerberos password change service account"));
    kadmin.attributes.insert(QStringLiteral("showInAdvancedViewOnly"), QStringLiteral("TRUE"));
    kadmin.attributes.insert(QStringLiteral("servicePrincipalName"),
                             QStringLiteral("kadmin/changepw"));
    kadmin.attributes.insert(QStringLiteral("ntHash"), randomKeyHex());
    Krb5::storeRandomKeys(kadmin);
    kadmin.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"), QStringLiteral("1"));

    // --- Groups ----------------------------------------------------------
    b.addGroup(QStringLiteral("Domain Admins"), 512,
               QStringLiteral("Designated administrators of the domain"),
               {QStringLiteral("Administrator")});
    b.addGroup(QStringLiteral("Domain Users"), 513, QStringLiteral("All domain users"),
               {QStringLiteral("Administrator"), QStringLiteral("Guest")});
    b.addGroup(QStringLiteral("Domain Guests"), 514, QStringLiteral("All domain guests"), {});
    b.addGroup(QStringLiteral("Domain Computers"), 515,
               QStringLiteral("All workstations and servers joined to the domain"), {});
    b.addGroup(QStringLiteral("Domain Controllers"), 516,
               QStringLiteral("All domain controllers in the domain"), {});
    b.addGroup(QStringLiteral("Schema Admins"), 518,
               QStringLiteral("Designated administrators of the schema"),
               {QStringLiteral("Administrator")});
    b.addGroup(QStringLiteral("Enterprise Admins"), 519,
               QStringLiteral("Designated administrators of the enterprise"),
               {QStringLiteral("Administrator")});
    b.addGroup(QStringLiteral("Group Policy Creator Owners"), 520,
               QStringLiteral("Members of this group can create and modify group policy"),
               {QStringLiteral("Administrator")});

    // --- This domain controller -----------------------------------------
    DirectoryObject &dc = b.add(
        QStringLiteral("CN=%1,OU=Domain Controllers,%2").arg(b.dcName, b.baseDn),
        b.dcName, QStringLiteral("Computer"), ObjectKind::Computer,
        QStringLiteral("Domain Controllers"));
    b.objectClass(dc, {QStringLiteral("top"), QStringLiteral("person"),
                       QStringLiteral("organizationalPerson"), QStringLiteral("user"),
                       QStringLiteral("computer")});
    dc.description = QStringLiteral("Domain controller for %1").arg(b.dnsDomain);
    dc.attributes.insert(QStringLiteral("cn"), b.dcName);
    dc.attributes.insert(QStringLiteral("sAMAccountName"), b.dcName + QStringLiteral("$"));
    dc.attributes.insert(QStringLiteral("dNSHostName"),
                         b.dcName.toLower() + QLatin1Char('.') + b.dnsDomain);
    dc.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("%1-1000").arg(b.sid));
    dc.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("12288"));
    dc.attributes.insert(QStringLiteral("operatingSystem"), QStringLiteral("Monarchy DC (Linux)"));
    dc.attributes.insert(QStringLiteral("isDomainController"), QStringLiteral("yes"));
    // Service keys live on the computer account, exactly as in AD: the KDC and
    // the LDAP acceptor both read the key from here, so no keytab file exists.
    dc.attributes.insert(QStringLiteral("ntHash"), randomKeyHex());
    Krb5::storeRandomKeys(dc);
    dc.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"), QStringLiteral("1"));
    // `DNS/ns1.<domain>` is the name the zone publishes as its NS and resolves
    // to this DC. A GSS-TSIG client asks for the primary a SOA query named, so
    // without this SPN the KDC has no key to issue that ticket from and a
    // member's own dynamic update cannot start.
    dc.attributes.insert(
        QStringLiteral("servicePrincipalName"),
        // The bare host name carries its own tickets: a Windows client that
        // opens \\\\<name>\\share asks for cifs/<name>, not cifs/<name>.<domain>,
        // and a KDC that only knows the FQDN answers S_PRINCIPAL_UNKNOWN and
        // leaves that connection on NTLM. AD registers both forms.
        QStringLiteral("ldap/%1; ldap/%1.%2; ldap/%1.%2/%2; HOST/%1; HOST/%1.%2; "
                       "GC/%1; GC/%1.%2; cifs/%1; cifs/%1.%2; DNS/%1.%2; DNS/ns1.%2; "
                       "RestrictedKrbHost/%1; RestrictedKrbHost/%1.%2")
            .arg(b.dcName.toLower(), b.dnsDomain));

    // The DC belongs to Domain Controllers. `member` holds distinguished names
    // and every memberOf is derived from these lists when the store loads.
    {
        const QString dcDn = dc.id;
        const QString groupDn =
            QStringLiteral("CN=Domain Controllers,CN=Users,%1").arg(b.baseDn);
        for (DirectoryObject &group : b.objects) {
            if (group.kind == ObjectKind::Group
                && group.id.compare(groupDn, Qt::CaseInsensitive) == 0
                && !group.members.contains(dcDn, Qt::CaseInsensitive)) {
                group.members.append(dcDn);
            }
        }
    }

    // --- Configuration NC / sites ---------------------------------------
    const QString configDn = QStringLiteral("CN=Configuration,%1").arg(b.baseDn);
    DirectoryObject &configuration = b.add(configDn, QStringLiteral("Configuration"),
                                          QStringLiteral("Container"), ObjectKind::Container,
                                          QStringLiteral("Console Root"));
    b.objectClass(configuration, {QStringLiteral("top"), QStringLiteral("configuration")});
    configuration.attributes.insert(QStringLiteral("cn"), QStringLiteral("Configuration"));

    const QString sitesDn = QStringLiteral("CN=Sites,%1").arg(configDn);
    DirectoryObject &sites = b.add(sitesDn, QStringLiteral("Sites"), QStringLiteral("Container"),
                                   ObjectKind::Container, QStringLiteral("Console Root"));
    b.objectClass(sites, {QStringLiteral("top"), QStringLiteral("sitesContainer")});
    sites.attributes.insert(QStringLiteral("cn"), QStringLiteral("Sites"));

    const QString siteDn = QStringLiteral("CN=Default-First-Site-Name,%1").arg(sitesDn);
    DirectoryObject &site = b.add(siteDn, QStringLiteral("Default-First-Site-Name"),
                                  QStringLiteral("Container"), ObjectKind::Container,
                                  QStringLiteral("Console Root"));
    b.objectClass(site, {QStringLiteral("top"), QStringLiteral("site")});
    site.attributes.insert(QStringLiteral("cn"), QStringLiteral("Default-First-Site-Name"));

    const QString serversDn = QStringLiteral("CN=Servers,%1").arg(siteDn);
    DirectoryObject &servers = b.add(serversDn, QStringLiteral("Servers"),
                                     QStringLiteral("Container"), ObjectKind::Container,
                                     QStringLiteral("Console Root"));
    b.objectClass(servers, {QStringLiteral("top"), QStringLiteral("serversContainer")});

    const QString serverDn = QStringLiteral("CN=%1,%2").arg(b.dcName, serversDn);
    DirectoryObject &server = b.add(serverDn, b.dcName, QStringLiteral("Server"),
                                    ObjectKind::Container, QStringLiteral("Console Root"));
    b.objectClass(server, {QStringLiteral("top"), QStringLiteral("server")});
    server.attributes.insert(QStringLiteral("cn"), b.dcName);
    server.attributes.insert(QStringLiteral("dNSHostName"),
                             b.dcName.toLower() + QLatin1Char('.') + b.dnsDomain);

    // The NTDS Settings object: the directory agent's own vertex in the
    // configuration NC. The domain object already named it in
    // fSMORoleOwner, so without it that value pointed at nothing.
    const QString ntdsSettingsDn = QStringLiteral("CN=NTDS Settings,%1").arg(serverDn);
    {
        DirectoryObject &ntds = b.add(ntdsSettingsDn, QStringLiteral("NTDS Settings"),
                                      QStringLiteral("NTDS Settings"), ObjectKind::Container,
                                      serverDn);
        b.objectClass(ntds, {QStringLiteral("top"), QStringLiteral("nTDSDSA")});
        ntds.attributes.insert(QStringLiteral("cn"), QStringLiteral("NTDS Settings"));
        // options bit 0 (IS_GC): this DSA serves the Global Catalog. The GC
        // listener is the same store on 3268, so the flag is true.
        ntds.attributes.insert(QStringLiteral("options"), QStringLiteral("1"));
        ntds.attributes.insert(QStringLiteral("invocationId"),
                               QUuid::createUuid().toString().remove(QLatin1Char('{')).remove(
                                   QLatin1Char('}')));
        ntds.attributes.insert(QStringLiteral("hasMasterNCs"),
                               QStringLiteral("%1; CN=Configuration,%1; CN=Schema,CN=Configuration,%1")
                                   .arg(b.baseDn));
    }

    // --- Schema NC -------------------------------------------------------
    const QString schemaDn = QStringLiteral("CN=Schema,%1").arg(configDn);
    DirectoryObject &schema = b.add(schemaDn, QStringLiteral("Schema"),
                                    QStringLiteral("dMD"), ObjectKind::Container,
                                    QStringLiteral("Console Root"));
    b.objectClass(schema, {QStringLiteral("top"), QStringLiteral("dMD")});
    schema.attributes.insert(QStringLiteral("cn"), QStringLiteral("Schema"));
    // Schema Master, held by this DSA.
    schema.attributes.insert(QStringLiteral("fSMORoleOwner"), ntdsSettingsDn);

    // CN=Partitions carries the Domain Naming Master role, the third FSMO
    // owner in a Windows 2000 forest's configuration NC.
    {
        const QString partitionsDn = QStringLiteral("CN=Partitions,%1").arg(configDn);
        DirectoryObject &partitions = b.add(partitionsDn, QStringLiteral("Partitions"),
                                            QStringLiteral("Container"), ObjectKind::Container,
                                            QStringLiteral("Console Root"));
        b.objectClass(partitions, {QStringLiteral("top"), QStringLiteral("crossRefContainer")});
        partitions.attributes.insert(QStringLiteral("cn"), QStringLiteral("Partitions"));
        partitions.attributes.insert(QStringLiteral("fSMORoleOwner"), ntdsSettingsDn);
    }

    // The two FSMO roles that live in the account NC rather than the
    // configuration NC. A forest has five role owners, and a client reads them
    // the same way an administrator checks a domain: one search for
    // fSMORoleOwner. Naming only three of them leaves the RID master and the
    // infrastructure master pointing at nothing, which is indistinguishable
    // from a domain where those roles were seized away.
    {
        const QString systemDn = QStringLiteral("CN=System,%1").arg(b.baseDn);
        DirectoryObject &ridManager =
            b.add(QStringLiteral("CN=RID Manager$,%1").arg(systemDn),
                  QStringLiteral("RID Manager$"), QStringLiteral("RID Manager"),
                  ObjectKind::Container, systemDn);
        b.objectClass(ridManager, {QStringLiteral("top"), QStringLiteral("rIDManager")});
        ridManager.attributes.insert(QStringLiteral("cn"), QStringLiteral("RID Manager$"));
        ridManager.attributes.insert(QStringLiteral("fSMORoleOwner"), ntdsSettingsDn);
    }
    {
        DirectoryObject &infrastructure =
            b.add(QStringLiteral("CN=Infrastructure,%1").arg(b.baseDn),
                  QStringLiteral("Infrastructure"), QStringLiteral("Infrastructure"),
                  ObjectKind::Container, b.baseDn);
        b.objectClass(infrastructure,
                      {QStringLiteral("top"), QStringLiteral("infrastructureUpdate")});
        infrastructure.attributes.insert(QStringLiteral("cn"),
                                         QStringLiteral("Infrastructure"));
        infrastructure.attributes.insert(QStringLiteral("fSMORoleOwner"), ntdsSettingsDn);
    }

    {
        // Fine-grained password policies live in a container the domain is
        // created with, before an administrator writes the first policy into it.
        const QString settingsDn =
            QStringLiteral("CN=Password Settings Container,CN=System,%1").arg(b.baseDn);
        DirectoryObject &settings =
            b.add(settingsDn, QStringLiteral("Password Settings Container"),
                  QStringLiteral("Container"), ObjectKind::Container,
                  QStringLiteral("Console Root"));
        b.objectClass(settings, {QStringLiteral("top"), QStringLiteral("container")});
        settings.attributes.insert(QStringLiteral("cn"),
                                   QStringLiteral("Password Settings Container"));
    }

    {
        // The BUILTIN domain: the well-known local groups whose SIDs appear in
        // ACLs on every machine. AD keeps them in this container, and stores
        // them here rather than synthesising them so a membership SAMR adds to
        // one has somewhere to live.
        const QString builtinDn = QStringLiteral("CN=Builtin,%1").arg(b.baseDn);
        DirectoryObject &builtin =
            b.add(builtinDn, QStringLiteral("Builtin"), QStringLiteral("Builtin-Domain"),
                  ObjectKind::Container, QStringLiteral("Console Root"));
        b.objectClass(builtin, {QStringLiteral("top"), QStringLiteral("builtinDomain")});
        // Each alias carries the comment NT5's SAM seeds it with
        // (SAMP_ALIAS_COMMENT_* in the server's sampmsgs.mc, punctuation
        // included; the seven RIDs added after NT5 take Samba 4.24.7's
        // source4/setup/provision_users.ldif wording). It is stored here as well
        // as seeded by Samr::builtinAliasTable() so a search on CN=Builtin
        // reads the same comment a SAMR alias query reports — `net localgroup
        // "Administrators" /domain` prints it on its Comment line.
        static const struct {
            const char *name;
            quint32 rid;
            const char *comment;
        } kAliases[] = {
            {"Administrators", 544,
             "Administrators have complete and unrestricted access to the computer/domain"},
            {"Users", 545,
             "Users are prevented from making accidental or intentional system-wide changes.  "
             "Thus, Users can run certified applications, but not most legacy applications"},
            {"Guests", 546,
             "Guests have the same access as members of the Users group by default, except "
             "for the Guest account which is further restricted"},
            {"Power Users", 547,
             "Power Users possess most administrative powers with some restrictions.  Thus, "
             "Power Users can run legacy applications in addition to certified applications"},
            {"Account Operators", 548, "Members can administer domain user and group accounts"},
            {"Server Operators", 549, "Members can administer domain servers"},
            {"Print Operators", 550, "Members can administer domain printers"},
            {"Backup Operators", 551,
             "Backup Operators can override security restrictions for the sole purpose of "
             "backing up or restoring files"},
            {"Replicator", 552, "Supports file replication in a domain"},
            {"Remote Desktop Users", 555,
             "Members in this group are granted the right to logon remotely"},
            {"Network Configuration Operators", 556,
             "Members in this group can have some administrative privileges to manage "
             "configuration of networking features"},
            {"Performance Monitor Users", 558,
             "Members of this group have remote access to monitor this computer"},
            {"Performance Log Users", 559,
             "Members of this group have remote access to schedule logging of performance "
             "counters on this computer"},
            {"IIS_IUSRS", 568, "Built-in group used by Internet Information Services."},
            {"Event Log Readers", 573,
             "Members of this group can read event logs from local machine"},
            {"Certificate Service DCOM Access", 574,
             "Members of this group are allowed to connect to Certification Authorities in the "
             "enterprise"},
        };
        for (const auto &alias : kAliases) {
            const QString name = QString::fromLatin1(alias.name);
            DirectoryObject &object = b.add(QStringLiteral("CN=%1,%2").arg(name, builtinDn), name,
                                            QStringLiteral("Security Group"), ObjectKind::Group,
                                            QStringLiteral("Builtin"));
            b.objectClass(object, {QStringLiteral("top"), QStringLiteral("group")});
            object.attributes.insert(QStringLiteral("cn"), name);
            object.attributes.insert(QStringLiteral("sAMAccountName"), name);
            object.attributes.insert(QStringLiteral("objectSid"),
                                     QStringLiteral("S-1-5-32-%1").arg(alias.rid));
            // A domain-local security group, which is what SAMR calls an alias.
            object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("-2147483644"));
            object.attributes.insert(QStringLiteral("description"),
                                     QString::fromLatin1(alias.comment));
        }
    }

    // --- Group Policy -----------------------------------------------------
    // The two policies every domain is created with, linked from the domain
    // and the Domain Controllers OU by the gPLink values set above.
    {
        const QString policiesDn = QStringLiteral("CN=Policies,CN=System,%1").arg(b.baseDn);
        DirectoryObject &policies = b.add(policiesDn, QStringLiteral("Policies"),
                                          QStringLiteral("Container"), ObjectKind::Container,
                                          QStringLiteral("Console Root"));
        b.objectClass(policies, {QStringLiteral("top"), QStringLiteral("container")});
        policies.attributes.insert(QStringLiteral("cn"), QStringLiteral("Policies"));

        auto addGpo = [&](const QString &guid, const QString &displayName) {
            DirectoryObject &gpo = b.add(QStringLiteral("CN=%1,%2").arg(guid, policiesDn),
                                         displayName, QStringLiteral("Group Policy Container"),
                                         ObjectKind::Container, QStringLiteral("Console Root"));
            b.objectClass(gpo, {QStringLiteral("top"), QStringLiteral("groupPolicyContainer")});
            gpo.description = displayName;
            gpo.attributes.insert(QStringLiteral("cn"), guid);
            gpo.attributes.insert(QStringLiteral("displayName"), displayName);
            gpo.attributes.insert(QStringLiteral("gPCFileSysPath"),
                                  QStringLiteral("\\\\%1\\sysvol\\%2\\Policies\\%3")
                                      .arg(result.dnsDomain, result.dnsDomain, guid));
            gpo.attributes.insert(QStringLiteral("versionNumber"), QStringLiteral("0"));
            gpo.attributes.insert(QStringLiteral("flags"), QStringLiteral("0"));
            gpo.attributes.insert(QStringLiteral("gPCFunctionalityVersion"), QStringLiteral("2"));
        };
        addGpo(defaultDomainPolicy, QStringLiteral("Default Domain Policy"));
        addGpo(defaultDcPolicy, QStringLiteral("Default Domain Controllers Policy"));
    }

    // --- Administrator credential -----------------------------------------
    // The verifier is stored on the object as well as in secrets.json, so a
    // bind works from the directory alone and the console can reset it later.
    QString saltHex;
    for (int i = 0; i < 2; ++i)
        saltHex += QStringLiteral("%1").arg(QRandomGenerator::system()->generate64(), 16, 16,
                                            QLatin1Char('0'));
    const QByteArray saltBytes = saltHex.toLatin1();
    const QByteArray hashHex = passwordHash(saltBytes, config.adminPassword);
    {
        const QString adminDn =
            QStringLiteral("CN=Administrator,CN=Users,%1").arg(b.baseDn);
        for (DirectoryObject &object : b.objects) {
            if (object.id.compare(adminDn, Qt::CaseInsensitive) != 0)
                continue;
            object.attributes.insert(QStringLiteral("userPasswordSalt"), saltHex);
            object.attributes.insert(QStringLiteral("userPasswordHash"),
                                     QString::fromLatin1(hashHex));
            object.attributes.insert(QStringLiteral("passwordScheme"),
                                     QStringLiteral("sha256-salted-1000+ntowfv1"));
            object.attributes.insert(QStringLiteral("ntHash"),
                                     QString::fromLatin1(Ntlm::ntowfV1(config.adminPassword).toHex()));
            Krb5::storePasswordKeys(object, config.adminPassword, b.dnsDomain.toUpper(),
                                    QStringLiteral("Administrator"));
            object.attributes.insert(
                QStringLiteral("pwdLastSet"),
                QString::number(QDateTime::currentDateTimeUtc().toSecsSinceEpoch()));
            break;
        }
    }

    // --- Persist the directory store ------------------------------------
    LdapServer store;
    store.setObjects(b.objects);
    if (!store.saveToFile(result.storePath)) {
        result.error = QStringLiteral("cannot write directory store %1").arg(result.storePath);
        return result;
    }
    result.objectCount = store.objects().size();

    // --- Secrets ---------------------------------------------------------
    QJsonObject secrets;
    secrets[QStringLiteral("realm")] = b.dnsDomain.toUpper();
    secrets[QStringLiteral("netbiosDomain")] = b.netbios;
    secrets[QStringLiteral("domainSid")] = b.sid;
    secrets[QStringLiteral("machineGuid")] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    secrets[QStringLiteral("created")] = b.whenCreated;
    secrets[QStringLiteral("administratorDn")] =
        QStringLiteral("CN=Administrator,CN=Users,%1").arg(b.baseDn);
    secrets[QStringLiteral("passwordSalt")] = saltHex;
    secrets[QStringLiteral("passwordHash")] = QString::fromLatin1(hashHex);
    secrets[QStringLiteral("passwordScheme")] = QStringLiteral("sha256-salted-1000");
    if (!writeFile(result.secretsPath,
                   QJsonDocument(secrets).toJson(QJsonDocument::Indented), &error)) {
        result.error = error;
        return result;
    }
    if (!QFile::setPermissions(result.secretsPath,
                               QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        result.error = QStringLiteral("cannot restrict permissions on %1").arg(result.secretsPath);
        return result;
    }

    // --- TLS --------------------------------------------------------------
    // The DC certificate the LDAP server presents when a client asks for
    // StartTLS. When it cannot be created (no openssl on this host) the domain
    // is still provisioned and the server refuses StartTLS, which is visible;
    // answering success without encrypting would not be.
    result.tlsCertPath = privateDir + QStringLiteral("/ldap.crt");
    result.tlsKeyPath = privateDir + QStringLiteral("/ldap.key");
    result.tlsEnabled = generateSelfSignedCertificate(
        result.tlsCertPath, result.tlsKeyPath, result.dcHost,
        {result.dcHost, b.dcName, dcIp, QStringLiteral("127.0.0.1"),
         QStringLiteral("localhost")},
        &result.tlsError);

    // --- SYSVOL policy content --------------------------------------------
    // GPT.INI carries the version the client compares against versionNumber,
    // and registry.pol is present (empty policy) in every policy folder.
    for (const QString &guid : {defaultDomainPolicy, defaultDcPolicy}) {
        const QString policyDir = result.sysvolPath + QStringLiteral("/Policies/") + guid;
        if (!writeFile(policyDir + QStringLiteral("/GPT.INI"),
                       QByteArray("[General]\r\nVersion=0\r\n"), &error)
            || !writeFile(policyDir + QStringLiteral("/Machine/registry.pol"),
                          QByteArray::fromHex("5052656701000000"), &error)
            || !writeFile(policyDir + QStringLiteral("/User/registry.pol"),
                          QByteArray::fromHex("5052656701000000"), &error)) {
            result.error = error;
            return result;
        }
    }

    // --- DNS zone ---------------------------------------------------------
    // The zone is produced by the same engine that serves it, so the published
    // service records and the records a client resolves can never disagree.
    {
        DnsServer dns;
        dns.loadAdZone(b.dnsDomain, result.dcHost, dcIp, ldapPort, gcPort,
                       QStringLiteral("Default-First-Site-Name"), kpasswdPort, kdcPort,
                       objectGuidFor(result.baseDn).toString(QUuid::WithoutBraces));
        QString zoneError;
        if (!dns.saveZone(result.zonePath, &zoneError)) {
            result.error = zoneError;
            return result;
        }
    }

    // --- Client configuration --------------------------------------------
    // A krb5.conf that points at this DC, so `kinit` needs no hand-written
    // realm stanza. The KDC port is the one this machine actually serves.
    result.krb5ConfPath = target + QStringLiteral("/krb5.conf");
    if (!writeKrb5Conf(result.krb5ConfPath, result.dnsDomain.toUpper(), result.dnsDomain,
                       dcIp, kdcPort, kpasswdPort, &error)) {
        result.error = error;
        return result;
    }

    // --- Server configuration --------------------------------------------
    // Native or dev ports: a DC answers on AD's well-known bindings; the tests
    // provisioning their own store go through ProvisionConfig.devPorts instead.
    QSettings conf(result.configPath, QSettings::IniFormat);
    conf.setValue(QStringLiteral("realm"), b.dnsDomain.toUpper());
    // The KDC puts this in every PAC as the logon domain's SID.
    conf.setValue(QStringLiteral("domainSid"), result.domainSid);
    conf.setValue(QStringLiteral("dnsDomain"), b.dnsDomain);
    conf.setValue(QStringLiteral("netbiosDomain"), b.netbios);
    conf.setValue(QStringLiteral("baseDn"), b.baseDn);
    conf.setValue(QStringLiteral("ldapPort"), ldapPort);
    conf.setValue(QStringLiteral("gcPort"), gcPort);
    conf.setValue(QStringLiteral("dnsPort"), dnsPort);
    if (!config.forwarders.isEmpty())
        conf.setValue(QStringLiteral("forwarders"), config.forwarders.join(QStringLiteral(", ")));
    // The DC serves SAMR, LSAD, the endpoint mapper and SMB2 the way a Windows
    // DC does: dynamic-RPC ports for the two SAM/LSA interfaces, well-known
    // 135/445 for the mapper and the pipe host. Under `--dev-ports` the mapper
    // and the pipe host move too, so a second DC on this host can bind them.
    conf.setValue(QStringLiteral("samrPort"), samrPort);
    conf.setValue(QStringLiteral("lsadPort"), lsadPort);
    conf.setValue(QStringLiteral("epmPort"), ports.epm);
    conf.setValue(QStringLiteral("smbPort"), ports.smb);
    conf.setValue(QStringLiteral("srvsvcPort"), ports.srvsvc);
    conf.setValue(QStringLiteral("netlogonPort"), config.netlogonPort);
    conf.setValue(QStringLiteral("drsPort"), config.drsPort);
    conf.setValue(QStringLiteral("kdcPort"), kdcPort);
    conf.setValue(QStringLiteral("kpasswdPort"), kpasswdPort);
    conf.setValue(QStringLiteral("krb5ConfPath"), result.krb5ConfPath);
    conf.setValue(QStringLiteral("dcName"), b.dcName);
    conf.setValue(QStringLiteral("dcHost"), result.dcHost);
    conf.setValue(QStringLiteral("dcIp"), dcIp);
    conf.setValue(QStringLiteral("siteName"), QStringLiteral("Default-First-Site-Name"));
    conf.setValue(QStringLiteral("storePath"), result.storePath);
    conf.setValue(QStringLiteral("secretsPath"), result.secretsPath);
    conf.setValue(QStringLiteral("zonePath"), result.zonePath);
    conf.setValue(QStringLiteral("sysvol"), result.sysvolPath);
    if (result.tlsEnabled) {
        conf.setValue(QStringLiteral("tlsCertPath"), result.tlsCertPath);
        conf.setValue(QStringLiteral("tlsKeyPath"), result.tlsKeyPath);
    }

    // Replication partner configuration. A single-DC domain has no partner, so
    // the address stays empty and no pull arms until an administrator adds one
    // with DsReplicaAdd (or sets replicaHost by hand). The credential fields are
    // written anyway so the running DC exercises the same path a multi-DC domain
    // uses, and so the secrets file is the single place the replica password
    // lives (not dc.conf, which is world-readable in some layouts).
    conf.setValue(QStringLiteral("replicaNamingContext"), b.baseDn);
    conf.setValue(QStringLiteral("replicaDomain"), b.netbios);
    conf.setValue(QStringLiteral("replicaUser"), QStringLiteral("Administrator"));
    conf.setValue(QStringLiteral("replicaHost"), QString());
    conf.setValue(QStringLiteral("replicaPort"), 0);
    conf.setValue(QStringLiteral("replicaIntervalSeconds"), 300);
    conf.sync();

    // No replica credential is written here. This file holds a salted verifier
    // and the domain SID; the administrator's password is one the DC must never
    // be able to read back, so a domain that gains a partner gets
    // `replicaPassword` added by the operator who configures that partner —
    // which is why DcService warns when it finds the value in dc.conf instead.
    if (!writeFile(result.secretsPath,
                   QJsonDocument(secrets).toJson(QJsonDocument::Indented), &error)) {
        result.error = error;
        return result;
    }
    if (!QFile::setPermissions(result.secretsPath,
                               QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        result.error = QStringLiteral("cannot restrict permissions on %1").arg(result.secretsPath);
        return result;
    }
    if (conf.status() != QSettings::NoError) {
        result.error = QStringLiteral("cannot write %1").arg(result.configPath);
        return result;
    }

    result.ok = true;
    return result;
}

// --- Promoting a second DC ------------------------------------------------
//
// AD's install-from-media build: a new DC starts from a copy of another DC's
// directory, so every identity a domain has exactly one of — the domain SID,
// the domain object's GUID, the SIDs already handed out, krbtgt's key, the
// policies — is carried over instead of generated again. That is the only way
// the two stores can agree: a domain with two different domain SIDs, or two
// different krbtgt keys, is two domains that happen to share a name.
//
// The copy keeps the source DC's own Server and NTDS Settings objects, which is
// what a second DC needs in its store to know who its partner is, and gains
// this DC's: a computer account under the next free RID, a Server object, and
// an NTDS Settings object beside the source's in the same site. Everything else
// in the store is the domain as it was when the copy was taken; the KCC's next
// pass in this site turns the source DSA into a connection, and the pull
// agent — pointed at the source by the dc.conf written here — takes the
// changes made since.
//
// What is deliberately not here: a pull of the secrets themselves over the
// wire. `Drs.cpp` serves the replicated attribute set and not the password
// material, so a promote that only pulled would leave this DC unable to
// authenticate an account or issue a TGT under the domain's key. The media
// copy is what carries them, which is exactly why AD treats install-from-media
// as carrying secrets and protects it accordingly.
ProvisionResult promoteDomain(const ProvisionConfig &config)
{
    ProvisionResult result;

    const QString source = config.promoteFrom.trimmed().isEmpty()
        ? QString()
        : QDir::cleanPath(QDir(config.promoteFrom).absolutePath());
    if (source.isEmpty() || !QFileInfo(source).isDir()) {
        result.error = QStringLiteral("a provisioned source directory is required to promote");
        return result;
    }
    QSettings sourceConf(source + QStringLiteral("/dc.conf"), QSettings::IniFormat);
    const QString sourceRealm = sourceConf.value(QStringLiteral("realm")).toString();
    const QString netbios = sourceConf.value(QStringLiteral("netbiosDomain")).toString();
    result.dnsDomain = sourceConf.value(QStringLiteral("dnsDomain")).toString();
    result.baseDn = sourceConf.value(QStringLiteral("baseDn")).toString();
    result.domainSid = sourceConf.value(QStringLiteral("domainSid")).toString();
    const QString siteName =
        sourceConf.value(QStringLiteral("siteName"), QStringLiteral("Default-First-Site-Name"))
            .toString();
    // Paths inside the copy first: a media directory is often copied to another
    // host, where the absolute store path the source dc.conf recorded does not
    // exist, and the copy's own tree is then the truth.
    const auto sourcePath = [&source](const QString &configured, const QString &relative) {
        const QString local = source + relative;
        if (QFileInfo::exists(local) || configured.isEmpty())
            return local;
        return configured;
    };
    const QString sourceStore = sourcePath(
        sourceConf.value(QStringLiteral("storePath")).toString(),
        QStringLiteral("/private/directory.json"));
    const QString sourceSecrets = sourcePath(
        sourceConf.value(QStringLiteral("secretsPath")).toString(),
        QStringLiteral("/private/secrets.json"));
    const QString sourceZone = sourcePath(
        sourceConf.value(QStringLiteral("zonePath")).toString(),
        QStringLiteral("/private/dnszone.json"));
    const QString sourceSysvol = sourcePath(sourceConf.value(QStringLiteral("sysvol")).toString(),
                                             QStringLiteral("/sysvol/") + result.dnsDomain);

    if (sourceRealm.isEmpty() || result.baseDn.isEmpty() || netbios.isEmpty()
        || !QFileInfo::exists(sourceStore)) {
        result.error =
            QStringLiteral("%1 does not hold a provisioned domain (no realm, base DN or store)")
                .arg(source);
        return result;
    }

    QString error;
    if (!validateNetbiosDomain(netbios, &error)) {
        result.error = error;
        return result;
    }
    if (config.adminPassword.isEmpty()) {
        result.error = QStringLiteral("the password used to pull from the source DC is required");
        return result;
    }
    const QString dcIp = config.dcIp.trimmed().isEmpty() ? QStringLiteral("127.0.0.1")
                                                         : config.dcIp.trimmed();
    if (QHostAddress(dcIp).isNull()) {
        result.error = QStringLiteral("invalid domain controller address: %1").arg(dcIp);
        return result;
    }

    QString dcLabel;
    QString dcHost;
    if (!resolveControllerHost(result.dnsDomain, config.dcHost, &dcLabel, &dcHost, &error)) {
        result.error = error;
        return result;
    }
    result.dcHost = dcHost;
    const ServicePorts ports = servicePorts(config);

    QString target = config.targetDir;
    if (target.trimmed().isEmpty()) {
        result.error = QStringLiteral("target directory must not be empty");
        return result;
    }
    target = QDir::cleanPath(QDir(target).absolutePath());
    if (target == source) {
        result.error = QStringLiteral("the target must not be the directory being copied from");
        return result;
    }

    const QString privateDir = target + QStringLiteral("/private");
    result.storePath = privateDir + QStringLiteral("/directory.json");
    result.secretsPath = privateDir + QStringLiteral("/secrets.json");
    result.configPath = target + QStringLiteral("/dc.conf");
    result.zonePath = privateDir + QStringLiteral("/dnszone.json");
    result.sysvolPath = target + QStringLiteral("/sysvol/") + result.dnsDomain;
    if (QFileInfo::exists(result.storePath) && !config.force) {
        result.error = QStringLiteral("%1 is already provisioned (use --force to overwrite)")
                           .arg(target);
        return result;
    }

    // --- The media copy ---------------------------------------------------
    LdapServer store;
    if (!store.loadFromFile(sourceStore)) {
        result.error = QStringLiteral("cannot read the copied directory store %1").arg(sourceStore);
        return result;
    }
    const QList<DirectoryObject> objects = store.objects();
    const auto find = [&objects](const QString &dn) -> const DirectoryObject * {
        for (const DirectoryObject &object : objects) {
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0)
                return &object;
        }
        return nullptr;
    };
    const DirectoryObject *domain = find(result.baseDn);
    if (!domain || domain->attributes.value(QStringLiteral("objectSid")).isEmpty()) {
        result.error = QStringLiteral("the copied store has no domain object at %1")
                           .arg(result.baseDn);
        return result;
    }
    // The domain object is the authority on the domain's SID, not dc.conf.
    result.domainSid = domain->attributes.value(QStringLiteral("objectSid"));
    const QString configDn = QStringLiteral("CN=Configuration,%1").arg(result.baseDn);
    const QString siteDn = QStringLiteral("CN=%1,CN=Sites,%2").arg(siteName, configDn);
    if (!find(siteDn)) {
        result.error = QStringLiteral("the copied store publishes no site %1").arg(siteName);
        return result;
    }

    const QString dcDn =
        QStringLiteral("CN=%1,OU=Domain Controllers,%2").arg(dcLabel, result.baseDn);
    const QString machineName = dcLabel + QStringLiteral("$");
    for (const DirectoryObject &object : objects) {
        if (object.id.compare(dcDn, Qt::CaseInsensitive) == 0
            || object.attributes.value(QStringLiteral("sAMAccountName"))
                   .compare(machineName, Qt::CaseInsensitive) == 0) {
            result.error = QStringLiteral("%1 is already a controller in this domain")
                               .arg(dcLabel);
            return result;
        }
    }

    // --- This DC's own objects -------------------------------------------
    // The computer account: the machine account every DC authenticates as, and
    // the object the KDC reads this DC's service keys from.
    DirectoryObject dc;
    dc.id = dcDn;
    dc.name = dcLabel;
    dc.type = QStringLiteral("Computer");
    dc.kind = ObjectKind::Computer;
    dc.container = QStringLiteral("Domain Controllers");
    dc.description = QStringLiteral("Domain controller for %1").arg(result.dnsDomain);
    dc.attributes.insert(QStringLiteral("distinguishedName"), dcDn);
    dc.attributes.insert(QStringLiteral("objectClass"),
                         joinAttributeValues({QStringLiteral("top"), QStringLiteral("person"),
                                              QStringLiteral("organizationalPerson"),
                                              QStringLiteral("user"),
                                              QStringLiteral("computer")}));
    dc.attributes.insert(QStringLiteral("cn"), dcLabel);
    dc.attributes.insert(QStringLiteral("sAMAccountName"), machineName);
    dc.attributes.insert(QStringLiteral("dNSHostName"), dcHost);
    dc.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("12288"));
    dc.attributes.insert(QStringLiteral("operatingSystem"),
                         QStringLiteral("Monarchy DC (Linux)"));
    dc.attributes.insert(QStringLiteral("isDomainController"), QStringLiteral("yes"));
    dc.attributes.insert(QStringLiteral("ntHash"), randomKeyHex());
    Krb5::storeRandomKeys(dc);
    dc.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"), QStringLiteral("1"));
    dc.attributes.insert(
        QStringLiteral("servicePrincipalName"),
        QStringLiteral("ldap/%1; ldap/%1.%2; ldap/%1.%2/%2; HOST/%1; HOST/%1.%2; "
                       "GC/%1; GC/%1.%2; cifs/%1; cifs/%1.%2; DNS/%1.%2; "
                       "DNS/ns1.%2; RestrictedKrbHost/%1; RestrictedKrbHost/%1.%2")
            .arg(dcLabel.toLower(), result.dnsDomain));
    dc.attributes.insert(QStringLiteral("pwdLastSet"),
                         QString::number(QDateTime::currentDateTimeUtc().toSecsSinceEpoch()));
    if (!store.addAccount(&dc, &error)) {
        result.error = QStringLiteral("cannot create the controller account: %1").arg(error);
        return result;
    }

    // The Server object and its NTDS Settings object, beside the source DC's in
    // the same site. Without the DSA the KCC on either side has no vertex to
    // connect to, and without the Server object the connection has no address.
    const QString serverDn = QStringLiteral("CN=%1,CN=Servers,%2").arg(dcLabel, siteDn);
    DirectoryObject server;
    server.id = serverDn;
    server.name = dcLabel;
    server.type = QStringLiteral("Server");
    server.kind = ObjectKind::Container;
    server.container = QStringLiteral("Console Root");
    server.attributes.insert(QStringLiteral("distinguishedName"), serverDn);
    server.attributes.insert(QStringLiteral("objectClass"),
                             joinAttributeValues({QStringLiteral("top"),
                                                  QStringLiteral("server")}));
    server.attributes.insert(QStringLiteral("cn"), dcLabel);
    server.attributes.insert(QStringLiteral("dNSHostName"), dcHost);
    store.addObject(server);

    const QString ntdsSettingsDn = QStringLiteral("CN=NTDS Settings,%1").arg(serverDn);
    DirectoryObject ntds;
    ntds.id = ntdsSettingsDn;
    ntds.name = QStringLiteral("NTDS Settings");
    ntds.type = QStringLiteral("NTDS Settings");
    ntds.kind = ObjectKind::Container;
    ntds.container = serverDn;
    ntds.attributes.insert(QStringLiteral("distinguishedName"), ntdsSettingsDn);
    ntds.attributes.insert(QStringLiteral("objectClass"),
                           joinAttributeValues({QStringLiteral("top"),
                                                QStringLiteral("nTDSDSA")}));
    ntds.attributes.insert(QStringLiteral("cn"), QStringLiteral("NTDS Settings"));
    // options bit 0: this DSA serves the Global Catalog.
    ntds.attributes.insert(QStringLiteral("options"), QStringLiteral("1"));
    ntds.attributes.insert(QStringLiteral("invocationId"),
                           QUuid::createUuid().toString(QUuid::WithoutBraces));
    ntds.attributes.insert(
        QStringLiteral("hasMasterNCs"),
        QStringLiteral("%1; CN=Configuration,%1; CN=Schema,CN=Configuration,%1")
            .arg(result.baseDn));
    store.addObject(ntds);

    // A DC is a member of Domain Controllers; every group membership a client
    // sees is derived from these lists.
    const QString groupDn =
        QStringLiteral("CN=Domain Controllers,CN=Users,%1").arg(result.baseDn);
    if (const DirectoryObject *group = find(groupDn)) {
        // The members are the object's list, not the joined attribute: the
        // attribute is derived on the way out, so reading it would drop the
        // controllers that are already members.
        QStringList members = group->members;
        if (!members.contains(dcDn, Qt::CaseInsensitive))
            members.append(dcDn);
        if (!store.modifyObject(groupDn,
                                {{QStringLiteral("member"), joinAttributeValues(members)}})) {
            result.error = QStringLiteral("cannot add %1 to Domain Controllers").arg(dcLabel);
            return result;
        }
    }

    for (const QString &dir : {target, privateDir, target + QStringLiteral("/var"),
                               target + QStringLiteral("/var/lib/monarchy")}) {
        if (!QDir().mkpath(dir)) {
            result.error = QStringLiteral("cannot create directory %1").arg(dir);
            return result;
        }
    }
    if (!store.saveToFile(result.storePath)) {
        result.error = QStringLiteral("cannot write directory store %1").arg(result.storePath);
        return result;
    }
    result.objectCount = store.objects().size();

    // --- Secrets ----------------------------------------------------------
    // The domain's secrets are the media copy's: same krbtgt key, same account
    // verifiers, so a ticket issued here opens there and the reverse. What is
    // this DC's own is the machine GUID, and the credential the pull
    // authenticates with.
    QJsonObject secrets;
    {
        QFile file(sourceSecrets);
        if (file.open(QIODevice::ReadOnly))
            secrets = QJsonDocument::fromJson(file.readAll()).object();
    }
    secrets[QStringLiteral("realm")] = result.dnsDomain.toUpper();
    secrets[QStringLiteral("netbiosDomain")] = netbios;
    secrets[QStringLiteral("domainSid")] = result.domainSid;
    secrets[QStringLiteral("machineGuid")] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    secrets[QStringLiteral("replicaPassword")] = config.adminPassword;
    if (!writeFile(result.secretsPath,
                   QJsonDocument(secrets).toJson(QJsonDocument::Indented), &error)) {
        result.error = error;
        return result;
    }
    if (!QFile::setPermissions(result.secretsPath,
                               QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        result.error = QStringLiteral("cannot restrict permissions on %1").arg(result.secretsPath);
        return result;
    }

    // --- TLS --------------------------------------------------------------
    result.tlsCertPath = privateDir + QStringLiteral("/ldap.crt");
    result.tlsKeyPath = privateDir + QStringLiteral("/ldap.key");
    result.tlsEnabled = generateSelfSignedCertificate(
        result.tlsCertPath, result.tlsKeyPath, dcHost,
        {dcHost, result.dnsDomain, dcIp, QStringLiteral("127.0.0.1"),
         QStringLiteral("localhost")},
        &result.tlsError);

    // --- SYSVOL -----------------------------------------------------------
    // The policy tree comes with the copy. Replicating SYSVOL between DCs is a
    // separate service (FRS/DFSR) and is not what this does.
    if (!copyTree(sourceSysvol, result.sysvolPath, &error)) {
        result.error = error;
        return result;
    }

    // --- DNS zone ---------------------------------------------------------
    // The copy's zone, with this DC's locators added and its own A records held
    // to its address. The source DC's records stay in the zone: a client that
    // follows either DC reaches a DC.
    {
        DnsServer dns;
        if (QFileInfo::exists(sourceZone)) {
            QString zoneError;
            if (!dns.loadZone(sourceZone, &zoneError)) {
                result.error = zoneError;
                return result;
            }
        } else {
            dns.loadAdZone(result.dnsDomain, dcHost, dcIp, ports.ldap, ports.gc, siteName,
                           ports.kpasswd, ports.kdc,
                           objectGuidFor(result.baseDn).toString(QUuid::WithoutBraces));
        }
        // The GUID clients key the locator names on is the domain NC's — the
        // same value the copy carried, never a function of the SID.
        const QString domainGuid = objectGuidFor(result.baseDn).toString(QUuid::WithoutBraces);
        dns.repairAdZoneLocators(dcHost, ports.ldap, ports.gc, siteName, ports.kpasswd,
                                 ports.kdc, domainGuid);
        dns.repairAdZoneAddresses(dcHost, dcIp);
        QString zoneError;
        if (!dns.saveZone(result.zonePath, &zoneError)) {
            result.error = zoneError;
            return result;
        }
    }

    result.krb5ConfPath = target + QStringLiteral("/krb5.conf");
    if (!writeKrb5Conf(result.krb5ConfPath, result.dnsDomain.toUpper(), result.dnsDomain,
                       dcIp, ports.kdc, ports.kpasswd, &error)) {
        result.error = error;
        return result;
    }

    // --- Server configuration --------------------------------------------
    const QString replicaHost = config.replicaHost.trimmed().isEmpty()
        ? sourceConf.value(QStringLiteral("dcHost"),
                           sourceConf.value(QStringLiteral("dcIp")).toString())
              .toString()
        : config.replicaHost.trimmed();
    const quint16 replicaPort = config.replicaPort != 0
        ? config.replicaPort
        : quint16(sourceConf.value(QStringLiteral("drsPort"), 1038).toUInt());
    if (replicaHost.isEmpty()) {
        result.error = QStringLiteral("the copied dc.conf names no source DC to pull from "
                                      "(pass --replica-host)");
        return result;
    }
    QSettings conf(result.configPath, QSettings::IniFormat);
    conf.setValue(QStringLiteral("realm"), result.dnsDomain.toUpper());
    conf.setValue(QStringLiteral("domainSid"), result.domainSid);
    conf.setValue(QStringLiteral("dnsDomain"), result.dnsDomain);
    conf.setValue(QStringLiteral("netbiosDomain"), netbios);
    conf.setValue(QStringLiteral("baseDn"), result.baseDn);
    conf.setValue(QStringLiteral("ldapPort"), ports.ldap);
    conf.setValue(QStringLiteral("gcPort"), ports.gc);
    conf.setValue(QStringLiteral("dnsPort"), ports.dns);
    // Forwarders follow the copy unless the caller names new ones: the upstream
    // list is a property of the network this DC sits in, not of the domain.
    QStringList forwarders = config.forwarders;
    if (forwarders.isEmpty()) {
        const QVariant raw = sourceConf.value(QStringLiteral("forwarders"));
        forwarders = raw.typeId() == QMetaType::QStringList
            ? raw.toStringList()
            : raw.toString().split(QLatin1Char(','), Qt::SkipEmptyParts);
        forwarders.erase(std::remove_if(forwarders.begin(), forwarders.end(),
                                        [](QString &value) {
                                            value = value.trimmed();
                                            return value.isEmpty();
                                        }),
                         forwarders.end());
    }
    if (!forwarders.isEmpty())
        conf.setValue(QStringLiteral("forwarders"), forwarders.join(QStringLiteral(", ")));
    conf.setValue(QStringLiteral("samrPort"), ports.samr);
    conf.setValue(QStringLiteral("lsadPort"), ports.lsad);
    conf.setValue(QStringLiteral("epmPort"), ports.epm);
    conf.setValue(QStringLiteral("smbPort"), ports.smb);
    conf.setValue(QStringLiteral("srvsvcPort"), ports.srvsvc);
    conf.setValue(QStringLiteral("netlogonPort"), config.netlogonPort);
    conf.setValue(QStringLiteral("drsPort"), config.drsPort);
    conf.setValue(QStringLiteral("kdcPort"), ports.kdc);
    conf.setValue(QStringLiteral("kpasswdPort"), ports.kpasswd);
    conf.setValue(QStringLiteral("krb5ConfPath"), result.krb5ConfPath);
    conf.setValue(QStringLiteral("dcName"), dcLabel);
    conf.setValue(QStringLiteral("dcHost"), dcHost);
    conf.setValue(QStringLiteral("dcIp"), dcIp);
    conf.setValue(QStringLiteral("siteName"), siteName);
    conf.setValue(QStringLiteral("storePath"), result.storePath);
    conf.setValue(QStringLiteral("secretsPath"), result.secretsPath);
    conf.setValue(QStringLiteral("zonePath"), result.zonePath);
    conf.setValue(QStringLiteral("sysvol"), result.sysvolPath);
    if (result.tlsEnabled) {
        conf.setValue(QStringLiteral("tlsCertPath"), result.tlsCertPath);
        conf.setValue(QStringLiteral("tlsKeyPath"), result.tlsKeyPath);
    }
    // The partner this DC pulls from, and the credential it does so with. The
    // source's DRS port is named rather than looked up through the endpoint
    // mapper: a second DC on the same host cannot own 135 as well.
    conf.setValue(QStringLiteral("replicaNamingContext"), result.baseDn);
    conf.setValue(QStringLiteral("replicaDomain"), netbios);
    conf.setValue(QStringLiteral("replicaUser"),
                  config.replicaUser.trimmed().isEmpty()
                      ? QStringLiteral("Administrator")
                      : config.replicaUser.trimmed());
    conf.setValue(QStringLiteral("replicaHost"), replicaHost);
    conf.setValue(QStringLiteral("replicaPort"), replicaPort);
    conf.setValue(QStringLiteral("replicaIntervalSeconds"), 300);
    conf.sync();
    if (conf.status() != QSettings::NoError) {
        result.error = QStringLiteral("cannot write %1").arg(result.configPath);
        return result;
    }

    result.ok = true;
    return result;
}
