// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Provisioner.h"

#include "DnsServer.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ntlm.h"

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
        object.attributes.insert(QStringLiteral("objectClass"), classes.join(QLatin1Char(';')));
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
            group.attributes.insert(QStringLiteral("member"), members.join(QStringLiteral("; ")));
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
    b.dcName = firstLabel(b.dnsDomain).toUpper() + QStringLiteral("DC1");
    b.whenCreated = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    result.domainSid = b.sid;
    result.dcHost = b.dcName.toLower() + QLatin1Char('.') + b.dnsDomain;

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
    dc.attributes.insert(
        QStringLiteral("servicePrincipalName"),
        QStringLiteral("ldap/%1; ldap/%1.%2; HOST/%1; HOST/%1.%2; GC/%1.%2; "
                       "cifs/%1.%2; DNS/%1.%2; RestrictedKrbHost/%1; RestrictedKrbHost/%1.%2")
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

    // --- Schema NC -------------------------------------------------------
    const QString schemaDn = QStringLiteral("CN=Schema,%1").arg(configDn);
    DirectoryObject &schema = b.add(schemaDn, QStringLiteral("Schema"),
                                    QStringLiteral("dMD"), ObjectKind::Container,
                                    QStringLiteral("Console Root"));
    b.objectClass(schema, {QStringLiteral("top"), QStringLiteral("dMD")});
    schema.attributes.insert(QStringLiteral("cn"), QStringLiteral("Schema"));

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
                                  QStringLiteral("\\\\%1\\sysvol\\%1\\Policies\\%2")
                                      .arg(result.dcHost, guid));
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
        dns.loadAdZone(b.dnsDomain, result.dcHost, dcIp, 1389, 3268,
                       QStringLiteral("Default-First-Site-Name"));
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
    {
        const QString realm = result.dnsDomain.toUpper();
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
                           "    }\n"
                           "\n"
                           "[domain_realm]\n"
                           "    .%4 = %1\n"
                           "    %4 = %1\n")
                .arg(realm, dcIp)
                .arg(config.kdcPort)
                .arg(result.dnsDomain);
        if (!writeFile(result.krb5ConfPath, contents.toUtf8(), &error)) {
            result.error = error;
            return result;
        }
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
    conf.setValue(QStringLiteral("ldapPort"), config.ldapPort);
    conf.setValue(QStringLiteral("dnsPort"), config.dnsPort);
    // The DC serves SAMR, LSAD, the endpoint mapper and SMB2 the way a Windows
    // DC does: dynamic-RPC ports for the two SAM/LSA interfaces, well-known
    // 135/445 for the mapper and the pipe host. Under `--dev-ports` the
    // unprivileged pair keeps a rootless console or test run bindable.
    conf.setValue(QStringLiteral("samrPort"), config.samrPort);
    conf.setValue(QStringLiteral("lsadPort"), config.lsadPort);
    conf.setValue(QStringLiteral("epmPort"), config.epmPort);
    conf.setValue(QStringLiteral("smbPort"), config.smbPort);
    conf.setValue(QStringLiteral("kdcPort"), config.kdcPort);
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
    conf.sync();
    if (conf.status() != QSettings::NoError) {
        result.error = QStringLiteral("cannot write %1").arg(result.configPath);
        return result;
    }

    result.ok = true;
    return result;
}
