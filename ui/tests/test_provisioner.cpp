// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>
#include <QFile>
#include <QFuture>
#include <QtConcurrent>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QTemporaryDir>

#include "LdapClient.h"
#include "LdapServer.h"
#include "Provisioner.h"

namespace {

ProvisionConfig testConfig(const QString &targetDir)
{
    ProvisionConfig config;
    config.realm = QStringLiteral("TEST.EXAMPLE.ORG");
    config.netbiosDomain = QStringLiteral("TEST");
    config.adminPassword = QStringLiteral("Secret123!");
    config.targetDir = targetDir;
    return config;
}

// The LDAP server and the test live on one thread, so the blocking client runs
// on a worker (exactly like the console's DirectoryService) and the main thread
// keeps spinning the server's event loop.
struct LdapProbe {
    bool opened = false;
    bool bound = false;
    bool anonymous = false;
    bool wrongPasswordAccepted = false;
    bool unknownUserAccepted = false;
    QList<LdapClient::Entry> users;
    QList<LdapClient::Entry> rootDse;
    QString error;
};

const DirectoryObject *findByDn(const QList<DirectoryObject> &objects, const QString &dn)
{
    for (const DirectoryObject &object : objects) {
        if (object.id.compare(dn, Qt::CaseInsensitive) == 0)
            return &object;
    }
    return nullptr;
}

} // namespace

class ProvisionerTest : public QObject
{
    Q_OBJECT

private slots:
    void buildsDomainFromScratch();
    void refusesExistingTargetWithoutForce();
    void servesProvisionedDomainOverLdap();
    void rejectsWrongCredentials();
};

void ProvisionerTest::buildsDomainFromScratch()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    const ProvisionResult result = provisionDomain(testConfig(dir.path()));
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.baseDn, QStringLiteral("DC=test,DC=example,DC=org"));
    QCOMPARE(result.dnsDomain, QStringLiteral("test.example.org"));
    QVERIFY(result.domainSid.startsWith(QStringLiteral("S-1-5-21-")));

    QVERIFY(QFile::exists(result.storePath));
    QVERIFY(QFile::exists(result.secretsPath));
    QVERIFY(QFile::exists(result.configPath));
    QVERIFY(QFileInfo(result.sysvolPath + QStringLiteral("/scripts")).isDir());
    QVERIFY(QFileInfo(result.sysvolPath + QStringLiteral("/Policies")).isDir());

    QSettings conf(result.configPath, QSettings::IniFormat);
    QCOMPARE(conf.value(QStringLiteral("baseDn")).toString(), result.baseDn);
    QCOMPARE(conf.value(QStringLiteral("realm")).toString(), QStringLiteral("TEST.EXAMPLE.ORG"));
    QCOMPARE(conf.value(QStringLiteral("netbiosDomain")).toString(), QStringLiteral("TEST"));
    // The config the console reads publishes the SAMR and LSAD endpoints it will
    // serve.
    QCOMPARE(conf.value(QStringLiteral("samrPort")).toInt(), 1035);
    QCOMPARE(conf.value(QStringLiteral("lsadPort")).toInt(), 1036);

    LdapServer store;
    QVERIFY(store.loadFromFile(result.storePath));
    const QList<DirectoryObject> objects = store.objects();
    QCOMPARE(objects.size(), result.objectCount);

    // Root DSE reflects the provisioned naming context, not a hardcoded one.
    QVERIFY(!objects.isEmpty());
    QVERIFY(objects.first().id.isEmpty());
    QCOMPARE(objects.first().attributes.value(QStringLiteral("defaultNamingContext")), result.baseDn);
    QCOMPARE(objects.first().attributes.value(QStringLiteral("configurationNamingContext")),
             QStringLiteral("CN=Configuration,%1").arg(result.baseDn));

    const DirectoryObject *domain = findByDn(objects, result.baseDn);
    QVERIFY(domain);
    QCOMPARE(domain->type, QStringLiteral("domainDNS"));
    QCOMPARE(domain->attributes.value(QStringLiteral("objectSid")), result.domainSid);

    const DirectoryObject *admin =
        findByDn(objects, QStringLiteral("CN=Administrator,CN=Users,%1").arg(result.baseDn));
    QVERIFY(admin);
    QVERIFY(admin->attributes.value(QStringLiteral("objectSid")).endsWith(QStringLiteral("-500")));
    const QString domainAdminsDn =
        QStringLiteral("CN=Domain Admins,CN=Users,%1").arg(result.baseDn);
    const QString adminDn = QStringLiteral("CN=Administrator,CN=Users,%1").arg(result.baseDn);
    QVERIFY(admin->memberOf.contains(domainAdminsDn));

    const DirectoryObject *krbtgt =
        findByDn(objects, QStringLiteral("CN=krbtgt,CN=Users,%1").arg(result.baseDn));
    QVERIFY(krbtgt);
    QVERIFY(krbtgt->attributes.value(QStringLiteral("objectSid")).endsWith(QStringLiteral("-502")));
    // The KDC's long-term key is random and never derived from a password.
    QCOMPARE(krbtgt->attributes.value(QStringLiteral("ntHash")).size(), 32);
    QCOMPARE(krbtgt->attributes.value(QStringLiteral("msDS-KeyVersionNumber")),
             QStringLiteral("1"));

    const DirectoryObject *domainAdmins = findByDn(objects, domainAdminsDn);
    QVERIFY(domainAdmins);
    QVERIFY(domainAdmins->members.contains(adminDn));

    const DirectoryObject *dc =
        findByDn(objects, QStringLiteral("CN=TESTDC1,OU=Domain Controllers,%1").arg(result.baseDn));
    QVERIFY(dc);
    QCOMPARE(dc->attributes.value(QStringLiteral("dNSHostName")),
             QStringLiteral("testdc1.test.example.org"));
    QCOMPARE(dc->attributes.value(QStringLiteral("isDomainController")), QStringLiteral("yes"));
    // The DC computer account carries the service keys and the SPNs a client
    // asks the KDC for, exactly as AD does.
    QCOMPARE(dc->attributes.value(QStringLiteral("ntHash")).size(), 32);
    const QString spns = dc->attributes.value(QStringLiteral("servicePrincipalName"));
    QVERIFY(spns.contains(QStringLiteral("ldap/testdc1.test.example.org")));
    QVERIFY(spns.contains(QStringLiteral("HOST/testdc1.test.example.org")));
    QVERIFY(spns.contains(QStringLiteral("GC/testdc1.test.example.org")));
    QVERIFY(spns.contains(QStringLiteral("cifs/testdc1.test.example.org")));

    // A ready-to-use client configuration points at this DC's KDC port.
    QVERIFY(QFile::exists(result.krb5ConfPath));
    QFile krb5Conf(result.krb5ConfPath);
    QVERIFY(krb5Conf.open(QIODevice::ReadOnly));
    const QByteArray krb5Text = krb5Conf.readAll();
    QVERIFY(krb5Text.contains("default_realm = TEST.EXAMPLE.ORG"));
    QVERIFY(krb5Text.contains(QStringLiteral("kdc = 127.0.0.1:%1")
                                  .arg(conf.value(QStringLiteral("kdcPort")).toInt())
                                  .toUtf8()));
    QCOMPARE(conf.value(QStringLiteral("kdcPort")).toInt(), 8888);

    QVERIFY(admin->memberOf.contains(
        QStringLiteral("CN=Enterprise Admins,CN=Users,%1").arg(result.baseDn)));

    // Every domain ships with the two well-known policies, linked from the
    // domain and the Domain Controllers OU, with content in SYSVOL.
    const QString domainPolicyGuid = QStringLiteral("{31B2F340-016D-11D2-945F-00C04FB984F9}");
    const QString dcPolicyGuid = QStringLiteral("{6AC1786C-016F-11D2-945F-00C04fB984F9}");
    const QString policiesDn = QStringLiteral("CN=Policies,CN=System,") + result.baseDn;
    QVERIFY(domain->attributes.value(QStringLiteral("gPLink"))
                .contains(QStringLiteral("CN=%1,").arg(domainPolicyGuid)));

    const DirectoryObject *domainPolicy =
        findByDn(objects, QStringLiteral("CN=%1,%2").arg(domainPolicyGuid, policiesDn));
    QVERIFY(domainPolicy);
    QCOMPARE(domainPolicy->attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Default Domain Policy"));
    QCOMPARE(domainPolicy->attributes.value(QStringLiteral("versionNumber")),
             QStringLiteral("0"));
    QVERIFY(domainPolicy->attributes.value(QStringLiteral("gPCFileSysPath"))
                .endsWith(QStringLiteral("Policies\\") + domainPolicyGuid));
    QVERIFY(findByDn(objects, QStringLiteral("CN=%1,%2").arg(dcPolicyGuid, policiesDn)));

    for (const QString &guid : {domainPolicyGuid, dcPolicyGuid}) {
        const QString policyDir = result.sysvolPath + QStringLiteral("/Policies/") + guid;
        QFile gpt(policyDir + QStringLiteral("/GPT.INI"));
        QVERIFY(gpt.open(QIODevice::ReadOnly));
        QVERIFY(gpt.readAll().contains("Version=0"));
        QFile machinePol(policyDir + QStringLiteral("/Machine/registry.pol"));
        QVERIFY(machinePol.open(QIODevice::ReadOnly));
        QCOMPARE(machinePol.read(4), QByteArray("PReg"));
        QVERIFY(QFileInfo::exists(policyDir + QStringLiteral("/User/registry.pol")));
    }

    // The administrator's verifier lives on the object, not only in secrets.
    QVERIFY(!admin->attributes.value(QStringLiteral("userPasswordHash")).isEmpty());
    QVERIFY(!admin->attributes.contains(QStringLiteral("userPassword")));
    // The AD credential (NTOWFv1) is stored too, so NTLM works from the store.
    QCOMPARE(admin->attributes.value(QStringLiteral("ntHash")).size(), 32);

    // The DC is a member of Domain Controllers, and its memberOf is derived
    // from that list rather than stored independently.
    const DirectoryObject *domainControllers =
        findByDn(objects, QStringLiteral("CN=Domain Controllers,CN=Users,%1").arg(result.baseDn));
    QVERIFY(domainControllers);
    QVERIFY(domainControllers->members.contains(dc->id));
    QVERIFY(dc->memberOf.contains(domainControllers->id));

    // Secrets hold a salted verifier, never the plaintext password.
    QFile secretsFile(result.secretsPath);
    QVERIFY(secretsFile.open(QIODevice::ReadOnly));
    const QByteArray rawSecrets = secretsFile.readAll();
    const QJsonObject secrets = QJsonDocument::fromJson(rawSecrets).object();
    QCOMPARE(secrets.value(QStringLiteral("domainSid")).toString(), result.domainSid);
    QCOMPARE(secrets.value(QStringLiteral("administratorDn")).toString(),
             QStringLiteral("CN=Administrator,CN=Users,%1").arg(result.baseDn));
    QVERIFY(!secrets.value(QStringLiteral("passwordHash")).toString().isEmpty());
    QVERIFY(!rawSecrets.contains("Secret123!"));
}

void ProvisionerTest::refusesExistingTargetWithoutForce()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    ProvisionConfig config = testConfig(dir.path());
    const ProvisionResult first = provisionDomain(config);
    QVERIFY2(first.ok, qPrintable(first.error));

    const ProvisionResult second = provisionDomain(config);
    QVERIFY(!second.ok);
    QVERIFY(second.error.contains(QStringLiteral("already provisioned")));

    config.force = true;
    const ProvisionResult forced = provisionDomain(config);
    QVERIFY2(forced.ok, qPrintable(forced.error));
    QVERIFY(forced.domainSid != first.domainSid);
}

void ProvisionerTest::servesProvisionedDomainOverLdap()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const ProvisionResult result = provisionDomain(testConfig(dir.path()));
    QVERIFY2(result.ok, qPrintable(result.error));

    LdapServer server;
    QVERIFY(server.loadFromFile(result.storePath));
    QVERIFY(server.loadSecretsFromFile(result.secretsPath));
    QVERIFY(server.listen(0));
    QVERIFY(server.isListening());

    const quint16 port = server.serverPort();
    const QString baseDn = result.baseDn;
    LdapProbe probe;
    QFuture<void> future = QtConcurrent::run([port, baseDn, &probe] {
        QString error;
        LdapClient client;
        probe.opened = client.open(QStringLiteral("127.0.0.1"), port, &error);
        if (!probe.opened) {
            probe.error = error;
            return;
        }
        probe.bound = client.bind(QStringLiteral("CN=Administrator,CN=Users,%1").arg(baseDn),
                                  QStringLiteral("Secret123!"), &error);
        if (!probe.bound) {
            probe.error = error;
            client.close();
            return;
        }
        probe.users = client.search(baseDn, 2, QStringLiteral("(objectClass=user)"),
                                    {QStringLiteral("sAMAccountName"),
                                     QStringLiteral("objectSid")}, &error);
        probe.rootDse = client.search(QString(), 0, QStringLiteral("(objectClass=*)"),
                                      {QStringLiteral("defaultNamingContext")}, &error);
        probe.error = error;
        client.close();

        // Anonymous binds still work so the console can start signed-out.
        LdapClient anonymous;
        if (!anonymous.open(QStringLiteral("127.0.0.1"), port, &error)) {
            probe.error = error;
            return;
        }
        probe.anonymous = anonymous.bind(QString(), QString(), &error);
        if (!probe.anonymous)
            probe.error = error;
        anonymous.close();
    });
    QTRY_VERIFY_WITH_TIMEOUT(future.isFinished(), 15000);

    QVERIFY2(probe.opened, qPrintable(probe.error));
    QVERIFY2(probe.bound, qPrintable(probe.error));
    QVERIFY2(probe.error.isEmpty(), qPrintable(probe.error));
    QVERIFY(probe.users.size() >= 3);

    bool foundAdministrator = false;
    for (const LdapClient::Entry &entry : probe.users) {
        if (entry.dn.compare(QStringLiteral("CN=Administrator,CN=Users,%1").arg(baseDn),
                             Qt::CaseInsensitive) == 0) {
            foundAdministrator = entry.attrs.value(QStringLiteral("sAMAccountName"))
                                     .value(0) == QStringLiteral("Administrator");
        }
    }
    QVERIFY(foundAdministrator);

    // Password material never leaves the server, even for the built-in admin.
    for (const LdapClient::Entry &entry : probe.users) {
        QVERIFY(!entry.attrs.contains(QStringLiteral("userPasswordHash")));
        QVERIFY(!entry.attrs.contains(QStringLiteral("userPasswordSalt")));
        QVERIFY(!entry.attrs.contains(QStringLiteral("unicodePwd")));
        QVERIFY(!entry.attrs.contains(QStringLiteral("userPassword")));
        QVERIFY(!entry.attrs.contains(QStringLiteral("ntHash")));
        QVERIFY(!entry.attrs.contains(QStringLiteral("passwordScheme")));
    }

    QCOMPARE(probe.rootDse.size(), 1);
    QCOMPARE(probe.rootDse.first().attrs.value(QStringLiteral("defaultNamingContext")).value(0),
             baseDn);
    QVERIFY(probe.anonymous);
}

void ProvisionerTest::rejectsWrongCredentials()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const ProvisionResult result = provisionDomain(testConfig(dir.path()));
    QVERIFY2(result.ok, qPrintable(result.error));

    LdapServer server;
    QVERIFY(server.loadFromFile(result.storePath));
    QVERIFY(server.loadSecretsFromFile(result.secretsPath));
    QVERIFY(server.listen(0));

    const quint16 port = server.serverPort();
    const QString baseDn = result.baseDn;
    LdapProbe probe;
    QFuture<void> future = QtConcurrent::run([port, baseDn, &probe] {
        QString error;
        LdapClient wrongPassword;
        if (!wrongPassword.open(QStringLiteral("127.0.0.1"), port, &error)) {
            probe.error = error;
            return;
        }
        probe.wrongPasswordAccepted =
            wrongPassword.bind(QStringLiteral("CN=Administrator,CN=Users,%1").arg(baseDn),
                               QStringLiteral("not-the-password"), &error);
        wrongPassword.close();

        LdapClient unknownUser;
        if (!unknownUser.open(QStringLiteral("127.0.0.1"), port, &error)) {
            probe.error = error;
            return;
        }
        probe.unknownUserAccepted =
            unknownUser.bind(QStringLiteral("CN=Nobody,CN=Users,%1").arg(baseDn),
                             QStringLiteral("Secret123!"), &error);
        unknownUser.close();
    });
    QTRY_VERIFY_WITH_TIMEOUT(future.isFinished(), 15000);

    QVERIFY2(probe.error.isEmpty(), qPrintable(probe.error));
    QVERIFY(!probe.wrongPasswordAccepted);
    QVERIFY(!probe.unknownUserAccepted);
}

QTEST_GUILESS_MAIN(ProvisionerTest)
#include "test_provisioner.moc"
