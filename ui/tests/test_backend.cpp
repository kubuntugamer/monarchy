// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QFuture>
#include <QTemporaryDir>

#include "AdminService.h"
#include "ConnectionService.h"
#include "DirectoryService.h"
#include "DnsServer.h"
#include "LdapServer.h"
#include "SampleData.h"

class BackendTest : public QObject
{
    Q_OBJECT

private slots:
    void servesSampleData();
    void writesRoundTrip();
    void persistsStore();
    void groupMembershipRoundTrip();
    void passwordSetAndBind();
    void evaluatesCompositeFilters();
    void dnsZoneLoaded();

private:
    static DirectoryObject findByName(const QList<DirectoryObject> &objects, const QString &name)
    {
        for (const DirectoryObject &object : objects) {
            if (object.name == name)
                return object;
        }
        return {};
    }
};

void BackendTest::servesSampleData()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());
    QVERIFY(connection.isConnected());
    QCOMPARE(connection.baseDn(), profile.baseDn);

    DirectoryService directory(&connection);
    auto searchFuture = directory.search(profile.baseDn, QStringLiteral("(objectClass=*)"),
                                        QStringList(), 1000);
    QTRY_VERIFY_WITH_TIMEOUT(searchFuture.isFinished(), 5000);
    const QList<DirectoryObject> objects = searchFuture.result();

    QCOMPARE(objects.size(), 12);
    for (const DirectoryObject &object : objects) {
        QVERIFY(!object.id.isEmpty());
        QVERIFY(!object.id.startsWith(QStringLiteral("CN=Schema,")));
        QVERIFY(!object.id.startsWith(QStringLiteral("CN=Configuration,")));
    }

    const DirectoryObject alice = findByName(objects, QStringLiteral("Alice Chen"));
    QVERIFY(!alice.id.isEmpty());
    QCOMPARE(alice.container, QStringLiteral("Users"));
    QCOMPARE(alice.attributes.value(QStringLiteral("givenName")), QStringLiteral("Alice"));
    QCOMPARE(alice.attributes.value(QStringLiteral("mail")),
             QStringLiteral("alice.chen@corp.example.com"));

    const DirectoryObject admins = findByName(objects, QStringLiteral("Domain Admins"));
    QVERIFY(!admins.id.isEmpty());
    QCOMPARE(admins.container, QStringLiteral("Groups"));
    QCOMPARE(admins.kind, ObjectKind::Group);
    QCOMPARE(admins.members.size(), 2);
    // `member` holds distinguished names, as AD stores it.
    QVERIFY(admins.members.contains(
        QStringLiteral("CN=Administrator,CN=Users,DC=corp,DC=example,DC=com")));

    const DirectoryObject dc = findByName(objects, QStringLiteral("DC01"));
    QVERIFY(!dc.id.isEmpty());
    QCOMPARE(dc.container, QStringLiteral("Domain Controllers"));
    QCOMPARE(dc.kind, ObjectKind::Computer);

    // A domain-naming-context search must not leak the root DSE.
    auto rootFuture = directory.getAttributes(QString());
    QTRY_VERIFY_WITH_TIMEOUT(rootFuture.isFinished(), 5000);
    QCOMPARE(rootFuture.result().value(QStringLiteral("vendorName")), QStringLiteral("Monarchy"));
    QCOMPARE(rootFuture.result().value(QStringLiteral("defaultNamingContext")), profile.baseDn);
}

void BackendTest::writesRoundTrip()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());

    DirectoryService directory(&connection);
    const QString dn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");

    QMap<QString, QString> changes;
    changes.insert(QStringLiteral("description"), QStringLiteral("Updated by test"));
    changes.insert(QStringLiteral("telephoneNumber"), QStringLiteral("555-0199"));
    auto modifyFuture = directory.modifyObject(dn, changes);
    QTRY_VERIFY_WITH_TIMEOUT(modifyFuture.isFinished(), 5000);
    QVERIFY(modifyFuture.result());

    auto readFuture = directory.getAttributes(dn);
    QTRY_VERIFY_WITH_TIMEOUT(readFuture.isFinished(), 5000);
    const QMap<QString, QString> attrs = readFuture.result();
    QCOMPARE(attrs.value(QStringLiteral("description")), QStringLiteral("Updated by test"));
    QCOMPARE(attrs.value(QStringLiteral("telephoneNumber")), QStringLiteral("555-0199"));

    DirectoryObject newUser;
    newUser.id = QStringLiteral("CN=Test User,CN=Users,DC=corp,DC=example,DC=com");
    newUser.name = QStringLiteral("Test User");
    newUser.description = QStringLiteral("Created by add test");
    newUser.kind = ObjectKind::User;
    newUser.container = QStringLiteral("Users");
    newUser.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    newUser.attributes.insert(QStringLiteral("cn"), QStringLiteral("Test User"));
    newUser.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("testuser"));
    newUser.attributes.insert(QStringLiteral("givenName"), QStringLiteral("Test"));
    newUser.attributes.insert(QStringLiteral("sn"), QStringLiteral("User"));

    auto addFuture = directory.addObject(newUser);
    QTRY_VERIFY_WITH_TIMEOUT(addFuture.isFinished(), 5000);
    QVERIFY(addFuture.result());

    auto findFuture = directory.search(profile.baseDn, QStringLiteral("(cn=Test User)"),
                                       QStringList(), 100);
    QTRY_VERIFY_WITH_TIMEOUT(findFuture.isFinished(), 5000);
    const QList<DirectoryObject> found = findFuture.result();
    QCOMPARE(found.size(), 1);
    QCOMPARE(found.first().name, QStringLiteral("Test User"));
    QCOMPARE(found.first().container, QStringLiteral("Users"));
    QCOMPARE(found.first().kind, ObjectKind::User);
    QCOMPARE(found.first().description, QStringLiteral("Created by add test"));
    QCOMPARE(found.first().attributes.value(QStringLiteral("sAMAccountName")),
             QStringLiteral("testuser"));

    auto duplicateFuture = directory.addObject(newUser);
    QTRY_VERIFY_WITH_TIMEOUT(duplicateFuture.isFinished(), 5000);
    QVERIFY(!duplicateFuture.result());

    auto removeFuture = directory.removeObject(newUser.id);
    QTRY_VERIFY_WITH_TIMEOUT(removeFuture.isFinished(), 5000);
    QVERIFY(removeFuture.result());

    auto goneFuture = directory.search(profile.baseDn, QStringLiteral("(cn=Test User)"),
                                       QStringList(), 100);
    QTRY_VERIFY_WITH_TIMEOUT(goneFuture.isFinished(), 5000);
    QVERIFY(goneFuture.result().isEmpty());

    auto removeAgainFuture = directory.removeObject(newUser.id);
    QTRY_VERIFY_WITH_TIMEOUT(removeAgainFuture.isFinished(), 5000);
    QVERIFY(!removeAgainFuture.result());

    auto missingModifyFuture = directory.modifyObject(QStringLiteral("CN=Missing,CN=Users,DC=corp,DC=example,DC=com"), changes);
    QTRY_VERIFY_WITH_TIMEOUT(missingModifyFuture.isFinished(), 5000);
    QVERIFY(!missingModifyFuture.result());
}

void BackendTest::persistsStore()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("directory.json"));

    {
        LdapServer server;
        server.setObjects(sampleObjects());
        QVERIFY(server.saveToFile(path));
    }

    LdapServer restored;
    QVERIFY(restored.loadFromFile(path));

    bool foundUser = false;
    bool foundGroup = false;
    bool foundComputer = false;
    for (const DirectoryObject &object : restored.objects()) {
        if (object.name == QStringLiteral("Alice Chen"))
            foundUser = object.attributes.value(QStringLiteral("mail"))
                            == QStringLiteral("alice.chen@corp.example.com");
        else if (object.name == QStringLiteral("Domain Admins"))
            foundGroup = object.attributes.value(QStringLiteral("groupType"))
                             == QStringLiteral("Security");
        else if (object.name == QStringLiteral("DC01"))
            foundComputer = object.attributes.value(QStringLiteral("operatingSystem"))
                                == QStringLiteral("Windows Server 2022");
    }
    QVERIFY(foundUser);
    QVERIFY(foundGroup);
    QVERIFY(foundComputer);
}

void BackendTest::groupMembershipRoundTrip()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());

    DirectoryService directory(&connection);
    AdminService admin(&directory);

    const QString usersDn = QStringLiteral("CN=Users,DC=corp,DC=example,DC=com");
    auto createFuture = admin.createGroup(QStringLiteral("Audit Team"), usersDn);
    QTRY_VERIFY_WITH_TIMEOUT(createFuture.isFinished(), 5000);
    QVERIFY(createFuture.result());

    const QString groupDn = QStringLiteral("CN=Audit Team,") + usersDn;
    const QString aliceDn = QStringLiteral("CN=Alice Chen,") + usersDn;
    const QString bobDn = QStringLiteral("CN=Bob Martinez,") + usersDn;

    auto addAlice = admin.addUserToGroup(aliceDn, groupDn);
    QTRY_VERIFY_WITH_TIMEOUT(addAlice.isFinished(), 5000);
    QVERIFY(addAlice.result());

    auto addBob = admin.addMember(groupDn, bobDn);
    QTRY_VERIFY_WITH_TIMEOUT(addBob.isFinished(), 5000);
    QVERIFY(addBob.result());

    // Adding a second member must not drop the first (the multi-valued list is
    // read, extended and written back).
    auto groupFuture = directory.search(groupDn, QStringLiteral("(objectClass=*)"), QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(groupFuture.isFinished(), 5000);
    const QList<DirectoryObject> groups = groupFuture.result();
    QCOMPARE(groups.size(), 1);
    QCOMPARE(groups.first().members.size(), 2);
    QVERIFY(groups.first().members.contains(aliceDn));
    QVERIFY(groups.first().members.contains(bobDn));

    // memberOf is derived by the server from the groups' member lists.
    auto aliceFuture = directory.search(aliceDn, QStringLiteral("(objectClass=*)"), QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(aliceFuture.isFinished(), 5000);
    const QList<DirectoryObject> alice = aliceFuture.result();
    QCOMPARE(alice.size(), 1);
    QCOMPARE(alice.first().memberOf.count(groupDn), 1);

    auto removeBob = admin.removeUserFromGroup(bobDn, groupDn);
    QTRY_VERIFY_WITH_TIMEOUT(removeBob.isFinished(), 5000);
    QVERIFY(removeBob.result());

    auto afterFuture = directory.search(groupDn, QStringLiteral("(objectClass=*)"), QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(afterFuture.isFinished(), 5000);
    const QList<DirectoryObject> after = afterFuture.result();
    QCOMPARE(after.first().members.size(), 1);
    QVERIFY(after.first().members.contains(aliceDn));

    auto bobFuture = directory.search(bobDn, QStringLiteral("(objectClass=*)"), QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(bobFuture.isFinished(), 5000);
    QCOMPARE(bobFuture.result().first().memberOf.count(groupDn), 0);

    // A client may not forge memberOf: the server keeps it derived.
    QMap<QString, QString> forged;
    forged.insert(QStringLiteral("memberOf"),
                  QStringLiteral("CN=Domain Admins,") + usersDn);
    auto forgeFuture = directory.modifyObject(aliceDn, forged);
    QTRY_VERIFY_WITH_TIMEOUT(forgeFuture.isFinished(), 5000);
    auto aliceAgain = directory.search(aliceDn, QStringLiteral("(objectClass=*)"), QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(aliceAgain.isFinished(), 5000);
    QCOMPARE(aliceAgain.result().first().memberOf.count(groupDn), 1);

    // Membership survives a save/load cycle.
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("directory.json"));
    QVERIFY(server.saveToFile(path));
    LdapServer restored;
    QVERIFY(restored.loadFromFile(path));
    const QList<DirectoryObject> reloaded = restored.objects();
    const DirectoryObject reloadedGroup = findByName(reloaded, QStringLiteral("Audit Team"));
    QCOMPARE(reloadedGroup.members, QStringList{aliceDn});
    QCOMPARE(findByName(reloaded, QStringLiteral("Alice Chen")).memberOf.count(groupDn), 1);
}

void BackendTest::passwordSetAndBind()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());

    DirectoryService directory(&connection);
    AdminService admin(&directory);

    const QString usersDn = QStringLiteral("CN=Users,DC=corp,DC=example,DC=com");
    auto createFuture = admin.createUser(QStringLiteral("Erin Shaw"), usersDn,
                                         QStringLiteral("Str0ng-Pass!"));
    QTRY_VERIFY_WITH_TIMEOUT(createFuture.isFinished(), 5000);
    QVERIFY(createFuture.result());

    const QString erinDn = QStringLiteral("CN=Erin Shaw,") + usersDn;

    // The engine stored a verifier, not the password, and never returns it.
    auto searchFuture = directory.search(erinDn, QStringLiteral("(objectClass=*)"),
                                         QStringList(), 10);
    QTRY_VERIFY_WITH_TIMEOUT(searchFuture.isFinished(), 5000);
    const QList<DirectoryObject> found = searchFuture.result();
    QCOMPARE(found.size(), 1);
    for (const QString &attribute : {QStringLiteral("userPassword"),
                                     QStringLiteral("userPasswordHash"),
                                     QStringLiteral("userPasswordSalt"),
                                     QStringLiteral("unicodePwd")})
        QVERIFY2(!found.first().attributes.contains(attribute), qPrintable(attribute));
    QVERIFY(!found.first().attributes.value(QStringLiteral("pwdLastSet")).isEmpty());

    // qWait pumps this thread's event loop, which the in-process server needs
    // in order to answer the worker thread's bind.
    auto bindAs = [&](const QString &password) {
        ConnectionService user;
        ConnectionProfile userProfile = profile;
        userProfile.bindDn = erinDn;
        userProfile.password = password;
        QFuture<bool> future = user.connect(userProfile);
        for (int i = 0; i < 200 && !future.isFinished(); ++i)
            QTest::qWait(10);
        if (!future.isFinished()) {
            user.disconnect();
            return false;
        }
        const bool ok = future.result();
        user.disconnect();
        return ok;
    };

    QVERIFY(bindAs(QStringLiteral("Str0ng-Pass!")));
    QVERIFY(!bindAs(QStringLiteral("wrong-password")));

    // A password that does not meet policy is rejected and changes nothing.
    auto weakReset = admin.resetPassword(erinDn, QStringLiteral("short"), false);
    QTRY_VERIFY_WITH_TIMEOUT(weakReset.isFinished(), 5000);
    QVERIFY(!weakReset.result());
    QVERIFY(bindAs(QStringLiteral("Str0ng-Pass!")));

    auto reset = admin.resetPassword(erinDn, QStringLiteral("N3w-Passw0rd!"), false);
    QTRY_VERIFY_WITH_TIMEOUT(reset.isFinished(), 5000);
    QVERIFY(reset.result());
    QVERIFY(!bindAs(QStringLiteral("Str0ng-Pass!")));
    QVERIFY(bindAs(QStringLiteral("N3w-Passw0rd!")));

    // Password material is server-only: a client cannot install its own hash.
    QMap<QString, QString> forged;
    forged.insert(QStringLiteral("userPasswordHash"), QStringLiteral("deadbeef"));
    auto forgeFuture = directory.modifyObject(erinDn, forged);
    QTRY_VERIFY_WITH_TIMEOUT(forgeFuture.isFinished(), 5000);
    QVERIFY(bindAs(QStringLiteral("N3w-Passw0rd!")));

    // ACCOUNTDISABLE (0x2) blocks authentication even with the right password.
    QMap<QString, QString> disable;
    disable.insert(QStringLiteral("userAccountControl"), QStringLiteral("514"));
    auto disableFuture = directory.modifyObject(erinDn, disable);
    QTRY_VERIFY_WITH_TIMEOUT(disableFuture.isFinished(), 5000);
    QVERIFY(!bindAs(QStringLiteral("N3w-Passw0rd!")));

    QMap<QString, QString> enable;
    enable.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    auto enableFuture = directory.modifyObject(erinDn, enable);
    QTRY_VERIFY_WITH_TIMEOUT(enableFuture.isFinished(), 5000);
    QVERIFY(bindAs(QStringLiteral("N3w-Passw0rd!")));
}

void BackendTest::evaluatesCompositeFilters()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());

    DirectoryService directory(&connection);
    auto run = [&directory, &profile](const QString &filter) {
        auto future = directory.search(profile.baseDn, filter, QStringList(), 100);
        for (int i = 0; i < 200 && !future.isFinished(); ++i)
            QTest::qWait(10);
        return future.isFinished() ? future.result() : QList<DirectoryObject>{};
    };

    auto names = [](const QList<DirectoryObject> &objects) {
        QStringList out;
        for (const DirectoryObject &object : objects)
            out.append(object.name);
        out.sort();
        return out;
    };

    // AND: only the user whose cn matches.
    QCOMPARE(names(run(QStringLiteral("(&(objectClass=user)(cn=Alice Chen))"))),
             QStringList{QStringLiteral("Alice Chen")});

    // OR: both users, nothing else.
    QCOMPARE(names(run(QStringLiteral("(|(cn=Alice Chen)(cn=Bob Martinez))"))),
             (QStringList{QStringLiteral("Alice Chen"), QStringLiteral("Bob Martinez")}));

    // NOT: everything except users.
    const QList<DirectoryObject> nonUsers = run(QStringLiteral("(!(objectClass=user))"));
    QCOMPARE(nonUsers.size(), 8);
    for (const DirectoryObject &object : nonUsers)
        QVERIFY(object.kind != ObjectKind::User);

    // Substring: initial, any and final components.
    QCOMPARE(names(run(QStringLiteral("(cn=Alice*)"))), QStringList{QStringLiteral("Alice Chen")});
    QCOMPARE(names(run(QStringLiteral("(cn=*Chen)"))), QStringList{QStringLiteral("Alice Chen")});
    QCOMPARE(names(run(QStringLiteral("(cn=*ice*)"))), QStringList{QStringLiteral("Alice Chen")});
    QVERIFY(run(QStringLiteral("(cn=*Nobody*)")).isEmpty());

    // Presence inside a boolean still works; Guest has an empty mail value,
    // so it is not "present".
    QCOMPARE(run(QStringLiteral("(&(objectClass=user)(mail=*))")).size(), 3);
}

void BackendTest::dnsZoneLoaded()
{
    DnsServer server;
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    QCOMPARE(server.records(QStringLiteral("corp.example.com"), 6).size(), 1);
    QCOMPARE(server.records(QStringLiteral("corp.example.com"), 2).size(), 1);
    QCOMPARE(server.records(QStringLiteral("ns1.corp.example.com"), 1).size(), 1);

    QCOMPARE(server.records(QStringLiteral("_ldap._tcp.dc._msdcs.corp.example.com"), 33).size(), 1);
    QCOMPARE(server.records(QStringLiteral("_kerberos._tcp.dc._msdcs.corp.example.com"), 33).size(), 1);

    server.addRecord(QStringLiteral("www.corp.example.com"), 1, 300,
                     QByteArray::fromHex("7f000002"));
    QCOMPARE(server.records(QStringLiteral("WWW.corp.example.com"), 1).size(), 1);
    server.removeRecord(QStringLiteral("www.corp.example.com"), 1);
    QVERIFY(server.records(QStringLiteral("www.corp.example.com"), 1).isEmpty());
}

QTEST_GUILESS_MAIN(BackendTest)
#include "test_backend.moc"
