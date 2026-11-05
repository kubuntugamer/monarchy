// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Applying a replication cycle: what a second DC does with the objects another
// DC sends. The source side is the store plus its tombstones — exactly what
// DRS exports — so the deletion half of convergence is exercised here without
// a second process or a socket.

#include <QtTest>

#include "LdapServer.h"

namespace {

DirectoryObject domainObject()
{
    DirectoryObject domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.name = QStringLiteral("corp.example.com");
    domain.type = QStringLiteral("Domain");
    return domain;
}

DirectoryObject account(const QString &cn, const QString &guid)
{
    DirectoryObject user;
    user.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(cn);
    user.name = cn;
    user.type = QStringLiteral("User");
    user.attributes.insert(QStringLiteral("sAMAccountName"), cn);
    user.attributes.insert(QStringLiteral("description"), QStringLiteral("temporary"));
    user.attributes.insert(QStringLiteral("objectGUID"), guid);
    return user;
}

QList<DirectoryObject> cycleFrom(const LdapServer &source)
{
    return source.objects() + source.tombstones();
}

const DirectoryObject *liveObject(const LdapServer &store, const QString &cn)
{
    for (const DirectoryObject &object : store.objects()) {
        if (object.name == cn)
            return &object;
    }
    return nullptr;
}

} // namespace

class ReplicationTest : public QObject
{
    Q_OBJECT

private slots:
    void createsObjectsThatTheSourceHolds()
    {
        LdapServer source;
        source.addObject(domainObject());
        source.addObject(account(QStringLiteral("alice"),
                                 QStringLiteral("{11111111-1111-1111-1111-111111111111}")));

        LdapServer target;
        target.addObject(domainObject());

        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);
        QVERIFY(liveObject(target, QStringLiteral("alice")) != nullptr);
        QCOMPARE(liveObject(target, QStringLiteral("alice"))
                     ->attributes.value(QStringLiteral("sAMAccountName")),
                 QStringLiteral("alice"));
    }

    void deletesAnObjectAndKeepsTheTombstone()
    {
        LdapServer source;
        source.addObject(domainObject());
        const DirectoryObject alice = account(
            QStringLiteral("alice"), QStringLiteral("{22222222-2222-2222-2222-222222222222}"));
        source.addObject(alice);

        LdapServer target;
        target.addObject(domainObject());
        target.applyReplication(cycleFrom(source));
        QVERIFY(liveObject(target, QStringLiteral("alice")) != nullptr);

        QVERIFY(source.removeObject(alice.id));
        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);

        QVERIFY(liveObject(target, QStringLiteral("alice")) == nullptr);
        QCOMPARE(target.tombstones().size(), 1);
        QCOMPARE(target.tombstones().first().attributes.value(QStringLiteral("isDeleted")),
                 QStringLiteral("TRUE"));
    }

    void applyingTheSameCycleTwiceChangesNothingTheSecondTime()
    {
        LdapServer source;
        source.addObject(domainObject());
        const DirectoryObject alice = account(
            QStringLiteral("alice"), QStringLiteral("{33333333-3333-3333-3333-333333333333}"));
        source.addObject(alice);
        source.removeObject(alice.id);

        LdapServer target;
        target.addObject(domainObject());
        target.applyReplication(cycleFrom(source));
        const int tombstoneCount = target.tombstones().size();

        target.applyReplication(cycleFrom(source));
        QCOMPARE(target.tombstones().size(), tombstoneCount);
        QVERIFY(liveObject(target, QStringLiteral("alice")) == nullptr);
    }

    void doesNotResurrectADeletedObject()
    {
        LdapServer source;
        source.addObject(domainObject());
        const DirectoryObject alice = account(
            QStringLiteral("alice"), QStringLiteral("{44444444-4444-4444-4444-444444444444}"));
        source.addObject(alice);

        LdapServer target;
        target.addObject(domainObject());
        target.applyReplication(cycleFrom(source));
        QVERIFY(source.removeObject(alice.id));
        target.applyReplication(cycleFrom(source));

        // A stale live copy still arrives from a partner that had not seen the
        // deletion; it must not bring the account back.
        const int applied = target.applyReplication(QList<DirectoryObject>{alice});
        QCOMPARE(applied, 0);
        QVERIFY(liveObject(target, QStringLiteral("alice")) == nullptr);
    }
};

QTEST_MAIN(ReplicationTest)
#include "test_replication.moc"
