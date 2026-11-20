// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Applying a replication cycle: what a second DC does with the objects another
// DC sends. The source side is the store plus its tombstones — exactly what
// DRS exports — so the deletion half of convergence is exercised here without
// a second process or a socket.

#include <QtTest>

#include "LdapServer.h"
#include "ObjectGuid.h"
#include "ReplicationAgent.h"

#include <QTimeZone>

#include <optional>

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

// objects() returns a QList by value, so a pointer into it dangles as soon as
// the range-for ends. Return the object itself; nullopt means absent.
std::optional<DirectoryObject> liveObject(const LdapServer &store, const QString &cn)
{
    for (const DirectoryObject &object : store.objects()) {
        if (object.name == cn)
            return object;
    }
    return std::nullopt;
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
        QVERIFY(liveObject(target, QStringLiteral("alice")).has_value());
        QCOMPARE(liveObject(target, QStringLiteral("alice"))
                     ->attributes.value(QStringLiteral("sAMAccountName")),
                 QStringLiteral("alice"));
    }

    // The store derives an objectGUID from the DN when it holds none, and that
    // derived GUID is the identity DRS exports for the object. A DC that created
    // an account before the replication link existed still holds it without a
    // stored GUID, so it has to recognise its own object by that same identity:
    // matching on the stored attribute alone left it unmatched and appended a
    // second entry at the same distinguished name.
    void recognisesItsOwnObjectByTheGuidThePartnerNames()
    {
        DirectoryObject local;
        local.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
        local.name = QStringLiteral("alice");
        local.type = QStringLiteral("User");
        local.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
        const QString derivedGuid = objectGuidFor(local.id).toString(QUuid::WithBraces);

        LdapServer source;
        source.addObject(domainObject());
        source.addObject(account(QStringLiteral("alice"), derivedGuid));

        LdapServer target;
        target.addObject(domainObject());
        target.addObject(local);

        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);

        int matches = 0;
        for (const DirectoryObject &object : target.objects()) {
            if (object.name == QStringLiteral("alice"))
                ++matches;
        }
        QCOMPARE(matches, 1);
        QCOMPARE(liveObject(target, QStringLiteral("alice"))
                     ->attributes.value(QStringLiteral("objectGUID")),
                 derivedGuid);
    }

    // What a cycle carries is the replicated attribute set, not the credentials:
    // each DC holds its own copy of the password hashes. Applying a cycle must
    // leave the hash this DC already had, or every account that replicated in
    // stops authenticating on this DC.
    void keepsTheCredentialsThePartnerDoesNotSend()
    {
        const QString guid = QStringLiteral("{66666666-6666-6666-6666-666666666666}");
        LdapServer source;
        source.addObject(domainObject());
        source.addObject(account(QStringLiteral("alice"), guid));

        DirectoryObject local = account(QStringLiteral("alice"), guid);
        local.attributes.insert(QStringLiteral("ntHash"),
                               QStringLiteral("0123456789abcdef0123456789abcdef"));

        LdapServer target;
        target.addObject(domainObject());
        target.addObject(local);

        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);
        const std::optional<DirectoryObject> alice = liveObject(target, QStringLiteral("alice"));
        QVERIFY(alice.has_value());
        QCOMPARE(alice->attributes.value(QStringLiteral("ntHash")),
                 QStringLiteral("0123456789abcdef0123456789abcdef"));
        // The attributes the partner does carry are applied over it.
        QCOMPARE(alice->attributes.value(QStringLiteral("description")),
                 QStringLiteral("temporary"));
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
        QVERIFY(liveObject(target, QStringLiteral("alice")).has_value());

        QVERIFY(source.removeObject(alice.id));
        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);

        QVERIFY(!liveObject(target, QStringLiteral("alice")).has_value());
        QCOMPARE(target.tombstones().size(), 1);
        QCOMPARE(target.tombstones().first().attributes.value(QStringLiteral("isDeleted")),
                 QStringLiteral("TRUE"));
    }

    // A deletion replicates by identity, not by the name the object no longer
    // has: the tombstone carries the objectGUID the live object had. A store
    // that derived that GUID has to carry the derived one, otherwise the
    // partner sees a tombstone it cannot match against anything and leaves the
    // live copy standing.
    void aDeletionCarriesTheIdentityTheObjectHad()
    {
        DirectoryObject alice;
        alice.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
        alice.name = QStringLiteral("alice");
        alice.type = QStringLiteral("User");
        alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));

        LdapServer source;
        source.addObject(domainObject());
        source.addObject(alice);

        LdapServer target;
        target.addObject(domainObject());
        target.addObject(alice);

        QVERIFY(source.removeObject(alice.id));
        QVERIFY(target.applyReplication(cycleFrom(source)) >= 1);
        QVERIFY(!liveObject(target, QStringLiteral("alice")).has_value());
        QCOMPARE(target.tombstones().size(), 1);
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
        QVERIFY(!liveObject(target, QStringLiteral("alice")).has_value());
    }

    // A replication partner asks only for what is above the cursor it already
    // has, so a USN that goes backwards is an object that never replicates.
    // The counter is in memory and a store loaded from disk already holds
    // higher USNs, so loading has to carry the high-water mark forward.
    void keepsUsnMovingForwardAcrossALoad()
    {
        DirectoryObject domain = domainObject();
        domain.attributes.insert(QStringLiteral("uSNChanged"), QStringLiteral("1031"));

        LdapServer store;
        store.setObjects(QList<DirectoryObject>{domain});

        DirectoryObject alice = account(
            QStringLiteral("alice"), QStringLiteral("{77777777-7777-7777-7777-777777777777}"));
        store.addObject(alice);
        QVERIFY(liveObject(store, QStringLiteral("alice")).has_value());
        QVERIFY(liveObject(store, QStringLiteral("alice"))
                    ->attributes.value(QStringLiteral("uSNChanged"))
                    .toLongLong()
                > 1031);
    }

    // REPLTIMES (MS-DRSR 5.165): 672 bits, 15 minutes each, counted from Sunday
    // 00:00 UTC, the most significant bit of a byte first. A link asking for
    // periodic sync is pulled only inside the slots its schedule sets.
    void scheduleSlotsAreTheQuarterHoursTheSpecNames()
    {
        QByteArray schedule(ReplicationAgent::kScheduleBytes, '\0');
        // Monday 2026-11-09 03:15 UTC is one day past Sunday and 13 quarter-hours
        // into the day.
        const int slot = 96 + 13;
        schedule[slot / 8] = char(0x80u >> (slot % 8));

        const QDateTime monday315(QDate(2026, 11, 9), QTime(3, 15), QTimeZone::utc());
        QVERIFY(ReplicationAgent::slotAllowed(schedule, monday315));
        QVERIFY(!ReplicationAgent::slotAllowed(
            schedule, QDateTime(QDate(2026, 11, 9), QTime(3, 30), QTimeZone::utc())));
        QCOMPARE(ReplicationAgent::nextSlotStart(schedule, monday315.addSecs(-900)),
                 monday315);
        // From Tuesday the next allowed slot is the following Monday.
        QCOMPARE(ReplicationAgent::nextSlotStart(
                     schedule, QDateTime(QDate(2026, 11, 10), QTime(9, 0), QTimeZone::utc())),
                 QDateTime(QDate(2026, 11, 16), QTime(3, 15), QTimeZone::utc()));
    }

    void theWeekWrapsAfterSevenDays()
    {
        QByteArray schedule(ReplicationAgent::kScheduleBytes, '\0');
        schedule[0] = char(0x80); // Sunday 00:00
        const QDateTime sunday(QDate(2026, 11, 8), QTime(0, 0), QTimeZone::utc());
        QVERIFY(ReplicationAgent::slotAllowed(schedule, sunday));
        // The slot ends a second later, and the next one is a week away.
        QCOMPARE(ReplicationAgent::nextSlotStart(schedule, sunday.addSecs(1)),
                 QDateTime(QDate(2026, 11, 15), QTime(0, 0), QTimeZone::utc()));
    }

    void theDelayFollowsTheScheduleOnlyWhenPeriodicSyncIsRequested()
    {
        QByteArray schedule(ReplicationAgent::kScheduleBytes, '\0');
        const int slot = 96 + 13;
        schedule[slot / 8] = char(0x80u >> (slot % 8));
        const QDateTime now(QDate(2026, 11, 9), QTime(3, 0), QTimeZone::utc());

        // DRS_PER_SYNC set: the next cycle waits for the slot.
        QCOMPARE(ReplicationAgent::nextCycleDelayMs(schedule, ReplicationAgent::kDrsPerSync,
                                                    300, now),
                 qint64(15 * 60 * 1000));
        // Without it the schedule does not govern; the interval does.
        QCOMPARE(ReplicationAgent::nextCycleDelayMs(schedule, 0, 300, now), qint64(300000));
        // A schedule with no bit set schedules nothing at all.
        QCOMPARE(ReplicationAgent::nextCycleDelayMs(QByteArray(84, '\0'),
                                                    ReplicationAgent::kDrsPerSync, 300, now),
                 qint64(-1));
        // A blob that is not 84 bytes is not a schedule.
        QCOMPARE(ReplicationAgent::nextCycleDelayMs(QByteArray(), 0, 300, now), qint64(300000));
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
        QVERIFY(!liveObject(target, QStringLiteral("alice")).has_value());
    }
};

QTEST_MAIN(ReplicationTest)
#include "test_replication.moc"
