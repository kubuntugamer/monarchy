// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "WorkstationRestriction.h"

// The "Log On To" list an account carries: comma-separated NetBIOS names of the
// workstations it may log on from. An unset value restricts nobody.
class WorkstationRestrictionTest : public QObject
{
    Q_OBJECT

private slots:
    void anUnsetListIsNoRestriction();
    void matchesAListedNameIgnoringCaseAndSpace();
    void refusesANameThatIsNotListed();
    void refusesAnUnnamedWorkstationWhenTheListIsSet();
    void ignoresBlankListEntries();
    void comparesTheNetbiosNameOnly();
};

void WorkstationRestrictionTest::anUnsetListIsNoRestriction()
{
    QVERIFY(WorkstationRestriction::allows(QString(), QStringLiteral("WS1")));
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("  "), QStringLiteral("WS1")));
    // Even an unnamed workstation is fine when the account is unrestricted.
    QVERIFY(WorkstationRestriction::allows(QString(), QString()));
}

void WorkstationRestrictionTest::matchesAListedNameIgnoringCaseAndSpace()
{
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("WS1"), QStringLiteral("WS1")));
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("ws1"), QStringLiteral("WS1")));
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("WS1"), QStringLiteral("ws1")));
    // The list is stored with the separator and padding the UI writes.
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("WS1, WS2"), QStringLiteral("WS2")));
    QVERIFY(WorkstationRestriction::allows(QStringLiteral(" WS3 , WS4 "), QStringLiteral("WS4")));
}

void WorkstationRestrictionTest::refusesANameThatIsNotListed()
{
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1,WS2"), QStringLiteral("WS9")));
    // A prefix of a listed name is a different workstation.
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1"), QStringLiteral("WS1A")));
}

void WorkstationRestrictionTest::refusesAnUnnamedWorkstationWhenTheListIsSet()
{
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1"), QString()));
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1"), QStringLiteral("   ")));
}

void WorkstationRestrictionTest::ignoresBlankListEntries()
{
    // "WS1,,WS2," is a list of two names, not a list that also allows nobody.
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1,,WS2,"), QString()));
    QVERIFY(WorkstationRestriction::allows(QStringLiteral("WS1,,WS2,"), QStringLiteral("WS2")));
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral(","), QStringLiteral("WS1")));
}

void WorkstationRestrictionTest::comparesTheNetbiosNameOnly()
{
    // AD stores NetBIOS names; a client that names itself by DNS name is not
    // the entry the administrator wrote, so it does not match.
    QVERIFY(!WorkstationRestriction::allows(QStringLiteral("WS1"),
                                            QStringLiteral("ws1.corp.example.com")));
}

QTEST_GUILESS_MAIN(WorkstationRestrictionTest)
#include "test_workstation.moc"
