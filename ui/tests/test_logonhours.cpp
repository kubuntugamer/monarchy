// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QDate>
#include <QDateTime>
#include <QTime>
#include <QTimeZone>

#include "LogonHours.h"

// The week AD keeps in logonHours: 21 bytes, 168 bits, Sunday 00:00 UTC first.
// Every case below is stated in UTC because that is the zone AD stores in.
class LogonHoursTest : public QObject
{
    Q_OBJECT

private slots:
    void mapsTheWeekFromSunday();
    void anUnsetValueIsNoRestriction();
    void readsEachBitOfTheWeek();
    void allowsOnlyTheSetHour();
    void treatsATruncatedValueAsSilent();
};

namespace {

QDateTime utc(int year, int month, int day, int hour)
{
    return QDateTime(QDate(year, month, day), QTime(hour, 0), QTimeZone::UTC);
}

// A 21-byte bitmap with only `hour` set.
QByteArray allowOnly(int hour)
{
    QByteArray bitmap(21, '\0');
    bitmap[hour / 8] = char(1 << (hour % 8));
    return bitmap;
}

} // namespace

void LogonHoursTest::mapsTheWeekFromSunday()
{
    // 2026-11-01 is a Sunday, so it is hour 0 of the week; the last hour is
    // Saturday 23:00, 167 hours later (2026-11-07).
    QCOMPARE(LogonHours::hourIndex(utc(2026, 11, 1, 0)), 0);
    QCOMPARE(LogonHours::hourIndex(utc(2026, 11, 2, 0)), 24);   // Monday
    QCOMPARE(LogonHours::hourIndex(utc(2026, 11, 2, 9)), 33);   // Monday 09:00
    QCOMPARE(LogonHours::hourIndex(utc(2026, 11, 7, 23)), 167); // Saturday
    QCOMPARE(LogonHours::hourIndex(QDateTime()), -1);
}

void LogonHoursTest::anUnsetValueIsNoRestriction()
{
    // An account that never had logonHours may log on at any hour.
    QVERIFY(LogonHours::allows(QByteArray(), utc(2026, 11, 2, 3)));
    QVERIFY(LogonHours::allowsHex(QString(), utc(2026, 11, 2, 3)));
}

void LogonHoursTest::readsEachBitOfTheWeek()
{
    const QByteArray allAllowed(21, char(0xff));
    const QByteArray noneAllowed(21, char(0x00));
    for (int hour = 0; hour < 168; ++hour) {
        QVERIFY2(LogonHours::allows(allAllowed, utc(2026, 11, 1 + hour / 24, hour % 24)),
                 qPrintable(QStringLiteral("hour %1 refused although every bit is set").arg(hour)));
        QVERIFY2(!LogonHours::allows(noneAllowed, utc(2026, 11, 1 + hour / 24, hour % 24)),
                 qPrintable(QStringLiteral("hour %1 allowed although no bit is set").arg(hour)));
    }
}

void LogonHoursTest::allowsOnlyTheSetHour()
{
    const QByteArray mondayNine = allowOnly(33);
    QVERIFY(LogonHours::allows(mondayNine, utc(2026, 11, 2, 9)));
    // The bit is not a range: the hours either side are outside it.
    QVERIFY(!LogonHours::allows(mondayNine, utc(2026, 11, 2, 8)));
    QVERIFY(!LogonHours::allows(mondayNine, utc(2026, 11, 2, 10)));
    // Nor does the same clock time on another day match.
    QVERIFY(!LogonHours::allows(mondayNine, utc(2026, 11, 3, 9)));

    // Boundaries of the bitmap: Sunday 00:00 is byte 0 bit 0, Saturday 23:00
    // is byte 20 bit 7.
    QVERIFY(LogonHours::allows(allowOnly(0), utc(2026, 11, 1, 0)));
    QVERIFY(LogonHours::allows(allowOnly(167), utc(2026, 11, 7, 23)));
    QVERIFY(!LogonHours::allows(allowOnly(167), utc(2026, 11, 8, 0)));

    // The hex form the directory stores is the same bytes.
    QVERIFY(LogonHours::allowsHex(QString::fromLatin1(mondayNine.toHex()), utc(2026, 11, 2, 9)));
    QVERIFY(!LogonHours::allowsHex(QString::fromLatin1(mondayNine.toHex()), utc(2026, 11, 2, 8)));
}

void LogonHoursTest::treatsATruncatedValueAsSilent()
{
    // AD always writes 21 bytes; a shorter value says nothing about the hours
    // it does not cover, and must not lock the account out of them.
    const QByteArray oneByte = QByteArray::fromHex("01"); // Sunday 00:00 only
    QVERIFY(LogonHours::allows(oneByte, utc(2026, 11, 1, 0)));
    QVERIFY(!LogonHours::allows(oneByte, utc(2026, 11, 1, 1))); // covered, bit clear
    QVERIFY(LogonHours::allows(oneByte, utc(2026, 11, 1, 9))); // not covered at all
    QVERIFY(LogonHours::allows(oneByte, utc(2026, 11, 5, 12)));
}

QTEST_GUILESS_MAIN(LogonHoursTest)
#include "test_logonhours.moc"
