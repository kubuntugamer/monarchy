// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LogonHours.h"

namespace LogonHours {

int hourIndex(const QDateTime &at)
{
    if (!at.isValid())
        return -1;
    const QDateTime utc = at.toUTC();
    // QDate::dayOfWeek() is Monday=1 … Sunday=7, and the bitmap starts on
    // Sunday, so the modulo puts Sunday first without a lookup table.
    return ((utc.date().dayOfWeek() % 7) * 24) + utc.time().hour();
}

bool allows(const QByteArray &bitmap, const QDateTime &at)
{
    if (bitmap.isEmpty())
        return true;
    const int hour = hourIndex(at);
    if (hour < 0)
        return true;
    const int byte = hour / 8;
    // A value shorter than the 21 bytes AD writes carries no opinion about the
    // hours it does not cover; those stay allowed rather than locking an
    // account out over a truncated attribute.
    if (byte >= bitmap.size())
        return true;
    return (bitmap.at(byte) & (1 << (hour % 8))) != 0;
}

bool allowsHex(const QString &hex, const QDateTime &at)
{
    if (hex.isEmpty())
        return true;
    return allows(QByteArray::fromHex(hex.toLatin1()), at);
}

} // namespace LogonHours
