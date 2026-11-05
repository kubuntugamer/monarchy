// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef LOGONHOURS_H
#define LOGONHOURS_H

#include <QByteArray>
#include <QDateTime>
#include <QString>

// logonHours is the 21-byte bitmap AD keeps on an account: 168 bits, one per
// hour of the week, counted in UTC from Sunday 00:00 with the least significant
// bit of the first byte first. A set bit means the account may log on during
// that hour; an account with no value at all is not restricted.
namespace LogonHours {

// 0..167, Sunday-first, or -1 for an invalid time.
int hourIndex(const QDateTime &at);

bool allows(const QByteArray &bitmap, const QDateTime &at);

// The same check for the hex string the directory stores.
bool allowsHex(const QString &hex, const QDateTime &at);

} // namespace LogonHours

#endif // LOGONHOURS_H
