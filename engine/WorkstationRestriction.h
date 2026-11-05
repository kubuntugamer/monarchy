// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef WORKSTATIONRESTRICTION_H
#define WORKSTATIONRESTRICTION_H

#include <QString>

// userWorkstations is the account's "Log On To" list: the NetBIOS names of the
// computers it may log on from, comma separated, at most eight on the wire that
// writes it. An account with no value is not restricted.
namespace WorkstationRestriction {

// True when `workstation` may log on as an account carrying `list`. Entries are
// matched case-insensitively after trimming, because a NetBIOS name has no
// case; blank entries in the list name nobody and never match.
bool allows(const QString &list, const QString &workstation);

} // namespace WorkstationRestriction

#endif // WORKSTATIONRESTRICTION_H
