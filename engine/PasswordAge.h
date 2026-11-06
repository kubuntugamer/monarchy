// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PASSWORDAGE_H
#define PASSWORDAGE_H

#include <QDateTime>
#include <QList>
#include <QString>

#include "resultsmodel.h"

// Whether an account may log on with a password it can still prove. AD keeps
// pwdLastSet as an absolute time and the domain's maxPwdAge as a delta time (a
// negative count of 100-nanosecond units); a password older than that delta has
// expired, and pwdLastSet of zero means the account must change it at the next
// logon whatever the age. DONT_EXPIRE_PASSWORD on the account overrides both.
namespace PasswordAge {

enum class State {
    Valid,
    // Older than the domain's maximum age: AD answers STATUS_PASSWORD_EXPIRED.
    Expired,
    // pwdLastSet is zero: AD answers STATUS_PASSWORD_MUST_CHANGE.
    MustChange,
};

// `pwdLastSet` is the directory's own attribute, seconds since the epoch.
State state(qint64 pwdLastSet, quint32 userAccountControl, qint64 maxPasswordAge,
            qint64 now = QDateTime::currentSecsSinceEpoch());

// The same check against an account object and the directory that holds the
// domain object carrying the policy. An account the directory does not describe
// (no pwdLastSet at all) is left to the caller's other checks.
State stateFor(const DirectoryObject &account, const QList<DirectoryObject> &directory,
               qint64 now = QDateTime::currentSecsSinceEpoch());

} // namespace PasswordAge

#endif // PASSWORDAGE_H
