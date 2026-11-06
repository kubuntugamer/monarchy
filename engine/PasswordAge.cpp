// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "PasswordAge.h"

#include <limits>

#include "LdapServer.h"

namespace {

// userAccountControl's DONT_EXPIRE_PASSWORD: the account's password never ages
// out, which is how service accounts are configured.
constexpr quint32 kDontExpirePassword = 0x10000;

} // namespace

PasswordAge::State PasswordAge::state(qint64 pwdLastSet, quint32 userAccountControl,
                                      qint64 maxPasswordAge, qint64 now)
{
    if (userAccountControl & kDontExpirePassword)
        return State::Valid;
    // Zero is "the password has not been set since an administrator demanded a
    // change", which AD reports as a must-change rather than as an expiry.
    if (pwdLastSet <= 0)
        return State::MustChange;
    // maxPwdAge of zero or of the most negative value means "never expires": AD's
    // tools store the latter when a policy of zero days is entered.
    if (maxPasswordAge == 0
        || maxPasswordAge == std::numeric_limits<qint64>::min())
        return State::Valid;
    // A delta time is negative, so its magnitude is the lifetime. pwdLastSet is
    // in seconds here, hence the division from 100-nanosecond units.
    const qint64 lifetime =
        (maxPasswordAge < 0 ? -maxPasswordAge : maxPasswordAge) / 10000000LL;
    return now >= pwdLastSet + lifetime ? State::Expired : State::Valid;
}

PasswordAge::State PasswordAge::stateFor(const DirectoryObject &account,
                                         const QList<DirectoryObject> &directory, qint64 now)
{
    // An account the directory does not describe at all — no pwdLastSet — has no
    // age to judge, so nothing is added to the caller's other refusals. AD
    // always stores the attribute, zero included.
    if (!account.attributes.contains(QStringLiteral("pwdLastSet")))
        return State::Valid;
    const qint64 pwdLastSet =
        account.attributes.value(QStringLiteral("pwdLastSet")).toLongLong();
    const quint32 userAccountControl =
        account.attributes.value(QStringLiteral("userAccountControl")).toUInt();
    qint64 maxPasswordAge = 0;
    for (const DirectoryObject &object : directory) {
        if (object.kind != ObjectKind::Domain)
            continue;
        maxPasswordAge = LdapServer::passwordPolicyFrom(object).maxAge;
        break;
    }
    return state(pwdLastSet, userAccountControl, maxPasswordAge, now);
}
