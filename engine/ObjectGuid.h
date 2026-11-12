// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef OBJECTGUID_H
#define OBJECTGUID_H

#include <QCryptographicHash>
#include <QString>
#include <QUuid>

// AD gives every object an objectGUID and clients key on it, but a store built
// here does not always carry one. Several places still have to name the same
// object the same way, and they must agree: the DSNAME on the replication wire,
// the objectGuid attribute, a replication target — and the domain GUID a
// Windows client learns from the DC locator's CLDAP ping, which it then matches
// against the directory. Deriving it in one place is what keeps those agreeing,
// so this lives in a header rather than in whichever file needed it first.
inline QUuid monarchyGuidForSeed(const QString &seed)
{
    return QUuid::fromRfc4122(QCryptographicHash::hash(seed.toUtf8(), QCryptographicHash::Md5));
}

inline QUuid objectGuidFor(const QString &dn)
{
    return monarchyGuidForSeed(QStringLiteral("monarchy-object/") + dn);
}

#endif // OBJECTGUID_H
