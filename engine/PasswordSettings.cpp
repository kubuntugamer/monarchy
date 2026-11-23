// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "PasswordSettings.h"

#include <limits>

namespace {

// This store keeps a multi-valued attribute as a ';'-joined list, which is how
// msDS-PSOAppliesTo's DNs travel through it.
QStringList splitList(const QString &value)
{
    QStringList out;
    for (const QString &part : value.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        const QString trimmed = part.trimmed();
        if (!trimmed.isEmpty())
            out.append(trimmed);
    }
    return out;
}

bool booleanValue(const QString &value)
{
    return value.compare(QLatin1String("TRUE"), Qt::CaseInsensitive) == 0
           || value == QLatin1String("1") || value.compare(QLatin1String("yes"), Qt::CaseInsensitive) == 0;
}

const DirectoryObject *domainObject(const QList<DirectoryObject> &directory)
{
    for (const DirectoryObject &object : directory) {
        if (object.kind == ObjectKind::Domain)
            return &object;
    }
    return nullptr;
}

} // namespace

namespace PasswordSettings {

QString containerDn(const QString &domainDn)
{
    return QStringLiteral("CN=Password Settings Container,CN=System,%1").arg(domainDn);
}

bool isPasswordSettings(const DirectoryObject &object)
{
    return object.attributes.value(QStringLiteral("objectClass"))
        .contains(QLatin1String("msDS-PasswordSettings"), Qt::CaseInsensitive);
}

const DirectoryObject *resultant(const DirectoryObject &account,
                                 const QList<DirectoryObject> &directory)
{
    if (account.id.isEmpty())
        return nullptr;
    const DirectoryObject *best = nullptr;
    quint32 bestPrecedence = 0;
    for (const DirectoryObject &object : directory) {
        if (!isPasswordSettings(object))
            continue;
        bool applies = false;
        for (const QString &target : splitList(
                 object.attributes.value(QStringLiteral("msDS-PSOAppliesTo")))) {
            // A policy applies to the account by name, or to a group the account
            // is a member of; AD stores both in the one attribute.
            if (target.compare(account.id, Qt::CaseInsensitive) == 0) {
                applies = true;
                break;
            }
            for (const QString &group : account.memberOf) {
                if (target.compare(group, Qt::CaseInsensitive) == 0) {
                    applies = true;
                    break;
                }
            }
            if (applies)
                break;
        }
        if (!applies)
            continue;
        bool ok = false;
        const quint32 precedence =
            object.attributes.value(QStringLiteral("msDS-PasswordSettingsPrecedence")).toUInt(&ok);
        // Zero is "unset" rather than a policy that beats everything, which is
        // what a client that forgot the attribute would otherwise get.
        if (!ok || precedence == 0)
            continue;
        if (!best || precedence < bestPrecedence) {
            best = &object;
            bestPrecedence = precedence;
        }
    }
    return best;
}

LdapServer::PasswordPolicy policyFor(const DirectoryObject &account,
                                     const QList<DirectoryObject> &directory)
{
    const DirectoryObject *domain = domainObject(directory);
    LdapServer::PasswordPolicy policy = LdapServer::passwordPolicyFrom(
        domain ? *domain : DirectoryObject());
    const DirectoryObject *pso = resultant(account, directory);
    if (!pso)
        return policy;
    const auto value = [pso](const char *name) { return pso->attributes.value(QString::fromLatin1(name)); };
    bool ok = false;
    int number = value("msDS-MinimumPasswordLength").toInt(&ok);
    if (ok)
        policy.minLength = number;
    number = value("msDS-PasswordHistoryLength").toInt(&ok);
    if (ok)
        policy.historyLength = number;
    if (pso->attributes.contains(QStringLiteral("msDS-PasswordComplexityEnabled"))) {
        // The attribute is on/off rather than a bit set, so it replaces the
        // domain's complexity bit and leaves the rest of pwdProperties alone.
        if (booleanValue(value("msDS-PasswordComplexityEnabled")))
            policy.properties |= LdapServer::kPasswordComplex;
        else
            policy.properties &= ~LdapServer::kPasswordComplex;
    }
    qint64 delta = value("msDS-MaximumPasswordAge").toLongLong(&ok);
    if (ok)
        policy.maxAge = delta;
    delta = value("msDS-MinimumPasswordAge").toLongLong(&ok);
    if (ok)
        policy.minAge = delta;
    return policy;
}

Lockout lockoutFor(const DirectoryObject &account, const QList<DirectoryObject> &directory)
{
    Lockout lockout;
    const DirectoryObject *domain = domainObject(directory);
    if (domain) {
        bool ok = false;
        quint32 threshold =
            domain->attributes.value(QStringLiteral("lockoutThreshold")).toUInt(&ok);
        if (ok)
            lockout.threshold = threshold;
        lockout.duration =
            domain->attributes.value(QStringLiteral("lockoutDuration")).toLongLong();
        lockout.window =
            domain->attributes.value(QStringLiteral("lockoutObservationWindow")).toLongLong();
    }
    const DirectoryObject *pso = resultant(account, directory);
    if (!pso)
        return lockout;
    bool ok = false;
    const quint32 threshold =
        pso->attributes.value(QStringLiteral("msDS-LockoutThreshold")).toUInt(&ok);
    if (ok)
        lockout.threshold = threshold;
    const qint64 duration =
        pso->attributes.value(QStringLiteral("msDS-LockoutObservationWindow")).toLongLong(&ok);
    if (ok)
        lockout.window = duration;
    const qint64 lockoutDuration =
        pso->attributes.value(QStringLiteral("msDS-LockoutDuration")).toLongLong(&ok);
    if (ok)
        lockout.duration = lockoutDuration;
    return lockout;
}

} // namespace PasswordSettings
