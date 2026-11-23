// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PASSWORDSETTINGS_H
#define PASSWORDSETTINGS_H

#include <QList>
#include <QString>

#include "LdapServer.h"
#include "resultsmodel.h"

// Fine-grained password policies: the msDS-PasswordSettings objects AD keeps in
// CN=Password Settings Container,CN=System,<domain>, each carrying its own
// length, complexity, history and age rules, and applying to the users and
// groups named in msDS-PSOAppliesTo. A password settings object (PSO) that
// applies to an account overrides the domain policy for that account alone; the
// one with the lowest msDS-PasswordSettingsPrecedence wins, and the domain
// policy governs everything the resulting PSO does not say.
namespace PasswordSettings {

// The container AD puts PSOs in. Provisioned empty, because an AD domain has it
// before an administrator creates the first policy.
QString containerDn(const QString &domainDn);

bool isPasswordSettings(const DirectoryObject &object);

// The PSO governing `account`, or null when the domain policy does. Applies-to
// names a user directly or a group the account is a member of, and the lowest
// precedence wins — the number AD documents as 1 being the most specific.
const DirectoryObject *resultant(const DirectoryObject &account,
                                 const QList<DirectoryObject> &directory);

// The policy that governs `account`: the domain's, overlaid with every field the
// resultant PSO carries. A field the PSO omits stays as the domain has it,
// which is how AD treats the optional fields of the class.
LdapServer::PasswordPolicy policyFor(const DirectoryObject &account,
                                     const QList<DirectoryObject> &directory);

// The lockout policy that governs `account`, from the same source: a PSO may
// narrow the domain's threshold, duration and observation window.
struct Lockout {
    quint32 threshold = 0;
    qint64 duration = 0; // AD delta-time form: negative 100ns units
    qint64 window = 0;
};
Lockout lockoutFor(const DirectoryObject &account, const QList<DirectoryObject> &directory);

} // namespace PasswordSettings

#endif // PASSWORDSETTINGS_H
