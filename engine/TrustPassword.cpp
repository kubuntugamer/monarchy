// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "TrustPassword.h"

#include "Krb5.h"

#include <QRandomGenerator>

namespace {

bool hasClass(const DirectoryObject &object, const QString &name)
{
    const QStringList classes = object.attributes.value(QStringLiteral("objectClass"))
                                    .split(QLatin1Char(';'), Qt::SkipEmptyParts);
    for (const QString &candidate : classes) {
        if (candidate.trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

// The naming context a trustedDomain object lives in: everything after the
// CN=System its DN is anchored at.
QString baseDnOf(const QString &trustDn)
{
    const int at = trustDn.indexOf(QStringLiteral("CN=System,"), 0, Qt::CaseInsensitive);
    if (at < 0)
        return QString();
    return trustDn.mid(at + 10);
}

} // namespace

QList<TrustPassword::Rotation> TrustPassword::due(const QList<DirectoryObject> &objects,
                                                  qint64 nowSeconds)
{
    QList<Rotation> rotations;
    for (const DirectoryObject &trust : objects) {
        if (!hasClass(trust, QStringLiteral("trustedDomain")))
            continue;
        // No incoming secret is no password to change: an outbound-only trust
        // carries nothing this DC could rotate.
        if (trust.attributes.value(QStringLiteral("trustAuthIncoming")).isEmpty())
            continue;
        const QString flat = trust.attributes.value(QStringLiteral("flatName"));
        const QString baseDn = baseDnOf(trust.id);
        if (flat.isEmpty() || baseDn.isEmpty())
            continue;
        const QString accountDn =
            QStringLiteral("CN=%1$,CN=Users,%2").arg(flat, baseDn);
        qint64 lastSet = -1;
        for (const DirectoryObject &object : objects) {
            if (object.id.compare(accountDn, Qt::CaseInsensitive) != 0)
                continue;
            bool ok = false;
            lastSet = object.attributes.value(QStringLiteral("pwdLastSet"))
                          .toLongLong(&ok);
            if (!ok)
                lastSet = -1;
            break;
        }
        // An account that is there but has never had a password set dates
        // nothing; one that is absent is not a trust this DC keeps a password
        // for.
        if (lastSet < 0)
            continue;
        const qint64 age = nowSeconds - lastSet;
        if (age < kLifetimeSeconds)
            continue;
        Rotation rotation;
        rotation.trustDn = trust.id;
        rotation.accountDn = accountDn;
        rotation.partner = trust.attributes.value(QStringLiteral("trustPartner"));
        rotation.flatName = flat;
        rotation.ageSeconds = age;
        rotations.append(rotation);
    }
    return rotations;
}

QString TrustPassword::generate()
{
    // No ';' or ':' and no whitespace: the secret travels through this store as
    // "2:<hex of the UTF-8 bytes>", and a separator inside the password would
    // make a stored secret unreadable.
    static const char kAlphabet[] =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.+=!";
    const int alphabetSize = int(sizeof(kAlphabet)) - 1;
    QString password;
    password.reserve(30);
    for (int i = 0; i < 30; ++i)
        password.append(QLatin1Char(kAlphabet[QRandomGenerator::global()->bounded(alphabetSize)]));
    return password;
}

QMap<QString, QString> TrustPassword::rotationAttributes(const DirectoryObject &trust,
                                                         const QString &realm,
                                                         const QString &password)
{
    QMap<QString, QString> updates;
    // TRUST_AUTH_TYPE_CLEAR: the form the trust channel reads and the form a
    // peer that fetches the secret over the channel can derive its hash from.
    const QString secret = QStringLiteral("2:") + QString::fromLatin1(password.toUtf8().toHex());
    updates.insert(QStringLiteral("trustAuthIncoming"), secret);
    updates.insert(QStringLiteral("trustAuthOutgoing"), secret);
    DirectoryObject derived;
    Krb5::storeTrustKeys(derived, password, realm,
                         trust.attributes.value(QStringLiteral("trustPartner")));
    for (auto it = derived.attributes.constBegin(); it != derived.attributes.constEnd(); ++it)
        updates.insert(it.key(), it.value());
    return updates;
}
