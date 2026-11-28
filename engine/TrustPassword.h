// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef MONARCHY_TRUSTPASSWORD_H
#define MONARCHY_TRUSTPASSWORD_H

#include "resultsmodel.h"

#include <QList>
#include <QMap>
#include <QString>

// A trust password has a clock of its own. The DC that holds the PDC emulator
// role changes an interdomain trust's password every 30 days (MS-ADTS 6.1.6.2),
// stores the new one as the trust's secret and tells the peer over the trust
// channel (MS-NRPC 3.5.4.4.6, NetrServerPasswordSet2 naming the interdomain
// account). This is the local half: which trusts are due, the password, and the
// attributes a rotation writes. Telling the peer needs a peer that answers; this
// tree does not open that channel yet, so a rotation here is the PDC-side change
// and the partner catches up when it next reads the secret.
namespace TrustPassword {

// 30 days, the interval Windows uses for an interdomain trust.
constexpr qint64 kLifetimeSeconds = 30 * 24 * 60 * 60;

struct Rotation {
    QString trustDn;
    QString accountDn; // the `X$` account Windows keeps beside the trust
    QString partner;   // trustPartner: the peer's DNS domain
    QString flatName;  // the trust's own name, for the line an operator reads
    qint64 ageSeconds = 0;
};

// Every trust whose secret is at least kLifetimeSeconds old. The clock is the
// trust account's pwdLastSet: that account carries the same password the channel
// authenticates with, and its pwdLastSet is the only instant this store keeps
// for a trust secret (the auth blob's own last_update_time is not stored). A
// trust with no incoming secret, or with no account to date it, is left alone
// rather than rotated on a guess.
QList<Rotation> due(const QList<DirectoryObject> &objects, qint64 nowSeconds);

// Thirty random characters. Printable, so an operator reading the store sees a
// password rather than a hex blob, and long enough that the NT one-way function
// is the only thing worth attacking.
QString generate();

// What a rotation writes onto the trustedDomain object: the new clear secret in
// both directions (a trust keeps one password, and the peer's copy is the same
// password) and the inter-realm keys derived from it.
QMap<QString, QString> rotationAttributes(const DirectoryObject &trust,
                                          const QString &realm, const QString &password);

} // namespace TrustPassword

#endif // MONARCHY_TRUSTPASSWORD_H
