// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef KRB5_H
#define KRB5_H

#include <QByteArray>
#include <QMap>
#include <QString>
#include <QStringList>

#include "resultsmodel.h"

// The Kerberos 5 encryption types AD uses for its accounts: RC4-HMAC
// (RFC 4757, keyed by the NT hash) and AES-128/256 with HMAC-SHA1-96
// (RFC 3961 §5, RFC 3962). Every account carries all three keys, so a client
// can pick the strongest type it supports.
namespace Krb5 {

constexpr int kAes128 = 17;
constexpr int kAes256 = 18;
constexpr int kRc4Hmac = 23;

constexpr int kRc4KeySize = 16;
// Clock skew accepted on pre-authentication timestamps and authenticators.
constexpr int kClockSkewSeconds = 300;
// PBKDF2 iterations AD and MIT use when the client is not told otherwise.
constexpr int kDefaultIterations = 4096;

// Key length for an encryption type, 0 when it is not supported here.
int keySize(int etype);
bool isSupportedEtype(int etype);
QByteArray randomKey(int etype = kRc4Hmac);

QByteArray rc4(const QByteArray &key, const QByteArray &data);

// RFC 4757 §5. The output is checksum || confounder || ciphertext.
QByteArray encrypt(int usage, const QByteArray &key, const QByteArray &plaintext);
bool decrypt(int usage, const QByteArray &key, const QByteArray &ciphertext,
             QByteArray *plaintext);
// RFC 4757 §4, used for PAC signatures.
QByteArray checksum(int usage, const QByteArray &key, const QByteArray &data);

// The same three operations for any supported encryption type. RC4-HMAC is
// checksum-first; the AES types follow the RFC 3961 simplified profile
// (confounder || plaintext, CBC-CTS, then a truncated HMAC-SHA1).
QByteArray encrypt(int etype, int usage, const QByteArray &key, const QByteArray &plaintext);
bool decrypt(int etype, int usage, const QByteArray &key, const QByteArray &ciphertext,
             QByteArray *plaintext);
QByteArray checksum(int etype, int usage, const QByteArray &key, const QByteArray &data);

// PBKDF2 + DK, RFC 3962 §4. Returns an empty string for RC4-HMAC, whose key is
// the NT hash rather than a password-derived AES key.
QByteArray stringToKey(int etype, const QString &password, const QString &salt,
                       int iterations = kDefaultIterations);

struct Principal {
    QString name;   // canonical principal name, e.g. "krbtgt/CORP.EXAMPLE.COM"
    QString realm;
    QString dn;     // directory object that holds the keys
    QString salt;   // salt published to clients for this account
    QMap<int, QByteArray> keys; // etype -> long-term key
    quint32 kvno = 1;
    bool disabled = false;

    bool isValid() const { return !dn.isEmpty() && !keys.isEmpty(); }
    QByteArray keyFor(int etype) const { return keys.value(etype); }
    QList<int> etypes() const { return keys.keys(); }
    // Strongest encryption type both sides support, 0 when there is none.
    int chooseEtype(const QList<int> &requested) const;
};

QString canonicalRealm(const QString &realm);
// Salt AD publishes for a principal; RC4-HMAC ignores it, AES clients use it.
QString principalSalt(const QString &realm, const QString &principal);

// Resolves "user@REALM", "krbtgt/REALM@REALM" or "ldap/host@REALM" against the
// directory. Service principals are matched against servicePrincipalName.
bool findPrincipal(const QList<DirectoryObject> &objects, const QString &principal,
                   const QString &realm, Principal *out);

// Every SPN of an object, in the order stored.
QStringList servicePrincipalNames(const DirectoryObject &object);

// The inter-realm key a trust gives us for `peerRealm`. AD keeps it on the
// trust object in CN=System, whose servicePrincipalName is krbtgt/<PEER>; both
// DCs of the trust hold the same secret, so a ticket one seals the other opens.
// This is deliberately separate from findPrincipal(), which resolves
// krbtgt/<realm> to the domain's own krbtgt account.
bool findTrustPrincipal(const QList<DirectoryObject> &objects, const QString &peerRealm,
                        const QString &realm, Principal *out);

// Stores the AES long-term keys derived from a password the same way AD does
// (PBKDF2 with the principal salt), alongside the NT hash. The values are
// private attributes and are never returned by a search.
void storePasswordKeys(DirectoryObject &object, const QString &password,
                       const QString &realm, const QString &accountName);

// Random AES keys for accounts whose password nobody knows (krbtgt, the DC
// machine account), matching how AD stores an unknown machine password.
void storeRandomKeys(DirectoryObject &object);

// Keys for an inter-realm trust account (krbtgt/<PEER>). Both domains must end
// up with the same bytes from the shared trust password, so the salt is the two
// realm names in lexical order — each side can compute it, and neither side's
// realm comes first by accident. Also stores the RC4 key, which is how a
// Windows 2000 trust actually talks.
void storeTrustKeys(DirectoryObject &object, const QString &password,
                    const QString &localRealm, const QString &peerRealm);

} // namespace Krb5

#endif // KRB5_H
