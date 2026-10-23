// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Krb5.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QStringList>

#include "Aes.h"
#include "Ntlm.h"

namespace {

void appendBe32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void appendLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

QByteArray md5(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Md5);
}

// RFC 3961 §5.1: DK(base, constant), the derived key for one usage. The
// constant is n-folded to a block, encrypted under the base key and, when the
// key is longer than a block, fed back for the remaining bytes.
QByteArray deriveKey(const QByteArray &base, const QByteArray &constant, int size)
{
    const QByteArray block = Aes::encryptBlock(base, Aes::nfold(constant, 16));
    if (block.isEmpty())
        return {};
    QByteArray out = block;
    while (out.size() < size) {
        const QByteArray next = Aes::encryptBlock(base, out.right(16));
        if (next.isEmpty())
            return {};
        out.append(next);
    }
    return out.left(size);
}

// Kc/Ke/Ki constants: usage (big-endian) plus 0x99, 0xAA and 0x55 (RFC 3961 §5.3).
QByteArray usageConstant(int usage, char kind)
{
    QByteArray out;
    appendBe32(out, quint32(usage));
    out.append(kind);
    return out;
}

QByteArray aesEncrypt(int usage, const QByteArray &key, const QByteArray &plaintext)
{
    if (key.size() != 16 && key.size() != 32)
        return {};
    const QByteArray ke = deriveKey(key, usageConstant(usage, 0xAA), key.size());
    const QByteArray ki = deriveKey(key, usageConstant(usage, 0x55), key.size());
    QByteArray confounder;
    while (confounder.size() < 16) {
        const quint64 value = QRandomGenerator::system()->generate64();
        for (int i = 0; i < 8 && confounder.size() < 16; ++i)
            confounder.append(char((value >> (8 * i)) & 0xff));
    }
    const QByteArray clear = confounder + plaintext;
    const QByteArray cipher = Aes::ctsEncrypt(ke, clear);
    if (cipher.isEmpty())
        return {};
    return cipher + Aes::hmacSha1(ki, clear).left(12);
}

bool aesDecrypt(int usage, const QByteArray &key, const QByteArray &ciphertext,
                QByteArray *plaintext)
{
    if ((key.size() != 16 && key.size() != 32) || ciphertext.size() < 16 + 12)
        return false;
    const QByteArray ke = deriveKey(key, usageConstant(usage, 0xAA), key.size());
    const QByteArray ki = deriveKey(key, usageConstant(usage, 0x55), key.size());
    const QByteArray cipher = ciphertext.left(ciphertext.size() - 12);
    const QByteArray mac = ciphertext.right(12);
    const QByteArray clear = Aes::ctsDecrypt(ke, cipher);
    if (clear.size() != cipher.size())
        return false;
    if (!Ntlm::secureEquals(Aes::hmacSha1(ki, clear).left(12), mac))
        return false;
    if (plaintext)
        *plaintext = clear.mid(16);
    return true;
}

QByteArray aesChecksum(int usage, const QByteArray &key, const QByteArray &data)
{
    if (key.size() != 16 && key.size() != 32)
        return {};
    const QByteArray kc = deriveKey(key, usageConstant(usage, 0x99), key.size());
    return Aes::hmacSha1(kc, data).left(12);
}

} // namespace

namespace Krb5 {

int keySize(int etype)
{
    switch (etype) {
    case kAes256:
        return 32;
    case kAes128:
    case kRc4Hmac:
        return 16;
    default:
        return 0;
    }
}

bool isSupportedEtype(int etype)
{
    return keySize(etype) > 0;
}

QByteArray randomKey(int etype)
{
    const int size = keySize(etype);
    if (size == 0)
        return {};
    QByteArray key;
    key.reserve(size);
    while (key.size() < size) {
        const quint64 value = QRandomGenerator::system()->generate64();
        for (int i = 0; i < 8 && key.size() < size; ++i)
            key.append(char((value >> (8 * i)) & 0xff));
    }
    return key;
}

QByteArray rc4(const QByteArray &key, const QByteArray &data)
{
    if (key.isEmpty())
        return {};
    unsigned char state[256];
    for (int i = 0; i < 256; ++i)
        state[i] = static_cast<unsigned char>(i);

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + state[i] + static_cast<unsigned char>(key.at(i % key.size()))) & 0xff;
        std::swap(state[i], state[j]);
    }

    QByteArray out;
    out.resize(data.size());
    int i = 0;
    j = 0;
    for (int n = 0; n < data.size(); ++n) {
        i = (i + 1) & 0xff;
        j = (j + state[i]) & 0xff;
        std::swap(state[i], state[j]);
        const unsigned char octet =
            static_cast<unsigned char>(data.at(n))
            ^ state[(state[i] + state[j]) & 0xff];
        out[n] = char(octet);
    }
    return out;
}

QByteArray encrypt(int usage, const QByteArray &key, const QByteArray &plaintext)
{
    if (key.size() != kRc4KeySize)
        return {};
    // K1 = HMAC(K, T); K2 = K1; K3 = HMAC(K1, checksum)
    QByteArray octets;
    appendLe32(octets, quint32(usage));
    const QByteArray k1 = Ntlm::hmacMd5(key, octets);

    QByteArray confounder;
    while (confounder.size() < 8) {
        const quint64 value = QRandomGenerator::system()->generate64();
        for (int i = 0; i < 8 && confounder.size() < 8; ++i)
            confounder.append(char((value >> (8 * i)) & 0xff));
    }

    const QByteArray checksum = Ntlm::hmacMd5(k1, confounder + plaintext);
    const QByteArray k3 = Ntlm::hmacMd5(k1, checksum);
    // One RC4 keystream spans confounder and data.
    const QByteArray keystream = rc4(k3, confounder + plaintext);

    QByteArray out = checksum;
    out.append(keystream);
    return out;
}

bool decrypt(int usage, const QByteArray &key, const QByteArray &ciphertext,
             QByteArray *plaintext)
{
    if (key.size() != kRc4KeySize || ciphertext.size() < 24)
        return false;
    const QByteArray checksum = ciphertext.left(16);
    const QByteArray body = ciphertext.mid(16);

    QByteArray octets;
    appendLe32(octets, quint32(usage));
    const QByteArray k1 = Ntlm::hmacMd5(key, octets);
    const QByteArray k3 = Ntlm::hmacMd5(k1, checksum);
    const QByteArray clear = rc4(k3, body);
    const QByteArray expected = Ntlm::hmacMd5(k1, clear);
    if (!Ntlm::secureEquals(expected, checksum))
        return false;
    if (plaintext)
        *plaintext = clear.mid(8); // strip the confounder
    return true;
}

QByteArray checksum(int usage, const QByteArray &key, const QByteArray &data)
{
    if (key.size() != kRc4KeySize)
        return {};
    QByteArray signatureKey(QByteArrayLiteral("signaturekey"));
    signatureKey.append('\0');
    const QByteArray ksign = Ntlm::hmacMd5(key, signatureKey);
    QByteArray material;
    appendLe32(material, quint32(usage));
    material.append(data);
    return Ntlm::hmacMd5(ksign, md5(material));
}

QByteArray encrypt(int etype, int usage, const QByteArray &key, const QByteArray &plaintext)
{
    if (etype == kRc4Hmac)
        return encrypt(usage, key, plaintext);
    if (etype == kAes128 || etype == kAes256)
        return key.size() == keySize(etype) ? aesEncrypt(usage, key, plaintext) : QByteArray();
    return {};
}

bool decrypt(int etype, int usage, const QByteArray &key, const QByteArray &ciphertext,
             QByteArray *plaintext)
{
    if (etype == kRc4Hmac)
        return decrypt(usage, key, ciphertext, plaintext);
    if (etype == kAes128 || etype == kAes256)
        return key.size() == keySize(etype) && aesDecrypt(usage, key, ciphertext, plaintext);
    return false;
}

QByteArray checksum(int etype, int usage, const QByteArray &key, const QByteArray &data)
{
    if (etype == kRc4Hmac)
        return checksum(usage, key, data);
    if (etype == kAes128 || etype == kAes256)
        return key.size() == keySize(etype) ? aesChecksum(usage, key, data) : QByteArray();
    return {};
}

QByteArray stringToKey(int etype, const QString &password, const QString &salt,
                       int iterations)
{
    const int size = keySize(etype);
    if ((etype != kAes128 && etype != kAes256) || size == 0)
        return {};
    const QByteArray tkey =
        Aes::pbkdf2Sha1(password.toUtf8(), salt.toUtf8(), iterations, size);
    return deriveKey(tkey, QByteArrayLiteral("kerberos"), size);
}

int Principal::chooseEtype(const QList<int> &requested) const
{
    for (const int candidate : {kAes256, kAes128, kRc4Hmac}) {
        if (!requested.contains(candidate))
            continue;
        if (keys.value(candidate).size() == keySize(candidate))
            return candidate;
    }
    return 0;
}

QString canonicalRealm(const QString &realm)
{
    return realm.trimmed().toUpper();
}

QString principalSalt(const QString &realm, const QString &principal)
{
    const QString canonical = canonicalRealm(realm);
    QString name = principal;
    const int at = name.lastIndexOf(QLatin1Char('@'));
    if (at >= 0)
        name = name.left(at);
    // AD splits the krbtgt salt around the account name, so a keytab exported
    // from a Windows DC matches one derived here.
    if (name.compare(QStringLiteral("krbtgt/%1").arg(canonical), Qt::CaseInsensitive) == 0)
        return canonical + QStringLiteral("krbtgt") + canonical;
    return canonical + name;
}

QStringList servicePrincipalNames(const DirectoryObject &object)
{
    QStringList names;
    const QString stored = object.attributes.value(QStringLiteral("servicePrincipalName"));
    if (stored.isEmpty())
        return names;
    const QStringList parts = stored.split(QLatin1Char(';'));
    for (const QString &part : parts) {
        const QString value = part.trimmed();
        if (!value.isEmpty())
            names.append(value);
    }
    return names;
}

namespace {

// Fills the etype -> key map of `out` from an object's private key attributes.
bool readKeys(const DirectoryObject &object, QMap<int, QByteArray> *keys)
{
    const QByteArray ntHash =
        QByteArray::fromHex(object.attributes.value(QStringLiteral("ntHash")).toLatin1());
    const QByteArray aes128 =
        QByteArray::fromHex(object.attributes.value(QStringLiteral("aes128Key")).toLatin1());
    const QByteArray aes256 =
        QByteArray::fromHex(object.attributes.value(QStringLiteral("aes256Key")).toLatin1());
    if (ntHash.size() == keySize(kRc4Hmac))
        keys->insert(kRc4Hmac, ntHash);
    if (aes128.size() == keySize(kAes128))
        keys->insert(kAes128, aes128);
    if (aes256.size() == keySize(kAes256))
        keys->insert(kAes256, aes256);
    return !keys->isEmpty();
}

} // namespace

bool findPrincipal(const QList<DirectoryObject> &objects, const QString &principal,
                   const QString &realm, Principal *out)
{
    QString name = principal.trimmed();
    QString principalRealm;
    const int at = name.lastIndexOf(QLatin1Char('@'));
    if (at >= 0) {
        principalRealm = name.mid(at + 1);
        name = name.left(at);
    }
    if (name.isEmpty())
        return false;
    const QString wantedRealm = canonicalRealm(realm);
    if (!principalRealm.isEmpty() && canonicalRealm(principalRealm) != wantedRealm)
        return false;

    const QString service = name.section(QLatin1Char('/'), 0, 0);
    const bool isServicePrincipal = name.contains(QLatin1Char('/'));

    for (const DirectoryObject &object : objects) {
        if (object.id.isEmpty())
            continue;
        QMap<int, QByteArray> keys;
        if (!readKeys(object, &keys))
            continue;

        QString canonical;
        bool match = false;
        if (isServicePrincipal) {
            // The krbtgt account has no SPN; its principal is derived from the
            // account name and the realm.
            if (service.compare(QLatin1String("krbtgt"), Qt::CaseInsensitive) == 0) {
                // krbtgt/<realm> is this domain's own TGT principal only when
                // the realm named is ours. krbtgt/<other realm> is an
                // inter-realm principal, whose key belongs to a trust and not
                // to the krbtgt account.
                const QString target = canonicalRealm(name.mid(7));
                if (!target.isEmpty() && target != wantedRealm)
                    return false;
                const QString account =
                    object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.compare(QLatin1String("krbtgt"), Qt::CaseInsensitive) != 0)
                    continue;
                if (out) {
                    out->name = QStringLiteral("krbtgt/%1").arg(wantedRealm);
                    out->realm = wantedRealm;
                    out->dn = object.id;
                    out->keys = keys;
                    out->salt = object.attributes.value(QStringLiteral("kerberosSalt"));
                    if (out->salt.isEmpty())
                        out->salt = principalSalt(wantedRealm, out->name);
                    out->kvno = object.attributes.value(
                                    QStringLiteral("msDS-KeyVersionNumber")).toUInt();
                    if (out->kvno == 0)
                        out->kvno = 1;
                }
                return true;
            }
            for (const QString &spn : servicePrincipalNames(object)) {
                if (spn.compare(name, Qt::CaseInsensitive) == 0) {
                    canonical = spn;
                    match = true;
                    break;
                }
            }
            if (!match)
                continue;
        } else {
            const QString account =
                object.attributes.value(QStringLiteral("sAMAccountName"));
            const QString upn = object.attributes.value(QStringLiteral("userPrincipalName"));
            const QString upnName = upn.contains(QLatin1Char('@'))
                                        ? upn.section(QLatin1Char('@'), 0, 0)
                                        : upn;
            if (account.compare(name, Qt::CaseInsensitive) == 0
                || (!upnName.isEmpty() && upnName.compare(name, Qt::CaseInsensitive) == 0)
                || object.name.compare(name, Qt::CaseInsensitive) == 0) {
                canonical = account.isEmpty() ? name : account;
                match = true;
            }
            if (!match)
                continue;
        }

        if (out) {
            out->name = canonical;
            out->realm = wantedRealm;
            out->dn = object.id;
            out->keys = keys;
            out->salt = object.attributes.value(QStringLiteral("kerberosSalt"));
            if (out->salt.isEmpty())
                out->salt = principalSalt(wantedRealm, canonical);
            out->kvno = object.attributes.value(QStringLiteral("msDS-KeyVersionNumber"))
                            .toUInt();
            if (out->kvno == 0)
                out->kvno = 1;
            const quint32 uac =
                object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
            out->disabled = (uac & 0x2u) != 0;
        }
        return true;
    }
    return false;
}

bool findTrustPrincipal(const QList<DirectoryObject> &objects, const QString &peerRealm,
                        const QString &realm, Principal *out)
{
    const QString peer = canonicalRealm(peerRealm);
    const QString local = canonicalRealm(realm);
    if (peer.isEmpty() || local.isEmpty() || peer == local)
        return false;

    for (const DirectoryObject &object : objects) {
        if (object.id.isEmpty())
            continue;
        const QString partner = canonicalRealm(
            object.attributes.value(QStringLiteral("trustPartner")));
        if (partner != peer)
            continue;
        QMap<int, QByteArray> keys;
        if (!readKeys(object, &keys))
            continue;
        if (out) {
            out->name = QStringLiteral("krbtgt/%1").arg(peer);
            out->realm = local;
            out->dn = object.id;
            out->keys = keys;
            out->salt = object.attributes.value(QStringLiteral("kerberosSalt"));
            if (out->salt.isEmpty())
                out->salt = principalSalt(local, out->name);
            out->kvno = object.attributes.value(QStringLiteral("msDS-KeyVersionNumber")).toUInt();
            if (out->kvno == 0)
                out->kvno = 1;
            const quint32 direction =
                object.attributes.value(QStringLiteral("trustDirection")).toUInt();
            out->disabled = direction == 0;
        }
        return true;
    }
    return false;
}

void storePasswordKeys(DirectoryObject &object, const QString &password,
                       const QString &realm, const QString &accountName)
{
    if (realm.isEmpty() || accountName.isEmpty())
        return;
    const QString salt = principalSalt(realm, accountName);
    const QByteArray aes128 = stringToKey(kAes128, password, salt);
    const QByteArray aes256 = stringToKey(kAes256, password, salt);
    if (aes128.isEmpty() || aes256.isEmpty())
        return;
    object.attributes.insert(QStringLiteral("kerberosSalt"), salt);
    object.attributes.insert(QStringLiteral("aes128Key"), QString::fromLatin1(aes128.toHex()));
    object.attributes.insert(QStringLiteral("aes256Key"), QString::fromLatin1(aes256.toHex()));
}

void storeTrustKeys(DirectoryObject &object, const QString &password,
                    const QString &localRealm, const QString &peerRealm)
{
    const QString local = canonicalRealm(localRealm);
    const QString peer = canonicalRealm(peerRealm);
    if (local.isEmpty() || peer.isEmpty() || local == peer || password.isEmpty())
        return;
    // Same input, same key on both sides of the trust: the salt is the two
    // realms sorted, which each domain computes identically.
    const QString salt = local < peer ? local + QLatin1Char('+') + peer
                                      : peer + QLatin1Char('+') + local;
    const QByteArray aes128 = stringToKey(kAes128, password, salt);
    const QByteArray aes256 = stringToKey(kAes256, password, salt);
    if (aes128.isEmpty() || aes256.isEmpty())
        return;
    object.attributes.insert(QStringLiteral("kerberosSalt"), salt);
    object.attributes.insert(QStringLiteral("aes128Key"), QString::fromLatin1(aes128.toHex()));
    object.attributes.insert(QStringLiteral("aes256Key"), QString::fromLatin1(aes256.toHex()));
    object.attributes.insert(QStringLiteral("ntHash"),
                             QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
}

void storeRandomKeys(DirectoryObject &object)
{
    object.attributes.insert(QStringLiteral("aes128Key"),
                             QString::fromLatin1(randomKey(kAes128).toHex()));
    object.attributes.insert(QStringLiteral("aes256Key"),
                             QString::fromLatin1(randomKey(kAes256).toHex()));
}

} // namespace Krb5
