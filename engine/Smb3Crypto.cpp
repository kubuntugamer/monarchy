// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Smb3Crypto.h"

#include "Aes.h"

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

namespace {

// One left shift of a 128-bit big-endian block, for the CMAC subkey doubling.
QByteArray shiftLeftOne(const QByteArray &block)
{
    QByteArray out = block;
    const int n = out.size();
    bool carry = false;
    for (int i = n - 1; i >= 0; --i) {
        const quint8 value = quint8(out.at(i));
        out[i] = char(quint8((value << 1) | (carry ? 1 : 0)));
        carry = (value & 0x80) != 0;
    }
    return out;
}

// Doubling in GF(2^128) with x^128 + x^7 + x^2 + x + 1, the CMAC subkey step.
QByteArray doubleSubkey(const QByteArray &subkey)
{
    const bool reduce = (quint8(subkey.at(0)) & 0x80) != 0;
    QByteArray out = shiftLeftOne(subkey);
    if (reduce)
        out[out.size() - 1] = char(quint8(out.at(out.size() - 1)) ^ 0x87);
    return out;
}

QByteArray xorBlocks(const QByteArray &a, const QByteArray &b)
{
    QByteArray out = a;
    for (int i = 0; i < out.size() && i < b.size(); ++i)
        out[i] = char(quint8(out.at(i)) ^ quint8(b.at(i)));
    return out;
}

} // namespace

namespace Smb3 {

QByteArray kdf(const QByteArray &key, const QByteArray &label, const QByteArray &context,
               int length)
{
    // K(i) = HMAC-SHA256(key, [i]_32 BE || label || 0x00 || context || [L]_32 BE)
    QByteArray out;
    const int blocks = (length + 31) / 32;
    for (int i = 1; i <= blocks; ++i) {
        QByteArray input;
        input.append(char((i >> 24) & 0xff));
        input.append(char((i >> 16) & 0xff));
        input.append(char((i >> 8) & 0xff));
        input.append(char(i & 0xff));
        // `label` arrives null-terminated and the KDF puts its own separator
        // after it, so the hashed prefix carries both terminators — measured
        // against Samba's client, which derives with gnutls' SP800-108 exactly
        // this way (MS-SMB2 3.1.4.2 writes only one).
        input.append(label);
        input.append('\0');
        input.append(context);
        const quint32 bits = quint32(length * 8);
        input.append(char((bits >> 24) & 0xff));
        input.append(char((bits >> 16) & 0xff));
        input.append(char((bits >> 8) & 0xff));
        input.append(char(bits & 0xff));
        QMessageAuthenticationCode hmac(QCryptographicHash::Sha256, key);
        hmac.addData(input);
        out.append(hmac.result());
    }
    return out.left(length);
}

QByteArray cmac(const QByteArray &key, const QByteArray &data)
{
    // L = E(K, 0^128), K1 = dbl(L), K2 = dbl(K1); a final block that is not a
    // whole block is padded with 0x80 and XORed with K2, one that is is XORed
    // with K1.
    const QByteArray zero(16, '\0');
    const QByteArray k1 = doubleSubkey(Aes::encryptBlock(key, zero));
    const QByteArray k2 = doubleSubkey(k1);

    const bool whole = !data.isEmpty() && (data.size() % 16) == 0;
    QByteArray padded = data;
    if (!whole) {
        padded.append(char(0x80));
        while (padded.size() % 16)
            padded.append('\0');
    }
    QByteArray last = padded.right(16);
    last = xorBlocks(last, whole ? k1 : k2);
    padded.chop(16);

    QByteArray state = zero;
    for (int offset = 0; offset < padded.size(); offset += 16)
        state = Aes::encryptBlock(key, xorBlocks(state, padded.mid(offset, 16)));
    return Aes::encryptBlock(key, xorBlocks(state, last));
}

QByteArray preauthUpdate(const QByteArray &previous, const QByteArray &message)
{
    // The signature field of a message entering the chain is zero, and the
    // chain starts at 64 zero bytes rather than at empty input.
    QCryptographicHash hash(QCryptographicHash::Sha512);
    hash.addData(previous.isEmpty() ? QByteArray(64, '\0') : previous);
    hash.addData(message);
    return hash.result();
}

QByteArray signingKey(const QByteArray &sessionKey, quint16 dialect,
                      const QByteArray &preauthHash)
{
    if (dialect < 0x0300)
        return sessionKey;
    const QByteArray terminator(1, '\0');
    if (dialect >= 0x0311) {
        if (preauthHash.isEmpty())
            return QByteArray();
        return kdf(sessionKey, QByteArrayLiteral("SMBSigningKey") + terminator, preauthHash, 16);
    }
    // 3.0.2 expands the session key with the constant context "SmbSign", and
    // both the label and that context are null-terminated on the wire.
    return kdf(sessionKey, QByteArrayLiteral("SMB2AESCMAC") + terminator,
               QByteArrayLiteral("SmbSign") + terminator, 16);
}

} // namespace Smb3
