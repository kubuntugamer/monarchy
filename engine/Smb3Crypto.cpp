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

// The 16-byte block CCM works in: the flags byte, the nonce, then a value in as
// many bytes as the nonce leaves over (L = 15 - nonce length).
QByteArray ccmBlock(const QByteArray &nonce, quint8 flags, quint64 value)
{
    QByteArray block;
    block.append(char(flags));
    block.append(nonce);
    const int length = 15 - nonce.size();
    for (int i = length - 1; i >= 0; --i)
        block.append(char(quint8((value >> (8 * i)) & 0xff)));
    return block;
}

// The CBC-MAC over the associated data and the message, unpadded at the end the
// way B0's own length field already describes it. The caller XORs S_0 in.
QByteArray ccmMac(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                  const QByteArray &data, int tagLength)
{
    const int length = 15 - nonce.size();
    const quint8 flags = quint8((aad.isEmpty() ? 0x00 : 0x40)
                                | quint8(((tagLength - 2) / 2) << 3) | quint8(length - 1));
    QByteArray state = Aes::encryptBlock(key, ccmBlock(nonce, flags, quint64(data.size())));
    if (!aad.isEmpty()) {
        // A length below 0xFF00 is encoded in two bytes; nothing SMB seals comes
        // near the longer encodings.
        QByteArray buffer;
        buffer.append(char(quint8((aad.size() >> 8) & 0xff)));
        buffer.append(char(quint8(aad.size() & 0xff)));
        buffer.append(aad);
        while (buffer.size() % 16)
            buffer.append('\0');
        for (int offset = 0; offset < buffer.size(); offset += 16)
            state = Aes::encryptBlock(key, xorBlocks(state, buffer.mid(offset, 16)));
    }
    QByteArray padded = data;
    while (padded.size() % 16)
        padded.append('\0');
    for (int offset = 0; offset < padded.size(); offset += 16)
        state = Aes::encryptBlock(key, xorBlocks(state, padded.mid(offset, 16)));
    return state;
}

// Counter-mode keystream from block `first` on: S_i = E(K, A_i), and A_i differs
// from B0 only in its flag byte and its counter.
QByteArray ccmXor(const QByteArray &key, const QByteArray &nonce, const QByteArray &data,
                  quint64 first)
{
    QByteArray out = data;
    quint64 counter = first;
    for (int offset = 0; offset < data.size(); offset += 16) {
        const QByteArray stream = Aes::encryptBlock(
            key, ccmBlock(nonce, quint8(15 - nonce.size() - 1), counter));
        const int n = qMin(16, int(data.size()) - offset);
        for (int i = 0; i < n; ++i)
            out[offset + i] = char(quint8(out.at(offset + i)) ^ quint8(stream.at(i)));
        ++counter;
    }
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

QByteArray ccmEncrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                      const QByteArray &plaintext, int tagLength)
{
    const QByteArray aesKey = key.left(16);
    const QByteArray ciphertext = ccmXor(aesKey, nonce, plaintext, 1);
    const QByteArray s0 = Aes::encryptBlock(aesKey, ccmBlock(nonce, quint8(15 - nonce.size() - 1), 0));
    QByteArray tag = xorBlocks(ccmMac(aesKey, nonce, aad, plaintext, tagLength), s0);
    return ciphertext + tag.left(tagLength);
}

QByteArray ccmDecrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                      const QByteArray &sealed, int tagLength)
{
    if (sealed.size() < tagLength)
        return QByteArray();
    const QByteArray ciphertext = sealed.left(sealed.size() - tagLength);
    const QByteArray tag = sealed.right(tagLength);
    const QByteArray aesKey = key.left(16);
    // CCM authenticates the message before it encrypts it, so the tag covers the
    // plaintext that comes back out of the counter-mode step, not the ciphertext
    // that arrived.
    const QByteArray plaintext = ccmXor(aesKey, nonce, ciphertext, 1);
    const QByteArray s0 = Aes::encryptBlock(aesKey, ccmBlock(nonce, quint8(15 - nonce.size() - 1), 0));
    const QByteArray expected =
        xorBlocks(ccmMac(aesKey, nonce, aad, plaintext, tagLength), s0).left(tagLength);
    if (expected != tag)
        return QByteArray();
    return plaintext;
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

void encryptionKeys(const QByteArray &sessionKey, quint16 dialect, const QByteArray &preauthHash,
                    QByteArray *out, QByteArray *in)
{
    out->clear();
    in->clear();
    if (dialect < 0x0300 || sessionKey.isEmpty())
        return;
    const QByteArray terminator(1, '\0');
    if (dialect >= 0x0311) {
        // 3.1.1 binds each direction's key to the preauth hash with its own
        // label — client to server and server to client are different keys.
        if (preauthHash.isEmpty())
            return;
        *out = kdf(sessionKey, QByteArrayLiteral("SMBS2CCipherKey") + terminator, preauthHash, 16);
        *in = kdf(sessionKey, QByteArrayLiteral("SMBC2SCipherKey") + terminator, preauthHash, 16);
        return;
    }
    // 3.0.x keeps the session key's two directions apart by constant, and both
    // constants are nine bytes: "ServerIn" padded with a space, "ServerOut"
    // already that long. An extra space on the outbound one derives a key Samba
    // rejects with DECRYPTION_FAILED the moment it reads the first sealed reply.
    *out = kdf(sessionKey, QByteArrayLiteral("SMB2AESCCM") + terminator,
               QByteArrayLiteral("ServerOut") + terminator, 16);
    *in = kdf(sessionKey, QByteArrayLiteral("SMB2AESCCM") + terminator,
              QByteArrayLiteral("ServerIn ") + terminator, 16);
}

} // namespace Smb3
