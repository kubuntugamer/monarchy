// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef AES_H
#define AES_H

#include <QByteArray>

// AES-128 / AES-256, CBC with ciphertext stealing (RFC 3962 §5) and the
// HMAC-SHA1 / PBKDF2 / n-fold primitives the Kerberos aes128-cts-hmac-sha1-96
// and aes256-cts-hmac-sha1-96 encryption types are built from (FIPS-197,
// RFC 3961 §5.1, RFC 3962 §4).
namespace Aes {

// One 16-byte block, under a 16- or 32-byte key.
QByteArray encryptBlock(const QByteArray &key, const QByteArray &block);
QByteArray decryptBlock(const QByteArray &key, const QByteArray &block);

// CBC-CTS with an all-zero initial vector, as the Kerberos profile uses it.
// The output has exactly the length of the input; a single block is plain ECB.
QByteArray ctsEncrypt(const QByteArray &key, const QByteArray &data);
QByteArray ctsDecrypt(const QByteArray &key, const QByteArray &data);

QByteArray hmacSha1(const QByteArray &key, const QByteArray &data);

// PKCS #5 v2 PBKDF2 with HMAC-SHA1 as the pseudorandom function.
QByteArray pbkdf2Sha1(const QByteArray &password, const QByteArray &salt,
                      int iterations, int keyLength);

// RFC 3961 n-fold: stretches `input` to `outLength` bytes with 1's-complement
// addition, which is how a short key-usage constant is expanded to a block.
QByteArray nfold(const QByteArray &input, int outLength);

} // namespace Aes

#endif // AES_H
