// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DES_H
#define DES_H

#include <QByteArray>

// DES (FIPS 46-3) as AD still uses it in two places: the LM/NT one-way
// functions and the SAMR password-hash encoding (MS-SAMR 2.2.11.1), which
// enciphers an OWF hash under the RPC session key with two DES keys.
namespace Des {

// One 8-byte block under an 8-byte key. The key's parity bits are ignored, so a
// key built by keyFromPassword() behaves as the FIPS specification requires.
QByteArray encryptBlock(const QByteArray &key, const QByteArray &block);
QByteArray decryptBlock(const QByteArray &key, const QByteArray &block);

// The key schedule AD applies to seven key bytes: each output byte is shifted
// up one place so the parity bit is clear and the seven input bytes' bits fill
// the 56 effective key bits (MS-SAMR 5.1.3, Samba's str_to_key).
QByteArray keyFromPassword(const QByteArray &sevenBytes);

// MS-SAMR 2.2.11.1: a 16-byte OWF hash, split into two blocks, each enciphered
// under a DES key taken from seven bytes of the session key at offset 0 and 7.
QByteArray encryptOwfHash(const QByteArray &hash, const QByteArray &sessionKey);
QByteArray decryptOwfHash(const QByteArray &hash, const QByteArray &sessionKey);

} // namespace Des

#endif // DES_H
