// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SMB3CRYPTO_H
#define SMB3CRYPTO_H

#include <QByteArray>

// The primitives SMB 3.x adds to what 2.1 signs with (MS-SMB2 §3.1.4.2,
// SP800-108, RFC 4493): the counter-mode KDF the session key is expanded with,
// AES-CMAC, which is what a 3.x session signs with instead of HMAC-SHA256, and
// the SHA-512 preauth-integrity chain that feeds the 3.1.1 key derivation.
namespace Smb3 {

// SP800-108 KDF in counter mode with HMAC-SHA256 as the PRF. `label` is the
// null-terminated ASCII label without its terminator, `context` the fixed
// input — the dialect's string constant in 3.0.2, the preauth hash in 3.1.1.
QByteArray kdf(const QByteArray &key, const QByteArray &label, const QByteArray &context,
               int length);

// AES-CMAC (RFC 4493) over `data`, under a 16- or 32-byte key.
QByteArray cmac(const QByteArray &key, const QByteArray &data);

// AES-CCM (RFC 3610) as SMB 3.x carries it: the associated data is the 52-byte
// transform header with its signature zeroed, the nonce is 12 bytes and the tag
// is the whole 16-byte block. `tagLength` is a parameter so the RFC's own
// vectors, which use an 8-byte tag and a 13-byte nonce, pin this down.
QByteArray ccmEncrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                      const QByteArray &plaintext, int tagLength = 16);
// The plaintext and its tag are returned together by ccmEncrypt; this takes them
// the same way and returns empty when the tag does not verify.
QByteArray ccmDecrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad,
                      const QByteArray &sealed, int tagLength = 16);

// The SMB 3.1.1 preauth-integrity hash: SHA-512 over the running value and the
// message, signature field zeroed. `previous` is empty for the first message,
// which is the negotiate request.
QByteArray preauthUpdate(const QByteArray &previous, const QByteArray &message);

// The signing keys a session derives from its session key (MS-SMB2 §3.2.5.3.1).
// 3.0.2 has no preauth hash, so its context is the constant "SmbSign"; 3.1.1
// binds the key to everything that was negotiated before it.
QByteArray signingKey(const QByteArray &sessionKey, quint16 dialect,
                      const QByteArray &preauthHash);

// The encryption keys a 3.x session derives from its session key (MS-SMB2
// 3.2.5.3.1): `out` seals what the server sends, `in` opens what it receives.
// Each direction has its own key — 3.0.x by the nine-byte constants "ServerOut"
// and "ServerIn ", 3.1.1 by "SMBS2CCipherKey" and "SMBC2SCipherKey" over the
// preauth hash. Both are empty when the dialect carries no encryption.
void encryptionKeys(const QByteArray &sessionKey, quint16 dialect, const QByteArray &preauthHash,
                    QByteArray *out, QByteArray *in);

} // namespace Smb3

#endif // SMB3CRYPTO_H
