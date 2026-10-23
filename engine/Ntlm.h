// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NTLM_H
#define NTLM_H

#include <QByteArray>
#include <QString>

// NTLMSSP as used by AD for password-based authentication (MS-NLMP).
//
// The directory stores the same credential AD does: NTOWFv1, the MD4 hash of
// the UTF-16LE password. Authentication is NTLMv2 challenge/response, so the
// password itself never crosses the wire and no reversible secret is kept.
namespace Ntlm {

// NTOWFv1: MD4(UTF-16LE(password)), the AD "NT hash".
QByteArray ntowfV1(const QString &password);

// HMAC-MD5 (RFC 2104), the keyed hash NTLMv2 is built from.
QByteArray hmacMd5(const QByteArray &key, const QByteArray &data);

// Constant-time comparison for 16-byte proofs.
bool secureEquals(const QByteArray &left, const QByteArray &right);

struct Negotiate {
    quint32 flags = 0;
};

struct Authenticate {
    quint32 flags = 0;
    QString domain;
    QString user;
    QString workstation;
    QByteArray ntResponse;
};

// 1 = NEGOTIATE, 2 = CHALLENGE, 3 = AUTHENTICATE, 0 = not an NTLMSSP token.
int messageType(const QByteArray &token);

// Message parsing. Both return false when the token is not a well-formed
// NTLMSSP message of the expected type.
bool parseNegotiate(const QByteArray &token, Negotiate *out);
bool parseAuthenticate(const QByteArray &token, Authenticate *out);

// Builds the CHALLENGE payload: target name (the NetBIOS domain), the
// 8-byte server challenge and the target-info AV pairs.
QByteArray challengeToken(const QByteArray &serverChallenge, const QString &domain,
                          const QString &serverName, const QString &dnsDomain);
inline QByteArray challengeToken(const QByteArray &serverChallenge, const QString &domain,
                                 const QString &serverName)
{
    return challengeToken(serverChallenge, domain, serverName, QString());
}

// AV_PAIR list for CHALLENGE: NbDomainName (2), NbComputerName (1) and
// DNSComputerName (3) — always present, because a client that builds a
// service principal from the target info needs it (impacket computes
// "service/FQDN" for every NTLMv2 answer) — plus DNSDomainName (4) when a
// DNS domain is given.
QByteArray targetInfo(const QString &domain, const QString &serverName,
                      const QString &dnsDomain = QString());

// Locates an embedded NTLMSSP token (GSS-SPNEGO wraps it in ASN.1).
QByteArray embeddedToken(const QByteArray &token);

// Verifies an NTLMv2 NtChallengeResponse against the stored NT hash.
// ResponseKeyNT = HMAC_MD5(NTOWFv1, UTF-16LE(Uppercase(User) + Domain))
// NtProofStr    = HMAC_MD5(ResponseKeyNT, ServerChallenge + blob)[0..15]
bool verifyNtlmv2(const QByteArray &ntHash, const QString &user, const QString &domain,
                  const QByteArray &serverChallenge, const QByteArray &ntResponse);

// Negotiation flags this implementation acts on.
constexpr quint32 kNegotiateSign = 0x00000010u;
constexpr quint32 kNegotiateSeal = 0x00000020u;
constexpr quint32 kNegotiate128 = 0x20000000u;
constexpr quint32 kNegotiate56 = 0x80000000u;

// ---------- Session security (MS-NLMP §3.4) ----------
//
// What LDAP signing and sealing are built from: the session key that comes out
// of the NTLMv2 exchange, the per-direction signing and sealing keys derived
// from it, and the MAC/RC4 operations per-message tokens use.
struct SessionKeys {
    QByteArray sessionBaseKey;   // HMAC_MD5(ResponseKeyNT, NtProofStr)
    QByteArray clientSigningKey; // MD5(session key + client-to-server sign magic)
    QByteArray serverSigningKey;
    QByteArray clientSealingKey; // MD5(session key + client-to-server seal magic)
    QByteArray serverSealingKey;
};

// `ntProofStr` is the first 16 bytes of the NTLMv2 response. Returns false when
// the inputs are not the lengths MS-NLMP requires. `negotiateFlags` picks the
// session-key strength (§3.4.5.1): 128-bit when NEGOTIATE_128 is set, 56-bit
// or 40-bit otherwise. Without flags this derives the 128-bit keys, which is
// what an NTLMv2 exchange with extended session security always uses.
bool sessionKeys(const QByteArray &ntHash, const QString &user, const QString &domain,
                 const QByteArray &ntProofStr, SessionKeys *out, quint32 negotiateFlags);
inline bool sessionKeys(const QByteArray &ntHash, const QString &user, const QString &domain,
                        const QByteArray &ntProofStr, SessionKeys *out)
{
    return sessionKeys(ntHash, user, domain, ntProofStr, out, kNegotiate128);
}

// NTLMSSP MAC: HMAC_MD5(signingKey, LE32(sequence) || message)[0..7].
QByteArray mac(const QByteArray &signingKey, quint32 sequence, const QByteArray &message);

// RC4 whose keystream state survives across messages, which is what the
// extended-session-security sealing rules require.
class Sealer
{
public:
    explicit Sealer(const QByteArray &key = QByteArray());
    void reset(const QByteArray &key);
    QByteArray apply(const QByteArray &data);
    bool isValid() const { return m_valid; }

private:
    unsigned char m_state[256] = {};
    int m_i = 0;
    int m_j = 0;
    bool m_valid = false;
};

// MS-NLMP §3.4.5.1: the key every per-direction key is derived from. With
// 128-bit session security it is the session base key; otherwise it is that
// key truncated to 7 (56-bit) or 5 (40-bit) bytes and padded with 0xA0.
QByteArray exportedSessionKey(const QByteArray &sessionBaseKey, quint32 negotiateFlags);

// ---------- Per-message tokens (MS-NLMP §3.4.5.2) ----------
//
// A token is the 16-byte NTLMSSP_MESSAGE_SIGNATURE followed by the payload:
// flag(4) || checksum(8) || sequence(4), then the message. With sealing
// negotiated both the message and the checksum are RC4-ciphered, under a
// keystream that continues across every token of the session.
QByteArray signMessage(const QByteArray &signingKey, quint32 sequence,
                       const QByteArray &plaintext);
QByteArray sealMessage(const QByteArray &sealingKey, const QByteArray &signingKey,
                       Sealer *sealer, quint32 sequence, const QByteArray &plaintext);

// Reverses signMessage/sealMessage. `sealer` is null for an integrity-only
// token. The MAC is checked over the recovered plaintext, and the sequence
// number in the token must equal `sequence`.
bool unsealMessage(const QByteArray &sealingKey, const QByteArray &signingKey,
                   Sealer *sealer, quint32 sequence, const QByteArray &token,
                   QByteArray *plaintext);

QByteArray utf16le(const QString &text);

} // namespace Ntlm

#endif // NTLM_H
