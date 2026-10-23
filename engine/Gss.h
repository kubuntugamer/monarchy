// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GSS_H
#define GSS_H

#include <QByteArray>
#include <QString>

// The GSS-API pieces Kerberos-authenticated services share: the SPNEGO
// wrappers an LDAP or RPC bind arrives in, the RFC 4121 (CFX) and RFC 1964
// per-message tokens, and the DCE/RPC framing that carries those tokens around
// a stub (RFC 4121 §7.1, MS-RPCE §2.2.3).
//
// Every token here is built for the acceptor side of a context, which is what
// both the directory and the management endpoint are: the flags mark tokens as
// acceptor tokens and the key usages are the acceptor ones.
namespace Gss {

// The Kerberos V5 mechanism OID, 1.2.840.113554.1.2.2, as DER content octets.
extern const QByteArray kKrb5MechOid;

// The two octets every per-message token starts with: RFC 4121's CFX wrap and
// MIC identifiers, and RFC 1964's wrap identifier.
extern const QByteArray kCfxWrapTokenId;
extern const QByteArray kCfxMicTokenId;
extern const QByteArray kLegacyWrapTokenId;

// A GSS-SPNEGO token either carries the Kerberos OID directly (GSSAPI) or
// lists it among the negotiable mechanisms.
bool carriesKerberos(const QByteArray &token);

// NegTokenInit { mechTypes, ... , mechToken } -> the Kerberos AP-REQ inside.
QByteArray kerberosToken(const QByteArray &token);

// The mechToken of a NegTokenInit or NegTokenResp, given the token either bare
// (what a DCE/RPC bind carries) or inside the GSS-API envelope LDAP SASL uses.
QByteArray spnegoNegotiatedToken(const QByteArray &token);

// A bare NegTokenResp (RFC 4178 §4.2.2) as DCE/RPC carries it: the LDAP SASL
// exchange wraps it in a GSS-API envelope, the RPC bind does not.
QByteArray spnegoResponse(quint8 negState, const QString &mech, const QByteArray &token);

// NegTokenResp accepting the AP-REP, for a SPNEGO client that keeps its GSS
// state machine running after the bind.
QByteArray spnegoAcceptToken(const QByteArray &apRep);

// GSS-API token envelope: [APPLICATION 0] { OID, token id, body }.
QByteArray gssEnvelope(const QByteArray &body);
bool stripGssEnvelope(const QByteArray &token, QByteArray *inner);

// RFC 4121 §4.2.6.2 Wrap token. `conf` seals the payload, otherwise the token
// carries a checksum next to it. RC4 handles both through the RFC 1964 form.
QByteArray cfxWrapToken(const QByteArray &data, bool conf, quint64 seq, int etype,
                        const QByteArray &key);
bool cfxUnwrapToken(const QByteArray &token, QByteArray *data, int etype,
                    const QByteArray &key, quint64 *seq);

// RFC 1964 / RFC 4757 §7 token, the form an RC4-HMAC session uses.
QByteArray legacyWrapToken(const QByteArray &data, bool conf, quint64 seq,
                           const QByteArray &key);
bool legacyUnwrapToken(const QByteArray &body, QByteArray *data, const QByteArray &key,
                       quint64 *seq);

// ---------- DCE/RPC framing ----------
//
// DCE/RPC keeps the stub in place and moves the rest of the GSS token into the
// auth verifier that follows it: the verifier holds the token header, the
// encrypted padding and header copy, the checksum and the encrypted
// confounder, while the stub carries the ciphered payload. Only the AES
// enctypes can arrive this way here; an RC4 service ticket is declined.
struct DceMessage {
    QByteArray payload;  // what replaces the stub on the wire
    QByteArray verifier; // the auth_value that follows the sec_trailer
};

// Seals `data`, which must already be padded to a 16-byte boundary (the caller
// reports that padding as auth_pad_length). The token is sent in DCE/RPC's
// split form: the verifier holds the header, the encrypted copy of it and the
// checksum, the stub holds the ciphertext of the data, and the token is rotated
// by RRC so the two put it back together (RFC 4121 §4.2.5, §7.1).
DceMessage dceSeal(const QByteArray &data, quint64 seq, int etype, const QByteArray &key);

// The reverse: `verifier` is the auth_value as received, `payload` the stub
// bytes in front of it. Fails on a bad checksum, a header mismatch or a
// non-CFX enctype.
bool dceUnseal(const QByteArray &verifier, const QByteArray &payload, int etype,
               const QByteArray &key, QByteArray *data, quint64 *seq);

// RFC 4121 §4.2.6.1 MIC token, what DCE/RPC carries at auth level 2
// (integrity without sealing).
QByteArray dceMic(const QByteArray &data, quint64 seq, int etype, const QByteArray &key);
bool checkDceMic(const QByteArray &token, const QByteArray &data, int etype,
                 const QByteArray &key, quint64 *seq);

} // namespace Gss

#endif // GSS_H
