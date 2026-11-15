// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SCHANNEL_H
#define SCHANNEL_H

#include <QByteArray>
#include <QString>

// The Netlogon security provider at the DCE/RPC layer (MS-NRPC 3.1.4.2, auth
// type 0x44): the bind carries an NL_AUTH_MESSAGE that names the domain and the
// computer, and every PDU after it an NL_AUTH_SIGNATURE sealed under the session
// key the secure channel established. That is what a client means when it takes
// up NETLOGON_NEG_AUTHENTICATED_RPC — the calls above are about the *channel*,
// this is about the pipe that carries them.
namespace Schannel {

// RPC_C_AUTHN_NETLOGON (MS-RPCE §2.2.3, MS-NRPC 2.2.1.3.1).
enum : quint8 { AuthType = 0x44 };

// NL_AUTH_MESSAGE.MessageType (MS-NRPC 2.2.1.3.1).
enum : quint32 {
    NegotiateRequest = 0,
    NegotiateResponse = 1
};

// NL_AUTH_MESSAGE_FLAGS: which strings the message carries.
enum : quint32 {
    FlagNetbiosDomain = 0x00000001u,
    FlagNetbiosComputer = 0x00000002u,
    FlagDnsDomain = 0x00000004u,
    FlagDnsHost = 0x00000008u,
    FlagUtf8Computer = 0x00000010u
};

// NETLOGON_NEG_SUPPORTS_AES: the signature is HMAC-SHA256 with an AES-128-CFB8
// sequence number and sealing, instead of the MD5/RC4 pair.
constexpr quint32 kSupportsAes = 0x01000000u;

// What the bind's NL_AUTH_MESSAGE said. `parsed` is false when the token is not
// one, and `computer` is empty when the message named no computer it could read
// (a message that carries only the UTF-8 names does not repeat the ASCII arm).
struct BindMessage {
    bool parsed = false;
    quint32 flags = 0;
    QString domain;
    QString computer;
};

BindMessage parseBind(const QByteArray &token);

// The NL_AUTH_MESSAGE a bind_ack answers with: type 1, no flags, and the
// placeholder `Buffer` every implementation sends.
QByteArray bindResponse();

bool usesAes(quint32 negotiateFlags);

// How many bytes the signature for these flags occupies on the wire (MS-NRPC
// 2.2.1.3.2 and 2.2.1.3.3, as Windows and Samba lay them out).
int signatureSize(quint32 negotiateFlags);

// Opens one signature: unseals `data` in place (the caller passes the bytes as
// they arrived, stub and padding) and returns false when the checksum or the
// sequence number does not match. `initiator` is whether the sender is the
// client, which is what sets the high bit of the sequence number.
bool open(quint32 negotiateFlags, const QByteArray &sessionKey, quint64 sequence,
          bool initiator, const QByteArray &signature, QByteArray *data);

// Builds the signature for `data`. With `seal` the ciphertext is written to
// `sealed` (and is what goes on the wire); without it `sealed` receives `data`.
QByteArray sign(quint32 negotiateFlags, const QByteArray &sessionKey, quint64 sequence,
                bool initiator, const QByteArray &data, bool seal, QByteArray *sealed);

} // namespace Schannel

#endif // SCHANNEL_H
