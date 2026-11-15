// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Schannel.h"

#include "Aes.h"
#include "Krb5.h"
#include "Ntlm.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QMessageAuthenticationCode>

namespace {

// NL_SIGN_HMAC_MD5 / NL_SIGN_HMAC_SHA256 and NL_SEAL_RC4 / NL_SEAL_AES128 /
// NL_SEAL_NONE (MS-NRPC 2.2.1.3.2), as the four little-endian uint16 fields that
// begin an NL_AUTH_SIGNATURE.
constexpr quint16 kSignHmacMd5 = 0x0077;
constexpr quint16 kSignHmacSha256 = 0x0013;
constexpr quint16 kSealRc4 = 0x007A;
constexpr quint16 kSealAes128 = 0x001A;
constexpr quint16 kSealNone = 0xFFFF;

QByteArray header(quint32 negotiateFlags, bool seal)
{
    const bool aes = Schannel::usesAes(negotiateFlags);
    QByteArray out;
    const auto put = [&out](quint16 value) {
        out.append(char(value & 0xff));
        out.append(char((value >> 8) & 0xff));
    };
    put(aes ? kSignHmacSha256 : kSignHmacMd5);
    put(seal ? (aes ? kSealAes128 : kSealRc4) : kSealNone);
    put(0xFFFF); // Pad
    put(0x0000); // Flags
    return out;
}

// AES-128 in 8-bit CFB: encrypt one keystream byte per data byte, feeding the
// ciphertext back into the register (FIPS-197, SP 800-38A §6.3). The Kerberos
// CFX profile next door uses CBC-CTS because RFC 4121 seals whole blocks; here
// the stream is a different length every time.
QByteArray cfb8(const QByteArray &key, const QByteArray &iv, const QByteArray &data,
                bool forward)
{
    QByteArray out;
    QByteArray feedback = iv.left(16);
    out.reserve(data.size());
    for (const char ch : data) {
        const QByteArray stream = Aes::encryptBlock(key, feedback);
        const char outByte = char(quint8(ch) ^ quint8(stream.at(0)));
        out.append(outByte);
        // The register shifts in the byte that went on the wire: the output
        // when sealing, the input when opening (SP 800-38A §6.3).
        feedback = feedback.mid(1) + QByteArray(1, forward ? outByte : ch);
    }
    return out;
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    return QMessageAuthenticationCode::hash(data, key, QCryptographicHash::Sha256);
}

// The two uint32 halves of the sequence number, big-endian, with the high bit of
// the second set when the sender is the initiator (MS-NRPC 3.1.4.2.1).
QByteArray encodeSequence(quint64 sequence, bool initiator)
{
    quint32 low = quint32(sequence & 0xffffffffu);
    quint32 high = quint32(sequence >> 32);
    if (initiator)
        high |= 0x80000000u;
    QByteArray out;
    const auto put = [&out](quint32 value) {
        out.append(char((value >> 24) & 0xff));
        out.append(char((value >> 16) & 0xff));
        out.append(char((value >> 8) & 0xff));
        out.append(char(value & 0xff));
    };
    put(low);
    put(high);
    return out;
}

// The sequence number as it goes on the wire is not the counter: it is the
// counter ciphered with a key derived from the checksum, so a receiver cannot
// replay a PDU under a different checksum.
QByteArray transformSequence(quint32 negotiateFlags, const QByteArray &sessionKey,
                             const QByteArray &checksum, const QByteArray &sequence)
{
    if (Schannel::usesAes(negotiateFlags)) {
        const QByteArray iv = checksum.left(8) + checksum.left(8);
        return cfb8(sessionKey, iv, sequence, true);
    }
    const QByteArray digest = Ntlm::hmacMd5(sessionKey, QByteArray(4, '\0'));
    const QByteArray sequenceKey = Ntlm::hmacMd5(digest, checksum.left(8));
    return Krb5::rc4(sequenceKey, sequence);
}

// The checksum over the header, the confounder when the PDU is sealed, and the
// plaintext. Only its first eight octets are transmitted.
QByteArray checksum(quint32 negotiateFlags, const QByteArray &sessionKey, const QByteArray &headerBytes,
                    const QByteArray &confounder, const QByteArray &plain)
{
    QByteArray material;
    if (Schannel::usesAes(negotiateFlags)) {
        material = headerBytes + confounder + plain;
        return hmacSha256(sessionKey, material).left(8);
    }
    // The MD5 profile hashes a fixed zero word in front of the header
    // (MS-NRPC 3.1.4.2.1), then keys the digest with the session key.
    material = QByteArray(4, '\0') + headerBytes + confounder + plain;
    const QByteArray digest = QCryptographicHash::hash(material, QCryptographicHash::Md5);
    return Ntlm::hmacMd5(sessionKey, digest).left(8);
}

// Seals `data` in place: the confounder goes through the cipher first and the
// stream carries on into the data, so the two are one keystream.
QByteArray seal(quint32 negotiateFlags, const QByteArray &sessionKey, const QByteArray &sequence,
                const QByteArray &confounder, const QByteArray &data, bool forward)
{
    if (Schannel::usesAes(negotiateFlags)) {
        QByteArray key = sessionKey.left(16);
        for (int i = 0; i < key.size(); ++i)
            key[i] = char(quint8(key.at(i)) ^ 0xf0);
        const QByteArray iv = sequence + sequence;
        return cfb8(key, iv, confounder + data, forward);
    }
    const QByteArray digest = Ntlm::hmacMd5(sessionKey, QByteArray(4, '\0'));
    const QByteArray sealingKey = Ntlm::hmacMd5(digest, sequence);
    return Krb5::rc4(sealingKey, confounder + data);
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16) | (quint32(quint8(data.at(pos + 3))) << 24);
}

quint16 readLe16(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(pos)) | (quint8(data.at(pos + 1)) << 8));
}

// One string arm of the message: the characters and their terminator, in place,
// with no conformant-array header in front of them (MS-NRPC 2.2.1.3.1, and as
// the client writes them).
bool readMessageString(const QByteArray &token, int *pos, QString *out)
{
    const int start = *pos;
    int end = start;
    while (end < token.size() && token.at(end) != 0)
        ++end;
    if (end >= token.size() || end - start > 256)
        return false;
    for (int i = start; i < end; ++i) {
        if (token.at(i) < 0x20)
            return false;
    }
    *out = QString::fromLatin1(token.mid(start, end - start));
    *pos = end + 1;
    return true;
}

} // namespace

namespace Schannel {

bool usesAes(quint32 negotiateFlags)
{
    return (negotiateFlags & kSupportsAes) != 0;
}

int signatureSize(quint32 negotiateFlags)
{
    // Windows and Samba keep the 32-octet NL_AUTH_SIGNATURE layout for AES too,
    // with the SHA-256 checksum cut to eight octets and the trailing 24 octets
    // zero: MS-NRPC 2.2.1.3.3 describes a wider one, and a client that sent it
    // would be rejected here rather than silently accepted.
    return usesAes(negotiateFlags) ? 56 : 32;
}

BindMessage parseBind(const QByteArray &token)
{
    BindMessage message;
    if (token.size() < 8)
        return message;
    if (readLe32(token, 0) != NegotiateRequest)
        return message;
    message.parsed = true;
    message.flags = readLe32(token, 4);

    // The arms appear in the order the fields are declared, each present only
    // when its flag is set. Only the ASCII domain and computer name are read:
    // they are the names the channel is keyed by.
    int pos = 8;
    QString text;
    if (message.flags & FlagNetbiosDomain) {
        if (!readMessageString(token, &pos, &text))
            return message;
        message.domain = text;
    }
    if (message.flags & FlagNetbiosComputer) {
        if (!readMessageString(token, &pos, &text))
            return message;
        message.computer = text;
    }
    return message;
}

QByteArray bindResponse()
{
    QByteArray out;
    const auto put16 = [&out](quint16 value) {
        out.append(char(value & 0xff));
        out.append(char((value >> 8) & 0xff));
    };
    const auto put32 = [&out](quint32 value) {
        out.append(char(value & 0xff));
        out.append(char((value >> 8) & 0xff));
        out.append(char((value >> 16) & 0xff));
        out.append(char((value >> 24) & 0xff));
    };
    put16(NegotiateResponse);
    put16(0); // alignment before the flags
    put32(0); // Flags: the response negotiates nothing
    put32(0x006c0000u); // Buffer: a placeholder both implementations send
    return out;
}

bool open(quint32 negotiateFlags, const QByteArray &sessionKey, quint64 sequence,
          bool initiator, const QByteArray &signature, QByteArray *data)
{
    const int size = signatureSize(negotiateFlags);
    if (signature.size() < size || !data)
        return false;

    const QByteArray headerBytes = signature.left(8);
    const QByteArray wireSequence = signature.mid(8, 8);
    const QByteArray wireChecksum = signature.mid(16, 8);
    const bool sealedSignature = readLe16(headerBytes, 2) != kSealNone;
    const QByteArray confounder = sealedSignature ? signature.mid(24, 8) : QByteArray();

    const QByteArray expectedSequence = encodeSequence(sequence, initiator);
    QByteArray plain = *data;
    // The confounder the signature carries is its ciphertext; the checksum is
    // computed over the plaintext one, which is the first eight octets of the
    // opened stream (the sender encrypted the pair and signed the pair).
    QByteArray plainConfounder = confounder;
    if (sealedSignature) {
        const QByteArray opened =
            seal(negotiateFlags, sessionKey, expectedSequence, confounder, *data, false);
        plainConfounder = opened.left(8);
        plain = opened.mid(8);
    }

    const QByteArray expected = checksum(negotiateFlags, sessionKey, header(negotiateFlags, sealedSignature),
                                         plainConfounder, plain);
    if (!Ntlm::secureEquals(expected, wireChecksum))
        return false;
    const QByteArray expectedWire =
        transformSequence(negotiateFlags, sessionKey, wireChecksum, expectedSequence);
    if (!Ntlm::secureEquals(expectedWire, wireSequence))
        return false;

    *data = plain;
    return true;
}

QByteArray sign(quint32 negotiateFlags, const QByteArray &sessionKey, quint64 sequence,
                bool initiator, const QByteArray &data, bool sealData, QByteArray *sealed)
{
    const QByteArray sequenceBytes = encodeSequence(sequence, initiator);
    QByteArray confounder;
    if (sealData) {
        confounder.resize(8);
        for (int i = 0; i < 8; ++i)
            confounder[i] = char(QRandomGenerator::system()->generate() & 0xff);
    }

    const QByteArray checksumBytes = checksum(negotiateFlags, sessionKey,
                                              header(negotiateFlags, sealData), confounder, data);
    const QByteArray wireSequence =
        transformSequence(negotiateFlags, sessionKey, checksumBytes, sequenceBytes);

    QByteArray signature = header(negotiateFlags, sealData) + wireSequence + checksumBytes;
    if (sealData) {
        // The pair goes through the cipher as one stream; the signature carries
        // the confounder's ciphertext, the PDU the rest.
        const QByteArray openedStream =
            seal(negotiateFlags, sessionKey, sequenceBytes, confounder, data, true);
        signature.append(openedStream.left(8));
        if (sealed)
            *sealed = openedStream.mid(8);
    } else if (sealed) {
        *sealed = data;
    }
    signature.append(QByteArray(signatureSize(negotiateFlags) - signature.size(), '\0'));
    return signature;
}

} // namespace Schannel
