// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Gss.h"

#include <QRandomGenerator>

#include "Asn1.h"
#include "Krb5.h"
#include "Ntlm.h"

namespace {

// RFC 4121 §7 key usages for tokens this side sends and receives.
constexpr int kAcceptorSealUsage = 22;
constexpr int kInitiatorSealUsage = 24;
constexpr int kAcceptorSignUsage = 23;
constexpr int kInitiatorSignUsage = 25;
// RFC 4757 §7.2: the legacy GSS tokens sign with key usage 13 (15 for MICs).
constexpr int kLegacySignUsage = 13;

quint16 readBe16(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 2 > data.size())
        return 0;
    return quint16((quint8(data[pos]) << 8) | quint8(data[pos + 1]));
}

quint32 readBe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return (quint32(quint8(data[pos])) << 24) | (quint32(quint8(data[pos + 1])) << 16)
           | (quint32(quint8(data[pos + 2])) << 8) | quint32(quint8(data[pos + 3]));
}

quint64 readBe64(const QByteArray &data, int pos)
{
    quint64 value = 0;
    for (int i = 0; i < 8; ++i) {
        if (pos + i >= data.size())
            return 0;
        value = (value << 8) | quint8(data.at(pos + i));
    }
    return value;
}

void appendBe16(QByteArray &out, quint16 value)
{
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void appendBe32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void appendBe64(QByteArray &out, quint64 value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
        out.append(char((value >> shift) & 0xff));
}

QByteArray randomBytes(int count)
{
    QByteArray out(count, '\0');
    for (int i = 0; i < count; ++i)
        out[i] = char(QRandomGenerator::system()->generate() & 0xff);
    return out;
}

// RFC 4757 §7 key derivation as the GSS-API RC4 mechanism applies it: K1 =
// HMAC(K, usage) with usage 0, then K2 = HMAC(K1, state) when there is state
// (the checksum for sequence numbers, the sequence number for data).
QByteArray rc4Gss(const QByteArray &key, const QByteArray &state, const QByteArray &data)
{
    const QByteArray k1 = Ntlm::hmacMd5(key, QByteArray(4, '\0'));
    const QByteArray k2 = state.isEmpty() ? k1 : Ntlm::hmacMd5(k1, state);
    return Krb5::rc4(k2, data);
}

} // namespace

namespace Gss {

const QByteArray kKrb5MechOid = QByteArray::fromHex("2a864886f712010202");
const QByteArray kCfxWrapTokenId = QByteArray("\x05\x04", 2);
const QByteArray kCfxMicTokenId = QByteArray("\x04\x04", 2);
const QByteArray kLegacyWrapTokenId = QByteArray("\x02\x01", 2);

bool carriesKerberos(const QByteArray &token)
{
    return token.contains(kKrb5MechOid);
}

QByteArray kerberosToken(const QByteArray &token)
{
    Asn1::Element outer;
    if (!Asn1::parse(token, &outer) || outer.tag != 0x60)
        return {};
    for (const Asn1::Element &wrapper : outer.children) {
        if (wrapper.tag != 0xA0) // negTokenInit [0]
            continue;
        Asn1::Element init;
        if (!Asn1::parse(wrapper.value, &init) || init.tag != 0x30)
            continue;
        const Asn1::Element *mechToken = Asn1::child(init, 0xA2);
        if (!mechToken)
            continue;
        Asn1::Element octets;
        int used = 0;
        if (Asn1::parse(mechToken->value, &octets, &used) && octets.tag == 0x04)
            return octets.value;
    }
    return {};
}

QByteArray spnegoNegotiatedToken(const QByteArray &token)
{
    Asn1::Element outer;
    if (!Asn1::parse(token, &outer))
        return {};
    QByteArray sequenceBytes;
    if (outer.tag == 0x60) {
        // GSS-API envelope: the negotiation token is the next app tag.
        for (const Asn1::Element &wrapper : outer.children) {
            if (wrapper.tag == 0xA0 || wrapper.tag == 0xA1) {
                sequenceBytes = wrapper.value;
                break;
            }
        }
    } else if (outer.tag == 0xA0 || outer.tag == 0xA1) {
        sequenceBytes = outer.value;
    }
    if (sequenceBytes.isEmpty())
        return {};

    Asn1::Element sequence;
    if (!Asn1::parse(sequenceBytes, &sequence) || sequence.tag != 0x30)
        return {};
    const Asn1::Element *mechToken = Asn1::child(sequence, 0xA2);
    if (!mechToken)
        return {};
    Asn1::Element octets;
    if (!Asn1::parse(mechToken->value, &octets) || octets.tag != 0x04)
        return {};
    return octets.value;
}

QByteArray spnegoResponse(quint8 negState, const QString &mech, const QByteArray &token)
{
    QByteArray fields;
    // negState: 0 accept-completed, 1 accept-incomplete.
    fields.append(Asn1::tlv(0xA0, Asn1::tlv(0x0A, QByteArray(1, char(negState)))));
    if (!mech.isEmpty())
        fields.append(Asn1::tlv(0xA1, Asn1::objectIdentifier(mech)));
    if (!token.isEmpty())
        fields.append(Asn1::tlv(0xA2, Asn1::octets(0x04, token)));
    return Asn1::tlv(0xA1, Asn1::sequence(fields));
}

QByteArray spnegoAcceptToken(const QByteArray &apRep)
{
    const QByteArray response = spnegoResponse(
        0, QStringLiteral("1.2.840.113554.1.2.2"), apRep);
    QByteArray content = Asn1::objectIdentifier(QStringLiteral("1.3.6.1.5.5.2"));
    content.append(response);
    return Asn1::tlv(0x60, content);
}

// RFC 4121 §4.2.6.2 Wrap token.
QByteArray cfxWrapToken(const QByteArray &data, bool conf, quint64 seq, int etype,
                        const QByteArray &key)
{
    QByteArray header;
    header.append(kCfxWrapTokenId);
    header.append(char(0x01 | (conf ? 0x02 : 0))); // sender is the acceptor
    header.append(char(0xff));                    // filler
    appendBe16(header, 0);                        // EC
    appendBe16(header, 0);                        // RRC
    appendBe64(header, seq);

    if (conf) {
        // Confidentiality: the header travels encrypted as well, with RRC
        // zeroed, and the enctype adds the confounder and the checksum.
        return header + Krb5::encrypt(etype, kAcceptorSealUsage, key, data + header);
    }

    const QByteArray checksum = Krb5::checksum(etype, kAcceptorSealUsage, key, data + header);
    header[4] = char((checksum.size() >> 8) & 0xff);
    header[5] = char(checksum.size() & 0xff);
    return header + data + checksum;
}

bool cfxUnwrapToken(const QByteArray &token, QByteArray *data, int etype,
                    const QByteArray &key, quint64 *seq)
{
    if (token.size() < 16 || token.left(2) != kCfxWrapTokenId)
        return false;
    const quint8 flags = quint8(token[2]);
    if (flags & 0x01) // sent by an acceptor; we are the acceptor
        return false;
    quint16 rrc = readBe16(token, 6);
    QByteArray body = token.mid(16);
    if (!body.isEmpty() && rrc != 0) {
        rrc = quint16(rrc % quint16(body.size()));
        if (rrc != 0)
            body = body.right(rrc) + body.left(body.size() - rrc);
    }

    QByteArray header = token.left(16);
    if (flags & 0x02) {
        QByteArray plain;
        if (!Krb5::decrypt(etype, kInitiatorSealUsage, key, body, &plain) || plain.size() < 16)
            return false;
        QByteArray sentHeader = plain.right(16);
        header[6] = 0;
        header[7] = 0;
        sentHeader[6] = 0;
        sentHeader[7] = 0;
        if (sentHeader != header)
            return false;
        *data = plain.left(plain.size() - 16);
    } else {
        const int checksumLength = etype == Krb5::kRc4Hmac ? 8 : 12;
        if (body.size() < checksumLength)
            return false;
        const QByteArray payload = body.left(body.size() - checksumLength);
        const QByteArray checksum = body.right(checksumLength);
        header[4] = 0;
        header[5] = 0;
        header[6] = 0;
        header[7] = 0;
        if (Krb5::checksum(etype, kInitiatorSealUsage, key, payload + header) != checksum)
            return false;
        *data = payload;
    }
    *seq = readBe64(token, 8);
    return true;
}

// RFC 1964 / RFC 4757 §7 token: metadata, checksum, then the sealed payload.
QByteArray legacyWrapToken(const QByteArray &data, bool conf, quint64 seq,
                           const QByteArray &key)
{
    const quint32 seq32 = quint32(seq);
    // SGN_ALG and SEAL_ALG are little-endian in the RFC 1964 token.
    QByteArray metadata;
    metadata.append(char(0x11));                          // SGN_ALG_HMAC_MD5
    metadata.append(char(0x00));
    metadata.append(char(conf ? 0x10 : 0xff));            // SEAL_ALG_MICROSOFT_RC4
    metadata.append(char(conf ? 0x00 : 0xff));
    metadata.append(char(0xff));                          // filler
    metadata.append(char(0xff));
    metadata.append(QByteArray(8, '\0'));                  // SND_SEQ, filled below

    // Confounder, data and one padding octet, as MS-RC4 GSS sealing expects.
    QByteArray plain = randomBytes(8);
    plain.append(data);
    plain.append(char(0x01));

    QByteArray header;
    header.append(kLegacyWrapTokenId);
    header.append(metadata.left(6)); // SGN_ALG, SEAL_ALG, filler
    const QByteArray checksum = Krb5::checksum(kLegacySignUsage, key, header + plain).left(8);

    QByteArray sequencePlain;
    appendBe32(sequencePlain, seq32);
    sequencePlain.append(QByteArray(4, char(0xff))); // direction: acceptor
    const QByteArray sequence = rc4Gss(key, checksum, sequencePlain);
    metadata.replace(6, 8, sequence);

    QByteArray body = metadata;
    body.append(checksum);
    if (conf) {
        QByteArray masked = key;
        for (int i = 0; i < masked.size(); ++i)
            masked[i] = char(masked.at(i) ^ 0xf0);
        QByteArray state;
        appendBe32(state, seq32);
        body.append(rc4Gss(masked, state, plain));
    } else {
        body.append(plain);
    }
    return body;
}

bool legacyUnwrapToken(const QByteArray &body, QByteArray *data, const QByteArray &key,
                       quint64 *seq)
{
    if (body.size() < 14 + 8)
        return false;
    if (quint8(body.at(0)) != 0x11 || quint8(body.at(1)) != 0x00)
        return false;
    const quint16 sealAlg =
        quint16(quint8(body.at(2)) | (quint16(quint8(body.at(3))) << 8));
    const QByteArray metadataHeader = body.left(6);
    const QByteArray sequenceField = body.mid(6, 8);
    const QByteArray checksum = body.mid(14, 8);
    QByteArray payload = body.mid(22);

    QByteArray sequencePlain = rc4Gss(key, checksum, sequenceField);
    const quint8 direction = quint8(sequencePlain[4]);
    if (direction != 0x00) // initiator tokens only
        return false;
    const quint32 seq32 = readBe32(sequencePlain, 0);

    QByteArray plain;
    if (sealAlg == 0x0010) {
        QByteArray masked = key;
        for (int i = 0; i < masked.size(); ++i)
            masked[i] = char(masked.at(i) ^ 0xf0);
        QByteArray state;
        appendBe32(state, seq32);
        plain = rc4Gss(masked, state, payload);
    } else if (sealAlg == 0xffff) {
        plain = payload;
    } else {
        return false;
    }

    QByteArray header;
    header.append(kLegacyWrapTokenId);
    header.append(metadataHeader);
    if (Krb5::checksum(kLegacySignUsage, key, header + plain).left(8) != checksum)
        return false;
    if (plain.size() < 9 || quint8(plain.at(plain.size() - 1)) != 0x01)
        return false;
    *data = plain.mid(8, plain.size() - 9);
    *seq = seq32;
    return true;
}

QByteArray gssEnvelope(const QByteArray &body)
{
    QByteArray content;
    content.append(char(0x06));
    content.append(char(kKrb5MechOid.size()));
    content.append(kKrb5MechOid);
    content.append(body);

    QByteArray out;
    out.append(char(0x60));
    if (content.size() < 0x80) {
        out.append(char(content.size()));
    } else {
        QByteArray length;
        int value = content.size();
        while (value > 0) {
            length.prepend(char(value & 0xff));
            value >>= 8;
        }
        out.append(char(0x80 | length.size()));
        out.append(length);
    }
    out.append(content);
    return out;
}

bool stripGssEnvelope(const QByteArray &token, QByteArray *inner)
{
    if (token.size() < 13 || quint8(token[0]) != 0x60)
        return false;
    int pos = 1;
    int length = quint8(token[pos++]);
    if (length & 0x80) {
        const int count = length & 0x7f;
        if (count < 1 || count > 3 || pos + count > token.size())
            return false;
        length = 0;
        for (int i = 0; i < count; ++i)
            length = (length << 8) | quint8(token[pos++]);
    }
    if (pos + length > token.size() || length < 11)
        return false;
    if (quint8(token[pos]) != 0x06 || quint8(token[pos + 1]) != kKrb5MechOid.size())
        return false;
    if (token.mid(pos + 2, kKrb5MechOid.size()) != kKrb5MechOid)
        return false;
    *inner = token.mid(pos + 2 + kKrb5MechOid.size(), length - 2 - kKrb5MechOid.size());
    return true;
}

// ---------- DCE/RPC framing ----------
//
// A CFX token is one ciphertext stream — E(confounder), E(data), E(padding),
// E(header copy), checksum — but DCE/RPC carries it in two pieces: the stub
// keeps the ciphertext of the data and the auth verifier takes the rest. The
// split needs the rotation RFC 4121 §4.2.5 defines: rotate the stream by RRC,
// put everything in front of the data in the verifier and the remainder in the
// stub. The receiver rotates the two halves back together, which is what
// Windows, Samba (through gss_wrap_iov without a trailer) and impacket all do.

Gss::DceMessage dceSeal(const QByteArray &data, quint64 seq, int etype, const QByteArray &key)
{
    DceMessage message;
    // CFX only: the RFC 1964 DCE layout differs in every field but the stub.
    if (etype == Krb5::kRc4Hmac || data.size() % 16 != 0 || !Krb5::isSupportedEtype(etype))
        return message;

    // No extra padding: the stub is already a whole number of blocks, so the
    // only thing the rotation has to move is the encrypted header and checksum.
    const int extraCount = 0;
    const int rotation = 16 + 12;

    QByteArray header;
    header.append(kCfxWrapTokenId);
    header.append(char(0x01 | 0x02 | 0x04)); // acceptor, confidential, acceptor subkey
    header.append(char(0xff));
    appendBe16(header, quint16(extraCount));
    appendBe16(header, quint16(rotation));
    appendBe64(header, seq);

    // The copy that travels inside the ciphertext predates the rotation.
    QByteArray copy = header;
    copy[6] = char(0);
    copy[7] = char(0);

    const QByteArray sealed = Krb5::encrypt(etype, kAcceptorSealUsage, key, data + copy);
    if (sealed.size() != data.size() + 16 + 16 + 12) // confounder, copy, checksum
        return message;

    const int shifted = rotation + extraCount;
    const QByteArray rotated =
        sealed.right(shifted) + sealed.left(sealed.size() - shifted);
    message.verifier = header + rotated.left(shifted + 16);
    message.payload = rotated.mid(shifted + 16);
    return message;
}

bool dceUnseal(const QByteArray &verifier, const QByteArray &payload, int etype,
               const QByteArray &key, QByteArray *data, quint64 *seq)
{
    if (etype == Krb5::kRc4Hmac || !Krb5::isSupportedEtype(etype))
        return false;
    if (verifier.size() < 16 || verifier.left(2) != kCfxWrapTokenId)
        return false;
    const quint8 flags = quint8(verifier[2]);
    if (!(flags & 0x02) || (flags & 0x01)) // sealed, and not an acceptor token
        return false;

    const int extraCount = readBe16(verifier, 4);
    const int rotation = readBe16(verifier, 6);
    if (verifier.size() < 16 + extraCount + 16 + 12)
        return false;

    QByteArray sentHeader = verifier.left(16);
    sentHeader[6] = char(0);
    sentHeader[7] = char(0);

    // Reassemble the rotated stream, then undo the rotation to get the token
    // back in its one-piece form.
    const QByteArray rotated = verifier.mid(16) + payload;
    const int shifted = rotation + extraCount;
    if (shifted <= 0 || shifted >= rotated.size())
        return false;
    const QByteArray sealed = rotated.mid(shifted) + rotated.left(shifted);

    QByteArray plaintext;
    if (!Krb5::decrypt(etype, kInitiatorSealUsage, key, sealed, &plaintext))
        return false;
    if (plaintext.size() < extraCount + 16)
        return false;

    QByteArray copy = plaintext.right(16);
    copy[6] = char(0);
    copy[7] = char(0);
    if (copy != sentHeader)
        return false;

    if (data)
        *data = plaintext.left(plaintext.size() - extraCount - 16);
    if (seq)
        *seq = readBe64(verifier, 8);
    return true;
}

QByteArray dceMic(const QByteArray &data, quint64 seq, int etype, const QByteArray &key)
{
    if (etype == Krb5::kRc4Hmac || !Krb5::isSupportedEtype(etype))
        return {};
    QByteArray header;
    header.append(kCfxMicTokenId);
    header.append(char(0x01 | 0x04)); // acceptor, acceptor subkey
    header.append(char(0xff));
    appendBe16(header, 0xffff);       // EC and RRC carry no meaning in a MIC token
    appendBe16(header, 0xffff);
    appendBe64(header, seq);
    return header + Krb5::checksum(etype, kAcceptorSignUsage, key, data + header);
}

bool checkDceMic(const QByteArray &token, const QByteArray &data, int etype,
                 const QByteArray &key, quint64 *seq)
{
    if (etype == Krb5::kRc4Hmac || !Krb5::isSupportedEtype(etype))
        return false;
    if (token.size() != 16 + 12 || token.left(2) != kCfxMicTokenId)
        return false;
    if (quint8(token[2]) & 0x01)
        return false;
    const QByteArray expected =
        Krb5::checksum(etype, kInitiatorSignUsage, key, data + token.left(16));
    if (!Ntlm::secureEquals(expected, token.mid(16, 12)))
        return false;
    if (seq)
        *seq = readBe64(token, 8);
    return true;
}

} // namespace Gss
