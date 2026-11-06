// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The initiator half of NTLMSSP (MS-NLMP §2.1.5): the messages a client sends
// and the NTLMv2 response it computes. The acceptor verifiers live in
// Ntlm.cpp; both halves derive from the same rules, which is what lets the
// replication client authenticate against this tree's own DC.

#include "Ntlm.h"

#include <QDateTime>
#include <QRandomGenerator>

namespace {

const QByteArray kSignature("NTLMSSP\0", 8);

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

void putLe64(QByteArray &out, quint64 value)
{
    putLe32(out, quint32(value & 0xffffffffu));
    putLe32(out, quint32(value >> 32));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16)
           | (quint32(quint8(data.at(pos + 3))) << 24);
}

// One NTLMSSP field: Length, MaximumLength and the offset of its payload, all
// counted from the start of the message.
void putField(QByteArray &out, int length, int offset)
{
    putLe16(out, quint16(length));
    putLe16(out, quint16(length));
    putLe32(out, quint32(offset));
}

quint16 fieldLength(const QByteArray &token, int pos)
{
    if (pos < 0 || pos + 2 > token.size())
        return 0;
    return quint16(quint8(token.at(pos)) | (quint8(token.at(pos + 1)) << 8));
}

QByteArray fieldBytes(const QByteArray &token, int pos)
{
    const quint16 length = fieldLength(token, pos);
    // A security buffer is length, allocated length, offset: the offset is the
    // fourth field of the eight bytes that start at pos.
    const quint32 offset = readLe32(token, pos + 4);
    if (length == 0 || offset > quint32(token.size()))
        return QByteArray();
    return token.mid(int(offset), int(length));
}

} // namespace

namespace Ntlm {

QByteArray negotiateToken(quint32 flags)
{
    QByteArray out(kSignature);
    putLe32(out, 1); // NEGOTIATE
    putLe32(out, flags);
    // DomainNameFields and WorkstationFields: both empty, both pointing past
    // the fixed part.
    putField(out, 0, 32);
    putField(out, 0, 32);
    return out;
}

bool parseChallenge(const QByteArray &token, Challenge *out)
{
    if (!out || token.size() < 32 || !token.startsWith(kSignature) || readLe32(token, 8) != 2)
        return false;
    out->flags = readLe32(token, 20);
    out->serverChallenge = token.mid(24, 8); // between the flags and the reserved word
    out->targetInfo = fieldBytes(token, 40);
    return out->serverChallenge.size() == 8;
}

QByteArray authenticateToken(const QString &domain, const QString &user, quint32 flags,
                             const QByteArray &ntResponse)
{
    const QByteArray domainBytes = utf16le(domain);
    const QByteArray userBytes = utf16le(user);
    const int header = 64; // 8 signature + 4 type + 6 fields + 4 flags

    QByteArray out(kSignature);
    putLe32(out, 3); // AUTHENTICATE
    putField(out, 0, header); // LmChallengeResponse: empty
    putField(out, ntResponse.size(), header);
    putField(out, domainBytes.size(), header + ntResponse.size());
    putField(out, userBytes.size(), header + ntResponse.size() + domainBytes.size());
    const int workstationOffset = header + ntResponse.size() + domainBytes.size()
                                  + userBytes.size();
    putField(out, 0, workstationOffset); // Workstation: empty
    putField(out, 0, workstationOffset); // EncryptedRandomSessionKey: no key exchange
    putLe32(out, flags);
    out.append(ntResponse);
    out.append(domainBytes);
    out.append(userBytes);
    return out;
}

bool ntlmv2Response(const QByteArray &ntHash, const QString &user, const QString &domain,
                    const QByteArray &serverChallenge, const QByteArray &targetInfo,
                    QByteArray *ntResponse, QByteArray *ntProofStr)
{
    if (!ntResponse || !ntProofStr || ntHash.size() != 16 || serverChallenge.size() < 8)
        return false;

    QByteArray clientChallenge(8, '\0');
    for (int i = 0; i < 8; ++i)
        clientChallenge[i] = char(QRandomGenerator::system()->generate() & 0xff);

    // The blob (MS-NLMP §3.3.2): response version, reserved word, timestamp,
    // client challenge, reserved word, the peer's target info, terminator.
    QByteArray blob = QByteArray::fromHex("01010000");
    blob.append(QByteArray(4, '\0'));
    const quint64 fileTime =
        quint64((QDateTime::currentMSecsSinceEpoch() + Q_INT64_C(11644473600000)) * 10000);
    putLe64(blob, fileTime);
    blob.append(clientChallenge);
    blob.append(QByteArray(4, '\0'));
    blob.append(targetInfo);
    blob.append(QByteArray(4, '\0'));

    const QByteArray responseKey = hmacMd5(ntHash, utf16le(user.toUpper() + domain));
    const QByteArray proof = hmacMd5(responseKey, serverChallenge.left(8) + blob).left(16);

    *ntProofStr = proof;
    *ntResponse = proof + blob;
    return true;
}

} // namespace Ntlm
