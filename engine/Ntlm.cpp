// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Ntlm.h"

#include <QCryptographicHash>
#include <QRandomGenerator>

#include <algorithm>

namespace {

const QByteArray kSignature("NTLMSSP\0", 8);

enum : quint32 {
    NegotiateUnicode = 0x00000001u,
    RequestTarget = 0x00000004u,
    NegotiateSign = 0x00000010u,
    NegotiateSeal = 0x00000020u,
    NegotiateNtlm = 0x00000200u,
    NegotiateAlwaysSign = 0x00008000u,
    TargetTypeDomain = 0x00010000u,
    NegotiateExtendedSessionSecurity = 0x00080000u,
    NegotiateTargetInfo = 0x00800000u,
    Negotiate128 = 0x20000000u,
    Negotiate56 = 0x80000000u
};

quint16 read16(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 2 > data.size())
        return 0;
    return quint16(quint8(data[pos]) | (quint8(data[pos + 1]) << 8));
}

quint32 read32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data[pos])) | (quint32(quint8(data[pos + 1])) << 8)
           | (quint32(quint8(data[pos + 2])) << 16) | (quint32(quint8(data[pos + 3])) << 24);
}

void put16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void put32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

// Security buffer: length, allocated length, payload offset.
void putField(QByteArray &out, int length, int offset)
{
    put16(out, quint16(length));
    put16(out, quint16(length));
    put32(out, quint32(offset));
}

QByteArray fieldBytes(const QByteArray &data, int fieldPos)
{
    const int length = read16(data, fieldPos);
    const int offset = int(read32(data, fieldPos + 4));
    if (length <= 0 || offset < 0 || offset + length > data.size())
        return {};
    return data.mid(offset, length);
}

QString decodeString(const QByteArray &bytes, quint32 flags)
{
    if (bytes.isEmpty())
        return {};
    if (flags & NegotiateUnicode)
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(bytes.constData()),
                                  qsizetype(bytes.size() / 2));
    return QString::fromLatin1(bytes);
}

} // namespace

namespace Ntlm {

QByteArray utf16le(const QString &text)
{
    QByteArray out;
    out.reserve(text.size() * 2);
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
    return out;
}

QByteArray ntowfV1(const QString &password)
{
    return QCryptographicHash::hash(utf16le(password), QCryptographicHash::Md4);
}

QByteArray hmacMd5(const QByteArray &key, const QByteArray &data)
{
    QByteArray block = key;
    if (block.size() > 64)
        block = QCryptographicHash::hash(block, QCryptographicHash::Md5);
    block.resize(64, '\0');

    QByteArray innerPad(64, '\0');
    QByteArray outerPad(64, '\0');
    for (int i = 0; i < 64; ++i) {
        innerPad[i] = char(block.at(i) ^ 0x36);
        outerPad[i] = char(block.at(i) ^ 0x5c);
    }
    const QByteArray inner =
        QCryptographicHash::hash(innerPad + data, QCryptographicHash::Md5);
    return QCryptographicHash::hash(outerPad + inner, QCryptographicHash::Md5);
}

bool secureEquals(const QByteArray &left, const QByteArray &right)
{
    if (left.size() != right.size())
        return false;
    unsigned char difference = 0;
    for (int i = 0; i < left.size(); ++i)
        difference |= static_cast<unsigned char>(left.at(i) ^ right.at(i));
    return difference == 0;
}

int messageType(const QByteArray &token)
{
    if (token.size() < 12 || !token.startsWith(kSignature))
        return 0;
    const quint32 type = read32(token, 8);
    return type >= 1 && type <= 3 ? int(type) : 0;
}

bool parseNegotiate(const QByteArray &token, Negotiate *out)
{
    if (token.size() < 16 || !token.startsWith(kSignature) || read32(token, 8) != 1)
        return false;
    out->flags = read32(token, 12);
    return true;
}

bool parseAuthenticate(const QByteArray &token, Authenticate *out)
{
    if (token.size() < 52 || !token.startsWith(kSignature) || read32(token, 8) != 3)
        return false;
    out->flags = read32(token, 60);
    if (!(out->flags & NegotiateUnicode))
        out->flags &= ~NegotiateUnicode; // decode as OEM below
    out->domain = decodeString(fieldBytes(token, 28), out->flags);
    out->user = decodeString(fieldBytes(token, 36), out->flags);
    out->workstation = decodeString(fieldBytes(token, 44), out->flags);
    out->ntResponse = fieldBytes(token, 20);
    return !out->user.isEmpty() && !out->ntResponse.isEmpty();
}

QByteArray targetInfo(const QString &domain, const QString &serverName, const QString &dnsDomain)
{
    QByteArray avPairs;
    auto appendEntry = [&avPairs](quint16 id, const QByteArray &value) {
        put16(avPairs, id);
        put16(avPairs, quint16(value.size()));
        avPairs.append(value);
    };
    appendEntry(2, utf16le(domain.toUpper()));     // MsvAvNbDomainName
    appendEntry(1, utf16le(serverName.toUpper())); // MsvAvNbComputerName
    // MsvAvDnsComputerName (AV 3): clients that build an SPN target name
    // from the target info (impacket computes "service/FQDN" for every
    // NTLMv2 answer) fail outright without it, so it is always present —
    // the FQDN when a DNS domain is configured, the server name otherwise.
    const QString host = dnsDomain.isEmpty()
        ? serverName
        : serverName.toLower() + QLatin1Char('.') + dnsDomain;
    appendEntry(3, utf16le(host)); // MsvAvDnsComputerName
    if (!dnsDomain.isEmpty())
        appendEntry(4, utf16le(dnsDomain)); // MsvAvDnsDomainName
    put16(avPairs, 0); // MsvAvEOL
    put16(avPairs, 0);
    return avPairs;
}

QByteArray challengeToken(const QByteArray &serverChallenge, const QString &domain,
                          const QString &serverName, const QString &dnsDomain)
{
    const QByteArray target = utf16le(domain.toUpper());
    const QByteArray info = targetInfo(domain, serverName, dnsDomain);

    QByteArray out;
    out.append(kSignature);
    put32(out, 2); // CHALLENGE
    putField(out, target.size(), 48);
    // Sign and seal are offered so a client can ask for LDAP integrity or
    // confidentiality; KEY_EXCH is not, because no exported session key is
    // negotiated and the client must use the sealed keys as derived.
    put32(out, NegotiateUnicode | RequestTarget | NegotiateNtlm | NegotiateAlwaysSign
                   | NegotiateSign | NegotiateSeal
                   | TargetTypeDomain | NegotiateExtendedSessionSecurity | NegotiateTargetInfo
                   | Negotiate128 | Negotiate56);
    out.append(serverChallenge.left(8).leftJustified(8, '\0'));
    out.append(QByteArray(8, '\0')); // reserved
    putField(out, info.size(), 48 + target.size());
    out.append(target);
    out.append(info);
    return out;
}

QByteArray embeddedToken(const QByteArray &token)
{
    const int offset = token.indexOf(kSignature);
    if (offset < 0)
        return {};
    return token.mid(offset);
}

bool verifyNtlmv2(const QByteArray &ntHash, const QString &user, const QString &domain,
                  const QByteArray &serverChallenge, const QByteArray &ntResponse)
{
    if (ntHash.size() != 16 || serverChallenge.size() < 8 || ntResponse.size() < 16 + 28)
        return false;

    const QByteArray proof = ntResponse.left(16);
    const QByteArray blob = ntResponse.mid(16);

    const QByteArray responseKey =
        hmacMd5(ntHash, utf16le(user.toUpper() + domain));
    const QByteArray expected =
        hmacMd5(responseKey, serverChallenge.left(8) + blob).left(16);
    return secureEquals(expected, proof);
}

// ---------- Session security (MS-NLMP §3.4) ----------

bool sessionKeys(const QByteArray &ntHash, const QString &user, const QString &domain,
                 const QByteArray &ntProofStr, SessionKeys *out, quint32 negotiateFlags)
{
    if (!out || ntHash.size() != 16 || ntProofStr.size() != 16)
        return false;
    const QByteArray responseKey =
        hmacMd5(ntHash, utf16le(user.toUpper() + domain));
    out->sessionBaseKey = hmacMd5(responseKey, ntProofStr);

    // The magic constants are fixed by MS-NLMP §3.4.5.3; all four keys are MD5
    // of the exported session key and the matching constant.
    const QByteArray exported = exportedSessionKey(out->sessionBaseKey, negotiateFlags);
    out->clientSigningKey = QCryptographicHash::hash(
        exported + QByteArrayLiteral("session key to client-to-server signing key magic constant\0"),
        QCryptographicHash::Md5);
    out->serverSigningKey = QCryptographicHash::hash(
        exported + QByteArrayLiteral("session key to server-to-client signing key magic constant\0"),
        QCryptographicHash::Md5);
    out->clientSealingKey = QCryptographicHash::hash(
        exported + QByteArrayLiteral("session key to client-to-server sealing key magic constant\0"),
        QCryptographicHash::Md5);
    out->serverSealingKey = QCryptographicHash::hash(
        exported + QByteArrayLiteral("session key to server-to-client sealing key magic constant\0"),
        QCryptographicHash::Md5);
    return true;
}

QByteArray mac(const QByteArray &signingKey, quint32 sequence, const QByteArray &message)
{
    QByteArray prefix(4, '\0');
    prefix[0] = char(sequence & 0xff);
    prefix[1] = char((sequence >> 8) & 0xff);
    prefix[2] = char((sequence >> 16) & 0xff);
    prefix[3] = char((sequence >> 24) & 0xff);
    return hmacMd5(signingKey, prefix + message).left(8);
}

Sealer::Sealer(const QByteArray &key)
{
    reset(key);
}

void Sealer::reset(const QByteArray &key)
{
    m_valid = !key.isEmpty();
    m_i = 0;
    m_j = 0;
    if (!m_valid)
        return;
    for (int i = 0; i < 256; ++i)
        m_state[i] = static_cast<unsigned char>(i);
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + m_state[i] + static_cast<unsigned char>(key.at(i % key.size()))) & 0xff;
        std::swap(m_state[i], m_state[j]);
    }
}

QByteArray Sealer::apply(const QByteArray &data)
{
    QByteArray out(data.size(), '\0');
    if (!m_valid)
        return out;
    for (int n = 0; n < data.size(); ++n) {
        m_i = (m_i + 1) & 0xff;
        m_j = (m_j + m_state[m_i]) & 0xff;
        std::swap(m_state[m_i], m_state[m_j]);
        const unsigned char octet = static_cast<unsigned char>(data.at(n))
                                    ^ m_state[(m_state[m_i] + m_state[m_j]) & 0xff];
        out[n] = char(octet);
    }
    return out;
}

QByteArray exportedSessionKey(const QByteArray &sessionBaseKey, quint32 negotiateFlags)
{
    if (negotiateFlags & kNegotiate128)
        return sessionBaseKey;
    const int length = (negotiateFlags & kNegotiate56) ? 7 : 5;
    if (sessionBaseKey.size() < length)
        return sessionBaseKey;
    QByteArray key = sessionBaseKey.left(length);
    key.append(char(0xa0));
    return key;
}

QByteArray signMessage(const QByteArray &signingKey, quint32 sequence,
                       const QByteArray &plaintext)
{
    QByteArray token;
    put32(token, 0x00000001u); // NTLMSSP_NEGOTIATE_SIGN, no key exchange
    token.append(mac(signingKey, sequence, plaintext));
    put32(token, sequence);
    token.append(plaintext);
    return token;
}

QByteArray sealMessage(const QByteArray &sealingKey, const QByteArray &signingKey,
                       Sealer *sealer, quint32 sequence, const QByteArray &plaintext)
{
    if (!sealer || !sealer->isValid())
        return signMessage(signingKey, sequence, plaintext);

    // MS-NLMP §3.4.4/§3.4.5.2: only the message is RC4-ciphered. The checksum
    // is encrypted as well when KEY_EXCH is negotiated, but no exported session
    // key is exchanged here, so it travels in the clear.
    Q_UNUSED(sealingKey)
    const QByteArray sealedMessage = sealer->apply(plaintext);
    const QByteArray checksum = mac(signingKey, sequence, plaintext);

    QByteArray token;
    put32(token, 0x00000001u);
    token.append(checksum);
    put32(token, sequence);
    token.append(sealedMessage);
    return token;
}

bool unsealMessage(const QByteArray &sealingKey, const QByteArray &signingKey,
                   Sealer *sealer, quint32 sequence, const QByteArray &token,
                   QByteArray *plaintext)
{
    Q_UNUSED(sealingKey)
    if (!plaintext || token.size() < 16)
        return false;
    if (read32(token, 12) != sequence)
        return false;

    QByteArray message = token.mid(16);
    const QByteArray checksum = token.mid(4, 8);
    if (sealer && sealer->isValid())
        message = sealer->apply(message);
    if (!secureEquals(mac(signingKey, sequence, message), checksum))
        return false;
    *plaintext = message;
    return true;
}

} // namespace Ntlm
