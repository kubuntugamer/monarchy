// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Netlogon.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>

#include "Aes.h"
#include "Des.h"
#include "Krb5.h"
#include "LogonHours.h"
#include "PasswordAge.h"
#include "WorkstationRestriction.h"
#include "Ndr.h"
#include "Ntlm.h"

namespace {

// NTSTATUS values MS-NRPC returns.
constexpr quint32 kStatusSuccess = 0x00000000u;
constexpr quint32 kStatusInvalidInfoClass = 0xc0000003u;
constexpr quint32 kStatusInvalidParameter = 0xc000000du;
constexpr quint32 kStatusAccessDenied = 0xc0000022u;
constexpr quint32 kStatusNoSuchUser = 0xc0000064u;
constexpr quint32 kStatusWrongPassword = 0xc000006au;
constexpr quint32 kStatusAccountDisabled = 0xc0000072u;
constexpr quint32 kStatusAccountRestriction = 0xc000006eu;
constexpr quint32 kStatusAccountLockedOut = 0xc0000234u;
constexpr quint32 kStatusPasswordExpired = 0xc0000071u;
constexpr quint32 kStatusPasswordMustChange = 0xc0000224u;
constexpr quint32 kStatusInvalidWorkstation = 0xc0000070u;
constexpr quint32 kStatusNotSupported = 0xc00000bbu;
constexpr quint32 kStatusNoTrustSamAccount = 0xc000018bu;

// SEC_CHAN_* values (MS-NRPC 2.2.1.3.10). A workstation, a member server and a
// trusting domain are all machine accounts; SEC_CHAN_WKSTA (1) is a standalone
// workstation, which has no domain credential to prove.
constexpr quint16 kSecChanMemberServer = 2;
constexpr quint16 kSecChanDomain = 3;
constexpr quint16 kSecChanServer = 6;
constexpr quint16 kSecChanDnsDomain = 11;

// NBT_SERVER_* bits a DC reports to the DC locator (MS-NRPC 2.2.1.4.13; the
// DS_SERVER_* names are the same field under another name). The numbering is
// the one the CLDAP answer in LdapServer.cpp publishes, which is checked byte
// for byte against Samba's own ping — these were shifted by one bit and named
// five of the seven bits this DC really has, so the Ex2 arm told a client it
// was read-only while claiming a time service. TIMESERV is absent on purpose:
// there is no NTP server here, so a client asking to be pointed at a time
// source is told no rather than sent to one that cannot answer.
constexpr quint32 kNbtServerPdc = 0x00000001u;
constexpr quint32 kNbtServerGc = 0x00000004u;
constexpr quint32 kNbtServerLdap = 0x00000008u;
constexpr quint32 kNbtServerDs = 0x00000010u;
constexpr quint32 kNbtServerKdc = 0x00000020u;
constexpr quint32 kNbtServerClosest = 0x00000080u;
constexpr quint32 kNbtServerWritable = 0x00000100u;

// What this server is, as both locator answers state it. 0x1bd: the word the
// CLDAP blob carries.
constexpr quint32 kNbtServerType = kNbtServerPdc | kNbtServerGc | kNbtServerLdap
    | kNbtServerDs | kNbtServerKdc | kNbtServerClosest | kNbtServerWritable;

// NETLOGON_VALIDATION_* levels (MS-NRPC 2.2.1.5.2).
constexpr quint16 kValidationSamInfo = 2;
constexpr quint16 kValidationSamInfo2 = 3;
constexpr quint16 kValidationSamInfo4 = 6;

// The user flags a Netlogon validation carries (MS-NRPC 2.2.1.5.4).
constexpr quint32 kUserFlagNtlmv2 = 0x00000100u;

constexpr quint64 kNeverNtTime = 0x7fffffffffffffffull;
constexpr quint64 kNtTimeEpoch = 11644473600ull;

// The flags this server negotiates. NETLOGON_NEG_AUTHENTICATED_RPC is left out
// on purpose: this endpoint does not implement the Netlogon security provider
// at the DCE/RPC layer, so claiming schannel would invite a client to sign PDUs
// that would then be refused.
constexpr quint32 kSupportedFlags =
    Netlogon::kNegArcFour | Netlogon::kNegStrongKeys | Netlogon::kNegDnsDomainTrusts
    | Netlogon::kNegPasswordSet2 | Netlogon::kNegGetDomainInfo | Netlogon::kNegSupportsAes
    | Netlogon::kNegAuthenticatedRpc;

quint64 ntTimeNow()
{
    return quint64(QDateTime::currentSecsSinceEpoch() + qint64(kNtTimeEpoch)) * 10000000ull;
}

// Reads an NTTIME out of a directory attribute that may hold either the decimal
// value the console writes or the hexadecimal one SAMR reports.
quint64 ntTimeAttribute(const DirectoryObject &object, const QString &name)
{
    const QString text = object.attributes.value(name).trimmed();
    if (text.isEmpty())
        return 0;
    bool ok = false;
    quint64 value = text.toULongLong(&ok, 10);
    if (!ok)
        value = text.toULongLong(&ok, 16);
    return ok ? value : 0;
}

quint32 ridOf(const DirectoryObject &object)
{
    const QStringList parts =
        object.attributes.value(QStringLiteral("objectSid")).split(QLatin1Char('-'));
    bool ok = false;
    const quint32 rid = parts.isEmpty() ? 0 : parts.last().toUInt(&ok);
    return ok ? rid : 0;
}

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
    putLe32(out, quint32((value >> 32) & 0xffffffffu));
}

quint16 readLe16(const QByteArray &data, int pos)
{
    if (pos + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(pos)) | (quint16(quint8(data.at(pos + 1))) << 8));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16) | (quint32(quint8(data.at(pos + 3))) << 24);
}

void alignTo(QByteArray &out, int boundary)
{
    while (out.size() % boundary != 0)
        out.append('\0');
}

// A reply that carries nothing but the status.
QByteArray statusOnly(quint32 status)
{
    QByteArray out;
    putLe32(out, status);
    return out;
}

// A conformant varying UTF-16 array as `[string]` marshals it: the maximum and
// actual counts include the terminator, and the terminator travels.
QByteArray stringArray(const QString &text)
{
    QByteArray out;
    const QByteArray utf16 = Ndr::utf16le(text);
    const quint32 count = quint32(text.size() + 1);
    putLe32(out, count);
    putLe32(out, 0);
    putLe32(out, count);
    out.append(utf16);
    out.append(QByteArray(2, '\0'));
    alignTo(out, 4);
    return out;
}

// `lsa_String` / `lsa_StringLarge` inside a structure: Length, MaximumLength
// and a referent, with the characters deferred behind the structure.
// lsa_StringLarge counts the terminator into its maximum (MS-LSAD 2.2.2.3).
void headerString(QByteArray &fixed, QByteArray &deferred, const QString &text,
                  quint32 referent, bool large)
{
    const quint16 length = quint16(text.size() * 2);
    putLe16(fixed, length);
    putLe16(fixed, quint16(large ? length + 2 : length));
    const bool present = !text.isEmpty();
    putLe32(fixed, present ? referent : 0u);
    if (!present)
        return;
    putLe32(deferred, quint32(text.size() + (large ? 1 : 0))); // MaximumCount
    putLe32(deferred, 0);                                      // Offset
    putLe32(deferred, quint32(text.size()));                   // ActualCount
    // NDR pushes the characters the actual count names and nothing else: the
    // terminator the large form counts in its maximum is never on the wire.
    deferred.append(Ndr::utf16le(text));
    alignTo(deferred, 4);
}

// A dom_sid2 as a structure member: a conformant array whose maximum count is
// the number of sub-authorities, then the revision, count, authority and the
// sub-authorities themselves.
QByteArray sidArray(const QByteArray &sid)
{
    QByteArray out;
    if (sid.size() < 8) {
        putLe32(out, 0);
        return out;
    }
    const int count = quint8(sid.at(1));
    putLe32(out, quint32(count));
    out.append(sid.left(8));
    out.append(sid.mid(8, count * 4));
    alignTo(out, 4);
    return out;
}

// ---------- MS-NRPC 3.1.4.3.1: session key and credential chain ----------

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    QMessageAuthenticationCode mac(QCryptographicHash::Sha256, key);
    mac.addData(data);
    return mac.result();
}

// AES-128-CFB8 with an all-zero IV, the per-message step MS-NRPC 3.1.4.3.1
// specifies once NETLOGON_NEG_SUPPORTS_AES is negotiated. Encryption and
// decryption are the same XOR against the keystream.
QByteArray aesCfb8(const QByteArray &key, const QByteArray &data)
{
    QByteArray out;
    QByteArray iv(16, '\0');
    out.reserve(data.size());
    for (int i = 0; i < data.size(); ++i) {
        const QByteArray block = Aes::encryptBlock(key, iv);
        const char cipher = char(quint8(data.at(i)) ^ quint8(block.at(0)));
        out.append(cipher);
        iv.remove(0, 1);
        iv.append(cipher);
    }
    return out;
}

// The session key depends on the mutually negotiated strength: AES is
// HMAC-SHA256(NT hash, client || server); strong-key is HMAC-MD5(NT hash,
// MD5(zeros || client || server)); legacy is DES-CBC over the per-word sum.
QByteArray sessionKeyFrom(const QByteArray &ntHash, const QByteArray &clientChallenge,
                          const QByteArray &serverChallenge, quint32 flags)
{
    if (flags & Netlogon::kNegSupportsAes)
        return hmacSha256(ntHash, clientChallenge + serverChallenge).left(16);

    if (flags & Netlogon::kNegStrongKeys) {
        const QByteArray digest = QCryptographicHash::hash(
            QByteArray(4, '\0') + clientChallenge + serverChallenge, QCryptographicHash::Md5);
        QMessageAuthenticationCode mac(QCryptographicHash::Md5, ntHash);
        mac.addData(digest);
        return mac.result();
    }

    QByteArray sum(8, '\0');
    for (int word = 0; word < 2; ++word) {
        const int at = word * 4;
        quint32 a = readLe32(clientChallenge, at);
        quint32 b = readLe32(serverChallenge, at);
        const quint32 total = a + b;
        for (int byte = 0; byte < 4; ++byte)
            sum[at + byte] = char((total >> (8 * byte)) & 0xff);
    }
    // Samba's des_crypt128 applies two successive 56-bit DES keys at offsets
    // zero and nine in the 16-byte machine hash.
    const QByteArray firstKey = Des::keyFromPassword(ntHash.left(7));
    const QByteArray secondKey = Des::keyFromPassword(ntHash.mid(9, 7));
    const QByteArray first = Des::encryptBlock(firstKey, sum);
    return Des::encryptBlock(secondKey, first) + QByteArray(8, '\0');
}

QByteArray stepCredential(const QByteArray &value, const QByteArray &sessionKey, quint32 flags)
{
    if (flags & Netlogon::kNegSupportsAes)
        return aesCfb8(sessionKey, value);

    const QByteArray first = Des::keyFromPassword(sessionKey.left(7));
    const QByteArray second = Des::keyFromPassword(sessionKey.mid(7, 7));
    return Des::encryptBlock(second, Des::encryptBlock(first, value));
}

bool constantTimeEquals(const QByteArray &left, const QByteArray &right)
{
    if (left.size() != right.size())
        return false;
    unsigned char difference = 0;
    for (int i = 0; i < left.size(); ++i)
        difference |= quint8(left.at(i)) ^ quint8(right.at(i));
    return difference == 0;
}

// CVE-2020-1472: a challenge whose first five bytes are identical carries no
// entropy, and accepting it is how ZeroLogon drives the session key to zero.
bool isRandomChallenge(const QByteArray &challenge)
{
    if (challenge.size() != 8)
        return false;
    for (int i = 1; i < 5; ++i) {
        if (challenge.at(i) != challenge.at(0))
            return true;
    }
    return false;
}

QByteArray randomChallenge()
{
    QByteArray out(8, '\0');
    do {
        for (int i = 0; i < 8; ++i)
            out[i] = char(QRandomGenerator::global()->bounded(256));
    } while (!isRandomChallenge(out));
    return out;
}

// ---------- reading MS-NRPC's arguments ----------

// `[string]` as a parameter: a conformant varying array inline, counts
// including the terminator.
bool readStringArray(Ndr::Reader &reader, QString *text)
{
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
        return false;
    if (maximum > 4096 || actual > maximum || actual * 2 > quint32(reader.remaining()))
        return false;
    QByteArray chars;
    if (actual > 0 && !reader.bytes(int(actual * 2), &chars))
        return false;
    QString value = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                       qsizetype(chars.size() / 2));
    const int terminator = value.indexOf(QChar(0));
    if (terminator >= 0)
        value.truncate(terminator);
    if (text)
        *text = value;
    return true;
}

// `[unique] [string]`: a referent, then the array inline when it is not NULL.
bool readUniqueString(Ndr::Reader &reader, QString *text)
{
    bool present = false;
    if (!reader.referent(&present))
        return false;
    if (!present) {
        if (text)
            text->clear();
        return true;
    }
    return readStringArray(reader, text);
}

struct StringHeader {
    quint16 length = 0;
    quint16 maximum = 0;
    quint32 referent = 0;
};

bool readStringHeader(Ndr::Reader &reader, StringHeader *header)
{
    return reader.u16(&header->length) && reader.u16(&header->maximum)
           && reader.u32(&header->referent);
}

// The characters of an `lsa_String` whose header was already read: a
// conformant varying array behind the enclosing structure.
bool readDeferredString(Ndr::Reader &reader, const StringHeader &header, QString *text)
{
    reader.align(4);
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
        return false;
    if (maximum > 4096 || actual > maximum
        || actual * 2 != quint32(header.length))
        return false;
    QByteArray chars;
    if (actual > 0 && !reader.bytes(int(actual * 2), &chars))
        return false;
    if (text) {
        *text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                   qsizetype(chars.size() / 2));
    }
    return true;
}

// The bytes of a netr_ChallengeResponse's `data`: length_is/size_is(count).
bool readDeferredBytes(Ndr::Reader &reader, const StringHeader &header, QByteArray *data)
{
    reader.align(4);
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
        return false;
    if (maximum > 4096 || actual > maximum
        || actual != quint32(header.length))
        return false;
    QByteArray bytes;
    if (actual > 0 && !reader.bytes(int(actual), &bytes))
        return false;
    if (data)
        *data = bytes;
    return true;
}

// The strings a logon carries are account, domain and workstation names: if a
// candidate structure decodes control characters or something enormous, the
// offset was wrong rather than the name exotic.
bool isPrintableName(const QString &text)
{
    if (text.size() > 64)
        return false;
    for (const QChar c : text) {
        if (c.unicode() < 0x20 || c.unicode() > 0x7e)
            return false;
    }
    return true;
}

// netr_NetworkInfo (MS-NRPC 2.2.4.1.2): the identity, the challenge the client
// answered and the two responses.
struct NetworkLogon {
    QString domain;
    QString account;
    QString workstation;
    quint32 parameterControl = 0;
    quint64 logonId = 0;
    QByteArray challenge;
    QByteArray ntResponse;
    QByteArray lmResponse;
};

bool parseNetworkInfo(Ndr::Reader &reader, NetworkLogon *logon)
{
    auto fail = [&reader](const char *field) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("Netlogon: malformed network info at %d reading %s", reader.position(), field);
        return false;
    };
    StringHeader domainHeader;
    StringHeader accountHeader;
    StringHeader workstationHeader;
    quint32 parameterControl = 0;
    quint64 logonId = 0;
    if (!readStringHeader(reader, &domainHeader))
        return fail("domain header");
    if (!reader.u32(&parameterControl))
        return fail("parameter control");
    // OLD_LARGE_INTEGER is two 32-bit halves, so NDR aligns it to 4: aligning
    // to 8 here skipped the first four bytes of the account header and every
    // field after it on a real client's request.
    reader.align(4);
    quint32 logonIdLow = 0;
    quint32 logonIdHigh = 0;
    if (!reader.u32(&logonIdLow) || !reader.u32(&logonIdHigh))
        return fail("logon id");
    logonId = quint64(logonIdLow) | (quint64(logonIdHigh) << 32);
    if (!readStringHeader(reader, &accountHeader) || !readStringHeader(reader, &workstationHeader))
        return fail("account/workstation header");
    QByteArray challenge;
    if (!reader.bytes(8, &challenge))
        return fail("challenge");
    quint16 ntLength = 0;
    quint16 ntSize = 0;
    quint32 ntReferent = 0;
    quint16 lmLength = 0;
    quint16 lmSize = 0;
    quint32 lmReferent = 0;
    reader.align(4);
    if (!reader.u16(&ntLength) || !reader.u16(&ntSize) || !reader.u32(&ntReferent))
        return fail("NT response header");
    if (!reader.u16(&lmLength) || !reader.u16(&lmSize) || !reader.u32(&lmReferent))
        return fail("LM response header");
    if (ntLength > 1024 || lmLength > 1024 || (ntReferent == 0 && ntLength != 0)
        || (lmReferent == 0 && lmLength != 0))
        return fail("response length");

    NetworkLogon parsed;
    parsed.parameterControl = parameterControl;
    parsed.logonId = logonId;
    parsed.challenge = challenge;
    if (domainHeader.referent != 0
        && !readDeferredString(reader, domainHeader, &parsed.domain))
        return fail("deferred domain");
    if (accountHeader.referent != 0
        && !readDeferredString(reader, accountHeader, &parsed.account))
        return fail("deferred account");
    if (workstationHeader.referent != 0
        && !readDeferredString(reader, workstationHeader, &parsed.workstation))
        return fail("deferred workstation");
    StringHeader ntHeader{ntLength, ntSize, ntReferent};
    StringHeader lmHeader{lmLength, lmSize, lmReferent};
    if (ntReferent != 0 && !readDeferredBytes(reader, ntHeader, &parsed.ntResponse))
        return fail("deferred NT response");
    if (lmReferent != 0 && !readDeferredBytes(reader, lmHeader, &parsed.lmResponse))
        return fail("deferred LM response");
    *logon = parsed;
    return true;
}

// netr_PasswordInfo (MS-NRPC 2.2.4.1.3): the identity a network logon also
// carries, followed by the password's own one-way functions instead of a
// challenge and its responses. The interactive (1) and service (3) classes
// marshal this arm.
struct PasswordLogon {
    QString domain;
    QString account;
    QString workstation;
    quint32 parameterControl = 0;
    quint64 logonId = 0;
    QByteArray lmOwf; // 16 bytes; never trusted, because no LM hash is stored
    QByteArray ntOwf; // 16 bytes
};

bool parsePasswordInfo(Ndr::Reader &reader, PasswordLogon *logon)
{
    auto fail = [&reader](const char *field) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("Netlogon: malformed password info at %d reading %s", reader.position(),
                     field);
        return false;
    };
    StringHeader domainHeader;
    StringHeader accountHeader;
    StringHeader workstationHeader;
    quint32 parameterControl = 0;
    quint64 logonId = 0;
    // The identity is laid out exactly as netr_NetworkInfo's, including the
    // 4-aligned OLD_LARGE_INTEGER the logon id is read as.
    if (!readStringHeader(reader, &domainHeader))
        return fail("domain header");
    if (!reader.u32(&parameterControl))
        return fail("parameter control");
    reader.align(4);
    quint32 logonIdLow = 0;
    quint32 logonIdHigh = 0;
    if (!reader.u32(&logonIdLow) || !reader.u32(&logonIdHigh))
        return fail("logon id");
    logonId = quint64(logonIdLow) | (quint64(logonIdHigh) << 32);
    if (!readStringHeader(reader, &accountHeader) || !readStringHeader(reader, &workstationHeader))
        return fail("account/workstation header");

    PasswordLogon parsed;
    parsed.parameterControl = parameterControl;
    parsed.logonId = logonId;
    // samr_Password is 16 inline bytes, so both one-way functions are part of
    // the fixed structure and the identity's strings are deferred past them.
    if (!reader.bytes(16, &parsed.lmOwf) || !reader.bytes(16, &parsed.ntOwf))
        return fail("one-way functions");
    if (domainHeader.referent != 0
        && !readDeferredString(reader, domainHeader, &parsed.domain))
        return fail("deferred domain");
    if (accountHeader.referent != 0
        && !readDeferredString(reader, accountHeader, &parsed.account))
        return fail("deferred account");
    if (workstationHeader.referent != 0
        && !readDeferredString(reader, workstationHeader, &parsed.workstation))
        return fail("deferred workstation");
    *logon = parsed;
    return true;
}

// ---------- writing netr_SamInfo2/3/6 ----------

struct SamAnswer {
    QString account;
    QString fullName;
    QString logonScript;
    QString profilePath;
    QString homeDirectory;
    QString homeDrive;
    quint16 logonCount = 0;
    quint16 badPasswordCount = 0;
    quint32 rid = 0;
    quint32 primaryGid = 513;
    QList<QPair<quint32, quint32>> groups; // rid, attributes
    quint32 acctFlags = 0;
    quint64 logonTime = 0;
    quint64 lastPasswordChange = 0;
    quint64 allowPasswordChange = 0;
    quint64 forcePasswordChange = 0;
    quint64 lastSuccessfulLogon = 0;
    quint64 lastFailedLogon = 0;
    quint32 failedLogonCount = 0;
    QString logonServer;
    QString logonDomain;
    QByteArray domainSid;
    QString dnsDomain;
    QString principalName;
};

// netr_SamBaseInfo (MS-NRPC 2.2.4.2.3). Every pointer's referent is written in
// place and its buffer deferred, in referent order, which is the order pidl and
// impacket both decode.
void appendSamBase(const SamAnswer &answer, QByteArray &fixed, QByteArray &deferred)
{
    quint32 referent = 0x0002f000u;

    putLe64(fixed, answer.logonTime);
    putLe64(fixed, 0);            // logoff_time
    putLe64(fixed, kNeverNtTime); // kickoff_time
    putLe64(fixed, answer.lastPasswordChange);
    putLe64(fixed, answer.allowPasswordChange);
    putLe64(fixed, answer.forcePasswordChange);

    headerString(fixed, deferred, answer.account, referent++, false);
    headerString(fixed, deferred, answer.fullName, referent++, false);
    headerString(fixed, deferred, answer.logonScript, referent++, false);
    headerString(fixed, deferred, answer.profilePath, referent++, false);
    headerString(fixed, deferred, answer.homeDirectory, referent++, false);
    headerString(fixed, deferred, answer.homeDrive, referent++, false);

    putLe16(fixed, answer.logonCount);
    putLe16(fixed, answer.badPasswordCount);
    putLe32(fixed, answer.rid);
    putLe32(fixed, answer.primaryGid);

    // GroupIds points directly to a conformant GROUP_MEMBERSHIP array.
    putLe32(fixed, quint32(answer.groups.size()));
    putLe32(fixed, answer.groups.isEmpty() ? 0u : referent++);
    if (!answer.groups.isEmpty()) {
        putLe32(deferred, quint32(answer.groups.size())); // array MaximumCount
        alignTo(deferred, 4);
        for (const auto &group : answer.groups) {
            putLe32(deferred, group.first);
            putLe32(deferred, group.second);
        }
        alignTo(deferred, 4);
    }

    putLe32(fixed, kUserFlagNtlmv2);   // user_flags
    fixed.append(QByteArray(16, '\0')); // key: all zero, so the client keeps its own

    headerString(fixed, deferred, answer.logonServer, referent++, true);
    headerString(fixed, deferred, answer.logonDomain, referent++, true);

    putLe32(fixed, answer.domainSid.isEmpty() ? 0u : referent++);
    if (!answer.domainSid.isEmpty())
        deferred.append(sidArray(answer.domainSid));

    fixed.append(QByteArray(8, '\0')); // LMSessKey
    putLe32(fixed, answer.acctFlags);
    putLe32(fixed, 0); // sub_auth_status
    putLe64(fixed, answer.lastSuccessfulLogon);
    putLe64(fixed, answer.lastFailedLogon);
    putLe32(fixed, answer.failedLogonCount);
    putLe32(fixed, 0); // reserved
}

// The validation union arm for `validationLevel`, ready to follow its referent.
QByteArray samValidation(const SamAnswer &answer, quint16 validationLevel,
                         QByteArray *deferredOut, quint32 *status)
{
    QByteArray fixed;
    QByteArray deferred;
    appendSamBase(answer, fixed, deferred);

    if (validationLevel == kValidationSamInfo) {
        *status = kStatusSuccess;
        alignTo(deferred, 4);
        *deferredOut = deferred;
        return fixed;
    }
    if (validationLevel != kValidationSamInfo2 && validationLevel != kValidationSamInfo4) {
        *status = kStatusInvalidInfoClass;
        return {};
    }

    // No resource-group SIDs are present; the optional SID-array pointer is NULL.
    putLe32(fixed, 0); // sidcount
    putLe32(fixed, 0); // sids referent

    // NDR defers embedded structure pointers in the order they occur in the
    // fixed structure: all base strings and arrays, then the base domain SID,
    // then these trailing strings. Keep the trailing referents in fixed, but
    // append their buffers after the base's deferred buffers.
    QByteArray trailingDeferred;
    alignTo(deferred, 4);
    if (validationLevel == kValidationSamInfo4) {
        headerString(fixed, trailingDeferred, answer.dnsDomain, 0x0002f101u, false);
        headerString(fixed, trailingDeferred, answer.principalName, 0x0002f102u, false);
        for (int i = 0; i < 20; ++i)
            putLe32(fixed, 0); // unknown4
    }
    deferred.append(trailingDeferred);

    *status = kStatusSuccess;
    *deferredOut = deferred;
    return fixed;
}

// A GUID for the domain, derived from its SID so every answer agrees and a
// restart does not change it. NDR writes Data1 to Data3 little-endian.
QByteArray domainGuid(const QString &domainSid)
{
    const QByteArray digest = QCryptographicHash::hash(domainSid.toUpper().toUtf8(),
                                                       QCryptographicHash::Md5);
    QByteArray guid;
    putLe32(guid, quint32(quint8(digest.at(0))) | (quint32(quint8(digest.at(1))) << 8)
                       | (quint32(quint8(digest.at(2))) << 16)
                       | (quint32(quint8(digest.at(3))) << 24));
    putLe16(guid, quint16(quint8(digest.at(4)) | (quint16(quint8(digest.at(5))) << 8)));
    putLe16(guid, quint16(quint8(digest.at(6)) | (quint16(quint8(digest.at(7))) << 8)));
    guid.append(digest.mid(8, 8));
    return guid;
}

} // namespace

namespace Netlogon {

Rpc::Interface interface()
{
    Rpc::Interface out;
    // 12345678-1234-abcd-ef00-01234567cffb on the wire: the first three fields
    // are little-endian, the last eight bytes travel as written.
    out.uuid = QByteArray::fromHex("785634123412cdabef0001234567cffb");
    out.major = 1;
    out.minor = 0;
    out.name = QStringLiteral("netlogon");
    return out;
}

} // namespace Netlogon

NetlogonServer::NetlogonServer(QObject *parent) : QObject(parent)
{
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Netlogon::interface(), [this](const Rpc::Call &call) {
        return handleCall(call.opnum, call.stub, call.user);
    });
    m_rpc->setSchannelAcceptor([this](const QString &domain, const QString &computer,
                                      Rpc::SchannelCredentials *credentials) {
        return schannelCredentials(domain, computer, credentials);
    });
    connect(m_rpc, &RpcServer::requestReceived, this, &NetlogonServer::requestReceived);
}

void NetlogonServer::setConfig(const Netlogon::Config &config)
{
    m_config = config;
}

bool NetlogonServer::schannelCredentials(const QString &domain, const QString &computer,
                                         Rpc::SchannelCredentials *credentials) const
{
    if (!credentials || computer.isEmpty())
        return false;
    if (!domain.isEmpty() && domain.compare(m_config.netbios, Qt::CaseInsensitive) != 0
        && domain.compare(m_config.realm, Qt::CaseInsensitive) != 0
        && domain.compare(m_config.dnsDomain, Qt::CaseInsensitive) != 0) {
        return false;
    }

    const auto channel = m_channels.constFind(computer.toLower());
    if (channel == m_channels.constEnd() || channel->sessionKey.isEmpty())
        return false;

    credentials->sessionKey = channel->sessionKey;
    credentials->negotiateFlags = channel->flags;
    credentials->account = channel->accountName;
    return true;
}

void NetlogonServer::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = std::move(provider);
}

void NetlogonServer::setWriteBackend(Netlogon::WriteBackend backend)
{
    m_writes = std::move(backend);
}

bool NetlogonServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void NetlogonServer::close()
{
    m_rpc->close();
}

bool NetlogonServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 NetlogonServer::serverPort() const
{
    return m_rpc->serverPort();
}

QList<DirectoryObject> NetlogonServer::directory() const
{
    return m_provider ? m_provider() : QList<DirectoryObject>();
}

DirectoryObject NetlogonServer::findAccount(const QString &name) const
{
    QString account = name;
    const int backslash = account.indexOf(QLatin1Char('\\'));
    if (backslash >= 0)
        account = account.mid(backslash + 1);
    const int at = account.indexOf(QLatin1Char('@'));
    if (at > 0)
        account = account.left(at);
    if (account.isEmpty())
        return {};
    for (const DirectoryObject &object : directory()) {
        if (object.attributes.value(QStringLiteral("sAMAccountName"))
                .compare(account, Qt::CaseInsensitive)
            == 0) {
            return object;
        }
    }
    return {};
}

// A trust channel authenticates against the trustedDomain object the LSAD
// calls store: the trusted domain's own account name (`FABRIKAM$`) and the
// secret in trustAuthIncoming. Windows keeps a disabled account for the same
// purpose; reading the trust directly means the two protocols cannot disagree
// about which secret is current.
DirectoryObject NetlogonServer::findTrustPrincipal(const QString &name) const
{
    QString account = name;
    const int backslash = account.indexOf(QLatin1Char('\\'));
    if (backslash >= 0)
        account = account.mid(backslash + 1);
    const int at = account.indexOf(QLatin1Char('@'));
    if (at > 0)
        account = account.left(at);
    if (account.endsWith(QLatin1Char('$')))
        account.chop(1);
    if (account.isEmpty())
        return {};
    for (const DirectoryObject &object : directory()) {
        if (!object.attributes.value(QStringLiteral("objectClass"))
                 .contains(QLatin1String("trustedDomain"), Qt::CaseInsensitive))
            continue;
        const QString flat = object.attributes.value(QStringLiteral("flatName"));
        const QString partner = object.attributes.value(QStringLiteral("trustPartner"));
        const QString partnerFlat = partner.section(QLatin1Char('.'), 0, 0);
        if (flat.compare(account, Qt::CaseInsensitive) != 0
            && partnerFlat.compare(account, Qt::CaseInsensitive) != 0)
            continue;
        // Only an inbound trust accepts a channel from that domain, and only a
        // secret this DC holds can prove it.
        if ((object.attributes.value(QStringLiteral("trustDirection")).toUInt() & 1u) == 0)
            continue;
        const QString auth = object.attributes.value(QStringLiteral("trustAuthIncoming"));
        const int colon = auth.indexOf(QLatin1Char(':'));
        if (colon < 0)
            continue;
        const quint32 authType = auth.left(colon).toUInt();
        const QByteArray data = QByteArray::fromHex(auth.mid(colon + 1).toLatin1());
        QByteArray ntHash;
        if (authType == 2) // TRUST_AUTH_TYPE_CLEAR
            ntHash = Ntlm::ntowfV1(QString::fromUtf8(data));
        else if (authType == 1 && data.size() == 16) // TRUST_AUTH_TYPE_NT4OWF
            ntHash = data;
        else
            continue;
        DirectoryObject principal;
        principal.id = object.id;
        principal.name = flat;
        principal.kind = ObjectKind::Unknown;
        principal.attributes.insert(QStringLiteral("sAMAccountName"),
                                    flat + QLatin1Char('$'));
        principal.attributes.insert(QStringLiteral("objectSid"),
                                    object.attributes.value(QStringLiteral("securityIdentifier")));
        principal.attributes.insert(QStringLiteral("ntHash"),
                                    QString::fromLatin1(ntHash.toHex()));
        principal.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("0"));
        return principal;
    }
    return {};
}

bool NetlogonServer::machineCredential(const DirectoryObject &object, QByteArray *ntHash) const
{
    const QByteArray hash = QByteArray::fromHex(
        object.attributes.value(QStringLiteral("ntHash")).toLatin1());
    if (hash.size() != 16)
        return false;
    *ntHash = hash;
    return true;
}

// The next link in the credential chain: the credential the client should have
// sent is derived from the seed and the timestamp it carries, and the reply is
// the one the client has to find in the server's answer.
bool NetlogonServer::stepAuthenticator(Channel *channel, quint32 timestamp,
                                       const QByteArray &credential, QByteArray *reply)
{
    channel->sequence = timestamp;
    QByteArray clientInput;
    putLe32(clientInput, quint32(readLe32(channel->seed, 0) + timestamp));
    clientInput.append(channel->seed.mid(4, 4));
    const QByteArray client = stepCredential(clientInput, channel->sessionKey, channel->flags);

    QByteArray serverInput;
    putLe32(serverInput, quint32(readLe32(channel->seed, 0) + timestamp + 1));
    serverInput.append(channel->seed.mid(4, 4));
    const QByteArray server = stepCredential(serverInput, channel->sessionKey, channel->flags);

    if (!constantTimeEquals(client, credential))
        return false;
    channel->client = client;
    channel->server = server;
    // The chain advances on the *input* of the reply credential, not on the
    // credential itself: `netlogon_creds_step` in Samba's credentials.c ends by
    // storing seed + sequence + 1, and the next call derives from that. Storing
    // the encrypted credential here makes this server and its client disagree
    // about the seed from the second call onwards, which is exactly what a
    // LogonGetCapabilities over the seal reported.
    channel->seed = serverInput;
    *reply = server;
    return true;
}

QByteArray NetlogonServer::serverReqChallenge(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverName;
    QString computerName;
    if (!readUniqueString(reader, &serverName))
        return statusOnly(kStatusInvalidParameter);
    if (!readStringArray(reader, &computerName))
        return statusOnly(kStatusInvalidParameter);
    QByteArray clientChallenge;
    if (!reader.bytes(8, &clientChallenge))
        return statusOnly(kStatusInvalidParameter);
    // MS-NRPC 3.1.4.4.1 and the ZeroLogon fix in CVE-2020-1472: a challenge
    // that carries no entropy is refused before anything is derived from it.
    if (!isRandomChallenge(clientChallenge))
        return statusOnly(kStatusAccessDenied);
    if (computerName.isEmpty())
        return statusOnly(kStatusInvalidParameter);

    Challenge challenge;
    challenge.client = clientChallenge;
    challenge.server = randomChallenge();
    m_challenges.insert(computerName.toLower(), challenge);
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("Netlogon: ReqChallenge for %s client=%s server=%s", qPrintable(computerName),
                 challenge.client.toHex().constData(), challenge.server.toHex().constData());

    QByteArray out = challenge.server;
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("ServerReqChallenge(%1)").arg(computerName));
    return out;
}

QByteArray NetlogonServer::serverAuthenticate(const QByteArray &stub, quint16 opnum)
{
    Ndr::Reader reader(stub);
    QString serverName;
    QString accountName;
    QString computerName;
    quint16 channelType = 0;
    if (!readUniqueString(reader, &serverName))
        return statusOnly(kStatusInvalidParameter);
    if (!readStringArray(reader, &accountName))
        return statusOnly(kStatusInvalidParameter);
    if (!reader.u16(&channelType))
        return statusOnly(kStatusInvalidParameter);
    reader.align(4);
    if (!readStringArray(reader, &computerName))
        return statusOnly(kStatusInvalidParameter);
    QByteArray credential;
    if (!reader.bytes(8, &credential))
        return statusOnly(kStatusInvalidParameter);
    quint32 requested = 0;
    if (opnum == Netlogon::OpServerAuthenticate2 || opnum == Netlogon::OpServerAuthenticate3) {
        if (!reader.u32(&requested))
            return statusOnly(kStatusInvalidParameter);
    } else {
        // The original NetrServerAuthenticate predates negotiate flags and
        // uses the legacy 64-bit DES session key by definition.
        requested = 0;
    }

    switch (channelType) {
    case kSecChanMemberServer:
    case kSecChanDomain:
    case kSecChanServer:
    case kSecChanDnsDomain:
        break;
    default:
        return statusOnly(kStatusNotSupported);
    }

    DirectoryObject account = findAccount(accountName);
    if (account.id.isEmpty())
        account = findTrustPrincipal(accountName);
    if (account.id.isEmpty())
        return statusOnly(kStatusNoSuchUser);
    QByteArray ntHash;
    if (!machineCredential(account, &ntHash)) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("Netlogon: %s has no NT hash", qPrintable(account.id));
        return statusOnly(kStatusAccessDenied);
    }
    const Challenge challenge =
        m_challenges.value(computerName.toLower(), m_challenges.value(accountName.toLower()));
    if (challenge.client.size() != 8 || challenge.server.size() != 8)
        return statusOnly(kStatusNoTrustSamAccount);

    const quint32 negotiated =
        (opnum == Netlogon::OpServerAuthenticate)
            ? 0u
            : (requested & kSupportedFlags);
    const QByteArray sessionKey =
        sessionKeyFrom(ntHash, challenge.client, challenge.server, negotiated);
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("Netlogon: %s key=%s hash=%s", qPrintable(accountName),
                 sessionKey.toHex().constData(), ntHash.toHex().constData());
    const QByteArray expected = stepCredential(challenge.client, sessionKey, negotiated);
    if (!constantTimeEquals(expected, credential)) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("Netlogon: credential mismatch for %s (expected %s got %s)",
                     qPrintable(accountName), expected.toHex().constData(),
                     credential.toHex().constData());
        return statusOnly(kStatusAccessDenied);
    }

    Channel channel;
    channel.sessionKey = sessionKey;
    channel.client = expected;
    channel.server = stepCredential(challenge.server, sessionKey, negotiated);
    // The seed a channel starts from is the client credential the challenge
    // produced - `netlogon_creds_first_step` sets exactly that - and the first
    // step of the chain is the one that turns it into the input for the next.
    channel.seed = channel.client;
    channel.sequence = 0;
    channel.flags = negotiated;
    channel.requestedFlags = requested;
    channel.accountName = accountName;
    channel.sid = account.attributes.value(QStringLiteral("objectSid"));
    m_channels.insert(accountName.toLower(), channel);
    m_channels.insert(computerName.toLower(), channel);
    m_challenges.remove(computerName.toLower());

    QByteArray out = channel.server;
    if (opnum == Netlogon::OpServerAuthenticate2 || opnum == Netlogon::OpServerAuthenticate3)
        putLe32(out, negotiated);
    if (opnum == Netlogon::OpServerAuthenticate3)
        putLe32(out, ridOf(account));
    putLe32(out, kStatusSuccess);
    emit requestReceived(
        QStringLiteral("ServerAuthenticate3(%1): channel established").arg(accountName));
    return out;
}

// MS-NRPC 3.5.4.4.10 (opnum 21). A client that authenticated its channel runs
// this before trusting it: the capabilities it reads back have to be byte for
// byte the flags the ServerAuthenticate3 reply negotiated, so a machine
// redirected to a server that negotiated a weaker channel than the real DC would
// sees the difference. Samba calls it from netlogon_creds_cli_check and treats
// "procedure not found" as NT_STATUS_DOWNGRADE_DETECTED as soon as
// NETLOGON_NEG_SUPPORTS_AES is on the channel — which is why the whole join
// stopped at the post-join verification until this answered. Query level 1 asks
// for the server's flags, level 2 for the flags the client asked with.
QByteArray NetlogonServer::logonGetCapabilities(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverName;
    QString computerName;
    // server_name is a `[in] [string]` and therefore in place, while
    // computer_name is `[in,unique] [string]` and carries a referent of its own
    // (MS-NRPC 3.5.4.4.1 as Samba's netlogon.idl declares it, and as the client
    // sends it).
    if (!readStringArray(reader, &serverName) || !readUniqueString(reader, &computerName))
        return statusOnly(kStatusInvalidParameter);
    QByteArray credential;
    quint32 timestamp = 0;
    if (!reader.bytes(8, &credential) || !reader.u32(&timestamp))
        return statusOnly(kStatusInvalidParameter);
    // return_authenticator is [in,out,ref]: the client sends a zeroed one and
    // reads ours back, so it occupies the same twelve octets on the way in.
    if (!reader.skip(12))
        return statusOnly(kStatusInvalidParameter);
    quint32 queryLevel = 0;
    if (!reader.u32(&queryLevel))
        return statusOnly(kStatusInvalidParameter);
    if (queryLevel != 1 && queryLevel != 2)
        return statusOnly(kStatusInvalidParameter);

    const QString key = computerName.isEmpty() ? serverName : computerName;
    auto channel = m_channels.find(key.toLower());
    if (channel == m_channels.end())
        return statusOnly(kStatusNoTrustSamAccount);
    QByteArray reply;
    if (!stepAuthenticator(&channel.value(), timestamp, credential, &reply))
        return statusOnly(kStatusAccessDenied);

    // The capability arm follows the return authenticator, then the status. The
    // union is declared with switch_is(query_level) and is not nodiscriminant, so
    // the discriminant travels too: a reply without it leaves the client reading
    // the flags as the switch value (`Bad switch value 0x41074004`).
    QByteArray out = reply;
    putLe32(out, timestamp);
    putLe32(out, queryLevel);
    putLe32(out, queryLevel == 2 ? channel->requestedFlags : channel->flags);
    putLe32(out, kStatusSuccess);
    emit requestReceived(
        QStringLiteral("LogonGetCapabilities(%1): 0x%2").arg(key).arg(channel->flags, 8, 16, QLatin1Char('0')));
    return out;
}

// NetrLogonGetDomainInfo (MS-NRPC 3.5.4.4.10): what a workstation asks when its
// netlogon service starts and again when a user logs on — level 1 registers the
// machine's own hostname and site and returns the domain's identity, level 2
// returns only the LSA policy. The answer the logon needs is the level it asks:
// the client reads the arm its own discriminant names, so a reply built for the
// other level is a marshalling failure rather than a lenient one.
QByteArray NetlogonServer::logonGetDomainInfo(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverName;
    QString computerName;
    if (!readStringArray(reader, &serverName) || !readUniqueString(reader, &computerName))
        return statusOnly(kStatusInvalidParameter);
    QByteArray credential;
    quint32 timestamp = 0;
    if (!reader.bytes(8, &credential) || !reader.u32(&timestamp))
        return statusOnly(kStatusInvalidParameter);
    if (!reader.skip(12)) // return_authenticator, in place on the way in
        return statusOnly(kStatusInvalidParameter);
    quint32 level = 0;
    if (!reader.u32(&level))
        return statusOnly(kStatusInvalidParameter);

    // The authenticator is stepped only when the answer is the success the
    // client will read: a refusal carries no reply credential, and advancing
    // this side's chain alone would desync every call after it.
    const QString key = computerName.isEmpty() ? serverName : computerName;
    auto channel = m_channels.find(key.toLower());
    if (channel == m_channels.end())
        return statusOnly(kStatusNoTrustSamAccount);
    if (level != 1)
        return statusOnly(kStatusInvalidInfoClass);
    QByteArray reply;
    if (!stepAuthenticator(&channel.value(), timestamp, credential, &reply))
        return statusOnly(kStatusAccessDenied);

    QByteArray out = reply;
    putLe32(out, timestamp);   // return_authenticator, twelve octets with the credential
    putLe32(out, level);       // the union's discriminant, which the client reads
    quint32 referent = 1;
    putLe32(out, referent++);  // domain_info: the arm is a pointer of its own

    // netr_DomainInformation, level 1. Everything a Windows 2000 workstation
    // does not need travels as an empty lsa_StringLarge and a NULL pointer, so
    // the only deferred buffers are the three domain names, the SID and the DC's
    // own DNS name — in the order the pointers appeared.
    QByteArray fixed;
    QByteArray deferred;
    const QString dnsDomain = m_config.dnsDomain.isEmpty() ? m_config.realm : m_config.dnsDomain;
    const QByteArray sid = Ndr::sidFromString(m_config.domainSid);

    headerString(fixed, deferred, m_config.netbios, referent++, true); // domainname
    headerString(fixed, deferred, dnsDomain, referent++, true);        // dns_domainname
    headerString(fixed, deferred, dnsDomain, referent++, true);        // dns_forestname
    fixed.append(domainGuid(m_config.domainSid));
    putLe32(fixed, sid.isEmpty() ? 0u : referent++); // domain_sid
    if (!sid.isEmpty())
        deferred.append(sidArray(sid));
    putLe16(fixed, 0); // trust_extension.length
    putLe16(fixed, 0); // trust_extension.size
    putLe32(fixed, 0); // trust_extension.info: no trust, so NULL
    for (int i = 0; i < 3; ++i) { // dummy_string2..4 of the primary domain
        putLe16(fixed, 0);
        putLe16(fixed, 0);
        putLe32(fixed, 0);
    }
    for (int i = 0; i < 4; ++i) // dummy_long1..4
        putLe32(fixed, 0);

    putLe32(fixed, 0); // trusted_domain_count
    putLe32(fixed, 0); // trusted_domains: a [size_is(0)] pointer, so NULL
    putLe32(fixed, 0); // lsa_policy.policy_size
    putLe32(fixed, 0); // lsa_policy.policy
    headerString(fixed, deferred, m_config.dcHost, referent++, true); // dns_hostname
    for (int i = 0; i < 3; ++i) { // dummy_string2..4
        putLe16(fixed, 0);
        putLe16(fixed, 0);
        putLe32(fixed, 0);
    }
    putLe32(fixed, 0); // workstation_flags: this DC handles inbound trusts or SPN updates
    // The encryption types this DC holds keys for ([MS-KILE] 2.2.6): every
    // account is stored with an NT hash and AES128/AES256 keys, so the KDC can
    // issue RC4-HMAC, AES128 and AES256 tickets. A zero here says the domain
    // supports no type at all, which is not true of this DC.
    putLe32(fixed, 0x1cu); // supported_enc_types: RC4-HMAC | AES128 | AES256
    putLe32(fixed, 0); // dummy_long3
    putLe32(fixed, 0); // dummy_long4

    out.append(fixed);
    out.append(deferred);
    putLe32(out, kStatusSuccess);
    emit requestReceived(
        QStringLiteral("LogonGetDomainInfo(%1): %2, %3").arg(key, m_config.netbios, dnsDomain));
    return out;
}

QByteArray NetlogonServer::serverPasswordSet2(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverName;
    QString accountName;
    QString computerName;
    quint16 channelType = 0;
    if (!readUniqueString(reader, &serverName))
        return statusOnly(kStatusInvalidParameter);
    if (!readStringArray(reader, &accountName))
        return statusOnly(kStatusInvalidParameter);
    if (!reader.u16(&channelType))
        return statusOnly(kStatusInvalidParameter);
    reader.align(4);
    if (!readStringArray(reader, &computerName))
        return statusOnly(kStatusInvalidParameter);
    QByteArray credential;
    quint32 timestamp = 0;
    if (!reader.bytes(8, &credential) || !reader.u32(&timestamp))
        return statusOnly(kStatusInvalidParameter);
    QByteArray cipherText;
    if (!reader.bytes(512, &cipherText))
        return statusOnly(kStatusInvalidParameter);
    quint32 length = 0;
    if (!reader.u32(&length))
        return statusOnly(kStatusInvalidParameter);
    Q_UNUSED(serverName)
    Q_UNUSED(channelType)

    auto channel = m_channels.find(accountName.toLower());
    if (channel == m_channels.end())
        return statusOnly(kStatusNoTrustSamAccount);
    QByteArray reply;
    if (!stepAuthenticator(&channel.value(), timestamp, credential, &reply))
        return statusOnly(kStatusAccessDenied);

    // MS-NRPC 3.1.4.4.5: the 512-byte buffer is the new password, UTF-16LE and
    // right-justified against its length, ciphered with the channel's session
    // key. Only the hash of it is ever stored.
    if (length == 0 || length > 512 || length % 2 != 0)
        return statusOnly(kStatusWrongPassword);
    const QByteArray plain = Krb5::rc4(channel->sessionKey, cipherText);
    QByteArray passwordBytes = plain.mid(512 - int(length), int(length));
    // Trim the UTF-16 terminator a code unit at a time. Chopping single bytes
    // would also eat the zero high byte of a final ASCII character, so
    // "Pass12" would arrive at the hash as "Pass1".
    while (passwordBytes.size() >= 2 && passwordBytes.at(passwordBytes.size() - 1) == '\0'
           && passwordBytes.at(passwordBytes.size() - 2) == '\0') {
        passwordBytes.chop(2);
    }
    if (passwordBytes.size() < 2)
        return statusOnly(kStatusWrongPassword);
    const QString password = QString::fromUtf16(
        reinterpret_cast<const char16_t *>(passwordBytes.constData()),
        qsizetype(passwordBytes.size() / 2));

    const DirectoryObject account = findAccount(accountName);
    if (account.id.isEmpty() || !m_writes.setNtHash)
        return statusOnly(kStatusNoSuchUser);
    QString error;
    if (!m_writes.setNtHash(account.id, Ntlm::ntowfV1(password), &error)) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("Netlogon password set for %s refused: %s", qPrintable(accountName),
                     qPrintable(error));
        return statusOnly(kStatusAccessDenied);
    }

    // The return authenticator echoes the request's timestamp, as the logon
    // arm does; a client steps its chain on that value, so a zero here would
    // desynchronise every later call on the channel.
    QByteArray out = reply;
    putLe32(out, timestamp);
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("ServerPasswordSet2(%1)").arg(accountName));
    return out;
}

QByteArray NetlogonServer::samLogon(const QByteArray &stub, bool withAuthenticator, bool withFlags)
{
    Ndr::Reader reader(stub);
    QString computerName;
    quint16 logonLevel = 0;
    quint16 validationLevel = 0;
    quint32 authenticatorReferent = 0;
    QByteArray requestCredential;
    QByteArray returnCredential;
    quint32 timestamp = 0;
    bool hasAuthenticator = false;
    bool returnAuthenticatorPresent = false;

    // Every answer to this call is the whole [out] frame, status included: a
    // client unmarshals validation_level, the netr_Validation union and the
    // authoritative byte before it reaches ReturnStatus, so a refusal that
    // carries only the status reads as "The stub received bad data" rather
    // than as a wrong password.
    const auto refused = [&](quint32 status) {
        QByteArray out;
        if (withAuthenticator) {
            const bool echo = returnAuthenticatorPresent && !returnCredential.isEmpty();
            putLe32(out, echo ? 0x0002f210u : 0u);
            if (echo) {
                out.append(returnCredential);
                putLe32(out, timestamp);
            }
        }
        putLe16(out, validationLevel);
        alignTo(out, 4);
        putLe32(out, 0); // NULL validation information
        out.append(char(0)); // not authoritative
        if (withFlags) {
            alignTo(out, 4);
            putLe32(out, 0);
        }
        alignTo(out, 4);
        putLe32(out, status);
        return out;
    };
    if (withAuthenticator) {
        // The call opens with two `[unique, string]` arguments, LogonServer and
        // then ComputerName, and each carries its own characters right behind
        // its referent. Reading only the second one left the parse four bytes
        // into LogonServer's array header, where the counts fail their sanity
        // check and every request is answered STATUS_INVALID_PARAMETER.
        QString logonServer;
        bool authenticatorPresent = false;
        if (!readUniqueString(reader, &logonServer) || !readUniqueString(reader, &computerName)
            || !reader.referent(&authenticatorPresent))
            return refused(kStatusInvalidParameter);
        if (computerName.isEmpty())
            return refused(kStatusInvalidParameter);
        if (authenticatorPresent) {
            if (!reader.bytes(8, &requestCredential) || !reader.u32(&timestamp))
                return refused(kStatusInvalidParameter);
            hasAuthenticator = true;
        }
        if (!reader.referent(&returnAuthenticatorPresent))
            return refused(kStatusInvalidParameter);
        if (returnAuthenticatorPresent && !reader.skip(12))
            return refused(kStatusInvalidParameter);
        if (!reader.u16(&logonLevel))
            return refused(kStatusInvalidParameter);
        quint16 unionTag = 0;
        if (!reader.u16(&unionTag) || unionTag != logonLevel)
            return refused(kStatusInvalidParameter);
        bool logonPresent = false;
        if (!reader.referent(&logonPresent) || !logonPresent)
            return refused(kStatusInvalidParameter);
    } else {
        QString serverName;
        quint16 unionTag = 0;
        bool logonPresent = false;
        if (!readUniqueString(reader, &serverName) || !readUniqueString(reader, &computerName)
            || !reader.u16(&logonLevel) || !reader.u16(&unionTag) || unionTag != logonLevel
            || !reader.referent(&logonPresent) || !logonPresent)
            return refused(kStatusInvalidParameter);
    }
    // The interactive (1) and service (3) classes carry netr_PasswordInfo: the
    // password's own one-way functions rather than a challenge and its
    // responses. The generic (4), ticket (8) and transitive (5/6/7) classes are
    // still refused.
    const bool passwordLogon = logonLevel == 1 || logonLevel == 3;
    if (!passwordLogon && logonLevel != 2 && logonLevel != 6)
        return refused(kStatusNotSupported);

    // NetrLogonSamLogon marshals the whole logon-information parameter before
    // validation_level: the union's arm referent, its fixed fields and every
    // deferred string and response come first (MS-NRPC 2.2.4.1 puts
    // validation_level after logon_information). Reading the level here used to
    // land in the identity's first length, so only a client that deferred those
    // strings past validation_level validated at all.
    NetworkLogon logon;
    PasswordLogon password;
    reader.align(4);
    if (passwordLogon) {
        if (!parsePasswordInfo(reader, &password))
            return refused(kStatusInvalidParameter);
    } else if (!parseNetworkInfo(reader, &logon)) {
        return refused(kStatusInvalidParameter);
    }
    const QString logonDomain = passwordLogon ? password.domain : logon.domain;
    const QString logonAccount = passwordLogon ? password.account : logon.account;
    const QString logonWorkstation = passwordLogon ? password.workstation : logon.workstation;

    quint32 flags = 0;
    if (!reader.u16(&validationLevel))
        return refused(kStatusInvalidParameter);
    if (withFlags && !reader.u32(&flags))
        return refused(kStatusInvalidParameter);
    if (!isPrintableName(logonDomain) || !isPrintableName(logonAccount)
        || !isPrintableName(logonWorkstation))
        return refused(kStatusInvalidParameter);
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("Netlogon: samlogon info at %d class=%u level=%u domain=%s account=%s",
                 reader.position(), logonLevel, validationLevel, qPrintable(logonDomain),
                 qPrintable(logonAccount));

    auto channel = m_channels.find(computerName.toLower());
    if (channel == m_channels.end())
        return refused(kStatusNoTrustSamAccount);
    if (withAuthenticator) {
        if (!hasAuthenticator)
            return refused(kStatusNoTrustSamAccount);
        if (!stepAuthenticator(&channel.value(), timestamp, requestCredential,
                               &returnCredential))
            return refused(kStatusAccessDenied);
    }

    QString domain = logonDomain;
    if (domain.isEmpty())
        domain = m_config.netbios;
    if (domain.compare(m_config.netbios, Qt::CaseInsensitive) != 0
        && domain.compare(m_config.realm, Qt::CaseInsensitive) != 0
        && domain.compare(m_config.dnsDomain, Qt::CaseInsensitive) != 0) {
        return refused(kStatusNoSuchUser);
    }

    const DirectoryObject account = findAccount(logonAccount);
    if (account.id.isEmpty())
        return refused(kStatusNoSuchUser);
    if (account.attributes.value(QStringLiteral("userAccountControl")).toUInt()
        & 0x00000002u) {
        return refused(kStatusAccountDisabled);
    }
    // The domain's lockout policy sits on the domain object, in AD's own
    // encoding: a negative 100-nanosecond interval for each duration, and a
    // threshold of zero for "count the refusal, never lock the account".
    quint32 lockoutThreshold = 0;
    quint64 lockoutDuration = 0;
    quint64 observationWindow = 0;
    for (const DirectoryObject &object : directory()) {
        if (object.kind != ObjectKind::Domain)
            continue;
        lockoutThreshold =
            object.attributes.value(QStringLiteral("lockoutThreshold")).toUInt();
        const qint64 duration =
            object.attributes.value(QStringLiteral("lockoutDuration")).toLongLong();
        const qint64 window =
            object.attributes.value(QStringLiteral("lockoutObservationWindow")).toLongLong();
        lockoutDuration = quint64(duration < 0 ? -duration : duration);
        observationWindow = quint64(window < 0 ? -window : window);
        break;
    }
    const quint64 now = ntTimeNow();
    const quint64 lockedAt = account.attributes.value(QStringLiteral("lockoutTime")).toULongLong();
    // A lockout lasts lockoutDuration; zero means until an administrator clears
    // it. Once it expires the account is open again and the counter restarts.
    const bool lockoutExpired =
        lockedAt != 0 && lockoutDuration != 0 && now > lockedAt + lockoutDuration;
    if (lockedAt != 0 && !lockoutExpired)
        return refused(kStatusAccountLockedOut);

    // A refused password is a counted failure: a Windows DC raises badPwdCount
    // and stamps badPasswordTime, and once the count reaches the domain's
    // threshold it stamps lockoutTime as well. A refusal older than the
    // observation window does not carry over, so the count restarts at one.
    // Only a well-formed response against a known account counts, so a
    // truncated request is an error rather than a strike.
    const auto countBadPassword = [this, &account, &lockoutThreshold, &observationWindow,
                                   lockoutExpired, now]() {
        quint64 count = account.attributes.value(QStringLiteral("badPwdCount")).toULongLong();
        const quint64 lastBad =
            account.attributes.value(QStringLiteral("badPasswordTime")).toULongLong();
        if (lockoutExpired
            || (observationWindow != 0 && lastBad != 0
                && now > lastBad + observationWindow)) {
            count = 0;
        }
        ++count;
        QMap<QString, QString> attributes;
        attributes.insert(QStringLiteral("badPwdCount"), QString::number(count));
        attributes.insert(QStringLiteral("badPasswordTime"), QString::number(now));
        if (lockoutThreshold != 0 && count >= lockoutThreshold)
            attributes.insert(QStringLiteral("lockoutTime"), QString::number(now));
        if (!m_writes.updateAccount)
            return;
        QString writeError;
        if (!m_writes.updateAccount(account.id, attributes, &writeError)
            && !qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE")) {
            qWarning("Netlogon: bad-password write for %s failed: %s", qPrintable(account.id),
                     qPrintable(writeError));
        }
    };

    QByteArray ntHash = QByteArray::fromHex(
        account.attributes.value(QStringLiteral("ntHash")).toLatin1());
    if (ntHash.size() != 16) {
        countBadPassword();
        return refused(kStatusWrongPassword);
    }
    if (passwordLogon) {
        // A password class proves the password by sending its own NT one-way
        // function, which is compared to the stored hash in constant time. The
        // LM function beside it is ignored rather than trusted: this store has
        // no LM hash to check it against, and a caller that sends only that
        // half is refused.
        //
        // The function does not travel in the clear: both halves arrive RC4-
        // ciphered under the channel's session key (MS-NRPC 3.1.4.4.1, the
        // netlogon password encryption; SAMR's password set uses the DES
        // transform instead), so they have to be unwrapped before the compare.
        Ntlm::Sealer sealer(channel.value().sessionKey);
        const QByteArray ntOwf = sealer.apply(password.ntOwf);
        if (ntOwf.size() != 16 || !constantTimeEquals(ntHash, ntOwf)) {
            countBadPassword();
            return refused(kStatusWrongPassword);
        }
    } else {
        if (logon.challenge.size() != 8 || logon.ntResponse.size() < 24)
            return refused(kStatusWrongPassword);
        // The same helper the SMB, RPC and LDAP acceptors use, so a network
        // logon from a client that predates NTLMv2 is judged by the domain's
        // own policy rather than by this pipe having its own rule. The session
        // keys go unused: nothing on this pipe signs with the logon's key.
        //
        // A network logon carries no negotiated flags, so the shape of the LM
        // response is what says which v1 variant arrived: eight bytes of client
        // challenge followed by sixteen zero bytes is NTLM2 session security,
        // and anything else is plain NTLMv1 over the challenge as sent. A v2
        // answer is unaffected by the bit either way.
        // An all-zero LM response is what a client with no LM hash sends, not a
        // client challenge of zero, so it stays on the plain v1 path; otherwise
        // such a client would be checked against the wrong seed.
        const bool sessionSecurity =
            logon.lmResponse.size() == 24
            && logon.lmResponse.mid(8) == QByteArray(16, '\0')
            && logon.lmResponse.left(8) != QByteArray(8, '\0');
        Ntlm::SessionKeys sessionKeys;
        const quint32 sessionFlags =
            Ntlm::kNegotiate128
            | (sessionSecurity ? Ntlm::kNegotiateExtendedSessionSecurity : 0u);
        if (!Ntlm::verifyResponse(ntHash, logonAccount, domain, logon.challenge,
                                  logon.ntResponse, logon.lmResponse, sessionFlags,
                                  m_lmCompatibilityLevel, &sessionKeys)) {
            countBadPassword();
            return refused(kStatusWrongPassword);
        }
    }

    // A correct password that has aged out is refused next, with the two codes
    // AD distinguishes: an expired password is STATUS_PASSWORD_EXPIRED and one an
    // administrator demanded be changed is STATUS_PASSWORD_MUST_CHANGE. Both mean
    // the password was right, so neither is a bad-password count.
    switch (PasswordAge::stateFor(account, directory())) {
    case PasswordAge::State::Expired:
        return refused(kStatusPasswordExpired);
    case PasswordAge::State::MustChange:
        return refused(kStatusPasswordMustChange);
    case PasswordAge::State::Valid:
        break;
    }

    // A correct password outside the account's logonHours is refused the way a
    // Windows DC refuses it, and no last-logon stamp is written for a logon
    // that did not happen.
    if (!LogonHours::allowsHex(account.attributes.value(QStringLiteral("logonHours")),
                               QDateTime::currentDateTimeUtc()))
        return refused(kStatusAccountRestriction);

    // The account may also name the workstations it logs on from. The list is
    // the directory's userWorkstations value and the name is the one the caller
    // put in NETLOGON_LOGON_INFO, so this is the only logon path where the
    // restriction can be checked against something on the wire. Like the week,
    // it sits after the password, so a wrong password is still answered as a
    // wrong password for a restricted account.
    if (!WorkstationRestriction::allows(
            account.attributes.value(QStringLiteral("userWorkstations")), logonWorkstation))
        return refused(kStatusInvalidWorkstation);

    // Record the logon the way a DC does. lastLogon is per-DC and always
    // updated; lastLogonTimestamp is the replicated value, refreshed only when
    // the stored one is older than the 14-day window (MS-ADTS 3.1.1.5.4), so a
    // busy account does not replicate on every logon.
    const quint64 logonTime = ntTimeNow();
    QMap<QString, QString> logonAttributes;
    logonAttributes.insert(QStringLiteral("lastLogon"), QString::number(logonTime));
    const quint64 previousLogonCount =
        account.attributes.value(QStringLiteral("logonCount")).toULongLong();
    logonAttributes.insert(QStringLiteral("logonCount"),
                           QString::number(previousLogonCount + 1));
    // A successful logon clears the failure counter; badPasswordTime keeps the
    // last refusal, as AD keeps it.
    logonAttributes.insert(QStringLiteral("badPwdCount"), QStringLiteral("0"));
    // A successful logon also lifts a lockout that has run its course, which is
    // what an administrator clearing the account does by hand.
    logonAttributes.insert(QStringLiteral("lockoutTime"), QStringLiteral("0"));
    const quint64 replicatedStamp =
        ntTimeAttribute(account, QStringLiteral("lastLogonTimestamp"));
    constexpr quint64 kFourteenDays = 14ull * 24 * 60 * 60 * 10000000ull;
    if (replicatedStamp == 0 || logonTime - replicatedStamp > kFourteenDays)
        logonAttributes.insert(QStringLiteral("lastLogonTimestamp"),
                               QString::number(logonTime));
    if (m_writes.updateAccount) {
        QString writeError;
        if (!m_writes.updateAccount(account.id, logonAttributes, &writeError)
            && !qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE")) {
            qWarning("Netlogon: last-logon write for %s failed: %s", qPrintable(account.id),
                     qPrintable(writeError));
        }
    }

    SamAnswer answer;
    answer.account = account.attributes.value(QStringLiteral("sAMAccountName"));
    answer.fullName = account.attributes.value(QStringLiteral("displayName"));
    if (answer.fullName.isEmpty())
        answer.fullName = account.attributes.value(QStringLiteral("cn"));
    answer.logonScript = account.attributes.value(QStringLiteral("scriptPath"));
    answer.profilePath = account.attributes.value(QStringLiteral("profilePath"));
    answer.homeDirectory = account.attributes.value(QStringLiteral("homeDirectory"));
    answer.homeDrive = account.attributes.value(QStringLiteral("homeDrive"));
    answer.rid = ridOf(account);
    answer.primaryGid = account.attributes.value(QStringLiteral("primaryGroupID")).toUInt();
    if (answer.primaryGid == 0)
        answer.primaryGid = 513;
    answer.acctFlags = account.attributes.value(QStringLiteral("userAccountControl")).toUInt();
    answer.logonTime = ntTimeNow();
    answer.logonCount = quint16(previousLogonCount + 1);
    // This logon cleared the failure counter, so the account it leaves behind
    // has none, whatever the copy read before the write.
    answer.badPasswordCount = 0;
    answer.lastPasswordChange = ntTimeAttribute(account, QStringLiteral("pwdLastSet"));
    answer.forcePasswordChange = kNeverNtTime;
    answer.lastSuccessfulLogon = ntTimeAttribute(account, QStringLiteral("lastLogon"));
    answer.logonServer = m_config.dcName;
    answer.logonDomain = m_config.netbios;
    answer.domainSid = Ndr::sidFromString(m_config.domainSid);
    answer.dnsDomain = m_config.dnsDomain;
    answer.principalName = QStringLiteral("%1@%2").arg(answer.account, m_config.realm);

    // The token's group list: the primary group first, then every group the
    // account is a member of, as MS-NRPC 2.2.4.2.3 orders it.
    answer.groups.append(qMakePair(answer.primaryGid, quint32(7)));
    for (const DirectoryObject &object : directory()) {
        if (object.kind != ObjectKind::Group)
            continue;
        const bool member = account.memberOf.contains(object.id, Qt::CaseInsensitive)
                            || object.members.contains(account.id, Qt::CaseInsensitive);
        if (!member)
            continue;
        const quint32 rid = ridOf(object);
        if (rid != 0 && rid != answer.primaryGid)
            answer.groups.append(qMakePair(rid, quint32(7)));
    }

    quint32 status = kStatusSuccess;
    QByteArray validationDeferred;
    QByteArray validationFixed = samValidation(answer, validationLevel, &validationDeferred,
                                               &status);
    if (status != kStatusSuccess)
        return refused(status);

    QByteArray out;
    if (withAuthenticator) {
        putLe32(out, returnAuthenticatorPresent ? 0x0002f210u : 0u);
        if (returnAuthenticatorPresent) {
            out.append(returnCredential);
            putLe32(out, timestamp);
        }
    }
    putLe16(out, validationLevel); // switch_is discriminator for netr_Validation
    alignTo(out, 4);
    putLe32(out, 0x0002f200u); // NETLOGON_VALIDATION_SAM_INFO2 pointer referent
    // The union is a single parameter, so its pointer's referent — the SAM_INFO2
    // fixed part and every deferred string and array it carries — is
    // marshalled before the fields that follow the union.
    out.append(validationFixed);
    out.append(validationDeferred);
    out.append(char(1)); // authoritative
    if (withFlags) {
        alignTo(out, 4);
        putLe32(out, flags); // ExtraFlags, which follows Authoritative
    }
    alignTo(out, 4);
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("LogonSamLogon%1(%2\\%3: ok)")
                             .arg(withFlags ? QStringLiteral("WithFlags") : QString())
                             .arg(domain, logonAccount));
    return out;
}

// NetrGetAnyDCName: the Windows 2000-era locator a workstation calls when it
// knows only the domain. Any DC in a served domain is a correct answer, so it
// is this one; a domain this DC does not serve is ERROR_NO_SUCH_DOMAIN.
QByteArray NetlogonServer::getAnyDcName(const QByteArray &stub)
{
    constexpr quint32 kErrorNoSuchDomain = 1355;
    Ndr::Reader reader(stub);
    QString logonServer;
    QString domain;
    if (!readUniqueString(reader, &logonServer) || !readUniqueString(reader, &domain))
        return statusOnly(kStatusInvalidParameter);
    Q_UNUSED(logonServer)
    const bool served = domain.compare(m_config.netbios, Qt::CaseInsensitive) == 0
                        || domain.compare(m_config.realm, Qt::CaseInsensitive) == 0
                        || domain.compare(m_config.dnsDomain, Qt::CaseInsensitive) == 0;
    QByteArray out;
    if (!served) {
        putLe32(out, 0); // NULL dcname
        putLe32(out, kErrorNoSuchDomain);
        emit requestReceived(QStringLiteral("GetAnyDCName(%1): no such domain").arg(domain));
        return out;
    }
    const QString name = QStringLiteral("\\\\%1").arg(m_config.dcName);
    putLe32(out, 0x00020001u);
    out.append(stringArray(name));
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("GetAnyDCName(%1) = %2").arg(domain, name));
    return out;
}

// NetrDsRGetSiteName: the site a computer belongs to. One site is defined, so
// every computer is in it.
QByteArray NetlogonServer::dsrGetSiteName(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString computer;
    if (!readUniqueString(reader, &computer))
        return statusOnly(kStatusInvalidParameter);
    Q_UNUSED(computer)
    QString site = m_config.siteName;
    if (site.isEmpty())
        site = QStringLiteral("Default-First-Site-Name");
    QByteArray out;
    putLe32(out, 0x00020001u);
    out.append(stringArray(site));
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("DsRGetSiteName = %1").arg(site));
    return out;
}

// NetrDsrEnumerateDomainTrusts (MS-NRPC 3.5.4.4.8): the domains in this
// forest. This server holds one domain and no trusts, so the list is empty, but
// the answer is still the whole netr_DomainTrustList — the count and the array
// pointer — because a client that receives only a WERROR cannot unmarshal it
// (a Windows 2000 join reports "The stub received bad data").
QByteArray NetlogonServer::dsrEnumerateDomainTrusts(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverName;
    if (!readUniqueString(reader, &serverName))
        return statusOnly(kStatusInvalidParameter);
    quint32 flags = 0;
    reader.u32(&flags);
    Q_UNUSED(flags)
    QByteArray out;
    // [out,ref] puts the list itself inline: a reference pointer has no
    // referent id, so the first word is the count rather than a pointer. A
    // referent here reads to the client as a count of 193280 and a long frame.
    putLe32(out, 0); // count
    putLe32(out, 0); // NULL array
    putLe32(out, 0); // WERROR
    emit requestReceived(QStringLiteral("DsrEnumerateDomainTrusts: 0 trusts"));
    return out;
}

// NetrLogonGetTrustRid (MS-NRPC 3.5.4.4.6): the RID of the account the trust
// keeps in this domain, which is the `FABRIKAM$` account LSAD created beside
// the trustedDomain object. A caller that names a domain this DC has no trust
// with gets ERROR_NO_SUCH_DOMAIN, as Windows answers.
QByteArray NetlogonServer::logonGetTrustRid(const QByteArray &stub)
{
    constexpr quint32 kErrorNoSuchDomain = 1355;
    Ndr::Reader reader(stub);
    QString serverName;
    QString domainName;
    if (!readUniqueString(reader, &serverName) || !readUniqueString(reader, &domainName))
        return statusOnly(kStatusInvalidParameter);
    Q_UNUSED(serverName)
    QString flat;
    for (const DirectoryObject &object : directory()) {
        if (!object.attributes.value(QStringLiteral("objectClass"))
                 .contains(QLatin1String("trustedDomain"), Qt::CaseInsensitive))
            continue;
        flat = object.attributes.value(QStringLiteral("flatName"));
        const QString partner = object.attributes.value(QStringLiteral("trustPartner"));
        if (flat.compare(domainName, Qt::CaseInsensitive) == 0
            || partner.compare(domainName, Qt::CaseInsensitive) == 0
            || partner.section(QLatin1Char('.'), 0, 0)
                   .compare(domainName, Qt::CaseInsensitive)
                   == 0)
            break;
        flat.clear();
    }
    if (flat.isEmpty())
        return statusOnly(kErrorNoSuchDomain);
    const DirectoryObject account = findAccount(flat + QLatin1Char('$'));
    if (account.id.isEmpty()) {
        emit requestReceived(QStringLiteral("GetTrustRid(%1): no trust account").arg(flat));
        return statusOnly(kErrorNoSuchDomain);
    }
    QByteArray out;
    putLe32(out, ridOf(account));
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("GetTrustRid(%1) = %2").arg(flat).arg(ridOf(account)));
    return out;
}

QByteArray NetlogonServer::getDcName(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString logonServer;
    QString domain;
    if (!readStringArray(reader, &logonServer))
        return statusOnly(kStatusInvalidParameter);
    if (!readUniqueString(reader, &domain))
        return statusOnly(kStatusInvalidParameter);
    if (!domain.isEmpty() && domain.compare(m_config.netbios, Qt::CaseInsensitive) != 0
        && domain.compare(m_config.dnsDomain, Qt::CaseInsensitive) != 0) {
        return statusOnly(kStatusNoSuchUser);
    }
    QByteArray out;
    putLe32(out, 0x0002f300u); // dcname referent
    out.append(stringArray(QStringLiteral("\\\\") + m_config.dcName.toUpper()));
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("GetDcName(%1)").arg(m_config.dcName));
    return out;
}

QByteArray NetlogonServer::dsrGetDcNameEx2(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QString serverUnc;
    QString clientAccount;
    QString domainName;
    QString siteName;
    quint32 mask = 0;
    quint32 flags = 0;
    if (!readUniqueString(reader, &serverUnc))
        return statusOnly(kStatusInvalidParameter);
    if (!readUniqueString(reader, &clientAccount))
        return statusOnly(kStatusInvalidParameter);
    if (!reader.u32(&mask))
        return statusOnly(kStatusInvalidParameter);
    if (!readUniqueString(reader, &domainName))
        return statusOnly(kStatusInvalidParameter);
    bool hasGuid = false;
    if (!reader.referent(&hasGuid))
        return statusOnly(kStatusInvalidParameter);
    if (hasGuid && !reader.skip(16))
        return statusOnly(kStatusInvalidParameter);
    if (!readUniqueString(reader, &siteName))
        return statusOnly(kStatusInvalidParameter);
    if (!reader.u32(&flags))
        return statusOnly(kStatusInvalidParameter);
    Q_UNUSED(serverUnc)
    Q_UNUSED(clientAccount)
    Q_UNUSED(mask)

    if (!domainName.isEmpty() && domainName.compare(m_config.netbios, Qt::CaseInsensitive) != 0
        && domainName.compare(m_config.dnsDomain, Qt::CaseInsensitive) != 0
        && domainName.compare(m_config.realm, Qt::CaseInsensitive) != 0) {
        return statusOnly(kStatusNoSuchUser);
    }

    QByteArray fixed;
    QByteArray deferred;
    putLe32(fixed, 0x0002f400u); // info: the [ref] **info's inner pointer
    putLe32(fixed, 0x0002f401u); // dc_unc
    putLe32(fixed, 0x0002f402u); // dc_address
    putLe32(fixed, 1);           // DS_ADDRESS_TYPE_INET
    fixed.append(domainGuid(m_config.domainSid));
    putLe32(fixed, 0x0002f403u); // domain_name
    putLe32(fixed, 0x0002f404u); // forest_name
    putLe32(fixed, kNbtServerType);
    putLe32(fixed, 0x0002f405u); // dc_site_name
    putLe32(fixed, 0x0002f406u); // client_site_name

    const QString site = siteName.isEmpty() ? m_config.siteName : siteName;
    deferred.append(stringArray(QStringLiteral("\\\\") + m_config.dcHost));
    deferred.append(stringArray(m_config.dcIp));
    deferred.append(stringArray(m_config.dnsDomain));
    deferred.append(stringArray(m_config.dnsDomain));
    deferred.append(stringArray(site));
    deferred.append(stringArray(site));

    QByteArray out = fixed + deferred;
    putLe32(out, kStatusSuccess);
    emit requestReceived(QStringLiteral("DsRGetDCNameEx2(%1)").arg(m_config.dcHost));
    return out;
}

QByteArray NetlogonServer::handleCall(quint16 opnum, const QByteArray &stub,
                                      const QString &clientUser)
{
    Q_UNUSED(clientUser)
    switch (opnum) {
    case Netlogon::OpServerReqChallenge:
        return serverReqChallenge(stub);
    case Netlogon::OpServerAuthenticate2:
    case Netlogon::OpServerAuthenticate3:
    case Netlogon::OpServerAuthenticate:
        return serverAuthenticate(stub, opnum);
    case Netlogon::OpServerPasswordSet2:
        return serverPasswordSet2(stub);
    case Netlogon::OpLogonGetCapabilities:
        return logonGetCapabilities(stub);
    case Netlogon::OpLogonSamLogonEx:
        return samLogon(stub, false, true);
    case Netlogon::OpGetAnyDCName:
        return getAnyDcName(stub);
    case Netlogon::OpDsRGetSiteName:
        return dsrGetSiteName(stub);
    case Netlogon::OpDsrEnumerateDomainTrusts:
        return dsrEnumerateDomainTrusts(stub);
    case Netlogon::OpLogonGetTrustRid:
        return logonGetTrustRid(stub);
    case Netlogon::OpGetDcName:
        return getDcName(stub);
    case Netlogon::OpDsRGetDcNameEx2:
        return dsrGetDcNameEx2(stub);
    case Netlogon::OpLogonSamLogon:
        return samLogon(stub, true, false);
    case Netlogon::OpLogonSamLogonWithFlags:
        return samLogon(stub, true, true);
    case Netlogon::OpLogonGetDomainInfo:
        return logonGetDomainInfo(stub);
    default:
        emit requestReceived(QStringLiteral("opnum %1 unsupported").arg(opnum));
        return statusOnly(kStatusNotSupported);
    }
}
