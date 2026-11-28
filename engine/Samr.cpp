// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Samr.h"

#include <QCryptographicHash>
#include <QRandomGenerator>

#include <algorithm>
#include <limits>
#include <QStringList>
#include <QDebug>

#include "Des.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ndr.h"
#include "PasswordAge.h"

namespace {

// NTSTATUS values MS-SAMR uses.
constexpr quint32 kStatusSuccess = 0x00000000u;
constexpr quint32 kStatusInvalidHandle = 0xc0000008u;
constexpr quint32 kStatusAccessDenied = 0xc0000022u;
constexpr quint32 kStatusNoSuchDomain = 0xc00000dfu;
constexpr quint32 kStatusUserExists = 0xc0000063u;
constexpr quint32 kStatusNoSuchUser = 0xc0000064u;
constexpr quint32 kStatusGroupExists = 0xc0000065u;
constexpr quint32 kStatusNoSuchGroup = 0xc0000066u;
constexpr quint32 kStatusMemberInGroup = 0xc0000067u;
constexpr quint32 kStatusMemberNotInGroup = 0xc0000068u;
constexpr quint32 kStatusInvalidParameter = 0xc000000du;
constexpr quint32 kStatusInvalidInfoClass = 0xc0000003u;
constexpr quint32 kStatusPasswordRestriction = 0xc000006cu;
constexpr quint32 kStatusNotSupported = 0xc00000bbu;
constexpr quint32 kStatusMoreEntries = 0x00000105u;
constexpr quint32 kStatusSomeNotMapped = 0x00000107u;
constexpr quint32 kStatusNoneMapped = 0xc0000073u;
constexpr quint32 kStatusAliasExists = 0xc0000155u;
constexpr quint32 kStatusNoSuchAlias = 0xc0000156u;
constexpr quint32 kStatusMemberInAlias = 0xc0000157u;
constexpr quint32 kStatusMemberNotInAlias = 0xc0000158u;
constexpr quint32 kStatusInvalidMember = 0xc0000178u;

// A SAMPR_HANDLE is a 20-byte context handle: a 16-byte id and a 4-byte
// server-side pointer that clients must not interpret.
constexpr int kHandleSize = 20;

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16) | (quint32(quint8(data.at(pos + 3))) << 24);
}

void putLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

// A varying, conformant UTF-16 string as NDR writes it: max_count, offset,
// actual_count, then the characters padded to a 4-byte boundary. Every SAMR
// caller pairs this with an lsa_String header whose size excludes the
// terminator, so the maximum count must too (see Lsad's appendVaryingChars).
void appendVaryingString(QByteArray &out, const QString &text)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    putLe32(out, quint32(text.size())); // MaximumCount
    putLe32(out, 0);                    // Offset
    putLe32(out, quint32(text.size())); // ActualCount
    out.append(utf16);
    while (out.size() % 4 != 0)
        out.append('\0');
}

// SamrCreateUser2InDomain's AccountType is a SAM_ACCOUNT_TYPE, not a set of
// userAccountControl bits: a plain user is 0x10 there and 0x200 here, a
// workstation trust 0x80 against 0x1000. Copying the value across stores an
// account that means something else — 128 is PASSWD_NOTREQD, not
// WORKSTATION_TRUST — and the directory then has no computer for the machine
// that joined, so `(objectClass=computer)` misses it and Netlogon has no
// workstation trust to open a secure channel against.
quint32 accountControlFor(quint32 accountType)
{
    switch (accountType) {
    case 0x08: return 0x0100;       // USER_TEMP_DUPLICATE_ACCOUNT
    case 0x10: return 0x0200;       // USER_NORMAL_ACCOUNT
    case 0x20: return 0x020000;     // USER_MNS_LOGON_ACCOUNT
    case 0x40: return 0x0800;       // USER_INTERDOMAIN_TRUST_ACCOUNT
    case 0x80: return 0x1000;       // USER_WORKSTATION_TRUST_ACCOUNT
    case 0x100: return 0x2000;      // USER_SERVER_TRUST_ACCOUNT
    case 0x100000: return 0x4000000; // USER_PARTIAL_SECRETS_ACCOUNT
    default:
        // Zero is what a client that predates the account type sends, and AD
        // makes a plain user of it.
        return 0x0200;
    }
}

// The other direction of the same problem: SAMR's acct_flags and AD's
// userAccountControl are different bit sets that coincide only in their low
// digits. A guest reads "Account active", the account type and "password never
// expires" off this word, so copying the directory value across told it that a
// plain user's password never expires (0x200 here is ACB_PWNOEXP, there is
// NORMAL_ACCOUNT) and left the type bits clear.
quint32 accountFlagsFor(quint32 control)
{
    quint32 flags = 0;
    if (control & 0x00000002u)
        flags |= 0x00000001u; // ACCOUNTDISABLE -> ACB_DISABLED
    if (control & 0x00000008u)
        flags |= 0x00000002u; // HOMEDIR_REQUIRED -> ACB_HOMDIRREQ
    if (control & 0x00000020u)
        flags |= 0x00000004u; // PASSWD_NOTREQD -> ACB_PWNOTREQ
    if (control & 0x00000100u)
        flags |= 0x00000008u; // TEMP_DUPLICATE_ACCOUNT -> ACB_TEMPDUP
    if (control & 0x00000200u)
        flags |= 0x00000010u; // NORMAL_ACCOUNT -> ACB_NORMAL
    if (control & 0x00020000u)
        flags |= 0x00000020u; // MNS_LOGON_ACCOUNT -> ACB_MNS
    if (control & 0x00000800u)
        flags |= 0x00000040u; // INTERDOMAIN_TRUST_ACCOUNT -> ACB_DOMTRUST
    if (control & 0x00001000u)
        flags |= 0x00000080u; // WORKSTATION_TRUST_ACCOUNT -> ACB_WSTRUST
    if (control & 0x00002000u)
        flags |= 0x00000100u; // SERVER_TRUST_ACCOUNT -> ACB_SVRTRUST
    if (control & 0x00010000u)
        flags |= 0x00000200u; // DONT_EXPIRE_PASSWORD -> ACB_PWNOEXP
    if (control & 0x00000080u)
        flags |= 0x00000800u; // ENCRYPTED_TEXT_PWD_ALLOWED -> ACB_ENC_TXT_PWD_ALLOWED
    if (control & 0x00040000u)
        flags |= 0x00001000u; // SMARTCARD_REQUIRED -> ACB_SMARTCARD_REQUIRED
    if (control & 0x00080000u)
        flags |= 0x00002000u; // TRUSTED_FOR_DELEGATION -> ACB_TRUSTED_FOR_DELEGATION
    if (control & 0x00100000u)
        flags |= 0x00004000u; // NOT_DELEGATED -> ACB_NOT_DELEGATED
    if (control & 0x00200000u)
        flags |= 0x00008000u; // USE_DES_KEY_ONLY -> ACB_USE_DES_KEY_ONLY
    if (control & 0x00400000u)
        flags |= 0x00010000u; // DONT_REQUIRE_PREAUTH -> ACB_DONT_REQUIRE_PREAUTH
    if (control & 0x00800000u)
        flags |= 0x00020000u; // PASSWORD_EXPIRED -> ACB_PW_EXPIRED
    if (control & 0x01000000u)
        flags |= 0x00040000u; // TRUSTED_TO_AUTH_FOR_DELEGATION
    if (control & 0x04000000u)
        flags |= 0x00100000u; // PARTIAL_SECRETS_ACCOUNT
    // Every account the directory holds is one of the types, and a value that
    // names none is still an ordinary user rather than an account of no kind.
    if ((flags & 0x000001f8u) == 0)
        flags |= 0x00000010u; // ACB_NORMAL
    return flags;
}

// The account-type bits of a SAMR acct_flags word, in the directory's
// numbering: TEMP_DUPLICATE 0x100, NORMAL 0x200, INTERDOMAIN_TRUST 0x800,
// WORKSTATION_TRUST 0x1000, SERVER_TRUST 0x2000.
constexpr quint32 kAccountTypeBits = 0x00003f00u;

// A written acct_flags word back into the directory's userAccountControl. A
// client that names no account type is still describing the account it opened,
// so the type it already has is kept rather than cleared.
quint32 accountControlFromFlags(quint32 flags, quint32 stored)
{
    quint32 control = 0;
    if (flags & 0x00000001u)
        control |= 0x00000002u; // ACB_DISABLED -> ACCOUNTDISABLE
    if (flags & 0x00000002u)
        control |= 0x00000008u; // ACB_HOMDIRREQ -> HOMEDIR_REQUIRED
    if (flags & 0x00000004u)
        control |= 0x00000020u; // ACB_PWNOTREQ -> PASSWD_NOTREQD
    if (flags & 0x00000008u)
        control |= 0x00000100u; // ACB_TEMPDUP -> TEMP_DUPLICATE_ACCOUNT
    if (flags & 0x00000010u)
        control |= 0x00000200u; // ACB_NORMAL -> NORMAL_ACCOUNT
    if (flags & 0x00000020u)
        control |= 0x00020000u; // ACB_MNS -> MNS_LOGON_ACCOUNT
    if (flags & 0x00000040u)
        control |= 0x00000800u; // ACB_DOMTRUST -> INTERDOMAIN_TRUST_ACCOUNT
    if (flags & 0x00000080u)
        control |= 0x00001000u; // ACB_WSTRUST -> WORKSTATION_TRUST_ACCOUNT
    if (flags & 0x00000100u)
        control |= 0x00002000u; // ACB_SVRTRUST -> SERVER_TRUST_ACCOUNT
    if (flags & 0x00000200u)
        control |= 0x00010000u; // ACB_PWNOEXP -> DONT_EXPIRE_PASSWORD
    if (flags & 0x00000800u)
        control |= 0x00000080u; // ACB_ENC_TXT_PWD_ALLOWED -> ENCRYPTED_TEXT_PWD_ALLOWED
    if (flags & 0x00001000u)
        control |= 0x00040000u; // ACB_SMARTCARD_REQUIRED -> SMARTCARD_REQUIRED
    if (flags & 0x00002000u)
        control |= 0x00080000u; // ACB_TRUSTED_FOR_DELEGATION
    if (flags & 0x00004000u)
        control |= 0x00100000u; // ACB_NOT_DELEGATED -> NOT_DELEGATED
    if (flags & 0x00008000u)
        control |= 0x00200000u; // ACB_USE_DES_KEY_ONLY -> USE_DES_KEY_ONLY
    if (flags & 0x00010000u)
        control |= 0x00400000u; // ACB_DONT_REQUIRE_PREAUTH -> DONT_REQUIRE_PREAUTH
    if (flags & 0x00020000u)
        control |= 0x00800000u; // ACB_PW_EXPIRED -> PASSWORD_EXPIRED
    if (flags & 0x00040000u)
        control |= 0x01000000u; // ACB_TRUSTED_TO_AUTH_FOR_DELEGATION
    if (flags & 0x00100000u)
        control |= 0x04000000u; // ACB_PARTIAL_SECRETS_ACCOUNT
    if ((control & kAccountTypeBits) == 0)
        control |= stored & kAccountTypeBits;
    return control;
}

// SID_NAME_USE as MS-SAMR reports it for a relative identifier.
bool isAlias(const DirectoryObject &object);

quint32 nameTypeFor(const DirectoryObject &object)
{
    if (object.kind == ObjectKind::Group)
        return isAlias(object) ? 4 : 2; // SidTypeAlias : SidTypeGroup
    if (object.kind == ObjectKind::Computer)
        return 9; // SidTypeComputer — 8 is SidTypeUnknown, which no mapped name is
    return 1;     // SidTypeUser
}

quint32 ridOf(const DirectoryObject &object)
{
    const QStringList parts =
        object.attributes.value(QStringLiteral("objectSid")).split(QLatin1Char('-'));
    return parts.isEmpty() ? 0 : parts.last().toUInt();
}

// AD stores the two SAMR name spaces as one: a group whose groupType has
// GROUP_TYPE_RESOURCE_GROUP (0x4) is a domain-local group, which SAMR calls an
// alias; the global and universal groups are the ones SAMR calls groups.
bool isAlias(const DirectoryObject &object)
{
    if (object.kind != ObjectKind::Group)
        return false;
    bool numeric = false;
    const qint64 type = object.attributes.value(QStringLiteral("groupType")).toLongLong(&numeric);
    return numeric && (type & 0x4) != 0;
}

// The BUILTIN domain (S-1-5-32) is the second domain every DC reports. Its
// aliases are the well-known local groups Windows seeds at install, and their
// SIDs appear in ACLs on every machine. AD keeps them in a naming context of
// their own, so this server synthesises them from the same table Lsad.cpp
// resolves instead of storing them in the account NC, and refuses writes to
// them: there is nowhere to persist one, and accepting it would lose it.
const QString kBuiltinDomainSid = QStringLiteral("S-1-5-32");

struct BuiltinAlias {
    const char *name;
    quint32 rid;
};

const QList<BuiltinAlias> &builtinAliasTable()
{
    static const QList<BuiltinAlias> table = {
        {"Administrators", 544},                {"Users", 545},
        {"Guests", 546},                        {"Power Users", 547},
        {"Account Operators", 548},             {"Server Operators", 549},
        {"Print Operators", 550},               {"Backup Operators", 551},
        {"Replicator", 552},                    {"Remote Desktop Users", 555},
        {"Network Configuration Operators", 556}, {"Performance Monitor Users", 558},
        {"Performance Log Users", 559},         {"IIS_IUSRS", 568},
        {"Event Log Readers", 573},             {"Certificate Service DCOM Access", 574},
    };
    return table;
}

// The aliases in the shape the enumeration and the lookups already take, so the
// BUILTIN domain needs no second code path through them. groupType carries
// GROUP_TYPE_RESOURCE_GROUP, which is what makes them aliases and not groups.
QList<DirectoryObject> builtinAliasObjects(const QList<DirectoryObject> &stored)
{
    QList<DirectoryObject> result;
    for (const BuiltinAlias &entry : builtinAliasTable()) {
        DirectoryObject object;
        object.id = QStringLiteral("%1-%2").arg(kBuiltinDomainSid).arg(entry.rid);
        object.name = QString::fromLatin1(entry.name);
        object.type = QStringLiteral("Group");
        object.kind = ObjectKind::Group;
        object.attributes.insert(QStringLiteral("objectSid"), object.id);
        object.attributes.insert(QStringLiteral("sAMAccountName"), object.name);
        object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("4"));
        // The memberships this directory keeps for the alias, when it keeps them:
        // the stored object under CN=Builtin is what a write lands on, and what
        // it holds is added to the memberships AD seeds. The SID stays the
        // well-known one, because that is the name every ACL on the machine uses.
        for (const DirectoryObject &candidate : stored) {
            if (!candidate.id.contains(QStringLiteral(",CN=Builtin,"), Qt::CaseInsensitive))
                continue;
            const bool sameSid =
                candidate.attributes.value(QStringLiteral("objectSid"))
                    .compare(object.id, Qt::CaseInsensitive) == 0;
            const bool sameName =
                candidate.attributes.value(QStringLiteral("sAMAccountName"))
                    .compare(object.name, Qt::CaseInsensitive) == 0;
            if (!sameSid && !sameName)
                continue;
            object.members = candidate.members;
            object.attributes.insert(QStringLiteral("description"),
                                     candidate.attributes.value(QStringLiteral("description")));
            break;
        }
        result.append(object);
    }
    return result;
}

bool isBuiltinAlias(const QString &dn)
{
    return dn.startsWith(kBuiltinDomainSid + QLatin1Char('-'));
}

// What AD seeds each BUILTIN alias with when a domain is created: its own
// groups, plus the two runtime identities Windows puts in Users. A group is
// listed only when the directory holds it, so a directory without Domain Admins
// reports an empty Administrators rather than a member nobody has.
// The SIDs of the given member DNs, for memberships this directory stores.
QList<QByteArray> memberSids(const QStringList &members, const QList<DirectoryObject> &objects)
{
    QList<QByteArray> sids;
    for (const QString &member : members) {
        for (const DirectoryObject &candidate : objects) {
            if (candidate.id.compare(member, Qt::CaseInsensitive) != 0)
                continue;
            const QByteArray sid = Ndr::sidFromString(
                candidate.attributes.value(QStringLiteral("objectSid")));
            if (!sid.isEmpty())
                sids.append(sid);
            break;
        }
    }
    return sids;
}

QList<QByteArray> builtinMemberSids(quint32 rid, const QString &domainSid,
                                    const QList<DirectoryObject> &objects,
                                    const QStringList &storedMembers = {})
{
    QList<QByteArray> sids;
    QList<quint32> seeded;
    if (rid == 544)
        seeded.append(512); // Administrators <- Domain Admins
    else if (rid == 545)
        seeded.append(513); // Users <- Domain Users
    else if (rid == 546)
        seeded.append(514); // Guests <- Domain Guests
    for (quint32 seededRid : seeded) {
        const QString text = QStringLiteral("%1-%2").arg(domainSid).arg(seededRid);
        for (const DirectoryObject &object : objects) {
            if (object.attributes.value(QStringLiteral("objectSid")) != text)
                continue;
            const QByteArray sid = Ndr::sidFromString(text);
            if (!sid.isEmpty())
                sids.append(sid);
            break;
        }
    }
    if (rid == 545) {
        for (const char *text : {"S-1-5-11", "S-1-5-4"}) {
            const QByteArray sid = Ndr::sidFromString(QString::fromLatin1(text));
            if (!sid.isEmpty())
                sids.append(sid);
        }
    }
    // A membership written since is reported alongside the seed ones, once: the
    // seeded groups are members through the table and would otherwise appear
    // twice to a client that added one of them explicitly.
    for (const QByteArray &sid : memberSids(storedMembers, objects)) {
        if (!sids.contains(sid))
            sids.append(sid);
    }
    return sids;
}


// RPC_SID as MS-RPCE carries it: the sub-authority count is a conformant array
// length, so it comes before the fixed header, then the header and the
// sub-authorities. Ndr::writeSid omits that count, which is the shape LSAD's
// inline SIDs use, so the alias calls marshal their own.
void putWireSid(QByteArray &out, const QByteArray &sid)
{
    const quint8 count = sid.size() >= 8 ? quint8(sid.at(1)) : 0;
    putLe32(out, quint32(count));
    out.append(sid.left(8));
    out.append(sid.mid(8, count * 4));
}

bool readWireSid(Ndr::Reader &reader, QByteArray *sid)
{
    quint32 maximum = 0;
    QByteArray header;
    if (!reader.u32(&maximum) || !reader.bytes(8, &header))
        return false;
    const quint8 count = quint8(header.at(1));
    if (maximum < count)
        return false;
    QByteArray out = header;
    for (quint8 i = 0; i < count; ++i) {
        QByteArray sub;
        if (!reader.bytes(4, &sub))
            return false;
        out.append(sub);
    }
    if (sid)
        *sid = out;
    return true;
}

// A referent is the offset of its pointee from the start of the stub (MS-RPCE
// 2.2.10.6), and a client resolves a pointer as stub + referent. Values that are
// merely unique — 0x0002e100 and the like — read fine through a client that
// walks the reply in order and put a Windows stub outside the buffer it was
// given, which is how a 2000 member answered a lookup that carried a zero
// status.
void setLe32(QByteArray &data, int pos, quint32 value)
{
    for (int i = 0; i < 4; ++i)
        data[pos + i] = char((value >> (8 * i)) & 0xff);
}

// MS-SAMR 2.2.11.1: a samr_CryptPassword holds the UTF-16LE password padded to
// 512 bytes with its length in bytes in the last four, RC4-ciphered under the
// RPC session key. samr_CryptPasswordEx appends a 16-byte confounder and keys
// the same cipher with MD5(confounder || session key), which is what Samba's
// samba_gnutls_arcfour_confounded_md5 does.
bool decodeCryptPassword(const QByteArray &payload, const QByteArray &sessionKey, bool salted,
                         QString *password, QString *error)
{
    const int size = salted ? 532 : 516;
    if (payload.size() < size) {
        if (error)
            *error = QStringLiteral("password buffer is %1 bytes, expected %2")
                         .arg(payload.size())
                         .arg(size);
        return false;
    }
    if (sessionKey.isEmpty()) {
        if (error)
            *error = QStringLiteral("no session key: the call was not authenticated");
        return false;
    }
    QByteArray key = sessionKey;
    if (salted) {
        key = QCryptographicHash::hash(payload.mid(516, 16) + sessionKey,
                                       QCryptographicHash::Md5);
    }
    const QByteArray plain = Krb5::rc4(key, payload.left(516));
    const quint32 length = readLe32(plain, 512);
    if (length > 512 || length % 2 != 0) {
        if (error)
            *error = QStringLiteral("password length %1 is not a UTF-16 string")
                         .arg(length);
        return false;
    }
    // The password sits at the end of the buffer, not the start: MS-SAMR's
    // buffer is 512 bytes of left padding followed by the UTF-16 password, with
    // its length in the last four bytes (Samba's extract_pw_from_buffer does the
    // same subtraction).
    const int start = 512 - int(length);
    *password = QString::fromUtf16(
        reinterpret_cast<const char16_t *>(plain.constData() + start), qsizetype(length / 2));
    return true;
}

// SAMPR_USER_ALL_INFORMATION (MS-SAMR 2.2.7.6): six NTTIMEs, thirteen counted
// strings, the security-descriptor and logon-hours pointers, four ULONGs, four
// USHORTs and four UCHARs. Every pointed-to buffer is deferred behind the whole
// structure in field order, so the arm is a fixed 196 bytes (48 + 13*8 + 8 +
// 16 + 8 + 8 + 4).
struct AllUserInfo {
    quint64 lastLogon = 0;
    quint64 lastLogoff = 0;
    quint64 passwordLastSet = 0;
    quint64 accountExpires = 0;
    quint64 passwordCanChange = 0;
    quint64 passwordMustChange = 0;
    QString userName;
    QString fullName;
    QString homeDirectory;
    QString homeDrive;
    QString scriptPath;
    QString profilePath;
    QString adminComment;
    QString workstations;
    QString userComment;
    QString parameters;
    quint32 userId = 0;
    quint32 primaryGroupId = 0;
    quint32 accountControl = 0; // AD's userAccountControl, which the policy uses
    quint32 accountFlags = 0;    // the same state in SAMR's acct_flags numbering
    quint32 fieldsPresent = 0;
    quint16 badPasswordCount = 0;
    quint16 logonCount = 0;
    quint16 countryCode = 0;
    quint16 codePage = 0;
    bool ntPasswordPresent = false;
    bool passwordExpired = false;
    // The week as the directory stores it: 21 bytes, one bit per hour. Empty
    // means the account has no restriction, which is what AD reports for an
    // object that never had a logonHours value.
    QByteArray logonHours;
};

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe64(QByteArray &out, quint64 value)
{
    putLe32(out, quint32(value & 0xffffffffu));
    putLe32(out, quint32((value >> 32) & 0xffffffffu));
}

// The week as SAMR carries it: 21 bytes for 168 hours, all of them allowed
// when the account has no logonHours value.
QByteArray logonHoursForWire(const QByteArray &stored)
{
    if (stored.size() == 21)
        return stored;
    QByteArray hours(21, char(0xff));
    if (!stored.isEmpty())
        hours.replace(0, qMin(21, int(stored.size())), stored.left(21));
    return hours;
}

// An RPC_UNICODE_STRING as it appears inside a structure: Length,
// MaximumLength and a pointer to characters written after the structure. An
// empty string is the NULL pointer AD sends for an attribute that is not set.
// The pointer's value is not known until the characters have been placed, so it
// is recorded here as {stub position, offset within the character blob} and
// filled in by appendArmWithStrings.
void appendCountedString(QByteArray &out, QByteArray &deferred, const QString &text,
                         QList<QPair<int, int>> &strings)
{
    const bool present = !text.isEmpty();
    const QByteArray utf16 = Ndr::utf16le(text);
    putLe16(out, quint16(utf16.size()));
    putLe16(out, quint16(utf16.size()));
    if (!present) {
        putLe32(out, 0);
        return;
    }
    strings.append(qMakePair(int(out.size()), int(deferred.size())));
    putLe32(out, 0); // patched once the blob is placed
    appendVaryingString(deferred, text);
}

// A counted string a WhichFields bit names present, even when it is empty: the
// pointer is never NULL, and an empty value is a conformant array of no
// characters (max 0, offset 0, actual 0). MS-SAMR 3.1.5.5.5.2 obliges a server
// to carry every field it names, and a DC's own answer gives such a field a
// buffer rather than a NULL (measured against Samba 4.24.7, whose empty
// full_name and home_directory both point at a three-word zero header).
void appendPresentCountedString(QByteArray &out, QByteArray &deferred, const QString &text,
                                QList<QPair<int, int>> &strings)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    putLe16(out, quint16(utf16.size()));
    putLe16(out, quint16(utf16.size()));
    strings.append(qMakePair(int(out.size()), int(deferred.size())));
    putLe32(out, 0); // patched once the blob is placed
    appendVaryingString(deferred, text);
}

// A pointer to something written after the structure that holds it, such as the
// logon-hours bitmap: the same record, without the string header.
void appendDeferredPointer(QByteArray &out, const QByteArray &deferred,
                           QList<QPair<int, int>> &strings)
{
    strings.append(qMakePair(int(out.size()), int(deferred.size())));
    putLe32(out, 0); // patched once the blob is placed
}

// Places an arm's fixed part and its character buffers in the reply, giving
// every recorded pointer the offset of its own data: the blob lands directly
// behind the arm, so each offset is the arm's own base plus the arm's length
// plus the offset recorded for it.
void placeStrings(QByteArray &reply, const QByteArray &blob,
                  const QList<QPair<int, int>> &strings)
{
    const int base = int(reply.size());
    for (const QPair<int, int> &string : strings)
        setLe32(reply, string.first, quint32(base + string.second));
    reply.append(blob);
}

// SAMPR_ENUMERATION_BUFFER, shared by the enumerations that answer with it:
// the context, a pointer to the buffer, the buffer's three words — entries
// read, a pointer to the entry array, its maximum count — one
// {RelativeId; RPC_UNICODE_STRING} per entry and the name arrays behind them.
// Every pointer is the offset of its pointee from the start of the stub
// (MS-RPCE 2.2.10.6), so a value that is merely unique names bytes outside the
// buffer a Windows stub was given.
void appendEnumeration(QByteArray &out, const QList<QPair<quint32, QString>> &page,
                       quint32 context)
{
    const int base = int(out.size());
    const int buffer = base + 8;     // the SAMPR_ENUMERATION_BUFFER
    const int entries = buffer + 12; // the entry array, behind its own maximum count
    putLe32(out, context);
    putLe32(out, quint32(buffer));
    putLe32(out, quint32(page.size())); // EntriesRead
    putLe32(out, quint32(entries));     // the entry array
    putLe32(out, quint32(page.size())); // Memsize
    QByteArray deferred;
    QList<QPair<int, int>> strings;
    for (const QPair<quint32, QString> &entry : page) {
        putLe32(out, entry.first);
        appendCountedString(out, deferred, entry.second, strings);
    }
    placeStrings(out, deferred, strings);
    putLe32(out, quint32(page.size())); // CountReturned
}

void appendArmWithStrings(QByteArray &reply, QByteArray &arm, const QByteArray &blob,
                          const QList<QPair<int, int>> &strings)
{
    const int blobBase = int(reply.size()) + int(arm.size());
    for (const QPair<int, int> &string : strings)
        setLe32(arm, string.first, quint32(blobBase + string.second));
    reply.append(arm);
    reply.append(blob);
}

void appendAllUserInfo(const AllUserInfo &info, QByteArray &out, QByteArray &deferred,
                       QList<QPair<int, int>> &strings)
{
    putLe64(out, info.lastLogon);
    putLe64(out, info.lastLogoff);
    putLe64(out, info.passwordLastSet);
    putLe64(out, info.accountExpires);
    putLe64(out, info.passwordCanChange);
    putLe64(out, info.passwordMustChange);

    for (const QString &text : {info.userName, info.fullName, info.homeDirectory,
                                info.homeDrive, info.scriptPath, info.profilePath,
                                info.adminComment, info.workstations, info.userComment}) {
        appendPresentCountedString(out, deferred, text, strings);
    }
    // Parameters is a binary string, and a DC leaves it NULL when the account
    // has none even though it names the field present.
    appendCountedString(out, deferred, info.parameters, strings);
    // The two OWF hashes and private_data are never served: AD returns them
    // only under an access right this endpoint does not model.
    const QString empty;
    for (int i = 0; i < 3; ++i)
        appendCountedString(out, deferred, empty, strings);

    // SAMPR_SR_SECURITY_DESCRIPTOR: a self-relative descriptor the caller has
    // to read separately, so a NULL here says "not carried in this answer".
    putLe32(out, 0); // cb
    putLe32(out, 0); // buffer

    putLe32(out, info.userId);
    putLe32(out, info.primaryGroupId);
    putLe32(out, info.accountFlags);
    putLe32(out, info.fieldsPresent);

    // SAMPR_LOGON_HOURS: the length is in bits, the units are one byte per
    // hour for a week. All bits set is "any hour", which is what an account
    // with no logonHours attribute allows.
    const QByteArray hours = logonHoursForWire(info.logonHours);
    putLe16(out, quint16(hours.size() * 8));
    out.append(QByteArray(2, '\0'));
    appendDeferredPointer(out, deferred, strings);
    // The array is [size_is(1260), length_is(units_per_week/8)] (MS-SAMR
    // 2.2.7.5): the maximum count is the fixed 1260 from the IDL, the offset is
    // zero, and the actual count is the week in bytes.
    putLe32(deferred, 1260);
    putLe32(deferred, 0);
    putLe32(deferred, quint32(hours.size()));
    deferred.append(hours);
    while (deferred.size() % 4 != 0)
        deferred.append('\0');

    putLe16(out, info.badPasswordCount);
    putLe16(out, info.logonCount);
    putLe16(out, info.countryCode);
    putLe16(out, info.codePage);
    out.append(char(0));                       // LmPasswordPresent
    out.append(char(info.ntPasswordPresent));
    out.append(char(info.passwordExpired));
    out.append(char(0));                       // PrivateDataSensitive
}

// The bits of samr_FieldsPresent that an answer actually fills in: every field
// up to CODE_PAGE. MS-SAMR 3.1.5.5.5.2 makes the bit set depend on the access
// the caller holds, and the guest opens the user with USER_READ_LOGON, so
// LAST_LOGON and LAST_LOGOFF belong here with the values the arm already
// carries — a 2000 client answers a set of fields that leaves them out with
// 124 without reading the record. The two password-presence bits and the
// expired flag stay out on purpose: MS-SAMR 3.1.5.5.5 lists them, with private
// data and the security descriptor, as bits a server MUST never return.
constexpr quint32 kFieldsPresentStandard =
    0x1u      // ACCOUNT_NAME
    | 0x2u    // FULL_NAME
    | 0x4u    // RID
    | 0x8u    // PRIMARY_GID
    | 0x10u   // DESCRIPTION
    | 0x20u   // COMMENT
    | 0x40u   // HOME_DIRECTORY
    | 0x80u   // HOME_DRIVE
    | 0x100u  // LOGON_SCRIPT
    | 0x200u  // PROFILE_PATH
    | 0x400u  // WORKSTATIONS
    | 0x800u  // LAST_LOGON
    | 0x1000u // LAST_LOGOFF
    | 0x2000u // LOGON_HOURS
    | 0x4000u // BAD_PWD_COUNT
    | 0x8000u // NUM_LOGONS
    | 0x10000u // ALLOW_PWD_CHANGE
    | 0x20000u // FORCE_PWD_CHANGE
    | 0x40000u // LAST_PWD_CHANGE
    | 0x80000u // ACCT_EXPIRY
    | 0x100000u // ACCT_FLAGS
    | 0x200000u // PARAMETERS
    | 0x400000u // COUNTRY_CODE
    | 0x800000u; // CODE_PAGE

// ---------- reading the aggregate write ----------
//
// SamrSetInformationUser's classes 21, 23 and 25 carry the whole
// SAMPR_USER_ALL_INFORMATION structure (MS-SAMR 2.2.7.6), which is how ADUC's
// "new user" dialog fills every field in one call. NDR puts the pointers' inline
// headers in the structure and defers every buffer to the end of it
// (MS-RPCE §2.2.6), so the structure has to be read in two passes: the fixed
// part first, then the buffers in the order their referents appeared.

// A pointer's inline header: the lengths the client filled in and whether the
// referent is there at all.
struct WirePointer {
    quint16 length = 0;
    bool present = false;
};

bool readWirePointer(Ndr::Reader &reader, WirePointer *field)
{
    quint16 maximum = 0;
    quint32 referent = 0;
    if (!reader.u16(&field->length) || !reader.u16(&maximum) || !reader.u32(&referent))
        return false;
    Q_UNUSED(maximum)
    field->present = referent != 0;
    return true;
}

// A varying array as NDR writes it: maximum count, offset, actual count, then
// the elements, padded back out to four bytes.
bool readDeferredVarying(Ndr::Reader &reader, bool present, int elementSize,
                         QByteArray *bytes)
{
    bytes->clear();
    if (!present)
        return true;
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
        return false;
    if (offset != 0 || actual > maximum)
        return false;
    if (quint64(actual) * quint64(elementSize) > quint64(reader.remaining()))
        return false;
    if (!reader.bytes(int(actual) * elementSize, bytes))
        return false;
    reader.align(4);
    return true;
}

// A conformant array (the security descriptor) has one length: every element it
// announces is present.
bool readDeferredConformant(Ndr::Reader &reader, bool present, QByteArray *bytes)
{
    bytes->clear();
    if (!present)
        return true;
    quint32 maximum = 0;
    if (!reader.u32(&maximum))
        return false;
    if (quint64(maximum) > quint64(reader.remaining()))
        return false;
    if (!reader.bytes(int(maximum), bytes))
        return false;
    reader.align(4);
    return true;
}

bool readDeferredString(Ndr::Reader &reader, bool present, QString *text)
{
    text->clear();
    QByteArray chars;
    if (!readDeferredVarying(reader, present, 2, &chars))
        return false;
    if (!chars.isEmpty()) {
        *text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                   qsizetype(chars.size() / 2));
    }
    return true;
}

// What a class 21/23/25 arm says. `trailer` is the ciphered password classes 23
// and 25 append to the structure, before the deferred buffers start.
struct IncomingUserInfo {
    AllUserInfo info;
    QByteArray ntOwf;
    QByteArray logonHours;
    QByteArray trailer;
};

bool readAllUserInfo(Ndr::Reader &reader, int trailingBytes, IncomingUserInfo *out)
{
    AllUserInfo &info = out->info;
    WirePointer strings[10];
    WirePointer lmOwf;
    WirePointer ntOwf;
    WirePointer privateData;
    WirePointer logonHours;
    quint32 descriptorLength = 0;
    bool descriptorPresent = false;
    bool logonHoursPresent = false;
    quint32 userId = 0;
    quint32 primaryGroupId = 0;
    quint32 accountControl = 0;
    quint32 whichFields = 0;
    quint16 unitsPerWeek = 0;
    quint16 badPasswordCount = 0;
    quint16 logonCount = 0;
    quint16 countryCode = 0;
    quint16 codePage = 0;
    quint8 lmPresent = 0;
    quint8 ntPresent = 0;
    quint8 passwordExpired = 0;
    quint8 privateDataSensitive = 0;

    if (!reader.u64(&info.lastLogon) || !reader.u64(&info.lastLogoff)
        || !reader.u64(&info.passwordLastSet) || !reader.u64(&info.accountExpires)
        || !reader.u64(&info.passwordCanChange) || !reader.u64(&info.passwordMustChange))
        return false;
    for (WirePointer &field : strings) {
        if (!readWirePointer(reader, &field))
            return false;
    }
    if (!readWirePointer(reader, &lmOwf) || !readWirePointer(reader, &ntOwf)
        || !readWirePointer(reader, &privateData))
        return false;
    if (!reader.u32(&descriptorLength) || !reader.referent(&descriptorPresent))
        return false;
    if (!reader.u32(&userId) || !reader.u32(&primaryGroupId) || !reader.u32(&accountControl)
        || !reader.u32(&whichFields))
        return false;
    if (!reader.u16(&unitsPerWeek) || !reader.skip(2))
        return false;
    if (!reader.referent(&logonHoursPresent))
        return false;
    if (!reader.u16(&badPasswordCount) || !reader.u16(&logonCount) || !reader.u16(&countryCode)
        || !reader.u16(&codePage))
        return false;
    if (!reader.u8(&lmPresent) || !reader.u8(&ntPresent) || !reader.u8(&passwordExpired)
        || !reader.u8(&privateDataSensitive))
        return false;
    Q_UNUSED(unitsPerWeek)
    Q_UNUSED(lmPresent)
    Q_UNUSED(privateDataSensitive)

    if (trailingBytes > 0 && !reader.bytes(trailingBytes, &out->trailer))
        return false;

    // The buffers now, in the order the headers listed them.
    QString *targets[10] = {&info.userName,    &info.fullName,     &info.homeDirectory,
                            &info.homeDrive,   &info.scriptPath,   &info.profilePath,
                            &info.adminComment, &info.workstations, &info.userComment,
                            &info.parameters};
    for (int i = 0; i < 10; ++i) {
        if (!readDeferredString(reader, strings[i].present, targets[i]))
            return false;
    }
    QByteArray lmHash;
    if (!readDeferredVarying(reader, lmOwf.present, 2, &lmHash))
        return false;
    if (!readDeferredVarying(reader, ntOwf.present, 2, &out->ntOwf))
        return false;
    QString privateDataText;
    if (!readDeferredString(reader, privateData.present, &privateDataText))
        return false;
    QByteArray descriptor;
    if (!readDeferredConformant(reader, descriptorPresent, &descriptor))
        return false;
    if (descriptor.size() != int(descriptorLength))
        return false;
    if (!readDeferredVarying(reader, logonHoursPresent, 1, &out->logonHours))
        return false;
    Q_UNUSED(lmHash)
    Q_UNUSED(privateDataText)
    Q_UNUSED(descriptor)

    info.userId = userId;
    info.primaryGroupId = primaryGroupId;
    info.accountControl = accountControl;
    info.fieldsPresent = whichFields;
    info.logonHours = out->logonHours;
    info.badPasswordCount = badPasswordCount;
    info.logonCount = logonCount;
    info.countryCode = countryCode;
    info.codePage = codePage;
    info.ntPasswordPresent = ntPresent != 0;
    info.passwordExpired = passwordExpired != 0;
    Q_UNUSED(logonHours.length)
    return true;
}

// Unix seconds to NTTIME (100ns ticks since 1601-01-01).
quint64 ntTimeFromUnix(quint64 seconds)
{
    return seconds * 10000000ull + 116444736000000000ull;
}

// The instant AD reports for "the password may change" and "the password must
// change": pwdLastSet plus the policy's delta time, which is negative and in
// 100-nanosecond units. A policy of zero, an account whose password never
// expires, and one that has never had a password all mean "never", which SAMR
// spells as the largest NTTIME.
quint64 ntTimeFromDelta(quint64 pwdLastSet, quint32 userAccountControl, qint64 delta)
{
    constexpr quint32 kDontExpirePassword = 0x10000;
    if (pwdLastSet == 0)
        return 0;
    if ((userAccountControl & kDontExpirePassword) || delta == 0
        || delta == std::numeric_limits<qint64>::min())
        return 0x7fffffffffffffffull;
    const qint64 lifetime = (delta < 0 ? -delta : delta) / 10000000LL;
    return ntTimeFromUnix(pwdLastSet + quint64(lifetime));
}

QByteArray sidForRid(const QString &domainSid, quint32 rid)
{
    QByteArray sid = Ndr::sidFromString(domainSid);
    if (sid.isEmpty())
        return sid;
    sid.append(char(rid & 0xff));
    sid.append(char((rid >> 8) & 0xff));
    sid.append(char((rid >> 16) & 0xff));
    sid.append(char((rid >> 24) & 0xff));
    return sid;
}

} // namespace

namespace Samr {

Rpc::Interface interface()
{
    Rpc::Interface iface;
    // 12345778-1234-ABCD-EF00-0123456789AC, SAMR v1.0.
    iface.uuid = QByteArray::fromHex("78 57 34 12 34 12 cd ab ef 00 01 23 45 67 89 ac");
    iface.major = 1;
    iface.minor = 0;
    iface.name = QStringLiteral("SAMR");
    return iface;
}

} // namespace Samr

SamrServer::SamrServer(QObject *parent) : QObject(parent)
{
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Samr::interface(), [this](const Rpc::Call &call) {
        return handleCall(call.opnum, call.stub, call.sessionKey);
    });
    connect(m_rpc, &RpcServer::requestReceived, this, &SamrServer::requestReceived);
}

void SamrServer::setConfig(const Samr::Config &config)
{
    m_config = config;
}

void SamrServer::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = std::move(provider);
}

void SamrServer::setWriteBackend(Samr::WriteBackend backend)
{
    m_writes = std::move(backend);
}

void SamrServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_rpc->setAuthenticator(std::move(authenticator));
}

void SamrServer::setKerberosAcceptor(Rpc::KerberosAcceptor acceptor,
                                     Rpc::KerberosFinisher finisher)
{
    m_rpc->setKerberosAcceptor(std::move(acceptor), std::move(finisher));
}

void SamrServer::setDomainNames(const QString &domain, const QString &serverName,
                                const QString &dnsDomain)
{
    m_rpc->setDomainNames(domain, serverName, dnsDomain);
}

bool SamrServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void SamrServer::close()
{
    m_rpc->close();
}

bool SamrServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 SamrServer::serverPort() const
{
    return m_rpc->serverPort();
}

QList<DirectoryObject> SamrServer::directory() const
{
    return m_provider ? m_provider() : QList<DirectoryObject>();
}

DirectoryObject SamrServer::domainObject() const
{
    for (const DirectoryObject &object : directory()) {
        if (object.kind == ObjectKind::Domain)
            return object;
    }
    return DirectoryObject();
}

QList<DirectoryObject> SamrServer::users() const
{
    QList<DirectoryObject> result;
    for (const DirectoryObject &object : directory()) {
        if (object.id.isEmpty())
            continue;
        const QString type = object.type;
        if (!type.contains(QLatin1String("User"), Qt::CaseInsensitive)
            && !type.contains(QLatin1String("Computer"), Qt::CaseInsensitive))
            continue;
        if (object.attributes.value(QStringLiteral("objectSid")).isEmpty())
            continue;
        result.append(object);
    }
    return result;
}

QStringList SamrServer::globalGroupNames() const
{
    QStringList names;
    for (const DirectoryObject &group : groups()) {
        QString name = group.attributes.value(QStringLiteral("sAMAccountName"));
        if (name.isEmpty())
            name = group.name;
        if (!name.isEmpty())
            names.append(name);
    }
    return names;
}

QList<DirectoryObject> SamrServer::groups() const
{
    QList<DirectoryObject> result;
    for (const DirectoryObject &object : directory()) {
        if (object.id.isEmpty() || object.kind != ObjectKind::Group)
            continue;
        if (object.attributes.value(QStringLiteral("objectSid")).isEmpty())
            continue;
        if (isAlias(object))
            continue;
        result.append(object);
    }
    return result;
}

// The object under CN=Builtin that holds this alias's memberships, created when
// the tree was provisioned before those objects existed. Its SID as stored is not
// what identifies it to a client: the alias keeps the well-known SID either way.
QString SamrServer::ensureBuiltinAlias(const QString &sidText, QString *error)
{
    const quint32 rid = sidText.section(QLatin1Char('-'), -1).toUInt();
    QString name;
    for (const BuiltinAlias &entry : builtinAliasTable()) {
        if (entry.rid == rid) {
            name = QString::fromLatin1(entry.name);
            break;
        }
    }
    if (name.isEmpty()) {
        if (error)
            *error = QStringLiteral("no BUILTIN alias carries %1").arg(sidText);
        return {};
    }
    const QString dn = QStringLiteral("CN=%1,CN=Builtin,%2").arg(name, m_config.baseDn);
    for (const DirectoryObject &candidate : directory()) {
        if (candidate.id.compare(dn, Qt::CaseInsensitive) == 0)
            return candidate.id;
    }
    if (!m_writes.create) {
        if (error)
            *error = QStringLiteral("no write backend");
        return {};
    }
    DirectoryObject alias;
    alias.id = dn;
    alias.name = name;
    alias.type = QStringLiteral("Group");
    alias.kind = ObjectKind::Group;
    alias.container = QStringLiteral("Builtin");
    alias.attributes.insert(QStringLiteral("distinguishedName"), dn);
    alias.attributes.insert(QStringLiteral("cn"), name);
    alias.attributes.insert(QStringLiteral("sAMAccountName"), name);
    alias.attributes.insert(QStringLiteral("objectSid"), sidText);
    // A domain-local security group, which is what SAMR calls an alias.
    alias.attributes.insert(QStringLiteral("groupType"), QStringLiteral("-2147483644"));
    alias.attributes.insert(QStringLiteral("objectClass"),
                            QStringLiteral("top;group"));
    if (!m_writes.create(&alias, error))
        return {};
    return dn;
}

QList<DirectoryObject> SamrServer::aliases() const
{
    QList<DirectoryObject> result;
    for (const DirectoryObject &object : directory()) {
        if (object.id.isEmpty() || !isAlias(object))
            continue;
        if (object.attributes.value(QStringLiteral("objectSid")).isEmpty())
            continue;
        result.append(object);
    }
    return result;
}

QByteArray SamrServer::newHandle(Handle::Kind kind, const QString &dn, quint32 rid)
{
    QByteArray id(kHandleSize, '\0');
    for (int i = 0; i < kHandleSize - 4; ++i)
        id[i] = char(QRandomGenerator::system()->generate() & 0xff);
    Handle handle;
    handle.kind = kind;
    handle.dn = dn;
    handle.rid = rid;
    m_handles.insert(id, handle);
    return id;
}

QList<QByteArray> SamrServer::aliasMemberSids(const QString &aliasDn, quint32 aliasRid) const
{
    QList<QByteArray> sids;
    QStringList members;
    if (isBuiltinAlias(aliasDn)) {
        for (const DirectoryObject &candidate : builtinAliasObjects(directory())) {
            if (candidate.id.compare(aliasDn, Qt::CaseInsensitive) == 0) {
                members = candidate.members;
                break;
            }
        }
        return builtinMemberSids(aliasRid, m_config.domainSid, directory(), members);
    }
    for (const DirectoryObject &object : aliases()) {
        if (object.id.compare(aliasDn, Qt::CaseInsensitive) == 0) {
            members = object.members;
            break;
        }
    }
    const QList<DirectoryObject> all = directory();
    for (const QString &member : members) {
        for (const DirectoryObject &candidate : all) {
            if (candidate.id.compare(member, Qt::CaseInsensitive) != 0)
                continue;
            const QByteArray sid = Ndr::sidFromString(
                candidate.attributes.value(QStringLiteral("objectSid")));
            if (!sid.isEmpty())
                sids.append(sid);
            break;
        }
    }
    return sids;
}

bool SamrServer::lookupHandle(const QByteArray &handle, Handle::Kind kind, Handle *out) const
{
    if (handle.size() != kHandleSize)
        return false;
    const auto it = m_handles.constFind(handle);
    if (it == m_handles.constEnd() || it->kind != kind)
        return false;
    if (out)
        *out = *it;
    return true;
}

QByteArray SamrServer::handleCall(quint16 opnum, const QByteArray &stub,
                                  const QByteArray &sessionKey)
{
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("SAMR opnum %u stub %s", opnum, stub.toHex().constData());
    Ndr::Reader reader(stub);
    QByteArray fixed;
    QByteArray deferred;
    QList<QPair<int, int>> strings;

    switch (opnum) {
    case Samr::OpConnect:
    case Samr::OpConnect2:
    case Samr::OpConnect4:
    case Samr::OpConnect5: {
        // [unique] pointer to the server name, then the access mask (and, for
        // Connect4, the client revision; for Connect5, the version and revision
        // info we do not use).
        bool present = false;
        if (!reader.referent(&present))
            return {};
        if (present) {
            quint16 length = 0;
            quint16 maximum = 0;
            if (!reader.u16(&length) || !reader.u16(&maximum))
                return {};
            if (maximum > 0) {
                bool buffer = false;
                reader.referent(&buffer);
            }
            Q_UNUSED(length)
            reader.align(4);
        }
        quint32 desired = 0;
        if (!reader.u32(&desired))
            return {};
        if (opnum == Samr::OpConnect4)
            reader.u32(&desired); // ClientRevision, which this server ignores

        const QByteArray handle = newHandle(Handle::Server, m_config.domainSid, 0);
        fixed.append(handle);
        if (opnum == Samr::OpConnect5) {
            // OutVersion, then the revision union switched on it — its tag and
            // SAMPR_REVISION_INFO_V1, which is Revision and SupportedFeatures —
            // then the handle and the status. SupportedFeatures was missing
            // here until impacket's decoder rejected the reply as four bytes
            // short, which is exactly what a conformance client is for.
            fixed.clear();
            putLe32(fixed, 1u); // OutVersion
            putLe32(fixed, 1u); // union tag (the same OutVersion)
            putLe32(fixed, 1u); // Revision
            putLe32(fixed, 0u); // SupportedFeatures
            fixed.append(handle);
        }
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("Connect (access 0x%1)")
                                 .arg(desired, 8, 16, QLatin1Char('0')));
        return fixed;
    }
    case Samr::OpCloseHandle: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        m_handles.remove(handle);
        QByteArray closed(kHandleSize, '\0');
        fixed.append(closed);
        putLe32(fixed, kStatusSuccess);
        return fixed;
    }
    // SamrQuerySecurityObject (opnum 3): `net user /domain` asks for the
    // account's DACL after it has read the record, and stops the whole command
    // when the answer carries no descriptor. The reference DC answers with a
    // self-relative header and nothing behind it — revision 1, SE_SELF_RELATIVE
    // with no DACL flag, all four offsets zero — which is 20 bytes and parses
    // as a security descriptor that grants nothing.
    case Samr::OpQuerySecurityObject: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 securityInformation = 0;
        reader.u32(&securityInformation);
        const auto it = m_handles.constFind(handle);
        if (it == m_handles.constEnd() || it->kind == Handle::None) {
            fixed.append(char(0)); // NULL descriptor referent
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // [out,ref] PSAMPR_SR_SECURITY_DESCRIPTOR: a referent, the length, the
        // array's referent and maximum count, then the bytes.
        QByteArray sd;
        sd.append(char(1));           // SECURITY_DESCRIPTOR_REVISION
        sd.append(char(0));           // Sbz1
        putLe16(sd, quint16(0x8000)); // SE_SELF_RELATIVE, no DACL present
        for (int i = 0; i < 4; ++i)
            putLe32(sd, 0); // Owner, Group, Sacl, Dacl
        // Both referents name where their pointee sits in this stub: the
        // descriptor starts at 4, behind its own referent, and the bytes at 16.
        putLe32(fixed, 4);                  // descriptor referent
        putLe32(fixed, quint32(sd.size())); // Length
        putLe32(fixed, 16);                 // array referent
        putLe32(fixed, quint32(sd.size())); // array MaximumCount
        fixed.append(sd);
        while (fixed.size() % 4 != 0)
            fixed.append('\0');
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("QuerySecurityObject(0x%1)")
                                 .arg(securityInformation, 8, 16, QLatin1Char('0')));
        return fixed;
    }
    case Samr::OpLookupDomainInSamServer: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle server;
        if (!lookupHandle(handle, Handle::Server, &server)) {
            fixed.append(char(0)); // NULL SID referent
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // SAMR passes the name as an inline RPC_UNICODE_STRING: Length,
        // MaximumLength, then the buffer referent and its varying data.
        QString name;
        quint16 nameLength = 0;
        quint16 nameMaximum = 0;
        reader.u16(&nameLength);
        reader.u16(&nameMaximum);
        if (nameMaximum > 0) {
            bool bufferPresent = false;
            reader.referent(&bufferPresent);
            if (bufferPresent) {
                quint32 count = 0;
                quint32 offset = 0;
                quint32 actual = 0;
                reader.conformantCount(&count);
                reader.u32(&offset);
                reader.u32(&actual);
                QByteArray chars;
                if (reader.bytes(int(actual) * 2, &chars))
                    name = QString::fromUtf16(
                        reinterpret_cast<const char16_t *>(chars.constData()),
                        qsizetype(chars.size() / 2));
            }
        }

        QString sidText = m_config.domainSid;
        if (name.compare(QStringLiteral("Builtin"), Qt::CaseInsensitive) == 0) {
            sidText = kBuiltinDomainSid;
        } else if (!m_config.netbios.isEmpty()
                   && name.compare(m_config.netbios, Qt::CaseInsensitive) != 0
                   && name.compare(m_config.realm, Qt::CaseInsensitive) != 0) {
            fixed.append(char(0));
            putLe32(fixed, kStatusNoSuchDomain);
            return fixed;
        }

        const QByteArray sid = Ndr::sidFromString(sidText);
        if (sid.isEmpty()) {
            // Without a domain SID there is nothing to hand out: answer with a
            // NULL SID rather than a malformed one.
            fixed.append(char(0));
            putLe32(fixed, kStatusInvalidParameter);
            return fixed;
        }
        putLe32(fixed, quint32(fixed.size() + 4)); // the SID, behind its own maximum count
        putLe32(fixed, quint32((sid.size() - 8) / 4)); // max_count: sub-authorities
        fixed.append(sid);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("LookupDomain(%1)").arg(name));
        return fixed;
    }
    case Samr::OpEnumerateDomainsInSamServer: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 context = 0;
        quint32 maximum = 0;
        reader.u32(&context);
        reader.u32(&maximum);
        Handle server;
        if (!lookupHandle(handle, Handle::Server, &server)) {
            putLe32(fixed, context);
            fixed.append(char(0));
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        // Every DC reports two domains, and AD lists BUILTIN first.
        QStringList names;
        if (context == 0) {
            names.append(QStringLiteral("Builtin"));
            names.append(m_config.netbios);
        }
        QList<QPair<quint32, QString>> entries;
        for (const QString &name : names)
            entries.append(qMakePair(0u, name)); // a domain entry carries no RID
        appendEnumeration(fixed, entries, 0);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateDomains"));
        return fixed;
    }
    case Samr::OpOpenDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 desired = 0;
        reader.u32(&desired);
        // The domain SID arrives in one of three shapes depending on the
        // marshaller: an inline conformant SID (max_count first), the same
        // preceded by 4 bytes of alignment padding, or a [unique] pointer with a
        // referent. A word in 1..15 can only be a sub-authority count.
        QByteArray sid;
        {
            quint32 word = 0;
            if (!reader.u32(&word))
                return {};
            quint32 count = 0;
            if (word >= 16)
                reader.conformantCount(&count); // referent id, then the count
            else if (word != 0)
                count = word;                   // inline count, no padding
            else
                reader.conformantCount(&count); // padding word, then the count
            if (count >= 1 && count <= 15)
                Ndr::readSid(reader, &sid);
        }
        Handle server;
        if (!lookupHandle(handle, Handle::Server, &server)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // Two domains are openable: the account NC and BUILTIN, whose handle is
        // tagged by its SID so the calls below know which space they are in.
        QString sidText = m_config.domainSid;
        if (!sid.isEmpty()) {
            const QString requested = Ndr::sidToString(sid);
            if (requested == kBuiltinDomainSid)
                sidText = kBuiltinDomainSid;
            else if (requested != m_config.domainSid) {
                fixed.append(QByteArray(kHandleSize, '\0'));
                putLe32(fixed, kStatusNoSuchDomain);
                return fixed;
            }
        }
        fixed.append(newHandle(Handle::Domain, sidText, 0));
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("OpenDomain"));
        return fixed;
    }
    // SamrQueryInformationDomain (opnum 8). The out parameter is a pointer to
    // the union: a referent, the class as a USHORT, two alignment bytes, then
    // the arm. Only the classes this directory can answer truthfully are served.
    // SamrQueryInformationDomain2 (opnum 46) is the (2) form of the same query:
    // the same handle and level in, the same union and status out. A Windows
    // 2000 client asks it for the lockout policy, which is class 12 here.
    case Samr::OpQueryInformationDomain:
    case Samr::OpQueryInformationDomain2: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, 0); // NULL union referent
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        if (domain.dn == kBuiltinDomainSid) {
            // BUILTIN reports no password policy, logon hours or role of its own.
            putLe32(fixed, 0); // NULL union referent
            putLe32(fixed, kStatusNotSupported);
            return fixed;
        }
        auto beginArm = [&fixed](quint16 tag) {
            // The pointer names the union, and a union begins with its
            // discriminant: MS-RPCE 2.2.10.6 makes the referent the offset of
            // the pointee from the start of the stub, so it is 4 here — the tag
            // is at 4, two alignment bytes follow it, and the arm starts at 8.
            putLe32(fixed, 4);
            fixed.append(char(tag & 0xff));
            fixed.append(char((tag >> 8) & 0xff));
            fixed.append(char(0));
            fixed.append(char(0));
        };
        switch (infoClass) {
        case 1: { // DomainPasswordInformation: the policy this server enforces
            // Read from the domain object's own attributes, so a client that
            // sets the policy over SAMR and one that reads it over LDAP see the
            // same values. Both ages travel as AD stores them: a delta time is
            // a negative count of 100-nanosecond units, and the struct puts the
            // two 8-byte members last, already aligned after the 8 bytes above.
            const LdapServer::PasswordPolicy policy =
                LdapServer::passwordPolicyFrom(domainObject());
            beginArm(1);
            fixed.append(char(policy.minLength & 0xff));
            fixed.append(char((policy.minLength >> 8) & 0xff));
            fixed.append(char(policy.historyLength & 0xff));
            fixed.append(char((policy.historyLength >> 8) & 0xff));
            putLe32(fixed, policy.properties);
            putLe64(fixed, quint64(policy.maxAge));
            putLe64(fixed, quint64(policy.minAge));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(password %1/%2/0x%3)")
                                     .arg(policy.minLength)
                                     .arg(policy.historyLength)
                                     .arg(policy.properties, 0, 16));
            return fixed;
        }
        case 2: { // DomainGeneralInformation: what rpcclient's `querydominfo`
            // asks for — the domain clock policy, names, role and populations.
            // This DC is the PDC and never forces logoff; the OEM comment, the
            // BDC's PDC name and the sequence number carry established empty
            // defaults rather than values the directory does not keep.
            beginArm(2);
            putLe32(fixed, 0xffffffffu); // ForceLogoff: never (NTTIME -1)
            putLe32(fixed, 0x7fffffffu);
            appendCountedString(fixed, deferred, QString(), strings); // OemInformation
            appendCountedString(fixed, deferred, m_config.netbios, strings);
            appendCountedString(fixed, deferred, QString(), strings); // Primary (BDC only)
            // udlong (hyper): NDR aligns 8-byte primitives, so pad after the
            // 12-byte string headers.
            while (fixed.size() % 8)
                fixed.append(char(0));
            putLe32(fixed, 1u); // sequence_num
            putLe32(fixed, 0u);
            // Both enums are [v1_enum] in the IDL: four bytes on the wire.
            putLe32(fixed, 1u); // domain_server_state: DOMAIN_SERVER_ENABLED
            putLe32(fixed, 3u); // role: DOMAIN_SERVER_ROLE_PRIMARY
            putLe32(fixed, 0u); // unknown3
            putLe32(fixed, quint32(users().size()));
            putLe32(fixed, quint32(groups().size()));
            putLe32(fixed, 0u); // aliases
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(general)"));
            return fixed;
        }
        case 3: { // DomainLogoffInformation: the interval after which a client
            // is forced off this domain's accounts. It is a relative time, so
            // zero — not the absolute NTTIME "never" class 2 uses — is how a
            // DC that forces none answers it. `net accounts /domain` reads
            // this class for its "Forced logoff" line.
            beginArm(3);
            putLe64(fixed, 0);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(logoff)"));
            return fixed;
        }
        case 5: { // DomainNameInformation: the NetBIOS name, as AD reports it
            const QByteArray utf16 = Ndr::utf16le(m_config.netbios);
            beginArm(5);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, utf16.isEmpty() ? 0u : 0x0002e460u);
            if (!utf16.isEmpty())
                appendVaryingString(deferred, m_config.netbios);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(name)"));
            return fixed;
        }
        case 4: { // DomainOemInformation: the domain comment AD keeps on the
            // domain NC. The directory model has no such attribute, so the
            // answer is the empty string the reference DC sends for a domain
            // with no comment — never a NULL pointer, which a client reads as
            // a missing arm rather than an empty one.
            beginArm(4);
            fixed.append(QByteArray(8, '\0')); // Length, MaximumLength, NULL buffer
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(oem)"));
            return fixed;
        }
        case 6: { // DomainPrimaryInformation: the PDC a BDC points at. This
            // DC holds the PDC role, so it names no primary — the empty string
            // the reference DC sends, on the same wire shape as class 5.
            beginArm(6);
            fixed.append(QByteArray(8, '\0')); // Length, MaximumLength, NULL buffer
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(primary)"));
            return fixed;
        }
        case 7: { // DomainServerRoleInformation: this DC holds the PDC role
            beginArm(7);
            fixed.append(char(3)); // DOMAIN_SERVER_ROLE_PRIMARY
            fixed.append(char(0));
            fixed.append(char(0)); // alignment before the status
            fixed.append(char(0));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(role)"));
            return fixed;
        }
        case 9: { // DomainServerStateInformation: whether logons are accepted
            beginArm(9);
            putLe32(fixed, 1u); // DOMAIN_SERVER_ENABLED, a [v1_enum]
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(state)"));
            return fixed;
        }
        case 11: { // DomainGeneralInformation2: class 2's structure with the
            // lockout policy appended, so one call answers everything a
            // command like `net accounts /domain` prints. The arm repeats
            // class 2 field for field and then adds the two intervals and the
            // threshold class 12 carries on its own.
            const DirectoryObject domain = domainObject();
            const qint64 duration =
                domain.attributes.value(QStringLiteral("lockoutDuration")).toLongLong();
            const qint64 window =
                domain.attributes.value(QStringLiteral("lockoutObservationWindow")).toLongLong();
            const quint32 threshold =
                domain.attributes.value(QStringLiteral("lockoutThreshold")).toUInt();
            beginArm(11);
            putLe32(fixed, 0xffffffffu); // ForceLogoff: never (NTTIME -1)
            putLe32(fixed, 0x7fffffffu);
            appendCountedString(fixed, deferred, QString(), strings); // OemInformation
            appendCountedString(fixed, deferred, m_config.netbios, strings);
            appendCountedString(fixed, deferred, QString(), strings); // Primary (BDC only)
            while (fixed.size() % 8)
                fixed.append(char(0));
            putLe32(fixed, 1u); // sequence_num
            putLe32(fixed, 0u);
            putLe32(fixed, 1u); // domain_server_state: DOMAIN_SERVER_ENABLED
            putLe32(fixed, 3u); // role: DOMAIN_SERVER_ROLE_PRIMARY
            putLe32(fixed, 0u); // unknown3
            putLe32(fixed, quint32(users().size()));
            putLe32(fixed, quint32(groups().size()));
            putLe32(fixed, 0u); // aliases
            // The lockout members are hyper: 8-aligned here, and carry the
            // intervals as MS-SAMR defines them, a negative delta time, which
            // is the form the directory already stores, so they go back as
            // read.
            putLe64(fixed, quint64(duration));
            putLe64(fixed, quint64(window));
            fixed.append(char(threshold & 0xff));
            fixed.append(char(0)); // padding before the status word
            fixed.append(char(0));
            fixed.append(char(0));
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(general2)"));
            return fixed;
        }
        case 12: { // DomainLockoutInformation: the policy the domain object carries
            // Both intervals are delta times, which MS-SAMR defines as negative
            // 100-nanosecond values, and the client encodes them that way:
            // `net accounts /domain /lockoutduration:30` writes -18000000000
            // and reads a positive 18000000000 as no limit at all. AD's
            // attributes hold the same negative form, so the arm hands back
            // the stored value unchanged. The threshold is the number of
            // refusals that locks the account; zero means a bad password is
            // counted but never locks it.
            const DirectoryObject domain = domainObject();
            const qint64 duration =
                domain.attributes.value(QStringLiteral("lockoutDuration")).toLongLong();
            const qint64 window =
                domain.attributes.value(QStringLiteral("lockoutObservationWindow")).toLongLong();
            const quint32 threshold =
                domain.attributes.value(QStringLiteral("lockoutThreshold")).toUInt();
            beginArm(12);
            putLe64(fixed, quint64(duration)); // LockoutDuration: negative delta
            putLe64(fixed, quint64(window));   // LockoutObservationWindow, likewise
            fixed.append(char(threshold & 0xff));                   // LockoutThreshold
            fixed.append(char(0));
            fixed.append(char(0));
            fixed.append(char(0));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(lockout)"));
            return fixed;
        }
        default:
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("QueryInformationDomain class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
    }
    // SamrSetInformationDomain (opnum 9): the write side of the query above,
    // and the only policy a domain administrator can change over RPC today.
    // The refusal classes are refused rather than accepted and dropped.
    case Samr::OpSetInformationDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        if (domain.dn == kBuiltinDomainSid) {
            // BUILTIN has no password or lockout policy of its own.
            putLe32(fixed, kStatusNotSupported);
            return fixed;
        }
        if (infoClass == 1) {
            // The password policy, in the shape the query answers with: two
            // 16-bit counts, a 32-bit flag word and two delta-time ages. AD
            // refuses a positive relative time outright (a delta time is a
            // negative count of 100-nanosecond units) and refuses a maximum
            // age that is shorter than the minimum, which together would make
            // every password expire before it could be set.
            quint16 minLength = 0;
            quint16 historyLength = 0;
            quint32 properties = 0;
            quint64 maxAge = 0;
            quint64 minAge = 0;
            // The union carries two 8-byte members, so NDR aligns the arm that
            // holds them to 8: the pad after the information class is part of
            // the wire form, not an artefact of any one client.
            reader.align(8);
            if (!reader.u16(&minLength) || !reader.u16(&historyLength)
                || !reader.u32(&properties))
                return {};
            reader.align(8);
            if (!reader.u64(&maxAge) || !reader.u64(&minAge))
                return {};
            const qint64 maxDelta = qint64(maxAge);
            const qint64 minDelta = qint64(minAge);
            const qint64 never = std::numeric_limits<qint64>::min();
            const auto positive = [](qint64 value) { return value > 0; };
            const auto magnitude = [](qint64 value) {
                return value < 0 ? quint64(-(value + 1)) + 1 : quint64(value);
            };
            const bool badAge = positive(maxDelta) || positive(minDelta)
                                || (maxDelta != 0 && maxDelta != never
                                    && magnitude(maxDelta) < magnitude(minDelta));
            if (badAge) {
                putLe32(fixed, kStatusInvalidParameter);
                emit requestReceived(QStringLiteral("SetInformationDomain(password) refused"));
                return fixed;
            }
            const DirectoryObject target = domainObject();
            const QString dn = target.id.isEmpty() ? m_config.baseDn : target.id;
            const QList<QPair<QString, QString>> changes = {
                {QStringLiteral("minPwdLength"), QString::number(minLength)},
                {QStringLiteral("pwdHistoryLength"), QString::number(historyLength)},
                {QStringLiteral("pwdProperties"), QString::number(properties)},
                {QStringLiteral("maxPwdAge"), QString::number(maxDelta)},
                {QStringLiteral("minPwdAge"), QString::number(minDelta)},
            };
            bool ok = !dn.isEmpty();
            QString error;
            for (const auto &change : changes) {
                if (!ok)
                    break;
                ok = m_writes.set && m_writes.set(dn, change.first, change.second, &error);
            }
            putLe32(fixed, ok ? kStatusSuccess : kStatusInvalidParameter);
            emit requestReceived(
                QStringLiteral("SetInformationDomain(password %1/%2/0x%3) %4")
                    .arg(minLength)
                    .arg(historyLength)
                    .arg(properties, 0, 16)
                    .arg(ok ? QStringLiteral("ok") : QStringLiteral("refused")));
            return fixed;
        }
        if (infoClass != 12) {
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("SetInformationDomain class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
        // The arm follows the class inline: two 8-byte intervals and then the
        // threshold as a USHORT, which is the shape the query answers with.
        reader.align(8);
        quint64 duration = 0;
        quint64 window = 0;
        quint16 threshold = 0;
        if (!reader.u64(&duration) || !reader.u64(&window) || !reader.u16(&threshold))
            return {};
        const DirectoryObject target = domainObject();
        const QString dn = target.id.isEmpty() ? m_config.baseDn : target.id;
        QMap<QString, QString> changes;
        // The client sends the intervals already in the directory's form, a
        // negative delta (0x8000000000000000 for "never"), so they are stored
        // as sent rather than flipped: the query above returns them the same
        // way, and a 30-minute lockout reads back as the 30 minutes written.
        changes.insert(QStringLiteral("lockoutDuration"), QString::number(qint64(duration)));
        changes.insert(QStringLiteral("lockoutObservationWindow"), QString::number(qint64(window)));
        changes.insert(QStringLiteral("lockoutThreshold"), QString::number(threshold));
        bool ok = !dn.isEmpty();
        QString error;
        for (auto it = changes.cbegin(); ok && it != changes.cend(); ++it) {
            ok = m_writes.set && m_writes.set(dn, it.key(), it.value(), &error);
        }
        putLe32(fixed, ok ? kStatusSuccess : kStatusInvalidParameter);
        emit requestReceived(QStringLiteral("SetInformationDomain(lockout %1, %2, %3) %4")
                                 .arg(threshold)
                                 .arg(duration)
                                 .arg(window)
                                 .arg(ok ? QStringLiteral("ok") : QStringLiteral("refused")));
        return fixed;
    }
    // SamrGetGroupsForUser (opnum 39): the RIDs and SE_GROUP attributes of every
    // group the account belongs to, read from the groups' member lists.
    case Samr::OpGetGroupsForUser: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle user;
        if (!lookupHandle(handle, Handle::User, &user)) {
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const QList<DirectoryObject> all = directory();
        QList<quint32> rids;
        for (const DirectoryObject &object : all) {
            if (object.id.compare(user.dn, Qt::CaseInsensitive) != 0)
                continue;
            for (const QString &groupDn : object.memberOf) {
                for (const DirectoryObject &group : all) {
                    if (group.id.compare(groupDn, Qt::CaseInsensitive) == 0) {
                        rids.append(ridOf(group));
                        break;
                    }
                }
            }
            break;
        }
        // SAMPR_GET_GROUPS_BUFFER: referent, MembershipCount, then the array's
        // pointer, its maximum count and one {RelativeId; Attributes} per group.
        putLe32(fixed, 4);                            // the SAMPR_GET_GROUPS_BUFFER
        putLe32(fixed, quint32(rids.size()));
        putLe32(fixed, rids.isEmpty() ? 0u : 12u);    // the groups, behind their maximum count
        putLe32(fixed, quint32(rids.size()));
        for (quint32 rid : rids) {
            putLe32(fixed, rid);
            // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            putLe32(fixed, 7);
        }
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("GetGroupsForUser(%1 of %2)")
                                 .arg(user.dn)
                                 .arg(rids.size()));
        return fixed;
    }
    // SamrGetUserPwInfo (opnum 44): the domain policy the account's password is
    // held to, as samr_PwInfo { uint16 min_password_length;
    // samr_PasswordProperties password_properties; } behind a referent. A
    // Windows 2000 join asks for it after creating its machine account and
    // abandons the join with "the parameter is incorrect" when the answer is
    // not this whole structure. The values come from the domain object, so the
    // policy a client reads here is the one LDAP and password changes enforce.
    case Samr::OpGetUserPwInfo: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle user;
        if (!lookupHandle(handle, Handle::User, &user)) {
            putLe32(fixed, 0); // NULL referent
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const LdapServer::PasswordPolicy policy =
            LdapServer::passwordPolicyFrom(domainObject());
        putLe32(fixed, quint32(fixed.size() + 4)); // samr_PwInfo, directly behind this word
        fixed.append(char(policy.minLength & 0xff));
        fixed.append(char((policy.minLength >> 8) & 0xff));
        fixed.append(char(0));
        fixed.append(char(0)); // padding to the 32-bit properties word
        putLe32(fixed, policy.properties);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("GetUserPwInfo(%1: %2 chars, props 0x%3)")
                                 .arg(user.dn)
                                 .arg(policy.minLength)
                                 .arg(policy.properties, 0, 16));
        return fixed;
    }
    case Samr::OpEnumerateUsersInDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 context = 0;
        quint32 accountControl = 0;
        quint32 maximum = 0;
        reader.u32(&context);
        reader.u32(&accountControl);
        reader.u32(&maximum);
        Q_UNUSED(maximum)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, context);
            fixed.append(char(0));
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        // Degenerate but legal: BUILTIN holds no accounts.
        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? QList<DirectoryObject>() : users();
        const int start = int(context);
        QList<DirectoryObject> page;
        for (int i = start; i < all.size(); ++i)
            page.append(all.at(i));

        QList<QPair<quint32, QString>> entries;
        for (const DirectoryObject &user : page) {
            QString name = user.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = user.name;
            entries.append(qMakePair(ridOf(user), name));
        }
        appendEnumeration(fixed, entries, 0);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateUsers (%1)").arg(page.size()));
        return fixed;
    }
    // SamrRemoveMemberFromForeignDomain (opnum 45): a member named by SID,
    // removed from every group in the domain. A Windows 2000 client calls this
    // on the way to deleting an account — `net user TMPCD$ /delete /domain`
    // issues it and only then SamrDeleteUser — and with no arm here the call was
    // answered NOT_SUPPORTED, so the client closed the connection and printed
    // "System error 50" without ever asking for the delete.
    case Samr::OpRemoveMemberFromForeignDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        QByteArray memberSid;
        if (!readWireSid(reader, &memberSid))
            return {};
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // The member is named only by SID, so its object is found by relative id
        // inside this domain. A SID no object carries has no memberships to
        // take away, which is the answer the client's delete path acts on: it
        // proceeds to the delete.
        const QByteArray domainSid = Ndr::sidFromString(
            domain.dn == kBuiltinDomainSid ? kBuiltinDomainSid : m_config.domainSid);
        quint32 rid = 0;
        if (memberSid.size() >= 12 && domainSid.size() >= 12
            && memberSid.size() > domainSid.size()
            && memberSid.mid(2, 6) == domainSid.mid(2, 6)
            && memberSid.mid(8, domainSid.size() - 12)
                   == domainSid.mid(8, domainSid.size() - 12)) {
            rid = quint32(quint8(memberSid.at(memberSid.size() - 4)))
                  | (quint32(quint8(memberSid.at(memberSid.size() - 3))) << 8)
                  | (quint32(quint8(memberSid.at(memberSid.size() - 2))) << 16)
                  | (quint32(quint8(memberSid.at(memberSid.size() - 1))) << 24);
        }
        QString memberDn;
        const QList<DirectoryObject> all = directory();
        for (const DirectoryObject &object : all) {
            if (object.id.isEmpty() || rid == 0 || ridOf(object) != rid)
                continue;
            memberDn = object.id;
            break;
        }
        int removed = 0;
        QString error;
        for (const DirectoryObject &group : all) {
            if (!memberDn.isEmpty() && group.kind == ObjectKind::Group && !group.id.isEmpty()) {
                bool member = false;
                for (const QString &candidate : group.members) {
                    if (candidate.compare(memberDn, Qt::CaseInsensitive) == 0)
                        member = true;
                }
                if (!member)
                    continue;
                if (!m_writes.removeMember
                    || !m_writes.removeMember(group.id, memberDn, &error)) {
                    putLe32(fixed, kStatusNotSupported);
                    emit requestReceived(QStringLiteral(
                        "RemoveMemberFromForeignDomain %1: no store").arg(memberDn));
                    return fixed;
                }
                ++removed;
            }
        }
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("RemoveMemberFromForeignDomain %1 (%2 groups)")
                                 .arg(memberDn.isEmpty() ? QStringLiteral("unknown SID")
                                                        : memberDn)
                                 .arg(removed));
        return fixed;
    }
    // SamrEnumerateGroupsInDomain (opnum 11): the same enumeration buffer as the
    // user call, over the groups the store holds.
    case Samr::OpEnumerateGroupsInDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 context = 0;
        quint32 accessMask = 0;
        quint32 maximum = 0;
        reader.u32(&context);
        reader.u32(&accessMask);
        reader.u32(&maximum);
        Q_UNUSED(accessMask)
        Q_UNUSED(maximum)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, context);
            fixed.append(char(0));
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? QList<DirectoryObject>() : groups();
        const int start = int(context);
        QList<DirectoryObject> page;
        for (int i = start; i < all.size(); ++i)
            page.append(all.at(i));

        QList<QPair<quint32, QString>> entries;
        for (const DirectoryObject &group : page) {
            QString name = group.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = group.name;
            entries.append(qMakePair(ridOf(group), name));
        }
        appendEnumeration(fixed, entries, 0);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateGroups (%1)").arg(page.size()));
        return fixed;
    }
    // SamrEnumerateAliasesInDomain (opnum 15): the group enumeration buffer
    // again, over the domain-local groups, and with no access mask in the
    // request (MS-SAMR 3.1.5.10.2).
    case Samr::OpEnumerateAliasesInDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 context = 0;
        quint32 maximum = 0;
        reader.u32(&context);
        reader.u32(&maximum);
        Q_UNUSED(maximum)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, context);
            fixed.append(char(0));
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? builtinAliasObjects(directory()) : aliases();
        QList<DirectoryObject> page;
        for (int i = int(context); i < all.size(); ++i)
            page.append(all.at(i));
        QList<QPair<quint32, QString>> entries;
        for (const DirectoryObject &alias : page) {
            QString name = alias.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = alias.name;
            entries.append(qMakePair(ridOf(alias), name));
        }
        appendEnumeration(fixed, entries, 0);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateAliases (%1)").arg(page.size()));
        return fixed;
    }
    // SamrQueryDisplayInfo2 (opnum 48): the display enumeration. `net group
    // /domain` asks for level 3 — the domain's groups — and pages through them
    // with start_idx, which is the only way that command reads a group list: it
    // never issues the group enumeration (opnum 11). The reply is three
    // referents, total_size, returned_size and the SAMPR_DISPLAYINFO, each the
    // offset of its own word or structure behind them (MS-RPCE 2.2.10.6), then
    // the status after all of it.
    case Samr::OpQueryDisplayInfo2: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 level = 0;
        reader.u16(&level);
        reader.align(4); // the level is a uint16 and start_idx a uint32
        quint32 startIdx = 0;
        quint32 maxEntries = 0;
        quint32 bufSize = 0;
        reader.u32(&startIdx);
        reader.u32(&maxEntries);
        reader.u32(&bufSize);

        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, 0); // total_size
            putLe32(fixed, 0); // returned_size
            putLe32(fixed, 0); // the display information
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // Level 3 is the one a client here has asked for; the users a client
        // lists come over the enumeration call (opnum 13). Any other level is
        // refused rather than guessed at.
        if (level != 3) {
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("QueryDisplayInfo2 level %1 unsupported")
                                     .arg(level));
            return fixed;
        }

        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? QList<DirectoryObject>() : groups();

        // How much of the list this reply may carry. The DC box B's guest reads
        // caps a request at 0x20 entries and then at the batch the client says
        // it will take, counting 0x20 bytes per entry; the entries carry idx
        // values, so a client pages on those and gets one page per call.
        const quint32 entrySize = 0x20;
        if (maxEntries > 0x20)
            maxEntries = 0x20;
        const quint32 batchSize = maxEntries * entrySize;
        if (batchSize > bufSize)
            maxEntries = qMin(bufSize / entrySize, maxEntries);

        const int count = int(all.size());
        const int from = int(qMin<quint32>(startIdx, quint32(count)));
        QList<DirectoryObject> page;
        for (int i = from; i < count && int(page.size()) < int(maxEntries); ++i)
            page.append(all.at(i));

        // The two sizes travel as the DC measures them: total_size counts the
        // entries this page carries and returned_size the batch the client
        // asked for, before the buffer trimmed the count. The guest pages on
        // the entries' own idx values, so both are ours to report this way.
        const quint32 totalSize = quint32(page.size()) * entrySize;
        const quint32 returnedSize = page.isEmpty() ? 0u : batchSize;

        const int base = int(fixed.size());
        putLe32(fixed, quint32(base + 12)); // total_size
        putLe32(fixed, quint32(base + 16)); // returned_size
        putLe32(fixed, quint32(base + 20)); // the SAMPR_DISPLAYINFO
        putLe32(fixed, totalSize);
        putLe32(fixed, returnedSize);
        // The display information is the count and a pointer to the entries,
        // which sit directly behind it.
        putLe32(fixed, quint32(page.size()));
        putLe32(fixed, page.isEmpty() ? 0u : quint32(base + 28));
        // The entries are a conformant array — `[size_is(count)]
        // samr_DispEntryFullGroup *entries` in samr.idl — so its referent
        // begins with the maximum count and the elements follow it
        // (MS-RPCE 2.2.10.3). Without this word a client reads the first
        // entry's idx as the maximum count and decodes one entry from inside
        // the first, which is a silently unusable answer rather than a fault.
        if (!page.isEmpty())
            putLe32(fixed, quint32(page.size()));
        QByteArray deferred;
        QList<QPair<int, int>> strings;
        for (int i = 0; i < page.size(); ++i) {
            const DirectoryObject &group = page.at(i);
            QString name = group.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = group.name;
            // SAMPR_DISP_ENTRY_FULL_GROUP: idx, rid, attributes, name,
            // description. The idx is one-based on the whole list, so a page
            // that starts halfway still numbers its entries where they belong.
            putLe32(fixed, startIdx + quint32(i) + 1);
            putLe32(fixed, ridOf(group));
            putLe32(fixed, 7u); // SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
            appendCountedString(fixed, deferred, name, strings);
            appendCountedString(fixed, deferred,
                                group.attributes.value(QStringLiteral("description")), strings);
        }
        placeStrings(fixed, deferred, strings);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("QueryDisplayInfo2(groups %1 of %2 from %3)")
                                 .arg(page.size())
                                 .arg(count)
                                 .arg(startIdx));
        return fixed;
    }
    // SamrGetAliasMembership (opnum 16): which domain-local groups a set of
    // SIDs belongs to, as samr_Ids. `net user /domain` asks it after
    // GetGroupsForUser to fill its "Local Group memberships" line, and stops
    // the command when the call is refused.
    case Samr::OpGetAliasMembership: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        // [in] lsa_SidArray: the count, the array's referent and maximum
        // count, one referent per lsa_SidPtr, then each SID. The count comes
        // first — `{ uint32 num_sids; lsa_SidPtr *sids; }` — so reading a
        // referent here made the count a pointer value and ran the element
        // loop off the stub.
        quint32 count = 0;
        quint32 sidArrayReferent = 0;
        quint32 maximum = 0;
        if (!reader.u32(&count) || !reader.u32(&sidArrayReferent)
            || !reader.u32(&maximum))
            return {};
        for (quint32 i = 0; i < count; ++i) {
            quint32 element = 0;
            if (!reader.u32(&element))
                return {};
        }
        QList<QByteArray> sids;
        for (quint32 i = 0; i < count; ++i) {
            QByteArray sid;
            if (!readWireSid(reader, &sid))
                return {};
            sids.append(sid);
        }
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, 0); // NULL rids referent
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // Each alias this domain has, in RID order, joined once when any of the
        // given SIDs is on its member list.
        const QList<DirectoryObject> pool =
            domain.dn == kBuiltinDomainSid ? builtinAliasObjects(directory()) : aliases();
        QList<quint32> rids;
        for (const DirectoryObject &alias : pool) {
            const QList<QByteArray> members = aliasMemberSids(alias.id, ridOf(alias));
            for (const QByteArray &sid : sids) {
                if (!members.contains(sid))
                    continue;
                rids.append(ridOf(alias));
                break;
            }
        }
        // [out] samr_Ids: the count, the array's referent, its maximum count,
        // then the conformant array. The referent stays non-NULL on an empty
        // list, the way the reference DC answers it.
        putLe32(fixed, quint32(rids.size())); // Count
        putLe32(fixed, 12);                   // ids at stub 12, behind the header
        putLe32(fixed, quint32(rids.size())); // MaximumCount
        for (quint32 rid : rids)
            putLe32(fixed, rid);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("GetAliasMembership(%1 -> %2)")
                                 .arg(sids.size())
                                 .arg(rids.size()));
        return fixed;
    }
    case Samr::OpOpenAlias: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 desired = 0;
        quint32 rid = 0;
        reader.u32(&desired);
        reader.u32(&rid);
        Q_UNUSED(desired)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const QList<DirectoryObject> pool =
            domain.dn == kBuiltinDomainSid ? builtinAliasObjects(directory()) : aliases();
        for (const DirectoryObject &alias : pool) {
            if (ridOf(alias) != rid)
                continue;
            fixed.append(newHandle(Handle::Alias, alias.id, rid));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("OpenAlias(%1)").arg(alias.name));
            return fixed;
        }
        fixed.append(QByteArray(kHandleSize, '\0'));
        putLe32(fixed, kStatusNoSuchAlias);
        return fixed;
    }
    // SamrAddMemberToAlias / SamrRemoveMemberFromAlias (opnum 31/32): the member
    // arrives as a SID rather than the RID the group calls take.
    case Samr::OpAddMemberToAlias:
    case Samr::OpRemoveMemberFromAlias: {
        const bool adding = opnum == Samr::OpAddMemberToAlias;
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        QByteArray memberSid;
        if (!readWireSid(reader, &memberSid))
            return {};
        Handle alias;
        if (!lookupHandle(handle, Handle::Alias, &alias)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // A BUILTIN alias is a stored object under CN=Builtin, so the write below
        // lands on it like any other alias; the target is resolved once the
        // member's DN is known. A server with no write backend has nothing to
        // store it in, and says so before it judges the member.
        const bool builtinAlias = isBuiltinAlias(alias.dn);
        if (builtinAlias && !m_writes.create) {
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("%1 BUILTIN alias member: no store")
                                     .arg(adding ? QStringLiteral("Add") : QStringLiteral("Remove")));
            return fixed;
        }
        // The member must be in this domain: same identifier authority and the
        // same sub-authorities up to the one that carries the relative id.
        const QByteArray domainSid = Ndr::sidFromString(m_config.domainSid);
        const bool inDomain = domainSid.size() >= 12 && memberSid.size() > domainSid.size()
                              && memberSid.size() >= 8 && memberSid.mid(2, 6) == domainSid.mid(2, 6)
                              && memberSid.mid(8, domainSid.size() - 12)
                                     == domainSid.mid(8, domainSid.size() - 12);
        quint32 rid = 0;
        if (inDomain)
            rid = quint32(quint8(memberSid.at(memberSid.size() - 4)))
                  | (quint32(quint8(memberSid.at(memberSid.size() - 3))) << 8)
                  | (quint32(quint8(memberSid.at(memberSid.size() - 2))) << 16)
                  | (quint32(quint8(memberSid.at(memberSid.size() - 1))) << 24);
        QString memberDn;
        if (rid != 0) {
            for (const DirectoryObject &object : directory()) {
                if (object.id.isEmpty() || ridOf(object) != rid)
                    continue;
                memberDn = object.id;
                break;
            }
        }
        if (memberDn.isEmpty()) {
            putLe32(fixed, kStatusInvalidMember);
            emit requestReceived(QStringLiteral("%1 alias member refused: no account for that SID")
                                     .arg(adding ? QStringLiteral("Add") : QStringLiteral("Remove")));
            return fixed;
        }
        QString error;
        const QString target = builtinAlias ? ensureBuiltinAlias(alias.dn, &error) : alias.dn;
        if (target.isEmpty()) {
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("%1 BUILTIN alias member refused: %2")
                                     .arg(adding ? QStringLiteral("Add") : QStringLiteral("Remove"),
                                          error));
            return fixed;
        }
        const bool ok = adding ? (m_writes.addMember && m_writes.addMember(target, memberDn, &error))
                               : (m_writes.removeMember
                                  && m_writes.removeMember(target, memberDn, &error));
        putLe32(fixed, ok ? kStatusSuccess
                          : (adding ? kStatusMemberInAlias : kStatusMemberNotInAlias));
        emit requestReceived(QStringLiteral("%1AliasMember(%2) %3")
                                 .arg(adding ? QStringLiteral("Add") : QStringLiteral("Remove"),
                                      memberDn, ok ? QStringLiteral("ok") : error));
        return fixed;
    }
    // SamrGetMembersInAlias (opnum 33): SAMPR_PSID_ARRAY, a count and a pointer
    // to an array of SIDs. Each element is a pointer to an RPC_SID, so the
    // referents follow the array, in order.
    case Samr::OpGetMembersInAlias: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle alias;
        if (!lookupHandle(handle, Handle::Alias, &alias)) {
            putLe32(fixed, 0); // Count
            putLe32(fixed, 0); // NULL array
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const QList<QByteArray> sids = aliasMemberSids(alias.dn, alias.rid);
        putLe32(fixed, quint32(sids.size()));
        if (sids.isEmpty()) {
            putLe32(fixed, 0);
        } else {
            const int array = int(fixed.size()) + 4; // behind the maximum count
            putLe32(fixed, quint32(array));          // the SID pointers
            putLe32(fixed, quint32(sids.size()));    // maximum count
            quint32 at = quint32(array + 4 + 4 * int(sids.size()));
            for (const QByteArray &sid : sids) {
                putLe32(fixed, at);
                at += 12 + 4 * quint32(sid.size() >= 2 ? quint8(sid.at(1)) : 0);
            }
            for (const QByteArray &sid : sids)
                putWireSid(fixed, sid);
        }
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("GetAliasMembers(%1)").arg(sids.size()));
        return fixed;
    }
    case Samr::OpOpenUser: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 desired = 0;
        quint32 rid = 0;
        reader.u32(&desired);
        reader.u32(&rid);
        Q_UNUSED(desired)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        if (domain.dn == kBuiltinDomainSid) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusNoSuchUser);
            return fixed;
        }
        for (const DirectoryObject &user : users()) {
            const QString sidText = user.attributes.value(QStringLiteral("objectSid"));
            const QStringList parts = sidText.split(QLatin1Char('-'));
            if (parts.isEmpty() || parts.last().toUInt() != rid)
                continue;
            fixed.append(newHandle(Handle::User, user.id, rid));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("OpenUser(%1)").arg(user.name));
            return fixed;
        }
        fixed.append(QByteArray(kHandleSize, '\0'));
        putLe32(fixed, kStatusNoSuchUser);
        return fixed;
    }
    // Opnum 36 (SamrQueryInformationUser) is byte-for-byte the same call on
    // the wire as opnum 47: handle + u16 class, Buffer union + NTSTATUS back.
    case Samr::OpQueryInformationUser:
    case Samr::OpQueryInformationUser2: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        reader.u16(&infoClass);
        Handle user;
        if (!lookupHandle(handle, Handle::User, &user)) {
            // The arm is `[out,ref,switch_is(level)] samr_UserInfo **info`: the
            // inner pointer is a unique pointer, so a refusal sends a
            // four-byte null referent before the status, never a single zero
            // octet. A one-octet marker puts the status where the client reads
            // a pointer and the call fails to unmarshal at all.
            putLe32(fixed, 0); // NULL user-information pointer
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        for (const DirectoryObject &object : directory()) {
            if (object.id != user.dn)
                continue;
            // SamrQueryInformationUser2, class 6 = SamrUserInformationName.
            // SAMPR_USER_INFO_BUFFER is a union whose discriminant is a USHORT;
            // the arm holds two inline RPC_UNICODE_STRINGs whose buffers are
            // deferred after both fixed parts (MS-SAMR 2.2.7.14, confirmed byte
            // for byte against impacket's marshaller).
            if (infoClass == 6) {
                QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.isEmpty())
                    account = object.name;
                QString fullName = object.attributes.value(QStringLiteral("displayName"));
                if (fullName.isEmpty())
                    fullName = object.name;

                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(6));       // tag: SamrUserInformationName
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));

                const QByteArray accountUtf16 = Ndr::utf16le(account);
                const QByteArray fullUtf16 = Ndr::utf16le(fullName);
                fixed.append(char(accountUtf16.size() & 0xff));
                fixed.append(char((accountUtf16.size() >> 8) & 0xff));
                fixed.append(char(accountUtf16.size() & 0xff));
                fixed.append(char((accountUtf16.size() >> 8) & 0xff));
                putLe32(fixed, accountUtf16.isEmpty() ? 0u : 0x0002d521u);
                fixed.append(char(fullUtf16.size() & 0xff));
                fixed.append(char((fullUtf16.size() >> 8) & 0xff));
                fixed.append(char(fullUtf16.size() & 0xff));
                fixed.append(char((fullUtf16.size() >> 8) & 0xff));
                putLe32(fixed, fullUtf16.isEmpty() ? 0u : 0x0002d522u);

                if (!accountUtf16.isEmpty())
                    appendVaryingString(deferred, account);
                if (!fullUtf16.isEmpty())
                    appendVaryingString(deferred, fullName);
                placeStrings(fixed, deferred, strings);
                putLe32(fixed, kStatusSuccess);
                return fixed;
            }
            // SamrQueryInformationUser2, class 16 = SamrUserControlInformation:
            // the arm is one ULONG. The tag is a USHORT padded back out to four
            // bytes, as impacket's reader expects it.
            if (infoClass == 16) {
                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(16));      // tag: SamrUserControlInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                putLe32(fixed, accountFlagsFor(
                                   object.attributes.value(QStringLiteral("userAccountControl"))
                                       .toUInt()));
                putLe32(fixed, kStatusSuccess);
                return fixed;
            }
            // Classes 1, 2 and 3 are the general, preferences and logon
            // records: what a property sheet reads before it opens the
            // aggregate, and what `rpcclient queryuser 1` asks for. Each arm is
            // a structure of counted strings, so every character buffer is
            // deferred behind the fixed part in field order; the numbering is
            // Samba's samr.idl, which is the order clients on this wire use.
            if (infoClass == 1 || infoClass == 2 || infoClass == 3 || infoClass == 5) {
                QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.isEmpty())
                    account = object.name;
                QString fullName = object.attributes.value(QStringLiteral("displayName"));
                if (fullName.isEmpty())
                    fullName = object.name;
                quint32 primaryGroup =
                    object.attributes.value(QStringLiteral("primaryGroupID")).toUInt();
                if (primaryGroup == 0)
                    primaryGroup = 513; // Domain Users

                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(infoClass));
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));

                QByteArray arm;
                QByteArray armDeferred;
                QList<QPair<int, int>> strings;
                if (infoClass == 1) {
                    // samr_UserInfo1: the two names, the primary group, the
                    // administrator's comment and the user's own.
                    appendCountedString(arm, armDeferred, account, strings);
                    appendCountedString(arm, armDeferred, fullName, strings);
                    putLe32(arm, primaryGroup);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("description")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("comment")),
                                        strings);
                } else if (infoClass == 2) {
                    // samr_UserInfo2: the user's comment, a reserved string AD
                    // accepts and never stores, and the two locale numbers.
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("comment")),
                                        strings);
                    appendCountedString(arm, armDeferred, QString(), strings);
                    putLe16(arm, quint16(
                                     object.attributes.value(QStringLiteral("countryCode"))
                                         .toUInt()));
                    putLe16(arm, quint16(object.attributes.value(QStringLiteral("codePage"))
                                             .toUInt()));
                } else if (infoClass == 5) {
                    // samr_UserInfo5: the logon record's predecessor. The same
                    // identity, home and workstations fields and the same week
                    // and counters, but the password instants collapse to
                    // last_password_change and one expiry, so the arm is laid
                    // out in that order rather than class 3's.
                    const quint32 accountControl =
                        object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                    appendCountedString(arm, armDeferred, account, strings);
                    appendCountedString(arm, armDeferred, fullName, strings);
                    putLe32(arm, ridOf(object));
                    putLe32(arm, primaryGroup);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("homeDirectory")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("homeDrive")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("scriptPath")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("profilePath")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("description")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("userWorkstations")),
                                        strings);
                    putLe64(arm, object.attributes.value(QStringLiteral("lastLogon")).toULongLong());
                    putLe64(arm,
                            object.attributes.value(QStringLiteral("lastLogoff")).toULongLong());
                    const QByteArray hours = logonHoursForWire(QByteArray::fromHex(
                        object.attributes.value(QStringLiteral("logonHours")).toLatin1()));
                    putLe16(arm, quint16(hours.size() * 8));
                    arm.append(QByteArray(2, '\0'));
                    appendDeferredPointer(arm, armDeferred, strings);
                    putLe16(arm, quint16(
                                     object.attributes.value(QStringLiteral("badPwdCount"))
                                         .toUInt()));
                    putLe16(arm, quint16(
                                     object.attributes.value(QStringLiteral("logonCount"))
                                         .toUInt()));
                    // No alignment gap before the instants: these legacy
                    // records carry OLD_LARGE_INTEGER, two ULONGs, so they sit
                    // on a four-byte boundary and a pad here desynchronises the
                    // deferred buffers of every client that reads them.
                    const quint64 pwdLastSet =
                        object.attributes.value(QStringLiteral("pwdLastSet")).toULongLong();
                    putLe64(arm, pwdLastSet == 0 ? 0 : ntTimeFromUnix(pwdLastSet));
                    putLe64(arm,
                            object.attributes.value(QStringLiteral("accountExpires")).toULongLong());
                    putLe32(arm, accountFlagsFor(accountControl));
                    putLe32(armDeferred, 1260);
                    putLe32(armDeferred, 0);
                    putLe32(armDeferred, quint32(hours.size()));
                    armDeferred.append(hours);
                    while (armDeferred.size() % 4 != 0)
                        armDeferred.append('\0');
                } else {
                    // samr_UserInfo3: the whole logon record — the account's
                    // identity, its home and profile paths, the five instants a
                    // logon screen and a `net user` listing show, the week, and
                    // the counters SamLogon keeps.
                    const quint64 pwdLastSet =
                        object.attributes.value(QStringLiteral("pwdLastSet")).toULongLong();
                    const quint32 accountControl =
                        object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                    const LdapServer::PasswordPolicy policy =
                        LdapServer::passwordPolicyFrom(domainObject());
                    appendCountedString(arm, armDeferred, account, strings);
                    appendCountedString(arm, armDeferred, fullName, strings);
                    putLe32(arm, ridOf(object));
                    putLe32(arm, primaryGroup);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("homeDirectory")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("homeDrive")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("scriptPath")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("profilePath")),
                                        strings);
                    appendCountedString(arm, armDeferred,
                                        object.attributes.value(QStringLiteral("userWorkstations")),
                                        strings);
                    // lastLogon is per-DC NTTIME as stored; the password
                    // instants are the domain policy's window around
                    // pwdLastSet, the same three the aggregate reports.
                    putLe64(arm, object.attributes.value(QStringLiteral("lastLogon")).toULongLong());
                    putLe64(arm,
                            object.attributes.value(QStringLiteral("lastLogoff")).toULongLong());
                    putLe64(arm, pwdLastSet == 0 ? 0 : ntTimeFromUnix(pwdLastSet));
                    putLe64(arm, ntTimeFromDelta(pwdLastSet, accountControl, policy.minAge));
                    putLe64(arm, ntTimeFromDelta(pwdLastSet, accountControl, policy.maxAge));
                    const QByteArray hours = logonHoursForWire(QByteArray::fromHex(
                        object.attributes.value(QStringLiteral("logonHours")).toLatin1()));
                    putLe16(arm, quint16(hours.size() * 8));
                    arm.append(QByteArray(2, '\0'));
                    appendDeferredPointer(arm, armDeferred, strings);
                    putLe16(arm, quint16(
                                     object.attributes.value(QStringLiteral("badPwdCount"))
                                         .toUInt()));
                    putLe16(arm, quint16(
                                     object.attributes.value(QStringLiteral("logonCount"))
                                         .toUInt()));
                    putLe32(arm, accountFlagsFor(accountControl));
                    // The week is the last deferred buffer: maximum count 1260
                    // from the IDL, offset zero, one octet per hour.
                    putLe32(armDeferred, 1260);
                    putLe32(armDeferred, 0);
                    putLe32(armDeferred, quint32(hours.size()));
                    armDeferred.append(hours);
                    while (armDeferred.size() % 4 != 0)
                        armDeferred.append('\0');
                }

                appendArmWithStrings(fixed, arm, armDeferred, strings);
                putLe32(fixed, kStatusSuccess);
                emit requestReceived(QStringLiteral("QueryInformationUser2(%1, class %2)")
                                         .arg(user.dn)
                                         .arg(infoClass));
                return fixed;
            }
            // Classes 7, 9, 10, 11, 12, 13, 14, 17 and 20 are the single-field
            // records a property sheet edits one at a time: the account name,
            // the primary group, the home path, the logon script, the profile
            // path, the administrator's comment, the workstations list, the
            // expiry instant and the user parameters blob. Each arm is one
            // counted string, two for the home path, or one ULONG or NTTIME, so
            // they are answered from the attributes the general record reads.
            if (infoClass == 7 || infoClass == 9 || infoClass == 10 || infoClass == 11
                || infoClass == 12 || infoClass == 13 || infoClass == 14 || infoClass == 17
                || infoClass == 20) {
                const auto attribute = [&object](const char *name) {
                    return object.attributes.value(QLatin1String(name));
                };
                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(infoClass));
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                if (infoClass == 9) {
                    quint32 primaryGroup =
                        object.attributes.value(QStringLiteral("primaryGroupID")).toUInt();
                    if (primaryGroup == 0)
                        primaryGroup = 513; // Domain Users
                    putLe32(fixed, primaryGroup);
                } else if (infoClass == 17) {
                    // accountExpires is already an NTTIME, and zero is the
                    // value AD keeps for an account that never expires.
                    putLe64(fixed,
                            object.attributes.value(QStringLiteral("accountExpires"))
                                .toULongLong());
                } else {
                    QByteArray arm;
                    QByteArray armDeferred;
                    QList<QPair<int, int>> strings;
                    if (infoClass == 7) {
                        QString account =
                            object.attributes.value(QStringLiteral("sAMAccountName"));
                        if (account.isEmpty())
                            account = object.name;
                        appendCountedString(arm, armDeferred, account, strings);
                    } else if (infoClass == 10) {
                        appendCountedString(arm, armDeferred, attribute("homeDirectory"),
                                            strings);
                        appendCountedString(arm, armDeferred, attribute("homeDrive"), strings);
                    } else {
                        const char *name = infoClass == 11   ? "scriptPath"
                                           : infoClass == 12 ? "profilePath"
                                           : infoClass == 13 ? "description"
                                           : infoClass == 14 ? "userWorkstations"
                                                             : "userParameters";
                        appendCountedString(arm, armDeferred, attribute(name), strings);
                    }
                    appendArmWithStrings(fixed, arm, armDeferred, strings);
                }
                putLe32(fixed, kStatusSuccess);
                emit requestReceived(QStringLiteral("QueryInformationUser2(%1, class %2)")
                                         .arg(user.dn)
                                         .arg(infoClass));
                return fixed;
            }
            // Class 8 = SamrUserFullNameInformation: one inline
            // RPC_UNICODE_STRING whose characters are deferred behind the arm.
            if (infoClass == 8) {
                QString fullName = object.attributes.value(QStringLiteral("displayName"));
                if (fullName.isEmpty())
                    fullName = object.name;
                const QByteArray utf16 = Ndr::utf16le(fullName);
                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(8));      // tag: SamrUserFullNameInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(utf16.size() & 0xff));
                fixed.append(char((utf16.size() >> 8) & 0xff));
                fixed.append(char(utf16.size() & 0xff));
                fixed.append(char((utf16.size() >> 8) & 0xff));
                putLe32(fixed, utf16.isEmpty() ? 0u : 0x0002d541u);
                if (!utf16.isEmpty())
                    appendVaryingString(deferred, fullName);
                placeStrings(fixed, deferred, strings);
                putLe32(fixed, kStatusSuccess);
                return fixed;
            }
            // Class 4 = SamrUserLogonHoursInformation: the week the account is
            // limited to, as a unit count and a deferred array of one byte per
            // hour. A stored logonHours is a 21-byte bitmap, so it is handed to
            // the same normaliser the aggregate answer uses.
            if (infoClass == 4) {
                const QByteArray hours = logonHoursForWire(QByteArray::fromHex(
                    object.attributes.value(QStringLiteral("logonHours")).toLatin1()));
                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(4));       // tag: SamrUserLogonHoursInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                putLe16(fixed, quint16(hours.size() * 8));
                fixed.append(QByteArray(2, '\0'));
                putLe32(fixed, quint32(fixed.size() + 4)); // week, directly behind this word
                putLe32(deferred, 1260);
                putLe32(deferred, 0);
                putLe32(deferred, quint32(hours.size()));
                deferred.append(hours);
                while (deferred.size() % 4 != 0)
                    deferred.append('\0');
                placeStrings(fixed, deferred, strings);
                putLe32(fixed, kStatusSuccess);
                emit requestReceived(QStringLiteral("QueryInformationUser2(%1, logon hours)")
                                         .arg(user.dn));
                return fixed;
            }
            // Class 21 = SamrUserAllInformation: the aggregate every directory
            // tool reads a user with, so it is the cheapest way to fill a
            // property sheet or a `net rpc user` listing in one call.
            if (infoClass == 21) {
                AllUserInfo info;
                QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.isEmpty())
                    account = object.name;
                QString fullName = object.attributes.value(QStringLiteral("displayName"));
                if (fullName.isEmpty())
                    fullName = object.name;

                info.userName = account;
                info.fullName = fullName;
                info.homeDirectory = object.attributes.value(QStringLiteral("homeDirectory"));
                info.homeDrive = object.attributes.value(QStringLiteral("homeDrive"));
                info.scriptPath = object.attributes.value(QStringLiteral("scriptPath"));
                info.profilePath = object.attributes.value(QStringLiteral("profilePath"));
                info.adminComment = object.attributes.value(QStringLiteral("description"));
                info.workstations = object.attributes.value(QStringLiteral("userWorkstations"));
                info.userComment = object.attributes.value(QStringLiteral("comment"));
                info.parameters = object.attributes.value(QStringLiteral("userParameters"));
                info.logonHours = QByteArray::fromHex(
                    object.attributes.value(QStringLiteral("logonHours")).toLatin1());
                info.countryCode = quint16(
                    object.attributes.value(QStringLiteral("countryCode")).toUInt());
                info.codePage =
                    quint16(object.attributes.value(QStringLiteral("codePage")).toUInt());
                info.userId = ridOf(object);
                info.primaryGroupId =
                    object.attributes.value(QStringLiteral("primaryGroupID")).toUInt();
                if (info.primaryGroupId == 0)
                    info.primaryGroupId = 513; // Domain Users
                info.accountControl =
                    object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                info.accountFlags = accountFlagsFor(info.accountControl);
                // The logon statistics a DC keeps on the account: when it last
                // logged on and how many times, and how many passwords were
                // refused. SamLogon writes them, so this reads the same values
                // a domain administrator would see on the account tab.
                info.lastLogon =
                    object.attributes.value(QStringLiteral("lastLogon")).toULongLong();
                info.logonCount = quint16(
                    object.attributes.value(QStringLiteral("logonCount")).toUInt());
                info.badPasswordCount = quint16(
                    object.attributes.value(QStringLiteral("badPwdCount")).toUInt());
                info.accountExpires =
                    object.attributes.value(QStringLiteral("accountExpires")).toULongLong();
                const quint64 pwdLastSet =
                    object.attributes.value(QStringLiteral("pwdLastSet")).toULongLong();
                info.passwordLastSet = pwdLastSet == 0 ? 0 : ntTimeFromUnix(pwdLastSet);
                // The account tab's three password facts, from the domain policy
                // the logon paths enforce: whether the credential has aged out or
                // must be changed, when a change is allowed again, and when one
                // is required.
                const LdapServer::PasswordPolicy policy =
                    LdapServer::passwordPolicyFrom(domainObject());
                const quint32 accountControl =
                    object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                info.passwordExpired =
                    PasswordAge::state(pwdLastSet, accountControl, policy.maxAge)
                    != PasswordAge::State::Valid;
                info.passwordCanChange = ntTimeFromDelta(pwdLastSet, accountControl, policy.minAge);
                info.passwordMustChange = ntTimeFromDelta(pwdLastSet, accountControl, policy.maxAge);
                info.ntPasswordPresent = QByteArray::fromHex(
                                             object.attributes.value(QStringLiteral("ntHash"))
                                                 .toLatin1())
                                             .size()
                                         == 16;
                info.fieldsPresent = kFieldsPresentStandard;

                putLe32(fixed, quint32(fixed.size() + 4)); // union, at the tag that follows
                fixed.append(char(21));      // tag: SamrUserAllInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                QByteArray arm;
                QByteArray armDeferred;
                QList<QPair<int, int>> strings;
                appendAllUserInfo(info, arm, armDeferred, strings);
                appendArmWithStrings(fixed, arm, armDeferred, strings);
                putLe32(fixed, kStatusSuccess);
                emit requestReceived(QStringLiteral("QueryInformationUser2(%1, all)")
                                         .arg(user.dn));
                return fixed;
            }
            emit requestReceived(QStringLiteral("QueryInformationUser2(class %1) refused: "
                                                "no arm for that class")
                                     .arg(infoClass));
            putLe32(fixed, 0); // NULL user-information pointer
            putLe32(fixed, 0xc0000003u); // STATUS_INVALID_INFO_CLASS
            return fixed;
        }
        putLe32(fixed, 0); // NULL user-information pointer
        putLe32(fixed, kStatusNoSuchUser);
        return fixed;
    }
    case Samr::OpLookupNamesInDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 count = 0;
        quint32 maximumCount = 0;
        quint32 offset = 0;
        quint32 actualCount = 0;
        if (!reader.u32(&count) || !reader.u32(&maximumCount) || !reader.u32(&offset)
            || !reader.u32(&actualCount))
            return {};
        Q_UNUSED(maximumCount)
        // lsa_String names[] is a conformant and varying array of structures
        // containing a pointer: every element's fixed part comes first, then the
        // character buffers, in pointer order (MS-RPCE §14.3.7.2).
        count = qMin(qMin(count, actualCount), 1000u);
        QList<quint32> buffers;
        QList<quint16> lengths;
        for (quint32 i = 0; i < count; ++i) {
            quint16 length = 0;
            quint16 maximumLength = 0;
            quint32 referent = 0;
            if (!reader.u16(&length) || !reader.u16(&maximumLength) || !reader.u32(&referent))
                return {};
            Q_UNUSED(maximumLength)
            lengths.append(length);
            buffers.append(referent);
        }
        QStringList names;
        for (quint32 i = 0; i < count; ++i) {
            QString name;
            if (buffers.at(i) != 0 && lengths.at(i) > 0) {
                quint32 stringMax = 0;
                quint32 stringOffset = 0;
                quint32 stringActual = 0;
                if (!reader.u32(&stringMax) || !reader.u32(&stringOffset)
                    || !reader.u32(&stringActual))
                    return {};
                Q_UNUSED(stringMax)
                Q_UNUSED(stringOffset)
                QByteArray chars;
                if (!reader.bytes(int(stringActual) * 2, &chars))
                    return {};
                name = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                          qsizetype(chars.size() / 2));
                reader.align(4);
            }
            names.append(name);
        }

        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            // SAMPR_ULONG_ARRAY carries a [unique] pointer, so a NULL referent is
            // a legal empty answer even on the error path.
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        // BUILTIN holds only its aliases, so its own name and RID tables are the
        // alias table rather than the account NC.
        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? builtinAliasObjects(directory()) : directory();
        QList<quint32> rids;
        QList<quint32> types;
        int mapped = 0;
        for (const QString &name : names) {
            quint32 rid = 0;
            quint32 type = 0;
            for (const DirectoryObject &object : all) {
                QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.isEmpty())
                    account = object.name;
                if (account.compare(name, Qt::CaseInsensitive) != 0)
                    continue;
                rid = ridOf(object);
                type = nameTypeFor(object);
                if (rid != 0)
                    break;
            }
            if (rid != 0)
                ++mapped;
            rids.append(rid);
            types.append(type);
        }

        // samr_Ids is {Count; [size_is(Count)] uint32 *Ids}. On this wire the
        // array follows its own pointer: count, pointer, maximum count,
        // elements. Probed against impacket's reader, which consumes the array
        // in place and ignores the pointer, so the value it receives is the one
        // a Windows stub resolves — the offset of the array from the start of
        // this reply.
        //
        // A lookup where no name mapped carries no array at all: both counts
        // zero and both pointers NULL. Answering with one element of RID 0 and
        // type 0 — which is what this arm did — reads as a mapped name with no
        // account, and a 2000 client answered that with 124 (the same error as
        // an unmarshalled pointer) instead of the "not found" the status word
        // asked for.
        const quint32 status = mapped == 0 ? kStatusNoneMapped
                              : (mapped < int(names.size()) ? kStatusSomeNotMapped
                                                            : kStatusSuccess);
        if (status == kStatusNoneMapped) {
            putLe32(fixed, 0); // RelativeIds.Count
            putLe32(fixed, 0); // RelativeIds.Ids
            putLe32(fixed, 0); // Types.Count
            putLe32(fixed, 0); // Types.Ids
            putLe32(fixed, status);
            emit requestReceived(QStringLiteral("LookupNames(none of %1 mapped)")
                                     .arg(names.size()));
            return fixed;
        }
        putLe32(fixed, quint32(names.size()));
        putLe32(fixed, names.isEmpty() ? 0u : quint32(fixed.size() + 4)); // Ids
        if (!names.isEmpty()) {
            putLe32(fixed, quint32(rids.size())); // MaximumCount
            for (quint32 rid : rids)
                putLe32(fixed, rid);
        }
        putLe32(fixed, quint32(types.size()));
        putLe32(fixed, types.isEmpty() ? 0u : quint32(fixed.size() + 4)); // Types
        if (!types.isEmpty()) {
            putLe32(fixed, quint32(types.size())); // MaximumCount
            for (quint32 type : types)
                putLe32(fixed, type);
        }
        putLe32(fixed, status);
        emit requestReceived(QStringLiteral("LookupNames(%1 of %2 mapped)")
                                 .arg(mapped)
                                 .arg(names.size()));
        return fixed;
    }
    case Samr::OpLookupIdsInDomain: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 count = 0;
        quint32 maximumCount = 0;
        quint32 offset = 0;
        quint32 actualCount = 0;
        if (!reader.u32(&count) || !reader.u32(&maximumCount) || !reader.u32(&offset)
            || !reader.u32(&actualCount))
            return {};
        Q_UNUSED(maximumCount)
        Q_UNUSED(offset)
        count = qMin(qMin(count, actualCount), 1000u);
        QList<quint32> rids;
        for (quint32 i = 0; i < count; ++i) {
            quint32 rid = 0;
            if (!reader.u32(&rid))
                return {};
            rids.append(rid);
        }

        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }

        const QList<DirectoryObject> all =
            domain.dn == kBuiltinDomainSid ? builtinAliasObjects(directory()) : directory();
        QStringList names;
        QList<quint32> types;
        QList<bool> resolved;
        int mapped = 0;
        for (quint32 rid : rids) {
            QString name;
            quint32 type = 0;
            for (const DirectoryObject &object : all) {
                if (rid == 0 || ridOf(object) != rid)
                    continue;
                name = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (name.isEmpty())
                    name = object.name;
                type = nameTypeFor(object);
                break;
            }
            if (!name.isEmpty())
                ++mapped;
            names.append(name);
            types.append(type);
            resolved.append(!name.isEmpty());
        }

        // SAMPR_RETURNED_USTRING_ARRAY: a conformant array of
        // RPC_UNICODE_STRING. The element structures are followed by their own
        // character buffers, and the type array follows in the same shape. The
        // pointers carry the offset of what they name, the element buffers
        // included: those are written after every element, so their offsets are
        // only known once the blob has been appended.
        putLe32(fixed, quint32(rids.size()));
        putLe32(fixed, rids.isEmpty() ? 0u : quint32(fixed.size() + 4)); // Names
        putLe32(fixed, quint32(rids.size())); // MaximumCount
        QByteArray stringBuffers;
        QList<QPair<int, int>> stringReferents; // stub position, offset in the blob
        for (int i = 0; i < names.size(); ++i) {
            const QByteArray utf16 = Ndr::utf16le(names.at(i));
            const quint16 length = quint16(utf16.size());
            fixed.append(char(length & 0xff));
            fixed.append(char((length >> 8) & 0xff));
            fixed.append(char(length & 0xff));
            fixed.append(char((length >> 8) & 0xff));
            if (resolved.value(i)) {
                stringReferents.append(qMakePair(int(fixed.size()), int(stringBuffers.size())));
                putLe32(fixed, 0); // patched once the blob is placed
                appendVaryingString(stringBuffers, names.at(i));
            } else {
                putLe32(fixed, 0);
            }
        }
        const int buffersBase = int(fixed.size());
        fixed.append(stringBuffers);
        for (const QPair<int, int> &referent : stringReferents)
            setLe32(fixed, referent.first, quint32(buffersBase + referent.second));
        putLe32(fixed, quint32(types.size()));
        if (types.isEmpty()) {
            putLe32(fixed, 0);
        } else {
            putLe32(fixed, quint32(fixed.size() + 4)); // Types
            putLe32(fixed, quint32(types.size()));     // MaximumCount
            for (quint32 type : types)
                putLe32(fixed, type);
        }
        const quint32 status = rids.isEmpty() ? kStatusSuccess
                              : (mapped == 0 ? kStatusNoneMapped
                                             : (mapped < int(rids.size()) ? kStatusSomeNotMapped
                                                                         : kStatusSuccess));
        putLe32(fixed, status);
        emit requestReceived(QStringLiteral("LookupIds(%1 of %2 mapped)")
                                 .arg(mapped)
                                 .arg(rids.size()));
        return fixed;
    }
    case Samr::OpCreateUser2:
    case Samr::OpCreateGroupInDomain:
    case Samr::OpCreateAliasInDomain: {
        const bool creatingAlias = opnum == Samr::OpCreateAliasInDomain;
        const bool creatingGroup = opnum == Samr::OpCreateGroupInDomain;
        // Aliases and groups are both group objects, and their create calls
        // carry the same arguments, so one arm serves both.
        const bool creatingContainer = creatingAlias || creatingGroup;
        const quint32 existsStatus = creatingAlias ? kStatusAliasExists
                                   : (creatingGroup ? kStatusGroupExists : kStatusUserExists);
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        // RPC_UNICODE_STRING: lengths and buffer referent inline, characters
        // deferred behind the rest of the request.
        quint16 nameLength = 0;
        quint16 nameMaximum = 0;
        quint32 nameReferent = 0;
        if (!reader.u16(&nameLength) || !reader.u16(&nameMaximum) || !reader.u32(&nameReferent))
            return {};
        Q_UNUSED(nameMaximum)
        // The name's characters follow its pointer: max count, offset, actual
        // count, then the UTF-16 text. The scalars come after that.
        QString account;
        if (nameReferent != 0 && nameLength > 0) {
            quint32 maximum = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
                return {};
            Q_UNUSED(maximum)
            Q_UNUSED(offset)
            QByteArray chars;
            if (!reader.bytes(int(actual) * 2, &chars))
                return {};
            account = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                         qsizetype(chars.size() / 2));
            reader.align(4);
        }
        // CreateUser2 carries an AccountType before the access mask; the group
        // and alias calls have only the mask.
        quint32 accountFlags = 0;
        quint32 accessMask = 0;
        if (creatingContainer) {
            if (!reader.u32(&accessMask))
                return {};
        } else if (!reader.u32(&accountFlags) || !reader.u32(&accessMask)) {
            return {};
        }
        account = account.trimmed();

        Handle domain;
        const bool handleOk = lookupHandle(handle, Handle::Domain, &domain);
        if (handleOk && domain.dn == kBuiltinDomainSid) {
            // BUILTIN's aliases are fixed by Windows; there is nowhere to store
            // a new one, so the create is refused rather than lost.
            fixed.append(QByteArray(kHandleSize, '\0'));
            if (!creatingGroup)
                putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("Create %1 in BUILTIN refused")
                                     .arg(creatingAlias ? QStringLiteral("alias")
                                          : (creatingGroup ? QStringLiteral("group")
                                                           : QStringLiteral("user"))));
            return fixed;
        }
        if (!handleOk || account.isEmpty() || !m_writes.create) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            if (!creatingGroup)
                putLe32(fixed, 0); // GrantedAccess
            putLe32(fixed, 0); // RelativeId
            putLe32(fixed, handleOk ? kStatusAccessDenied : kStatusInvalidHandle);
            return fixed;
        }

        // A user created here may be a machine: a workstation or server trust
        // account is a `computer` in CN=Computers, owned by Domain Computers —
        // not a user in CN=Users. A Windows join reads the entry back after
        // creating it, and every later search for members of the domain looks
        // for the computer class, so the class has to be right from the first
        // write rather than patched in afterwards.
        const quint32 accountControl = accountControlFor(accountFlags);
        const bool machineAccount =
            !creatingContainer && (accountControl & (0x1000u | 0x2000u)) != 0;
        DirectoryObject object;
        object.name = account;
        object.kind = creatingContainer ? ObjectKind::Group
                     : machineAccount   ? ObjectKind::Computer
                                        : ObjectKind::User;
        object.type = creatingContainer ? QStringLiteral("Security Group")
                      : machineAccount   ? QStringLiteral("Computer")
                                         : QStringLiteral("User");
        object.container = machineAccount
            ? QStringLiteral("CN=Computers,%1").arg(m_config.baseDn)
            : QStringLiteral("CN=Users,%1").arg(m_config.baseDn);
        object.id = QStringLiteral("CN=%1,%2").arg(account, object.container);
        object.attributes.insert(QStringLiteral("cn"), account);
        object.attributes.insert(QStringLiteral("sAMAccountName"), account);
        object.attributes.insert(
            QStringLiteral("objectClass"),
            creatingContainer ? QStringLiteral("group")
            : machineAccount
                ? QStringLiteral("top;person;organizationalPerson;user;computer")
                : QStringLiteral("user"));
        if (creatingAlias) {
            // GROUP_TYPE_RESOURCE_GROUP | SECURITY_ENABLED: the domain-local
            // group AD presents to SAMR as an alias.
            object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("-2147483644"));
            object.attributes.insert(QStringLiteral("description"), QString());
        } else if (creatingGroup) {
            object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("Security"));
        } else {
            object.attributes.insert(QStringLiteral("userAccountControl"),
                                     QString::number(accountControl));
            if (machineAccount) {
                // A joined machine is a member of Domain Computers, and its
                // host name is what Netlogon and the DNS zone publish.
                object.attributes.insert(QStringLiteral("primaryGroupID"),
                                         QStringLiteral("515"));
                const QString host = account.endsWith(QLatin1Char('$'))
                                         ? account.left(account.size() - 1)
                                         : account;
                object.attributes.insert(
                    QStringLiteral("dNSHostName"),
                    QStringLiteral("%1.%2").arg(host.toLower(), m_config.realm.toLower()));
            }
            object.attributes.insert(QStringLiteral("displayName"), account);
            object.attributes.insert(QStringLiteral("pwdLastSet"), QStringLiteral("0"));
            // A machine account carries its own service principal names. A
            // Windows join creates the account here and does not write them
            // afterwards, while its first domain logon asks the KDC for
            // HOST/<name>; without these the TGT is issued and the next
            // request is answered S_PRINCIPAL_UNKNOWN, so the logon fails.
            if (machineAccount || account.endsWith(QLatin1Char('$'))) {
                const QString host = account.endsWith(QLatin1Char('$'))
                                         ? account.left(account.size() - 1)
                                         : account;
                object.attributes.insert(
                    QStringLiteral("servicePrincipalName"),
                    QStringLiteral("HOST/%1; HOST/%2; RestrictedKrbHost/%1; RestrictedKrbHost/%2")
                        .arg(host.toUpper(),
                             QStringLiteral("%1.%2").arg(host.toLower(),
                                                         m_config.realm.toLower())));
            }
        }

        const QString kindName = creatingAlias ? QStringLiteral("Alias")
                                 : (creatingGroup ? QStringLiteral("Group")
                                                  : QStringLiteral("User"));
        QString error;
        if (!m_writes.create(&object, &error)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            if (!creatingContainer)
                putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, existsStatus);
            emit requestReceived(QStringLiteral("Create%1(%2) refused: %3")
                                     .arg(kindName, account, error));
            return fixed;
        }

        const quint32 rid = ridOf(object);
        fixed.append(newHandle(creatingAlias ? Handle::Alias
                                             : (creatingGroup ? Handle::Group : Handle::User),
                               object.id, rid));
        if (!creatingContainer)
            putLe32(fixed, accessMask);
        putLe32(fixed, rid);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("Create%1(%2) rid %3").arg(kindName, account).arg(rid));
        return fixed;
    }
    case Samr::OpDeleteUser:
    case Samr::OpDeleteGroup:
    case Samr::OpDeleteAlias: {
        const bool deletingGroup = opnum == Samr::OpDeleteGroup;
        const bool deletingAlias = opnum == Samr::OpDeleteAlias;
        const Handle::Kind kind = deletingAlias ? Handle::Alias
                                 : (deletingGroup ? Handle::Group : Handle::User);
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle object;
        if (!lookupHandle(handle, kind, &object)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        if (deletingAlias && isBuiltinAlias(object.dn)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("DeleteAlias(%1): BUILTIN is read-only")
                                     .arg(object.dn));
            return fixed;
        }
        QString error;
        if (!m_writes.remove || !m_writes.remove(object.dn, &error)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusAccessDenied);
            return fixed;
        }
        m_handles.remove(handle);
        fixed.append(QByteArray(kHandleSize, '\0'));
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("Delete%1(%2)")
                                 .arg(deletingAlias ? QStringLiteral("Alias")
                                      : (deletingGroup ? QStringLiteral("Group")
                                                       : QStringLiteral("User")),
                                      object.dn));
        return fixed;
    }
    case Samr::OpOpenGroup: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 accessMask = 0;
        quint32 rid = 0;
        if (!reader.u32(&accessMask) || !reader.u32(&rid))
            return {};
        Q_UNUSED(accessMask)
        Handle domain;
        if (!lookupHandle(handle, Handle::Domain, &domain)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        if (domain.dn == kBuiltinDomainSid) {
            // The BUILTIN aliases are opened with SamrOpenAlias; there are no
            // groups of the other kind in that domain.
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusNoSuchGroup);
            return fixed;
        }
        for (const DirectoryObject &object : directory()) {
            if (object.kind != ObjectKind::Group || ridOf(object) != rid)
                continue;
            fixed.append(newHandle(Handle::Group, object.id, rid));
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("OpenGroup(%1)").arg(object.name));
            return fixed;
        }
        fixed.append(QByteArray(kHandleSize, '\0'));
        putLe32(fixed, kStatusNoSuchGroup);
        return fixed;
    }
    case Samr::OpAddMemberToGroup:
    case Samr::OpRemoveMemberFromGroup: {
        const bool adding = opnum == Samr::OpAddMemberToGroup;
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 rid = 0;
        if (!reader.u32(&rid))
            return {};
        if (adding) {
            quint32 attributes = 0;
            if (!reader.u32(&attributes))
                return {};
            Q_UNUSED(attributes)
        }
        Handle group;
        if (!lookupHandle(handle, Handle::Group, &group)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        QString memberDn;
        for (const DirectoryObject &object : directory()) {
            if (ridOf(object) == rid && object.kind != ObjectKind::Group) {
                memberDn = object.id;
                break;
            }
        }
        if (memberDn.isEmpty()) {
            putLe32(fixed, kStatusNoSuchUser);
            return fixed;
        }
        QString error;
        const bool ok = adding ? (m_writes.addMember && m_writes.addMember(group.dn, memberDn, &error))
                               : (m_writes.removeMember
                                  && m_writes.removeMember(group.dn, memberDn, &error));
        putLe32(fixed, ok ? kStatusSuccess
                          : (adding ? kStatusMemberInGroup : kStatusMemberNotInGroup));
        emit requestReceived(QStringLiteral("%1 r%2 %3")
                                 .arg(adding ? QStringLiteral("AddMember")
                                             : QStringLiteral("RemoveMember"))
                                 .arg(rid)
                                 .arg(ok ? QStringLiteral("ok") : QStringLiteral("refused")));
        return fixed;
    }
    case Samr::OpGetMembersInGroup: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle group;
        if (!lookupHandle(handle, Handle::Group, &group)) {
            putLe32(fixed, 0); // NULL buffer
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        QList<quint32> rids;
        const QList<DirectoryObject> all = directory();
        for (const DirectoryObject &object : all) {
            if (object.id.compare(group.dn, Qt::CaseInsensitive) != 0 || object.kind != ObjectKind::Group)
                continue;
            for (const QString &member : object.members) {
                for (const DirectoryObject &candidate : all) {
                    if (candidate.id.compare(member, Qt::CaseInsensitive) == 0) {
                        rids.append(ridOf(candidate));
                        break;
                    }
                }
            }
            break;
        }
        // PSAMPR_GET_MEMBERS_BUFFER: pointer, member count, then the two
        // conformant arrays (maximum count plus elements), and the status last.
        // Attributes are ULONGs, as SAMPR_GET_MEMBERS_BUFFER declares them.
        putLe32(fixed, 0x0002e200u);          // buffer referent
        putLe32(fixed, quint32(rids.size())); // MemberCount
        putLe32(fixed, 0x0002e210u);          // Members referent
        putLe32(fixed, 0x0002e220u);          // Attributes referent
        putLe32(fixed, quint32(rids.size())); // Members MaximumCount
        for (quint32 rid : rids)
            putLe32(fixed, rid);
        putLe32(fixed, quint32(rids.size())); // Attributes MaximumCount
        for (int i = 0; i < rids.size(); ++i) {
            // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            putLe32(fixed, 7);
        }
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("GetMembers(%1)").arg(rids.size()));
        return fixed;
    }
    // SamrSetInformationUser / SamrSetInformationUser2 (opnum 57/58). Both take
    // the user handle, a USHORT information class and then the union itself: an
    // inline USHORT discriminant followed by the arm, so a scalar arm starts
    // four bytes after the class. Confirmed against impacket's marshaller.
    // SamrQueryInformationGroup (opnum 12): the group's name, attributes, member
    // count and description, in the union shape impacket and Windows expect.
    case Samr::OpQueryInformationGroup: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        Handle group;
        if (!lookupHandle(handle, Handle::Group, &group)) {
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        DirectoryObject found;
        bool foundObject = false;
        for (const DirectoryObject &object : directory()) {
            if (object.id.compare(group.dn, Qt::CaseInsensitive) == 0
                && object.kind == ObjectKind::Group) {
                found = object;
                foundObject = true;
                break;
            }
        }
        if (!foundObject) {
            putLe32(fixed, 0);
            putLe32(fixed, kStatusNoSuchGroup);
            return fixed;
        }
        QString name = found.attributes.value(QStringLiteral("sAMAccountName"));
        if (name.isEmpty())
            name = found.name;
        const QString comment = found.attributes.value(QStringLiteral("description"));

        QByteArray deferred;
        auto beginArm = [&fixed](quint16 tag) {
            putLe32(fixed, 0x0002e600u + tag); // union referent
            fixed.append(char(tag & 0xff));
            fixed.append(char((tag >> 8) & 0xff));
            fixed.append(char(0));
            fixed.append(char(0));
        };
        // RPC_UNICODE_STRING: Length, MaximumLength and the buffer referent
        // inline; the characters go after the fixed part of the structure.
        auto putUnicode = [&fixed, &deferred](const QString &text, quint32 referent) {
            const QByteArray utf16 = Ndr::utf16le(text);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, utf16.isEmpty() ? 0u : referent);
            if (!utf16.isEmpty())
                appendVaryingString(deferred, text);
        };
        switch (infoClass) {
        case 1:   // GroupGeneralInformation: name, attributes, members, comment
        case 5: { // GroupAllInformation2: the same structure
            beginArm(infoClass);
            putUnicode(name, 0x0002e610u);
            putLe32(fixed, 7u); // SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
            putLe32(fixed, quint32(found.members.size()));
            putUnicode(comment, 0x0002e620u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationGroup(%1, all)").arg(name));
            return fixed;
        }
        case 2: { // GroupNameInformation
            beginArm(2);
            putUnicode(name, 0x0002e630u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationGroup(%1, name)").arg(name));
            return fixed;
        }
        case 3: { // GroupAttributeInformation
            beginArm(3);
            putLe32(fixed, 7u);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationGroup(%1, attributes)").arg(name));
            return fixed;
        }
        case 4: { // GroupAdminCommentInformation
            beginArm(4);
            putUnicode(comment, 0x0002e640u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationGroup(%1, comment)").arg(name));
            return fixed;
        }
        default:
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("QueryInformationGroup class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
    }
    // SamrQueryInformationAlias (opnum 28): the alias's name, member count and
    // administrative comment. Unlike the group and domain queries the union is
    // behind a pointer here, so it starts with a referent.
    case Samr::OpQueryInformationAlias: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        Handle alias;
        if (!lookupHandle(handle, Handle::Alias, &alias)) {
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const QList<DirectoryObject> pool =
            isBuiltinAlias(alias.dn) ? builtinAliasObjects(directory()) : aliases();
        DirectoryObject found;
        bool foundObject = false;
        for (const DirectoryObject &object : pool) {
            if (object.id.compare(alias.dn, Qt::CaseInsensitive) == 0) {
                found = object;
                foundObject = true;
                break;
            }
        }
        if (!foundObject) {
            putLe32(fixed, 0);
            putLe32(fixed, kStatusNoSuchAlias);
            return fixed;
        }
        QString name = found.attributes.value(QStringLiteral("sAMAccountName"));
        if (name.isEmpty())
            name = found.name;
        const QString comment = found.attributes.value(QStringLiteral("description"));

        QByteArray deferred;
        auto beginArm = [&fixed](quint16 tag) {
            putLe32(fixed, 0x0002e700u + tag); // union referent
            fixed.append(char(tag & 0xff));
            fixed.append(char((tag >> 8) & 0xff));
            fixed.append(char(0));
            fixed.append(char(0));
        };
        auto putUnicode = [&fixed, &deferred](const QString &text, quint32 referent) {
            const QByteArray utf16 = Ndr::utf16le(text);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, utf16.isEmpty() ? 0u : referent);
            if (!utf16.isEmpty())
                appendVaryingString(deferred, text);
        };
        switch (infoClass) {
        case 1: { // AliasGeneralInformation
            beginArm(1);
            putUnicode(name, 0x0002e710u);
            putLe32(fixed, quint32(isBuiltinAlias(alias.dn)
                                       ? builtinMemberSids(alias.rid, m_config.domainSid,
                                                          directory(), found.members)
                                             .size()
                                       : found.members.size()));
            putUnicode(comment, 0x0002e720u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationAlias(%1, general)").arg(name));
            return fixed;
        }
        case 2: { // AliasNameInformation
            beginArm(2);
            putUnicode(name, 0x0002e730u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationAlias(%1, name)").arg(name));
            return fixed;
        }
        case 3: { // AliasAdminCommentInformation
            beginArm(3);
            putUnicode(comment, 0x0002e740u);
            placeStrings(fixed, deferred, strings);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationAlias(%1, comment)").arg(name));
            return fixed;
        }
        default:
            putLe32(fixed, 0);
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("QueryInformationAlias class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
    }
    // SamrSetInformationAlias (opnum 29): the comment is a directory attribute;
    // renaming needs a rename the write backend does not offer, so the name
    // class is refused rather than accepted and dropped.
    case Samr::OpSetInformationAlias: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        quint16 tag = 0;
        if (!reader.u16(&infoClass) || !reader.u16(&tag))
            return {};
        Q_UNUSED(tag)
        Handle alias;
        if (!lookupHandle(handle, Handle::Alias, &alias)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        const bool builtinAlias = isBuiltinAlias(alias.dn);
        if (builtinAlias && !m_writes.set) {
            // No store to write a BUILTIN alias's description into: the refusal
            // comes before the arguments are read, as it did when every BUILTIN
            // write was refused.
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("SetInformationAlias(%1): no store")
                                     .arg(alias.dn));
            return fixed;
        }
        if (infoClass != 3) {
            putLe32(fixed, infoClass == 2 ? kStatusNotSupported : kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("SetInformationAlias class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
        quint16 length = 0;
        quint16 maximum = 0;
        quint32 referent = 0;
        if (!reader.u16(&length) || !reader.u16(&maximum) || !reader.u32(&referent))
            return {};
        Q_UNUSED(maximum)
        QString text;
        if (referent != 0 && length > 0) {
            quint32 count = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&count) || !reader.u32(&offset) || !reader.u32(&actual))
                return {};
            Q_UNUSED(count)
            Q_UNUSED(offset)
            QByteArray chars;
            if (!reader.bytes(int(actual) * 2, &chars))
                return {};
            text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                      qsizetype(chars.size() / 2));
        }
        QString error;
        const QString target = builtinAlias ? ensureBuiltinAlias(alias.dn, &error) : alias.dn;
        const bool ok = !target.isEmpty() && m_writes.set
                        && m_writes.set(target, QStringLiteral("description"), text, &error);
        putLe32(fixed, ok ? kStatusSuccess
                          : (m_writes.set ? kStatusAccessDenied : kStatusNotSupported));
        emit requestReceived(QStringLiteral("SetInformationAlias(%1) description: %2")
                                 .arg(alias.dn, ok ? QStringLiteral("ok") : error));
        return fixed;
    }
    // SamrSetInformationGroup (opnum 14). The description is a directory
    // attribute; the name and the SE_GROUP_* attribute set are not, so those
    // classes are refused rather than accepted and dropped.
    case Samr::OpSetInformationGroup: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        quint16 tag = 0;
        if (!reader.u16(&infoClass) || !reader.u16(&tag))
            return {};
        Q_UNUSED(tag)
        Handle group;
        if (!lookupHandle(handle, Handle::Group, &group)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        switch (infoClass) {
        case 4: { // GroupAdminCommentInformation
            quint16 length = 0;
            quint16 maximum = 0;
            quint32 referent = 0;
            if (!reader.u16(&length) || !reader.u16(&maximum) || !reader.u32(&referent))
                return {};
            Q_UNUSED(maximum)
            QString text;
            if (referent != 0 && length > 0) {
                quint32 count = 0;
                quint32 offset = 0;
                quint32 actual = 0;
                if (!reader.u32(&count) || !reader.u32(&offset) || !reader.u32(&actual))
                    return {};
                Q_UNUSED(count)
                Q_UNUSED(offset)
                QByteArray chars;
                if (!reader.bytes(int(actual) * 2, &chars))
                    return {};
                text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                          qsizetype(chars.size() / 2));
            }
            QString error;
            const bool ok = m_writes.set && m_writes.set(group.dn, QStringLiteral("description"),
                                                         text, &error);
            putLe32(fixed, ok ? kStatusSuccess
                              : (m_writes.set ? kStatusAccessDenied : kStatusNotSupported));
            emit requestReceived(QStringLiteral("SetInformationGroup(%1) description: %2")
                                     .arg(group.dn, ok ? QStringLiteral("ok") : error));
            return fixed;
        }
        default:
            putLe32(fixed, kStatusNotSupported);
            emit requestReceived(QStringLiteral("SetInformationGroup class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
    }
    case Samr::OpSetInformationUser:
    case Samr::OpSetInformationUser2: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        quint16 tag = 0;
        if (!reader.u16(&infoClass) || !reader.u16(&tag))
            return {};
        Q_UNUSED(tag) // a client always repeats the class it selected
        Handle user;
        if (!lookupHandle(handle, Handle::User, &user)) {
            putLe32(fixed, kStatusInvalidHandle);
            return fixed;
        }
        // A handle outlives the account if something else deleted it, so the
        // object is looked up again rather than trusted from the handle alone.
        // Its current value is kept: a set that names no account type still
        // describes the account it opened, and acct_flags need converting.
        const QList<DirectoryObject> all = directory();
        const DirectoryObject *target = nullptr;
        for (const DirectoryObject &o : all) {
            if (o.id.compare(user.dn, Qt::CaseInsensitive) == 0) {
                target = &o;
                break;
            }
        }
        if (!target) {
            putLe32(fixed, kStatusNoSuchUser);
            return fixed;
        }
        auto writeAttribute = [&](const QString &attribute, const QString &value) {
            QString error;
            const bool ok = m_writes.set && m_writes.set(user.dn, attribute, value, &error);
            putLe32(fixed, ok ? kStatusSuccess
                              : (m_writes.set ? kStatusAccessDenied : kStatusNotSupported));
            emit requestReceived(QStringLiteral("SetInformationUser(%1) %2=%3: %4")
                                     .arg(user.dn, attribute, value,
                                          ok ? QStringLiteral("ok") : error));
            return fixed;
        };

        // A set that names several attributes reports the first failure and the
        // rest of the record stands as it was, which is what AD does when one
        // attribute in the write is refused.
        auto apply = [&](const QList<QPair<QString, QString>> &writes) {
            quint32 status = kStatusSuccess;
            for (const auto &write : writes) {
                QString error;
                if (m_writes.set && m_writes.set(user.dn, write.first, write.second, &error))
                    continue;
                status = m_writes.set ? kStatusAccessDenied : kStatusNotSupported;
                emit requestReceived(QStringLiteral("SetInformationUser(%1) %2=%3: %4")
                                         .arg(user.dn, write.first, write.second,
                                              m_writes.set ? error
                                                           : QStringLiteral("no write backend")));
                break;
            }
            putLe32(fixed, status);
            return fixed;
        };
        // A counted string arrives as its (length, maximum, referent) tuple in
        // the fixed part and its characters behind it, in field order, so a
        // record of several strings is read in two passes: every tuple first,
        // then every buffer the referents point at.
        struct Counted {
            quint16 length = 0;
            quint32 referent = 0;
        };
        // A structure that does not parse is refused with a status rather than
        // answered with an empty stub, which a client reads as transport loss.
        const auto malformed = [&fixed]() {
            putLe32(fixed, kStatusInvalidParameter);
            return fixed;
        };
        const auto readCounted = [&reader](Counted *out) {
            quint16 maximum = 0;
            return reader.u16(&out->length) && reader.u16(&maximum)
                   && reader.u32(&out->referent);
        };
        const auto readCountedText = [&reader](const Counted &ref, QString *out) {
            out->clear();
            if (ref.referent == 0)
                return true;
            // An empty string still carries its buffer's three counts, so it is
            // read and dropped rather than skipped: skipping it would shift
            // every buffer behind it.
            quint32 count = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&count) || !reader.u32(&offset) || !reader.u32(&actual))
                return false;
            if (actual == 0)
                return true;
            QByteArray chars;
            if (!reader.bytes(int(actual) * 2, &chars))
                return false;
            *out = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                      qsizetype(chars.size() / 2));
            // Some clients count the terminator in the buffer (impacket does);
            // it ends the string rather than being part of it, and AD stores
            // what is left.
            if (out->endsWith(QChar(u'\0')))
                out->chop(1);
            return true;
        };

        switch (infoClass) {
        // Classes 1, 2 and 3 are the general, preferences and logon records a
        // property sheet writes back whole. The fields the DC owns — the RID,
        // the instants the domain policy derives, the logon counters and the
        // account flags — are read past and left alone: they are not the
        // client's to set through this call, and a stale copy of them must not
        // overwrite what the server keeps.
        case 1: { // SamrUserGeneralInformation
            Counted account;
            Counted fullName;
            quint32 primaryGroup = 0;
            Counted description;
            Counted comment;
            QString accountText;
            QString fullNameText;
            QString descriptionText;
            QString commentText;
            if (!readCounted(&account) || !readCounted(&fullName)
                || !reader.u32(&primaryGroup) || !readCounted(&description)
                || !readCounted(&comment) || !readCountedText(account, &accountText)
                || !readCountedText(fullName, &fullNameText)
                || !readCountedText(description, &descriptionText)
                || !readCountedText(comment, &commentText))
                return malformed();
            QList<QPair<QString, QString>> writes;
            // The account name is what the handle was opened by; a record that
            // carries none is not a rename and is skipped.
            if (!accountText.isEmpty())
                writes.append({QStringLiteral("sAMAccountName"), accountText});
            writes.append({QStringLiteral("displayName"), fullNameText});
            writes.append({QStringLiteral("primaryGroupID"), QString::number(primaryGroup)});
            writes.append({QStringLiteral("description"), descriptionText});
            writes.append({QStringLiteral("comment"), commentText});
            return apply(writes);
        }
        case 2: { // SamrUserPreferencesInformation
            Counted comment;
            Counted reserved;
            quint16 countryCode = 0;
            quint16 codePage = 0;
            QString commentText;
            QString reservedText;
            // The second string is the field AD accepts and never stores, so its
            // characters are consumed to keep the stream in step and dropped.
            if (!readCounted(&comment) || !readCounted(&reserved) || !reader.u16(&countryCode)
                || !reader.u16(&codePage) || !readCountedText(comment, &commentText)
                || !readCountedText(reserved, &reservedText))
                return malformed();
            return apply({{QStringLiteral("comment"), commentText},
                          {QStringLiteral("countryCode"), QString::number(countryCode)},
                          {QStringLiteral("codePage"), QString::number(codePage)}});
        }
        case 3: { // SamrUserLogonInformation
            Counted account;
            Counted fullName;
            quint32 rid = 0;
            quint32 primaryGroup = 0;
            Counted homeDirectory;
            Counted homeDrive;
            Counted scriptPath;
            Counted profilePath;
            Counted workstations;
            // The five instants sit between the workstations and the week, in
            // a fixed eight-byte width each (MS-SAMR 2.2.7.5). samr_LogonHours
            // follows as a pointer to the week: its units-per-week count and
            // referent inline, the octets behind the strings.
            quint64 instants[5] = {};
            quint16 hoursLength = 0;
            quint16 hoursPad = 0;
            quint32 hoursReferent = 0;
            quint16 badPasswordCount = 0;
            quint16 logonCount = 0;
            quint32 accountControl = 0;
            bool complete = readCounted(&account) && readCounted(&fullName) && reader.u32(&rid)
                            && reader.u32(&primaryGroup) && readCounted(&homeDirectory)
                            && readCounted(&homeDrive) && readCounted(&scriptPath)
                            && readCounted(&profilePath) && readCounted(&workstations);
            for (quint64 &instant : instants)
                complete = complete && reader.u64(&instant);
            complete = complete && reader.u16(&hoursLength) && reader.u16(&hoursPad)
                       && reader.u32(&hoursReferent) && reader.u16(&badPasswordCount)
                       && reader.u16(&logonCount) && reader.u32(&accountControl);
            if (!complete)
                return malformed();
            Q_UNUSED(instants)
            Q_UNUSED(hoursPad)
            Q_UNUSED(rid)
            Q_UNUSED(logonCount)
            Q_UNUSED(accountControl)
            QString accountText;
            QString fullNameText;
            QString homeDirectoryText;
            QString homeDriveText;
            QString scriptPathText;
            QString profilePathText;
            QString workstationsText;
            if (!readCountedText(account, &accountText) || !readCountedText(fullName, &fullNameText)
                || !readCountedText(homeDirectory, &homeDirectoryText)
                || !readCountedText(homeDrive, &homeDriveText)
                || !readCountedText(scriptPath, &scriptPathText)
                || !readCountedText(profilePath, &profilePathText)
                || !readCountedText(workstations, &workstationsText))
                return malformed();
            QList<QPair<QString, QString>> writes;
            if (!accountText.isEmpty())
                writes.append({QStringLiteral("sAMAccountName"), accountText});
            writes.append({QStringLiteral("displayName"), fullNameText});
            writes.append({QStringLiteral("primaryGroupID"), QString::number(primaryGroup)});
            writes.append({QStringLiteral("homeDirectory"), homeDirectoryText});
            writes.append({QStringLiteral("homeDrive"), homeDriveText});
            writes.append({QStringLiteral("scriptPath"), scriptPathText});
            writes.append({QStringLiteral("profilePath"), profilePathText});
            writes.append({QStringLiteral("userWorkstations"), workstationsText});
            if (hoursReferent != 0) {
                // units_per_week counts bits; the array itself is one octet per
                // eight hours of the week.
                quint32 count = 0;
                quint32 offset = 0;
                quint32 actual = 0;
                QByteArray hours;
                if (!reader.u32(&count) || !reader.u32(&offset) || !reader.u32(&actual)
                    || !reader.bytes(int(actual), &hours))
                    return malformed();
                if (!hours.isEmpty())
                    writes.append(
                        {QStringLiteral("logonHours"), QString::fromLatin1(hours.toHex())});
            }
            Q_UNUSED(hoursLength)
            return apply(writes);
        }
        case 8:  // SamrUserFullNameInformation
        case 13: // SamrUserAdminCommentInformation
        case 20: { // SamrUserParametersInformation
            // RPC_UNICODE_STRING: the lengths and the buffer pointer inline, the
            // characters deferred behind the rest of the arm.
            quint16 length = 0;
            quint16 maximum = 0;
            quint32 referent = 0;
            if (!reader.u16(&length) || !reader.u16(&maximum) || !reader.u32(&referent))
                return {};
            Q_UNUSED(maximum)
            QString text;
            if (referent != 0 && length > 0) {
                quint32 count = 0;
                quint32 offset = 0;
                quint32 actual = 0;
                if (!reader.u32(&count) || !reader.u32(&offset) || !reader.u32(&actual))
                    return {};
                Q_UNUSED(count)
                Q_UNUSED(offset)
                QByteArray chars;
                if (!reader.bytes(int(actual) * 2, &chars))
                    return {};
                text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                          qsizetype(chars.size() / 2));
            }
            const QString attribute = infoClass == 8    ? QStringLiteral("displayName")
                                      : infoClass == 13 ? QStringLiteral("description")
                                                        : QStringLiteral("userParameters");
            return writeAttribute(attribute, text);
        }
        case 16: { // SamrUserControlInformation: SAMR's acct_flags, not the
            // directory's userAccountControl bits. `net user NAME /active:no`
            // sends ACB_DISABLED (0x1) here, and storing it as written left the
            // account enabled in a bit set that means nothing in AD.
            quint32 flags = 0;
            if (!reader.u32(&flags))
                return {};
            const quint32 stored =
                target->attributes.value(QStringLiteral("userAccountControl")).toUInt();
            return writeAttribute(QStringLiteral("userAccountControl"),
                                  QString::number(accountControlFromFlags(flags, stored)));
        }
        case 17: { // SamrUserExpiresInformation: accountExpires, a FILETIME
            quint64 expires = 0;
            if (!reader.u64(&expires))
                return {};
            // 0 and 0x7fffffffffffffff both mean "never" in AD.
            const QString value = (expires == 0 || expires == 0x7fffffffffffffffull)
                                      ? QStringLiteral("0")
                                      : QString::number(expires);
            return writeAttribute(QStringLiteral("accountExpires"), value);
        }
        case 18: { // SamrUserInternal1Information: DES-enciphered OWF hashes
            // EncryptedNtOwfPassword, EncryptedLmOwfPassword, then three UCHARs
            // (MS-SAMR 2.2.7.11). MS-SAMR 2.2.11.1 enciphers each 16-byte hash
            // with two DES keys taken from the session key, so the hashes never
            // cross the wire in the clear either.
            QByteArray payload;
            if (!reader.bytes(35, &payload))
                return {};
            const quint8 ntPresent = quint8(payload.at(32));
            const quint8 lmPresent = quint8(payload.at(33));
            const quint8 passwordExpired = quint8(payload.at(34));
            if (!ntPresent) {
                // No LM credential is stored at all, so a set that carries only
                // one has nothing to apply; saying so beats a silent success.
                putLe32(fixed, lmPresent ? kStatusNotSupported : kStatusInvalidParameter);
                emit requestReceived(QStringLiteral("SetInformationUser(%1) hash set refused: "
                                                    "no NT hash present")
                                         .arg(user.dn));
                return fixed;
            }
            const QByteArray ntHash = Des::decryptOwfHash(payload.left(16), sessionKey);
            if (ntHash.size() != 16) {
                putLe32(fixed, kStatusInvalidParameter);
                emit requestReceived(QStringLiteral("SetInformationUser(%1) hash set refused: "
                                                    "no session key")
                                         .arg(user.dn));
                return fixed;
            }
            QString error;
            const bool ok = m_writes.setNtHash && m_writes.setNtHash(user.dn, ntHash, &error);
            if (ok && passwordExpired != 0)
                m_writes.set(user.dn, QStringLiteral("pwdLastSet"), QStringLiteral("0"), &error);
            // A refused hash is the same policy refusal the plaintext classes
            // report — history, length, the account being gone — so it carries
            // the same word. Answering ACCESS_DENIED here named the caller's
            // rights instead, and told a client with the rights two different
            // things about one refusal depending on how it encoded the password.
            putLe32(fixed, ok ? kStatusSuccess
                              : (m_writes.setNtHash ? kStatusPasswordRestriction
                                                    : kStatusNotSupported));
            emit requestReceived(QStringLiteral("SetInformationUser(%1) NT hash: %2")
                                     .arg(user.dn,
                                          ok ? QStringLiteral("ok") : error));
            return fixed;
        }
        // Classes 21, 23 and 25 carry the whole SAMPR_USER_ALL_INFORMATION
        // structure, and 23/25 append the password buffer after it. This is the
        // call ADUC's "new user" dialog makes, and the one `net rpc user add`
        // follows with after SamrCreateUser2InDomain.
        case 21:   // SamprUserAllInformation
        case 23:   // SamprUserInternal4Information
        case 25: { // SamprUserInternal4InformationNew
            const bool carriesPassword = infoClass != 21;
            const int passwordSize = infoClass == 25 ? 532 : 516;
            IncomingUserInfo wire;
            if (!readAllUserInfo(reader, carriesPassword ? passwordSize : 0, &wire)) {
                putLe32(fixed, kStatusInvalidParameter);
                emit requestReceived(QStringLiteral("SetInformationUser(%1) class %2: "
                                                    "malformed structure")
                                         .arg(user.dn)
                                         .arg(infoClass));
                return fixed;
            }
            const AllUserInfo &info = wire.info;

            // WhichFields names what the caller wants applied. Everything it
            // does not name — the RID, the logon counters, the timestamps the
            // server keeps — is left alone, as AD leaves it.
            QList<QPair<QString, QString>> writes;
            auto carry = [&](quint32 bit, const QString &attribute, const QString &value) {
                if (info.fieldsPresent & bit)
                    writes.append({attribute, value});
            };
            carry(0x00000001u, QStringLiteral("sAMAccountName"), info.userName);
            carry(0x00000002u, QStringLiteral("displayName"), info.fullName);
            carry(0x00000008u, QStringLiteral("primaryGroupID"),
                  QString::number(info.primaryGroupId));
            carry(0x00000010u, QStringLiteral("description"), info.adminComment);
            carry(0x00000020u, QStringLiteral("comment"), info.userComment);
            carry(0x00000040u, QStringLiteral("homeDirectory"), info.homeDirectory);
            carry(0x00000080u, QStringLiteral("homeDrive"), info.homeDrive);
            carry(0x00000100u, QStringLiteral("scriptPath"), info.scriptPath);
            carry(0x00000200u, QStringLiteral("profilePath"), info.profilePath);
            carry(0x00000400u, QStringLiteral("userWorkstations"), info.workstations);
            carry(0x00200000u, QStringLiteral("userParameters"), info.parameters);
            carry(0x00400000u, QStringLiteral("countryCode"), QString::number(info.countryCode));
            carry(0x00800000u, QStringLiteral("codePage"), QString::number(info.codePage));
            carry(0x00100000u, QStringLiteral("userAccountControl"),
                  QString::number(accountControlFromFlags(
                      info.accountControl,
                      target->attributes.value(QStringLiteral("userAccountControl")).toUInt())));
            // 0 and 0x7fffffffffffffff both mean "never" in AD.
            carry(0x00080000u, QStringLiteral("accountExpires"),
                  (info.accountExpires == 0
                   || info.accountExpires == 0x7fffffffffffffffull)
                      ? QStringLiteral("0")
                      : QString::number(info.accountExpires));
            // The week goes into the directory as the 21-byte bitmap AD keeps
            // there; an empty array is the account having no restriction.
            carry(0x00002000u, QStringLiteral("logonHours"),
                  QString::fromLatin1(wire.logonHours.toHex()));

            quint32 status = kStatusSuccess;
            for (const auto &write : writes) {
                QString error;
                if (m_writes.set && m_writes.set(user.dn, write.first, write.second, &error))
                    continue;
                status = m_writes.set ? kStatusAccessDenied : kStatusNotSupported;
                emit requestReceived(QStringLiteral("SetInformationUser(%1) %2=%3: %4")
                                         .arg(user.dn, write.first, write.second,
                                              m_writes.set ? error
                                                           : QStringLiteral("no write backend")));
                break;
            }

            // SAMPR_FIELD_OWF_PWD carries the NT hash DES-enciphered under the
            // session key, the same encoding class 18 uses.
            if (status == kStatusSuccess && (info.fieldsPresent & 0x20000000u)
                && wire.ntOwf.size() == 16) {
                const QByteArray ntHash = Des::decryptOwfHash(wire.ntOwf, sessionKey);
                QString error;
                if (ntHash.size() != 16) {
                    status = kStatusInvalidParameter;
                } else if (!m_writes.setNtHash || !m_writes.setNtHash(user.dn, ntHash, &error)) {
                    status = m_writes.setNtHash ? kStatusPasswordRestriction
                                                : kStatusNotSupported;
                }
                emit requestReceived(QStringLiteral("SetInformationUser(%1) NT hash: %2")
                                         .arg(user.dn,
                                              status == kStatusSuccess
                                                  ? QStringLiteral("ok")
                                                  : error));
            }

            // 23 and 25 close with samr_CryptPassword: the password ciphered
            // under the session key, the same buffer class 24/26 carries alone.
            if (status == kStatusSuccess && carriesPassword && !wire.trailer.isEmpty()) {
                QString password;
                QString error;
                if (!decodeCryptPassword(wire.trailer, sessionKey, infoClass == 25, &password,
                                         &error)) {
                    status = kStatusInvalidParameter;
                } else if (!m_writes.setPassword
                           || !m_writes.setPassword(user.dn, password, &error)) {
                    status = m_writes.setPassword ? kStatusPasswordRestriction
                                                  : kStatusNotSupported;
                }
                emit requestReceived(QStringLiteral("SetPassword(%1): %2")
                                         .arg(user.dn,
                                              status == kStatusSuccess
                                                  ? QStringLiteral("ok")
                                                  : error));
            }

            // A set that has to be changed at next logon stamps pwdLastSet 0,
            // which is what AD does for "user must change password".
            if (status == kStatusSuccess && info.passwordExpired
                && (info.fieldsPresent & 0x08000000u) && m_writes.set) {
                QString error;
                m_writes.set(user.dn, QStringLiteral("pwdLastSet"), QStringLiteral("0"),
                             &error);
            }

            putLe32(fixed, status);
            return fixed;
        }
        case 24: // SamrUserInternal5Information: samr_CryptPassword
        case 26: { // SamrUserInternal5InformationNew: samr_CryptPasswordEx
            const bool salted = infoClass == 26;
            const int size = salted ? 532 : 516;
            // The arm closes with a password_expired byte after the cipher text.
            const bool hasExpiredFlag = reader.remaining() >= size + 1;
            QByteArray payload;
            if (!reader.bytes(hasExpiredFlag ? size + 1 : size, &payload))
                return {};
            const quint8 passwordExpired = hasExpiredFlag ? quint8(payload.at(size)) : 0;
            QString password;
            QString error;
            if (!decodeCryptPassword(payload, sessionKey, salted, &password, &error)) {
                putLe32(fixed, kStatusInvalidParameter);
                emit requestReceived(QStringLiteral("SetPassword(%1) refused: %2")
                                         .arg(user.dn, error));
                return fixed;
            }
            const bool ok = m_writes.setPassword && m_writes.setPassword(user.dn, password, &error);
            if (!ok && !qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
                qWarning("SetPassword(%s) refused: %s", qPrintable(user.dn),
                         qPrintable(error));
            // A reset that has to be changed at next logon stamps pwdLastSet 0,
            // which is what AD does for "user must change password".
            if (ok && passwordExpired != 0)
                m_writes.set(user.dn, QStringLiteral("pwdLastSet"), QStringLiteral("0"), &error);
            // What is left of the failure is the domain policy: too short, too
            // few character classes, or the account is gone.
            putLe32(fixed, ok ? kStatusSuccess
                              : (m_writes.setPassword ? kStatusPasswordRestriction
                                                      : kStatusNotSupported));
            emit requestReceived(QStringLiteral("SetPassword(%1): %2")
                                     .arg(user.dn,
                                          ok ? QStringLiteral("ok") : error));
            return fixed;
        }
        default:
            putLe32(fixed, kStatusInvalidInfoClass);
            emit requestReceived(QStringLiteral("SetInformationUser class %1 unsupported")
                                     .arg(infoClass));
            return fixed;
        }
    }
    default:
        emit requestReceived(QStringLiteral("Unsupported opnum %1").arg(opnum));
        return {};
    }
}
