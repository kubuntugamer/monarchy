// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Samr.h"

#include <QCryptographicHash>
#include <QRandomGenerator>

#include <algorithm>
#include <QStringList>
#include <QDebug>

#include "Des.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ndr.h"

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
// actual_count, then the characters padded to a 4-byte boundary.
void appendVaryingString(QByteArray &out, const QString &text)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    putLe32(out, quint32(text.size() + 1));
    putLe32(out, 0);
    putLe32(out, quint32(text.size()));
    out.append(utf16);
    while (out.size() % 4 != 0)
        out.append('\0');
}

// SID_NAME_USE as MS-SAMR reports it for a relative identifier.
quint32 nameTypeFor(const DirectoryObject &object)
{
    if (object.kind == ObjectKind::Group)
        return 2; // SidTypeGroup
    if (object.kind == ObjectKind::Computer)
        return 8; // SidTypeComputer
    return 1;     // SidTypeUser
}

quint32 ridOf(const DirectoryObject &object)
{
    const QStringList parts =
        object.attributes.value(QStringLiteral("objectSid")).split(QLatin1Char('-'));
    return parts.isEmpty() ? 0 : parts.last().toUInt();
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
    quint32 accountControl = 0;
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
// MaximumLength and a referent, with the characters deferred. An empty string
// is the NULL pointer AD sends for an attribute that is not set.
void appendCountedString(QByteArray &out, QByteArray &deferred, const QString &text,
                         quint32 referent)
{
    const bool present = !text.isEmpty();
    const QByteArray utf16 = Ndr::utf16le(text);
    putLe16(out, quint16(utf16.size()));
    putLe16(out, quint16(utf16.size() + (present ? 2 : 0)));
    putLe32(out, present ? referent : 0u);
    if (present)
        appendVaryingString(deferred, text);
}

void appendAllUserInfo(const AllUserInfo &info, QByteArray &out, QByteArray &deferred)
{
    putLe64(out, info.lastLogon);
    putLe64(out, info.lastLogoff);
    putLe64(out, info.passwordLastSet);
    putLe64(out, info.accountExpires);
    putLe64(out, info.passwordCanChange);
    putLe64(out, info.passwordMustChange);

    quint32 referent = 0x0002e200u;
    for (const QString &text : {info.userName, info.fullName, info.homeDirectory,
                                info.homeDrive, info.scriptPath, info.profilePath,
                                info.adminComment, info.workstations, info.userComment,
                                info.parameters}) {
        appendCountedString(out, deferred, text, referent++);
    }
    // The two OWF hashes and private_data are never served: AD returns them
    // only under an access right this endpoint does not model.
    const QString empty;
    for (int i = 0; i < 3; ++i)
        appendCountedString(out, deferred, empty, 0);

    // SAMPR_SR_SECURITY_DESCRIPTOR: a self-relative descriptor the caller has
    // to read separately, so a NULL here says "not carried in this answer".
    putLe32(out, 0); // cb
    putLe32(out, 0); // buffer

    putLe32(out, info.userId);
    putLe32(out, info.primaryGroupId);
    putLe32(out, info.accountControl);
    putLe32(out, info.fieldsPresent);

    // SAMPR_LOGON_HOURS: the length is in bits, the units are one byte per
    // hour for a week. All bits set is "any hour", which is what an account
    // with no logonHours attribute allows.
    const QByteArray hours = logonHoursForWire(info.logonHours);
    putLe16(out, quint16(hours.size() * 8));
    out.append(QByteArray(2, '\0'));
    putLe32(out, referent++);
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

// The bits of samr_FieldsPresent that an answer actually fills in.
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
    | 0x800000u // CODE_PAGE
    | 0x1000000u // NT_PASSWORD_PRESENT
    | 0x8000000u; // EXPIRED_FLAG

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

QList<DirectoryObject> SamrServer::groups() const
{
    QList<DirectoryObject> result;
    for (const DirectoryObject &object : directory()) {
        if (object.id.isEmpty() || object.kind != ObjectKind::Group)
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
            // OutVersion, then revision info (revision 1: one ULONG), then the
            // handle, then the status.
            fixed.clear();
            putLe32(fixed, 1u);
            putLe32(fixed, 1u);
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

        if (!m_config.netbios.isEmpty()
            && name.compare(m_config.netbios, Qt::CaseInsensitive) != 0
            && name.compare(m_config.realm, Qt::CaseInsensitive) != 0) {
            fixed.append(char(0));
            putLe32(fixed, kStatusNoSuchDomain);
            return fixed;
        }

        const QByteArray sid = Ndr::sidFromString(m_config.domainSid);
        if (sid.isEmpty()) {
            // Without a domain SID there is nothing to hand out: answer with a
            // NULL SID rather than a malformed one.
            fixed.append(char(0));
            putLe32(fixed, kStatusInvalidParameter);
            return fixed;
        }
        putLe32(fixed, 0x0002d4c5u); // referent for the SID
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

        const bool more = context == 0;
        const int entries = more ? 1 : 0;
        putLe32(fixed, 0);            // EnumerationContext: nothing follows
        putLe32(fixed, 0x0002d4c6u);  // Buffer referent
        putLe32(fixed, quint32(entries));
        putLe32(fixed, 0x0002d4c7u);  // entry array referent
        putLe32(fixed, quint32(entries));
        QList<QByteArray> strings;
        if (more) {
            putLe32(fixed, 0); // RelativeId: the domain entry has none
            const QString name = m_config.netbios;
            const QByteArray utf16 = Ndr::utf16le(name);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, 0x0002d4c8u); // name buffer referent
            QByteArray deferredString;
            appendVaryingString(deferredString, name);
            strings.append(deferredString);
        }
        for (const QByteArray &bytes : strings)
            fixed.append(bytes);
        putLe32(fixed, quint32(entries)); // CountReturned
        putLe32(fixed, more ? kStatusSuccess : kStatusSuccess);
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
        if (!sid.isEmpty() && Ndr::sidToString(sid) != m_config.domainSid) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusNoSuchDomain);
            return fixed;
        }
        fixed.append(newHandle(Handle::Domain, m_config.domainSid, 0));
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("OpenDomain"));
        return fixed;
    }
    // SamrQueryInformationDomain (opnum 8). The out parameter is a pointer to
    // the union: a referent, the class as a USHORT, two alignment bytes, then
    // the arm. Only the classes this directory can answer truthfully are served.
    case Samr::OpQueryInformationDomain: {
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
        auto beginArm = [&fixed](quint16 tag) {
            putLe32(fixed, 0x0002e400u + tag); // union referent
            fixed.append(char(tag & 0xff));
            fixed.append(char((tag >> 8) & 0xff));
            fixed.append(char(0));
            fixed.append(char(0));
        };
        switch (infoClass) {
        case 1: { // DomainPasswordInformation: the policy this server enforces
            beginArm(1);
            fixed.append(char(LdapServer::kPasswordMinLength & 0xff));
            fixed.append(char((LdapServer::kPasswordMinLength >> 8) & 0xff));
            // No password history and no maximum age are enforced, so reporting
            // zero is the truth rather than a policy nobody applies.
            fixed.append(char(0));
            fixed.append(char(0));
            putLe32(fixed, 1u);                 // DOMAIN_PASSWORD_COMPLEX
            fixed.append(QByteArray(8, '\0'));  // MaxPasswordAge
            fixed.append(QByteArray(8, '\0'));  // MinPasswordAge
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(password)"));
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
            fixed.append(deferred);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationDomain(name)"));
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
        case 12: { // DomainLockoutInformation: no lockout is enforced
            beginArm(12);
            fixed.append(QByteArray(8, '\0')); // LockoutDuration
            fixed.append(QByteArray(8, '\0')); // LockoutObservationWindow
            fixed.append(char(0));             // LockoutThreshold
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
        putLe32(fixed, 0x0002e470u);
        putLe32(fixed, quint32(rids.size()));
        putLe32(fixed, rids.isEmpty() ? 0u : 0x0002e480u);
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

        const QList<DirectoryObject> all = users();
        const int start = int(context);
        QList<DirectoryObject> page;
        for (int i = start; i < all.size(); ++i)
            page.append(all.at(i));

        putLe32(fixed, 0);           // EnumerationContext: one page, nothing follows
        putLe32(fixed, 0x0002d4d0u); // Buffer referent
        putLe32(fixed, quint32(page.size()));
        putLe32(fixed, 0x0002d4d1u); // entry array referent
        putLe32(fixed, quint32(page.size()));
        QList<QByteArray> strings;
        for (const DirectoryObject &user : page) {
            const QString sidText = user.attributes.value(QStringLiteral("objectSid"));
            const QStringList parts = sidText.split(QLatin1Char('-'));
            const quint32 rid = parts.isEmpty() ? 0 : parts.last().toUInt();
            putLe32(fixed, rid);
            QString name = user.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = user.name;
            const QByteArray utf16 = Ndr::utf16le(name);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, 0x0002d500u + quint32(strings.size()));
            QByteArray deferredString;
            appendVaryingString(deferredString, name);
            strings.append(deferredString);
        }
        for (const QByteArray &bytes : strings)
            fixed.append(bytes);
        putLe32(fixed, quint32(page.size())); // CountReturned
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateUsers (%1)").arg(page.size()));
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

        const QList<DirectoryObject> all = groups();
        const int start = int(context);
        QList<DirectoryObject> page;
        for (int i = start; i < all.size(); ++i)
            page.append(all.at(i));

        putLe32(fixed, 0);           // EnumerationContext
        putLe32(fixed, 0x0002d4e0u); // Buffer referent
        putLe32(fixed, quint32(page.size()));
        putLe32(fixed, 0x0002d4e1u); // entry array referent
        putLe32(fixed, quint32(page.size()));
        QList<QByteArray> strings;
        for (const DirectoryObject &group : page) {
            putLe32(fixed, ridOf(group));
            QString name = group.attributes.value(QStringLiteral("sAMAccountName"));
            if (name.isEmpty())
                name = group.name;
            const QByteArray utf16 = Ndr::utf16le(name);
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            fixed.append(char(utf16.size() & 0xff));
            fixed.append(char((utf16.size() >> 8) & 0xff));
            putLe32(fixed, 0x0002d4f0u + quint32(strings.size()));
            QByteArray deferredString;
            appendVaryingString(deferredString, name);
            strings.append(deferredString);
        }
        for (const QByteArray &bytes : strings)
            fixed.append(bytes);
        putLe32(fixed, quint32(page.size())); // CountReturned
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("EnumerateGroups (%1)").arg(page.size()));
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
    case Samr::OpQueryInformationUser2: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint16 infoClass = 0;
        reader.u16(&infoClass);
        Handle user;
        if (!lookupHandle(handle, Handle::User, &user)) {
            fixed.append(char(0));
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

                putLe32(fixed, 0x0002d520u); // union referent
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
                fixed.append(deferred);
                putLe32(fixed, kStatusSuccess);
                return fixed;
            }
            // SamrQueryInformationUser2, class 16 = SamrUserControlInformation:
            // the arm is one ULONG. The tag is a USHORT padded back out to four
            // bytes, as impacket's reader expects it.
            if (infoClass == 16) {
                putLe32(fixed, 0x0002d530u); // union referent
                fixed.append(char(16));      // tag: SamrUserControlInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                putLe32(fixed,
                        object.attributes.value(QStringLiteral("userAccountControl")).toUInt());
                putLe32(fixed, kStatusSuccess);
                return fixed;
            }
            // Class 8 = SamrUserFullNameInformation: one inline
            // RPC_UNICODE_STRING whose characters are deferred behind the arm.
            if (infoClass == 8) {
                QString fullName = object.attributes.value(QStringLiteral("displayName"));
                if (fullName.isEmpty())
                    fullName = object.name;
                const QByteArray utf16 = Ndr::utf16le(fullName);
                putLe32(fixed, 0x0002d540u); // union referent
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
                fixed.append(deferred);
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
                putLe32(fixed, 0x0002e1e8u); // union referent
                fixed.append(char(4));       // tag: SamrUserLogonHoursInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                putLe16(fixed, quint16(hours.size() * 8));
                fixed.append(QByteArray(2, '\0'));
                putLe32(fixed, 0x0002e1e9u); // array referent
                putLe32(deferred, 1260);
                putLe32(deferred, 0);
                putLe32(deferred, quint32(hours.size()));
                deferred.append(hours);
                while (deferred.size() % 4 != 0)
                    deferred.append('\0');
                fixed.append(deferred);
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
                info.accountExpires =
                    object.attributes.value(QStringLiteral("accountExpires")).toULongLong();
                const quint64 pwdLastSet =
                    object.attributes.value(QStringLiteral("pwdLastSet")).toULongLong();
                info.passwordLastSet = pwdLastSet == 0 ? 0 : ntTimeFromUnix(pwdLastSet);
                info.passwordExpired = pwdLastSet == 0;
                // No age limits are enforced, so a password never expires and
                // may be changed at any time; that is what these two report.
                info.passwordCanChange = 0;
                info.passwordMustChange = 0x7fffffffffffffffull;
                info.ntPasswordPresent = QByteArray::fromHex(
                                             object.attributes.value(QStringLiteral("ntHash"))
                                                 .toLatin1())
                                             .size()
                                         == 16;
                info.fieldsPresent = kFieldsPresentStandard;

                putLe32(fixed, 0x0002e1f0u); // union referent
                fixed.append(char(21));      // tag: SamrUserAllInformation
                fixed.append(char(0));
                fixed.append(char(0));
                fixed.append(char(0));
                QByteArray arm;
                QByteArray armDeferred;
                appendAllUserInfo(info, arm, armDeferred);
                fixed.append(arm);
                fixed.append(armDeferred);
                putLe32(fixed, kStatusSuccess);
                emit requestReceived(QStringLiteral("QueryInformationUser2(%1, all)")
                                         .arg(user.dn));
                return fixed;
            }
            fixed.append(char(0));
            putLe32(fixed, 0xc0000003u); // STATUS_INVALID_INFO_CLASS
            return fixed;
        }
        fixed.append(char(0));
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

        const QList<DirectoryObject> all = directory();
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
        // referent follows its pointer: count, pointer, maximum count, elements.
        // Probed against impacket's reader, which consumes the array in place.
        putLe32(fixed, quint32(names.size()));
        if (names.isEmpty()) {
            putLe32(fixed, 0);
        } else {
            putLe32(fixed, 0x0002e100u);
            putLe32(fixed, quint32(rids.size())); // MaximumCount
            for (quint32 rid : rids)
                putLe32(fixed, rid);
        }
        putLe32(fixed, quint32(types.size()));
        if (types.isEmpty()) {
            putLe32(fixed, 0);
        } else {
            putLe32(fixed, 0x0002e110u);
            putLe32(fixed, quint32(types.size())); // MaximumCount
            for (quint32 type : types)
                putLe32(fixed, type);
        }
        const quint32 status = mapped == 0 ? kStatusNoneMapped
                              : (mapped < int(names.size()) ? kStatusSomeNotMapped
                                                            : kStatusSuccess);
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

        const QList<DirectoryObject> all = directory();
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
        // character buffers, and the type array follows in the same shape.
        putLe32(fixed, quint32(rids.size()));
        putLe32(fixed, rids.isEmpty() ? 0u : 0x0002e120u);
        putLe32(fixed, quint32(rids.size())); // MaximumCount
        QByteArray stringBuffers;
        for (int i = 0; i < names.size(); ++i) {
            const QByteArray utf16 = Ndr::utf16le(names.at(i));
            const quint16 length = quint16(utf16.size());
            fixed.append(char(length & 0xff));
            fixed.append(char((length >> 8) & 0xff));
            fixed.append(char(length & 0xff));
            fixed.append(char((length >> 8) & 0xff));
            if (resolved.value(i)) {
                putLe32(fixed, 0x0002e140u + quint32(i));
                appendVaryingString(stringBuffers, names.at(i));
            } else {
                putLe32(fixed, 0);
            }
        }
        fixed.append(stringBuffers);
        putLe32(fixed, quint32(types.size()));
        if (types.isEmpty()) {
            putLe32(fixed, 0);
        } else {
            putLe32(fixed, 0x0002e130u);
            putLe32(fixed, quint32(types.size())); // MaximumCount
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
    case Samr::OpCreateGroupInDomain: {
        const bool creatingGroup = opnum == Samr::OpCreateGroupInDomain;
        const quint32 existsStatus = creatingGroup ? kStatusGroupExists : kStatusUserExists;
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
        // call has only the mask.
        quint32 accountFlags = 0;
        quint32 accessMask = 0;
        if (creatingGroup) {
            if (!reader.u32(&accessMask))
                return {};
        } else if (!reader.u32(&accountFlags) || !reader.u32(&accessMask)) {
            return {};
        }
        account = account.trimmed();

        Handle domain;
        const bool handleOk = lookupHandle(handle, Handle::Domain, &domain);
        if (!handleOk || account.isEmpty() || !m_writes.create) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            if (!creatingGroup)
                putLe32(fixed, 0); // GrantedAccess
            putLe32(fixed, 0); // RelativeId
            putLe32(fixed, handleOk ? kStatusAccessDenied : kStatusInvalidHandle);
            return fixed;
        }

        DirectoryObject object;
        object.name = account;
        object.kind = creatingGroup ? ObjectKind::Group : ObjectKind::User;
        object.type = creatingGroup ? QStringLiteral("Security Group") : QStringLiteral("User");
        object.container = QStringLiteral("CN=Users,%1").arg(m_config.baseDn);
        object.id = QStringLiteral("CN=%1,%2").arg(account, object.container);
        object.attributes.insert(QStringLiteral("cn"), account);
        object.attributes.insert(QStringLiteral("sAMAccountName"), account);
        object.attributes.insert(QStringLiteral("objectClass"),
                                 creatingGroup ? QStringLiteral("group") : QStringLiteral("user"));
        if (creatingGroup) {
            object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("Security"));
        } else {
            // SamrCreateUser2's AccountType is a SAMR_ACCT_FLAGS set, which is
            // the low half of userAccountControl; a plain user is 512.
            object.attributes.insert(QStringLiteral("userAccountControl"),
                                     QString::number(accountFlags != 0 ? accountFlags : 512u));
            object.attributes.insert(QStringLiteral("displayName"), account);
            object.attributes.insert(QStringLiteral("pwdLastSet"), QStringLiteral("0"));
        }

        QString error;
        if (!m_writes.create(&object, &error)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            if (!creatingGroup)
                putLe32(fixed, 0);
            putLe32(fixed, 0);
            putLe32(fixed, existsStatus);
            emit requestReceived(QStringLiteral("Create%1(%2) refused: %3")
                                     .arg(creatingGroup ? QStringLiteral("Group")
                                                        : QStringLiteral("User"),
                                          account, error));
            return fixed;
        }

        const quint32 rid = ridOf(object);
        fixed.append(newHandle(creatingGroup ? Handle::Group : Handle::User, object.id, rid));
        if (!creatingGroup)
            putLe32(fixed, accessMask);
        putLe32(fixed, rid);
        putLe32(fixed, kStatusSuccess);
        emit requestReceived(QStringLiteral("Create%1(%2) rid %3")
                                 .arg(creatingGroup ? QStringLiteral("Group")
                                                    : QStringLiteral("User"))
                                 .arg(account)
                                 .arg(rid));
        return fixed;
    }
    case Samr::OpDeleteUser:
    case Samr::OpDeleteGroup: {
        const bool deletingGroup = opnum == Samr::OpDeleteGroup;
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle object;
        if (!lookupHandle(handle, deletingGroup ? Handle::Group : Handle::User, &object)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            putLe32(fixed, kStatusInvalidHandle);
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
                                 .arg(deletingGroup ? QStringLiteral("Group")
                                                    : QStringLiteral("User"),
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
            fixed.append(deferred);
            putLe32(fixed, kStatusSuccess);
            emit requestReceived(QStringLiteral("QueryInformationGroup(%1, all)").arg(name));
            return fixed;
        }
        case 2: { // GroupNameInformation
            beginArm(2);
            putUnicode(name, 0x0002e630u);
            fixed.append(deferred);
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
            fixed.append(deferred);
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
        const QList<DirectoryObject> all = directory();
        const bool found = std::any_of(all.begin(), all.end(), [&user](const DirectoryObject &o) {
            return o.id.compare(user.dn, Qt::CaseInsensitive) == 0;
        });
        if (!found) {
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

        switch (infoClass) {
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
        case 16: { // SamrUserControlInformation: USER_ACCOUNT_* flags
            quint32 control = 0;
            if (!reader.u32(&control))
                return {};
            return writeAttribute(QStringLiteral("userAccountControl"),
                                  QString::number(control));
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
            putLe32(fixed, ok ? kStatusSuccess
                              : (m_writes.setNtHash ? kStatusAccessDenied : kStatusNotSupported));
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
                  QString::number(info.accountControl));
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
                    status = m_writes.setNtHash ? kStatusAccessDenied : kStatusNotSupported;
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
