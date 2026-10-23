// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Lsad.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QRandomGenerator>

#include <algorithm>

#include "Ndr.h"

namespace {

// NTSTATUS values MS-LSAD returns.
constexpr quint32 kStatusSuccess = 0x00000000u;
constexpr quint32 kStatusMoreEntries = 0x00000105u;
constexpr quint32 kStatusNoMoreEntries = 0x8000001au;
constexpr quint32 kStatusInvalidHandle = 0xc0000008u;
constexpr quint32 kStatusInvalidParameter = 0xc000000du;
constexpr quint32 kStatusInvalidInfoClass = 0xc0000003u;
constexpr quint32 kStatusObjectNameNotFound = 0xc0000034u;
constexpr quint32 kStatusNoSuchPrivilege = 0xc0000060u;
constexpr quint32 kStatusNoSuchUser = 0xc0000064u;
constexpr quint32 kStatusInvalidSid = 0xc0000078u;
constexpr quint32 kStatusNotSupported = 0xc00000bbu;

// An LSAPR_HANDLE is 20 bytes, like a SAMR handle.
constexpr int kHandleSize = 20;

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

// Samba's pidl aligns the start of every structure it marshals (ndr_push_align
// at the top of each ndr_push_*), while ndr_push_uint32 aligns itself. The
// trailer alignment MS-RPCE 2.2.5.3.4.1 mentions is a no-op for NDR32, so
// nothing pads after a structure's last field: the next parameter aligns
// instead. Reproducing that here is what makes these replies decode.
void alignFixed(QByteArray &out, int boundary)
{
    while (out.size() % boundary != 0)
        out.append('\0');
}

// UTF-16 characters as NDR writes a counted array: only the `length_is`
// elements travel (the maximum count a StringLarge declares is the capacity,
// which includes the terminator, but the terminator itself is not sent).
// ndr_push_charset pads no further than the character width, so the padding
// before whatever follows is that field's own alignment, not a blanket 4: a
// 2-byte language id follows the display name directly, and rounding the
// characters to 4 there would push it out of place.
void appendChars(QByteArray &out, const QString &text)
{
    out.append(Ndr::utf16le(text));
    while (out.size() % 2 != 0)
        out.append('\0');
}

// The header of an in-line lsa_String / lsa_StringLarge (both are
// Length, MaximumLength, buffer referent; MS-LSAD 2.2.2.2/2.2.2.3). lsa_String
// declares size = 2*strlen_m, so its maximum excludes the terminator and the
// characters travel without one; lsa_StringLarge adds the terminator to both.
void putStringHeader(QByteArray &fixed, const QString &text, quint32 referent, bool large)
{
    alignFixed(fixed, 4);
    const quint16 length = quint16(text.size() * 2);
    putLe16(fixed, length);
    putLe16(fixed, large ? quint16(length + 2) : length);
    putLe32(fixed, text.isEmpty() ? 0u : referent);
}

// The buffer of an lsa_String / lsa_StringLarge is a conformant varying array:
// maximum count, offset, actual count, characters (MS-RPCE 2.2.6; `size_is` is
// the capacity, `length_is` what travels). lsa_StringLarge counts the terminator
// into its maximum, lsa_String does not.
void appendVaryingChars(QByteArray &out, const QString &text, bool large)
{
    // The maximum count is a uint3264, so the array starts 4-aligned whatever
    // the previous buffer ended on.
    alignFixed(out, 4);
    putLe32(out, quint32(text.size() + (large ? 1 : 0))); // MaximumCount
    putLe32(out, 0);                                      // Offset
    putLe32(out, quint32(text.size()));                   // ActualCount
    appendChars(out, text);
}

void appendVaryingString(QByteArray &out, const QString &text)
{
    appendVaryingChars(out, text, true);
}

// Reads such a buffer where the structure's buffer referent already said the
// characters are present.
bool readVaryingChars(Ndr::Reader &reader, QString *text)
{
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
        return false;
    QByteArray chars;
    if (!reader.bytes(int(actual * 2), &chars))
        return false;
    reader.align(4);
    *text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                               qsizetype(chars.size() / 2));
    return true;
}

// dom_sid2 opens with the conformant sub-authority array's maximum count, and
// only then the revision, sub-authority count and identifier authority followed
// by the elements. Samba's ndr_lsa and impacket both push it in that order (see
// ndr_push_lsa_DnsDomainInfo); a client that finds the count after the header
// instead decodes the revision as a count of sub-authorities.
QByteArray sidBytes(const QString &sidText)
{
    const QStringList parts = sidText.split(QLatin1Char('-'));
    QByteArray out;
    if (parts.size() < 3 || parts.at(0) != QLatin1String("S")) {
        putLe32(out, 0); // MaximumCount
        out.append(QByteArray(8, '\0'));
        return out;
    }
    // S-<revision>-<identifier authority>-<sub authority>...
    const QStringList subAuthorities = parts.mid(3);
    putLe32(out, quint32(subAuthorities.size())); // MaximumCount
    out.append(char(parts.at(1).toUInt()));       // revision
    out.append(char(subAuthorities.size()));      // number of sub-authorities
    const quint64 authority = parts.at(2).toULongLong();
    for (int i = 5; i >= 0; --i)
        out.append(char((authority >> (i * 8)) & 0xff));
    for (const QString &sub : subAuthorities)
        putLe32(out, sub.toUInt());
    return out;
}

// dom_sid2 starts with a uint32 (the sub-authority array's maximum count), so
// the field carrying it is 4-aligned: the descriptor's start has to be aligned
// in the buffer it is appended to, not in its own bytes.
void appendSid(QByteArray &out, const QString &sidText)
{
    alignFixed(out, 4);
    out.append(sidBytes(sidText));
}

// Reads the wire form above and gives back the textual SID.
bool readWireSid(Ndr::Reader &reader, QString *sidText)
{
    reader.align(4);
    quint32 maximum = 0;
    if (!reader.u32(&maximum))
        return false;
    QByteArray header;
    if (!reader.bytes(8, &header))
        return false;
    const int count = quint8(header.at(1));
    QByteArray packed = header;
    for (int i = 0; i < count; ++i) {
        QByteArray sub;
        if (!reader.bytes(4, &sub))
            return false;
        packed.append(sub);
    }
    if (sidText)
        *sidText = maximum == 0 ? QString() : Ndr::sidToString(packed);
    return true;
}

// RPC_UNICODE_STRING / lsa_String as a structure field whose characters are
// deferred: Length, MaximumLength and the buffer referent.
bool readStringInline(Ndr::Reader &reader, QString *text)
{
    quint16 length = 0;
    quint16 maximum = 0;
    quint32 buffer = 0;
    if (!reader.u16(&length) || !reader.u16(&maximum) || !reader.u32(&buffer))
        return false;
    if (buffer == 0 || length == 0) {
        text->clear();
        return true;
    }
    return readVaryingChars(reader, text);
}

// A [ref] or [unique] pointer to an lsa_String: the referent, then the
// Length/MaximumLength/buffer header and the characters.
bool readStringPointer(Ndr::Reader &reader, QString *text)
{
    bool present = false;
    if (!reader.referent(&present))
        return false;
    if (!present) {
        text->clear();
        return true;
    }
    return readStringInline(reader, text);
}

const QString kBuiltinDomainSid = QStringLiteral("S-1-5-32");
const QString kNtAuthoritySid = QStringLiteral("S-1-5");

struct WellKnownSid {
    const char *name;
    const char *sid;
    quint32 use; // SID_NAME_USE
};

// The names a DC resolves before it consults the directory. Domain objects shadow
// nothing here: these are the built-in aliases Windows reports for the well-known
// SIDs (MS-DTYP 2.4.2.4 and the BUILTIN domain).
const QList<WellKnownSid> &wellKnownSids()
{
    static const QList<WellKnownSid> table = {
        {"Everyone", "S-1-1-0", 5},
        {"Authenticated Users", "S-1-5-11", 5},
        {"SYSTEM", "S-1-5-18", 5},
        {"LOCAL SYSTEM", "S-1-5-18", 5},
        {"LOCAL SERVICE", "S-1-5-19", 5},
        {"NETWORK SERVICE", "S-1-5-20", 5},
        {"ANONYMOUS LOGON", "S-1-5-7", 5},
        {"INTERACTIVE", "S-1-5-4", 4},
        {"CREATOR OWNER", "S-1-3-0", 5},
        {"Administrators", "S-1-5-32-544", 4},
        {"Users", "S-1-5-32-545", 4},
        {"Guests", "S-1-5-32-546", 4},
        {"Power Users", "S-1-5-32-547", 4},
        {"Account Operators", "S-1-5-32-548", 4},
        {"Server Operators", "S-1-5-32-549", 4},
        {"Print Operators", "S-1-5-32-550", 4},
        {"Backup Operators", "S-1-5-32-551", 4},
        {"Replicator", "S-1-5-32-552", 4},
        {"Remote Desktop Users", "S-1-5-32-555", 4},
        {"Network Configuration Operators", "S-1-5-32-556", 4},
        {"IIS_IUSRS", "S-1-5-32-568", 4},
        {"Performance Monitor Users", "S-1-5-32-558", 4},
        {"Performance Log Users", "S-1-5-32-559", 4},
        {"Event Log Readers", "S-1-5-32-573", 4},
        {"Certificate Service DCOM Access", "S-1-5-32-574", 4},
    };
    return table;
}

struct PrivilegeDef {
    const char *name;
    quint32 luid;
    const char *display;
};

// The privilege table a Windows 2008 R2 DC reports, with the LUIDs
// `lsa_LUID` carries (Samba's `libcli/security/privileges.c` and
// reference/specs/samba-security.idl). The bottom 32 bits are the identifier;
// the high part is zero for every well-known privilege.
const QList<PrivilegeDef> &privilegeCatalog()
{
    static const QList<PrivilegeDef> table = {
        {"SeCreateTokenPrivilege", 0x02, "Create a token object"},
        {"SeAssignPrimaryTokenPrivilege", 0x03, "Replace a process level token"},
        {"SeLockMemoryPrivilege", 0x04, "Lock pages in memory"},
        {"SeIncreaseQuotaPrivilege", 0x05, "Adjust memory quotas for a process"},
        {"SeMachineAccountPrivilege", 0x06, "Add workstations to domain"},
        {"SeTcbPrivilege", 0x07, "Act as part of the operating system"},
        {"SeSecurityPrivilege", 0x08, "Manage auditing and security log"},
        {"SeTakeOwnershipPrivilege", 0x09, "Take ownership of files or other objects"},
        {"SeLoadDriverPrivilege", 0x0a, "Load and unload device drivers"},
        {"SeSystemProfilePrivilege", 0x0b, "Profile system performance"},
        {"SeSystemtimePrivilege", 0x0c, "Change the system time"},
        {"SeProfileSingleProcessPrivilege", 0x0d, "Profile single process"},
        {"SeIncreaseBasePriorityPrivilege", 0x0e, "Increase scheduling priority"},
        {"SeCreatePagefilePrivilege", 0x0f, "Create a pagefile"},
        {"SeCreatePermanentPrivilege", 0x10, "Create permanent shared objects"},
        {"SeBackupPrivilege", 0x11, "Back up files and directories"},
        {"SeRestorePrivilege", 0x12, "Restore files and directories"},
        {"SeShutdownPrivilege", 0x13, "Shut down the system"},
        {"SeDebugPrivilege", 0x14, "Debug programs"},
        {"SeAuditPrivilege", 0x15, "Generate security audits"},
        {"SeSystemEnvironmentPrivilege", 0x16, "Modify firmware environment values"},
        {"SeChangeNotifyPrivilege", 0x17, "Bypass traverse checking"},
        {"SeRemoteShutdownPrivilege", 0x18, "Force shutdown from a remote system"},
        {"SeUndockPrivilege", 0x19, "Remove computer from docking station"},
        {"SeSyncAgentPrivilege", 0x1a, "Synchronize directory service data"},
        {"SeEnableDelegationPrivilege", 0x1b,
         "Enable computer and user accounts to be trusted for delegation"},
        {"SeManageVolumePrivilege", 0x1c, "Perform volume maintenance tasks"},
        {"SeImpersonatePrivilege", 0x1d, "Impersonate a client after authentication"},
        {"SeCreateGlobalPrivilege", 0x1e, "Create global objects"},
        {"SeTrustedCredManAccessPrivilege", 0x1f,
         "Access Credential Manager as a trusted caller"},
        {"SeRelabelPrivilege", 0x20, "Modify an object label"},
        {"SeIncreaseWorkingSetPrivilege", 0x21, "Increase a process working set"},
        {"SeTimeZonePrivilege", 0x22, "Change the time zone"},
        {"SeCreateSymbolicLinkPrivilege", 0x23, "Create symbolic links"},
    };
    return table;
}

const PrivilegeDef *privilegeByName(const QString &name)
{
    for (const PrivilegeDef &def : privilegeCatalog()) {
        if (name.compare(QLatin1String(def.name), Qt::CaseInsensitive) == 0)
            return &def;
    }
    return nullptr;
}

const PrivilegeDef *privilegeByLuid(quint32 luid)
{
    for (const PrivilegeDef &def : privilegeCatalog()) {
        if (def.luid == luid)
            return &def;
    }
    return nullptr;
}

// An account as LSAD translates it: the directory object and its SID usage.
struct AccountEntry {
    QString sid;
    QString name;
    QString dn;
    quint32 use = 1;
};

// The domains a translation refers to: index 0 is this DC's account domain,
// BUILTIN and NT AUTHORITY join it when a translated SID belongs to them.
struct DomainTable {
    QString accountName;
    QString accountSid;
    QList<QPair<QString, QString>> entries;

    DomainTable(const QString &netbios, const QString &sid)
        : accountName(netbios), accountSid(sid)
    {
        entries.append({netbios, sid});
    }

    int add(const QString &name, const QString &sid)
    {
        for (int i = 0; i < entries.size(); ++i) {
            if (entries.at(i).second.compare(sid, Qt::CaseInsensitive) == 0)
                return i;
        }
        entries.append({name, sid});
        return int(entries.size()) - 1;
    }

    int indexForSid(const QString &sid)
    {
        if (sid.compare(accountSid, Qt::CaseInsensitive) == 0
            || sid.startsWith(accountSid + QLatin1Char('-'), Qt::CaseInsensitive))
            return 0;
        if (sid.compare(kBuiltinDomainSid, Qt::CaseInsensitive) == 0
            || sid.startsWith(kBuiltinDomainSid + QLatin1Char('-'), Qt::CaseInsensitive))
            return add(QStringLiteral("BUILTIN"), kBuiltinDomainSid);
        if (sid.startsWith(QStringLiteral("S-1-5-"), Qt::CaseInsensitive))
            return add(QStringLiteral("NT AUTHORITY"), kNtAuthoritySid);
        return 0;
    }
};

struct LookupResult {
    QString sid;
    QString name;
    quint32 use = 8; // SID_NAME_UNKNOWN
    int domain = 0;
};

quint32 ridOfSid(const QString &sid)
{
    const QStringList parts = sid.split(QLatin1Char('-'));
    return parts.isEmpty() ? 0 : parts.last().toUInt();
}

// A SID type for a directory object: SID_NAME_USER, _DOM_GRP or _COMPUTER.
quint32 useForObject(const DirectoryObject &object)
{
    if (object.kind == ObjectKind::Group)
        return 2;
    if (object.kind == ObjectKind::Computer)
        return 9;
    const QString type = object.type;
    if (type.contains(QLatin1String("Group"), Qt::CaseInsensitive))
        return 2;
    if (type.contains(QLatin1String("Computer"), Qt::CaseInsensitive))
        return 9;
    return 1;
}

// The DC's domain GUID, derived from the domain SID so it is stable and unique
// to this domain without a separate registry of allocated GUIDs.
QByteArray domainGuid(const QString &domainSid)
{
    return QCryptographicHash::hash(domainSid.toUtf8(), QCryptographicHash::Md5);
}

quint64 ntTimeNow()
{
    // 100-ns intervals since 1601-01-01, the NTTIME every LSA time uses.
    const qint64 msecs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    return quint64((msecs + Q_INT64_C(11644473600000)) * Q_INT64_C(10000));
}

// A self-relative security descriptor for the LSA policy object: owner and
// group BUILTIN\Administrators, and a DACL granting SYSTEM and Administrators
// POLICY_ALL_ACCESS, Authenticated Users view, audit-view and lookup. A client
// that sets its own descriptor gets exactly those bytes back.
QByteArray defaultPolicySecurityDescriptor()
{
    const QByteArray administrators = Ndr::sidFromString(QStringLiteral("S-1-5-32-544"));
    const QByteArray system = Ndr::sidFromString(QStringLiteral("S-1-5-18"));
    const QByteArray authenticated = Ndr::sidFromString(QStringLiteral("S-1-5-11"));

    auto ace = [](const QByteArray &sid, quint32 mask) {
        QByteArray out;
        out.append(char(0)); // ACCESS_ALLOWED_ACE_TYPE
        out.append(char(0)); // InheritFlags
        putLe16(out, quint16(4 + 4 + sid.size()));
        putLe32(out, mask);
        out.append(sid);
        return out;
    };

    QByteArray aces;
    aces.append(ace(system, 0x000f0fffu));        // POLICY_ALL_ACCESS
    aces.append(ace(administrators, 0x000f0fffu)); // POLICY_ALL_ACCESS
    // POLICY_VIEW_LOCAL_INFORMATION | POLICY_VIEW_AUDIT_INFORMATION |
    // POLICY_LOOKUP_NAMES
    aces.append(ace(authenticated, 0x00000803u));

    QByteArray acl;
    acl.append(char(2)); // ACL_REVISION
    acl.append(char(0));
    putLe16(acl, quint16(8 + aces.size()));
    putLe16(acl, quint16(3)); // AceCount
    putLe16(acl, quint16(0));
    acl.append(aces);

    const int ownerOffset = 20;
    const int groupOffset = ownerOffset + administrators.size();
    const int daclOffset = groupOffset + administrators.size();

    QByteArray sd;
    sd.append(char(1)); // SECURITY_DESCRIPTOR_REVISION
    sd.append(char(0));
    putLe16(sd, quint16(0x8004)); // SE_SELF_RELATIVE | SE_DACL_PRESENT
    putLe32(sd, quint32(ownerOffset));
    putLe32(sd, quint32(groupOffset));
    putLe32(sd, 0); // no SACL
    putLe32(sd, quint32(daclOffset));
    sd.append(administrators); // owner
    sd.append(administrators); // group
    sd.append(acl);
    return sd;
}

} // namespace

namespace Lsad {

Rpc::Interface interface()
{
    Rpc::Interface iface;
    // 12345778-1234-ABCD-EF00-0123456789AB, the LSAD (lsarpc) interface.
    iface.uuid = QByteArray::fromHex("78 57 34 12 34 12 cd ab ef 00 01 23 45 67 89 ab");
    iface.major = 0;
    iface.minor = 0;
    iface.name = QStringLiteral("LSAD");
    return iface;
}

} // namespace Lsad

LsadServer::LsadServer(QObject *parent) : QObject(parent)
{
    m_policySd = defaultPolicySecurityDescriptor();
    m_createdTime = ntTimeNow();
    m_modifiedId = m_createdTime;
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Lsad::interface(), [this](const Rpc::Call &call) {
        return handleCall(call.opnum, call.stub, call.user);
    });
    connect(m_rpc, &RpcServer::requestReceived, this, &LsadServer::requestReceived);
}

void LsadServer::setConfig(const Samr::Config &config)
{
    m_config = config;
    if (m_dnsDomain.isEmpty())
        m_dnsDomain = config.realm.toLower();
}

void LsadServer::setDomainNames(const QString &netbios, const QString &serverName,
                                const QString &dnsDomain, const QString &domainSid)
{
    m_config.netbios = netbios;
    m_dnsDomain = dnsDomain;
    m_config.domainSid = domainSid;
    // The NTLM CHALLENGE publishes the same names the SAMR endpoint does, so a
    // client computing an NTLMv2 response finds the target and DNS host AV pairs
    // it expects.
    m_rpc->setDomainNames(netbios, serverName, dnsDomain);
}

void LsadServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_rpc->setAuthenticator(authenticator);
}

void LsadServer::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = std::move(provider);
}

void LsadServer::setWriteBackend(Lsad::WriteBackend backend)
{
    m_writes = std::move(backend);
}

bool LsadServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void LsadServer::close()
{
    m_rpc->close();
}

bool LsadServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 LsadServer::serverPort() const
{
    return m_rpc->serverPort();
}

QList<DirectoryObject> LsadServer::directory() const
{
    return m_provider ? m_provider() : QList<DirectoryObject>();
}

DirectoryObject LsadServer::findAccount(const QString &sid) const
{
    for (const DirectoryObject &object : directory()) {
        if (object.attributes.value(QStringLiteral("objectSid"))
                .compare(sid, Qt::CaseInsensitive)
            == 0)
            return object;
    }
    return {};
}

QStringList LsadServer::rightsFor(const QString &sid) const
{
    for (const DirectoryObject &object : directory()) {
        if (object.attributes.value(QStringLiteral("objectSid"))
                .compare(sid, Qt::CaseInsensitive)
            != 0)
            continue;
        const QString stored = object.attributes.value(QStringLiteral("userRight"));
        return stored.split(QStringLiteral("; "), Qt::SkipEmptyParts);
    }
    return m_extraRights.value(sid);
}

bool LsadServer::storeRights(const QString &sid, const QStringList &rights, quint32 *status)
{
    QStringList unique;
    for (const QString &right : rights) {
        if (!unique.contains(right, Qt::CaseInsensitive))
            unique.append(right);
    }
    const DirectoryObject account = findAccount(sid);
    if (account.id.isEmpty()) {
        m_extraRights.insert(sid, unique);
        return true;
    }
    if (!m_writes.setRights) {
        m_extraRights.insert(sid, unique);
        return true;
    }
    QString error;
    if (!m_writes.setRights(account.id, unique, &error)) {
        if (status)
            *status = kStatusObjectNameNotFound;
        emit requestReceived(QStringLiteral("Account rights write refused: %1").arg(error));
        return false;
    }
    return true;
}

QStringList LsadServer::accountsWithRights() const
{
    QStringList sids;
    for (const DirectoryObject &object : directory()) {
        const QString sid = object.attributes.value(QStringLiteral("objectSid"));
        if (sid.isEmpty())
            continue;
        if (object.attributes.value(QStringLiteral("userRight")).trimmed().isEmpty())
            continue;
        sids.append(sid);
    }
    for (auto it = m_extraRights.constBegin(); it != m_extraRights.constEnd(); ++it) {
        if (!it.value().isEmpty() && !sids.contains(it.key()))
            sids.append(it.key());
    }
    std::sort(sids.begin(), sids.end());
    return sids;
}

QByteArray LsadServer::newHandle(Handle::Kind kind, const QString &sid, const QString &name,
                                 quint32 access)
{
    QByteArray id(kHandleSize, '\0');
    for (int i = 0; i < kHandleSize - 4; ++i)
        id[i] = char(QRandomGenerator::system()->generate() & 0xff);
    Handle handle;
    handle.kind = kind;
    handle.sid = sid;
    handle.name = name;
    handle.access = access;
    m_handles.insert(id, handle);
    return id;
}

bool LsadServer::lookupHandle(const QByteArray &handle, Handle::Kind kind, Handle *out) const
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

void LsadServer::retireHandle(const QByteArray &handle)
{
    m_handles.remove(handle);
}

// The layout of every response below is the one Samba's pidl generates from
// lsa.idl (reference/specs/samba-lsa.idl): a [ref] parameter travels without a
// referent, a [unique] one starts with one, and a `T **` out parameter starts
// with exactly one because the inner pointer is the [unique] one. Structures
// flush their own buffers before the next parameter begins.
QByteArray LsadServer::handleCall(quint16 opnum, const QByteArray &stub,
                                  const QString &clientUser)
{
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("LSAD opnum %u stub %s", opnum, stub.toHex().constData());
    Ndr::Reader reader(stub);
    QByteArray fixed;
    QByteArray deferred;
    // Referent ids have to be unique within the stub; the generator hands out
    // the next one so the bytes are deterministic for a given response shape.
    quint32 nextReferent = 0x00030000u;
    const auto referent = [&nextReferent]() { return ++nextReferent; };

    // The trailing NTSTATUS is a uint32, so it lands on the next 4-byte
    // boundary whatever the last parameter ended on.
    const auto result = [&fixed](quint32 status) {
        alignFixed(fixed, 4);
        putLe32(fixed, status);
        return fixed;
    };

    // A policy handle the client presented, or INVALID_HANDLE when it is not
    // one this server issued.
    const auto readPolicy = [&](Handle *handle) {
        QByteArray bytes;
        if (!reader.bytes(kHandleSize, &bytes))
            return false;
        return lookupHandle(bytes, Handle::Policy, handle);
    };

    // Builds the directory view the translation calls share.
    const auto accounts = [this]() {
        QList<AccountEntry> list;
        for (const DirectoryObject &object : directory()) {
            const QString sid = object.attributes.value(QStringLiteral("objectSid"));
            if (sid.isEmpty())
                continue;
            AccountEntry entry;
            entry.sid = sid;
            entry.name = object.attributes.value(QStringLiteral("sAMAccountName"));
            if (entry.name.isEmpty())
                entry.name = object.name;
            entry.dn = object.id;
            entry.use = useForObject(object);
            list.append(entry);
        }
        return list;
    };

    // The account-domain list a translation refers to. `dns` is what a
    // domain-qualified name may use instead of the NetBIOS name.
    const auto newDomains = [this]() {
        return DomainTable(m_config.netbios,
                           m_config.domainSid.isEmpty() ? QStringLiteral("S-1-5-21-0-0-0")
                                                        : m_config.domainSid);
    };

    switch (opnum) {
    case Lsad::OpOpenPolicy:
    case Lsad::OpOpenPolicy2: {
        // LsarOpenPolicy prefixes the attribute block with a [unique]
        // server-name string. lsa_ObjectAttribute is six ULONGs (length, root
        // directory, object name, attributes, security descriptor, quality of
        // service), and the desired access mask follows.
        bool hasSystemName = false;
        if (!reader.referent(&hasSystemName))
            return {};
        if (hasSystemName) {
            quint32 maximum = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
                return {};
            if (!reader.skip(int(actual * 2)))
                return {};
            reader.align(4);
        }
        quint32 length = 0;
        quint32 rootDirectory = 0;
        quint32 objectName = 0;
        quint32 attributes = 0;
        quint32 securityDescriptor = 0;
        quint32 qualityOfService = 0;
        quint32 desiredAccess = 0;
        if (!reader.u32(&length) || !reader.u32(&rootDirectory) || !reader.u32(&objectName)
            || !reader.u32(&attributes) || !reader.u32(&securityDescriptor)
            || !reader.u32(&qualityOfService) || !reader.u32(&desiredAccess))
            return {};
        Q_UNUSED(length)
        Q_UNUSED(rootDirectory)
        Q_UNUSED(objectName)
        Q_UNUSED(attributes)
        Q_UNUSED(securityDescriptor)
        Q_UNUSED(qualityOfService)

        fixed.append(newHandle(Handle::Policy, QString(), QString(), desiredAccess));
        emit requestReceived(QStringLiteral("OpenPolicy (access 0x%1)")
                                 .arg(desiredAccess, 8, 16, QLatin1Char('0')));
        return result(kStatusSuccess);
    }
    case Lsad::OpClose:
    case Lsad::OpDeleteObject: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        retireHandle(handle);
        fixed.append(QByteArray(kHandleSize, '\0'));
        emit requestReceived(opnum == Lsad::OpClose ? QStringLiteral("Close")
                                                    : QStringLiteral("DeleteObject"));
        return result(kStatusSuccess);
    }
    case Lsad::OpQueryInformationPolicy:
    case Lsad::OpQueryInformationPolicy2: {
        Handle policy;
        if (!readPolicy(&policy)) {
            putLe32(fixed, 0); // NULL union pointer
            return result(kStatusInvalidHandle);
        }
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        reader.align(4);

        // The union is behind one pointer referent, and its discriminant is a
        // 2-byte enum written where it lands: pidl emits no union padding for
        // NDR32 (ndr_push_union_align is a no-op before NDR64), so each arm is
        // aligned by its own leading ndr_push_align instead.
        auto beginArm = [&fixed](quint16 tag) {
            putLe32(fixed, 0x00030000u + tag);
            putLe16(fixed, tag);
        };
        const QString dns = m_dnsDomain.isEmpty() ? m_config.realm.toLower() : m_dnsDomain;

        switch (infoClass) {
        case Lsad::InfoAuditLog: {
            // lsa_AuditLogInfo: percent full, maximum log size, the retention
            // period, the shutdown flag (padded out to the LARGE_INTEGER that
            // follows) and the next record id. No audit log is kept, so it is
            // reported empty rather than with a plausible-looking file size.
            beginArm(infoClass);
            alignFixed(fixed, 8); // lsa_AuditLogInfo opens with ndr_push_align(8)
            putLe32(fixed, 0); // AuditLogPercentFull
            putLe32(fixed, 0); // MaximumLogSize
            putLe64(fixed, 0); // AuditRetentionPeriod
            fixed.append(char(0)); // AuditLogFullShutdownInProgress
            fixed.append(QByteArray(7, '\0'));
            putLe64(fixed, 0); // TimeToShutdown
            putLe32(fixed, 0); // NextAuditRecordId
            return result(kStatusSuccess);
        }
        case Lsad::InfoAuditEvents: {
            // lsa_AuditEventsInfo: the auditing mode, a pointer to one policy
            // value per category, and the category count.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putLe32(fixed, 0);           // AuditingMode
            putLe32(fixed, 0x00030030u); // settings pointer
            putLe32(fixed, 9);           // count
            putLe32(fixed, 9);           // array maximum count
            for (int i = 0; i < 9; ++i)
                putLe32(fixed, 0); // LSA_AUDIT_POLICY_NONE
            return result(kStatusSuccess);
        }
        case Lsad::InfoPrimaryDomain:
        case Lsad::InfoAccountDomain:
        case Lsad::InfoLocalAccountDomain: {
            // lsa_DomainInfo: the domain's name and its SID.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putStringHeader(fixed, m_config.netbios, 0x00030010u, true);
            putLe32(fixed, 0x00030020u); // SID referent
            appendVaryingString(deferred, m_config.netbios);
            appendSid(deferred, m_config.domainSid);
            fixed.append(deferred);
            emit requestReceived(QStringLiteral("QueryInformationPolicy(class %1) domain %2")
                                     .arg(infoClass)
                                     .arg(m_config.netbios));
            return result(kStatusSuccess);
        }
        case Lsad::InfoPdAccount: {
            // lsa_PDAccountInfo: a native-mode DC has no primary-domain account.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putStringHeader(fixed, QString(), 0, false);
            return result(kStatusSuccess);
        }
        case Lsad::InfoServerRole: {
            // lsa_ServerRole: LSA_ROLE_PRIMARY for this DC.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putLe32(fixed, 3);
            return result(kStatusSuccess);
        }
        case Lsad::InfoReplicaSource: {
            // lsa_ReplicaSourceInfo: a primary DC replicates from nothing.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putStringHeader(fixed, QString(), 0, false);
            putStringHeader(fixed, QString(), 0, false);
            return result(kStatusSuccess);
        }
        case Lsad::InfoQuota: {
            // lsa_DefaultQuotaInfo: five 32-bit limits and a hyper, which
            // ndr_push_hyper aligns to 8. No per-user quota is enforced.
            beginArm(infoClass);
            alignFixed(fixed, 8);
            for (int i = 0; i < 5; ++i)
                putLe32(fixed, 0);
            alignFixed(fixed, 8);
            putLe64(fixed, 0);
            return result(kStatusSuccess);
        }
        case Lsad::InfoModification: {
            beginArm(infoClass);
            alignFixed(fixed, 8);
            putLe64(fixed, m_modifiedId);
            putLe64(fixed, m_createdTime);
            return result(kStatusSuccess);
        }
        case Lsad::InfoAuditFullSet: {
            // lsa_AuditFullSetInfo is a single byte. MS-RPCE 2.2.5.3.4.4 puts a
            // union arm on the arm's own alignment, and the 2-byte discriminant
            // is padded to the 4-byte boundary every NDR32 decoder in the wild
            // reads the arm from (impacket reads the arm there; pidl does not,
            // and then reads the NTSTATUS out of the arm byte, which no other
            // decoder accepts).
            beginArm(infoClass);
            alignFixed(fixed, 4);
            fixed.append(char(m_shutdownOnFull ? 1 : 0));
            return result(kStatusSuccess);
        }
        case Lsad::InfoAuditFullQuery: {
            beginArm(infoClass);
            alignFixed(fixed, 4);
            fixed.append(char(m_shutdownOnFull ? 1 : 0));
            fixed.append(char(0)); // LogIsFull
            return result(kStatusSuccess);
        }
        case Lsad::InfoDnsDomain:
        case Lsad::InfoDnsDomainInt: {
            // lsa_DnsDomainInfo: NetBIOS name, DNS domain, DNS forest, GUID, SID.
            beginArm(infoClass);
            alignFixed(fixed, 4);
            putStringHeader(fixed, m_config.netbios, 0x00030010u, true);
            putStringHeader(fixed, dns, 0x00030011u, true);
            // The forest root is the domain itself in a single-domain forest.
            putStringHeader(fixed, dns, 0x00030012u, true);
            fixed.append(domainGuid(m_config.domainSid));
            putLe32(fixed, 0x00030020u);
            appendVaryingString(deferred, m_config.netbios);
            appendVaryingString(deferred, dns);
            appendVaryingString(deferred, dns);
            appendSid(deferred, m_config.domainSid);
            fixed.append(deferred);
            emit requestReceived(QStringLiteral("QueryInformationPolicy(DNS) %1").arg(dns));
            return result(kStatusSuccess);
        }
        default:
            emit requestReceived(QStringLiteral("QueryInformationPolicy class %1 unsupported")
                                     .arg(infoClass));
            putLe32(fixed, 0);
            return result(kStatusInvalidInfoClass);
        }
    }
    case Lsad::OpSetInformationPolicy:
    case Lsad::OpSetInformationPolicy2: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint16 infoClass = 0;
        if (!reader.u16(&infoClass))
            return {};
        // The information structure is an [in] pointer marshalled in place (no
        // referent): the union's own 2-byte discriminant follows the parameter
        // level directly, and the arm is aligned by its own first field.
        quint16 tag = 0;
        if (!reader.u16(&tag))
            return {};
        if (tag != infoClass)
            return result(kStatusInvalidInfoClass);
        // Only the levels MS-LSAD makes settable are settable (3.1.4.4.4):
        // the modification time and the audit-full flag.
        if (infoClass == Lsad::InfoModification) {
            quint64 modified = 0;
            quint64 created = 0;
            reader.align(8);
            if (!reader.u64(&modified) || !reader.u64(&created))
                return {};
            m_modifiedId = modified;
            Q_UNUSED(created)
            emit requestReceived(QStringLiteral("SetInformationPolicy(modification)"));
            return result(kStatusSuccess);
        }
        if (infoClass == Lsad::InfoAuditFullSet) {
            quint8 value = 0;
            if (!reader.u8(&value))
                return {};
            m_shutdownOnFull = value != 0;
            emit requestReceived(QStringLiteral("SetInformationPolicy(audit full)"));
            return result(kStatusSuccess);
        }
        emit requestReceived(QStringLiteral("SetInformationPolicy class %1 refused")
                                 .arg(infoClass));
        return result(kStatusInvalidInfoClass);
    }
    case Lsad::OpQueryDomainInfoPolicy: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint16 level = 0;
        if (!reader.u16(&level))
            return {};
        reader.align(4);
        if (level == Lsad::DomainQos) {
            putLe32(fixed, ++nextReferent); // union referent
            putLe16(fixed, level);
            alignFixed(fixed, 4);
            putLe32(fixed, 0); // QualityOfService: none requested
            return result(kStatusSuccess);
        }
        if (level == Lsad::DomainKerberos) {
            // POLICY_DOMAIN_KERBEROS_TICKET_INFO: the AD defaults for a domain
            // provisioned without an explicit policy, in 100-ns units.
            // lsa_DomainInfoKerberos aligns to 8 at its start, and every
            // lifetime is a hyper, so each one lands on an 8-byte boundary.
            putLe32(fixed, ++nextReferent);
            putLe16(fixed, level);
            alignFixed(fixed, 8);
            putLe32(fixed, 0); // AuthenticationOptions
            alignFixed(fixed, 8); // every lifetime below is a hyper
            putLe64(fixed, 36000000000ull);  // MaxServiceTicketAge: 10 hours
            putLe64(fixed, 36000000000ull);  // MaxTicketAge
            putLe64(fixed, 604800000000ull); // MaxRenewAge: 7 days
            putLe64(fixed, 300000000ull);    // MaxClockSkew: 5 minutes
            putLe64(fixed, 0);               // Reserved
            return result(kStatusSuccess);
        }
        if (level == Lsad::DomainEfs) {
            putLe32(fixed, ++nextReferent);
            putLe16(fixed, level);
            alignFixed(fixed, 4);
            putLe32(fixed, 0); // EfsBlob length
            putLe32(fixed, 0); // NULL blob
            return result(kStatusSuccess);
        }
        putLe32(fixed, 0);
        return result(kStatusInvalidInfoClass);
    }
    case Lsad::OpSetDomainInfoPolicy: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        // The ticket lifetime policy is part of the directory's Kerberos
        // policy; there is no attribute behind it here, so a write is refused
        // rather than accepted and dropped.
        emit requestReceived(QStringLiteral("SetDomainInformationPolicy refused"));
        return result(kStatusInvalidInfoClass);
    }
    case Lsad::OpQuerySecurityObject: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint32 securityInformation = 0;
        reader.u32(&securityInformation);
        Q_UNUSED(securityInformation)
        // [out,ref] sec_desc_buf *: a NULL-capable referent, the size, the
        // descriptor pointer, then the bytes.
        const QByteArray &sd = m_policySd;
        putLe32(fixed, ++nextReferent);
        putLe32(fixed, quint32(sd.size()));
        putLe32(fixed, ++nextReferent);
        putLe32(fixed, quint32(sd.size())); // array maximum count
        fixed.append(sd);
        while (fixed.size() % 4 != 0)
            fixed.append('\0');
        return result(kStatusSuccess);
    }
    case Lsad::OpSetSecurityObject: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint32 securityInformation = 0;
        quint32 sdSize = 0;
        if (!reader.u32(&securityInformation) || !reader.u32(&sdSize))
            return {};
        bool present = false;
        if (!reader.referent(&present))
            return {};
        QByteArray sd;
        if (present) {
            quint32 maximum = 0;
            if (!reader.u32(&maximum))
                return {};
            if (!reader.bytes(int(qMin(maximum, sdSize)), &sd))
                return {};
            reader.align(4);
        }
        if (!sd.isEmpty()) {
            m_policySd = sd;
            m_modifiedId = ntTimeNow();
        }
        emit requestReceived(QStringLiteral("SetSecurityObject(0x%1)")
                                 .arg(securityInformation, 8, 16, QLatin1Char('0')));
        return result(kStatusSuccess);
    }
    case Lsad::OpCreateAccount:
        // MS-LSAD 3.1.4.5.1: accounts are created through SAMR.
        return result(kStatusNotSupported);
    case Lsad::OpEnumAccounts: {
        Handle policy;
        quint32 context = 0;
        quint32 maximumLength = 0;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        if (!reader.u32(&context) || !reader.u32(&maximumLength))
            return {};
        Q_UNUSED(maximumLength)

        const QStringList sids = accountsWithRights();
        const int start = int(qMin<qsizetype>(context, sids.size()));
        QStringList page;
        for (int i = start; i < sids.size(); ++i)
            page.append(sids.at(i));

        putLe32(fixed, 0); // resume
        putLe32(fixed, quint32(page.size()));
        putLe32(fixed, 0x00030100u); // array pointer
        putLe32(fixed, quint32(page.size())); // array maximum count
        for (int i = 0; i < page.size(); ++i)
            putLe32(fixed, 0x00030110u + quint32(i)); // SID pointers
        for (const QString &sid : page)
            appendSid(fixed, sid);
        emit requestReceived(QStringLiteral("EnumAccounts (%1)").arg(page.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpEnumTrustDom:
    case Lsad::OpEnumTrustedDomainsEx: {
        Handle policy;
        if (!readPolicy(&policy))
            return {};
        quint32 context = 0;
        quint32 maximumLength = 0;
        if (!reader.u32(&context) || !reader.u32(&maximumLength))
            return {};
        Q_UNUSED(context)
        Q_UNUSED(maximumLength)
        // A standalone DC has no trusted domains; an empty enumeration that
        // says so is the answer a Windows DC gives in the same state.
        putLe32(fixed, 0); // resume
        putLe32(fixed, 0); // entries
        putLe32(fixed, 0); // NULL array
        emit requestReceived(QStringLiteral("EnumTrustedDomains (0)"));
        return result(kStatusNoMoreEntries);
    }
    case Lsad::OpOpenTrustedDomain:
    case Lsad::OpOpenTrustedDomainByName: {
        // No trust exists to open.
        fixed.append(QByteArray(kHandleSize, '\0'));
        emit requestReceived(QStringLiteral("OpenTrustedDomain: no such trust"));
        return result(kStatusObjectNameNotFound);
    }
    case Lsad::OpQueryTrustedDomainInfo:
    case Lsad::OpSetInformationTrustedDomain: {
        Handle policy;
        if (!readPolicy(&policy))
            return {};
        putLe32(fixed, 0); // NULL information pointer
        emit requestReceived(QStringLiteral("trust information for an absent trust"));
        return result(kStatusObjectNameNotFound);
    }
    case Lsad::OpQueryForestTrustInfo: {
        Handle policy;
        if (!readPolicy(&policy))
            return {};
        putLe32(fixed, 0);
        return result(kStatusObjectNameNotFound);
    }
    case Lsad::OpCreateTrustedDomain:
    case Lsad::OpCreateTrustedDomainEx:
    case Lsad::OpCreateTrustedDomainEx2:
        // A trust is only real once Netlogon carries its secure channel, which
        // this DC does not serve yet; recording one would make every later
        // authentication through it fail with no explanation.
        emit requestReceived(QStringLiteral("CreateTrustedDomain refused: no Netlogon channel"));
        return result(kStatusNotSupported);
    case Lsad::OpLookupNames:
    case Lsad::OpLookupNames2:
    case Lsad::OpLookupNames3:
    case Lsad::OpLookupNames4: {
        // IN: [handle,] num_names, the conformant array of lsa_String (whose
        // buffers follow the elements), the in/out TransSidArray, the level and
        // the in/out count. LookupNames3/4 drop the policy handle.
        Handle policy;
        const bool withHandle = opnum == Lsad::OpLookupNames || opnum == Lsad::OpLookupNames2;
        if (withHandle && !readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint32 numNames = 0;
        quint32 maximum = 0;
        if (!reader.u32(&numNames) || !reader.u32(&maximum))
            return {};
        if (numNames > 1000)
            return result(kStatusInvalidParameter);
        QList<quint16> lengths;
        QList<quint32> buffers;
        for (quint32 i = 0; i < numNames; ++i) {
            quint16 length = 0;
            quint16 maxLength = 0;
            quint32 buffer = 0;
            if (!reader.u16(&length) || !reader.u16(&maxLength) || !reader.u32(&buffer))
                return {};
            lengths.append(length);
            buffers.append(buffer);
        }
        QStringList names;
        for (int i = 0; i < lengths.size(); ++i) {
            if (buffers.at(i) == 0 || lengths.at(i) == 0) {
                names.append(QString());
                continue;
            }
            QString name;
            if (!readVaryingChars(reader, &name))
                return {};
            names.append(name);
        }
        // The client's TransSidArray input: count and the (usually NULL) array
        // pointer. Its elements hold no data a server needs.
        quint32 sidCount = 0;
        quint32 sidArray = 0;
        if (!reader.u32(&sidCount) || !reader.u32(&sidArray))
            return {};
        if (sidArray != 0) {
            quint32 size = 0;
            if (!reader.u32(&size))
                return {};
            for (quint32 i = 0; i < size; ++i) {
                quint32 unused = 0;
                if (!reader.u32(&unused) || !reader.u32(&unused) || !reader.u32(&unused))
                    return {};
            }
        }
        quint16 level = 0;
        if (!reader.u16(&level))
            return {};
        reader.align(4);
        quint32 inputCount = 0;
        if (!reader.u32(&inputCount))
            return {};

        const QList<AccountEntry> all = accounts();
        DomainTable domains = newDomains();
        const QString dns = m_dnsDomain.isEmpty() ? m_config.realm.toLower() : m_dnsDomain;

        QList<LookupResult> results;
        for (const QString &raw : names) {
            LookupResult found;
            QString name = raw.trimmed();
            bool domainQualified = true;
            const int backslash = name.indexOf(QLatin1Char('\\'));
            if (backslash >= 0) {
                const QString qualifier = name.left(backslash);
                name = name.mid(backslash + 1);
                domainQualified = qualifier.compare(m_config.netbios, Qt::CaseInsensitive) == 0
                                  || qualifier.compare(dns, Qt::CaseInsensitive) == 0;
            } else {
                const int at = name.lastIndexOf(QLatin1Char('@'));
                if (at > 0) {
                    const QString qualifier = name.mid(at + 1);
                    name = name.left(at);
                    domainQualified = qualifier.compare(dns, Qt::CaseInsensitive) == 0
                                      || qualifier.compare(m_config.netbios, Qt::CaseInsensitive)
                                             == 0;
                }
            }
            if (!domainQualified) {
                results.append(found);
                continue;
            }
            if (name.compare(m_config.netbios, Qt::CaseInsensitive) == 0
                || name.compare(dns, Qt::CaseInsensitive) == 0) {
                found.sid = domains.accountSid;
                found.name = m_config.netbios;
                found.use = 3; // SID_NAME_DOMAIN
                found.domain = 0;
                results.append(found);
                continue;
            }
            for (const WellKnownSid &known : wellKnownSids()) {
                if (name.compare(QLatin1String(known.name), Qt::CaseInsensitive) != 0)
                    continue;
                found.sid = QLatin1String(known.sid);
                found.name = QLatin1String(known.name);
                found.use = known.use;
                found.domain = domains.indexForSid(found.sid);
                break;
            }
            if (found.sid.isEmpty()) {
                for (const AccountEntry &account : all) {
                    bool matches = account.name.compare(name, Qt::CaseInsensitive) == 0;
                    if (!matches)
                        matches = account.dn.section(QLatin1Char('='), 1)
                                      .section(QLatin1Char(','), 0, 0)
                                      .compare(name, Qt::CaseInsensitive)
                                  == 0;
                    if (!matches)
                        continue;
                    found.sid = account.sid;
                    found.name = account.name;
                    found.use = account.use;
                    found.domain = domains.indexForSid(account.sid);
                    break;
                }
            }
            results.append(found);
        }

        // LSAPR_REFERENCED_DOMAIN_LIST: count, the domain array pointer and the
        // maximum entry count, then the array and each domain's buffers.
        putLe32(fixed, ++nextReferent);
        putLe32(fixed, quint32(domains.entries.size()));
        putLe32(fixed, ++nextReferent); // domains array
        putLe32(fixed, quint32(domains.entries.size())); // MaxEntries
        putLe32(fixed, quint32(domains.entries.size())); // array maximum count
        for (int i = 0; i < domains.entries.size(); ++i) {
            putStringHeader(fixed, domains.entries.at(i).first, 0x00031000u + quint32(i), true);
            putLe32(fixed, 0x00031100u + quint32(i));
        }
        // Each lsa_DomainInfo defers its own name and SID, in that order.
        for (const auto &entry : domains.entries) {
            appendVaryingString(fixed, entry.first);
            appendSid(fixed, entry.second);
        }

        // The translation array: lsa_TranslatedSid (12 bytes), _2 (16) and _3
        // (a SID pointer per entry) differ only in the extra fields.
        putLe32(fixed, quint32(results.size()));
        putLe32(fixed, ++nextReferent); // sids array
        putLe32(fixed, quint32(results.size())); // array maximum count
        const bool sid3 = opnum == Lsad::OpLookupNames3 || opnum == Lsad::OpLookupNames4;
        for (int i = 0; i < results.size(); ++i) {
            const LookupResult &found = results.at(i);
            putLe32(fixed, found.use);
            if (sid3) {
                putLe32(fixed, found.sid.isEmpty() ? 0u : 0x00031200u + quint32(i));
            } else {
                putLe32(fixed, found.sid.isEmpty() ? 0u : ridOfSid(found.sid));
            }
            putLe32(fixed, quint32(found.domain));
            if (!sid3 && opnum != Lsad::OpLookupNames)
                putLe32(fixed, 0); // Unknown
        }
        if (sid3) {
            for (const LookupResult &found : results) {
                if (!found.sid.isEmpty())
                    appendSid(fixed, found.sid);
            }
        }
        Q_UNUSED(level)
        putLe32(fixed, quint32(results.size())); // the in/out count
        emit requestReceived(QStringLiteral("LookupNames (%1)").arg(names.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpLookupSids:
    case Lsad::OpLookupSids2:
    case Lsad::OpLookupSids3: {
        Handle policy;
        const bool withHandle = opnum != Lsad::OpLookupSids3;
        if (withHandle && !readPolicy(&policy))
            return result(kStatusInvalidHandle);
        // IN: lsa_SidArray in place: num_sids, the array pointer, the size, the
        // per-entry SID pointers and the SIDs themselves.
        quint32 numSids = 0;
        quint32 arrayReferent = 0;
        if (!reader.u32(&numSids) || !reader.u32(&arrayReferent))
            return {};
        if (arrayReferent != 0) {
            quint32 size = 0;
            if (!reader.u32(&size))
                return {};
        }
        QList<QString> inputSids;
        for (quint32 i = 0; i < numSids; ++i) {
            bool sidPresent = false;
            if (!reader.referent(&sidPresent))
                return {};
            inputSids.append(sidPresent ? QStringLiteral("\x01") : QString());
        }
        for (int i = 0; i < inputSids.size(); ++i) {
            if (inputSids.at(i).isEmpty())
                continue;
            QString sid;
            if (!readWireSid(reader, &sid))
                return {};
            inputSids[i] = sid;
        }
        // The client's TransNameArray input, then level and count.
        quint32 nameCount = 0;
        quint32 nameArray = 0;
        if (!reader.u32(&nameCount) || !reader.u32(&nameArray))
            return {};
        QList<quint16> nameLengths;
        QList<quint32> nameBuffers;
        if (nameArray != 0) {
            quint32 size = 0;
            if (!reader.u32(&size))
                return {};
            for (quint32 i = 0; i < size; ++i) {
                quint32 unused = 0;
                quint16 length = 0;
                quint16 maxLength = 0;
                quint32 buffer = 0;
                if (!reader.u32(&unused) || !reader.u16(&length) || !reader.u16(&maxLength)
                    || !reader.u32(&buffer) || !reader.u32(&unused))
                    return {};
                if (opnum == Lsad::OpLookupSids2 && !reader.u32(&unused))
                    return {};
                nameLengths.append(length);
                nameBuffers.append(buffer);
            }
            for (int i = 0; i < nameLengths.size(); ++i) {
                if (nameBuffers.at(i) == 0 || nameLengths.at(i) == 0)
                    continue;
                QString ignored;
                if (!readVaryingChars(reader, &ignored))
                    return {};
            }
        }
        quint16 level = 0;
        if (!reader.u16(&level))
            return {};
        reader.align(4);
        quint32 inputCount = 0;
        if (!reader.u32(&inputCount))
            return {};

        const QList<AccountEntry> all = accounts();
        DomainTable domains = newDomains();
        QList<LookupResult> results;
        for (const QString &sid : inputSids) {
            LookupResult found;
            found.sid = sid;
            if (sid.isEmpty()) {
                results.append(found);
                continue;
            }
            if (sid.compare(domains.accountSid, Qt::CaseInsensitive) == 0) {
                found.name = m_config.netbios;
                found.use = 3;
                results.append(found);
                continue;
            }
            if (sid.startsWith(domains.accountSid + QLatin1Char('-'), Qt::CaseInsensitive)) {
                for (const AccountEntry &account : all) {
                    if (account.sid.compare(sid, Qt::CaseInsensitive) != 0)
                        continue;
                    found.name = account.name;
                    found.use = account.use;
                    break;
                }
                found.domain = 0;
                results.append(found);
                continue;
            }
            for (const WellKnownSid &known : wellKnownSids()) {
                if (sid.compare(QLatin1String(known.sid), Qt::CaseInsensitive) != 0)
                    continue;
                found.name = QLatin1String(known.name);
                found.use = known.use;
                break;
            }
            found.domain = domains.indexForSid(sid);
            results.append(found);
        }

        putLe32(fixed, ++nextReferent); // referenced domain list
        putLe32(fixed, quint32(domains.entries.size()));
        putLe32(fixed, ++nextReferent); // domains array
        putLe32(fixed, quint32(domains.entries.size())); // MaxEntries
        putLe32(fixed, quint32(domains.entries.size())); // array maximum count
        for (int i = 0; i < domains.entries.size(); ++i) {
            putStringHeader(fixed, domains.entries.at(i).first, 0x00032000u + quint32(i), true);
            putLe32(fixed, 0x00032100u + quint32(i));
        }
        for (const auto &entry : domains.entries) {
            appendVaryingString(fixed, entry.first);
            appendSid(fixed, entry.second);
        }

        // lsa_TransNameArray / _2 in place: count, array pointer, size, the
        // elements, then the deferred names.
        putLe32(fixed, quint32(results.size()));
        putLe32(fixed, ++nextReferent); // names array
        putLe32(fixed, quint32(results.size())); // array maximum count
        for (int i = 0; i < results.size(); ++i) {
            const LookupResult &found = results.at(i);
            putLe32(fixed, found.use);
            putStringHeader(fixed, found.name, 0x00032200u + quint32(i), false);
            putLe32(fixed, quint32(found.domain));
            if (opnum == Lsad::OpLookupSids2)
                putLe32(fixed, 0); // Unknown
        }
        for (const LookupResult &found : results) {
            // A NULL name pointer carries no buffer: there is nothing to defer.
            if (!found.name.isEmpty())
                appendVaryingChars(fixed, found.name, false);
        }
        Q_UNUSED(level)
        alignFixed(fixed, 4);                    // the in/out count is a uint32
        putLe32(fixed, quint32(results.size())); // the in/out count
        emit requestReceived(QStringLiteral("LookupSids (%1)").arg(inputSids.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpOpenAccount: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        // [in,ref] dom_sid2 *sid travels in place, without a referent.
        QString sid;
        if (!readWireSid(reader, &sid))
            return {};
        quint32 access = 0;
        reader.u32(&access);
        const bool known =
            !sid.isEmpty()
            && (sid.compare(m_config.domainSid, Qt::CaseInsensitive) == 0
                || !findAccount(sid).id.isEmpty()
                || wellKnownSids().end()
                       != std::find_if(wellKnownSids().begin(), wellKnownSids().end(),
                                       [&sid](const WellKnownSid &knownSid) {
                                           return sid.compare(QLatin1String(knownSid.sid),
                                                              Qt::CaseInsensitive)
                                                  == 0;
                                       }));
        if (!known) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            emit requestReceived(QStringLiteral("OpenAccount for an unknown SID refused"));
            return result(kStatusObjectNameNotFound);
        }
        fixed.append(newHandle(Handle::Account, sid, QString(), access));
        emit requestReceived(QStringLiteral("OpenAccount(%1)").arg(sid));
        return result(kStatusSuccess);
    }
    case Lsad::OpEnumPrivsAccount: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle account;
        if (!lookupHandle(handle, Handle::Account, &account)) {
            putLe32(fixed, 0);
            return result(kStatusInvalidHandle);
        }

        QList<quint32> luids;
        for (const QString &right : rightsFor(account.sid)) {
            if (const PrivilegeDef *def = privilegeByName(right))
                luids.append(def->luid);
        }
        // lsa_PrivilegeSet is an in-place conformant array: the maximum count
        // first, then PrivilegeCount, Control and the elements.
        putLe32(fixed, ++nextReferent); // privilege set pointer
        putLe32(fixed, quint32(luids.size())); // array maximum count
        putLe32(fixed, quint32(luids.size())); // PrivilegeCount
        putLe32(fixed, 0);                     // Control
        for (quint32 luid : luids) {
            putLe32(fixed, luid); // LowPart
            putLe32(fixed, 0);    // HighPart
            putLe32(fixed, 0);    // Attributes: held, not enabled
        }
        emit requestReceived(QStringLiteral("EnumPrivilegesAccount (%1)").arg(luids.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpAddPrivilegesToAccount:
    case Lsad::OpRemovePrivilegesFromAccount: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle account;
        if (!lookupHandle(handle, Handle::Account, &account))
            return result(kStatusInvalidHandle);
        quint8 removeAll = 0;
        bool privPresent = true;
        if (opnum == Lsad::OpRemovePrivilegesFromAccount) {
            if (!reader.u8(&removeAll))
                return {};
            reader.align(4);
            if (!reader.referent(&privPresent))
                return {};
        }
        if (!privPresent)
            return result(kStatusInvalidParameter);
        quint32 arraySize = 0;
        quint32 privilegeCount = 0;
        quint32 control = 0;
        if (!reader.u32(&arraySize) || !reader.u32(&privilegeCount) || !reader.u32(&control))
            return {};
        QList<quint32> requested;
        for (quint32 i = 0; i < privilegeCount; ++i) {
            quint32 low = 0;
            quint32 high = 0;
            quint32 attributes = 0;
            if (!reader.u32(&low) || !reader.u32(&high) || !reader.u32(&attributes))
                return {};
            if (!privilegeByLuid(low)) {
                emit requestReceived(QStringLiteral("account privilege 0x%1 is unknown").arg(low));
                return result(kStatusNoSuchPrivilege);
            }
            requested.append(low);
        }
        QStringList rights = rightsFor(account.sid);
        if (opnum == Lsad::OpAddPrivilegesToAccount) {
            for (quint32 luid : requested) {
                const QString right = QLatin1String(privilegeByLuid(luid)->name);
                if (!rights.contains(right, Qt::CaseInsensitive))
                    rights.append(right);
            }
        } else if (removeAll) {
            rights.clear();
        } else {
            for (quint32 luid : requested)
                rights.removeAll(QLatin1String(privilegeByLuid(luid)->name));
        }
        quint32 status = kStatusSuccess;
        if (!storeRights(account.sid, rights, &status))
            return result(status);
        emit requestReceived(QStringLiteral("Account privileges changed (%1)")
                                 .arg(account.sid));
        return result(kStatusSuccess);
    }
    case Lsad::OpGetSystemAccessAccount: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle account;
        if (!lookupHandle(handle, Handle::Account, &account))
            return result(kStatusInvalidHandle);
        putLe32(fixed, account.access); // the mask travels in place
        return result(kStatusSuccess);
    }
    case Lsad::OpSetSystemAccessAccount: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        quint32 access = 0;
        if (!reader.u32(&access))
            return {};
        const auto it = m_handles.find(handle);
        if (it == m_handles.end() || it->kind != Handle::Account)
            return result(kStatusInvalidHandle);
        it->access = access;
        return result(kStatusSuccess);
    }
    case Lsad::OpEnumAccountRights: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString sid;
        if (!readWireSid(reader, &sid))
            return {};
        const bool known =
            !findAccount(sid).id.isEmpty() || m_extraRights.contains(sid)
            || sid.compare(m_config.domainSid, Qt::CaseInsensitive) == 0
            || wellKnownSids().end()
                   != std::find_if(wellKnownSids().begin(), wellKnownSids().end(),
                                   [&sid](const WellKnownSid &knownSid) {
                                       return sid.compare(QLatin1String(knownSid.sid),
                                                          Qt::CaseInsensitive)
                                              == 0;
                                   });
        const QStringList rights = known ? rightsFor(sid) : QStringList();
        // lsa_RightSet in place: count, the array pointer, the size, the
        // StringLarge elements and their buffers.
        putLe32(fixed, quint32(rights.size()));
        putLe32(fixed, rights.isEmpty() ? 0u : ++nextReferent);
        if (!rights.isEmpty()) {
            putLe32(fixed, quint32(rights.size())); // array maximum count
            for (int i = 0; i < rights.size(); ++i)
                putStringHeader(fixed, rights.at(i), 0x00033000u + quint32(i), true);
            for (const QString &right : rights)
                appendVaryingString(fixed, right);
        }
        emit requestReceived(QStringLiteral("EnumAccountRights (%1)").arg(rights.size()));
        return result(known ? kStatusSuccess : kStatusObjectNameNotFound);
    }
    case Lsad::OpAddAccountRights:
    case Lsad::OpRemoveAccountRights: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString sid;
        if (!readWireSid(reader, &sid))
            return {};
        quint8 removeAll = 0;
        if (opnum == Lsad::OpRemoveAccountRights) {
            if (!reader.u8(&removeAll))
                return {};
            reader.align(4);
        }
        quint32 count = 0;
        quint32 arrayReferent = 0;
        if (!reader.u32(&count) || !reader.u32(&arrayReferent))
            return {};
        QList<quint16> lengths;
        QList<quint32> buffers;
        if (arrayReferent != 0) {
            quint32 size = 0;
            if (!reader.u32(&size))
                return {};
            for (quint32 i = 0; i < size; ++i) {
                quint16 length = 0;
                quint16 maxLength = 0;
                quint32 buffer = 0;
                if (!reader.u16(&length) || !reader.u16(&maxLength) || !reader.u32(&buffer))
                    return {};
                lengths.append(length);
                buffers.append(buffer);
            }
        }
        QStringList requested;
        for (int i = 0; i < lengths.size(); ++i) {
            if (buffers.at(i) == 0 || lengths.at(i) == 0)
                continue;
            QString right;
            if (!readVaryingChars(reader, &right))
                return {};
            requested.append(right);
        }
        for (const QString &right : requested) {
            if (!privilegeByName(right)) {
                emit requestReceived(QStringLiteral("Account right %1 is not a privilege")
                                         .arg(right));
                return result(kStatusNoSuchPrivilege);
            }
        }
        if (opnum == Lsad::OpAddAccountRights && findAccount(sid).id.isEmpty()
            && !m_extraRights.contains(sid)
            && sid.compare(m_config.domainSid, Qt::CaseInsensitive) != 0
            && wellKnownSids().end()
                   == std::find_if(wellKnownSids().begin(), wellKnownSids().end(),
                                   [&sid](const WellKnownSid &knownSid) {
                                       return sid.compare(QLatin1String(knownSid.sid),
                                                          Qt::CaseInsensitive)
                                              == 0;
                                   })) {
            return result(kStatusNoSuchUser);
        }
        QStringList rights = rightsFor(sid);
        if (opnum == Lsad::OpAddAccountRights) {
            for (const QString &right : requested) {
                if (!rights.contains(right, Qt::CaseInsensitive))
                    rights.append(right);
            }
        } else if (removeAll) {
            rights.clear();
        } else {
            for (const QString &right : requested)
                rights.removeAll(right);
        }
        quint32 status = kStatusSuccess;
        if (!storeRights(sid, rights, &status))
            return result(status);
        emit requestReceived(QStringLiteral("Account rights changed for %1 (%2)")
                                 .arg(sid)
                                 .arg(rights.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpEnumAccountsWithUserRight: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString right;
        if (!readStringPointer(reader, &right))
            return {};
        if (!right.isEmpty() && !privilegeByName(right)) {
            return result(kStatusNoSuchPrivilege);
        }
        QStringList sids;
        for (const QString &candidate : accountsWithRights()) {
            const QStringList rights = rightsFor(candidate);
            if (right.isEmpty()) {
                if (!rights.isEmpty())
                    sids.append(candidate);
                continue;
            }
            for (const QString &granted : rights) {
                if (granted.compare(right, Qt::CaseInsensitive) == 0) {
                    sids.append(candidate);
                    break;
                }
            }
        }
        // lsa_SidArray in place.
        putLe32(fixed, quint32(sids.size()));
        putLe32(fixed, ++nextReferent);
        putLe32(fixed, quint32(sids.size()));
        for (int i = 0; i < sids.size(); ++i)
            putLe32(fixed, 0x00034000u + quint32(i));
        for (const QString &sid : sids)
            appendSid(fixed, sid);
        emit requestReceived(QStringLiteral("EnumAccountsWithUserRight %1 (%2)")
                                 .arg(right)
                                 .arg(sids.size()));
        return result(kStatusSuccess);
    }
    case Lsad::OpEnumeratePrivileges: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint32 context = 0;
        quint32 maxCount = 0;
        if (!reader.u32(&context) || !reader.u32(&maxCount))
            return {};
        const QList<PrivilegeDef> &catalog = privilegeCatalog();
        const int start = int(qMin<qsizetype>(context, catalog.size()));
        const int remaining = int(catalog.size()) - start;
        const int page = qMax(0, qMin(remaining, int(qMin<quint32>(maxCount, 0x1000))));
        putLe32(fixed, quint32(start + page)); // resume
        putLe32(fixed, quint32(page));
        putLe32(fixed, page > 0 ? ++nextReferent : 0u);
        if (page > 0) {
            putLe32(fixed, quint32(page)); // array maximum count
            for (int i = 0; i < page; ++i) {
                const PrivilegeDef &def = catalog.at(start + i);
                putStringHeader(fixed, QLatin1String(def.name), 0x00035100u + quint32(i), true);
                putLe32(fixed, def.luid);
                putLe32(fixed, 0);
            }
            for (int i = 0; i < page; ++i)
                appendVaryingString(fixed, QLatin1String(catalog.at(start + i).name));
        }
        emit requestReceived(QStringLiteral("EnumeratePrivileges (%1 of %2)")
                                 .arg(page)
                                 .arg(catalog.size()));
        return result(start + page >= catalog.size() ? kStatusNoMoreEntries : kStatusMoreEntries);
    }
    case Lsad::OpLookupPrivValue: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        const PrivilegeDef *def = privilegeByName(name);
        if (!def)
            return result(kStatusNoSuchPrivilege);
        putLe32(fixed, def->luid); // LUID in place
        putLe32(fixed, 0);
        return result(kStatusSuccess);
    }
    case Lsad::OpLookupPrivName: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        quint32 low = 0;
        quint32 high = 0;
        if (!reader.u32(&low) || !reader.u32(&high))
            return {};
        const PrivilegeDef *def = privilegeByLuid(low);
        if (!def) {
            putLe32(fixed, 0);
            return result(kStatusNoSuchPrivilege);
        }
        putLe32(fixed, ++nextReferent); // lsa_StringLarge pointer
        putStringHeader(fixed, QLatin1String(def->name), ++nextReferent, true);
        appendVaryingString(fixed, QLatin1String(def->name));
        return result(kStatusSuccess);
    }
    case Lsad::OpLookupPrivDisplayName: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        quint16 language = 0;
        quint16 systemLanguage = 0;
        reader.u16(&language);
        reader.u16(&systemLanguage);
        Q_UNUSED(language)
        Q_UNUSED(systemLanguage)
        const PrivilegeDef *def = privilegeByName(name);
        if (!def) {
            putLe32(fixed, 0);
            putLe16(fixed, 0); // returned_language_id
            return result(kStatusNoSuchPrivilege);
        }
        const QString display = QLatin1String(def->display);
        putLe32(fixed, ++nextReferent); // lsa_StringLarge pointer
        putStringHeader(fixed, display, ++nextReferent, true);
        appendVaryingString(fixed, display);
        // [out,ref] uint16 *returned_language_id travels in place, and the
        // NTSTATUS follows it without any padding of its own.
        putLe16(fixed, 0x0409); // en-US
        return result(kStatusSuccess);
    }
    case Lsad::OpCreateSecret: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        quint32 access = 0;
        reader.u32(&access);
        if (!m_secrets.contains(name))
            m_secrets.insert(name, SecretValue());
        fixed.append(newHandle(Handle::Secret, QString(), name, access));
        emit requestReceived(QStringLiteral("CreateSecret(%1)").arg(name));
        return result(kStatusSuccess);
    }
    case Lsad::OpOpenSecret: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        quint32 access = 0;
        reader.u32(&access);
        if (!m_secrets.contains(name)) {
            fixed.append(QByteArray(kHandleSize, '\0'));
            return result(kStatusObjectNameNotFound);
        }
        fixed.append(newHandle(Handle::Secret, QString(), name, access));
        emit requestReceived(QStringLiteral("OpenSecret(%1)").arg(name));
        return result(kStatusSuccess);
    }
    case Lsad::OpSetSecret: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle secret;
        if (!lookupHandle(handle, Handle::Secret, &secret))
            return result(kStatusInvalidHandle);
        // Two [unique] lsa_DATA_BUF pointers: a referent, then Length, Size,
        // the buffer pointer and the bytes.
        const auto readData = [&reader](QByteArray *out) {
            bool present = false;
            if (!reader.referent(&present))
                return false;
            if (!present) {
                out->clear();
                return true;
            }
            quint32 length = 0;
            quint32 size = 0;
            quint32 buffer = 0;
            if (!reader.u32(&length) || !reader.u32(&size) || !reader.u32(&buffer))
                return false;
            quint32 maxCount = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maxCount) || !reader.u32(&offset) || !reader.u32(&actual))
                return false;
            QByteArray bytes;
            if (!reader.bytes(int(actual), &bytes))
                return false;
            reader.align(4);
            *out = bytes;
            return true;
        };
        QByteArray current;
        QByteArray old;
        if (!readData(&current) || !readData(&old))
            return {};
        SecretValue &value = m_secrets[secret.name];
        value.old = value.current;
        value.oldTime = value.currentTime;
        value.current = current;
        value.currentTime = ntTimeNow();
        if (!old.isEmpty()) {
            value.old = old;
            value.oldTime = value.currentTime;
        }
        emit requestReceived(QStringLiteral("SetSecret(%1)").arg(secret.name));
        return result(kStatusSuccess);
    }
    case Lsad::OpQuerySecret: {
        QByteArray handle;
        if (!reader.bytes(kHandleSize, &handle))
            return {};
        Handle secret;
        if (!lookupHandle(handle, Handle::Secret, &secret))
            return result(kStatusInvalidHandle);
        const SecretValue value = m_secrets.value(secret.name);
        // Each value is an [in,out,unique] lsa_DATA_BUF_PTR *: the outer
        // pointer, the lsa_DATA_BUF* it holds, then the buffer itself.
        const auto writeData = [&fixed, &nextReferent](const QByteArray &bytes, quint64 time) {
            putLe32(fixed, ++nextReferent); // lsa_DATA_BUF_PTR pointer
            // lsa_DATA_BUF_PTR holds an lsa_DATA_BUF*, which is always present on
            // the way out: an unset secret is a zero-length buffer, not a NULL
            // structure, so its Length/Size/buffer fields still travel.
            putLe32(fixed, ++nextReferent);        // lsa_DATA_BUF pointer
            putLe32(fixed, quint32(bytes.size())); // length
            putLe32(fixed, quint32(bytes.size())); // size
            if (bytes.isEmpty()) {
                putLe32(fixed, 0); // NULL buffer
            } else {
                putLe32(fixed, ++nextReferent);        // buffer
                putLe32(fixed, quint32(bytes.size())); // array maximum count
                putLe32(fixed, 0);                     // offset
                putLe32(fixed, quint32(bytes.size())); // length_is
                fixed.append(bytes);
                while (fixed.size() % 4 != 0)
                    fixed.append('\0');
            }
            putLe32(fixed, ++nextReferent); // set time pointer
            alignFixed(fixed, 8);           // the set time is an NTTIME_hyper
            putLe64(fixed, time);
        };
        writeData(value.current, value.currentTime);
        writeData(value.old, value.oldTime);
        emit requestReceived(QStringLiteral("QuerySecret(%1)").arg(secret.name));
        return result(kStatusSuccess);
    }
    case Lsad::OpStorePrivateData: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        // lsa_String name in place, then a [unique] lsa_DATA_BUF value.
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        bool valuePresent = false;
        if (!reader.referent(&valuePresent))
            return {};
        QByteArray data;
        if (valuePresent) {
            quint32 length = 0;
            quint32 size = 0;
            quint32 buffer = 0;
            if (!reader.u32(&length) || !reader.u32(&size) || !reader.u32(&buffer))
                return {};
            quint32 maxCount = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maxCount) || !reader.u32(&offset) || !reader.u32(&actual))
                return {};
            if (!reader.bytes(int(actual), &data))
                return {};
            reader.align(4);
        }
        SecretValue &secret = m_secrets[name];
        secret.old = secret.current;
        secret.oldTime = secret.currentTime;
        secret.current = data;
        secret.currentTime = ntTimeNow();
        emit requestReceived(QStringLiteral("StorePrivateData(%1)").arg(name));
        return result(kStatusSuccess);
    }
    case Lsad::OpRetrievePrivateData: {
        Handle policy;
        if (!readPolicy(&policy))
            return result(kStatusInvalidHandle);
        // lsa_String name in place, then the [in,out,ref] value pointer.
        QString name;
        if (!readStringInline(reader, &name))
            return {};
        bool valuePresent = false;
        if (!reader.referent(&valuePresent))
            return {};
        if (!m_secrets.contains(name)) {
            putLe32(fixed, 0);
            return result(kStatusObjectNameNotFound);
        }
        const QByteArray bytes = m_secrets.value(name).current;
        putLe32(fixed, ++nextReferent); // lsa_DATA_BUF pointer
        putLe32(fixed, quint32(bytes.size())); // length
        putLe32(fixed, quint32(bytes.size())); // size
        putLe32(fixed, ++nextReferent);        // buffer
        putLe32(fixed, quint32(bytes.size())); // array maximum count
        putLe32(fixed, 0);                     // offset
        putLe32(fixed, quint32(bytes.size())); // length_is
        fixed.append(bytes);
        while (fixed.size() % 4 != 0)
            fixed.append('\0');
        emit requestReceived(QStringLiteral("RetrievePrivateData(%1)").arg(name));
        return result(kStatusSuccess);
    }
    case Lsad::OpGetUserName: {
        // [unique] server name, then [in,out,ref] account name and the
        // [in,out,unique] authority name.
        bool hasServer = false;
        if (!reader.referent(&hasServer))
            return {};
        if (hasServer) {
            quint32 maximum = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maximum) || !reader.u32(&offset) || !reader.u32(&actual))
                return {};
            if (!reader.skip(int(actual * 2)))
                return {};
            reader.align(4);
        }
        bool hasAccount = false;
        bool hasAuthority = false;
        if (!reader.referent(&hasAccount) || !reader.referent(&hasAuthority))
            return {};
        Q_UNUSED(hasAccount)

        QString account = clientUser;
        const int backslash = account.indexOf(QLatin1Char('\\'));
        if (backslash >= 0)
            account = account.mid(backslash + 1);
        const int at = account.indexOf(QLatin1Char('@'));
        if (at > 0)
            account = account.left(at);
        if (account.isEmpty())
            account = m_config.netbios + QStringLiteral("$");

        // The account name is a [ref] pointer to a [unique] string pointer, so
        // one referent; the characters follow before the next parameter.
        putLe32(fixed, ++nextReferent);
        putStringHeader(fixed, account, ++nextReferent, false);
        appendVaryingChars(fixed, account, false);
        if (hasAuthority) {
            alignFixed(fixed, 4); // the referent that follows is a uint32
            putLe32(fixed, ++nextReferent);
            putLe32(fixed, ++nextReferent);
            putStringHeader(fixed, m_config.netbios, ++nextReferent, false);
            appendVaryingChars(fixed, m_config.netbios, false);
        } else {
            alignFixed(fixed, 4);
            putLe32(fixed, 0);
        }
        emit requestReceived(QStringLiteral("GetUserName(%1)").arg(account));
        return result(kStatusSuccess);
    }
    default:
        emit requestReceived(QStringLiteral("opnum %1 unsupported").arg(opnum));
        return result(kStatusNotSupported);
    }
}
