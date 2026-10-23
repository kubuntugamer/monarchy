// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Pac.h"

#include <QDateTime>
#include <QStringList>

#include "Asn1.h"
#include "Krb5.h"

namespace {

constexpr quint32 kLogonInfoType = 1;
constexpr quint32 kClientInfoType = 10;
constexpr quint32 kUpnDnsInfoType = 12;
constexpr quint32 kServerChecksumType = 6;
constexpr quint32 kKdcChecksumType = 7;
constexpr quint32 kLogonInfoSize = 216;
// MS-PAC 2.8: both signatures are made with key usage 17.
constexpr int kSignatureUsage = 17;

// AD-IF-RELEVANT and AD-WIN2K-PAC (MS-PAC 2.6).
constexpr int kIfRelevant = 1;
constexpr int kWin2kPac = 128;

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
    for (int i = 0; i < 8; ++i)
        out.append(char((value >> (8 * i)) & 0xff));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos)))
           | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16)
           | (quint32(quint8(data.at(pos + 3))) << 24);
}

void setLe32(QByteArray &data, int pos, quint32 value)
{
    if (pos < 0 || pos + 4 > data.size())
        return;
    for (int i = 0; i < 4; ++i)
        data[pos + i] = char((value >> (8 * i)) & 0xff);
}

QByteArray utf16le(const QString &text)
{
    QByteArray out;
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
    return out;
}

// 100 ns intervals since 1601-01-01, the FILETIME the PAC carries.
quint64 fileTime(qint64 unixSeconds)
{
    if (unixSeconds <= 0)
        return 0;
    return quint64(unixSeconds + 11644473600LL) * 10000000ULL;
}

void align(QByteArray &data, int alignment)
{
    while (data.size() % alignment != 0)
        data.append('\0');
}

QList<quint32> sidParts(const QString &sid)
{
    QList<quint32> parts;
    const QStringList fields = sid.split(QLatin1Char('-'));
    if (fields.size() < 4 || fields.value(0) != QLatin1String("S"))
        return parts;
    for (int i = 3; i < fields.size(); ++i)
        parts.append(fields.at(i).toUInt());
    return parts;
}

// SID: revision, sub-authority count, a 6-byte big-endian authority, then the
// sub-authorities as little-endian 32-bit values.
QByteArray sidBytes(const QString &sid)
{
    const QList<quint32> parts = sidParts(sid);
    if (parts.isEmpty())
        return {};
    QByteArray out;
    out.append(char(1));
    out.append(char(parts.size()));
    // Authority 5 (NT), the only one AD uses for directory SIDs.
    out.append(QByteArray(5, '\0'));
    out.append(char(5));
    for (const quint32 part : parts)
        putLe32(out, part);
    return out;
}

quint32 checksumTypeFor(int etype)
{
    switch (etype) {
    case Krb5::kAes256:
        return 16; // hmac-sha1-96-aes256
    case Krb5::kAes128:
        return 15; // hmac-sha1-96-aes128
    default:
        return 0xFFFFFF76u; // hmac-md5 (RC4-HMAC)
    }
}

int signatureLength(int etype)
{
    return (etype == Krb5::kAes256 || etype == Krb5::kAes128) ? 12 : 16;
}

QByteArray signatureFor(const QByteArray &pac, const Pac::Keys &keys, bool kdc)
{
    const QByteArray &key = kdc ? keys.kdcKey : keys.serviceKey;
    const int etype = kdc ? keys.kdcEtype : keys.serviceEtype;
    if (key.isEmpty() || etype == 0)
        return {};
    return Krb5::checksum(etype, kSignatureUsage, key, pac);
}

// Walks the PAC_INFO_BUFFER array and returns the offset of a buffer of a
// given type, or -1.
int bufferOffset(const QByteArray &pac, quint32 type)
{
    const quint32 count = readLe32(pac, 0);
    for (quint32 i = 0; i < count; ++i) {
        const int entry = 8 + int(i) * 16;
        if (int(readLe32(pac, entry)) == int(type))
            return int(readLe32(pac, entry + 8));
    }
    return -1;
}

// Zeroes the signature bytes of a checksum buffer (leaving the checksum type
// in place) so the checksum can be computed over the PAC, as MS-PAC 2.8.1 and
// MIT's zero_signature() require.
void clearSignature(QByteArray &pac, quint32 type)
{
    const quint32 count = readLe32(pac, 0);
    for (quint32 i = 0; i < count; ++i) {
        const int entry = 8 + int(i) * 16;
        if (int(readLe32(pac, entry)) != int(type))
            continue;
        const int size = int(readLe32(pac, entry + 4));
        const int offset = int(readLe32(pac, entry + 8));
        if (size < 4 || offset < 0 || offset + size > pac.size())
            return;
        for (int b = 4; b < size; ++b)
            pac[offset + b] = '\0';
        return;
    }
}

} // namespace

namespace Pac {

quint32 ridOf(const DirectoryObject &object)
{
    const QList<quint32> parts =
        sidParts(object.attributes.value(QStringLiteral("objectSid")));
    return parts.isEmpty() ? 0 : parts.last();
}

QByteArray build(const DirectoryObject &client, const QString &realm, const QString &netbios,
                 const QString &domainSid, const QList<DirectoryObject> &directory,
                 const Keys &keys, qint64 authtime)
{
    Q_UNUSED(realm)
    const QString account = client.attributes.value(QStringLiteral("sAMAccountName"));
    const quint32 userId = ridOf(client);
    if (account.isEmpty() || userId == 0)
        return {};

    const QByteArray domainSidBytes = sidBytes(domainSid);
    if (domainSidBytes.isEmpty())
        return {};

    // Groups the client belongs to, by RID, plus Domain Users as primary.
    QList<quint32> groupRids;
    groupRids.append(513);
    for (const DirectoryObject &object : directory) {
        // Provisioned groups carry the AD object class name ("Security Group")
        // while sample data uses "Group", so accept both.
        const bool isGroup =
            object.kind == ObjectKind::Group
            || object.type.compare(QStringLiteral("Group"), Qt::CaseInsensitive) == 0
            || object.type.compare(QStringLiteral("Security Group"), Qt::CaseInsensitive) == 0;
        if (!isGroup)
            continue;
        bool member = false;
        for (const QString &entry : object.members) {
            if (entry.compare(client.id, Qt::CaseInsensitive) == 0) {
                member = true;
                break;
            }
        }
        if (!member)
            continue;
        const quint32 rid = ridOf(object);
        if (rid != 0 && !groupRids.contains(rid))
            groupRids.append(rid);
    }

    const qint64 pwdLastSet =
        client.attributes.value(QStringLiteral("pwdLastSet")).toLongLong();
    const quint32 uac =
        client.attributes.value(QStringLiteral("userAccountControl")).toUInt();
    const QString fullName = client.attributes.value(QStringLiteral("displayName"));
    const QString logonServer = netbios;

    QByteArray info;
    info.reserve(int(kLogonInfoSize) + 256);
    // The fixed part of KERB_VALIDATION_INFO, all offsets patched at the end.
    const quint64 now = fileTime(QDateTime::currentSecsSinceEpoch());
    putLe64(info, now);                                  // LogonTime
    putLe64(info, 0x7fffffffffffffffULL);                // LogoffTime: never
    putLe64(info, 0x7fffffffffffffffULL);                // KickOffTime: never
    putLe64(info, fileTime(pwdLastSet));                 // PasswordLastSet
    putLe64(info, 0);                                    // PasswordCanChange
    putLe64(info, 0x7fffffffffffffffULL);                // PasswordMustChange
    const int effectiveNamePos = info.size();            // EffectiveName
    info.append(QByteArray(8, '\0'));
    const int fullNamePos = info.size();                 // FullName
    info.append(QByteArray(8, '\0'));
    const int logonScriptPos = info.size();              // LogonScript
    info.append(QByteArray(8, '\0'));
    const int profilePathPos = info.size();              // ProfilePath
    info.append(QByteArray(8, '\0'));
    const int homeDirPos = info.size();                  // HomeDirectory
    info.append(QByteArray(8, '\0'));
    const int homeDrivePos = info.size();                // HomeDirectoryDrive
    info.append(QByteArray(8, '\0'));
    putLe16(info, 0);                                    // LogonCount
    putLe16(info, 0);                                    // BadPasswordCount
    putLe32(info, userId);                               // UserId
    putLe32(info, 513);                                  // PrimaryGroupId
    putLe32(info, quint32(groupRids.size()));            // GroupCount
    const int groupIdsPos = info.size();                 // GroupIds
    info.append(QByteArray(4, '\0'));
    putLe32(info, 0);                                    // UserFlags
    info.append(QByteArray(16, '\0'));                   // UserSessionKey
    const int logonServerPos = info.size();              // LogonServer
    info.append(QByteArray(8, '\0'));
    const int logonDomainPos = info.size();              // LogonDomainName
    info.append(QByteArray(8, '\0'));
    const int logonDomainIdPos = info.size();            // LogonDomainId
    info.append(QByteArray(4, '\0'));
    putLe32(info, 0);                                    // Reserved1[0]
    putLe32(info, 0);                                    // Reserved1[1]
    putLe32(info, uac);                                  // UserAccountControl
    putLe32(info, 0);                                    // SubAuthStatus
    putLe64(info, 0);                                    // LastSuccessfulILogon
    putLe64(info, 0);                                    // LastFailedILogon
    putLe32(info, 0);                                    // FailedILogonCount
    putLe32(info, 0);                                    // Reserved3
    putLe32(info, 0);                                    // SidCount
    putLe32(info, 0);                                    // ExtraSids
    putLe32(info, 0);                                    // ResourceGroupDomainSid
    putLe32(info, 0);                                    // ResourceGroupCount
    putLe32(info, 0);                                    // ResourceGroupIds

    if (info.size() != int(kLogonInfoSize))
        return {};

    struct PendingString {
        int headerPos;
        QString value;
    };
    const QList<PendingString> strings = {
        {effectiveNamePos, account},
        {fullNamePos, fullName},
        {logonScriptPos, QString()},
        {profilePathPos, QString()},
        {homeDirPos, QString()},
        {homeDrivePos, QString()},
        {logonServerPos, logonServer},
        {logonDomainPos, netbios}};

    for (const PendingString &pending : strings) {
        if (pending.value.isEmpty())
            continue;
        const QByteArray text = utf16le(pending.value);
        const quint32 offset = quint32(info.size());
        info.append(text);
        align(info, 2);
        setLe32(info, pending.headerPos + 4, offset);
        // RPC_UNICODE_STRING: Length, MaximumLength, Buffer offset.
        info[pending.headerPos] = char(text.size() & 0xff);
        info[pending.headerPos + 1] = char((text.size() >> 8) & 0xff);
        info[pending.headerPos + 2] = info[pending.headerPos];
        info[pending.headerPos + 3] = info[pending.headerPos + 1];
    }

    align(info, 4);
    setLe32(info, logonDomainIdPos, quint32(info.size()));
    info.append(domainSidBytes);
    align(info, 4);

    setLe32(info, groupIdsPos, quint32(info.size()));
    for (const quint32 rid : groupRids)
        putLe32(info, rid);
    align(info, 8);

    // PACTYPE: cBuffers, Version, then one PAC_INFO_BUFFER per buffer. The two
    // signature buffers are appended after the payload and filled in below.
    const int bufferCount = 5;
    const int headerSize = 8 + bufferCount * 16;
    QByteArray pac;
    putLe32(pac, bufferCount);
    putLe32(pac, 0); // Version: 0
    for (int i = 0; i < bufferCount; ++i)
        pac.append(QByteArray(16, '\0'));

    const auto appendBuffer = [&pac, headerSize](int index, quint32 type,
                                                 const QByteArray &payload) {
        while (pac.size() % 8 != 0)
            pac.append('\0');
        const quint32 offset = quint32(pac.size());
        pac.append(payload);
        const int entry = 8 + index * 16;
        setLe32(pac, entry, type);
        setLe32(pac, entry + 4, quint32(payload.size()));
        setLe32(pac, entry + 8, offset);
    };
    Q_UNUSED(headerSize)

    appendBuffer(0, kLogonInfoType, info);

    // PAC_CLIENT_INFO (10): the logon time and the account name, which
    // Windows and MIT match against the ticket's client principal.
    QByteArray clientInfo;
    putLe64(clientInfo, fileTime(authtime));
    const QByteArray clientName = utf16le(account);
    putLe16(clientInfo, quint16(clientName.size()));
    clientInfo.append(clientName);
    appendBuffer(1, kClientInfoType, clientInfo);

    // PAC_UPN_DNS_INFO (12): the account's UPN and the DNS form of the domain,
    // which Windows uses to resolve the logon name without a directory lookup.
    // Offsets are relative to the start of this buffer (MS-PAC 2.11).
    QString upn = client.attributes.value(QStringLiteral("userPrincipalName"));
    if (upn.isEmpty())
        upn = account + QLatin1Char('@') + realm;
    const QByteArray upnUtf16 = utf16le(upn);
    const QByteArray dnsDomainUtf16 = utf16le(realm.toLower());
    QByteArray upnDnsInfo;
    putLe32(upnDnsInfo, quint32(upnUtf16.size()));
    putLe32(upnDnsInfo, 16);
    putLe16(upnDnsInfo, quint16(dnsDomainUtf16.size()));
    putLe16(upnDnsInfo, quint16(16 + upnUtf16.size()));
    putLe32(upnDnsInfo, 0); // Flags
    upnDnsInfo.append(upnUtf16);
    upnDnsInfo.append(dnsDomainUtf16);
    appendBuffer(2, kUpnDnsInfoType, upnDnsInfo);

    QByteArray serverChecksum;
    putLe32(serverChecksum, checksumTypeFor(keys.serviceEtype));
    serverChecksum.append(QByteArray(signatureLength(keys.serviceEtype), '\0'));
    appendBuffer(3, kServerChecksumType, serverChecksum);

    QByteArray kdcChecksum;
    putLe32(kdcChecksum, checksumTypeFor(keys.kdcEtype));
    kdcChecksum.append(QByteArray(signatureLength(keys.kdcEtype), '\0'));
    appendBuffer(4, kKdcChecksumType, kdcChecksum);

    // The server signature covers the PAC with both signatures zeroed; the KDC
    // signature covers the server signature bytes alone (MS-PAC 2.8), which is
    // also how MIT krb5 verifies it.
    QByteArray forServer = pac;
    clearSignature(forServer, kServerChecksumType);
    clearSignature(forServer, kKdcChecksumType);
    const QByteArray server = signatureFor(forServer, keys, false);
    const int serverOffset = bufferOffset(pac, kServerChecksumType);
    if (serverOffset > 0) {
        for (int i = 0; i < server.size() && serverOffset + 4 + i < pac.size(); ++i)
            pac[serverOffset + 4 + i] = server.at(i);
    }

    const QByteArray kdc = signatureFor(server, keys, true);
    const int kdcOffset = bufferOffset(pac, kKdcChecksumType);
    if (kdcOffset > 0) {
        for (int i = 0; i < kdc.size() && kdcOffset + 4 + i < pac.size(); ++i)
            pac[kdcOffset + 4 + i] = kdc.at(i);
    }
    return pac;
}

QByteArray resign(const QByteArray &pac, const Keys &keys)
{
    if (pac.isEmpty())
        return {};
    QByteArray out = pac;
    const int serverOffset = bufferOffset(out, kServerChecksumType);
    const int kdcOffset = bufferOffset(out, kKdcChecksumType);
    if (serverOffset < 0 || kdcOffset < 0)
        return {};
    setLe32(out, serverOffset, checksumTypeFor(keys.serviceEtype));
    setLe32(out, kdcOffset, checksumTypeFor(keys.kdcEtype));

    QByteArray forServer = out;
    clearSignature(forServer, kServerChecksumType);
    clearSignature(forServer, kKdcChecksumType);
    const QByteArray server = signatureFor(forServer, keys, false);
    for (int i = 0; i < server.size() && serverOffset + 4 + i < out.size(); ++i)
        out[serverOffset + 4 + i] = server.at(i);

    const QByteArray kdc = signatureFor(server, keys, true);
    for (int i = 0; i < kdc.size() && kdcOffset + 4 + i < out.size(); ++i)
        out[kdcOffset + 4 + i] = kdc.at(i);
    return out;
}

bool verify(const QByteArray &pac, const Keys &keys)
{
    if (pac.size() < 8 || !keys.isValid())
        return false;
    const int serverOffset = bufferOffset(pac, kServerChecksumType);
    const int kdcOffset = bufferOffset(pac, kKdcChecksumType);
    if (serverOffset < 0 || kdcOffset < 0)
        return false;

    QByteArray forServer = pac;
    clearSignature(forServer, kServerChecksumType);
    clearSignature(forServer, kKdcChecksumType);
    const QByteArray expectedServer = signatureFor(forServer, keys, false);
    if (expectedServer.isEmpty())
        return false;
    if (forServer.size() < serverOffset + 4 + expectedServer.size())
        return false;
    const QByteArray actualServer = pac.mid(serverOffset + 4, expectedServer.size());
    if (actualServer != expectedServer)
        return false;

    if (pac.size() < kdcOffset + 4 + signatureLength(keys.kdcEtype))
        return false;
    const QByteArray actualKdc = pac.mid(kdcOffset + 4, signatureLength(keys.kdcEtype));
    const QByteArray expectedKdc = signatureFor(actualServer, keys, true);
    return !expectedKdc.isEmpty() && actualKdc == expectedKdc;
}

QByteArray authorizationData(const QByteArray &pac)
{
    // AuthorizationData ::= SEQUENCE OF AuthorizationDataElement, with
    // AD-IF-RELEVANT wrapping AD-WIN2K-PAC.
    QByteArray pacElement;
    pacElement.append(Asn1::integer(0x02, kWin2kPac));
    pacElement.append(Asn1::octets(0x04, pac));
    const QByteArray innerAuthorizationData = Asn1::sequenceOf({Asn1::sequence(pacElement)});

    QByteArray ifRelevant;
    ifRelevant.append(Asn1::integer(0x02, kIfRelevant));
    ifRelevant.append(Asn1::octets(0x04, innerAuthorizationData));
    return Asn1::sequenceOf({Asn1::sequence(ifRelevant)});
}

QByteArray extract(const QByteArray &authorizationData)
{
    if (authorizationData.isEmpty())
        return {};
    Asn1::Element outer;
    if (!Asn1::parse(authorizationData, &outer) || outer.tag != 0x30)
        return {};
    for (const Asn1::Element &outerElement : outer.children) {
        if (outerElement.tag != 0x30 || outerElement.children.size() < 2)
            continue;
        if (int(Asn1::toInteger(outerElement.children.at(0))) != kIfRelevant)
            continue;
        if (outerElement.children.at(1).tag != 0x04)
            continue;
        Asn1::Element inner;
        if (!Asn1::parse(outerElement.children.at(1).value, &inner) || inner.tag != 0x30)
            continue;
        for (const Asn1::Element &pacElement : inner.children) {
            if (pacElement.tag != 0x30 || pacElement.children.size() < 2)
                continue;
            if (int(Asn1::toInteger(pacElement.children.at(0))) != kWin2kPac)
                continue;
            if (pacElement.children.at(1).tag == 0x04)
                return pacElement.children.at(1).value;
        }
    }
    return {};
}

bool readIdentity(const QByteArray &pac, Identity *identity)
{
    if (pac.isEmpty() || !identity)
        return false;
    const int offset = bufferOffset(pac, kLogonInfoType);
    if (offset < 0)
        return false;
    const quint32 count = readLe32(pac, 0);
    int size = 0;
    for (quint32 i = 0; i < count; ++i) {
        const int entry = 8 + int(i) * 16;
        if (int(readLe32(pac, entry)) == int(kLogonInfoType))
            size = int(readLe32(pac, entry + 4));
    }
    if (size < 116 || offset + size > pac.size())
        return false;
    const QByteArray info = pac.mid(offset, size);
    identity->userId = readLe32(info, 100);
    identity->primaryGroupId = readLe32(info, 104);
    const quint32 groups = readLe32(info, 108);
    const int groupOffset = int(readLe32(info, 112));
    identity->groupIds.clear();
    for (quint32 i = 0; i < groups; ++i) {
        const int pos = groupOffset + int(i) * 4;
        if (pos < 0 || pos + 4 > info.size())
            return false;
        identity->groupIds.append(readLe32(info, pos));
    }
    return identity->userId != 0;
}

} // namespace Pac
