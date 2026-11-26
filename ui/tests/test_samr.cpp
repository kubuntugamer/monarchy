// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QCryptographicHash>
#include <QtTest>
#include <QStringList>

#include "Des.h"
#include "Krb5.h"
#include "Ndr.h"
#include "Samr.h"

namespace {

// Request stubs captured from impacket's SAMR client (an independent
// implementation), so the parser is tested against real client bytes.
const QByteArray kConnect =
    QByteArray::fromHex("3e3600000000000000000002");
// The handle in a captured request is from another session, so the caller
// splices in the one this server issued.
QByteArray enumDomainsStub(const QByteArray &serverHandle)
{
    return serverHandle + QByteArray::fromHex("0000000000000000ffffffff");
}

QByteArray lookupDomainStub(const QByteArray &serverHandle)
{
    return serverHandle
           + QByteArray::fromHex("08000800696f000004000000"
                                 "000000000400000043004f0052005000");
}

QByteArray openDomainStub(const QByteArray &serverHandle)
{
    return serverHandle
           + QByteArray::fromHex("000000020000000004000000"
                                 "010400000000000515000000010000000200000003000000");
}

QByteArray enumUsersStub(const QByteArray &domainHandle)
{
    return domainHandle + QByteArray::fromHex("0000000000000000ffffffff");
}

QByteArray openUserStub(const QByteArray &domainHandle, quint32 rid)
{
    QByteArray stub = domainHandle;
    stub.append(QByteArray::fromHex("00000002")); // DesiredAccess
    stub.append(char(rid & 0xff));
    stub.append(char((rid >> 8) & 0xff));
    stub.append(char((rid >> 16) & 0xff));
    stub.append(char((rid >> 24) & 0xff));
    return stub;
}

quint32 lastWord(const QByteArray &stub)
{
    if (stub.size() < 4)
        return 0xffffffffu;
    const int offset = stub.size() - 4;
    return quint32(quint8(stub.at(offset)))
           | (quint32(quint8(stub.at(offset + 1))) << 8)
           | (quint32(quint8(stub.at(offset + 2))) << 16)
           | (quint32(quint8(stub.at(offset + 3))) << 24);
}

void appendLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

quint32 readLe32At(const QByteArray &data, int at)
{
    return quint32(quint8(data.at(at))) | (quint32(quint8(data.at(at + 1))) << 8)
           | (quint32(quint8(data.at(at + 2))) << 16)
           | (quint32(quint8(data.at(at + 3))) << 24);
}

// A varying UTF-16 string as NDR writes it: max count, offset, actual count,
// then the characters padded to a 4-byte boundary.
void appendVaryingString(QByteArray &out, const QString &text)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    appendLe32(out, quint32(text.size() + 1));
    appendLe32(out, 0);
    appendLe32(out, quint32(text.size()));
    out.append(utf16);
    while (out.size() % 4 != 0)
        out.append('\0');
}

// SamrLookupNamesInDomain as impacket marshals it: the count, the array's
// maximum count / offset / actual count, the element structures, then their
// character buffers.
QByteArray lookupNamesStub(const QByteArray &domainHandle, const QStringList &names)
{
    QByteArray stub = domainHandle;
    appendLe32(stub, quint32(names.size()));
    appendLe32(stub, 1000); // MaximumCount, from the IDL's size_is(1000)
    appendLe32(stub, 0);
    appendLe32(stub, quint32(names.size()));
    QByteArray buffers;
    for (const QString &name : names) {
        const QByteArray utf16 = Ndr::utf16le(name);
        const quint16 length = quint16(utf16.size());
        stub.append(char(length & 0xff));
        stub.append(char((length >> 8) & 0xff));
        stub.append(char(length & 0xff));
        stub.append(char((length >> 8) & 0xff));
        appendLe32(stub, 0x0002c400u + quint32(buffers.size()));
        appendVaryingString(buffers, name);
    }
    stub.append(buffers);
    return stub;
}

QByteArray lookupIdsStub(const QByteArray &domainHandle, const QList<quint32> &rids)
{
    QByteArray stub = domainHandle;
    appendLe32(stub, quint32(rids.size()));
    appendLe32(stub, 1000);
    appendLe32(stub, 0);
    appendLe32(stub, quint32(rids.size()));
    for (quint32 rid : rids)
        appendLe32(stub, rid);
    return stub;
}

// SamrCreateUser2InDomain / SamrCreateGroupInDomain: the name travels inline
// right behind its pointer, then the scalars.
QByteArray createStub(const QByteArray &domainHandle, const QString &name, bool user,
                      quint32 accountType = 0x10) // USER_NORMAL_ACCOUNT
{
    const QByteArray utf16 = Ndr::utf16le(name);
    QByteArray stub = domainHandle;
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    appendLe32(stub, 0x00026a00u);
    appendLe32(stub, quint32(name.size() + 1)); // MaximumCount
    appendLe32(stub, 0);                        // Offset
    appendLe32(stub, quint32(name.size()));     // ActualCount
    stub.append(utf16);
    while (stub.size() % 4 != 0)
        stub.append('\0');
    if (user)
        appendLe32(stub, accountType);
    appendLe32(stub, 0x000f001fu); // MAXIMUM_ALLOWED
    return stub;
}

// The two server-level calls for the BUILTIN domain, which every DC reports
// next to the account NC.
QByteArray lookupDomainStubFor(const QByteArray &serverHandle, const QString &name)
{
    const QByteArray utf16 = Ndr::utf16le(name);
    QByteArray stub = serverHandle;
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    appendLe32(stub, 0x00006f69u); // name buffer referent
    appendLe32(stub, quint32(name.size()));
    appendLe32(stub, 0);
    appendLe32(stub, quint32(name.size()));
    stub.append(utf16);
    while (stub.size() % 4 != 0)
        stub.append('\0');
    return stub;
}

QByteArray openDomainStubFor(const QByteArray &serverHandle, const QString &sidText)
{
    QByteArray stub = serverHandle;
    appendLe32(stub, 0x00000002u); // DesiredAccess
    appendLe32(stub, 0);           // alignment before the inline SID count
    const QByteArray sid = Ndr::sidFromString(sidText);
    appendLe32(stub, quint32((sid.size() - 8) / 4));
    stub.append(sid);
    return stub;
}

// SamrEnumerateAliasesInDomain: no access mask, just the window.
QByteArray enumAliasesStub(const QByteArray &domainHandle)
{
    QByteArray stub = domainHandle;
    appendLe32(stub, 0);
    appendLe32(stub, 0x10000);
    return stub;
}

// SamrQueryInformationAlias: the class is a USHORT behind the handle.
QByteArray queryAliasStub(const QByteArray &aliasHandle, quint16 infoClass)
{
    QByteArray stub = aliasHandle;
    stub.append(char(infoClass & 0xff));
    stub.append(char((infoClass >> 8) & 0xff));
    return stub;
}

// SamrAddMemberToAlias: the member is an RPC_SID, whose sub-authority count is
// a conformant array length in front of the header.
QByteArray aliasMemberStub(const QByteArray &aliasHandle, const QByteArray &sid)
{
    QByteArray stub = aliasHandle;
    appendLe32(stub, quint32((sid.size() - 8) / 4));
    stub.append(sid);
    return stub;
}

// SamrSetInformationUser2, captured from impacket for a control-information
// write: info class 16, union tag 16, then the ULONG arm.
QByteArray controlStub(const QByteArray &userHandle)
{
    // ACB_DISABLED | ACB_NORMAL: the word a client that disables the account
    // writes, in SAMR's acct_flags numbering.
    return userHandle + QByteArray::fromHex("10001000") + QByteArray::fromHex("11000000");
}

// SamrSetInformationUser2, class 8 (full name), captured from impacket: the
// string lengths and pointer inline, its characters deferred.
QByteArray fullNameStub(const QByteArray &userHandle, const QString &name)
{
    const QByteArray utf16 = Ndr::utf16le(name);
    QByteArray stub = userHandle + QByteArray::fromHex("08000800");
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    stub.append(char(utf16.size() & 0xff));
    stub.append(char((utf16.size() >> 8) & 0xff));
    appendLe32(stub, 0x00008d50u); // buffer referent, as impacket emits it
    appendVaryingString(stub, name);
    return stub;
}

// One counted string of a class 1/2/3 record: its length and referent in the
// fixed part, its characters behind it. A string that is not set still carries
// its three counts, which is what keeps the buffers behind it in step.
void appendCountedTuple(QByteArray &fixed, QByteArray &deferred, const QString &text,
                        quint32 referent)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    fixed.append(char(utf16.size() & 0xff));
    fixed.append(char((utf16.size() >> 8) & 0xff));
    fixed.append(char(utf16.size() & 0xff));
    fixed.append(char((utf16.size() >> 8) & 0xff));
    appendLe32(fixed, referent);
    appendLe32(deferred, quint32(text.size() + 1));
    appendLe32(deferred, 0);
    appendLe32(deferred, quint32(text.size()));
    deferred.append(utf16);
    while (deferred.size() % 4 != 0)
        deferred.append('\0');
}

// SamrSetInformationUser2, class 1 (general record), as impacket marshals it.
QByteArray generalRecordStub(const QByteArray &userHandle, const QString &name,
                             const QString &fullName, quint32 primaryGroup,
                             const QString &adminComment, const QString &comment)
{
    QByteArray stub = userHandle + QByteArray::fromHex("01000100");
    QByteArray deferred;
    appendCountedTuple(stub, deferred, name, 0x0000e310u);
    appendCountedTuple(stub, deferred, fullName, 0x0000e320u);
    appendLe32(stub, primaryGroup);
    appendCountedTuple(stub, deferred, adminComment, 0x0000e330u);
    appendCountedTuple(stub, deferred, comment, 0x0000e340u);
    stub.append(deferred);
    return stub;
}

// SamrSetInformationUser2, class 2 (preferences): the comment, the string AD
// accepts and never stores, and the two locale numbers.
QByteArray preferencesStub(const QByteArray &userHandle, const QString &comment,
                           quint16 countryCode, quint16 codePage)
{
    QByteArray stub = userHandle + QByteArray::fromHex("02000200");
    QByteArray deferred;
    appendCountedTuple(stub, deferred, comment, 0x0000e410u);
    appendCountedTuple(stub, deferred, QString(), 0x0000e420u);
    stub.append(char(countryCode & 0xff));
    stub.append(char((countryCode >> 8) & 0xff));
    stub.append(char(codePage & 0xff));
    stub.append(char((codePage >> 8) & 0xff));
    stub.append(deferred);
    return stub;
}

// SamrSetInformationUser2, class 3 (logon record): nine counted strings, the
// RID and primary group, five instants, the week, the counters and the flags.
QByteArray logonRecordStub(const QByteArray &userHandle, const QString &name,
                           const QString &fullName, quint32 primaryGroup,
                           const QString &homeDirectory, const QString &homeDrive,
                           const QString &scriptPath, const QString &profilePath,
                           const QString &workstations, const QByteArray &week)
{
    QByteArray stub = userHandle + QByteArray::fromHex("03000300");
    QByteArray deferred;
    appendCountedTuple(stub, deferred, name, 0x0000e510u);
    appendCountedTuple(stub, deferred, fullName, 0x0000e520u);
    appendLe32(stub, 1001); // RID, which the DC owns
    appendLe32(stub, primaryGroup);
    appendCountedTuple(stub, deferred, homeDirectory, 0x0000e530u);
    appendCountedTuple(stub, deferred, homeDrive, 0x0000e540u);
    appendCountedTuple(stub, deferred, scriptPath, 0x0000e550u);
    appendCountedTuple(stub, deferred, profilePath, 0x0000e560u);
    appendCountedTuple(stub, deferred, workstations, 0x0000e570u);
    for (int i = 0; i < 5; ++i)
        for (int b = 0; b < 8; ++b)
            stub.append('\0'); // last logon, last logoff, and the three password instants
    stub.append(char((week.size() * 8) & 0xff));
    stub.append(char(((week.size() * 8) >> 8) & 0xff));
    stub.append(QByteArray(2, '\0'));
    appendLe32(stub, 0x0000e580u);
    stub.append(QByteArray(4, '\0')); // bad-password and logon counters
    appendLe32(stub, 0x200);        // userAccountControl, which the DC owns here
    appendLe32(deferred, 1260);
    appendLe32(deferred, 0);
    appendLe32(deferred, quint32(week.size()));
    deferred.append(week);
    while (deferred.size() % 4 != 0)
        deferred.append('\0');
    stub.append(deferred);
    return stub;
}

// A class 24/26 password set: 512 bytes of UTF-16 password followed by its
// length, ciphered with the session key (class 24) or with MD5(confounder ||
// session key) behind a 16-byte confounder (class 26).
QByteArray cryptPasswordStub(const QByteArray &userHandle, quint16 infoClass,
                             const QString &password, const QByteArray &sessionKey)
{
    const QByteArray utf16 = Ndr::utf16le(password);
    // The buffer is left padding followed by the password, as Samba's
    // extract_pw_from_buffer and impacket's rjust both build it.
    QByteArray plain(512, '\0');
    plain.replace(512 - utf16.size(), utf16.size(), utf16);
    appendLe32(plain, quint32(utf16.size()));

    QByteArray ciphered = Krb5::rc4(sessionKey, plain);
    if (infoClass == 26) {
        const QByteArray confounder = QByteArray(16, '\xa5');
        const QByteArray key =
            QCryptographicHash::hash(confounder + sessionKey, QCryptographicHash::Md5);
        ciphered = Krb5::rc4(key, plain) + confounder;
    }

    QByteArray stub = userHandle;
    stub.append(char(infoClass & 0xff));
    stub.append(char((infoClass >> 8) & 0xff));
    stub.append(char(infoClass & 0xff)); // union tag
    stub.append(char((infoClass >> 8) & 0xff));
    stub.append(ciphered);
    stub.append('\0'); // password_expired
    return stub;
}

// SamrSetInformationUser, class 18: two DES-enciphered 16-byte hashes, then the
// three presence flags (MS-SAMR 2.2.7.11 / 2.2.11.1).
QByteArray internal1Stub(const QByteArray &userHandle, const QByteArray &ntHash,
                         const QByteArray &sessionKey, bool expired = false)
{
    QByteArray stub = userHandle + QByteArray::fromHex("1200") + QByteArray::fromHex("1200");
    stub.append(Des::encryptOwfHash(ntHash, sessionKey));
    stub.append(QByteArray(16, '\0')); // EncryptedLmOwfPassword
    stub.append(char(1));              // NtPasswordPresent
    stub.append(char(0));              // LmPasswordPresent
    stub.append(char(expired ? 1 : 0));
    return stub;
}

// One SAMPR_USER_ALL_INFORMATION arm, written the way MS-SAMR 2.2.7.6 lays it
// out: the fixed part first, then every buffer a pointer named, in order.
struct UserInfoFields {
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
    quint32 fieldsPresent = 0;
    quint32 accountControl = 0;
    quint32 primaryGroupId = 0;
    quint64 accountExpires = 0;
    quint16 countryCode = 0;
    quint16 codePage = 0;
    QByteArray logonHours; // empty means the NULL pointer
    QByteArray ntOwf;      // the DES-enciphered hash, or empty for NULL
    bool passwordExpired = false;
};

// The inline header of an RPC_UNICODE_STRING or RPC_SHORT_BLOB: Length,
// MaximumLength and the buffer referent, which is all a NULL field contributes.
void appendStringHeader(QByteArray &out, bool present, quint16 length, quint16 maximum,
                        quint32 referent)
{
    out.append(char(length & 0xff));
    out.append(char((length >> 8) & 0xff));
    out.append(char(maximum & 0xff));
    out.append(char((maximum >> 8) & 0xff));
    appendLe32(out, present ? referent : 0u);
}

QByteArray allUserInfoStub(const QByteArray &userHandle, quint16 infoClass,
                           const UserInfoFields &fields,
                           const QByteArray &password = QByteArray(),
                           const QByteArray &sessionKey = QByteArray())
{
    QByteArray stub = userHandle;
    stub.append(char(infoClass & 0xff));
    stub.append(char((infoClass >> 8) & 0xff));
    stub.append(char(infoClass & 0xff)); // union tag
    stub.append(char((infoClass >> 8) & 0xff));

    const QList<QString> strings = {fields.userName,        fields.fullName,
                                    fields.homeDirectory,  fields.homeDrive,
                                    fields.scriptPath,     fields.profilePath,
                                    fields.adminComment,   fields.workstations,
                                    fields.userComment,    fields.parameters};

    // The six timestamps the server owns; a set leaves them as the client sent
    // them and the server ignores the values.
    stub.append(QByteArray(48, '\0'));
    quint32 referent = 0x0003a100u;
    for (const QString &text : strings) {
        const quint16 length = quint16(Ndr::utf16le(text).size());
        appendStringHeader(stub, !text.isEmpty(), length, quint16(length + 2), referent++);
    }
    // LmOwfPassword and NtOwfPassword (RPC_SHORT_BLOB), then PrivateData.
    appendStringHeader(stub, false, 0, 0, 0);
    appendStringHeader(stub, !fields.ntOwf.isEmpty(), quint16(fields.ntOwf.size() * 2),
                       quint16(fields.ntOwf.size() * 2), referent++);
    appendStringHeader(stub, false, 0, 0, 0);
    // SAMPR_SR_SECURITY_DESCRIPTOR: cb and a NULL buffer.
    appendLe32(stub, 0);
    appendLe32(stub, 0);

    appendLe32(stub, 0); // UserId, the server's to assign
    appendLe32(stub, fields.primaryGroupId);
    appendLe32(stub, fields.accountControl);
    appendLe32(stub, fields.fieldsPresent);

    // SAMPR_LOGON_HOURS: one byte per hour, 21 for the week.
    const quint16 units = quint16(fields.logonHours.size() * 8);
    stub.append(char(units & 0xff));
    stub.append(char((units >> 8) & 0xff));
    stub.append(QByteArray(2, '\0'));
    appendLe32(stub, fields.logonHours.isEmpty() ? 0u : referent++);

    stub.append(QByteArray(4, '\0')); // BadPasswordCount, LogonCount
    stub.append(char(fields.countryCode & 0xff));
    stub.append(char((fields.countryCode >> 8) & 0xff));
    stub.append(char(fields.codePage & 0xff));
    stub.append(char((fields.codePage >> 8) & 0xff));
    stub.append(char(0)); // LmPasswordPresent
    stub.append(char(fields.ntOwf.isEmpty() ? 0 : 1));
    stub.append(char(fields.passwordExpired ? 1 : 0));
    stub.append(char(0)); // PrivateDataSensitive

    // Classes 23 and 25 close the structure with the ciphered password, which
    // sits in front of every deferred buffer.
    if (infoClass == 23 || infoClass == 25) {
        const QByteArray utf16 = Ndr::utf16le(QStringLiteral("An0ther!Pass"));
        QByteArray plain(512, '\0');
        plain.replace(512 - utf16.size(), utf16.size(), utf16);
        appendLe32(plain, quint32(utf16.size()));
        if (infoClass == 25) {
            const QByteArray confounder(16, '\x5a');
            const QByteArray key =
                QCryptographicHash::hash(confounder + sessionKey, QCryptographicHash::Md5);
            stub.append(Krb5::rc4(key, plain) + confounder);
        } else {
            stub.append(Krb5::rc4(sessionKey, plain));
        }
    }

    for (const QString &text : strings) {
        if (text.isEmpty())
            continue;
        appendVaryingString(stub, text);
    }
    if (!fields.ntOwf.isEmpty()) {
        // RPC_SHORT_BLOB counts USHORT elements, so its Length is twice the
        // element count.
        const quint32 elements = quint32(fields.ntOwf.size() / 2);
        appendLe32(stub, elements);
        appendLe32(stub, 0);
        appendLe32(stub, elements);
        stub.append(fields.ntOwf);
        while (stub.size() % 4 != 0)
            stub.append('\0');
    }
    if (!fields.logonHours.isEmpty()) {
        appendLe32(stub, 1260); // MaximumCount, from the IDL's size_is(1260)
        appendLe32(stub, 0);
        appendLe32(stub, quint32(fields.logonHours.size()));
        stub.append(fields.logonHours);
        while (stub.size() % 4 != 0)
            stub.append('\0');
    }
    return stub;
}

// Reads one samr_Ids: count, pointer, then the maximum count and its values.
bool readIdArray(const QByteArray &data, int *pos, QList<quint32> *values)
{
    if (*pos + 8 > data.size())
        return false;
    const quint32 count = readLe32At(data, *pos);
    const quint32 pointer = readLe32At(data, *pos + 4);
    // The referent has to be the offset of the array it names — the maximum
    // count that begins it — because that is how a Windows stub resolves a
    // pointer. A unique-but-wrong value (0x0002e100) unmarshals to a wild
    // address on the client, which is what a 2000 `net user` reported as 124.
    if (pointer != 0 && pointer != quint32(*pos + 8))
        return false;
    *pos += 8;
    values->clear();
    if (pointer == 0)
        return count == 0;
    if (*pos + 4 > data.size())
        return false;
    const quint32 maximum = readLe32At(data, *pos);
    *pos += 4;
    if (maximum != count || *pos + int(count) * 4 > data.size())
        return false;
    for (quint32 i = 0; i < count; ++i) {
        values->append(readLe32At(data, *pos));
        *pos += 4;
    }
    return true;
}

QString utf16Text(const QByteArray &stub)
{
    QString text;
    for (int i = 0; i + 1 < stub.size(); i += 2) {
        const uint16_t unit = uint16_t(quint8(stub.at(i)) | (quint8(stub.at(i + 1)) << 8));
        if (unit >= 0x20 && unit < 0x7f)
            text.append(QChar(unit));
    }
    return text;
}

} // namespace

class SamrTest : public QObject
{
    Q_OBJECT

private slots:
    void ndrPrimitivesRoundTrip();
    void sidEncoding();
    void samrDirectoryCalls();
    void samrServesTheDomainPasswordPolicy();
    void samrServesTheBuiltinDomain();
    void samrWritesAccountsAndGroups();
    void samrWritesBuiltinAliasMembers();
    void samrSetPasswordAndAccountControl();
    void desPrimitivesAndHashEncoding();
    void samrSetsCredentialFromHash();
    void samrWritesTheAggregateUserInformation();
    void samrSetsPasswordThroughTheAggregateClasses();
    void rpcFramingCarriesSamr();
    void rpcBindAnswersEveryContext();
};

void SamrTest::ndrPrimitivesRoundTrip()
{
    Ndr::Writer writer;
    writer.u8(0x12);
    writer.u16(0x3456);
    writer.u32(0x789abcde);
    writer.referent(true);
    writer.conformantCount(3);
    const QByteArray data = writer.take();

    Ndr::Reader reader(data);
    quint8 a = 0;
    quint16 b = 0;
    quint32 c = 0;
    bool present = false;
    quint32 count = 0;
    QVERIFY(reader.u8(&a));
    QVERIFY(reader.u16(&b));
    QVERIFY(reader.u32(&c));
    QVERIFY(reader.referent(&present));
    QVERIFY(reader.conformantCount(&count));
    QCOMPARE(a, quint8(0x12));
    QCOMPARE(b, quint16(0x3456));
    QCOMPARE(c, 0x789abcdeu);
    QVERIFY(present);
    QCOMPARE(count, 3u);
    QVERIFY(reader.atEnd());

    // A NULL referent is distinguishable from a live one.
    Ndr::Writer nullWriter;
    nullWriter.referent(false);
    Ndr::Reader nullReader(nullWriter.take());
    bool nullPresent = true;
    QVERIFY(nullReader.referent(&nullPresent));
    QVERIFY(!nullPresent);
}

void SamrTest::sidEncoding()
{
    const QByteArray sid = Ndr::sidFromString(QStringLiteral("S-1-5-21-1-2-3-500"));
    QCOMPARE(sid.size(), 8 + 4 * 5);
    QCOMPARE(quint8(sid.at(0)), quint8(1));   // revision
    QCOMPARE(quint8(sid.at(1)), quint8(5));   // sub-authorities
    QCOMPARE(Ndr::sidToString(sid), QStringLiteral("S-1-5-21-1-2-3-500"));

    Ndr::Writer writer;
    Ndr::writeSid(writer, sid);
    Ndr::Reader reader(writer.take());
    QByteArray parsed;
    QVERIFY(Ndr::readSid(reader, &parsed));
    QCOMPARE(Ndr::sidToString(parsed), QStringLiteral("S-1-5-21-1-2-3-500"));
}

// The domain password policy lives on the domain object under the attribute
// names AD uses, and SAMR both reports and writes it there: 7 characters, 24
// remembered passwords, complexity on, and the two ages as negative
// 100-nanosecond deltas. A policy that could not be honoured is refused rather
// than accepted and dropped.
void SamrTest::samrServesTheDomainPasswordPolicy()
{
    DirectoryObject domainObject;
    domainObject.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domainObject.name = QStringLiteral("CORP");
    domainObject.type = QStringLiteral("domainDNS");
    domainObject.kind = ObjectKind::Domain;
    domainObject.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));
    domainObject.attributes.insert(QStringLiteral("minPwdLength"), QStringLiteral("12"));
    domainObject.attributes.insert(QStringLiteral("pwdHistoryLength"), QStringLiteral("5"));
    domainObject.attributes.insert(QStringLiteral("pwdProperties"), QStringLiteral("1"));
    domainObject.attributes.insert(QStringLiteral("maxPwdAge"),
                                   QStringLiteral("-36288000000000"));
    domainObject.attributes.insert(QStringLiteral("minPwdAge"),
                                   QStringLiteral("-864000000000"));
    const QList<DirectoryObject> objects{domainObject};

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([objects]() { return objects; });

    QMap<QString, QString> written;
    Samr::WriteBackend backend;
    backend.set = [&written](const QString &dn, const QString &attribute, const QString &value,
                             QString *) {
        written.insert(attribute, value);
        return dn.compare(QStringLiteral("DC=corp,DC=example,DC=com")) == 0;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle =
        server.handleCall(Samr::OpConnect, kConnect).left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);

    // A set stub: the handle, the information class, then the class's arm
    // inline (two counts, the flag word, and the two 8-byte-aligned ages).
    const auto policyStub = [](const QByteArray &handle, quint16 minLength, quint16 history,
                               quint32 properties, qint64 maxAge, qint64 minAge) {
        QByteArray stub = handle;
        stub.append(char(1));
        stub.append(char(0));
        while (stub.size() % 8) // the arm is 8-aligned for its two ages
            stub.append(char(0));
        stub.append(char(minLength & 0xff));
        stub.append(char((minLength >> 8) & 0xff));
        stub.append(char(history & 0xff));
        stub.append(char((history >> 8) & 0xff));
        for (int i = 0; i < 4; ++i)
            stub.append(char((properties >> (8 * i)) & 0xff));
        while (stub.size() % 8)
            stub.append(char(0));
        for (int i = 0; i < 8; ++i)
            stub.append(char((quint64(maxAge) >> (8 * i)) & 0xff));
        for (int i = 0; i < 8; ++i)
            stub.append(char((quint64(minAge) >> (8 * i)) & 0xff));
        return stub;
    };

    // The query reports the stored policy, with the ages as AD keeps them.
    QByteArray request = domainHandle;
    request.append(char(1));
    request.append(char(0));
    const QByteArray reply = server.handleCall(Samr::OpQueryInformationDomain, request);
    QCOMPARE(lastWord(reply), 0u);
    // The union is behind a pointer: the referent names the tag word at offset
    // 4, and the arm begins at 8 behind the tag and its alignment pad.
    QCOMPARE(readLe32At(reply, 0), 4u);
    QCOMPARE(reply.mid(4, 2), QByteArray::fromHex("0100")); // tag: DomainPasswordInformation
    QByteArray expected;
    expected.append(char(12));
    expected.append(char(0));
    expected.append(char(5));
    expected.append(char(0));
    expected.append(QByteArray::fromHex("01000000"));
    for (int i = 0; i < 8; ++i)
        expected.append(char((quint64(-36288000000000LL) >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        expected.append(char((quint64(-864000000000LL) >> (8 * i)) & 0xff));
    QVERIFY2(reply.contains(expected), qPrintable(QString::fromLatin1(reply.toHex())));

    // A set writes every field it carries to the domain object.
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationDomain,
                 policyStub(domainHandle, 14, 3, 1, -864000000000LL, -864000000000LL))),
             0u);
    QCOMPARE(written.value(QStringLiteral("minPwdLength")), QStringLiteral("14"));
    QCOMPARE(written.value(QStringLiteral("pwdHistoryLength")), QStringLiteral("3"));
    QCOMPARE(written.value(QStringLiteral("pwdProperties")), QStringLiteral("1"));
    QCOMPARE(written.value(QStringLiteral("maxPwdAge")), QStringLiteral("-864000000000"));
    QCOMPARE(written.value(QStringLiteral("minPwdAge")), QStringLiteral("-864000000000"));

    // A maximum age shorter than the minimum would expire a password before it
    // could be set.
    written.clear();
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationDomain,
                 policyStub(domainHandle, 14, 3, 1, -864000000000LL, -1728000000000LL))),
             0xc000000du); // STATUS_INVALID_PARAMETER
    QVERIFY(written.isEmpty());

    // Zero is how SAMR says "never expires" (NetUserModalsGet reads it that
    // way); AD's own attribute holds the most negative value instead. Both are
    // accepted, and neither is rewritten behind the client's back.
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationDomain,
                                        policyStub(domainHandle, 14, 3, 1, 0, 0))),
             0u);
    QCOMPARE(written.value(QStringLiteral("maxPwdAge")), QStringLiteral("0"));

    // Complexity off and an 8-character floor, which the directory then honours
    // instead of the built-in rule.
    written.clear();
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationDomain,
                                        policyStub(domainHandle, 8, 3, 0,
                                                   -36288000000000LL, -864000000000LL))),
             0u);
    QCOMPARE(written.value(QStringLiteral("pwdProperties")), QStringLiteral("0"));
}

void SamrTest::samrDirectoryCalls()
{
    QList<DirectoryObject> objects;
    auto addUser = [&objects](const QString &name, const QString &account, const QString &sid) {
        DirectoryObject object;
        object.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(name);
        object.name = name;
        object.type = QStringLiteral("User");
        object.attributes.insert(QStringLiteral("sAMAccountName"), account);
        object.attributes.insert(QStringLiteral("objectSid"), sid);
        object.attributes.insert(QStringLiteral("displayName"), name);
        objects.append(object);
    };
    addUser(QStringLiteral("Administrator"), QStringLiteral("Administrator"),
            QStringLiteral("S-1-5-21-1-2-3-500"));
    addUser(QStringLiteral("alice"), QStringLiteral("alice"), QStringLiteral("S-1-5-21-1-2-3-1001"));
    // The logon statistics SamLogon keeps on the account, so the aggregate read
    // reports what a domain administrator sees on the account tab.
    objects.last().attributes.insert(QStringLiteral("lastLogon"),
                                     QStringLiteral("1234605616436508552"));
    objects.last().attributes.insert(QStringLiteral("logonCount"), QStringLiteral("7"));
    objects.last().attributes.insert(QStringLiteral("badPwdCount"), QStringLiteral("3"));
    // A machine account, whose SID_NAME_USE is not a user's.
    addUser(QStringLiteral("WS01$"), QStringLiteral("WS01$"), QStringLiteral("S-1-5-21-1-2-3-2001"));
    objects.last().type = QStringLiteral("Computer");
    objects.last().kind = ObjectKind::Computer;

    // The domain NC object, which carries the lockout policy.
    DirectoryObject domainObject;
    domainObject.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domainObject.name = QStringLiteral("CORP");
    domainObject.type = QStringLiteral("domainDNS");
    domainObject.kind = ObjectKind::Domain;
    domainObject.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));
    domainObject.attributes.insert(QStringLiteral("lockoutThreshold"), QStringLiteral("3"));
    domainObject.attributes.insert(QStringLiteral("lockoutDuration"),
                                   QStringLiteral("-18000000000"));
    domainObject.attributes.insert(QStringLiteral("lockoutObservationWindow"),
                                   QStringLiteral("-18000000000"));
    objects.append(domainObject);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([objects]() { return objects; });

    // SamrConnect: a 20-byte context handle and STATUS_SUCCESS.
    const QByteArray connectReply = server.handleCall(Samr::OpConnect, kConnect);
    QCOMPARE(connectReply.size(), 24);
    QCOMPARE(lastWord(connectReply), 0u);
    const QByteArray serverHandle = connectReply.left(20);

    // EnumerateDomainsInSamServer: the NetBIOS name and one entry.
    const QByteArray domainsReply = server.handleCall(Samr::OpEnumerateDomainsInSamServer,
                                                      enumDomainsStub(serverHandle));
    QVERIFY(domainsReply.contains(QByteArrayLiteral("C\x00O\x00R\x00P\x00")));
    QCOMPARE(lastWord(domainsReply), 0u);

    // LookupDomainInSamServer: the domain SID, printed back in canonical form.
    const QByteArray lookupReply =
        server.handleCall(Samr::OpLookupDomainInSamServer, lookupDomainStub(serverHandle));
    QCOMPARE(lastWord(lookupReply), 0u);
    QVERIFY(lookupReply.contains(Ndr::sidFromString(config.domainSid)));

    // OpenDomain: a domain handle.
    const QByteArray domainReply =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle));
    QCOMPARE(domainReply.size(), 24);
    QCOMPARE(lastWord(domainReply), 0u);
    const QByteArray domainHandle = domainReply.left(20);

    // QueryInformationDomain class 12 reports the domain's lockout policy: the
    // intervals AD stores as negative values come back as their magnitude, and
    // the threshold as the number of refusals that locks an account.
    QByteArray lockoutRequest = domainHandle;
    lockoutRequest.append(char(12));
    lockoutRequest.append(QByteArray(2, '\0'));
    const QByteArray lockoutReply =
        server.handleCall(Samr::OpQueryInformationDomain, lockoutRequest);
    QCOMPARE(lastWord(lockoutReply), 0u);
    QByteArray halfHour(8, '\0');
    for (int i = 0; i < 8; ++i)
        halfHour[i] = char((18000000000ull >> (8 * i)) & 0xff);
    QVERIFY(lockoutReply.contains(halfHour));
    QVERIFY(lockoutReply.contains(QByteArray::fromHex("03000000"))); // threshold 3

    // QueryInformationDomain class 3 is the forced-logoff instant, which a DC
    // that forces none answers as the NTTIME "never": `net accounts /domain`
    // reads it and stops the command when the class is refused.
    QByteArray logoffRequest = domainHandle;
    logoffRequest.append(char(3));
    logoffRequest.append(QByteArray(2, '\0'));
    const QByteArray logoffReply =
        server.handleCall(Samr::OpQueryInformationDomain, logoffRequest);
    QCOMPARE(lastWord(logoffReply), 0u);
    QCOMPARE(readLe32At(logoffReply, 0), 4u);
    QCOMPARE(logoffReply.mid(4, 2), QByteArray::fromHex("0300")); // tag
    QCOMPARE(logoffReply.mid(8, 8), QByteArray::fromHex("ffffffffffffff7f"));

    // EnumerateUsersInDomain: both accounts with their RIDs.
    const QByteArray usersReply =
        server.handleCall(Samr::OpEnumerateUsersInDomain, enumUsersStub(domainHandle));
    QCOMPARE(lastWord(usersReply), 0u);
    const QString text = utf16Text(usersReply);
    QVERIFY(text.contains(QStringLiteral("Administrator")));
    QVERIFY(text.contains(QStringLiteral("alice")));
    QVERIFY(usersReply.contains(QByteArray::fromHex("f4010000"))); // RID 500
    QVERIFY(usersReply.contains(QByteArray::fromHex("e9030000"))); // RID 1001

    // OpenUser for a known RID succeeds, an unknown one reports no-such-user.
    const QByteArray userReply = server.handleCall(Samr::OpOpenUser,
                                                   openUserStub(domainHandle, 1001));
    QCOMPARE(userReply.size(), 24);
    QCOMPARE(lastWord(userReply), 0u);
    const QByteArray missing = server.handleCall(Samr::OpOpenUser,
                                                 openUserStub(domainHandle, 4242));
    QCOMPARE(lastWord(missing), 0xc0000064u); // STATUS_NO_SUCH_USER

    // QueryInformationUser2, class 6 (Name): a union whose tag is a USHORT and
    // whose arm carries both strings in the deferred area.
    const QByteArray userHandle = userReply.left(20);

    // GetUserPwInfo (44): the domain policy behind the user handle as
    // samr_PwInfo — a referent, the 16-bit minimum length, two bytes of
    // padding, then the 32-bit properties word. A Windows 2000 client asks for
    // this while joining and aborts with "the parameter is incorrect" if the
    // answer is anything less than this whole structure.
    const QByteArray pwInfo = server.handleCall(Samr::OpGetUserPwInfo, userHandle);
    QCOMPARE(pwInfo.size(), 16);
    QCOMPARE(lastWord(pwInfo), 0u);
    // The pointer names the offset of its own data, which is the word behind it.
    // A client resolves it as stub + referent, so a unique-but-wrong value here
    // sends it outside a 16-byte reply and the call fails to unmarshal.
    QCOMPARE(readLe32At(pwInfo, 0), 4u);
    QCOMPARE(quint8(pwInfo.at(4)), quint8(7));  // minPwdLength
    QCOMPARE(quint8(pwInfo.at(5)), quint8(0));
    QCOMPARE(pwInfo.mid(8, 4), QByteArray::fromHex("01000000")); // pwdProperties

    QByteArray nameRequest = userHandle;
    nameRequest.append(char(6));
    nameRequest.append(QByteArray(2, '\0'));
    const QByteArray nameReply =
        server.handleCall(Samr::OpQueryInformationUser2, nameRequest);
    QCOMPARE(lastWord(nameReply), 0u);
    QCOMPARE(readLe32At(nameReply, 0), 4u); // union at the tag that follows it
    QCOMPARE(quint8(nameReply.at(4)), quint8(6)); // tag: SamrUserInformationName
    const QString nameText = utf16Text(nameReply);
    QVERIFY(nameText.contains(QStringLiteral("alice")));
    // QueryInformationUser2, class 21 (all information): the aggregate a
    // property sheet or `net rpc user` fills in one call. Its arm is a fixed
    // 196 bytes (six NTTIMEs, thirteen counted strings, the descriptor and
    // logon-hours pointers, four ULONGs and the flags), then every counted
    // buffer deferred in field order.
    QByteArray allRequest = userHandle;
    allRequest.append(char(21));
    allRequest.append(QByteArray(2, '\0'));
    const QByteArray allReply =
        server.handleCall(Samr::OpQueryInformationUser2, allRequest);
    QCOMPARE(lastWord(allReply), 0u);
    QCOMPARE(readLe32At(allReply, 0), 4u); // union at the tag that follows it
    QCOMPARE(quint8(allReply.at(4)), quint8(21)); // tag: SamrUserAllInformation
    QVERIFY(utf16Text(allReply).contains(QStringLiteral("alice")));
    QVERIFY(allReply.contains(QByteArray::fromHex("e9030000"))); // RID 1001
    // WhichFields sits in the arm after the account flags: every field through
    // CODE_PAGE, including LAST_LOGON and LAST_LOGOFF, whose values the arm
    // carries and whose bits USER_READ_LOGON requires (MS-SAMR 3.1.5.5.5.2).
    // The password-presence and expired-flag bits are not in it: MS-SAMR
    // 3.1.5.5.5 forbids a server from ever returning those.
    QCOMPARE(readLe32At(allReply, 8 + 172), 0x00ffffffu); // fields present
    // acct_flags sits just before WhichFields and speaks SAMR's numbering, not
    // the directory's: this account is NORMAL_ACCOUNT (0x200) in AD and must
    // read ACB_NORMAL (0x10) here, where 0x200 would mean "password does not
    // expire" and 0x10 would mean LOCKOUT in the directory.
    QCOMPARE(readLe32At(allReply, 8 + 168), 0x10u); // acct_flags: ACB_NORMAL
    // A field the mask names present is never a NULL pointer: this account has
    // no home directory, and the arm still carries a buffer for it — a
    // conformant array of no characters, the shape a DC's own answer uses.
    const quint32 homeDirectory = readLe32At(allReply, 8 + 48 + 2 * 8 + 4);
    QVERIFY(homeDirectory != 0);
    QCOMPARE(allReply.mid(int(homeDirectory), 12), QByteArray(12, '\0'));
    // LastLogon, badPwdCount and logonCount are the stored values: the arm is
    // the 196-byte aggregate that starts after the referent and tag.
    QVERIFY(allReply.contains(QByteArray::fromHex("8877665544332211"))); // lastLogon
    QCOMPARE(allReply.mid(8 + 184, 4), QByteArray::fromHex("03000700"));
    // The logon-hours pointer is [size_is(1260), length_is(168/8)]: maximum
    // count 1260, offset 0, twenty-one octets of "every hour allowed".
    QByteArray hours;
    hours.append(QByteArray::fromHex("ec040000")); // 1260
    hours.append(QByteArray::fromHex("00000000")); // offset
    hours.append(QByteArray::fromHex("15000000")); // 21
    hours.append(QByteArray(21, char(0xff)));
    QVERIFY(allReply.contains(hours));
    // And the pointer to that week is where the week is: every pointer in the
    // aggregate named a made-up value (0x0002e1f0 was 188912 in a 470-byte
    // reply), which a 2000 client answered with 124 without reading the record.
    QCOMPARE(readLe32At(allReply, 8 + 180), quint32(allReply.indexOf(hours)));

    // The per-field records a property sheet reads before it opens the
    // aggregate, and the ones `rpcclient queryuser` asks for by number: the
    // general, preferences and logon records, the logon record's predecessor,
    // and the single-field arms. This endpoint used to drop every one of them
    // on the floor with a tag of its own choosing. Samba's NDR decoder pulls
    // all of them, so each arm is pinned here by shape.
    for (int level : {1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 14, 17, 20}) {
        QByteArray request = userHandle;
        request.append(char(level));
        request.append(QByteArray(2, '\0'));
        const QByteArray reply = server.handleCall(Samr::OpQueryInformationUser2, request);
        QCOMPARE(lastWord(reply), 0u);
        QCOMPARE(quint8(reply.at(4)), quint8(level)); // the tag names the class
        // Only the classes that carry a name of some kind report the account's.
        if (level == 1 || level == 3 || level == 5 || level == 7)
            QVERIFY(utf16Text(reply).contains(QStringLiteral("alice")));
    }

    // Class 5 is the logon record's predecessor: two names, the RID and group,
    // six more strings, two instants, the week's length and pointer, the two
    // counters, then the two password instants and the flags. Its 120-byte arm
    // has no padding inside it, because those legacy records carry
    // OLD_LARGE_INTEGER (two ULONGs, four-byte aligned) rather than a hyper;
    // Samba's decoder rejects the reply if a pad is inserted there.
    QByteArray predecessorRequest = userHandle;
    predecessorRequest.append(char(5));
    predecessorRequest.append(QByteArray(2, '\0'));
    const QByteArray predecessorReply =
        server.handleCall(Samr::OpQueryInformationUser2, predecessorRequest);
    QVERIFY(predecessorReply.contains(QByteArray::fromHex("e9030000"))); // RID 1001
    QVERIFY(predecessorReply.size() > 8 + 120 + 4); // arm, then the week
    QByteArray predecessorWeek;
    predecessorWeek.append(QByteArray::fromHex("ec040000")); // 1260
    predecessorWeek.append(QByteArray::fromHex("00000000")); // offset
    predecessorWeek.append(QByteArray::fromHex("15000000")); // 21
    predecessorWeek.append(QByteArray(21, char(0xff)));
    QVERIFY(predecessorReply.contains(predecessorWeek));

    // Class 9 is the primary group on its own, with the same Domain Users
    // fallback the general record applies.
    QByteArray groupRequest = userHandle;
    groupRequest.append(char(9));
    groupRequest.append(QByteArray(2, '\0'));
    const QByteArray groupReply = server.handleCall(Samr::OpQueryInformationUser2, groupRequest);
    QCOMPARE(groupReply.size(), 16);
    QCOMPARE(groupReply.mid(8, 4), QByteArray::fromHex("01020000")); // group 513

    // Class 17 is accountExpires as a bare NTTIME, and zero is the value AD
    // keeps for an account that never expires.
    QByteArray expiryRequest = userHandle;
    expiryRequest.append(char(17));
    expiryRequest.append(QByteArray(2, '\0'));
    const QByteArray expiryReply =
        server.handleCall(Samr::OpQueryInformationUser2, expiryRequest);
    QCOMPARE(expiryReply.size(), 20);
    QCOMPARE(expiryReply.mid(8, 8), QByteArray(8, '\0'));

    // Class 20 is userParameters, unset on this account, so it is answered as
    // the NULL pointer: the lengths are zero and no characters follow.
    QByteArray parametersRequest = userHandle;
    parametersRequest.append(char(20));
    parametersRequest.append(QByteArray(2, '\0'));
    const QByteArray parametersReply =
        server.handleCall(Samr::OpQueryInformationUser2, parametersRequest);
    QCOMPARE(parametersReply.size(), 20);
    QCOMPARE(parametersReply.mid(8, 8), QByteArray(8, '\0'));

    // A class with no arm (18 is the NT one-way function, which this endpoint
    // does not serve) is refused with STATUS_INVALID_INFO_CLASS, and the
    // refusal is the same shape a success has in front of its arm: the reply is
    // `[out,ref,switch_is(level)] samr_UserInfo **info`, so the inner unique
    // pointer is four octets and a refusal sends a null one. A single zero octet
    // there put the status inside the pointer's own four octets, so a client
    // read a non-null pointer with no referent behind it and the call failed to
    // unmarshal — which is what a Windows client reported as a name it could not
    // read, not as an unsupported class.
    QByteArray unsupportedRequest = userHandle;
    unsupportedRequest.append(char(18));
    unsupportedRequest.append(QByteArray(2, '\0'));
    const QByteArray unsupportedReply =
        server.handleCall(Samr::OpQueryInformationUser2, unsupportedRequest);
    QCOMPARE(unsupportedReply, QByteArray::fromHex("00000000030000c0"));
    // The pre-revision form (opnum 36) takes the same arguments and answers the
    // same bytes, which is what a Windows 2000 client calls when it reads an
    // account at the older information levels.
    QByteArray oldFormRequest = userHandle;
    oldFormRequest.append(char(21));
    oldFormRequest.append(QByteArray(2, '\0'));
    QCOMPARE(server.handleCall(Samr::OpQueryInformationUser, oldFormRequest), allReply);
    QByteArray oldFormUnsupported = userHandle;
    oldFormUnsupported.append(char(18));
    oldFormUnsupported.append(QByteArray(2, '\0'));
    QCOMPARE(server.handleCall(Samr::OpQueryInformationUser, oldFormUnsupported),
             QByteArray::fromHex("00000000030000c0"));

    // Class 1: five counted strings around the primary group, which falls back
    // to Domain Users for an account that names none.
    QByteArray generalRequest = userHandle;
    generalRequest.append(char(1));
    generalRequest.append(QByteArray(2, '\0'));
    const QByteArray generalReply =
        server.handleCall(Samr::OpQueryInformationUser2, generalRequest);
    QCOMPARE(generalReply.mid(8 + 16, 4), QByteArray::fromHex("01020000")); // group 513

    // Class 2: the user's comment, then the string AD accepts and never stores
    // — answered as the NULL pointer, so no characters follow it.
    QByteArray preferencesRequest = userHandle;
    preferencesRequest.append(char(2));
    preferencesRequest.append(QByteArray(2, '\0'));
    const QByteArray preferencesReply =
        server.handleCall(Samr::OpQueryInformationUser2, preferencesRequest);
    QCOMPARE(preferencesReply.mid(8 + 8 + 4, 4), QByteArray::fromHex("00000000"));

    // Class 3: the logon record. Its fixed part is 120 bytes — nine counted
    // strings, the RID and group, five NTTIMEs, the week's length and pointer,
    // the two counters and the flags — with the week behind it.
    QByteArray logonRequest = userHandle;
    logonRequest.append(char(3));
    logonRequest.append(QByteArray(2, '\0'));
    const QByteArray logonReply = server.handleCall(Samr::OpQueryInformationUser2, logonRequest);
    QVERIFY(logonReply.contains(QByteArray::fromHex("e9030000"))); // RID 1001
    QVERIFY(logonReply.size() > 8 + 120 + 4);                       // arm, then buffers
    QByteArray week;
    week.append(QByteArray::fromHex("ec040000")); // 1260
    week.append(QByteArray::fromHex("00000000")); // offset
    week.append(QByteArray::fromHex("15000000")); // 21
    week.append(QByteArray(21, char(0xff)));
    QVERIFY(logonReply.contains(week));

    // A class this server does not implement is refused, not faked.
    QByteArray otherClass = userHandle;
    otherClass.append(char(23)); // SamrUserInternal4Information
    otherClass.append(QByteArray(2, '\0'));
    QCOMPARE(lastWord(server.handleCall(Samr::OpQueryInformationUser2, otherClass)),
             0xc0000003u); // STATUS_INVALID_INFO_CLASS

    // LookupNamesInDomain: names to RIDs, with the SID_NAME_USE of each.
    const QByteArray namesReply = server.handleCall(
        Samr::OpLookupNamesInDomain,
        lookupNamesStub(domainHandle, {QStringLiteral("alice"), QStringLiteral("Administrator")}));
    QCOMPARE(lastWord(namesReply), 0u);
    int pos = 0;
    QList<quint32> rids;
    QList<quint32> types;
    QVERIFY(readIdArray(namesReply, &pos, &rids));
    QVERIFY(readIdArray(namesReply, &pos, &types));
    QCOMPARE(rids, (QList<quint32>{1001, 500}));
    QCOMPARE(types, (QList<quint32>{1, 1})); // SidTypeUser
    QCOMPARE(pos + 4, int(namesReply.size())); // the status word closes the reply

    // A name nobody has is reported as unmapped rather than translated.
    const QByteArray partial = server.handleCall(
        Samr::OpLookupNamesInDomain,
        lookupNamesStub(domainHandle, {QStringLiteral("alice"), QStringLiteral("nosuch")}));
    QCOMPARE(lastWord(partial), 0x00000107u); // STATUS_SOME_NOT_MAPPED
    pos = 0;
    QVERIFY(readIdArray(partial, &pos, &rids));
    QCOMPARE(rids, (QList<quint32>{1001, 0}));
    // Nothing mapped means no array at all: an answer with one element of RID 0
    // reads as a mapped name with no account, and a 2000 client replied to that
    // with 124 instead of "not found".
    const QByteArray noneMapped = server.handleCall(
        Samr::OpLookupNamesInDomain, lookupNamesStub(domainHandle, {QStringLiteral("nosuch")}));
    QCOMPARE(lastWord(noneMapped), 0xc0000073u); // STATUS_NONE_MAPPED
    QCOMPARE(noneMapped.left(16), QByteArray(16, '\0'));
    QCOMPARE(noneMapped.size(), 20);

    // LookupIdsInDomain is the inverse mapping, RIDs to account names.
    const QByteArray idsReply = server.handleCall(
        Samr::OpLookupIdsInDomain, lookupIdsStub(domainHandle, {1001, 500}));
    QCOMPARE(lastWord(idsReply), 0u);
    const QString idText = utf16Text(idsReply);
    QVERIFY(idText.contains(QStringLiteral("alice")));
    QVERIFY(idText.contains(QStringLiteral("Administrator")));
    QCOMPARE(lastWord(server.handleCall(Samr::OpLookupIdsInDomain,
                                        lookupIdsStub(domainHandle, {4242}))),
             0xc0000073u); // STATUS_NONE_MAPPED
    QCOMPARE(lastWord(server.handleCall(Samr::OpLookupIdsInDomain,
                                        lookupIdsStub(domainHandle, {1001, 4242}))),
             0x00000107u); // STATUS_SOME_NOT_MAPPED

    // A machine account carries SidTypeComputer (9) in both directions. It used
    // to be answered 8, SidTypeUnknown: the one value that says nothing about a
    // name the lookup had just mapped, and a different answer for the same
    // account than LsaLookupNames gives over LSAD.
    const QByteArray machineNames = server.handleCall(
        Samr::OpLookupNamesInDomain, lookupNamesStub(domainHandle, {QStringLiteral("WS01$")}));
    QCOMPARE(lastWord(machineNames), 0u);
    pos = 0;
    QVERIFY(readIdArray(machineNames, &pos, &rids));
    QVERIFY(readIdArray(machineNames, &pos, &types));
    QCOMPARE(rids, (QList<quint32>{2001}));
    QCOMPARE(types, (QList<quint32>{9})); // SidTypeComputer
    const QByteArray machineIds =
        server.handleCall(Samr::OpLookupIdsInDomain, lookupIdsStub(domainHandle, {2001}));
    QCOMPARE(lastWord(machineIds), 0u);
    // The types array closes the answer: count, pointer, maximum, value, status.
    // The pointer names the array by its offset in this reply, the byte the
    // maximum count starts at, which is what a client resolves it with.
    const int typesAt = int(machineIds.size()) - 20;
    QVERIFY(typesAt > 0);
    QCOMPARE(readLe32At(machineIds, typesAt), 1u);     // Count
    QCOMPARE(readLe32At(machineIds, typesAt + 4), quint32(typesAt + 8));
    QCOMPARE(readLe32At(machineIds, typesAt + 8), 1u); // MaximumCount
    QCOMPARE(readLe32At(machineIds, typesAt + 12), 9u); // SidTypeComputer

    // CloseHandle releases the context.
    QByteArray closeRequest = userHandle;
    closeRequest.append(QByteArray(4, '\0'));
    QCOMPARE(lastWord(server.handleCall(Samr::OpCloseHandle, closeRequest)), 0u);
    // ...and the handle no longer resolves.
    QCOMPARE(lastWord(server.handleCall(Samr::OpQueryInformationUser2, nameRequest)),
             0xc0000008u); // STATUS_INVALID_HANDLE

    // A stale handle is refused rather than trusted.
    const QByteArray stale = server.handleCall(Samr::OpEnumerateUsersInDomain,
                                               enumUsersStub(QByteArray(20, '\x7f')));
    QCOMPARE(lastWord(stale), 0xc0000008u); // STATUS_INVALID_HANDLE
}

// BUILTIN (S-1-5-32) is the second domain a DC reports: its well-known aliases
// are not in the account NC, so SAMR derives them, and every write to them is
// refused rather than accepted and dropped.
void SamrTest::samrServesTheBuiltinDomain()
{
    QList<DirectoryObject> objects;
    DirectoryObject admins;
    admins.id = QStringLiteral("CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com");
    admins.name = QStringLiteral("Domain Admins");
    admins.type = QStringLiteral("Group");
    admins.kind = ObjectKind::Group;
    admins.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("Domain Admins"));
    admins.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-512"));
    admins.attributes.insert(QStringLiteral("groupType"), QStringLiteral("-2147483646"));
    objects.append(admins);

    DirectoryObject domainObject;
    domainObject.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domainObject.name = QStringLiteral("CORP");
    domainObject.type = QStringLiteral("domainDNS");
    domainObject.kind = ObjectKind::Domain;
    domainObject.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));
    objects.append(domainObject);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([objects]() { return objects; });

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);

    // Both domains come back in one page, BUILTIN first as AD lists it.
    const QByteArray domains =
        server.handleCall(Samr::OpEnumerateDomainsInSamServer, enumDomainsStub(serverHandle));
    QCOMPARE(lastWord(domains), 0u);
    QCOMPARE(readLe32At(domains, 8), 2u); // CountReturned
    const QString domainText = utf16Text(domains);
    QVERIFY(domainText.contains(QStringLiteral("Builtin")));
    QVERIFY(domainText.contains(QStringLiteral("CORP")));

    // Its SID is the well-known one, and that SID opens it by name or directly.
    const QByteArray builtinSid = Ndr::sidFromString(QStringLiteral("S-1-5-32"));
    const QByteArray lookup = server.handleCall(
        Samr::OpLookupDomainInSamServer,
        lookupDomainStubFor(serverHandle, QStringLiteral("Builtin")));
    QCOMPARE(lastWord(lookup), 0u);
    QVERIFY(lookup.contains(builtinSid));
    const QByteArray open = server.handleCall(
        Samr::OpOpenDomain, openDomainStubFor(serverHandle, QStringLiteral("S-1-5-32")));
    QCOMPARE(open.size(), 24);
    QCOMPARE(lastWord(open), 0u);
    const QByteArray builtinHandle = open.left(20);

    // The alias table, and none of the account domain's groups or accounts.
    const QByteArray aliases =
        server.handleCall(Samr::OpEnumerateAliasesInDomain, enumAliasesStub(builtinHandle));
    QCOMPARE(lastWord(aliases), 0u);
    QCOMPARE(readLe32At(aliases, 8), 16u); // CountReturned
    QVERIFY(utf16Text(aliases).contains(QStringLiteral("Administrators")));
    QCOMPARE(readLe32At(server.handleCall(Samr::OpEnumerateGroupsInDomain,
                                          enumUsersStub(builtinHandle)),
                        8),
             0u);
    QCOMPARE(readLe32At(server.handleCall(Samr::OpEnumerateUsersInDomain,
                                          enumUsersStub(builtinHandle)),
                        8),
             0u);

    // Names and RIDs round-trip inside BUILTIN, with SidTypeAlias.
    const QByteArray namesReply = server.handleCall(
        Samr::OpLookupNamesInDomain,
        lookupNamesStub(builtinHandle, {QStringLiteral("Administrators")}));
    QCOMPARE(lastWord(namesReply), 0u);
    int pos = 0;
    QList<quint32> rids;
    QList<quint32> types;
    QVERIFY(readIdArray(namesReply, &pos, &rids));
    QVERIFY(readIdArray(namesReply, &pos, &types));
    QCOMPARE(rids, (QList<quint32>{544}));
    QCOMPARE(types, (QList<quint32>{4})); // SidTypeAlias
    const QByteArray idsReply =
        server.handleCall(Samr::OpLookupIdsInDomain, lookupIdsStub(builtinHandle, {545}));
    QCOMPARE(lastWord(idsReply), 0u);
    QVERIFY(utf16Text(idsReply).contains(QStringLiteral("Users")));

    // OpenAlias, the general information and the membership AD seeds: the
    // Administrators alias holds the domain's Domain Admins group.
    const QByteArray aliasReply =
        server.handleCall(Samr::OpOpenAlias, openUserStub(builtinHandle, 544));
    QCOMPARE(aliasReply.size(), 24);
    QCOMPARE(lastWord(aliasReply), 0u);
    const QByteArray aliasHandle = aliasReply.left(20);
    const QByteArray general =
        server.handleCall(Samr::OpQueryInformationAlias, queryAliasStub(aliasHandle, 1));
    QCOMPARE(lastWord(general), 0u);
    QVERIFY(utf16Text(general).contains(QStringLiteral("Administrators")));
    const QByteArray members = server.handleCall(Samr::OpGetMembersInAlias, aliasHandle);
    QCOMPARE(lastWord(members), 0u);
    QCOMPARE(readLe32At(members, 0), 1u);
    QVERIFY(members.contains(Ndr::sidFromString(QStringLiteral("S-1-5-21-1-2-3-512"))));

    // Everything that would write is refused: there is nowhere to persist a
    // BUILTIN write, so accepting it would lose the change.
    const QByteArray memberSid = Ndr::sidFromString(QStringLiteral("S-1-5-21-1-2-3-1001"));
    QCOMPARE(lastWord(server.handleCall(Samr::OpAddMemberToAlias,
                                        aliasMemberStub(aliasHandle, memberSid))),
             0xc00000bbu); // STATUS_NOT_SUPPORTED
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationAlias,
                                        aliasHandle + QByteArray::fromHex("03000300"))),
             0xc00000bbu);
    QCOMPARE(lastWord(server.handleCall(Samr::OpDeleteAlias, aliasHandle)), 0xc00000bbu);
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpCreateAliasInDomain,
                 createStub(builtinHandle, QStringLiteral("not-here"), false))),
             0xc00000bbu);
}

void SamrTest::samrWritesAccountsAndGroups()
{
    QList<DirectoryObject> store;
    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    Samr::WriteBackend backend;
    backend.create = [&store](DirectoryObject *object, QString *error) {
        const QString account = object->attributes.value(QStringLiteral("sAMAccountName"));
        for (const DirectoryObject &existing : store) {
            if (existing.attributes.value(QStringLiteral("sAMAccountName"))
                    .compare(account, Qt::CaseInsensitive) == 0) {
                if (error)
                    *error = QStringLiteral("exists");
                return false;
            }
        }
        quint32 rid = 1000;
        for (const DirectoryObject &existing : store) {
            const QStringList parts = existing.attributes.value(QStringLiteral("objectSid"))
                                          .split(QLatin1Char('-'));
            if (parts.size() == 8)
                rid = qMax(rid, parts.last().toUInt());
        }
        object->attributes.insert(QStringLiteral("objectSid"),
                                  QStringLiteral("S-1-5-21-1-2-3-%1").arg(rid + 1));
        store.append(*object);
        return true;
    };
    backend.remove = [&store](const QString &dn, QString *) {
        for (int i = 0; i < store.size(); ++i) {
            if (store.at(i).id.compare(dn, Qt::CaseInsensitive) == 0) {
                store.removeAt(i);
                return true;
            }
        }
        return false;
    };
    backend.addMember = [&store](const QString &groupDn, const QString &memberDn, QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(groupDn, Qt::CaseInsensitive) == 0) {
                if (!object.members.contains(memberDn, Qt::CaseInsensitive))
                    object.members.append(memberDn);
                return true;
            }
        }
        return false;
    };
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0) {
                object.attributes.insert(attribute, value);
                return true;
            }
        }
        return false;
    };
    backend.removeMember = [&store](const QString &groupDn, const QString &memberDn, QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(groupDn, Qt::CaseInsensitive) == 0) {
                object.members.removeAll(memberDn);
                return true;
            }
        }
        return false;
    };
    server.setWriteBackend(backend);

    const QByteArray connectReply = server.handleCall(Samr::OpConnect, kConnect);
    const QByteArray serverHandle = connectReply.left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);
    QVERIFY(domainHandle.size() == 20);

    // A user is created with the next relative id, and the handle it returns
    // resolves back to that account.
    const QByteArray userReply = server.handleCall(Samr::OpCreateUser2,
                                                   createStub(domainHandle,
                                                              QStringLiteral("gina"), true));
    QCOMPARE(userReply.size(), 32);
    QCOMPARE(lastWord(userReply), 0u);
    QCOMPARE(readLe32At(userReply, 24), 1001u); // RelativeId
    const QByteArray userHandle = userReply.left(20);
    QCOMPARE(store.size(), 1);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("objectSid")),
             QStringLiteral("S-1-5-21-1-2-3-1001"));
    // USER_NORMAL_ACCOUNT on the wire (0x10) is NORMAL_ACCOUNT in the directory
    // (0x200), and it stays a user in CN=Users.
    QCOMPARE(store.at(0).kind, ObjectKind::User);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("512"));

    // Opening the same account by RID works, and its name arm reports it.
    const QByteArray reopened = server.handleCall(Samr::OpOpenUser,
                                                 openUserStub(domainHandle, 1001));
    QCOMPARE(lastWord(reopened), 0u);

    // A group, then membership in both directions.
    const QByteArray groupReply = server.handleCall(Samr::OpCreateGroupInDomain,
                                                    createStub(domainHandle,
                                                               QStringLiteral("staff"), false));
    QCOMPARE(groupReply.size(), 28);
    QCOMPARE(lastWord(groupReply), 0u);
    const quint32 groupRid = readLe32At(groupReply, 20);
    QCOMPARE(groupRid, 1002u);

    QByteArray openGroup = domainHandle;
    appendLe32(openGroup, 0x000f001fu);
    appendLe32(openGroup, groupRid);
    const QByteArray groupHandleReply = server.handleCall(Samr::OpOpenGroup, openGroup);
    QCOMPARE(lastWord(groupHandleReply), 0u);
    const QByteArray groupHandle = groupHandleReply.left(20);

    QByteArray addMember = groupHandle;
    appendLe32(addMember, 1001);
    appendLe32(addMember, 0);
    QCOMPARE(lastWord(server.handleCall(Samr::OpAddMemberToGroup, addMember)), 0u);

    const QByteArray members =
        server.handleCall(Samr::OpGetMembersInGroup, groupHandle);
    QCOMPARE(lastWord(members), 0u);
    QCOMPARE(readLe32At(members, 4), 1u);          // MemberCount
    QCOMPARE(readLe32At(members, 20), 1001u);      // the member's RID

    // SamrRemoveMemberFromForeignDomain names the member by SID and takes it out
    // of every group in the domain. A Windows 2000 client calls it on the way to
    // deleting an account — `net user TMPCD$ /delete /domain` issues it and only
    // then SamrDeleteUser — and with no arm this was answered NOT_SUPPORTED, so
    // the client closed the connection and printed "System error 50" without
    // ever asking for the delete.
    QByteArray removeForeign = domainHandle;
    appendLe32(removeForeign, 5); // sub-authority count, as a conformant array length
    removeForeign.append(QByteArray::fromHex("0105000000000005"));
    for (quint32 sub : {21u, 1u, 2u, 3u, 1001u})
        appendLe32(removeForeign, sub);
    QCOMPARE(lastWord(server.handleCall(Samr::OpRemoveMemberFromForeignDomain,
                                        removeForeign)),
             0u);
    QCOMPARE(readLe32At(server.handleCall(Samr::OpGetMembersInGroup, groupHandle), 4), 0u);
    // A SID no object carries has nothing to take away and is not an error the
    // client's delete path can act on.
    QByteArray unknownMember = domainHandle;
    appendLe32(unknownMember, 5);
    unknownMember.append(QByteArray::fromHex("0105000000000005"));
    for (quint32 sub : {21u, 1u, 2u, 3u, 4242u})
        appendLe32(unknownMember, sub);
    QCOMPARE(lastWord(server.handleCall(Samr::OpRemoveMemberFromForeignDomain,
                                       unknownMember)),
             0u);
    // The membership is put back so the rest of this test measures what it did
    // before.
    QCOMPARE(lastWord(server.handleCall(Samr::OpAddMemberToGroup, addMember)), 0u);

    // An alias is a domain-local group: the same object kind, told apart by
    // groupType, and it takes its members as SIDs rather than RIDs.
    const QByteArray aliasReply = server.handleCall(Samr::OpCreateAliasInDomain,
                                                    createStub(domainHandle,
                                                               QStringLiteral("engineers"), false));
    QCOMPARE(aliasReply.size(), 28);
    QCOMPARE(lastWord(aliasReply), 0u);
    const quint32 aliasRid = readLe32At(aliasReply, 20);
    QCOMPARE(aliasRid, 1003u);
    QCOMPARE(store.size(), 3);
    QCOMPARE(store.last().attributes.value(QStringLiteral("groupType")),
             QStringLiteral("-2147483644"));

    // The two enumerations each see their own objects: the alias is in one and
    // not the other, and the group still is a group.
    const QByteArray aliasPage =
        server.handleCall(Samr::OpEnumerateAliasesInDomain,
                          domainHandle + QByteArray::fromHex("00000000ffffffff"));
    QCOMPARE(lastWord(aliasPage), 0u);
    QCOMPARE(readLe32At(aliasPage, 8), 1u); // EntriesRead
    QVERIFY(aliasPage.contains(Ndr::utf16le(QStringLiteral("engineers"))));
    const QByteArray groupPage =
        server.handleCall(Samr::OpEnumerateGroupsInDomain,
                          domainHandle + QByteArray::fromHex("0000000000000000ffffffff"));
    QCOMPARE(lastWord(groupPage), 0u);
    QVERIFY(!groupPage.contains(Ndr::utf16le(QStringLiteral("engineers"))));
    QVERIFY(groupPage.contains(Ndr::utf16le(QStringLiteral("staff"))));

    QByteArray openAlias = domainHandle;
    appendLe32(openAlias, 0x000f001fu);
    appendLe32(openAlias, aliasRid);
    const QByteArray aliasHandleReply = server.handleCall(Samr::OpOpenAlias, openAlias);
    QCOMPARE(lastWord(aliasHandleReply), 0u);
    const QByteArray aliasHandle = aliasHandleReply.left(20);

    // The member SID on this wire: the sub-authority count is a conformant
    // array length and comes before the header.
    QByteArray aliasMemberSid;
    appendLe32(aliasMemberSid, 5);
    aliasMemberSid.append(QByteArray::fromHex("0105000000000005"));
    for (quint32 sub : {21u, 1u, 2u, 3u, 1001u})
        appendLe32(aliasMemberSid, sub);

    QCOMPARE(lastWord(server.handleCall(Samr::OpAddMemberToAlias,
                                        aliasHandle + aliasMemberSid)),
             0u);

    const QByteArray aliasMembers = server.handleCall(Samr::OpGetMembersInAlias, aliasHandle);
    QCOMPARE(lastWord(aliasMembers), 0u);
    QCOMPARE(readLe32At(aliasMembers, 0), 1u); // Count
    QVERIFY(aliasMembers.contains(QByteArray::fromHex("e9030000"))); // rid 1001

    // The general arm carries the name, the member count and the comment; the
    // union is behind a pointer, so a referent comes first.
    const QByteArray aliasGeneral =
        server.handleCall(Samr::OpQueryInformationAlias,
                          aliasHandle + QByteArray::fromHex("0100"));
    QCOMPARE(lastWord(aliasGeneral), 0u);
    QCOMPARE(readLe32At(aliasGeneral, 16), 1u); // MemberCount

    // The administrative comment is a directory attribute.
    QByteArray setAlias = aliasHandle;
    setAlias.append(QByteArray::fromHex("03000300"));
    const QByteArray comment = Ndr::utf16le(QStringLiteral("Domain engineers"));
    setAlias.append(char(comment.size() & 0xff));
    setAlias.append(char((comment.size() >> 8) & 0xff));
    setAlias.append(char(comment.size() & 0xff));
    setAlias.append(char((comment.size() >> 8) & 0xff));
    appendLe32(setAlias, 0x00027000u);
    appendVaryingString(setAlias, QStringLiteral("Domain engineers"));
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationAlias, setAlias)), 0u);
    QCOMPARE(store.last().attributes.value(QStringLiteral("description")),
             QStringLiteral("Domain engineers"));

    // Membership comes back off again, and the alias is deleted like a group.
    QCOMPARE(lastWord(server.handleCall(Samr::OpRemoveMemberFromAlias,
                                        aliasHandle + aliasMemberSid)),
             0u);
    QCOMPARE(readLe32At(server.handleCall(Samr::OpGetMembersInAlias, aliasHandle), 0), 0u);
    QCOMPARE(lastWord(server.handleCall(Samr::OpDeleteAlias, aliasHandle)), 0u);
    QCOMPARE(store.size(), 2);

    // Deleting the account removes it from the store, and its handle dies.
    QCOMPARE(lastWord(server.handleCall(Samr::OpDeleteUser, userHandle)), 0u);
    QCOMPARE(store.size(), 1); // only the group is left
    QCOMPARE(store.at(0).kind, ObjectKind::Group);
    QCOMPARE(lastWord(server.handleCall(Samr::OpQueryInformationUser2,
                                        userHandle + QByteArray::fromHex("06000000"))),
             0xc0000008u); // STATUS_INVALID_HANDLE

    // A machine account's own service principal names are written when the
    // account is created. A Windows join does not write them afterwards, and
    // its first logon asks the KDC for HOST/<name>; without them the TGT is
    // issued and the next request is answered S_PRINCIPAL_UNKNOWN.
    //
    // It is also a `computer`, not a user: the account type on the wire is
    // 0x80 (workstation trust), which is userAccountControl 0x1000, and AD
    // keeps it in CN=Computers under Domain Computers. Copying the wire value
    // across would store 0x80, which means PASSWD_NOTREQD.
    const QByteArray machineReply = server.handleCall(
        Samr::OpCreateUser2,
        createStub(domainHandle, QStringLiteral("NEURALNODE0$"), true, 0x80));
    QCOMPARE(lastWord(machineReply), 0u);
    const DirectoryObject &machine = store.last();
    QCOMPARE(machine.kind, ObjectKind::Computer);
    QCOMPARE(machine.container, QStringLiteral("CN=Computers,DC=corp,DC=example,DC=com"));
    QCOMPARE(machine.id, QStringLiteral("CN=NEURALNODE0$,CN=Computers,DC=corp,DC=example,DC=com"));
    QCOMPARE(machine.attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("4096"));
    QCOMPARE(machine.attributes.value(QStringLiteral("primaryGroupID")), QStringLiteral("515"));
    QCOMPARE(machine.attributes.value(QStringLiteral("dNSHostName")),
             QStringLiteral("neuralnode0.corp.example.com"));
    QVERIFY(machine.attributes.value(QStringLiteral("objectClass"))
                .contains(QStringLiteral("computer")));
    const QString machineSpns =
        store.last().attributes.value(QStringLiteral("servicePrincipalName"));
    QVERIFY(machineSpns.contains(QStringLiteral("HOST/NEURALNODE0")));
    QVERIFY(machineSpns.contains(QStringLiteral("HOST/neuralnode0.corp.example.com")));
    QVERIFY(machineSpns.contains(QStringLiteral("RestrictedKrbHost/neuralnode0.corp.example.com")));
}

// The write path ADUC and `net rpc` use once an account exists: account flags,
// the descriptive strings, and the password buffer that is ciphered under the
// RPC session key rather than sent in the clear.
void SamrTest::samrSetPasswordAndAccountControl()
{
    QList<DirectoryObject> store;
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("objectSid"),
                            QStringLiteral("S-1-5-21-1-2-3-1001"));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    alice.attributes.insert(QStringLiteral("displayName"), QStringLiteral("alice"));
    store.append(alice);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    QString lastPassword;
    Samr::WriteBackend backend;
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) != 0)
                continue;
            object.attributes.insert(attribute, value);
            if (attribute == QLatin1String("displayName"))
                object.name = value;
            return true;
        }
        return false;
    };
    // Stands in for the directory's password path: the real one enforces the
    // domain policy and stores the NTLM hash, the Kerberos keys and the
    // simple-bind verifier together.
    backend.setPassword = [&lastPassword](const QString &, const QString &password,
                                          QString *error) {
        lastPassword = password;
        if (password.size() < 8) {
            if (error)
                *error = QStringLiteral("too short");
            return false;
        }
        return true;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);
    const QByteArray userHandle =
        server.handleCall(Samr::OpOpenUser, openUserStub(domainHandle, 1001)).left(20);

    // Account flags: ACB_DISABLED | ACB_NORMAL (0x11) disables the account, and
    // reaches the directory as ACCOUNTDISABLE | NORMAL_ACCOUNT (514).
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2, controlStub(userHandle))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("514"));

    // ...and reading the same class back reports what was written.
    QByteArray query = userHandle;
    query.append(char(16));
    query.append(QByteArray(3, '\0'));
    const QByteArray queryReply = server.handleCall(Samr::OpQueryInformationUser2, query);
    QCOMPARE(lastWord(queryReply), 0u);
    QCOMPARE(quint8(queryReply.at(4)), quint8(16)); // tag: SamrUserControlInformation
    QCOMPARE(readLe32At(queryReply, 8), 0x11u); // acct_flags, not the directory bits

    // The full name follows the same string layout the query uses.
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 fullNameStub(userHandle, QStringLiteral("Gina Walker")))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Gina Walker"));

    // Classes 1, 2 and 3 are written back whole: each counted string's tuple is
    // inline and its characters deferred, so the reader has to walk both passes
    // to find them.
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 generalRecordStub(userHandle, QStringLiteral("walker"),
                                   QStringLiteral("Gina Walker"), 513,
                                   QStringLiteral("in the office"),
                                   QStringLiteral("night shift")))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("sAMAccountName")),
             QStringLiteral("walker"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Gina Walker"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("primaryGroupID")), QStringLiteral("513"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("description")),
             QStringLiteral("in the office"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("comment")),
             QStringLiteral("night shift"));

    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2,
                                        preferencesStub(userHandle,
                                                        QStringLiteral("day shift"), 39, 850))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("comment")),
             QStringLiteral("day shift"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("countryCode")), QStringLiteral("39"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("codePage")), QStringLiteral("850"));

    const QByteArray week = QByteArray::fromHex("00000000000000000000ffffffffffffffffffffff");
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 logonRecordStub(userHandle, QStringLiteral("walker"),
                                 QStringLiteral("Gina W"), 513,
                                 QStringLiteral("\\\\srv\\home\\walker"),
                                 QStringLiteral("H:"), QStringLiteral("logon.bat"),
                                 QStringLiteral("\\\\srv\\profiles\\walker"),
                                 QStringLiteral("WKS01,WKS02"), week))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("homeDirectory")),
             QStringLiteral("\\\\srv\\home\\walker"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("homeDrive")), QStringLiteral("H:"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("scriptPath")),
             QStringLiteral("logon.bat"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("userWorkstations")),
             QStringLiteral("WKS01,WKS02"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("logonHours")),
             QString::fromLatin1(week.toHex()));
    // The RID and the account flags are the DC's, so the record that carries them
    // does not overwrite either.
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("514"));

    // A record cut short is refused rather than half-applied.
    QByteArray shortLogon = logonRecordStub(userHandle, QStringLiteral("walker"),
                                            QStringLiteral("Gina W"), 513, QString(),
                                            QString(), QString(), QString(), QString(), week);
    shortLogon.chop(24);
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2, shortLogon)),
             0xc000000du); // STATUS_INVALID_PARAMETER

    // A password set: class 24 ciphers 516 bytes under the session key alone.
    const QByteArray sessionKey = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 cryptPasswordStub(userHandle, 24, QStringLiteral("Str0ngPass!23"), sessionKey),
                 sessionKey)),
             0u);
    QCOMPARE(lastPassword, QStringLiteral("Str0ngPass!23"));

    // Class 26 carries a confounder and keys the cipher with MD5 over it.
    lastPassword.clear();
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 cryptPasswordStub(userHandle, 26, QStringLiteral("An0ther!Pass"), sessionKey),
                 sessionKey)),
             0u);
    QCOMPARE(lastPassword, QStringLiteral("An0ther!Pass"));

    // Without the session key the buffer cannot be opened, so nothing is set.
    lastPassword.clear();
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 cryptPasswordStub(userHandle, 24, QStringLiteral("Str0ngPass!23"), sessionKey))),
             0xc000000du); // STATUS_INVALID_PARAMETER
    QVERIFY(lastPassword.isEmpty());

    // A password the policy rejects is reported as such, not as success.
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 cryptPasswordStub(userHandle, 24, QStringLiteral("short"), sessionKey),
                 sessionKey)),
             0xc000006cu); // STATUS_PASSWORD_RESTRICTION

    // A class this server does not write is refused rather than half-applied.
    QByteArray unsupported = userHandle;
    unsupported.append(QByteArray::fromHex("1e001e00")); // SamprUserResetInformation
    unsupported.append(QByteArray(84, '\0'));
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2, unsupported)),
             0xc0000003u); // STATUS_INVALID_INFO_CLASS

    // A stale handle is refused before anything is written.
    QByteArray stale = QByteArray(20, '\x7f');
    stale.append(QByteArray::fromHex("10001000"));
    stale.append(QByteArray::fromHex("02020000"));
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2, stale)),
             0xc0000008u); // STATUS_INVALID_HANDLE
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("514"));
}

// DES is the one primitive AD still relies on for password encoding; the FIPS
// vectors pin the whole implementation, not just the encoding on top of it.
void SamrTest::desPrimitivesAndHashEncoding()
{
    const QByteArray key = QByteArray::fromHex("133457799BBCDFF1");
    const QByteArray block = QByteArray::fromHex("0123456789ABCDEF");
    QCOMPARE(Des::encryptBlock(key, block),
             QByteArray::fromHex("85E813540F0AB405"));
    QCOMPARE(Des::decryptBlock(key, QByteArray::fromHex("85E813540F0AB405")), block);

    const QByteArray key2 = QByteArray::fromHex("0123456789ABCDEF");
    QCOMPARE(Des::encryptBlock(key2, QByteArray::fromHex("4E6F772069732074")),
             QByteArray::fromHex("3FA40E8A984D4815"));

    // The seven-byte key schedule and the two-block OWF encoding, checked
    // against impacket's transformKey / SamEncryptNTLMHash.
    const QByteArray sessionKey = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    QCOMPARE(Des::keyFromPassword(sessionKey.left(7)),
             QByteArray::fromHex("00084846342254cc"));
    const QByteArray hash = QByteArray::fromHex("5f695b7f2516dd9281fd2da14dcfdd81");
    const QByteArray encoded = Des::encryptOwfHash(hash, sessionKey);
    QCOMPARE(encoded, QByteArray::fromHex("d8cfce4f4bea435146c0efce61f7410a"));
    QCOMPARE(Des::decryptOwfHash(encoded, sessionKey), hash);
}

// SamrSetInformationUser, class 18: the NT hash arrives DES-enciphered under the
// session key and becomes the account's credential of record.
void SamrTest::samrSetsCredentialFromHash()
{
    QList<DirectoryObject> store;
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("objectSid"),
                            QStringLiteral("S-1-5-21-1-2-3-1001"));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    // A credential from an earlier password, which the hash set has to displace.
    alice.attributes.insert(QStringLiteral("userPasswordSalt"), QStringLiteral("aabb"));
    alice.attributes.insert(QStringLiteral("userPasswordHash"), QStringLiteral("ccdd"));
    alice.attributes.insert(QStringLiteral("aes256Key"), QStringLiteral("eeff"));
    alice.attributes.insert(QStringLiteral("ntHash"), QStringLiteral("00"));
    store.append(alice);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    QByteArray receivedHash;
    Samr::WriteBackend backend;
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0) {
                object.attributes.insert(attribute, value);
                return true;
            }
        }
        return false;
    };
    bool refuseHash = false;
    backend.setNtHash = [&store, &receivedHash, &refuseHash](const QString &dn,
                                                             const QByteArray &hash,
                                                             QString *) {
        // The store's own policy: a hash it has seen before is refused, the way
        // the password history refuses it on the live DC.
        if (refuseHash)
            return false;
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) != 0)
                continue;
            for (const QString &stale : {QStringLiteral("userPasswordSalt"),
                                         QStringLiteral("userPasswordHash"),
                                         QStringLiteral("aes256Key")})
                object.attributes.remove(stale);
            receivedHash = hash;
            object.attributes.insert(QStringLiteral("ntHash"),
                                     QString::fromLatin1(hash.toHex()));
            object.attributes.insert(QStringLiteral("pwdLastSet"), QStringLiteral("1792568173"));
            return true;
        }
        return false;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);
    const QByteArray userHandle =
        server.handleCall(Samr::OpOpenUser, openUserStub(domainHandle, 1001)).left(20);

    const QByteArray sessionKey = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    const QByteArray ntHash = QByteArray::fromHex("5f695b7f2516dd9281fd2da14dcfdd81");

    // Without the session key the enciphered hash cannot be opened.
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser,
                                        internal1Stub(userHandle, ntHash, sessionKey))),
             0xc000000du); // STATUS_INVALID_PARAMETER
    QVERIFY(receivedHash.isEmpty());

    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser,
                                        internal1Stub(userHandle, ntHash, sessionKey),
                                        sessionKey)),
             0u);
    QCOMPARE(receivedHash, ntHash);
    // The stale verifier is gone, so the previous password cannot still bind.
    QVERIFY(!store.at(0).attributes.contains(QStringLiteral("userPasswordSalt")));
    QVERIFY(!store.at(0).attributes.contains(QStringLiteral("aes256Key")));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("ntHash")),
             QString::fromLatin1(ntHash.toHex()));
    QVERIFY(store.at(0).attributes.value(QStringLiteral("pwdLastSet")) != QStringLiteral("0"));

    // PasswordExpired stamps pwdLastSet 0 for "change at next logon".
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser,
                                        internal1Stub(userHandle, ntHash, sessionKey, true),
                                        sessionKey)),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("pwdLastSet")), QStringLiteral("0"));

    // A hash the store refuses is a policy refusal, not a verdict on the
    // caller's rights: a client that sends the password as a hash has to read
    // the same word a client that sends it ciphered reads, or an operator is
    // told "access denied" about a password the policy rejected.
    refuseHash = true;
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser,
                                        internal1Stub(userHandle, ntHash, sessionKey),
                                        sessionKey)),
             0xc000006cu); // STATUS_PASSWORD_RESTRICTION
}

// SamrSetInformationUser2 class 21 is the call ADUC's "new user" dialog makes:
// one SAMPR_USER_ALL_INFORMATION with the fields it wants written named in
// WhichFields. Everything the mask leaves out has to survive untouched, and the
// logon week has to land in the directory as the bitmap AD keeps.
void SamrTest::samrWritesTheAggregateUserInformation()
{
    QList<DirectoryObject> store;
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("objectSid"),
                            QStringLiteral("S-1-5-21-1-2-3-1001"));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    alice.attributes.insert(QStringLiteral("description"), QStringLiteral("kept"));
    alice.attributes.insert(QStringLiteral("comment"), QStringLiteral("also kept"));
    store.append(alice);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    Samr::WriteBackend backend;
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) != 0)
                continue;
            if (value.isEmpty())
                object.attributes.remove(attribute);
            else
                object.attributes.insert(attribute, value);
            return true;
        }
        return false;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);
    const QByteArray userHandle =
        server.handleCall(Samr::OpOpenUser, openUserStub(domainHandle, 1001)).left(20);

    QByteArray week(21, '\0');
    week[3] = char(0xfe); // Monday, 09:00-17:00

    UserInfoFields fields;
    // Named in the structure but not in WhichFields, so neither is applied.
    fields.userName = QStringLiteral("renamed");
    fields.adminComment = QStringLiteral("replaced");
    fields.fullName = QStringLiteral("Gina Walker");
    fields.homeDirectory = QStringLiteral("\\\\srv\\home\\gina");
    fields.homeDrive = QStringLiteral("H:");
    fields.scriptPath = QStringLiteral("logon.bat");
    fields.profilePath = QStringLiteral("\\\\srv\\profiles\\gina");
    fields.workstations = QStringLiteral("WS01,WS02");
    fields.parameters = QStringLiteral("a=b");
    fields.primaryGroupId = 513;
    fields.accountControl = 0x11; // acct_flags: ACB_DISABLED | ACB_NORMAL
    fields.accountExpires = 0;
    fields.countryCode = 39;
    fields.codePage = 1252;
    fields.logonHours = week;
    fields.fieldsPresent = 0x00000002u  // FULL_NAME
                          | 0x00000008u // PRIMARY_GID
                          | 0x00000040u // HOME_DIRECTORY
                          | 0x00000080u // HOME_DRIVE
                          | 0x00000100u // LOGON_SCRIPT
                          | 0x00000200u // PROFILE_PATH
                          | 0x00000400u // WORKSTATIONS
                          | 0x00002000u // LOGON_HOURS
                          | 0x00080000u // ACCT_EXPIRY
                          | 0x00100000u // ACCT_FLAGS
                          | 0x00200000u // PARAMETERS
                          | 0x00400000u // COUNTRY_CODE
                          | 0x00800000u; // CODE_PAGE

    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2,
                                        allUserInfoStub(userHandle, 21, fields))),
             0u);

    const QMap<QString, QString> &written = store.at(0).attributes;
    QCOMPARE(written.value(QStringLiteral("displayName")), QStringLiteral("Gina Walker"));
    QCOMPARE(written.value(QStringLiteral("homeDirectory")),
             QStringLiteral("\\\\srv\\home\\gina"));
    QCOMPARE(written.value(QStringLiteral("homeDrive")), QStringLiteral("H:"));
    QCOMPARE(written.value(QStringLiteral("scriptPath")), QStringLiteral("logon.bat"));
    QCOMPARE(written.value(QStringLiteral("profilePath")),
             QStringLiteral("\\\\srv\\profiles\\gina"));
    QCOMPARE(written.value(QStringLiteral("userWorkstations")), QStringLiteral("WS01,WS02"));
    QCOMPARE(written.value(QStringLiteral("userParameters")), QStringLiteral("a=b"));
    QCOMPARE(written.value(QStringLiteral("primaryGroupID")), QStringLiteral("513"));
    QCOMPARE(written.value(QStringLiteral("userAccountControl")), QStringLiteral("514"));
    QCOMPARE(written.value(QStringLiteral("countryCode")), QStringLiteral("39"));
    QCOMPARE(written.value(QStringLiteral("codePage")), QStringLiteral("1252"));
    // 0 is AD's "never", which is what the directory stores.
    QCOMPARE(written.value(QStringLiteral("accountExpires")), QStringLiteral("0"));
    QCOMPARE(written.value(QStringLiteral("logonHours")),
             QString::fromLatin1(week.toHex()));
    // The mask did not name these, so the set must not touch them.
    QCOMPARE(written.value(QStringLiteral("sAMAccountName")), QStringLiteral("alice"));
    QCOMPARE(written.value(QStringLiteral("description")), QStringLiteral("kept"));
    QCOMPARE(written.value(QStringLiteral("comment")), QStringLiteral("also kept"));

    // The week reads back through class 4 and through the aggregate.
    QByteArray query = userHandle;
    query.append(QByteArray::fromHex("04000000"));
    const QByteArray hours = server.handleCall(Samr::OpQueryInformationUser2, query);
    QCOMPARE(lastWord(hours), 0u);
    QCOMPARE(quint8(hours.at(4)), quint8(4)); // tag: SamrUserLogonHoursInformation
    QCOMPARE(readLe32At(hours, 8) & 0xffffu, 168u); // UnitsPerWeek
    QCOMPARE(readLe32At(hours, 16), 1260u);         // MaximumCount, from the IDL
    QCOMPARE(readLe32At(hours, 24), 21u);           // ActualCount
    QCOMPARE(hours.mid(28, 21), week);

    QByteArray all = userHandle;
    all.append(QByteArray::fromHex("15000000"));
    const QByteArray aggregate = server.handleCall(Samr::OpQueryInformationUser2, all);
    QCOMPARE(lastWord(aggregate), 0u);
    QVERIFY(aggregate.contains(week));
    // CountryCode and CodePage sit together 188 bytes into the arm: 48 of
    // timestamps, ten strings, two OWF blobs, private data, the descriptor and
    // the four ULONGs, the logon-hours header, then the bad-password and logon
    // counters.
    QCOMPARE(readLe32At(aggregate, 8 + 188), 39u | (1252u << 16));

    // A truncated structure is refused rather than half-applied.
    QByteArray truncated = allUserInfoStub(userHandle, 21, fields);
    truncated.chop(40);
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2, truncated)),
             0xc000000du); // STATUS_INVALID_PARAMETER
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Gina Walker"));
}

// Classes 23 and 25 are the same structure plus the password buffer, and class
// 21 can name the NT hash in WhichFields instead. Both arrive ciphered under the
// RPC session key, never in the clear.
void SamrTest::samrSetsPasswordThroughTheAggregateClasses()
{
    QList<DirectoryObject> store;
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("objectSid"),
                            QStringLiteral("S-1-5-21-1-2-3-1001"));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    store.append(alice);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    QString lastPassword;
    QByteArray receivedHash;
    Samr::WriteBackend backend;
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) != 0)
                continue;
            object.attributes.insert(attribute, value);
            return true;
        }
        return false;
    };
    backend.setPassword = [&lastPassword](const QString &, const QString &password,
                                          QString *) {
        lastPassword = password;
        return true;
    };
    backend.setNtHash = [&receivedHash](const QString &, const QByteArray &hash, QString *) {
        receivedHash = hash;
        return true;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);
    const QByteArray domainHandle =
        server.handleCall(Samr::OpOpenDomain, openDomainStub(serverHandle)).left(20);
    const QByteArray userHandle =
        server.handleCall(Samr::OpOpenUser, openUserStub(domainHandle, 1001)).left(20);

    const QByteArray sessionKey = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    UserInfoFields fields;
    fields.fieldsPresent = 0x01000000u | 0x08000000u; // NT_PASSWORD_PRESENT | EXPIRED_FLAG
    fields.passwordExpired = true;

    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 allUserInfoStub(userHandle, 23, fields, QByteArray(), sessionKey), sessionKey)),
             0u);
    QCOMPARE(lastPassword, QStringLiteral("An0ther!Pass"));
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("pwdLastSet")), QStringLiteral("0"));

    // Class 25 ciphers with MD5(confounder || session key) behind a confounder.
    lastPassword.clear();
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 allUserInfoStub(userHandle, 25, fields, QByteArray(), sessionKey), sessionKey)),
             0u);
    QCOMPARE(lastPassword, QStringLiteral("An0ther!Pass"));

    // Without the session key nothing can be opened, so nothing is set.
    lastPassword.clear();
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 allUserInfoStub(userHandle, 23, fields, QByteArray(), sessionKey))),
             0xc000000du); // STATUS_INVALID_PARAMETER
    QVERIFY(lastPassword.isEmpty());

    // Class 21 with SAMPR_FIELD_OWF_PWD: the NT hash DES-enciphered the way
    // class 18 carries it.
    const QByteArray ntHash = QByteArray::fromHex("5f695b7f2516dd9281fd2da14dcfdd81");
    UserInfoFields hashFields;
    hashFields.fieldsPresent = 0x20000000u;
    hashFields.ntOwf = Des::encryptOwfHash(ntHash, sessionKey);
    QCOMPARE(lastWord(server.handleCall(Samr::OpSetInformationUser2,
                                        allUserInfoStub(userHandle, 21, hashFields),
                                        sessionKey)),
             0u);
    QCOMPARE(receivedHash, ntHash);
}

void SamrTest::rpcFramingCarriesSamr()
{
    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([]() { return QList<DirectoryObject>(); });
    QVERIFY(server.listen(0));

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    // A bind PDU offering SAMR over NDR32, as impacket sends it: the server
    // must answer with an acceptance result.
    QByteArray bind;
    bind.append(char(5)); // rpc_vers
    bind.append(char(0));
    bind.append(char(11)); // PTYPE bind
    bind.append(char(3));
    bind.append(QByteArray::fromHex("10000000"));
    bind.append(QByteArray::fromHex("0000"));       // frag_length, patched below
    bind.append(QByteArray::fromHex("0000"));       // auth_length
    bind.append(QByteArray::fromHex("01000000"));   // call id
    bind.append(QByteArray::fromHex("b010b010"));   // max xmit/recv
    bind.append(QByteArray::fromHex("00000000"));   // assoc group
    bind.append(char(1));                           // one context
    bind.append(QByteArray::fromHex("000000"));
    bind.append(QByteArray::fromHex("0000"));       // context id
    bind.append(char(1));                           // one transfer syntax
    bind.append(char(0));
    bind.append(Samr::interface().uuid);
    bind.append(QByteArray::fromHex("01000000"));   // version 1.0
    bind.append(Rpc::kNdrSyntaxUuid);
    bind.append(QByteArray::fromHex("02000000"));   // NDR32 v2
    const quint16 length = quint16(bind.size());
    bind[8] = char(length & 0xff);
    bind[9] = char((length >> 8) & 0xff);

    socket.write(bind);
    socket.flush();
    QByteArray reply;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        reply += socket.readAll();
        if (reply.size() >= 16 && reply.size() >= int(quint8(reply.at(10)))
                + 0 && reply.size() >= (quint8(reply.at(8)) | (quint8(reply.at(9)) << 8)))
            if (quint8(reply.at(8)) | (quint8(reply.at(9)) << 8))
                break;
        socket.waitForReadyRead(20);
    }
    QVERIFY(reply.size() >= 26);
    QCOMPARE(quint8(reply.at(2)), quint8(12)); // bind_ack
    // The first result follows the secondary address; acceptance is result 0.
    const int resultOffset = reply.indexOf(Rpc::kNdrSyntaxUuid) - 4;
    QVERIFY(resultOffset > 0);
    QCOMPARE(quint16(quint8(reply.at(resultOffset))),
             quint16(0)); // acceptance
}

// Windows and Samba offer NDR32 and NDR64 in one bind and expect a result for
// each; answering only the first is a protocol error to them.
void SamrTest::rpcBindAnswersEveryContext()
{
    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([]() { return QList<DirectoryObject>(); });
    QVERIFY(server.listen(0));

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    QByteArray bind;
    bind.append(char(5));
    bind.append(char(0));
    bind.append(char(11));                         // PTYPE bind
    bind.append(char(3));
    bind.append(QByteArray::fromHex("10000000"));
    bind.append(QByteArray::fromHex("0000"));      // frag_length, patched below
    bind.append(QByteArray::fromHex("0000"));      // auth_length
    bind.append(QByteArray::fromHex("01000000"));  // call id
    bind.append(QByteArray::fromHex("b010b010"));  // max xmit/recv
    bind.append(QByteArray::fromHex("00000000"));  // assoc group
    bind.append(char(2));                          // two contexts
    bind.append(QByteArray::fromHex("000000"));
    // Context 0: SAMR with NDR32 only.
    bind.append(QByteArray::fromHex("0000"));      // context id 0
    bind.append(char(1));
    bind.append(char(0));
    bind.append(Samr::interface().uuid);
    bind.append(QByteArray::fromHex("01000000"));  // version 1.0
    bind.append(Rpc::kNdrSyntaxUuid);
    bind.append(QByteArray::fromHex("02000000"));  // NDR32 v2
    // Context 1: SAMR with NDR64 only, which this server does not speak.
    bind.append(QByteArray::fromHex("0100"));      // context id 1
    bind.append(char(1));
    bind.append(char(0));
    bind.append(Samr::interface().uuid);
    bind.append(QByteArray::fromHex("01000000"));
    bind.append(Rpc::kNdrsSyntaxUuid);
    bind.append(QByteArray::fromHex("01000000")); // NDR64 v1
    const quint16 length = quint16(bind.size());
    bind[8] = char(length & 0xff);
    bind[9] = char((length >> 8) & 0xff);

    socket.write(bind);
    socket.flush();
    QByteArray reply;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        reply += socket.readAll();
        if (reply.size() >= (quint8(reply.at(8)) | (quint8(reply.at(9)) << 8)))
            break;
        socket.waitForReadyRead(20);
    }
    QVERIFY(reply.size() >= 28 + 2 * 24);
    QCOMPARE(quint8(reply.at(2)), quint8(12)); // bind_ack
    // Header (24) + secondary address length and padding (4) put the result
    // list at offset 28: one count octet, then 24 bytes per context.
    QCOMPARE(quint8(reply.at(28)), quint8(2));
    const int first = 32;
    QCOMPARE(quint16(quint8(reply.at(first))),
             quint16(0)); // result: acceptance
    QCOMPARE(quint16(quint8(reply.at(first + 24))),
             quint16(2)); // result: provider rejection
    QCOMPARE(quint16(quint8(reply.at(first + 26))),
             quint16(2)); // reason: transfer syntaxes not supported
}


// A BUILTIN alias is a stored object, so a membership SAMR adds to one is
// written where LDAP serves it: the well-known SIDs stay the identity a client
// sees, and the memberships AD seeds are reported beside the added ones.
void SamrTest::samrWritesBuiltinAliasMembers()
{
    QList<DirectoryObject> store;
    DirectoryObject user;
    user.id = QStringLiteral("CN=gina,CN=Users,DC=corp,DC=example,DC=com");
    user.name = QStringLiteral("gina");
    user.type = QStringLiteral("User");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1001"));
    store.append(user);

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    server.setConfig(config);
    server.setObjectProvider([&store]() { return store; });

    Samr::WriteBackend backend;
    backend.create = [&store](DirectoryObject *object, QString *) {
        store.append(*object);
        return true;
    };
    backend.addMember = [&store](const QString &groupDn, const QString &memberDn, QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(groupDn, Qt::CaseInsensitive) == 0) {
                if (!object.members.contains(memberDn, Qt::CaseInsensitive))
                    object.members.append(memberDn);
                return true;
            }
        }
        return false;
    };
    backend.removeMember = [&store](const QString &groupDn, const QString &memberDn, QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(groupDn, Qt::CaseInsensitive) == 0) {
                object.members.removeAll(memberDn);
                return true;
            }
        }
        return false;
    };
    backend.set = [&store](const QString &dn, const QString &attribute, const QString &value,
                           QString *) {
        for (DirectoryObject &object : store) {
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0) {
                object.attributes.insert(attribute, value);
                return true;
            }
        }
        return false;
    };
    backend.remove = [&store](const QString &dn, QString *) {
        for (int i = 0; i < store.size(); ++i) {
            if (store.at(i).id.compare(dn, Qt::CaseInsensitive) == 0) {
                store.removeAt(i);
                return true;
            }
        }
        return false;
    };
    server.setWriteBackend(backend);

    const QByteArray serverHandle = server.handleCall(Samr::OpConnect, kConnect).left(20);
    // The BUILTIN domain, S-1-5-32, opened by its own SID.
    QByteArray openBuiltin = serverHandle;
    openBuiltin.append(QByteArray::fromHex("000000020000000001000000"
                                           "010100000000000520000000"));
    const QByteArray builtinReply = server.handleCall(Samr::OpOpenDomain, openBuiltin);
    QCOMPARE(lastWord(builtinReply), 0u);
    const QByteArray builtinHandle = builtinReply.left(20);

    const QByteArray memberSid = Ndr::sidFromString(QStringLiteral("S-1-5-21-1-2-3-1001"));
    const QByteArray aliasReply = server.handleCall(Samr::OpOpenAlias,
                                                   openUserStub(builtinHandle, 546));
    QCOMPARE(lastWord(aliasReply), 0u);
    const QByteArray aliasHandle = aliasReply.left(20);
    QCOMPARE(lastWord(server.handleCall(Samr::OpAddMemberToAlias,
                                        aliasMemberStub(aliasHandle, memberSid))),
             0u);

    // The membership is in the store, on the alias object LDAP serves.
    QStringList storedMembers;
    bool stored = false;
    for (const DirectoryObject &object : store) {
        if (object.id.compare(QStringLiteral("CN=Guests,CN=Builtin,DC=corp,DC=example,DC=com"),
                              Qt::CaseInsensitive) == 0) {
            stored = true;
            storedMembers = object.members;
        }
    }
    QVERIFY(stored);
    QCOMPARE(storedMembers,
             QStringList{QStringLiteral("CN=gina,CN=Users,DC=corp,DC=example,DC=com")});
    QCOMPARE(lastWord(server.handleCall(Samr::OpQueryInformationAlias,
                                       queryAliasStub(aliasHandle, 1))),
             0u);
    const QByteArray members = server.handleCall(Samr::OpGetMembersInAlias, aliasHandle);
    QCOMPARE(lastWord(members), 0u);
    QCOMPARE(readLe32At(members, 0), 1u);
    QVERIFY(members.contains(memberSid));

    QCOMPARE(lastWord(server.handleCall(Samr::OpRemoveMemberFromAlias,
                                        aliasMemberStub(aliasHandle, memberSid))),
             0u);
    QCOMPARE(readLe32At(server.handleCall(Samr::OpGetMembersInAlias, aliasHandle), 0), 0u);
}

#include "test_samr.moc"

QTEST_GUILESS_MAIN(SamrTest)
