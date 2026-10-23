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
QByteArray createStub(const QByteArray &domainHandle, const QString &name, bool user)
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
        appendLe32(stub, 0x10); // USER_NORMAL_ACCOUNT
    appendLe32(stub, 0x000f001fu); // MAXIMUM_ALLOWED
    return stub;
}

// SamrSetInformationUser2, captured from impacket for a control-information
// write: info class 16, union tag 16, then the ULONG arm.
QByteArray controlStub(const QByteArray &userHandle)
{
    return userHandle + QByteArray::fromHex("10001000") + QByteArray::fromHex("02020000");
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
    void samrWritesAccountsAndGroups();
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
    QByteArray nameRequest = userHandle;
    nameRequest.append(char(6));
    nameRequest.append(QByteArray(2, '\0'));
    const QByteArray nameReply =
        server.handleCall(Samr::OpQueryInformationUser2, nameRequest);
    QCOMPARE(lastWord(nameReply), 0u);
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
    QCOMPARE(quint8(allReply.at(4)), quint8(21)); // tag: SamrUserAllInformation
    QVERIFY(utf16Text(allReply).contains(QStringLiteral("alice")));
    QVERIFY(allReply.contains(QByteArray::fromHex("e9030000"))); // RID 1001
    QVERIFY(allReply.contains(QByteArray::fromHex("ffe7ff09"))); // fields present
    // The logon-hours pointer is [size_is(1260), length_is(168/8)]: maximum
    // count 1260, offset 0, twenty-one octets of "every hour allowed".
    QByteArray hours;
    hours.append(QByteArray::fromHex("ec040000")); // 1260
    hours.append(QByteArray::fromHex("00000000")); // offset
    hours.append(QByteArray::fromHex("15000000")); // 21
    hours.append(QByteArray(21, char(0xff)));
    QVERIFY(allReply.contains(hours));

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
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpLookupNamesInDomain,
                 lookupNamesStub(domainHandle, {QStringLiteral("nosuch")}))),
             0xc0000073u); // STATUS_NONE_MAPPED

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

    // Deleting the account removes it from the store, and its handle dies.
    QCOMPARE(lastWord(server.handleCall(Samr::OpDeleteUser, userHandle)), 0u);
    QCOMPARE(store.size(), 1); // only the group is left
    QCOMPARE(store.at(0).kind, ObjectKind::Group);
    QCOMPARE(lastWord(server.handleCall(Samr::OpQueryInformationUser2,
                                        userHandle + QByteArray::fromHex("06000000"))),
             0xc0000008u); // STATUS_INVALID_HANDLE
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

    // Account flags: 514 = ACCOUNTDISABLE | NORMAL_ACCOUNT disables the account.
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
    QCOMPARE(readLe32At(queryReply, 8), 514u);

    // The full name follows the same string layout the query uses.
    QCOMPARE(lastWord(server.handleCall(
                 Samr::OpSetInformationUser2,
                 fullNameStub(userHandle, QStringLiteral("Gina Walker")))),
             0u);
    QCOMPARE(store.at(0).attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Gina Walker"));

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
    backend.setNtHash = [&store, &receivedHash](const QString &dn, const QByteArray &hash,
                                                QString *) {
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
    fields.accountControl = 514;
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

#include "test_samr.moc"

QTEST_GUILESS_MAIN(SamrTest)
