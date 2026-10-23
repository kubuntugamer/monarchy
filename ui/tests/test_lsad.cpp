// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Lsad.h"

namespace {

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

quint16 readLe16At(const QByteArray &data, int at)
{
    return quint16(quint8(data.at(at)) | (quint16(quint8(data.at(at + 1))) << 8));
}

quint32 lastWord(const QByteArray &stub)
{
    if (stub.size() < 4)
        return 0xffffffffu;
    return readLe32At(stub, stub.size() - 4);
}

// LsarOpenPolicy2 as a client marshals it: the [unique] system name (NULL),
// LSAPR_OBJECT_ATTRIBUTES (Length and the five pointers/attributes) and the
// desired access mask.
QByteArray openPolicyStub()
{
    QByteArray stub;
    appendLe32(stub, 0); // SystemName: NULL
    for (int i = 0; i < 6; ++i)
        appendLe32(stub, 0);
    appendLe32(stub, 0x000f0fffu); // MAXIMUM_ALLOWED
    return stub;
}

// LsarQueryInformationPolicy(2): the policy handle and the 2-byte level.
QByteArray queryStub(const QByteArray &handle, quint16 level)
{
    QByteArray stub = handle;
    stub.append(char(level & 0xff));
    stub.append(char((level >> 8) & 0xff));
    return stub;
}

Samr::Config testConfig()
{
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    return config;
}

// The bytes this endpoint puts on the wire, in the order MS-LSAD puts them: the
// union referent, the 2-byte level and its two alignment bytes, the arm, then
// the NTSTATUS. The arm is `lsa_DomainInfo`: `lsa_StringLarge` (2-byte length,
// 2-byte size, 4-byte buffer referent) and the SID pointer, with both buffers
// deferred behind them; dom_sid2 opens with the conformant sub-authority
// array's maximum count and only then the revision, count and authority.
//
// These exact stubs were decoded from this server by impacket at PKT_PRIVACY
// and by Samba's `samba.dcerpc.lsa` (the reference NDR implementation), which
// is what makes them a specification rather than a snapshot of the encoder.
// Only the referents and `MaximumLength` are free choices; both clients accept
// them, and Samba pushes length+2 there as this does.
const char *kPrimaryDomainLevel3 =
    "030003000300000008000a001000030020000300050000000000000004000000"
    "43004f0052005000040000000104000000000005150000000100000002000000"
    "0300000000000000";

const char *kAccountDomainLevel5 =
    "050003000500000008000a001000030020000300050000000000000004000000"
    "43004f0052005000040000000104000000000005150000000100000002000000"
    "0300000000000000";

// lsa_DnsDomainInfo: three strings, the domain GUID (16 raw bytes, the MD5 of
// the domain SID in this implementation) and the SID, all buffers deferred.
const char *kDnsDomainLevel12 =
    "0c0003000c00000008000a001000030020002200110003002000220012000300"
    "2aefca07d18a84e9edd5499d877cb72c20000300050000000000000004000000"
    "43004f005200500011000000000000001000000063006f00720070002e006500"
    "780061006d0070006c0065002e0063006f006d00110000000000000010000000"
    "63006f00720070002e006500780061006d0070006c0065002e0063006f006d00"
    "0400000001040000000000051500000001000000020000000300000000000000";

} // namespace

class LsadTest : public QObject
{
    Q_OBJECT

private slots:
    void answersTheDomainIdentity();
    void answersTheDnsDomainIdentity();
    void alignsThePolicyArmsApparentlyTrivialLevelsHide();
    void answersThePrivilegeDisplayName();
    void refusesUnknownHandlesAndClasses();
};

void LsadTest::answersTheDomainIdentity()
{
    LsadServer server;
    server.setConfig(testConfig());

    const QByteArray openReply = server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub());
    QCOMPARE(openReply.size(), 24); // 20-byte handle and the status
    QCOMPARE(lastWord(openReply), 0u);
    const QByteArray handle = openReply.left(20);

    for (const auto &[level, expected] :
         {qMakePair(quint16(3), QByteArray::fromHex(kPrimaryDomainLevel3)),
          qMakePair(quint16(5), QByteArray::fromHex(kAccountDomainLevel5))}) {
        const QByteArray reply = server.handleCall(Lsad::OpQueryInformationPolicy2,
                                                   queryStub(handle, level));
        QVERIFY2(reply == expected,
                 qPrintable(QStringLiteral("level %1: %2").arg(level).arg(QString::fromLatin1(reply.toHex()))));
        QCOMPARE(lastWord(reply), 0u);

        // The union rides behind one pointer referent, and the level is a
        // 2-byte discriminant followed by two alignment bytes.
        QVERIFY(readLe32At(reply, 0) != 0);
        QCOMPARE(readLe16At(reply, 4), level);
        QCOMPARE(readLe16At(reply, 6), quint16(0));

        // The domain name is a deferred lsa_StringLarge, so the arm itself
        // carries the buffer referent at offset 12, not characters.
        QVERIFY(readLe32At(reply, 12) != 0);
        QVERIFY(readLe32At(reply, 16) != 0); // the SID's referent
        // Last four bytes of the stub are what a client reads as the result.
        QCOMPARE(readLe32At(reply, reply.size() - 4), 0u);
    }

    // dom_sid2 starts with the conformant array's maximum count: the count of
    // sub-authorities here, then revision and count, then the authority and the
    // sub-authorities. A client that finds the count anywhere else decodes the
    // revision as a huge array length and runs off the end of the stub, which is
    // exactly how this call used to fail.
    const QByteArray reply =
        server.handleCall(Lsad::OpQueryInformationPolicy2, queryStub(handle, 3));
    const int nameHeader = 20;                                   // the name's deferral header
    const int nameChars = readLe32At(reply, nameHeader + 8) * 2;  // ActualCount, in bytes
    const int sidAt = nameHeader + 12 + nameChars + ((4 - nameChars % 4) % 4);
    QCOMPARE(readLe32At(reply, sidAt), 4u);            // maximum count
    QCOMPARE(quint8(reply.at(sidAt + 4)), quint8(1));  // revision
    QCOMPARE(quint8(reply.at(sidAt + 5)), quint8(4));  // sub-authority count
    QCOMPARE(reply.mid(sidAt + 6, 6), QByteArray::fromHex("000000000005"));
    QCOMPARE(readLe32At(reply, sidAt + 12), 21u);      // the first sub-authority
}

void LsadTest::answersTheDnsDomainIdentity()
{
    LsadServer server;
    server.setConfig(testConfig());
    server.setDomainNames(QStringLiteral("CORP"), QStringLiteral("CORPDC1"),
                          QStringLiteral("corp.example.com"),
                          QStringLiteral("S-1-5-21-1-2-3"));

    const QByteArray handle =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);
    const QByteArray reply =
        server.handleCall(Lsad::OpQueryInformationPolicy2, queryStub(handle, 12));

    QCOMPARE(reply, QByteArray::fromHex(kDnsDomainLevel12));
    QCOMPARE(lastWord(reply), 0u);
    QCOMPARE(readLe16At(reply, 4), quint16(12));
    // The names travel behind their referents: the arm ends at the SID pointer
    // and the three buffers follow it in the order they were declared.
    QVERIFY(readLe32At(reply, 12) != 0);
    QVERIFY(readLe32At(reply, 20) != 0);
    QVERIFY(readLe32At(reply, 28) != 0);
    QVERIFY(readLe32At(reply, 44) != 0);
}

// lsa_DefaultQuotaInfo is five uint32 limits followed by a hyper, and the hyper
// lands on an 8-byte boundary, so four padding bytes sit between the last limit
// and the unknown value. A reply that omits them is four bytes short of what
// Samba's decoder wants and it answers STATUS_BUFFER_TOO_SMALL, which is exactly
// how this class failed before the padding was added.
void LsadTest::alignsThePolicyArmsApparentlyTrivialLevelsHide()
{
    LsadServer server;
    server.setConfig(testConfig());
    const QByteArray handle =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);

    // 4 pointer + 2 level + 2 padding, 5 * 4 limits, 4 padding, the hyper and
    // the status.
    const QByteArray quota = server.handleCall(Lsad::OpQueryInformationPolicy2,
                                               queryStub(handle, 8));
    QCOMPARE(quota.size(), 44);
    QCOMPARE(readLe32At(quota, quota.size() - 4), 0u);

    // lsa_AuditFullSetInfo and lsa_AuditFullQueryInfo are one and two bytes, and
    // every NDR32 decoder reads the arm from the 4-byte boundary after the
    // discriminant: a 16-byte reply is what impacket decodes and what Samba's
    // pidl marshaller leaves room for.
    for (quint16 level : {quint16(10), quint16(11)}) {
        const QByteArray reply = server.handleCall(Lsad::OpQueryInformationPolicy2,
                                                   queryStub(handle, level));
        QCOMPARE(reply.size(), 16);
        QCOMPARE(readLe16At(reply, 4), level);
        QCOMPARE(quint8(reply.at(8)), quint8(0)); // ShutdownOnFull
        QCOMPARE(readLe32At(reply, 12), 0u);      // status
    }
}

// lsa_LookupPrivDisplayName returns the display name and then a 2-byte language
// id, which travels directly after the characters: padding the characters to a
// 4-byte boundary would push the id out of place and shift the status with it.
void LsadTest::answersThePrivilegeDisplayName()
{
    LsadServer server;
    server.setConfig(testConfig());
    const QByteArray handle =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);

    const QString privilege = QStringLiteral("SeBackupPrivilege");
    QByteArray stub = handle;
    stub.append(char(quint16(privilege.size() * 2) & 0xff));
    stub.append(char((quint16(privilege.size() * 2) >> 8) & 0xff)); // Length
    stub.append(char(quint16(privilege.size() * 2) & 0xff));
    stub.append(char((quint16(privilege.size() * 2) >> 8) & 0xff)); // MaximumLength
    appendLe32(stub, 0x00020000);                                   // buffer referent
    appendLe32(stub, quint32(privilege.size())); // maximum count
    appendLe32(stub, 0);                         // offset
    appendLe32(stub, quint32(privilege.size())); // actual count
    for (const QChar c : privilege) {
        stub.append(char(c.unicode() & 0xff));
        stub.append(char((c.unicode() >> 8) & 0xff));
    }
    stub.append(QByteArray(4, '\0')); // language_id and language_id_sys

    const QByteArray reply = server.handleCall(Lsad::OpLookupPrivDisplayName, stub);
    QCOMPARE(reply.size(), 88);
    QCOMPARE(readLe16At(reply, reply.size() - 6), quint16(0x0409)); // en-US
    QCOMPARE(readLe32At(reply, reply.size() - 4), 0u);              // status
    // The display name is deferred behind its referent and travels as a
    // varrying array: maximum count, offset, actual count, characters.
    QVERIFY(readLe32At(reply, 0) != 0);
    QCOMPARE(readLe32At(reply, 12), 30u); // "Back up files and directories" + terminator
    QCOMPARE(readLe32At(reply, 20), 29u); // characters actually sent
}

void LsadTest::refusesUnknownHandlesAndClasses()
{
    LsadServer server;
    server.setConfig(testConfig());

    // A handle this server never issued: a NULL union referent and the status.
    const QByteArray unknown = server.handleCall(
        Lsad::OpQueryInformationPolicy2, queryStub(QByteArray(20, '\x5a'), 3));
    QCOMPARE(unknown.size(), 8);
    QCOMPARE(readLe32At(unknown, 0), 0u);
    QCOMPARE(lastWord(unknown), 0xc0000008u); // STATUS_INVALID_HANDLE

    const QByteArray handle =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);

    // A level outside the table is refused, not guessed at.
    const QByteArray unsupported =
        server.handleCall(Lsad::OpQueryInformationPolicy2, queryStub(handle, 15));
    QCOMPARE(readLe32At(unsupported, 0), 0u);
    QCOMPARE(lastWord(unsupported), 0xc0000003u); // STATUS_INVALID_INFO_CLASS

    // Close retires the handle, so the same query is then refused.
    const QByteArray closed = server.handleCall(Lsad::OpClose, handle);
    QCOMPARE(lastWord(closed), 0u);
    const QByteArray afterClose =
        server.handleCall(Lsad::OpQueryInformationPolicy2, queryStub(handle, 3));
    QCOMPARE(lastWord(afterClose), 0xc0000008u);
}

QTEST_MAIN(LsadTest)
#include "test_lsad.moc"
