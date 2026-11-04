// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Lsad.h"
#include "Ntlm.h"

namespace {

void appendLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
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
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    return config;
}

void alignTo(QByteArray &out, int boundary)
{
    while (out.size() % boundary != 0)
        out.append('\0');
}

void appendUtf16(QByteArray &out, const QString &text)
{
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
}

QByteArray utf16Bytes(const QString &text)
{
    QByteArray out;
    appendUtf16(out, text);
    return out;
}

// An lsa_StringLarge header: Length, MaximumLength (which counts the
// terminator) and the buffer referent.
void appendStringHeader(QByteArray &out, const QString &text, quint32 referent)
{
    appendLe16(out, quint16(text.size() * 2));
    appendLe16(out, quint16(text.size() * 2 + 2));
    appendLe32(out, referent);
}

// A deferred varying buffer: maximum count, offset, actual count, characters.
void appendDeferredChars(QByteArray &out, const QString &text)
{
    appendLe32(out, quint32(text.size() + 1));
    appendLe32(out, 0);
    appendLe32(out, quint32(text.size()));
    appendUtf16(out, text);
    alignTo(out, 4);
}

// dom_sid2 in the order this endpoint writes it: the sub-authority array's
// maximum count, then revision, count, identifier authority and elements.
QByteArray wireSid(const QString &sid)
{
    const QStringList parts = sid.split(QLatin1Char('-'));
    QByteArray out;
    appendLe32(out, quint32(parts.size() - 3));
    out.append(char(parts.at(1).toUInt()));
    out.append(char(parts.size() - 3));
    const quint64 authority = parts.at(2).toULongLong();
    for (int i = 5; i >= 0; --i)
        out.append(char((authority >> (i * 8)) & 0xff));
    for (int i = 3; i < parts.size(); ++i)
        appendLe32(out, parts.at(i).toUInt());
    return out;
}

// LsarCreateTrustedDomainEx as Samba's pidl client marshals it: the policy
// handle, the InfoEx referent with its fixed fields, the auth-info referent and
// the access mask, then every deferred buffer in pointer order.
QByteArray createTrustStub(const QByteArray &handle, const QString &partner,
                           const QString &flat, const QString &sid, quint32 direction,
                           quint32 type, bool internalBlob = false)
{
    QByteArray stub = handle;
    appendLe32(stub, 0x00020010); // InfoEx pointer
    appendStringHeader(stub, partner, 0x00020011);
    appendStringHeader(stub, flat, 0x00020012);
    appendLe32(stub, 0x00020013); // SID pointer
    appendLe32(stub, direction);
    appendLe32(stub, type);
    appendLe32(stub, 0); // trust attributes
    appendLe32(stub, 0x00020020); // auth-info pointer
    appendLe32(stub, 0x000f0fff); // access mask

    appendDeferredChars(stub, partner);
    appendDeferredChars(stub, flat);
    alignTo(stub, 4);
    stub.append(wireSid(sid));

    if (internalBlob) {
        const QByteArray blob = QByteArray::fromHex("0011223344");
        appendLe32(stub, quint32(blob.size()));
        appendLe32(stub, 0x00020021);
        appendLe32(stub, quint32(blob.size()));
        stub.append(blob);
        alignTo(stub, 4);
        return stub;
    }

    // lsa_TrustDomainInfoAuthInfo: counts and four pointers, then the buffers
    // they point at. Only the incoming current secret is set.
    appendLe32(stub, 1); // incoming_count
    appendLe32(stub, 0x00020022); // incoming_current
    appendLe32(stub, 0);          // incoming_previous
    appendLe32(stub, 0);          // outgoing_count
    appendLe32(stub, 0);          // outgoing_current
    appendLe32(stub, 0);          // outgoing_previous

    const QByteArray secret = QByteArray("s3cret");
    alignTo(stub, 8);
    stub.append(QByteArray(8, '\0')); // last_update_time (NTTIME)
    appendLe32(stub, 2);              // TRUST_AUTH_TYPE_CLEAR
    appendLe32(stub, quint32(secret.size()));
    appendLe32(stub, 0x00020023);
    appendLe32(stub, quint32(secret.size()));
    stub.append(secret);
    alignTo(stub, 4);
    return stub;
}

// LsarSetInformationTrustedDomain level 7: the trust handle, the level, and a
// pointer to the union whose arm is lsa_TrustDomainInfoAuthInfo.
QByteArray setTrustAuthStub(const QByteArray &handle, const QByteArray &secret)
{
    QByteArray stub = handle;
    appendLe16(stub, 7);
    alignTo(stub, 4);
    appendLe32(stub, 0x00020030); // union pointer
    appendLe16(stub, 7);
    alignTo(stub, 4);
    appendLe32(stub, 1);          // incoming_count
    appendLe32(stub, 0x00020031); // incoming_current
    appendLe32(stub, 0);          // incoming_previous
    appendLe32(stub, 0);          // outgoing_count
    appendLe32(stub, 0);
    appendLe32(stub, 0);
    alignTo(stub, 8);
    stub.append(QByteArray(8, '\0')); // last_update_time
    appendLe32(stub, 2);              // TRUST_AUTH_TYPE_CLEAR
    appendLe32(stub, quint32(secret.size()));
    appendLe32(stub, 0x00020032);
    appendLe32(stub, quint32(secret.size()));
    stub.append(secret);
    alignTo(stub, 4);
    return stub;
}

// An lsa_String the way a client marshals it: the header, the varying buffer
// it points at, and only then the following scalar.
void appendInlineString(QByteArray &out, const QString &text, quint32 referent)
{
    appendLe16(out, quint16(text.size() * 2));
    appendLe16(out, quint16(text.size() * 2));
    appendLe32(out, referent);
    appendLe32(out, quint32(text.size()));
    appendLe32(out, 0);
    appendLe32(out, quint32(text.size()));
    appendUtf16(out, text);
    alignTo(out, 4);
}

// LsarOpenTrustedDomainByName: the policy handle, an in-line lsa_String and
// the access mask.
QByteArray openTrustByNameStub(const QByteArray &handle, const QString &name)
{
    QByteArray stub = handle;
    appendInlineString(stub, name, 0x00020011);
    appendLe32(stub, 0x000f0fff);
    return stub;
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
    void createsQueriesEnumeratesAndDeletesATrust();
    void refusesDuplicateAndUnknownTrusts();
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

void LsadTest::createsQueriesEnumeratesAndDeletesATrust()
{
    LsadServer server;
    server.setConfig(testConfig());
    QList<DirectoryObject> store;
    server.setObjectProvider([&store]() { return store; });
    Lsad::WriteBackend writes;
    DirectoryObject trustAccount;
    writes.createTrust = [&store](DirectoryObject *object, QString *) {
        store.append(*object);
        return true;
    };
    writes.createTrustAccount = [&trustAccount](DirectoryObject *object, QString *) {
        trustAccount = *object;
        return true;
    };
    writes.updateTrust = [&store](const QString &dn,
                                  const QMap<QString, QString> &attributes, QString *) {
        for (DirectoryObject &object : store) {
            if (object.id != dn)
                continue;
            for (auto it = attributes.constBegin(); it != attributes.constEnd(); ++it)
                object.attributes.insert(it.key(), it.value());
            return true;
        }
        return false;
    };
    writes.removeTrust = [&store](const QString &dn, QString *) {
        for (int i = 0; i < store.size(); ++i) {
            if (store.at(i).id == dn) {
                store.removeAt(i);
                return true;
            }
        }
        return false;
    };
    server.setWriteBackend(writes);

    const QByteArray policy =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);
    const QByteArray created = server.handleCall(
        Lsad::OpCreateTrustedDomainEx,
        createTrustStub(policy, QStringLiteral("fabrikam.local"), QStringLiteral("FABRIKAM"),
                        QStringLiteral("S-1-5-21-9-8-7"), 3, 2));
    QCOMPARE(lastWord(created), 0u);
    QCOMPARE(created.size(), 24);
    QVERIFY(created.left(20) != QByteArray(20, '\0'));

    // The trust is the trustedDomain object under CN=System that a Windows DC
    // stores, with the partner, direction and SID the call carried.
    QCOMPARE(store.size(), 1);
    const DirectoryObject trust = store.first();
    QCOMPARE(trust.id, QStringLiteral("CN=FABRIKAM,CN=System,DC=corp,DC=example,DC=com"));
    QVERIFY(trust.attributes.value(QStringLiteral("objectClass"))
                .contains(QLatin1String("trustedDomain")));
    QCOMPARE(trust.attributes.value(QStringLiteral("trustPartner")),
             QStringLiteral("fabrikam.local"));
    QCOMPARE(trust.attributes.value(QStringLiteral("trustDirection")), QStringLiteral("3"));
    QCOMPARE(trust.attributes.value(QStringLiteral("securityIdentifier")),
             QStringLiteral("S-1-5-21-9-8-7"));
    QCOMPARE(trust.attributes.value(QStringLiteral("trustAuthIncoming")),
             QStringLiteral("2:") + QString::fromLatin1(QByteArray("s3cret").toHex()));
    // The clear secret is the trust password, so the inter-realm keys the KDC
    // uses are derived from it, exactly as a Windows DC does.
    QCOMPARE(trust.attributes.value(QStringLiteral("kerberosSalt")),
             QStringLiteral("CORP.EXAMPLE.COM+FABRIKAM.LOCAL"));
    // The disabled trust account a Windows DC keeps beside the trust is what
    // NetrLogonGetTrustRid reports and the trust channel can authenticate as.
    QCOMPARE(trustAccount.id,
             QStringLiteral("CN=FABRIKAM$,CN=Users,DC=corp,DC=example,DC=com"));
    QCOMPARE(trustAccount.attributes.value(QStringLiteral("sAMAccountName")),
             QStringLiteral("FABRIKAM$"));
    QCOMPARE(trustAccount.attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("546")); // ACCOUNTDISABLE|PASSWD_NOTREQD|NORMAL_ACCOUNT
    QCOMPARE(trustAccount.attributes.value(QStringLiteral("ntHash")),
             QString::fromLatin1(Ntlm::ntowfV1(QStringLiteral("s3cret")).toHex()));
    QVERIFY(!trust.attributes.value(QStringLiteral("aes128Key")).isEmpty());
    QVERIFY(!trust.attributes.value(QStringLiteral("aes256Key")).isEmpty());

    const QByteArray trustHandle = created.left(20);

    // QueryTrustedDomainInfo level 6: the InfoEx fixed half names both names and
    // the SID pointer, then the direction, type and attributes.
    QByteArray query = trustHandle;
    appendLe16(query, 6);
    const QByteArray info = server.handleCall(Lsad::OpQueryTrustedDomainInfo, query);
    QCOMPARE(lastWord(info), 0u);
    QVERIFY(readLe32At(info, 0) != 0); // information pointer
    QCOMPARE(readLe16At(info, 4), quint16(6));
    QCOMPARE(readLe32At(info, 28), 3u); // trust_direction
    QCOMPARE(readLe32At(info, 32), 2u); // trust_type
    QVERIFY(readLe32At(info, 24) != 0); // the SID's referent
    QVERIFY(info.contains(utf16Bytes(QStringLiteral("fabrikam.local"))));
    QVERIFY(info.contains(utf16Bytes(QStringLiteral("FABRIKAM"))));

    // The same information by name, which is what a client that knows only the
    // partner name asks for.
    QByteArray byName = policy;
    appendInlineString(byName, QStringLiteral("FABRIKAM"), 0x00020011);
    appendLe16(byName, 6);
    const QByteArray byNameReply = server.handleCall(Lsad::OpQueryTrustedDomainInfoByName, byName);
    QCOMPARE(lastWord(byNameReply), 0u);
    QCOMPARE(readLe32At(byNameReply, 28), 3u);

    // Open by name hands out a trust handle for the information calls.
    const QByteArray opened =
        server.handleCall(Lsad::OpOpenTrustedDomainByName,
                          openTrustByNameStub(policy, QStringLiteral("FABRIKAM")));
    QCOMPARE(lastWord(opened), 0u);
    QCOMPARE(opened.size(), 24);
    QVERIFY(opened.left(20) != QByteArray(20, '\0'));

    // EnumTrustedDomainsEx: one entry, the partner's names and direction.
    QByteArray enumerate = policy;
    appendLe32(enumerate, 0);
    appendLe32(enumerate, 0);
    const QByteArray list = server.handleCall(Lsad::OpEnumTrustedDomainsEx, enumerate);
    QCOMPARE(lastWord(list), 0u);
    QCOMPARE(readLe32At(list, 4), 1u); // count
    QVERIFY(readLe32At(list, 8) != 0); // array pointer
    QVERIFY(list.contains(utf16Bytes(QStringLiteral("fabrikam.local"))));

    // A password rollover writes the new clear secret and the keys derived
    // from it, so the partner's next ticket uses the new key.
    const QString oldAes = trust.attributes.value(QStringLiteral("aes128Key"));
    QVERIFY(!oldAes.isEmpty());
    QCOMPARE(lastWord(server.handleCall(Lsad::OpSetInformationTrustedDomain,
                                        setTrustAuthStub(trustHandle, QByteArray("n3wpass")))),
             0u);
    QCOMPARE(store.first().attributes.value(QStringLiteral("trustAuthIncoming")),
             QStringLiteral("2:") + QString::fromLatin1(QByteArray("n3wpass").toHex()));
    QVERIFY(store.first().attributes.value(QStringLiteral("aes128Key")) != oldAes);

    // Delete by SID removes the object; the enumeration then reports no more
    // entries rather than an empty success.
    QByteArray remove = policy;
    appendLe32(remove, 0x00020011);
    remove.append(wireSid(QStringLiteral("S-1-5-21-9-8-7")));
    QCOMPARE(lastWord(server.handleCall(Lsad::OpDeleteTrustedDomain, remove)), 0u);
    QVERIFY(store.isEmpty());
    const QByteArray gone = server.handleCall(Lsad::OpEnumTrustedDomainsEx, enumerate);
    QCOMPARE(lastWord(gone), 0x8000001au); // STATUS_NO_MORE_ENTRIES
    QCOMPARE(readLe32At(gone, 4), 0u);
}

void LsadTest::refusesDuplicateAndUnknownTrusts()
{
    LsadServer server;
    server.setConfig(testConfig());
    QList<DirectoryObject> store;
    server.setObjectProvider([&store]() { return store; });
    Lsad::WriteBackend writes;
    writes.createTrust = [&store](DirectoryObject *object, QString *) {
        store.append(*object);
        return true;
    };
    writes.removeTrust = [](const QString &, QString *) { return false; };
    server.setWriteBackend(writes);

    const QByteArray policy =
        server.handleCall(Lsad::OpOpenPolicy2, openPolicyStub()).left(20);
    const auto create = [&](const QString &flat, bool internal) {
        return server.handleCall(
            internal ? Lsad::OpCreateTrustedDomainEx2 : Lsad::OpCreateTrustedDomainEx,
            createTrustStub(policy, QStringLiteral("tailspin.local"), flat,
                            QStringLiteral("S-1-5-21-4-5-6"), 3, 2, internal));
    };
    QCOMPARE(lastWord(create(QStringLiteral("TAILSPIN"), true)), 0u);
    QCOMPARE(store.size(), 1);
    // The Ex2 form carries the opaque internal blob; the object keeps it.
    QCOMPARE(store.first().attributes.value(QStringLiteral("msDS-AuthInfoInternal")),
             QStringLiteral("0011223344"));

    // The same flat name twice is a collision, not a second trust.
    QCOMPARE(lastWord(create(QStringLiteral("TAILSPIN"), false)), 0xc0000035u);
    QCOMPARE(store.size(), 1);

    // A name nothing created is not found on open, and an unknown SID is not
    // found on delete.
    const QByteArray missing =
        server.handleCall(Lsad::OpOpenTrustedDomainByName,
                          openTrustByNameStub(policy, QStringLiteral("CONTOSO")));
    QCOMPARE(lastWord(missing), 0xc0000034u);
    QCOMPARE(missing.left(20), QByteArray(20, '\0'));

    QByteArray remove = policy;
    appendLe32(remove, 0x00020011);
    remove.append(wireSid(QStringLiteral("S-1-5-21-1-1-1")));
    QCOMPARE(lastWord(server.handleCall(Lsad::OpDeleteTrustedDomain, remove)), 0xc0000034u);

    // Level 7 carries the trust secret; it is refused rather than answered with
    // an empty password a client might install as the trust key.
    const QByteArray opened =
        server.handleCall(Lsad::OpOpenTrustedDomainByName,
                          openTrustByNameStub(policy, QStringLiteral("TAILSPIN")));
    QByteArray query = opened.left(20);
    appendLe16(query, 7);
    const QByteArray refused = server.handleCall(Lsad::OpQueryTrustedDomainInfo, query);
    QCOMPARE(lastWord(refused), 0xc0000003u); // STATUS_INVALID_INFO_CLASS
    QCOMPARE(readLe32At(refused, 0), 0u);
}

QTEST_MAIN(LsadTest)
#include "test_lsad.moc"
