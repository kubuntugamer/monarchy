// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// DRSUAPI (MS-DRSR) conformance, driven the way an independent client reads
// the wire: the bind's advertised extensions, a V8 GetNCChanges answered in
// V6 with its object chain walked field by field, the two lookups a
// DCSync-style client makes first (DsGetDomainControllerInfo level 2 and
// DsCrackNames FQDN -> canonical), and the refusals outside the implemented
// set. Every reply is parsed positionally from its bytes; nothing is taken
// on trust from the server's own structures.

#include <QtTest>

#include "Drs.h"
#include "Ndr.h"

namespace {

void appendLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

void appendLe64(QByteArray &out, quint64 value)
{
    appendLe32(out, quint32(value & 0xffffffffu));
    appendLe32(out, quint32(value >> 32));
}

quint32 readLe32(const QByteArray &data, int offset)
{
    if (offset < 0 || offset + 4 > data.size())
        return 0xdeadbeefu;
    return quint32(quint8(data.at(offset))) | (quint32(quint8(data.at(offset + 1))) << 8)
           | (quint32(quint8(data.at(offset + 2))) << 16)
           | (quint32(quint8(data.at(offset + 3))) << 24);
}

quint64 readLe64(const QByteArray &data, int offset)
{
    return quint64(readLe32(data, offset)) | (quint64(readLe32(data, offset + 4)) << 32);
}

void padTo8(QByteArray &out)
{
    while (out.size() % 8 != 0)
        out.append('\0');
}

void appendGuid(QByteArray &out, const QUuid &guid)
{
    appendLe32(out, guid.data1);
    out.append(char(guid.data2 & 0xffu));
    out.append(char((guid.data2 >> 8) & 0xffu));
    out.append(char(guid.data3 & 0xffu));
    out.append(char((guid.data3 >> 8) & 0xffu));
    for (int i = 0; i < 8; ++i)
        out.append(char(guid.data4[i]));
}

QString readWideString(Ndr::Reader *reader)
{
    quint32 maximum = 0;
    quint32 offset = 0;
    quint32 actual = 0;
    reader->u32(&maximum);
    reader->u32(&offset);
    reader->u32(&actual);
    QByteArray chars;
    if (actual > 65536 || !reader->bytes(int(actual) * 2, &chars))
        return QString();
    QString text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                      int(actual));
    while (text.endsWith(QChar(u'\0')))
        text.chop(1);
    return text;
}

// One element of REPLENTINFLIST as the reply lays it out: the spine, then
// (deeper elements first) this element's DSNAME, attribute block and parent.
struct ChainEntry {
    QString dn;
    quint32 attrCount = 0;
    QByteArray attidsPacked;                    // le32 per ATTR, in wire order
    QHash<quint32, QByteArray> firstValue;      // attid -> first value bytes
};

bool walkDsName(Ndr::Reader *reader, QString *dn)
{
    quint32 count = 0;
    quint32 structLen = 0;
    quint32 sidLen = 0;
    quint32 nameLen = 0;
    if (!reader->u32(&count) || !reader->u32(&structLen) || !reader->u32(&sidLen)
        || !reader->skip(16) || !reader->skip(28) || !reader->u32(&nameLen))
        return false;
    if (count > 4096)
        return false;
    QByteArray chars;
    if (!reader->bytes(int(count) * 2, &chars))
        return false;
    reader->align(4); // the next child opens on a boundary
    *dn = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                             int(count));
    if (dn->endsWith(QChar(u'\0')))
        dn->chop(1);
    return true;
}

bool walkAttrBlock(Ndr::Reader *reader, quint32 declaredCount, ChainEntry *entry)
{
    quint32 maxCount = 0;
    if (!reader->u32(&maxCount) || maxCount != declaredCount)
        return false;
    QVector<QPair<quint32, quint32>> attrs; // attid, valCount
    for (quint32 i = 0; i < maxCount; ++i) {
        quint32 attid = 0;
        quint32 valCount = 0;
        quint32 arrayRef = 0;
        if (!reader->u32(&attid) || !reader->u32(&valCount) || !reader->u32(&arrayRef))
            return false;
        if (arrayRef == 0)
            return false;
        attrs.append(qMakePair(attid, valCount));
        entry->attidsPacked.append(char(attid & 0xff));
        entry->attidsPacked.append(char((attid >> 8) & 0xff));
        entry->attidsPacked.append(char((attid >> 16) & 0xff));
        entry->attidsPacked.append(char((attid >> 24) & 0xff));
    }
    for (const auto &attr : attrs) {
        quint32 count = 0;
        if (!reader->u32(&count) || count != attr.second)
            return false;
        QVector<quint32> lengths;
        for (quint32 i = 0; i < count; ++i) {
            quint32 valueLength = 0;
            quint32 valueRef = 0;
            if (!reader->u32(&valueLength) || !reader->u32(&valueRef))
                return false;
            if (valueRef == 0)
                return false;
            lengths.append(valueLength);
        }
        for (quint32 valueLength : lengths) {
            quint32 leafCount = 0;
            if (!reader->u32(&leafCount) || leafCount != valueLength)
                return false;
            QByteArray value;
            if (!reader->bytes(int(leafCount), &value))
                return false;
            reader->align(4); // the next leaf opens on a boundary
            if (!entry->firstValue.contains(attr.first))
                entry->firstValue.insert(attr.first, value);
        }
    }
    return true;
}

bool walkChain(Ndr::Reader *reader, QList<ChainEntry> *entries)
{
    quint32 nextRef = 0;
    quint32 nameRef = 0;
    quint32 flags = 0;
    quint32 attrCount = 0;
    quint32 attrBlockRef = 0;
    quint32 isNcHead = 0;
    quint32 parentRef = 0;
    quint32 metaDataRef = 0;
    if (!reader->u32(&nextRef) || !reader->u32(&nameRef) || !reader->u32(&flags)
        || !reader->u32(&attrCount) || !reader->u32(&attrBlockRef)
        || !reader->u32(&isNcHead) || !reader->u32(&parentRef)
        || !reader->u32(&metaDataRef))
        return false;
    if (nameRef == 0 || attrCount != 0 && attrBlockRef == 0)
        return false;
    if (nextRef != 0 && !walkChain(reader, entries)) // deeper elements first
        return false;

    ChainEntry entry;
    if (!walkDsName(reader, &entry.dn))
        return false;
    entry.attrCount = attrCount;
    if (attrCount != 0 && !walkAttrBlock(reader, attrCount, &entry))
        return false;
    if (isNcHead == 0) {
        if (!reader->skip(16)) // the parent GUID body
            return false;
    }
    entries->append(entry);
    return true;
}

// --- request builders ------------------------------------------------------

QByteArray bindRequest()
{
    QByteArray stub;
    appendLe32(stub, 0x00020000u);   // puuidClientDsa referent
    stub.append(QByteArray(16, '\x11'));
    appendLe32(stub, 0x00020001u);   // pextClient referent
    appendLe32(stub, 52);            // DRS_EXTENSIONS.cb
    appendLe32(stub, 52);            // rgb conformant count
    stub.append(QByteArray(52, '\0'));
    return stub;
}

QByteArray getNcChangesRequest(const QByteArray &handle, const QString &ncDn)
{
    QByteArray stub = handle; // DRS_HANDLE: 20 bytes flat
    appendLe32(stub, 8);      // dwInVersion
    appendLe32(stub, 8);      // pmsgIn tag
    padTo8(stub);             // the V8 arm carries hyper fields
    stub.append(QByteArray(16, '\0')); // uuidDsaObjDest
    stub.append(QByteArray(16, '\0')); // uuidInvocIdSrc
    appendLe32(stub, 0x00020000u);     // pNC referent
    for (int i = 0; i < 3; ++i) {      // usnvecFrom: three LONGLONGs
        padTo8(stub);
        appendLe64(stub, 0);
    }
    appendLe32(stub, 0);     // pUpToDateVecDest: NULL
    appendLe32(stub, 0);     // ulFlags
    appendLe32(stub, 1000);  // cMaxObjects
    appendLe32(stub, 0);     // cMaxBytes
    appendLe32(stub, 0);     // ulExtendedOp: a plain cycle
    padTo8(stub);
    appendLe64(stub, 0);     // liFsmoInfo
    appendLe32(stub, 0);     // pPartialAttrSet: NULL
    appendLe32(stub, 0);     // pPartialAttrSetEx1: NULL
    appendLe32(stub, 0);     // PrefixTableDest.PrefixCount
    appendLe32(stub, 0);     // pPrefixEntry: NULL

    // The deferred pNC DSNAME: conformant character count first, then the
    // struct (MS-RPCE 14.3.7.2).
    const QByteArray chars = Ndr::utf16le(ncDn + QChar(u'\0'));
    appendLe32(stub, quint32(chars.size() / 2));
    appendLe32(stub, 60 + quint32(chars.size())); // structLen
    appendLe32(stub, 0);                          // SidLen
    stub.append(QByteArray(16, '\0'));            // Guid
    stub.append(QByteArray(28, '\0'));            // Sid slot
    appendLe32(stub, quint32(chars.size() / 2));  // NameLen, characters
    stub.append(chars);
    return stub;
}

QByteArray domainControllerInfoRequest(const QByteArray &handle)
{
    QByteArray stub = handle;
    appendLe32(stub, 1);                  // dwInVersion
    appendLe32(stub, 1);                  // pmsgIn tag
    appendLe32(stub, 0x00020000u);        // Domain referent
    appendLe32(stub, 2);                  // InfoLevel 2
    // Deferred Domain string (WSTR): the body lands after both fields.
    const QByteArray chars = Ndr::utf16le(QStringLiteral("CORP.EXAMPLE.COM") + QChar(u'\0'));
    appendLe32(stub, quint32(chars.size() / 2));
    appendLe32(stub, 0);
    appendLe32(stub, quint32(chars.size() / 2));
    stub.append(chars);
    return stub;
}

QByteArray crackNamesRequest(const QByteArray &handle, const QString &name)
{
    QByteArray stub = handle;
    appendLe32(stub, 1);                  // dwInVersion
    appendLe32(stub, 1);                  // pmsgIn tag
    appendLe32(stub, 0);                  // CodePage
    appendLe32(stub, 0);                  // LocaleId
    appendLe32(stub, 0);                  // dwFlags
    appendLe32(stub, 1);                  // formatOffered: DS_FQDN_1779_NAME
    appendLe32(stub, 7);                  // formatDesired: DS_CANONICAL_NAME
    appendLe32(stub, 1);                  // cNames
    appendLe32(stub, 0x00020040u);        // rpNames referent
    appendLe32(stub, 1);                  // array max_count
    appendLe32(stub, 0x00020041u);        // element referent
    const QByteArray chars = Ndr::utf16le(name + QChar(u'\0'));
    appendLe32(stub, quint32(chars.size() / 2));
    appendLe32(stub, 0);
    appendLe32(stub, quint32(chars.size() / 2));
    stub.append(chars);
    return stub;
}

} // namespace

class DrsTest : public QObject
{
    Q_OBJECT

private:
    Samr::Config config() const
    {
        Samr::Config config;
        config.realm = QStringLiteral("CORP.EXAMPLE.COM");
        config.netbios = QStringLiteral("CORP");
        config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
        config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
        return config;
    }

    QList<DirectoryObject> fixture() const
    {
        DirectoryObject domain;
        domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
        domain.name = QStringLiteral("corp.example.com");
        domain.type = QStringLiteral("Domain");

        DirectoryObject user;
        user.id = QStringLiteral("CN=Administrator,CN=Users,DC=corp,DC=example,DC=com");
        user.name = QStringLiteral("Administrator");
        user.type = QStringLiteral("User");
        user.attributes.insert(QStringLiteral("sAMAccountName"),
                               QStringLiteral("Administrator"));
        user.attributes.insert(QStringLiteral("objectSid"),
                               QStringLiteral("S-1-5-21-1-2-3-500"));
        user.attributes.insert(QStringLiteral("userPrincipalName"),
                               QStringLiteral("Administrator@corp.example.com"));
        user.attributes.insert(QStringLiteral("userAccountControl"),
                               QStringLiteral("512"));
        return {domain, user};
    }

    static QByteArray packed(quint32 value)
    {
        QByteArray out;
        appendLe32(out, value);
        return out;
    }

private slots:
    void drsBindAdvertisesTheReplyShapes()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([this]() { return fixture(); });

        const QByteArray reply = server.handleCall(0, bindRequest());
        QCOMPARE(reply.size(), 88);
        QCOMPARE(readLe32(reply, 0), quint32(0x00020000)); // ppextServer referent
        QCOMPARE(readLe32(reply, 4), quint32(52));         // DRS_EXTENSIONS.cb
        QCOMPARE(readLe32(reply, 8), quint32(52));         // rgb conformant count
        // dwFlags: GETCHGREQ V5/V8/V10, GETCHGREPLY V6 — the shapes served.
        QCOMPARE(readLe32(reply, 12), quint32(0x25100000));
        // The handle: 16-byte key plus the 4-byte pad, all non-zero key bytes.
        for (int i = 64; i < 80; ++i)
            QVERIFY2(reply.at(i) != '\0', "handle key must be non-zero");
        QCOMPARE(readLe32(reply, 84), quint32(0)); // ErrorCode
    }

    void getNCChangesServesTheObjectChain()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([this]() { return fixture(); });

        const QByteArray bindReply = server.handleCall(0, bindRequest());
        const QByteArray handle = bindReply.mid(64, 20);
        const QString ncDn = QStringLiteral("DC=corp,DC=example,DC=com");
        const QByteArray reply = server.handleCall(3, getNcChangesRequest(handle, ncDn));
        QVERIFY(reply.size() > 256);

        // The V6 arm's fixed header.
        QCOMPARE(readLe32(reply, 0), quint32(6)); // pdwOutVersion
        QCOMPARE(readLe32(reply, 4), quint32(6)); // pmsgOut tag
        QVERIFY(readLe32(reply, 40) != 0);        // pNC referent
        QCOMPARE(readLe64(reply, 48), quint64(0)); // usnvecFrom echoes the request
        QCOMPARE(readLe64(reply, 56), quint64(0));
        QCOMPARE(readLe64(reply, 64), quint64(0));
        QVERIFY(readLe32(reply, 96) != 0);        // pUpToDateVecSrc referent
        QCOMPARE(readLe32(reply, 100), quint32(19)); // PrefixTableSrc.PrefixCount
        QVERIFY(readLe32(reply, 104) != 0);        // pPrefixEntry referent
        QCOMPARE(readLe32(reply, 108), quint32(0)); // ulExtendedRet: no extended op
        QCOMPARE(readLe32(reply, 112), quint32(2)); // cNumObjects
        QVERIFY(readLe32(reply, 116) != 0);        // cNumBytes
        QVERIFY(readLe32(reply, 120) != 0);        // pObjects referent
        QCOMPARE(readLe32(reply, 124), quint32(0)); // fMoreData
        QCOMPARE(readLe32(reply, 128), quint32(2)); // cNumNcSizeObjectsc

        // The deferred region, walked in the order the peer reads it.
        Ndr::Reader reader(reply);
        QVERIFY(reader.skip(148)); // past the fixed header and the V6 tail

        QString pNcDn;
        QVERIFY(walkDsName(&reader, &pNcDn));
        QCOMPARE(pNcDn, ncDn); // pNC echoes the request

        // UPTODATE_VECTOR_V2_EXT: conformant count, four head words, cursor.
        quint32 count = 0, version = 0, reserved1 = 0, cursors = 0, reserved2 = 0;
        QVERIFY(reader.u32(&count));
        QVERIFY(reader.u32(&version));
        QVERIFY(reader.u32(&reserved1));
        QVERIFY(reader.u32(&cursors));
        QVERIFY(reader.u32(&reserved2));
        QCOMPARE(count, quint32(1));
        QCOMPARE(version, quint32(2));
        QCOMPARE(cursors, quint32(1));
        QVERIFY(reader.skip(16)); // invocation id
        reader.align(8);
        quint64 usnHigh = 0;
        quint64 lastSync = 0;
        QVERIFY(reader.u64(&usnHigh));
        QVERIFY(reader.u64(&lastSync));
        QVERIFY(usnHigh > 0);

        // The prefix table: 19 interleaved entries, then the OID bodies.
        quint32 prefixCount = 0;
        QVERIFY(reader.u32(&prefixCount));
        QCOMPARE(prefixCount, quint32(19));
        QVector<quint32> lengths;
        static const quint32 kExpectedNdx[19] = {
            0x00000000u, 0x00000001u, 0x00000002u, 0x00000003u, 0x00000004u,
            0x00000005u, 0x00000006u, 0x00000007u, 0x00000008u, 0x00000009u,
            0x0000000au, 0x00000013u, 0x00000014u, 0x00000015u, 0x00000016u,
            0x00000017u, 0x00000018u, 0x00000019u, 0x0000001au };
        for (int i = 0; i < 19; ++i) {
            quint32 ndx = 0, length = 0, elementsRef = 0;
            QVERIFY(reader.u32(&ndx));
            QVERIFY(reader.u32(&length));
            QVERIFY(reader.u32(&elementsRef));
            QCOMPARE(ndx, kExpectedNdx[i]); // the canonical MS-DRSR 5.12.2 map
            QVERIFY(elementsRef != 0);
            lengths.append(length);
        }
        for (quint32 length : lengths) {
            quint32 maxCount = 0;
            QVERIFY(reader.u32(&maxCount));
            QCOMPARE(maxCount, length);
            QByteArray oid;
            QVERIFY(reader.bytes(int(length), &oid));
        }
        QCOMPARE(lengths.at(0), quint32(Drs::partialBinaryOid("2.5.4").size()));

        // The chain: every object, deep element first, with its attributes.
        QList<ChainEntry> entries;
        QVERIFY(walkChain(&reader, &entries));
        QCOMPARE(entries.size(), 2);

        QCOMPARE(readLe32(reply, reply.size() - 4), quint32(0)); // ErrorCode

        const ChainEntry *domain = nullptr;
        const ChainEntry *user = nullptr;
        for (const ChainEntry &entry : entries) {
            if (entry.dn == QStringLiteral("DC=corp,DC=example,DC=com"))
                domain = &entry;
            if (entry.dn == QStringLiteral(
                    "CN=Administrator,CN=Users,DC=corp,DC=example,DC=com"))
                user = &entry;
        }
        QVERIFY(domain);
        QVERIFY(user);

        // The domain NC head serves name, DN, objectClass, cn, objectGuid and
        // instanceType — six attributes, in that order.
        QCOMPARE(domain->attrCount, quint32(6));
        QCOMPARE(domain->attidsPacked,
                 packed(0x00090001u) + packed(0x00000031u) + packed(0x00000000u)
                     + packed(0x00000003u) + packed(0x00090002u)
                     + packed(0x00020001u));

        // The account: ten attributes in the served order, with their values.
        QCOMPARE(user->attrCount, quint32(10));
        QCOMPARE(user->attidsPacked,
                 packed(0x000900DDu) // sAMAccountName
                     + packed(0x00090092u) // objectSid
                     + packed(0x00090001u) // name
                     + packed(0x00000031u) // distinguishedName
                     + packed(0x00090290u) // userPrincipalName
                     + packed(0x00090008u) // userAccountControl
                     + packed(0x00000000u) // objectClass
                     + packed(0x00000003u) // cn
                     + packed(0x00090002u) // objectGuid
                     + packed(0x00020001u)); // instanceType
        QCOMPARE(user->firstValue.value(0x000900DDu),
                 Ndr::utf16le(QStringLiteral("Administrator")));
        QCOMPARE(user->firstValue.value(0x00090092u),
                 Ndr::sidFromString(QStringLiteral("S-1-5-21-1-2-3-500")));
        QCOMPARE(user->firstValue.value(0x00090008u), packed(512));
        QCOMPARE(user->firstValue.value(0x00000000u),
                 Ndr::utf16le(QStringLiteral("user")));
        QCOMPARE(user->firstValue.value(0x00000031u),
                 Ndr::utf16le(user->dn));
        QCOMPARE(user->firstValue.value(0x00090001u),
                 Ndr::utf16le(QStringLiteral("Administrator")));
        QCOMPARE(user->firstValue.value(0x00020001u), packed(4));
        QCOMPARE(user->firstValue.value(0x00090002u).size(), 16);
    }

    void domainControllerInfoDescribesThisDc()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([this]() { return fixture(); });

        const QByteArray bindReply = server.handleCall(0, bindRequest());
        const QByteArray handle = bindReply.mid(64, 20);
        const QByteArray reply =
            server.handleCall(16, domainControllerInfoRequest(handle));

        Ndr::Reader reader(reply);
        quint32 version = 0, tag = 0, items = 0, itemsRef = 0;
        QVERIFY(reader.u32(&version));
        QVERIFY(reader.u32(&tag));
        QVERIFY(reader.u32(&items));
        QVERIFY(reader.u32(&itemsRef));
        QCOMPARE(version, quint32(2));
        QCOMPARE(tag, quint32(2));
        QCOMPARE(items, quint32(1));
        QVERIFY(itemsRef != 0);

        quint32 maxCount = 0;
        QVERIFY(reader.u32(&maxCount));
        QCOMPARE(maxCount, quint32(1));

        // DS_DOMAIN_CONTROLLER_INFO_2W: seven string referents, three flags.
        QStringList referents;
        for (int i = 0; i < 7; ++i) {
            quint32 ref = 0;
            QVERIFY(reader.u32(&ref));
            QVERIFY(ref != 0);
            referents.append(QString::number(ref));
        }
        for (int i = 0; i < 3; ++i) {
            quint32 flag = 0;
            QVERIFY(reader.u32(&flag));
            QCOMPARE(flag, quint32(1)); // fIsPdc, fDsEnabled, fIsGc
        }

        // Four GUIDs: the site, the computer object, the server object and
        // this DSA's own NTDS Settings GUID — the one a client comes here for.
        reader.skip(48);
        QByteArray ntdsGuid;
        QVERIFY(reader.bytes(16, &ntdsGuid));
        const QUuid expected = Drs::sourceDsaGuid(config().domainSid,
                                                  config().netbios);
        QByteArray expectedBytes;
        appendGuid(expectedBytes, expected);
        QCOMPARE(ntdsGuid, expectedBytes);

        // The seven strings, in field order.
        QCOMPARE(readWideString(&reader), QStringLiteral("CORP"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("corp.corp.example.com"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("Default-First-Site-Name"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("CN=Default-First-Site-Name,CN=Sites,"
                                "CN=Configuration,DC=corp,DC=example,DC=com"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("CN=CORP,OU=Domain Controllers,"
                                "DC=corp,DC=example,DC=com"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("CN=CORP,CN=Servers,CN=Default-First-Site-Name,"
                                "CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("CN=NTDS Settings,CN=CORP,CN=Servers,"
                                "CN=Default-First-Site-Name,CN=Sites,"
                                "CN=Configuration,DC=corp,DC=example,DC=com"));

        QCOMPARE(readLe32(reply, reply.size() - 4), quint32(0)); // ErrorCode
    }

    void crackNamesTranslatesFqdnToCanonical()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([this]() { return fixture(); });

        const QByteArray bindReply = server.handleCall(0, bindRequest());
        const QByteArray handle = bindReply.mid(64, 20);
        const QByteArray reply = server.handleCall(
            12, crackNamesRequest(handle,
                                  QStringLiteral("CN=Administrator,CN=Users,"
                                                 "DC=corp,DC=example,DC=com")));

        Ndr::Reader reader(reply);
        quint32 version = 0, tag = 0, resultRef = 0, items = 0, itemsRef = 0;
        QVERIFY(reader.u32(&version));
        QVERIFY(reader.u32(&tag));
        QVERIFY(reader.u32(&resultRef));
        QVERIFY(reader.u32(&items));
        QVERIFY(reader.u32(&itemsRef));
        QCOMPARE(version, quint32(1));
        QCOMPARE(tag, quint32(1));
        QVERIFY(resultRef != 0);
        QCOMPARE(items, quint32(1));
        QVERIFY(itemsRef != 0);

        quint32 maxCount = 0;
        QVERIFY(reader.u32(&maxCount));
        QCOMPARE(maxCount, quint32(1));
        quint32 status = 0, domainRef = 0, nameRef = 0;
        QVERIFY(reader.u32(&status));
        QVERIFY(reader.u32(&domainRef));
        QVERIFY(reader.u32(&nameRef));
        QCOMPARE(status, quint32(0)); // DRSUAPI_DS_NAME_STATUS_OK
        QVERIFY(domainRef != 0);
        QVERIFY(nameRef != 0);

        QCOMPARE(readWideString(&reader), QStringLiteral("corp.example.com"));
        QCOMPARE(readWideString(&reader),
                 QStringLiteral("corp.example.com/Users/Administrator"));
        QCOMPARE(readLe32(reply, reply.size() - 4), quint32(0)); // ErrorCode
    }

    void refusesCallsOutsideTheImplementedSet()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([this]() { return fixture(); });

        // An unimplemented opnum answers ERROR_INVALID_PARAMETER, not a
        // reply that pretends to be understood.
        const QByteArray unsupported = server.handleCall(5, QByteArray());
        QCOMPARE(unsupported.size(), 4);
        QCOMPARE(readLe32(unsupported, 0), quint32(0x57));

        // A GetNCChanges on a handle that was never bound is refused.
        QByteArray forgedHandle(20, '\x7f');
        const QByteArray invalid = server.handleCall(3, forgedHandle);
        QCOMPARE(invalid.size(), 4);
        QCOMPARE(readLe32(invalid, 0), quint32(0x000006f7)); // ERROR_INVALID_HANDLE
    }
};

#include "test_drs.moc"
QTEST_GUILESS_MAIN(DrsTest)
