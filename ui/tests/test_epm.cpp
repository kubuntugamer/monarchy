// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Epm.h"

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

QByteArray samrUuid()
{
    return QByteArray::fromHex("78 57 34 12 34 12 cd ab ef 00 01 23 45 67 89 ac");
}

QByteArray lsadUuid()
{
    return QByteArray::fromHex("78 57 34 12 34 12 cd ab ef 00 01 23 45 67 89 ab");
}

// ept_lookup as impacket marshals it: inquiry, the object and interface
// referents, the version option, the 20-byte entry handle written in place and
// the maximum entry count. The bytes below are what its `ept_lookup().getData()`
// produced for the all-elements inquiry, so the test pins the layout a real
// client sends rather than one this server would like to receive.
QByteArray impacketLookupAll(quint32 maxEntries = 500)
{
    QByteArray stub;
    appendLe32(stub, 0); // RPC_C_EP_ALL_ELTS
    appendLe32(stub, 0); // object: NULL
    appendLe32(stub, 0); // interface id: NULL
    appendLe32(stub, 1); // RPC_C_VERS_ALL
    stub.append(QByteArray(20, '\0'));
    appendLe32(stub, maxEntries);
    return stub;
}

QByteArray impacketLookupByInterface(const QByteArray &uuid, quint32 maxEntries = 500)
{
    QByteArray stub;
    appendLe32(stub, 1); // RPC_C_EP_MATCH_BY_IF
    appendLe32(stub, 0); // object: NULL
    appendLe32(stub, 0x9dbc); // interface id referent, written at its position
    stub.append(uuid);
    stub.append(QByteArray(4, '\0')); // major, minor
    appendLe32(stub, 1);              // RPC_C_VERS_ALL
    stub.append(QByteArray(20, '\0'));
    appendLe32(stub, maxEntries);
    return stub;
}

// The same call as a client that marshals the handle as a pointer sends it: the
// referent in the fixed part, the structure deferred behind everything else.
QByteArray pointerLookupAll()
{
    QByteArray stub;
    appendLe32(stub, 0);
    appendLe32(stub, 0);
    appendLe32(stub, 0);
    appendLe32(stub, 1);
    appendLe32(stub, 0x00020000); // handle referent
    appendLe32(stub, 500);
    stub.append(QByteArray(20, '\0')); // the handle itself, deferred
    return stub;
}

QList<Epm::Entry> testEntries()
{
    Epm::Entry samr;
    samr.uuid = samrUuid();
    samr.major = 1;
    samr.minor = 0;
    samr.port = 1035;
    samr.annotation = QStringLiteral("samr");

    Epm::Entry lsad;
    lsad.uuid = lsadUuid();
    lsad.major = 0;
    lsad.minor = 0;
    lsad.port = 1036;
    lsad.annotation = QStringLiteral("lsarpc");

    return {samr, lsad};
}

// The fixed size of one entry in a lookup reply: object UUID, tower referent,
// the annotation's offset and length, then the annotation padded to four.
int entryFixedSize(const QString &annotation)
{
    const int bytes = annotation.toUtf8().size() + 1; // the NUL travels
    return 16 + 4 + 4 + 4 + bytes + ((4 - bytes % 4) % 4);
}

} // namespace

class EpmTest : public QObject
{
    Q_OBJECT

private slots:
    void towerIsFiveFloorsWithABigEndianPort();
    void pipeTowerNamesThePipeAndTheHost();
    void lookupAllReturnsEveryEntry();
    void lookupByInterfaceReturnsOnlyThatInterface();
    void acceptsAHandleMarshalledAsAPointer();
    void pagesWhenMoreEntriesExistThanFit();
    void mapsAnInterfaceToItsTower();
    void refusesManagementOpnums();
};

// C706 appendix L: a floor count, then each floor's left-hand side and
// right-hand side with 2-byte lengths. The interface floor names the UUID and
// its major version with the minor on the right; the transport floors end in a
// big-endian port and a big-endian address.
void EpmTest::towerIsFiveFloorsWithABigEndianPort()
{
    Epm::Entry entry;
    entry.uuid = samrUuid();
    entry.major = 1;
    entry.minor = 0;
    entry.port = 1035;

    const QByteArray tower = Epm::tower(entry, QHostAddress(QStringLiteral("10.1.2.3")));
    QCOMPARE(readLe16At(tower, 0), quint16(5));

    // Floor 1: LHS 19 (0x0d, UUID, major), RHS 2 (minor).
    QCOMPARE(readLe16At(tower, 2), quint16(19));
    QCOMPARE(quint8(tower.at(4)), quint8(0x0d));
    QCOMPARE(tower.mid(5, 16), entry.uuid);
    QCOMPARE(readLe16At(tower, 21), quint16(1));
    QCOMPARE(readLe16At(tower, 23), quint16(2));
    QCOMPARE(readLe16At(tower, 25), quint16(0));

    // Each uuid floor is 25 bytes (2 length + 19 + 2 length + 2), each one-byte
    // floor is 7, so floor 2 starts at 2 and floor 3 at 27.
    const int floor2 = 2 + 25;
    const int floor3 = floor2 + 25; // the connection-oriented binder, 0x0b
    QCOMPARE(quint8(tower.at(floor3 + 2)), quint8(0x0b));

    // Floor 4 carries the port big-endian: 1035 is 0x040b.
    const int floor4 = floor3 + 7;
    QCOMPARE(quint8(tower.at(floor4 + 2)), quint8(0x07));
    QCOMPARE(quint8(tower.at(floor4 + 5)), quint8(0x04));
    QCOMPARE(quint8(tower.at(floor4 + 6)), quint8(0x0b));

    // Floor 5 is the IPv4 address, also big-endian.
    const int floor5 = floor4 + 7;
    QCOMPARE(quint8(tower.at(floor5 + 2)), quint8(0x09));
    QCOMPARE(tower.mid(floor5 + 5, 4), QByteArray::fromHex("0a010203"));
}

// An ncacn_np entry puts the pipe name and the host in the last two floors, and
// carries no port: a client matching the tower against `ncacn_np` reads those.
void EpmTest::pipeTowerNamesThePipeAndTheHost()
{
    Epm::Entry entry;
    entry.uuid = samrUuid();
    entry.major = 1;
    entry.minor = 0;
    entry.pipe = QStringLiteral("samr");
    QVERIFY(entry.isPipe());

    const QByteArray tower = Epm::tower(entry, QHostAddress::LocalHost, QStringLiteral("dc1"));
    QCOMPARE(readLe16At(tower, 0), quint16(5));

    // Floor 3 is the binder, floor 4 the pipe (0x0f), floor 5 the host (0x11).
    const int floor3 = 2 + 25 + 25;
    QCOMPARE(quint8(tower.at(floor3 + 2)), quint8(0x0b));
    const int floor4 = floor3 + 7;
    QCOMPARE(quint8(tower.at(floor4 + 2)), quint8(0x0f));
    QCOMPARE(readLe16At(tower, floor4 + 3), quint16(11)); // "\pipe\samr" + NUL
    QCOMPARE(tower.mid(floor4 + 5, 11), QByteArray("\\pipe\\samr\0", 11));
    const int floor5 = floor4 + 2 + 1 + 2 + 11;
    QCOMPARE(quint8(tower.at(floor5 + 2)), quint8(0x11));
    QCOMPARE(tower.mid(floor5 + 5, 4), QByteArray("DC1\0", 4));
}

void EpmTest::lookupAllReturnsEveryEntry()
{
    EpmServer server;
    const QList<Epm::Entry> entries = testEntries();
    server.setEntries(entries);

    const QByteArray reply = server.handleCall(Epm::OpLookup, impacketLookupAll());
    QCOMPARE(readLe32At(reply, 20), 2u);              // num_ents
    QCOMPARE(readLe32At(reply, 24), 500u);            // MaximumCount
    QCOMPARE(readLe32At(reply, 28), 0u);              // Offset
    QCOMPARE(readLe32At(reply, 32), 2u);              // ActualCount
    QCOMPARE(lastWord(reply), 0u);                    // EPMAPPER_STATUS_OK
    // No more pages, so the handle is NULL and the client stops asking.
    QCOMPARE(reply.left(20), QByteArray(20, '\0'));

    // The first entry's fixed part, then its annotation.
    QCOMPARE(readLe32At(reply, 36 + 16), quint32(0x00020000)); // tower referent
    QCOMPARE(readLe32At(reply, 36 + 20), 0u);                  // annotation offset
    QCOMPARE(readLe32At(reply, 36 + 24), 5u);                  // "samr" + NUL
    QCOMPARE(reply.mid(36 + 28, 5), QByteArray("samr\0", 5));

    // The towers are deferred to the end of the reply, in referent order.
    const int secondEntry = 36 + entryFixedSize(QStringLiteral("samr"));
    const int firstTower = secondEntry + entryFixedSize(QStringLiteral("lsarpc"));
    const int firstTowerLength = int(readLe32At(reply, firstTower));
    QCOMPARE(firstTowerLength, Epm::tower(entries.at(0), QHostAddress::LocalHost).size());
    QCOMPARE(reply.mid(firstTower + 8, firstTowerLength),
             Epm::tower(entries.at(0), QHostAddress::LocalHost));
}

void EpmTest::lookupByInterfaceReturnsOnlyThatInterface()
{
    EpmServer server;
    server.setEntries(testEntries());

    const QByteArray reply =
        server.handleCall(Epm::OpLookup, impacketLookupByInterface(lsadUuid()));
    QCOMPARE(readLe32At(reply, 20), 1u);
    QCOMPARE(lastWord(reply), 0u);
    QCOMPARE(readLe32At(reply, 36 + 24), 7u); // "lsarpc" + NUL

    // An interface nobody serves is an empty, successful answer: the caller
    // learns there is no endpoint, which is not an error.
    const QByteArray unknown = server.handleCall(
        Epm::OpLookup,
        impacketLookupByInterface(QByteArray::fromHex("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff")));
    QCOMPARE(readLe32At(unknown, 20), 0u);
    QCOMPARE(lastWord(unknown), 0u);
}

void EpmTest::acceptsAHandleMarshalledAsAPointer()
{
    EpmServer server;
    server.setEntries(testEntries());

    const QByteArray reply = server.handleCall(Epm::OpLookup, pointerLookupAll());
    QCOMPARE(readLe32At(reply, 20), 2u);
    QCOMPARE(lastWord(reply), 0u);
}

void EpmTest::pagesWhenMoreEntriesExistThanFit()
{
    EpmServer server;
    server.setEntries(testEntries());

    const QByteArray first = server.handleCall(Epm::OpLookup, impacketLookupAll(1));
    QCOMPARE(readLe32At(first, 20), 1u);
    // One entry fits, so the handle is not NULL and names the next offset.
    QVERIFY(first.left(20) != QByteArray(20, '\0'));
    QCOMPARE(readLe32At(first, 4), 1u); // the page handle's uuid holds offset 1

    QByteArray second = impacketLookupAll(1);
    second.replace(16, 20, first.left(20)); // send the handle back
    const QByteArray page2 = server.handleCall(Epm::OpLookup, second);
    QCOMPARE(readLe32At(page2, 20), 1u);
    QCOMPARE(page2.left(20), QByteArray(20, '\0')); // that was the last page
    QCOMPARE(readLe32At(page2, 36 + 24), 7u);       // lsarpc, the second entry
}

// ept_map asks which tower serves an interface. The stub below is exactly what
// impacket's `ept_map().getData()` produces for the SAMR interface: the object
// referent, the object it points at (written in place), the tower referent, the
// tower it points at, the 20-byte handle and the maximum tower count.
void EpmTest::mapsAnInterfaceToItsTower()
{
    EpmServer server;
    const QList<Epm::Entry> entries = testEntries();
    server.setEntries(entries);

    const QByteArray request = QByteArray::fromHex(
        "01000000" "00000000000000000000000000000000" "02000000" "4b000000" "4b000000"
        "050013000d785734123412cdabef000123456789ac01000200000013000d045d888aeb1cc9119f"
        "e808002b10486002000200000001000b0200000001000702000000010009040000000000ab0000"
        "00000000000000000000000000000000000000000000");
    QCOMPARE(request.size(), 132);

    const QByteArray reply = server.handleCall(Epm::OpMap, request);
    QCOMPARE(readLe32At(reply, 20), 1u); // num_towers
    QCOMPARE(lastWord(reply), 0u);

    const QByteArray expected = Epm::tower(entries.at(0), QHostAddress::LocalHost);
    QCOMPARE(readLe32At(reply, 40), quint32(expected.size())); // tower_length
    QCOMPARE(reply.mid(48, expected.size()), expected);

    // An interface that is not served returns no tower and says so, which is how
    // a client learns there is nothing to connect to.
    QByteArray unknown = request;
    // The interface UUID sits at 4 (object ref) + 16 (object) + 4 (tower ref) +
    // 8 (length and capacity) + 2 (floor count) + 2 (LHS length) + 1 (0x0d).
    unknown[37] = char(0xaa);
    const QByteArray none = server.handleCall(Epm::OpMap, unknown);
    QCOMPARE(readLe32At(none, 20), 0u);
    QCOMPARE(lastWord(none), quint32(Epm::StatusNoMoreEntries));
}

void EpmTest::refusesManagementOpnums()
{
    EpmServer server;
    server.setEntries(testEntries());

    // Insert, Delete and MgmtDelete change the mapper's table; a DC's table is
    // the interfaces it serves, so they are refused rather than accepted.
    for (quint16 opnum : {quint16(Epm::OpInsert), quint16(Epm::OpDelete),
                          quint16(Epm::OpMgmtDelete)}) {
        const QByteArray reply = server.handleCall(opnum, QByteArray(8, '\0'));
        QCOMPARE(reply.size(), 4);
        QCOMPARE(lastWord(reply), quint32(Epm::StatusCantPerformOp));
    }

    // LookupHandleFree echoes a cleared handle and succeeds.
    const QByteArray freed = server.handleCall(Epm::OpLookupHandleFree, QByteArray(20, '\x01'));
    QCOMPARE(freed.size(), 24);
    QCOMPARE(freed.left(20), QByteArray(20, '\0'));
    QCOMPARE(lastWord(freed), 0u);
}

QTEST_MAIN(EpmTest)
#include "test_epm.moc"
