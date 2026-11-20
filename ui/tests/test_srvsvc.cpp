// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Srvsvc.h"

// The replies are pinned byte for byte against stubs produced by an independent
// encoder — Samba's own NDR (samba.dcerpc.srvsvc.NetShareEnum, packed with
// __ndr_pack_out__ for the same values). A reply that puts the union tag, the
// buffer referent, the deferral order of the strings, TotalEntries or the
// resume handle anywhere else decodes in Samba's client as a malformed stub,
// which is exactly the failure this test exists to prevent.
class TestSrvsvc : public QObject
{
    Q_OBJECT

private slots:
    void level1MatchesSambaEncoding();
    void level1EmptyShareList();
    void level2MatchesSambaEncoding();
    void levelBeyondTwoIsInvalidLevel();
    void unknownOpnumIsNotSupported();

private:
    static QByteArray request(quint32 level);
};

static QByteArray hex(const char *text)
{
    return QByteArray::fromHex(text);
}

// The request a client sends for `level`: a ServerName referent, then the
// SHARE_ENUM_STRUCT's level and its union tag. Only the level is read, but the
// stub has to look like the real one for the parse to be exercised.
QByteArray TestSrvsvc::request(quint32 level)
{
    QByteArray out;
    out.append(hex("00000200")); // ServerName referent
    for (int i = 0; i < 4; ++i)
        out.append(char((level >> (8 * i)) & 0xff));
    out.append(out.right(4)); // union tag repeats the level
    out.append(hex("04000200")); // the container the client allocated
    return out;
}

void TestSrvsvc::level1MatchesSambaEncoding()
{
    SrvsvcServer server;
    Srvsvc::Share share;
    share.name = QStringLiteral("SYSVOL");
    share.comment = QStringLiteral("Logon server share");
    server.setShares({share});

    const QByteArray expected = hex(
        "01000000" "01000000" "00000200" "01000000" "04000200" "01000000"
        "08000200" "00000000" "0c000200" "07000000" "00000000" "07000000"
        "53005900" "53005600" "4f004c00" "00000000"
        "13000000" "00000000" "13000000"
        "4c006f00" "67006f00" "6e002000" "73006500" "72007600" "65007200"
        "20007300" "68006100" "72006500" "00000000"
        "01000000" "10000200" "00000000" "00000000");
    const QByteArray actual = server.handleCall(Srvsvc::OpNetrShareEnum, request(1));

    QCOMPARE(actual.size(), expected.size());
    QCOMPARE(actual.toHex(), expected.toHex());
}

void TestSrvsvc::level1EmptyShareList()
{
    SrvsvcServer server;
    server.setShares({});

    // An empty answer still carries a present buffer and a zero MaxCount; a
    // NULL buffer there is what made Samba's decoder read a bad array size.
    const QByteArray expected = hex(
        "01000000" "01000000" "00000200" "00000000" "04000200" "00000000"
        "00000000" "08000200" "00000000" "00000000");
    const QByteArray actual = server.handleCall(Srvsvc::OpNetrShareEnumSticky, request(1));

    QCOMPARE(actual.size(), expected.size());
    QCOMPARE(actual.toHex(), expected.toHex());
}

void TestSrvsvc::level2MatchesSambaEncoding()
{
    SrvsvcServer server;
    Srvsvc::Share share;
    share.name = QStringLiteral("SYSVOL");
    share.comment = QStringLiteral("Logon server share");
    share.path = QStringLiteral("/srv/sysvol");
    server.setShares({share});

    const QByteArray expected = hex(
        "02000000" "02000000" "00000200" "01000000" "04000200" "01000000"
        "08000200" "00000000" "0c000200" "00000000" "ffffffff" "00000000"
        "10000200" "00000000"
        "07000000" "00000000" "07000000"
        "53005900" "53005600" "4f004c00" "00000000"
        "13000000" "00000000" "13000000"
        "4c006f00" "67006f00" "6e002000" "73006500" "72007600" "65007200"
        "20007300" "68006100" "72006500" "00000000"
        "0c000000" "00000000" "0c000000"
        "2f007300" "72007600" "2f007300" "79007300" "76006f00" "6c000000"
        "01000000" "14000200" "00000000" "00000000");
    const QByteArray actual = server.handleCall(Srvsvc::OpNetrShareEnumSticky, request(2));

    QCOMPARE(actual.size(), expected.size());
    QCOMPARE(actual.toHex(), expected.toHex());
}

void TestSrvsvc::levelBeyondTwoIsInvalidLevel()
{
    SrvsvcServer server;
    const QByteArray actual = server.handleCall(Srvsvc::OpNetrShareEnum, request(5));
    QCOMPARE(actual, hex("7c000000"));
}

void TestSrvsvc::unknownOpnumIsNotSupported()
{
    SrvsvcServer server;
    const QByteArray actual = server.handleCall(16, request(2));
    QCOMPARE(actual, hex("32000000"));
}

QTEST_MAIN(TestSrvsvc)
#include "test_srvsvc.moc"
