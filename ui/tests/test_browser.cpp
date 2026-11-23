// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Browser.h"

// The browser endpoint exists because of what its absence did: a Windows 2000
// member's logon opens \pipe\browser to enumerate the domain, and an open
// refused with STATUS_OBJECT_NAME_NOT_FOUND stopped that logon before any
// Netlogon call. The endpoint answers the interface and refuses the call by
// status, which is a defined answer a client acts on; the tests pin the identity
// and the refusal, not an invented enumeration.
class TestBrowser : public QObject
{
    Q_OBJECT

private slots:
    void interfaceIsTheBrowserUuid();
    void queryOtherDomainsAnswersAnEmptyList();
    void netServerEnumIsRefusedByStatus();
};

void TestBrowser::interfaceIsTheBrowserUuid()
{
    const Rpc::Interface browser = Browser::interface();
    QCOMPARE(browser.uuid.toHex(), QByteArray("98d0ff6b12a110369833012892020162"));
    QCOMPARE(browser.major, quint16(0));
    QCOMPARE(browser.minor, quint16(0));
    QCOMPARE(browser.name, QStringLiteral("browser"));
}

void TestBrowser::queryOtherDomainsAnswersAnEmptyList()
{
    BrowserServer server;
    const QByteArray reply = server.handleCall(Browser::OpQueryOtherDomains, QByteArray());
    // The empty SERVER_ENUM at level 100 MS-BRWS 3.1.4.1 asks for, with the
    // [out] TotalEntries that follows it: two present pointers for the enum, the
    // container's own present pointer, the count's, then the empty container and
    // NERR_Success. Pinned byte for byte because a reply that omits the out
    // parameters is the packet tshark called malformed.
    const QByteArray expected = QByteArray::fromHex(
        "00000200"  // InfoStruct present
        "64000000"  // Level 100
        "04000200"  // Level100 present
        "08000200"  // TotalEntries present
        "00000000"  // EntriesRead
        "00000000"  // Buffer NULL
        "00000000"  // TotalEntries
        "00000000"); // NERR_Success
    QCOMPARE(reply.toHex(), expected.toHex());
}

void TestBrowser::netServerEnumIsRefusedByStatus()
{
    BrowserServer server;
    const QByteArray reply = server.handleCall(Browser::OpNetServerEnum, QByteArray());
    // A four-byte WERROR, little endian: ERROR_NOT_SUPPORTED.
    QCOMPARE(reply, QByteArray("\x32\x00\x00\x00", 4));
    // An opnum this endpoint has never had answered the same way, so a client
    // that guesses one learns the same thing.
    QCOMPARE(server.handleCall(9, QByteArray()), QByteArray("\x32\x00\x00\x00", 4));
}

QTEST_MAIN(TestBrowser)
#include "test_browser.moc"
