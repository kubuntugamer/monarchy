// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QSet>
#include <QTcpSocket>
#include <QUdpSocket>

#include "LdapServer.h"
#include "ObjectGuid.h"
#include "Ndr.h"
#include "Ntlm.h"
#include "SampleData.h"
#include "ldap_wire_helpers.h"

using namespace ldapwire;

namespace {

int pagedTotal(const QByteArray &value)
{
    int pos = 0, tag = 0;
    QByteArray sequence, size;
    if (!nextElement(value, &pos, &tag, &sequence) || tag != 0x30)
        return -1;
    pos = 0;
    if (!nextElement(sequence, &pos, &tag, &size) || tag != 0x02)
        return -1;
    int total = 0;
    for (char c : size)
        total = (total << 8) | (unsigned char)c;
    return total;
}

// A search with an explicit scope; the header's searchRequest() is subtree only.
QByteArray scopedSearch(int id, const QByteArray &base, int scope)
{
    QByteArray inner = tlv(0x04, base);
    inner += tlv(char(0x0a), QByteArray(1, char(scope)));
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // derefAliases: never
    inner += tlv(char(0x02), QByteArray(1, char(0))); // sizeLimit: no limit
    inner += tlv(char(0x02), QByteArray(1, char(0))); // timeLimit: no limit
    inner += tlv(char(0x01), QByteArray(1, char(0))); // typesOnly: FALSE
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    return ldapMessage(id, char(0x63), inner);
}

// A search over the whole subtree with an arbitrary filter, which is the shape a
// client uses when it asks for one kind of object.
QByteArray searchWith(int id, const QByteArray &base, const QByteArray &filter)
{
    QByteArray inner = tlv(0x04, base);
    inner += tlv(char(0x0a), QByteArray(1, char(2))); // scope: wholeSubtree
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // derefAliases: never
    inner += tlv(char(0x02), QByteArray(1, char(0))); // sizeLimit: no limit
    inner += tlv(char(0x02), QByteArray(1, char(0))); // timeLimit: no limit
    inner += tlv(char(0x01), QByteArray(1, char(0))); // typesOnly: FALSE
    inner += filter;
    inner += tlv(char(0x30), QByteArray());
    return ldapMessage(id, char(0x63), inner);
}

QByteArray equalitySearch(int id, const QByteArray &base, const QByteArray &type,
                          const QByteArray &value)
{
    return searchWith(id, base, tlv(char(0xa3), tlv(0x04, type) + tlv(0x04, value)));
}

// extensibleMatch: [1] matchingRule, [2] type, [3] matchValue.
QByteArray extensibleMatch(const QByteArray &attr, const QByteArray &rule,
                           const QByteArray &value)
{
    QByteArray body;
    body += tlv(char(0x81), rule);
    body += tlv(char(0x82), attr);
    body += tlv(char(0x83), value);
    return tlv(char(0xa5), body);
}

QByteArray notOf(const QByteArray &filter)
{
    return tlv(char(0xa2), filter);
}

// Sends one search and collects its reply up to and including the done message.
QList<QByteArray> runSearch(QTcpSocket &client, Reader &reader, int id,
                            const QByteArray &base, int scope)
{
    client.write(scopedSearch(id, base, scope));
    QList<QByteArray> messages;
    while (true) {
        const QByteArray message = reader.next();
        if (message.isEmpty())
            break;
        messages.append(message);
        if (operationTag(message) == 0x65)
            break;
    }
    return messages;
}

// A bind with a non-empty DN is what turns a connection from anonymous into
// authenticated. The sample store carries no verifier, so any account name
// authenticates there; a provisioned store verifies the password instead.
void authenticate(QTcpSocket &client, Reader &reader, const QByteArray &dn, int id = 1)
{
    client.write(bindRequest(id, dn, QByteArray("secret")));
    const QByteArray reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(operationTag(reply), 0x61); // bindResponse
    QCOMPARE(resultCode(reply), 0);
}

const char kSampleUserDn[] = "CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com";

// The Windows DC locator's query (MS-ADTS 6.3.1.4.1.1): a baseObject search on
// the root DSE whose filter asserts DnsDomain and the NtVer capabilities it
// speaks. This is the only LDAP query sent over UDP.
QByteArray locatorPing(const QByteArray &domain, int id = 7)
{
    QByteArray filter = tlv(char(0xa0),
                            tlv(char(0xa3), tlv(0x04, "DnsDomain") + tlv(0x04, domain))
                                + tlv(char(0xa3), tlv(0x04, "NtVer")
                                                      + tlv(0x04, QByteArray("\x06\x00\x00\x00", 4))));
    QByteArray inner = tlv(0x04, QByteArray());        // base: the root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // scope: baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // derefAliases: never
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // sizeLimit
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0)));   // typesOnly: FALSE
    inner += filter;
    inner += tlv(char(0x30), QByteArray());             // no attributes named
    return ldapMessage(id, char(0x63), inner);
}

// Samba's locator ping, as `net ads lookup` puts it on the wire: the filter
// asserts NtVer alone and the attribute list names one attribute, NetLogon. A
// client that sends this reads the binary blob in the answer and nothing else,
// so it is the shape that decides whether the DC is findable at all.
QByteArray sambaLocatorPing(int id = 0x0000FB3D)
{
    QByteArray filter = tlv(char(0xa0),
                            tlv(char(0xa3), tlv(0x04, "NtVer")
                                                + tlv(0x04, QByteArray("\x06\x00\x00\x00", 4))));
    QByteArray inner = tlv(0x04, QByteArray());        // base: the root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // scope: baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // derefAliases: never
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // sizeLimit
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0)));   // typesOnly: FALSE
    inner += filter;
    inner += tlv(char(0x30), tlv(0x04, "NetLogon"));    // one attribute named
    return ldapMessage(id, char(0x63), inner);
}

// The ping a Windows 2000 member sends, captured from a live logon: the domain
// as an FQDN with its root dot, and the client's own account facts alongside
// it. The extra clauses are the client's, not the DC's, and must not stop the
// answer; the dotted domain is the same domain the SRV record named.
QByteArray windows2000LocatorPing(const QByteArray &domain, int id = 26)
{
    QByteArray filter = tlv(char(0xa0),
                            tlv(char(0xa3), tlv(0x04, "DnsDomain") + tlv(0x04, domain))
                                + tlv(char(0xa3), tlv(0x04, "Host") + tlv(0x04, "NEURALNODE0"))
                                + tlv(char(0xa3), tlv(0x04, "User") + tlv(0x04, "NEURALNODE0$"))
                                + tlv(char(0xa3), tlv(0x04, "AAC")
                                                      + tlv(0x04, QByteArray("\x80\x00\x00\x00", 4)))
                                + tlv(char(0xa3), tlv(0x04, "DomainSid")
                                                      + tlv(0x04, "S-1-5-21-1-2-3"))
                                + tlv(char(0xa3), tlv(0x04, "DomainGuid")
                                                      + tlv(0x04, "{00000000-0000-0000-0000-000000000000}"))
                                + tlv(char(0xa3), tlv(0x04, "NtVer")
                                                      + tlv(0x04, QByteArray("\x06\x00\x00\x00", 4))));
    QByteArray inner = tlv(0x04, QByteArray());        // base: the root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // scope: baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0)));   // derefAliases: never
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // sizeLimit
    inner += tlv(char(0x02), QByteArray(1, char(0)));   // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0)));   // typesOnly: FALSE
    inner += filter;
    inner += tlv(char(0x30), tlv(0x04, "Netlogon"));    // one attribute named
    return ldapMessage(id, char(0x63), inner);
}

// The GUID a Windows client is told and then matches against the directory, in
// the byte order a GUID wears on the wire.
QByteArray wireGuid(const QUuid &guid)
{
    QByteArray out;
    for (int shift = 0; shift <= 24; shift += 8)
        out.append(char((guid.data1 >> shift) & 0xff));
    out.append(char(guid.data2 & 0xff));
    out.append(char((guid.data2 >> 8) & 0xff));
    out.append(char(guid.data3 & 0xff));
    out.append(char((guid.data3 >> 8) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.append(char(guid.data4[i]));
    return out;
}

// Everything one UDP query gets back, or empty when nothing arrives.
QByteArray udpQuery(quint16 port, const QByteArray &request, int waitMs = 1500)
{
    QUdpSocket client;
    if (client.writeDatagram(request, QHostAddress::LocalHost, port) != request.size())
        return QByteArray();
    // The server lives in this thread, so its socket notifiers only run while
    // the event loop is pumped; a plain waitForReadyRead would block them.
    QByteArray reply;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < waitMs && reply.isEmpty()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        if (!client.hasPendingDatagrams() && !client.waitForReadyRead(20))
            continue;
        while (client.hasPendingDatagrams()) {
            QByteArray buffer;
            buffer.resize(int(client.pendingDatagramSize()));
            const qint64 read = client.readDatagram(buffer.data(), buffer.size());
            if (read <= 0)
                continue;
            buffer.truncate(int(read));
            reply = buffer;
        }
    }
    return reply;
}

void addSampleDomain(LdapServer &server)
{
    DirectoryObject domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.name = QStringLiteral("CORP");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("distinguishedName"), domain.id);
    domain.attributes.insert(QStringLiteral("objectClass"),
                             QStringLiteral("top;domain;domainDNS"));
    server.addObject(domain);
}

} // namespace

class LdapTest : public QObject
{
    Q_OBJECT

private slots:
    void enforcesTheDomainPasswordPolicy();
    void refusesAnExpiredPasswordAtBind();
    void pagesThroughSearchResults();
    void refusesUnknownCriticalControl();
    void acceptsPermissiveModifyControl();
    void objectSidIsBinaryOnTheWire();
    void derivesTheCategoryAndAccountTypeClientsFilterOn();
    void understandsTheBitwiseFiltersAducSends();
    void storesAQuotedUtf16MachinePassword();
    void ignoresUnknownOptionalControl();
    void rejectsCookieItDidNotIssue();
    void searchOnMissingBaseIsNoSuchObject();
    void anonymousSearchesOnlyTheRootDse();
    void simpleBindRecordsTheConnectionIdentity();
    void whoAmIReportsTheBoundIdentity();
    void searchMissingRequiredFieldsIsProtocolError();
    void searchOversizeIntegerIsProtocolError();
    void messageIdWithTheTopBitSetIsEchoed();
    void answersTheDcLocatorPingOverUdp();
    void locatorPingForAnotherDomainIsNoSuchObject();
    void udpIsSilentForAnythingButTheLocatorPing();
};

// The password policy is the domain object's: minPwdLength, pwdHistoryLength and
// pwdProperties, with AD's defaults for a domain that does not carry them. A
// password that breaks it is refused with constraintViolation and the account
// keeps the credential it had, which is what AD does.
void LdapTest::enforcesTheDomainPasswordPolicy()
{
    const QString domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString userDn = QStringLiteral("CN=alice,CN=Users,%1").arg(domainDn);

    DirectoryObject domain;
    domain.id = domainDn;
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));
    domain.attributes.insert(QStringLiteral("minPwdLength"), QStringLiteral("12"));
    domain.attributes.insert(QStringLiteral("pwdHistoryLength"), QStringLiteral("2"));
    domain.attributes.insert(QStringLiteral("pwdProperties"), QStringLiteral("1"));

    DirectoryObject user;
    user.id = userDn;
    user.name = QStringLiteral("alice");
    user.type = QStringLiteral("User");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1001"));

    LdapServer server;
    server.setObjects({domain, user});

    const auto setPassword = [&](const QString &password) {
        LdapServer::ModifyChange change;
        change.operation = 2;
        change.type = QStringLiteral("unicodePwd");
        change.values = QStringList{password};
        change.rawValue = password.toUtf8();
        return server.applyModify(userDn, {change});
    };
    const auto setPolicy = [&](const QString &attribute, const QString &value) {
        LdapServer::ModifyChange change;
        change.operation = 2;
        change.type = attribute;
        change.values = QStringList{value};
        change.rawValue = value.toUtf8();
        QCOMPARE(server.applyModify(domainDn, {change}), 0);
    };

    // Under the 12-character floor, then a password that meets both rules.
    QCOMPARE(setPassword(QStringLiteral("Short1!")), 19);
    QCOMPARE(setPassword(QStringLiteral("correct-horse-9")), 0);
    // One character class only: complexity is on, so letters alone are refused.
    QCOMPARE(setPassword(QStringLiteral("abcdefghijklm")), 19);
    // The current password is in the history, as is the one before it.
    QCOMPARE(setPassword(QStringLiteral("correct-horse-9")), 19);
    QCOMPARE(setPassword(QStringLiteral("An0ther-Passphrase")), 0);
    QCOMPARE(setPassword(QStringLiteral("correct-horse-9")), 19);

    // A policy of no remembered passwords lets the old one come back, and a
    // cleared complexity bit lets letters alone through.
    setPolicy(QStringLiteral("pwdHistoryLength"), QStringLiteral("0"));
    setPolicy(QStringLiteral("pwdProperties"), QStringLiteral("0"));
    setPolicy(QStringLiteral("minPwdLength"), QStringLiteral("8"));
    QCOMPARE(setPassword(QStringLiteral("correct-horse-9")), 0);
    QCOMPARE(setPassword(QStringLiteral("abcdefghijklm")), 0);
    QCOMPARE(setPassword(QStringLiteral("short")), 19);
}

// A bind proves the password before it judges the account, and then answers 49
// for a credential that has aged out — the same answer as a wrong password, so
// an expired account cannot be told apart from a wrong one by a stranger.
void LdapTest::refusesAnExpiredPasswordAtBind()
{
    const QString domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString userDn = QStringLiteral("CN=alice,CN=Users,%1").arg(domainDn);
    const QString password = QStringLiteral("Alice!Password123");

    DirectoryObject domain;
    domain.id = domainDn;
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("maxPwdAge"),
                             QStringLiteral("-36288000000000")); // 42 days

    const auto userWith = [&](const QString &pwdLastSet, const QString &accountControl) {
        DirectoryObject user;
        user.id = userDn;
        user.name = QStringLiteral("alice");
        user.type = QStringLiteral("User");
        user.kind = ObjectKind::User;
        user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
        user.attributes.insert(QStringLiteral("objectSid"),
                               QStringLiteral("S-1-5-21-1-2-3-1001"));
        user.attributes.insert(QStringLiteral("ntHash"),
                               QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
        user.attributes.insert(QStringLiteral("userAccountControl"), accountControl);
        user.attributes.insert(QStringLiteral("pwdLastSet"), pwdLastSet);
        return user;
    };
    const QString stale = QString::number(QDateTime::currentSecsSinceEpoch() - 60 * 86400);

    struct Case {
        QString pwdLastSet;
        QString accountControl;
        int expectedResult;
    };
    const QList<Case> cases = {
        // Sixty days old under a 42-day policy.
        {stale, QStringLiteral("512"), 49},
        // Still fresh: the same password binds.
        {QString::number(QDateTime::currentSecsSinceEpoch()), QStringLiteral("512"), 0},
        // DONT_EXPIRE_PASSWORD keeps a 60-day-old credential usable.
        {stale, QStringLiteral("66048"), 0},
        // pwdLastSet zero is "must change at next logon".
        {QStringLiteral("0"), QStringLiteral("512"), 49},
    };

    for (const Case &entry : cases) {
        LdapServer server;
        server.setObjects({domain, userWith(entry.pwdLastSet, entry.accountControl)});
        QVERIFY(server.listen(0));

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, server.serverPort());
        QVERIFY(client.waitForConnected(3000));
        Reader reader(&client);
        client.write(bindRequest(1, userDn.toUtf8(), password.toUtf8()));
        const QByteArray message = reader.next();
        QVERIFY(!message.isEmpty());
        int tag = 0;
        QByteArray op, controls;
        QVERIFY(splitMessage(message, &tag, &op, &controls));
        QCOMPARE(tag, 0x61); // bindResponse
        int pos = 0, innerTag = 0;
        QByteArray result;
        QVERIFY(nextElement(op, &pos, &innerTag, &result));
        QCOMPARE(innerTag, 0x0a); // ENUMERATED resultCode
        int code = 0;
        for (char c : result)
            code = (code << 8) | (unsigned char)c;
        QCOMPARE(code, entry.expectedResult);
        client.disconnectFromHost();
    }
}

// RFC 2696: a search returns one page at a time, each page announcing the total
// and a cookie that resumes exactly where the previous page stopped.
void LdapTest::pagesThroughSearchResults()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    const QByteArray base("DC=corp,DC=example,DC=com");
    QSet<QString> dns;
    QByteArray cookie;
    int pages = 0;
    int firstPageEntries = -1;
    int reportedTotal = -1;

    for (int page = 0; page < 10; ++page) {
        const QByteArray controls = controlsField(
            {control(kPagedResultsOid, pagedResultsValue(5, cookie))});
        client.write(searchRequest(100 + page, base, controls));

        int entries = 0;
        bool done = false;
        while (!done) {
            const QByteArray message = reader.next();
            QVERIFY(!message.isEmpty());
            const int tag = operationTag(message);
            if (tag == 0x64) {
                dns.insert(entryDn(message));
                ++entries;
                continue;
            }
            QCOMPARE(tag, 0x65); // SearchResultDone
            QCOMPARE(resultCode(message), 0);
            const QByteArray value = pagedResultsValueFromResponse(message);
            QVERIFY2(!value.isEmpty(), "the response carries no paged results control");
            reportedTotal = pagedTotal(value);
            cookie = cookieFromPagedValue(value);
            done = true;
        }
        QVERIFY(entries <= 5);
        if (page == 0)
            firstPageEntries = entries;
        ++pages;
        if (cookie.isEmpty())
            break;
    }

    QCOMPARE(firstPageEntries, 5);
    QCOMPARE(reportedTotal, 12);
    QCOMPARE(pages, 3);
    // Every object exactly once: paging neither repeats nor drops entries.
    QCOMPARE(dns.size(), 12);
}

// A control the server does not implement, marked critical, must be refused.
void LdapTest::refusesUnknownCriticalControl()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    const QByteArray controls =
        controlsField({control("1.2.840.113556.1.4.999", QByteArray(), true)});
    client.write(searchRequest(1, "DC=corp,DC=example,DC=com", controls));
    const QByteArray message = reader.next();
    QVERIFY(!message.isEmpty());
    QCOMPARE(operationTag(message), 0x65);
    QCOMPARE(resultCode(message), 12); // unavailableCriticalExtension
}

// LDAP_SERVER_PERMISSIVE_MODIFY_OID is the one control besides paged results a
// client may mark critical here: `net ads join` sends it when it writes the
// machine account's servicePrincipalName, and refusing it stopped the join.
void LdapTest::acceptsPermissiveModifyControl()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    const QByteArray controls =
        controlsField({control("1.2.840.113556.1.4.1413", QByteArray(), true)});
    client.write(modifyRequest(2, kSampleUserDn, "description",
                               {QByteArray("joined by a real client")}, controls));
    const QByteArray message = reader.next();
    QVERIFY(!message.isEmpty());
    QCOMPARE(operationTag(message), 0x67);
    QCOMPARE(resultCode(message), 0);
}

// AD defines objectSid as a binary SID and objectGUID as sixteen octets. Sending
// the textual "S-1-5-..." made Samba's NDR reader read the '-' as a sub-authority
// count and abandon the join, so the wire form is what this pins down.
void LdapTest::objectSidIsBinaryOnTheWire()
{
    DirectoryObject user;
    user.id = QString::fromLatin1(kSampleUserDn);
    user.name = QStringLiteral("Alice Chen");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    const QString sidText = QStringLiteral("S-1-5-21-1-2-3-1001");
    user.attributes.insert(QStringLiteral("objectSid"), sidText);

    LdapServer server;
    server.setObjects({user});
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    client.write(searchRequest(2, kSampleUserDn));
    const QByteArray message = reader.next();
    QVERIFY(!message.isEmpty());
    QCOMPARE(operationTag(message), 0x64); // searchResEntry

    const QList<QByteArray> values = entryAttribute(message, QByteArray("objectSid"));
    QCOMPARE(values.size(), 1);
    QCOMPARE(values.first(), Ndr::sidFromString(sidText));
    QVERIFY(values.first().startsWith(QByteArray("\x01\x05", 2)));
}

// AD computes a handful of attributes instead of storing them, and its own
// tooling filters on them: `(objectCategory=user)` is what ADUC, realmd and most
// scripts send, and `(sAMAccountType=805306368)` is the principal filter. A
// directory that answers only what it stores returns nothing for either, which
// reads to the client as an empty domain rather than as an unanswerable filter.
void LdapTest::derivesTheCategoryAndAccountTypeClientsFilterOn()
{
    const QString base = QStringLiteral("DC=example,DC=com");
    DirectoryObject domain;
    domain.id = base;
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("objectClass"),
                             QStringLiteral("top;domain;domainDNS"));
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=Alice,%1").arg(base);
    alice.name = QStringLiteral("Alice");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("objectClass"),
                            QStringLiteral("top;person;organizationalPerson;user"));
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1105"));
    DirectoryObject staff;
    staff.id = QStringLiteral("CN=Staff,%1").arg(base);
    staff.name = QStringLiteral("Staff");
    staff.kind = ObjectKind::Group;
    staff.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("top;group"));
    staff.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("staff"));
    staff.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-513"));

    LdapServer server;
    server.setObjects({domain, alice, staff});
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, alice.id.toUtf8());

    const auto search = [&](int id, const QByteArray &type, const QByteArray &value) {
        client.write(equalitySearch(id, base.toUtf8(), type, value));
        QList<QByteArray> hits;
        while (true) {
            const QByteArray message = reader.next();
            if (message.isEmpty())
                break;
            if (operationTag(message) == 0x64)
                hits.append(message);
            if (operationTag(message) == 0x65)
                break;
        }
        return hits;
    };

    // A client that asks for a user by category finds exactly the user, and the
    // account type it reads back is the one AD reports for a normal account.
    QList<QByteArray> hits = search(2, "objectCategory",
                                    "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com");
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), alice.id);
    QCOMPARE(entryAttribute(hits.first(), QByteArray("sAMAccountType")).value(0),
             QByteArray("805306368"));
    QVERIFY(entryAttribute(hits.first(), QByteArray("primaryGroupToken")).isEmpty());

    // ADUC and Get-ADUser name the category by its CN alone rather than by the
    // schema DN, so the same filter written the short way finds the same user.
    hits = search(5, "objectCategory", "person");
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), alice.id);

    // The group answers the group type, and its own RID is the primary group
    // token a member's token list names.
    hits = search(3, "sAMAccountType", "268435456");
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), staff.id);
    QCOMPARE(entryAttribute(hits.first(), QByteArray("primaryGroupToken")).value(0),
             QByteArray("513"));

    // The domain is a domain, not a container, so a client that asks for the
    // domain by category finds it.
    hits = search(4, "objectCategory",
                  "CN=Domain-DNS,CN=Schema,CN=Configuration,DC=example,DC=com");
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), base);
}

// ADUC's own user list ends with a negation of a bitwise extensible match:
//   (&(objectCategory=person)(objectClass=user)
//      (!userAccountControl:1.2.840.113556.1.4.803:=2))
// The extensible match used to fall through to the parser's match-everything
// default, so the negation rejected every user and the page came up empty.
void LdapTest::understandsTheBitwiseFiltersAducSends()
{
    const QByteArray uac = QByteArray("userAccountControl");
    const QByteArray andRule = QByteArray("1.2.840.113556.1.4.803");
    const QByteArray orRule = QByteArray("1.2.840.113556.1.4.804");
    const QString base = QStringLiteral("DC=example,DC=com");

    DirectoryObject domain;
    domain.id = base;
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("objectClass"),
                             QStringLiteral("top;domain;domainDNS"));
    DirectoryObject alice;
    alice.id = QStringLiteral("CN=Alice,CN=Users,%1").arg(base);
    alice.name = QStringLiteral("Alice");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("objectClass"),
                            QStringLiteral("top;person;organizationalPerson;user"));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    DirectoryObject bob;
    bob.id = QStringLiteral("CN=Bob,CN=Users,%1").arg(base);
    bob.name = QStringLiteral("Bob");
    bob.kind = ObjectKind::User;
    bob.attributes.insert(QStringLiteral("objectClass"),
                          QStringLiteral("top;person;organizationalPerson;user"));
    bob.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("514"));

    LdapServer server;
    server.setObjects({domain, alice, bob});
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, alice.id.toUtf8());

    const auto searchFilter = [&](int id, const QByteArray &filter) {
        client.write(searchWith(id, base.toUtf8(), filter));
        QList<QByteArray> hits;
        while (true) {
            const QByteArray message = reader.next();
            if (message.isEmpty())
                break;
            if (operationTag(message) == 0x64)
                hits.append(message);
            if (operationTag(message) == 0x65)
                break;
        }
        return hits;
    };

    // The disabled accounts, which is the positive form of the same filter.
    QList<QByteArray> hits = searchFilter(6, extensibleMatch(uac, andRule, "2"));
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), bob.id);

    // The enabled list as ADUC writes it: users, minus the disabled bit.
    const QByteArray aduc =
        tlv(char(0xa0), tlv(char(0xa3), tlv(0x04, QByteArray("objectClass"))
                                          + tlv(0x04, QByteArray("user")))
                           + notOf(extensibleMatch(uac, andRule, "2")));
    hits = searchFilter(7, aduc);
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), alice.id);

    // The OR rule is the other one AD sends: any of the asserted bits set. The
    // disabled account has bit 2 of 3, the enabled one has none of them.
    hits = searchFilter(8, extensibleMatch(uac, orRule, "3"));
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), bob.id);

    // Range filters are evaluated, not widened to the whole subtree.
    hits = searchFilter(9, tlv(char(0xa8), tlv(0x04, uac) + tlv(0x04, QByteArray("512"))));
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), alice.id);
    hits = searchFilter(10, tlv(char(0xa6), tlv(0x04, uac) + tlv(0x04, QByteArray("513"))));
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), bob.id);

    // An approximate match is an equality to AD, and a client that writes one
    // for an attribute the store cannot approximate used to get everything.
    hits = searchFilter(11, tlv(char(0xa9), tlv(0x04, QByteArray("cn"))
                                            + tlv(0x04, QByteArray("alice"))));
    QCOMPARE(hits.size(), 1);
    QCOMPARE(entryDn(hits.first()), alice.id);
}

// The same control without the critical flag is ignored, and the search runs.
// AD writes unicodePwd as a quoted UTF-16LE string, and `net ads join` sets the
// machine account's password that way in its LDAP add. The quotes have to come
// off *after* decoding: in that form the first byte is 0x22 but the last byte is
// the top half of the closing quote, so testing the bytes finds no pair and both
// quotes stay in the password. The account then holds a secret one character
// longer than the one the machine derived its keys from, and the kinit the join
// runs seconds later fails on preauthentication — which is exactly how this was
// found.
void LdapTest::storesAQuotedUtf16MachinePassword()
{
    const QString domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString machineDn = QStringLiteral("CN=BOX,CN=Computers,%1").arg(domainDn);
    const QString password = QStringLiteral("Mach!neP@ss1");

    DirectoryObject domain;
    domain.id = domainDn;
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));

    DirectoryObject machine;
    machine.id = machineDn;
    machine.name = QStringLiteral("BOX");
    machine.type = QStringLiteral("Computer");
    machine.kind = ObjectKind::Computer;
    machine.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("BOX$"));
    // The spelling `net ads join` uses: DnsHostName, not dNSHostName.
    machine.attributes.insert(QStringLiteral("DnsHostName"),
                              QStringLiteral("BOX.corp.example.com"));

    LdapServer server;
    server.setObjects({domain, machine});

    // A quoted UTF-16LE value: 0x22 0x00, the characters, 0x22 0x00.
    QByteArray quoted("\x22\x00", 2);
    quoted.append(Ndr::utf16le(password));
    quoted.append("\x22\x00", 2);

    LdapServer::ModifyChange change;
    change.operation = 2;
    change.type = QStringLiteral("unicodePwd");
    change.values = QStringList{password};
    change.rawValue = quoted;
    QCOMPARE(server.applyModify(machineDn, {change}), 0);

    QString ntHash;
    for (const DirectoryObject &object : server.objects()) {
        if (object.id.compare(machineDn, Qt::CaseInsensitive) == 0)
            ntHash = object.attributes.value(QStringLiteral("ntHash"));
    }
    // The hash of the password itself, which is what the machine knows. Had the
    // quotes stayed in, this would be the hash of the quoted string instead.
    QCOMPARE(ntHash, QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
    const QString quotedPassword = QStringLiteral("\"") + password;
    QVERIFY(ntHash != QString::fromLatin1(Ntlm::ntowfV1(quotedPassword).toHex()));
}

void LdapTest::ignoresUnknownOptionalControl()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    const QByteArray controls =
        controlsField({control("1.2.840.113556.1.4.999", QByteArray(), false)});
    client.write(searchRequest(1, "DC=corp,DC=example,DC=com", controls));

    int entries = 0;
    while (true) {
        const QByteArray message = reader.next();
        QVERIFY(!message.isEmpty());
        const int tag = operationTag(message);
        if (tag == 0x64) {
            ++entries;
            continue;
        }
        QCOMPARE(tag, 0x65);
        QCOMPARE(resultCode(message), 0);
        break;
    }
    QCOMPARE(entries, 12);
}

// A cookie from a search this connection never started cannot resume anything.
void LdapTest::rejectsCookieItDidNotIssue()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, kSampleUserDn);

    const QByteArray forged("ABCDEFGHIJKL"); // 12 bytes: id + offset, but never issued
    const QByteArray controls =
        controlsField({control(kPagedResultsOid, pagedResultsValue(5, forged))});
    client.write(searchRequest(1, "DC=corp,DC=example,DC=com", controls));
    const QByteArray message = reader.next();
    QVERIFY(!message.isEmpty());
    QCOMPARE(operationTag(message), 0x65);
    QCOMPARE(resultCode(message), 53); // unwillingToPerform
}

// RFC 4511 §4.5.1: a search whose base names no entry is noSuchObject, not an
// empty success. Search was the only operation that skipped that check, so a
// client validating a DN (a referral chase, a FSMO owner, a replication target)
// was told the object exists and is empty.
void LdapTest::searchOnMissingBaseIsNoSuchObject()
{
    const QString domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString usersDn = QStringLiteral("CN=Users,%1").arg(domainDn);
    const QString emptyDn = QStringLiteral("OU=Empty,%1").arg(domainDn);

    DirectoryObject domain;
    domain.id = domainDn;
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;

    DirectoryObject users;
    users.id = usersDn;
    users.name = QStringLiteral("Users");
    users.type = QStringLiteral("container");
    users.kind = ObjectKind::Container;

    DirectoryObject alice;
    alice.id = QStringLiteral("CN=alice,%1").arg(usersDn);
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;

    // Exists, has no children: the case that must stay an empty success.
    DirectoryObject empty;
    empty.id = emptyDn;
    empty.name = QStringLiteral("Empty");
    empty.type = QStringLiteral("organizationalUnit");
    empty.kind = ObjectKind::Container;

    LdapServer server;
    server.setObjects({domain, users, alice, empty});
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    authenticate(client, reader, alice.id.toUtf8());

    const auto search = [&](int id, const QByteArray &base, int scope) {
        return runSearch(client, reader, id, base, scope);
    };

    // Missing entry inside a naming context the server holds: every scope is
    // noSuchObject, and no entry precedes the done message.
    for (int scope = 0; scope <= 2; ++scope) {
        const QList<QByteArray> reply =
            search(10 + scope, QStringLiteral("CN=nobody,%1").arg(usersDn).toUtf8(), scope);
        QCOMPARE(reply.size(), 1);
        QCOMPARE(operationTag(reply.first()), 0x65);
        QCOMPARE(resultCode(reply.first()), 32);
    }

    // A naming context the server does not hold at all.
    for (int scope = 0; scope <= 2; ++scope) {
        const QList<QByteArray> reply =
            search(20 + scope, "DC=nosuchdomain,DC=example,DC=com", scope);
        QCOMPARE(reply.size(), 1);
        QCOMPARE(resultCode(reply.first()), 32);
    }

    // The configuration partition shares the DN suffix, and is checked apart.
    {
        const QList<QByteArray> reply = search(
            30, "CN=nobody,CN=Configuration,DC=corp,DC=example,DC=com", 0);
        QCOMPARE(reply.size(), 1);
        QCOMPARE(resultCode(reply.first()), 32);
    }

    // A subtree search includes its base, so a container with no children answers
    // one entry — itself — and success. It must not be noSuchObject.
    {
        const QList<QByteArray> reply = search(31, emptyDn.toUtf8(), 2);
        QCOMPARE(reply.size(), 2);
        QCOMPARE(operationTag(reply.first()), 0x64);
        QCOMPARE(entryDn(reply.first()), emptyDn);
        QCOMPARE(resultCode(reply.last()), 0);
    }

    // An existing base still answers itself and its children.
    {
        const QList<QByteArray> reply = search(32, usersDn.toUtf8(), 2);
        QCOMPARE(reply.size(), 3);
        QCOMPARE(resultCode(reply.last()), 0);
        QSet<QString> returned;
        for (const QByteArray &message : reply) {
            if (operationTag(message) == 0x64)
                returned.insert(entryDn(message));
        }
        QVERIFY((returned == QSet<QString>{usersDn, alice.id}));
    }

    // The root DSE is synthesized rather than stored, so the empty base is never
    // missing and stays answerable, as RFC 4512 requires.
    {
        const QList<QByteArray> reply = search(33, QByteArray(), 0);
        QCOMPARE(reply.size(), 2);
        QCOMPARE(operationTag(reply.first()), 0x64);
        QCOMPARE(resultCode(reply.last()), 0);
    }
}

// Anonymous may read the root DSE and nothing else: every non-empty base, at
// every scope, is an explicit refusal rather than an empty success, and zero
// entries precede the done message. AD has behaved this way since Server 2003,
// and an empty success let a stranger count the directory.
void LdapTest::anonymousSearchesOnlyTheRootDse()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    for (int scope = 0; scope <= 2; ++scope) {
        const QList<QByteArray> reply =
            runSearch(client, reader, 10 + scope, "DC=corp,DC=example,DC=com", scope);
        QCOMPARE(reply.size(), 1);
        QCOMPARE(operationTag(reply.first()), 0x65);
        QCOMPARE(resultCode(reply.first()), 50); // insufficientAccessRights
    }

    // The root DSE is synthesized and answers on the empty base, which is how a
    // client learns the naming context before it has credentials. Requiring a
    // bind here would break that discovery step.
    const QList<QByteArray> rootDse = runSearch(client, reader, 20, QByteArray(), 0);
    QCOMPARE(rootDse.size(), 2);
    QCOMPARE(operationTag(rootDse.first()), 0x64);
    QVERIFY(entryDn(rootDse.first()).isEmpty());
    QCOMPARE(resultCode(rootDse.last()), 0);
}

// A simple bind has to record the connection's identity, or gating reads on it
// would refuse every simple-bind client — the common case and most LDAP tooling.
// A refused or anonymous bind must clear it, because the connection's rights are
// those of its latest bind, not of the one that once succeeded.
void LdapTest::simpleBindRecordsTheConnectionIdentity()
{
    const QString domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString aliceDn = QStringLiteral("CN=alice,CN=Users,%1").arg(domainDn);
    const QString password = QStringLiteral("Alice!Password123");

    DirectoryObject domain;
    domain.id = domainDn;
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;

    DirectoryObject alice;
    alice.id = aliceDn;
    alice.name = QStringLiteral("alice");
    alice.type = QStringLiteral("User");
    alice.kind = ObjectKind::User;
    alice.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    alice.attributes.insert(QStringLiteral("ntHash"),
                            QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
    alice.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    alice.attributes.insert(QStringLiteral("pwdLastSet"),
                            QString::number(QDateTime::currentSecsSinceEpoch()));

    LdapServer server;
    server.setObjects({domain, alice});
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    // Before any bind the base is unreadable.
    QList<QByteArray> reply = runSearch(client, reader, 10, domainDn.toUtf8(), 2);
    QCOMPARE(reply.size(), 1);
    QCOMPARE(resultCode(reply.first()), 50);

    // A wrong password is refused, and the failed bind leaves the connection
    // anonymous rather than authenticated as the account it named.
    client.write(bindRequest(2, aliceDn.toUtf8(), QByteArray("wrong-password")));
    QCOMPARE(resultCode(reader.next()), 49);
    reply = runSearch(client, reader, 11, domainDn.toUtf8(), 2);
    QCOMPARE(reply.size(), 1);
    QCOMPARE(resultCode(reply.first()), 50);

    // The right password authenticates, and the same search runs unchanged.
    client.write(bindRequest(3, aliceDn.toUtf8(), password.toUtf8()));
    QCOMPARE(resultCode(reader.next()), 0);
    reply = runSearch(client, reader, 12, domainDn.toUtf8(), 2);
    QCOMPARE(reply.size(), 3);
    QSet<QString> returned;
    for (const QByteArray &message : reply) {
        if (operationTag(message) == 0x64)
            returned.insert(entryDn(message));
    }
    QVERIFY((returned == QSet<QString>{domainDn, aliceDn}));
    QCOMPARE(resultCode(reply.last()), 0);

    // An anonymous bind replaces the identity, so the read is refused again.
    client.write(bindRequest(4, QByteArray(), QByteArray()));
    QCOMPARE(resultCode(reader.next()), 0);
    reply = runSearch(client, reader, 13, domainDn.toUtf8(), 2);
    QCOMPARE(reply.size(), 1);
    QCOMPARE(resultCode(reply.first()), 50);
}

// A SearchRequest that carries only the base, the scope and the filter is not a
// request the server may answer: RFC 4511 §4.5.1.1 requires derefAliases,
// sizeLimit, timeLimit and typesOnly between the scope and the filter. Before
// the parser checked tags, the presence filter's "objectClass" value was read
// as derefAliases, the remaining fields were filled with zeros from whatever
// followed, and the search succeeded on a malformed request.
// RFC 4532 WhoAmI: a client asks what it is bound as. The empty `dn:` answered
// unconditionally told every client the same thing — nothing — so a session that
// had bound could neither learn its own identity nor tell that it had one.
void LdapTest::whoAmIReportsTheBoundIdentity()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    // Anonymous answers the empty authzid, the form RFC 4532 defines for a
    // connection that has not bound.
    client.write(whoAmIRequest(2));
    QByteArray reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(operationTag(reply), 0x78); // extendedResponse
    QCOMPARE(resultCode(reply), 0);
    QCOMPARE(extendedResponseValue(reply), QByteArray("dn:"));

    // Bound, it names the entry the connection is bound as — the same DN the
    // read side gates on, not the name the client happened to send.
    authenticate(client, reader, kSampleUserDn, 3);
    client.write(whoAmIRequest(4));
    reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(resultCode(reply), 0);
    QCOMPARE(extendedResponseValue(reply), QByteArray("dn:") + QByteArray(kSampleUserDn));

    // A later anonymous bind replaces the identity, so the answer follows it
    // back to empty rather than keeping the account it once held.
    client.write(bindRequest(5, QByteArray(), QByteArray()));
    QCOMPARE(resultCode(reader.next()), 0);
    client.write(whoAmIRequest(6));
    reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(extendedResponseValue(reply), QByteArray("dn:"));
}

void LdapTest::searchMissingRequiredFieldsIsProtocolError()
{
    LdapServer server;
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    QByteArray inner = tlv(0x04, QByteArray()); // root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // scope: baseObject
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    client.write(ldapMessage(1, char(0x63), inner));

    const QByteArray reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(operationTag(reply), 0x65); // searchResDone
    QCOMPARE(resultCode(reply), 2); // protocolError
}

// Every field present and correctly ordered, but sizeLimit is five bytes: wider
// than the four decodeInt can hold, so it would otherwise truncate silently.
void LdapTest::searchOversizeIntegerIsProtocolError()
{
    LdapServer server;
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    QByteArray inner = tlv(0x04, QByteArray()); // root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // scope: baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // derefAliases: never
    inner += tlv(char(0x02), QByteArray(5, char(0x7f))); // sizeLimit: 5 bytes
    inner += tlv(char(0x02), QByteArray(1, char(0))); // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0))); // typesOnly
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    client.write(ldapMessage(1, char(0x63), inner));

    const QByteArray reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(operationTag(reply), 0x65); // searchResDone
    QCOMPARE(resultCode(reply), 2); // protocolError
}

// The id is a client-supplied INTEGER that can carry the top bit set, and every
// suite sent a small one, so the path that accumulates into the sign bit was
// never walked. The reply must carry the same four bytes back.
void LdapTest::messageIdWithTheTopBitSetIsEchoed()
{
    LdapServer server;
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    QByteArray inner = tlv(0x04, QByteArray()); // root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // scope: baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0))); // derefAliases: never
    inner += tlv(0x02, QByteArray(1, char(0))); // sizeLimit
    inner += tlv(0x02, QByteArray(1, char(0))); // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0))); // typesOnly
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray()); // no attributes requested
    const int id = -1; // encodes as 0xFFFFFFFF
    client.write(ldapMessage(id, char(0x63), inner));

    const QByteArray reply = reader.next();
    QVERIFY(!reply.isEmpty());
    QCOMPARE(messageId(reply), id);
    QCOMPARE(operationTag(reply), 0x65); // searchResDone, not a refusal
}

// DsGetDcName follows a DC's SRV record and then pings UDP/389 to satisfy
// itself that the machine really hosts the domain; a candidate that stays
// silent is discarded and the client reports ERROR_NO_SUCH_DOMAIN, so this is
// the difference between a directory and a directory a Windows client can find.
void LdapTest::answersTheDcLocatorPingOverUdp()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    addSampleDomain(server);
    LdapServer::Identity identity;
    identity.realm = QStringLiteral("CORP.EXAMPLE.COM");
    identity.netbios = QStringLiteral("CORP");
    identity.dnsDomain = QStringLiteral("corp.example.com");
    identity.dcHost = QStringLiteral("dc1.corp.example.com");
    identity.siteName = QStringLiteral("Default-First-Site-Name");
    server.setIdentity(identity);
    QVERIFY(server.listen(0));
    QVERIFY2(server.cldapListening(), "no CLDAP listener was bound");
    // The locator sends the ping to the same port number as LDAP.
    QCOMPARE(server.cldapPort(), server.serverPort());

    const QByteArray direct = server.cldapResponse(locatorPing("corp.example.com"));
    QVERIFY2(!direct.isEmpty(), "cldapResponse returned nothing for a valid ping");
    const QByteArray reply = udpQuery(server.cldapPort(), locatorPing("corp.example.com"));
    QVERIFY2(!reply.isEmpty(), "the locator ping went unanswered");
    QCOMPARE(operationTag(reply), 0x64); // searchResEntry
    QCOMPARE(messageId(reply), 7);

    // The answer is two LDAPMessages back to back — the entry, then the result —
    // each its own SEQUENCE. Wrapping both in one SEQUENCE is not an LDAPMessage:
    // a client decodes the message id, finds no searchResDone after it, and drops
    // the answer. This server did exactly that until `net ads lookup` was driven
    // against it, because the only decoder reading the answer was its own.
    QList<QByteArray> messages;
    int pos = 0;
    while (pos < reply.size()) {
        const int start = pos;
        int tag = 0;
        QByteArray body;
        QVERIFY2(nextElement(reply, &pos, &tag, &body), "a message did not parse");
        QCOMPARE(tag, 0x30);
        messages.append(reply.mid(start, pos - start));
    }
    QCOMPARE(messages.size(), 2);
    QCOMPARE(operationTag(messages.at(0)), 0x64);
    QCOMPARE(operationTag(messages.at(1)), 0x65);
    QCOMPARE(messageId(messages.at(1)), 7);
    QCOMPARE(messages.at(0) + messages.at(1), reply);

    // The ping a Windows 2000 member sends. Its domain carries the root dot and
    // its filter also names its own Host, User, AAC, DomainSid and DomainGuid;
    // the answer has to be the entry, not noSuchObject, or the logon stops with
    // "the domain is not available" before any Netlogon call.
    const QByteArray win2000 =
        udpQuery(server.cldapPort(), windows2000LocatorPing("corp.example.com."));
    QVERIFY2(!win2000.isEmpty(), "a Windows 2000 locator ping went unanswered");
    QCOMPARE(operationTag(win2000), 0x64); // searchResEntry
    QVERIFY(win2000.contains("Netlogon"));

    // What the client reads to decide this DC hosts the domain.
    QVERIFY(reply.contains("DnsDomain"));
    QVERIFY(reply.contains("corp.example.com"));
    QVERIFY(reply.contains("DnsForestName"));
    QVERIFY(reply.contains("DcSiteName"));
    QVERIFY(reply.contains("NetbiosDomainName"));
    QVERIFY(reply.contains("CORP"));
    QVERIFY(reply.contains("HostName"));
    QVERIFY(reply.contains("dc1.corp.example.com"));
    QVERIFY(reply.contains("NtVer"));
    QVERIFY(reply.contains(QByteArray("\x06\x00\x00\x00", 4)));
    QVERIFY(reply.contains("LdapService"));
    // The domain GUID the client is told is the one the directory publishes for
    // the same object, so a join can match them up.
    QVERIFY(reply.contains("DomainGuid"));
    QVERIFY(reply.contains(wireGuid(objectGuidFor(QStringLiteral("DC=corp,DC=example,DC=com")))));

    // Samba's ping asks for one attribute, so the entry carries one: its client
    // rejects any answer whose entry is not exactly one attribute called
    // netlogon, and the blob below is what it then reads.
    const QByteArray strict = udpQuery(server.cldapPort(), sambaLocatorPing());
    QVERIFY2(!strict.isEmpty(), "Samba's ping went unanswered");
    QVERIFY(strict.contains("Netlogon"));
    QVERIFY2(!strict.contains("DnsDomain"),
             "the answer carried an attribute the ping did not ask for");

    // NETLOGON_SAM_LOGON_RESPONSE_EX, as Samba's nbt.idl defines it with
    // NDR_NOALIGN. The command word, then the capability word with no 2008+ bits
    // (the domain records no functional level), and the two legacy tokens at the
    // end, which a client checks before it reads anything above them.
    QVERIFY(strict.contains(QByteArray("\x17\x00" "\x00\x00" "\xbd\x01\x00\x00", 8)));
    QVERIFY(strict.contains(QByteArray("\x05\x00\x00\x00\xff\xff\xff\xff", 8)));
    // The strings are DNS label lists — a length byte per label and a closing
    // NUL — not UTF-16 and not NUL-terminated text, which is the part the wire
    // documentation does not say out loud.
    QVERIFY(strict.contains(QByteArray("\x04" "corp" "\x07" "example" "\x03" "com" "\x00", 18)));
    QVERIFY(strict.contains(QByteArray("\x03" "dc1" "\x04" "corp" "\x07" "example" "\x03" "com\x00", 22)));
    QVERIFY(strict.contains(QByteArray("\x04" "CORP" "\x00", 6)));
    QVERIFY(strict.contains(QByteArray("\x03" "DC1" "\x00", 5)));
}

// The ping names the domain it is looking for. Answering a different name
// would claim this DC hosts somebody else's namespace.
void LdapTest::locatorPingForAnotherDomainIsNoSuchObject()
{
    LdapServer server;
    LdapServer::Identity identity;
    identity.dnsDomain = QStringLiteral("corp.example.com");
    identity.netbios = QStringLiteral("CORP");
    identity.dcHost = QStringLiteral("dc1.corp.example.com");
    server.setIdentity(identity);
    QVERIFY(server.listen(0));

    const QByteArray reply = udpQuery(server.cldapPort(), locatorPing("other.example.com"));
    QVERIFY(!reply.isEmpty());
    QCOMPARE(operationTag(reply), 0x65); // searchResDone only
    QCOMPARE(resultCode(reply), 32);     // noSuchObject
}

// RFC 4511 dropped LDAP over UDP; only the locator ping survives on it. A
// search that is not a ping must not be answered, because a reply would tell a
// client that a transport it does not implement works.
void LdapTest::udpIsSilentForAnythingButTheLocatorPing()
{
    LdapServer server;
    LdapServer::Identity identity;
    identity.dnsDomain = QStringLiteral("corp.example.com");
    server.setIdentity(identity);
    QVERIFY(server.listen(0));

    QByteArray inner = tlv(0x04, QByteArray());          // root DSE
    inner += tlv(char(0x0a), QByteArray(1, char(0)));    // baseObject
    inner += tlv(char(0x0a), QByteArray(1, char(0)));    // derefAliases
    inner += tlv(char(0x02), QByteArray(1, char(0)));    // sizeLimit
    inner += tlv(char(0x02), QByteArray(1, char(0)));    // timeLimit
    inner += tlv(char(0x01), QByteArray(1, char(0)));    // typesOnly
    inner += tlv(char(0x87), QByteArray("objectClass")); // plain present filter
    inner += tlv(char(0x30), QByteArray());
    const QByteArray reply = udpQuery(server.cldapPort(), ldapMessage(1, char(0x63), inner), 700);
    QVERIFY2(reply.isEmpty(), "a non-locator search was answered over UDP");
}

QTEST_MAIN(LdapTest)
#include "test_ldap.moc"
