// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QSet>
#include <QTcpSocket>

#include "LdapServer.h"
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
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    return ldapMessage(id, char(0x63), inner);
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
    void ignoresUnknownOptionalControl();
    void rejectsCookieItDidNotIssue();
    void searchOnMissingBaseIsNoSuchObject();
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

    const QByteArray controls =
        controlsField({control("1.2.840.113556.1.4.999", QByteArray(), true)});
    client.write(searchRequest(1, "DC=corp,DC=example,DC=com", controls));
    const QByteArray message = reader.next();
    QVERIFY(!message.isEmpty());
    QCOMPARE(operationTag(message), 0x65);
    QCOMPARE(resultCode(message), 12); // unavailableCriticalExtension
}

// The same control without the critical flag is ignored, and the search runs.
void LdapTest::ignoresUnknownOptionalControl()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

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

    const auto search = [&](int id, const QByteArray &base, int scope) {
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

QTEST_MAIN(LdapTest)
#include "test_ldap.moc"
