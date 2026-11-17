// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QElapsedTimer>
#include <QFile>
#include <QHash>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QUdpSocket>

#include "DnsServer.h"

namespace {

void put16(QByteArray &out, quint16 value)
{
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void put32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

bool take16(const QByteArray &data, int &pos, quint16 *out)
{
    if (pos < 0 || pos + 2 > data.size())
        return false;
    *out = quint16((quint8(data[pos]) << 8) | quint8(data[pos + 1]));
    pos += 2;
    return true;
}

bool take32(const QByteArray &data, int &pos, quint32 *out)
{
    if (pos < 0 || pos + 4 > data.size())
        return false;
    *out = (quint32(quint8(data[pos])) << 24) | (quint32(quint8(data[pos + 1])) << 16)
           | (quint32(quint8(data[pos + 2])) << 8) | quint32(quint8(data[pos + 3]));
    pos += 4;
    return true;
}

QByteArray nameBytes(const QString &name)
{
    QByteArray out;
    for (const QString &label : name.split(QLatin1Char('.'), Qt::SkipEmptyParts)) {
        const QByteArray bytes = label.toUtf8();
        out.append(char(bytes.size()));
        out.append(bytes);
    }
    out.append('\0');
    return out;
}

QString readName(const QByteArray &packet, int &pos)
{
    QStringList labels;
    int after = -1;
    int cursor = pos;
    for (int guard = 0; guard < 128; ++guard) {
        if (cursor < 0 || cursor >= packet.size())
            break;
        const quint8 len = quint8(packet[cursor]);
        if (len == 0) {
            if (after < 0)
                after = cursor + 1;
            break;
        }
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.size())
                break;
            if (after < 0)
                after = cursor + 2;
            cursor = ((len & 0x3f) << 8) | quint8(packet[cursor + 1]);
            continue;
        }
        if (cursor + 1 + len > packet.size())
            break;
        labels.append(QString::fromUtf8(packet.mid(cursor + 1, len)));
        cursor += 1 + len;
    }
    pos = after < 0 ? packet.size() : after;
    return labels.join(QLatin1Char('.'));
}

bool skipName(const QByteArray &data, int &pos)
{
    for (int guard = 0; guard < 128; ++guard) {
        if (pos >= data.size())
            return false;
        const quint8 len = quint8(data[pos]);
        if (len == 0) {
            ++pos;
            return true;
        }
        if ((len & 0xc0) != 0)
            return false;
        pos += 1 + len;
    }
    return false;
}

struct Answer {
    QString name;
    quint16 type = 0;
    quint16 rclass = 0;
    quint32 ttl = 0;
    QByteArray rdata;
};

struct Reply {
    quint16 id = 0;
    int rcode = -1;
    quint16 qdcount = 0;
    bool truncated = false;
    QList<Answer> answers;
    QList<Answer> authority;
    QList<Answer> additional;
    bool parsed = false;
};

bool parseReply(const QByteArray &packet, Reply *reply)
{
    int pos = 0;
    quint16 id = 0;
    quint16 flags = 0;
    quint16 qdcount = 0;
    quint16 ancount = 0;
    quint16 nscount = 0;
    quint16 arcount = 0;
    quint16 ignored = 0;
    if (!take16(packet, pos, &id) || !take16(packet, pos, &flags) || !take16(packet, pos, &qdcount)
        || !take16(packet, pos, &ancount) || !take16(packet, pos, &nscount)
        || !take16(packet, pos, &arcount))
        return false;
    reply->id = id;
    reply->rcode = flags & 0x0f;
    reply->truncated = (flags & 0x0200) != 0;
    reply->qdcount = qdcount;
    for (int i = 0; i < qdcount; ++i) {
        readName(packet, pos);
        if (!take16(packet, pos, &ignored) || !take16(packet, pos, &ignored))
            return false;
    }
    for (int i = 0; i < ancount; ++i) {
        Answer answer;
        answer.name = readName(packet, pos);
        quint16 rdlength = 0;
        if (!take16(packet, pos, &answer.type) || !take16(packet, pos, &answer.rclass)
            || !take32(packet, pos, &answer.ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos + rdlength > packet.size())
            return false;
        answer.rdata = packet.mid(pos, rdlength);
        pos += rdlength;
        reply->answers.append(answer);
    }
    for (int i = 0; i < nscount; ++i) {
        Answer answer;
        answer.name = readName(packet, pos);
        quint16 rdlength = 0;
        if (!take16(packet, pos, &answer.type) || !take16(packet, pos, &answer.rclass)
            || !take32(packet, pos, &answer.ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos + rdlength > packet.size())
            return false;
        answer.rdata = packet.mid(pos, rdlength);
        pos += rdlength;
        reply->authority.append(answer);
    }
    for (int i = 0; i < arcount; ++i) {
        Answer answer;
        answer.name = readName(packet, pos);
        quint16 rdlength = 0;
        if (!take16(packet, pos, &answer.type) || !take16(packet, pos, &answer.rclass)
            || !take32(packet, pos, &answer.ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos + rdlength > packet.size())
            return false;
        answer.rdata = packet.mid(pos, rdlength);
        pos += rdlength;
        reply->additional.append(answer);
    }
    reply->parsed = true;
    return true;
}

QByteArray exchange(quint16 port, const QByteArray &request, int timeoutMs = 3000)
{
    QUdpSocket socket;
    if (socket.writeDatagram(request, QHostAddress::LocalHost, port) != request.size())
        return {};
    const quint16 wantedId = quint16((quint8(request[0]) << 8) | quint8(request[1]));
    QByteArray reply;
    QElapsedTimer timer;
    timer.start();
    // The server lives in this thread, so its socket notifiers only run while
    // the event loop is pumped; a plain waitForReadyRead would block them.
    while (timer.elapsed() < timeoutMs && reply.isEmpty()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        if (!socket.hasPendingDatagrams() && !socket.waitForReadyRead(20))
            continue;
        while (socket.hasPendingDatagrams()) {
            QByteArray buffer;
            buffer.resize(int(socket.pendingDatagramSize()));
            const qint64 read = socket.readDatagram(buffer.data(), buffer.size());
            if (read <= 0)
                continue;
            buffer.truncate(int(read));
            if (buffer.size() >= 2 && quint16((quint8(buffer[0]) << 8) | quint8(buffer[1])) == wantedId)
                reply = buffer;
        }
    }
    return reply;
}

QByteArray exchangeTcp(quint16 port, const QByteArray &request, int timeoutMs = 3000)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, port);
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs
           && socket.state() != QAbstractSocket::ConnectedState)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    if (socket.state() != QAbstractSocket::ConnectedState)
        return {};

    QByteArray frame;
    put16(frame, quint16(request.size()));
    frame += request;
    socket.write(frame);

    QByteArray buffer;
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        buffer += socket.readAll();
        if (buffer.size() >= 2) {
            const int length = (int(quint8(buffer[0])) << 8) | int(quint8(buffer[1]));
            if (buffer.size() >= 2 + length)
                return buffer.mid(2, length);
        }
    }
    return {};
}

struct UpdateRecord {
    QString name;
    quint16 type = 1;
    quint16 rclass = 1;
    quint32 ttl = 0;
    QByteArray rdata;
};

QByteArray updatePacket(quint16 id, const QString &zone, const QList<UpdateRecord> &prerequisites,
                        const QList<UpdateRecord> &updates)
{
    QByteArray packet;
    put16(packet, id);
    put16(packet, 0x2800); // opcode UPDATE
    put16(packet, 1);
    put16(packet, quint16(prerequisites.size()));
    put16(packet, quint16(updates.size()));
    put16(packet, 0);
    packet += nameBytes(zone);
    put16(packet, 6); // SOA
    put16(packet, 1); // IN

    auto appendRecord = [&packet](const UpdateRecord &record) {
        packet += nameBytes(record.name);
        put16(packet, record.type);
        put16(packet, record.rclass);
        put32(packet, record.ttl);
        put16(packet, quint16(record.rdata.size()));
        packet += record.rdata;
    };
    for (const UpdateRecord &record : prerequisites)
        appendRecord(record);
    for (const UpdateRecord &record : updates)
        appendRecord(record);
    return packet;
}

QString srvTarget(const QByteArray &rdata)
{
    int pos = 6;
    return readName(rdata, pos);
}

quint32 soaSerial(const QByteArray &rdata)
{
    int pos = 0;
    quint32 serial = 0;
    if (!skipName(rdata, pos) || !skipName(rdata, pos) || !take32(rdata, pos, &serial))
        return 0;
    return serial;
}

} // namespace

class DnsTest : public QObject
{
    Q_OBJECT

private slots:
    void publishesAdServiceRecords();
    void repairsAdZoneLocators();
    void withdrawsLocatorsForUnboundServices();
    void followsConfiguredAddressOnDiskZone();
    void answersQueriesOverUdp();
    void refusesOutOfZoneQueries();
    void pinsTheSoaOnlyToANegativeAnswerAboutThisZone();
    void answersQueriesOverTcp();
    void forwardsAndCachesOutOfZoneQueries();
    void forwardsTcpQueriesOverTcp();
    void dropsNameserversThatWouldLoopBack();
    void followsForwarderChangesWhileRunning();
    void reportsMissingForwarderAgainAfterReconfiguration();
    void dropsItsOwnListenerFromAConfiguredList();
    void separatesAHostFilesForwardingFacts();
    void appliesDynamicUpdates();
    void enforcesUpdatePolicy();
    void refusesZoneTransfers();
    void answersAnEdnsQuery();
    void truncatesADatagramReplyToWhatTheClientCanReceive();
    void persistsZone();
};

void DnsTest::publishesAdServiceRecords()
{
    DnsServer server;
    // The dev-ports set: LDAP, kpasswd and the KDC all elsewhere, so a locator
    // that assumed 88 or 464 would point a client at nothing.
    server.loadAdZone(QStringLiteral("monarchy.example.com"),
                      QStringLiteral("monarchydc1.monarchy.example.com"), QStringLiteral("10.0.0.10"),
                      1389, 3268, QStringLiteral("Default-First-Site-Name"), 1464, 8888);

    QCOMPARE(server.zone(), QStringLiteral("monarchy.example.com"));

    const QList<DnsServer::Record> apexA =
        server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeA);
    QCOMPARE(apexA.size(), 1);
    QCOMPARE(apexA.first().rdata, QByteArray::fromHex("0a00000a"));

    const QList<DnsServer::Record> hostA =
        server.records(QStringLiteral("monarchydc1.monarchy.example.com"), DnsServer::TypeA);
    QCOMPARE(hostA.size(), 1);
    QCOMPARE(hostA.first().rdata, QByteArray::fromHex("0a00000a"));

    const QList<DnsServer::Record> soa =
        server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa);
    QCOMPARE(soa.size(), 1);
    QVERIFY(soaSerial(soa.first().rdata) >= 2026010100u);
    QCOMPARE(server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeNs).size(), 1);

    // Every service locator record an AD client looks for must exist, point at
    // this DC and carry the port the engine actually listens on.
    struct Expectation {
        QString owner;
        quint16 port;
    };
    const QList<Expectation> expectations = {
        {QStringLiteral("_ldap._tcp.monarchy.example.com"), 1389},
        {QStringLiteral("_ldap._tcp.dc._msdcs.monarchy.example.com"), 1389},
        {QStringLiteral("_ldap._tcp.default-first-site-name._sites.monarchy.example.com"), 1389},
        {QStringLiteral("_ldap._tcp.default-first-site-name._sites.dc._msdcs.monarchy.example.com"),
         1389},
        {QStringLiteral("_kerberos._tcp.monarchy.example.com"), 8888},
        {QStringLiteral("_kerberos._tcp.dc._msdcs.monarchy.example.com"), 8888},
        {QStringLiteral("_kerberos._udp.monarchy.example.com"), 8888},
        {QStringLiteral("_kpasswd._tcp.monarchy.example.com"), 1464},
        {QStringLiteral("_kpasswd._udp.monarchy.example.com"), 1464},
        {QStringLiteral("_gc._tcp.monarchy.example.com"), 3268},
        {QStringLiteral("_gc._tcp.default-first-site-name._sites.monarchy.example.com"), 3268},
        {QStringLiteral("_ldap._tcp.gc._msdcs.monarchy.example.com"), 3268},
        {QStringLiteral("_ldap._tcp.default-first-site-name._sites.gc._msdcs.monarchy.example.com"),
         3268},
        {QStringLiteral("_ldap._tcp.pdc._msdcs.monarchy.example.com"), 1389},
    };
    for (const Expectation &expectation : expectations) {
        const QList<DnsServer::Record> records =
            server.records(expectation.owner, DnsServer::TypeSrv);
        QCOMPARE(records.size(), 1);
        int pos = 4; // priority + weight
        quint16 port = 0;
        QVERIFY(take16(records.first().rdata, pos, &port));
        QCOMPARE(port, expectation.port);
        QCOMPARE(srvTarget(records.first().rdata),
                 QStringLiteral("monarchydc1.monarchy.example.com"));
    }
}

void DnsTest::repairsAdZoneLocators()
{
    const QString zone = QStringLiteral("monarchy.example.com");
    const QString host = QStringLiteral("monarchydc1.monarchy.example.com");
    const QString site = QStringLiteral("Default-First-Site-Name");

    DnsServer server;
    // An older provision: LDAP on the dev port, and no kpasswd service at all.
    server.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 1389, 3268, site);
    server.removeRecord(QStringLiteral("_kpasswd._tcp.") + zone, DnsServer::TypeSrv);
    server.removeRecord(QStringLiteral("_kpasswd._udp.") + zone, DnsServer::TypeSrv);

    QVERIFY(server.repairAdZoneLocators(host, 389, 3268, site, 464, 8888));

    const QList<DnsServer::Record> ldap =
        server.records(QStringLiteral("_ldap._tcp.") + zone, DnsServer::TypeSrv);
    QCOMPARE(ldap.size(), 1);
    int pos = 4; // priority + weight
    quint16 port = 0;
    QVERIFY(take16(ldap.first().rdata, pos, &port));
    QCOMPARE(port, quint16(389));

    // The removed locators come back at the port the service really uses.
    for (const QString &owner : {QStringLiteral("_kpasswd._tcp."),
                                 QStringLiteral("_kpasswd._udp.")}) {
        const QList<DnsServer::Record> records =
            server.records(owner + zone, DnsServer::TypeSrv);
        QCOMPARE(records.size(), 1);
        int at = 4;
        quint16 kpasswdPort = 0;
        QVERIFY(take16(records.first().rdata, at, &kpasswdPort));
        QCOMPARE(kpasswdPort, quint16(464));
    }

    // A KDC this build serves on 8888 must not stay advertised at 88, the port
    // a native-binding DC uses; the repair follows the port actually bound.
    for (const QString &owner : {QStringLiteral("_kerberos._tcp."),
                                 QStringLiteral("_kerberos._tcp.dc._msdcs."),
                                 QStringLiteral("_kerberos._udp.")}) {
        const QList<DnsServer::Record> records =
            server.records(owner + zone, DnsServer::TypeSrv);
        QCOMPARE(records.size(), 1);
        int at = 4;
        quint16 kdcPort = 0;
        QVERIFY(take16(records.first().rdata, at, &kdcPort));
        QCOMPARE(kdcPort, quint16(8888));
    }

    // A zone that already matches is not rewritten, so a start does not bump
    // the serial for nothing.
    QVERIFY(!server.repairAdZoneLocators(host, 389, 3268, site, 464, 8888));
}

void DnsTest::withdrawsLocatorsForUnboundServices()
{
    const QString zone = QStringLiteral("monarchy.example.com");
    const QString host = QStringLiteral("monarchydc1.monarchy.example.com");
    const QString site = QStringLiteral("Default-First-Site-Name");

    DnsServer server;
    // A KDC and a kpasswd service that did not bind, so their ports are 0.
    server.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 1389, 3268, site, 0, 0);

    QCOMPARE(server.records(QStringLiteral("_ldap._tcp.") + zone, DnsServer::TypeSrv).size(), 1);
    QCOMPARE(server.records(QStringLiteral("_gc._tcp.") + zone, DnsServer::TypeSrv).size(), 1);
    // Nothing advertises a service this DC does not answer.
    for (const QString &owner : {QStringLiteral("_kerberos._tcp."),
                                 QStringLiteral("_kerberos._udp."),
                                 QStringLiteral("_kpasswd._tcp."),
                                 QStringLiteral("_kpasswd._udp.")})
        QVERIFY(server.records(owner + zone, DnsServer::TypeSrv).isEmpty());

    // A zone from disk that still names those services loses the records when
    // the DC is held to what it answers, so an older zone cannot outlive the
    // service that used to answer it.
    DnsServer restored;
    restored.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 1389, 3268, site, 464, 8888);
    QCOMPARE(restored.records(QStringLiteral("_kpasswd._tcp.") + zone, DnsServer::TypeSrv).size(),
             1);
    QVERIFY(restored.repairAdZoneLocators(host, 1389, 3268, site, 0, 8888));
    for (const QString &owner : {QStringLiteral("_kpasswd._tcp."),
                                 QStringLiteral("_kpasswd._udp.")})
        QVERIFY(restored.records(owner + zone, DnsServer::TypeSrv).isEmpty());
    // The services that are served are untouched, so a start is not a rewrite.
    QVERIFY(!restored.repairAdZoneLocators(host, 1389, 3268, site, 0, 8888));
}

void DnsTest::followsConfiguredAddressOnDiskZone()
{
    const QString zone = QStringLiteral("monarchy.example.com");
    const QString host = QStringLiteral("monarchydc1.monarchy.example.com");

    DnsServer server;
    // Written when this DC was 10.0.0.10, started where dcIp is now something
    // else: the address records follow the configuration, or a client resolves
    // the DC to a machine that no longer holds that address.
    server.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 1389, 3268,
                      QStringLiteral("Default-First-Site-Name"));
    QCOMPARE(server.records(host, DnsServer::TypeA).first().rdata,
             QByteArray::fromHex("0a00000a"));

    QVERIFY(server.repairAdZoneAddresses(host, QStringLiteral("10.0.0.99")));
    for (const QString &owner : {host, QStringLiteral("ns1.") + zone, zone}) {
        const QList<DnsServer::Record> records = server.records(owner, DnsServer::TypeA);
        QCOMPARE(records.size(), 1);
        QCOMPARE(records.first().rdata, QByteArray::fromHex("0a000063"));
    }
    // Already correct: nothing is rewritten, so the serial does not move on
    // every start.
    QVERIFY(!server.repairAdZoneAddresses(host, QStringLiteral("10.0.0.99")));
}

void DnsTest::answersQueriesOverUdp()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("monarchy.example.com"),
                      QStringLiteral("monarchydc1.monarchy.example.com"), QStringLiteral("10.0.0.10"),
                      1389, 3268, QStringLiteral("Default-First-Site-Name"));

    const QByteArray request = DnsServer::buildQuery(
        QStringLiteral("_ldap._tcp.dc._msdcs.monarchy.example.com"), DnsServer::TypeSrv, 0x4242);
    const QByteArray response = exchange(server.serverPort(), request);
    QVERIFY(!response.isEmpty());

    Reply reply;
    QVERIFY(parseReply(response, &reply));
    QCOMPARE(reply.id, quint16(0x4242));
    QCOMPARE(reply.rcode, 0);
    QCOMPARE(reply.qdcount, quint16(1));
    QCOMPARE(reply.answers.size(), 1);
    QCOMPARE(reply.answers.first().name,
             QStringLiteral("_ldap._tcp.dc._msdcs.monarchy.example.com"));
    QCOMPARE(reply.answers.first().type, DnsServer::TypeSrv);
    QCOMPARE(reply.answers.first().rclass, quint16(1));
    int pos = 4;
    quint16 port = 0;
    QVERIFY(take16(reply.answers.first().rdata, pos, &port));
    QCOMPARE(port, quint16(1389));
    QCOMPARE(srvTarget(reply.answers.first().rdata),
             QStringLiteral("monarchydc1.monarchy.example.com"));

    // A name that exists but has no records of the requested type is a NOERROR
    // with an empty answer section, not an error.
    const QByteArray anyRequest = DnsServer::buildQuery(
        QStringLiteral("monarchydc1.monarchy.example.com"), DnsServer::TypeMx, 0x4243);
    Reply anyReply;
    QVERIFY(parseReply(exchange(server.serverPort(), anyRequest), &anyReply));
    QCOMPARE(anyReply.rcode, 0);
    QVERIFY(anyReply.answers.isEmpty());

    // ANY returns everything stored at the name.
    const QByteArray allRequest = DnsServer::buildQuery(
        QStringLiteral("monarchy.example.com"), DnsServer::TypeAny, 0x4244);
    Reply allReply;
    QVERIFY(parseReply(exchange(server.serverPort(), allRequest), &allReply));
    QCOMPARE(allReply.rcode, 0);
    QVERIFY(allReply.answers.size() >= 3);
}

void DnsTest::refusesOutOfZoneQueries()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    Reply reply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                      DnsServer::TypeA, 0x5151)),
                       &reply));
    QCOMPARE(reply.rcode, 5); // REFUSED: not authoritative, not a resolver
    QVERIFY(reply.answers.isEmpty());
}

void DnsTest::pinsTheSoaOnlyToANegativeAnswerAboutThisZone()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    // NODATA and NXDOMAIN inside the zone carry the SOA so a resolver can cache
    // the absence (RFC 2308). A refusal is not a negative answer: pinning an
    // IN-class SOA to a CHAOS question made the whole packet unparseable for a
    // client that checks the class — dig called it malformed and threw away the
    // rcode it had already read.
    Reply nodata;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("corp.example.com"),
                                                      DnsServer::TypeTxt, 0x6001)),
                       &nodata));
    QCOMPARE(nodata.rcode, 0);
    QVERIFY(nodata.answers.isEmpty());
    QCOMPARE(nodata.authority.size(), 1);
    QCOMPARE(nodata.authority.first().type, DnsServer::TypeSoa);

    Reply nxdomain;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("nope.corp.example.com"),
                                                      DnsServer::TypeA, 0x6002)),
                       &nxdomain));
    QCOMPARE(nxdomain.rcode, 3);
    QCOMPARE(nxdomain.authority.size(), 1);

    // The same name, asked in class CH: refused, and refused cleanly. buildQuery
    // writes the question in class IN, so its last two bytes are patched here.
    QByteArray chaos = DnsServer::buildQuery(QStringLiteral("version.bind"),
                                             DnsServer::TypeTxt, 0x6003);
    chaos[chaos.size() - 2] = 0x00;
    chaos[chaos.size() - 1] = 0x03;
    Reply refused;
    QVERIFY(parseReply(exchange(server.serverPort(), chaos), &refused));
    QCOMPARE(refused.rcode, 5); // REFUSED
    QVERIFY(refused.answers.isEmpty());
    QVERIFY2(refused.authority.isEmpty(),
             "a refusal about another class must not carry this zone's SOA");

    // And out of zone with recursion off: refused, no SOA either.
    QByteArray outside = DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                               DnsServer::TypeA, 0x6004);
    outside[2] = char(outside.at(2) & ~0x01); // clear RD
    Reply notOurs;
    QVERIFY(parseReply(exchange(server.serverPort(), outside), &notOurs));
    QCOMPARE(notOurs.rcode, 5);
    QVERIFY(notOurs.authority.isEmpty());
}

void DnsTest::answersQueriesOverTcp()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    Reply reply;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   DnsServer::buildQuery(
                                       QStringLiteral("_ldap._tcp.corp.example.com"),
                                       DnsServer::TypeSrv, 0x5301)),
                       &reply));
    QCOMPARE(reply.id, 0x5301);
    QCOMPARE(reply.rcode, 0);
    QCOMPARE(reply.answers.size(), 1);
    QCOMPARE(reply.answers.first().type, DnsServer::TypeSrv);
}

void DnsTest::forwardsTcpQueriesOverTcp()
{
    // The upstream only speaks DNS-over-TCP: a TCP client query must reach it
    // framed, and the framed answer must come back to the client.
    QTcpServer upstream;
    QVERIFY(upstream.listen(QHostAddress::LocalHost, 0));
    int upstreamQueries = 0;
    QHash<QTcpSocket *, QByteArray> buffers;
    QObject::connect(&upstream, &QTcpServer::newConnection, &upstream, [&]() {
        while (QTcpSocket *connection = upstream.nextPendingConnection()) {
            buffers.insert(connection, {});
            QObject::connect(connection, &QTcpSocket::readyRead, connection,
                             [connection, &buffers, &upstreamQueries]() {
                                 QByteArray &buffer = buffers[connection];
                                 buffer += connection->readAll();
                                 while (buffer.size() >= 2) {
                                     const int length = (int(quint8(buffer[0])) << 8)
                                                        | int(quint8(buffer[1]));
                                     if (buffer.size() < 2 + length)
                                         return;
                                     const QByteArray query = buffer.mid(2, length);
                                     buffer.remove(0, 2 + length);
                                     if (query.size() < 12)
                                         continue;
                                     ++upstreamQueries;

                                     QByteArray response;
                                     put16(response, quint16((quint8(query[0]) << 8)
                                                             | quint8(query[1])));
                                     put16(response, 0x8180); // QR, RD, RA, NOERROR
                                     put16(response, 1);
                                     put16(response, 1);
                                     put16(response, 0);
                                     put16(response, 0);
                                     response += query.mid(12);
                                     response.append(char(0xc0));
                                     response.append(char(0x0c));
                                     put16(response, DnsServer::TypeA);
                                     put16(response, 1);
                                     put32(response, 60);
                                     put16(response, 4);
                                     response.append(QByteArray::fromHex("c0000207"));

                                     QByteArray frame;
                                     put16(frame, quint16(response.size()));
                                     frame += response;
                                     connection->write(frame);
                                 }
                             });
            QObject::connect(connection, &QTcpSocket::disconnected, connection,
                             [connection, &buffers]() {
                                 buffers.remove(connection);
                                 connection->deleteLater();
                             });
        }
    });

    DnsServer server;
    server.setForwarders(
        {QStringLiteral("127.0.0.1:%1").arg(upstream.serverPort())});
    server.setForwardingEnabled(true);
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    Reply first;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                         DnsServer::TypeA, 0x5302)),
                       &first));
    QCOMPARE(first.id, 0x5302);
    QCOMPARE(first.answers.size(), 1);
    QCOMPARE(first.answers.first().rdata, QByteArray::fromHex("c0000207"));
    QCOMPARE(upstreamQueries, 1);

    Reply cached;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                         DnsServer::TypeA, 0x5303)),
                       &cached));
    QCOMPARE(cached.id, 0x5303);
    QCOMPARE(cached.answers.size(), 1);
    QCOMPARE(upstreamQueries, 1);
}

void DnsTest::forwardsAndCachesOutOfZoneQueries()
{
    // A tiny upstream resolver: it answers every A query with 192.0.2.7 and
    // counts how often it was actually asked.
    QUdpSocket upstream;
    QVERIFY(upstream.bind(QHostAddress::LocalHost, 0));
    int upstreamQueries = 0;
    QObject::connect(&upstream, &QUdpSocket::readyRead, &upstream, [&upstream, &upstreamQueries]() {
        while (upstream.hasPendingDatagrams()) {
            QByteArray query;
            query.resize(int(upstream.pendingDatagramSize()));
            QHostAddress peer;
            quint16 peerPort = 0;
            const qint64 read = upstream.readDatagram(query.data(), query.size(), &peer, &peerPort);
            if (read < 12)
                continue;
            query.truncate(int(read));
            ++upstreamQueries;

            QByteArray response;
            put16(response, quint16((quint8(query[0]) << 8) | quint8(query[1])));
            put16(response, 0x8180); // QR, RD, RA, NOERROR
            put16(response, 1);
            put16(response, 1);
            put16(response, 0);
            put16(response, 0);
            response += query.mid(12); // question
            response.append(char(0xc0));
            response.append(char(0x0c)); // pointer to the question name
            put16(response, DnsServer::TypeA);
            put16(response, 1);
            put32(response, 60);
            put16(response, 4);
            response.append(QByteArray::fromHex("c0000207"));
            upstream.writeDatagram(response, peer, peerPort);
        }
    });

    DnsServer server;
    server.setForwarders({QStringLiteral("127.0.0.1:%1").arg(upstream.localPort())});
    server.setForwardingEnabled(true);
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    // The domain stays authoritative: no upstream traffic for its own names.
    Reply inZone;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(
                                    QStringLiteral("_ldap._tcp.corp.example.com"),
                                    DnsServer::TypeSrv, 0x5200)),
                       &inZone));
    QCOMPARE(inZone.rcode, 0);
    QCOMPARE(upstreamQueries, 0);

    Reply first;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                      DnsServer::TypeA, 0x5201)),
                       &first));
    QCOMPARE(first.rcode, 0);
    QCOMPARE(first.id, 0x5201);
    QCOMPARE(first.answers.size(), 1);
    QCOMPARE(first.answers.first().rdata, QByteArray::fromHex("c0000207"));
    QCOMPARE(upstreamQueries, 1);

    // A second client gets the cached answer: a different transaction ID, no
    // second upstream query, and the TTL is not older than it was received.
    Reply second;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                      DnsServer::TypeA, 0x5202)),
                       &second));
    QCOMPARE(second.id, 0x5202);
    QCOMPARE(second.answers.size(), 1);
    QCOMPARE(second.answers.first().rdata, QByteArray::fromHex("c0000207"));
    QVERIFY(second.answers.first().ttl <= 60);
    QCOMPARE(upstreamQueries, 1);
    QCOMPARE(server.cachedResponseCount(), 1);

    // Turning recursion off restores the authoritative-only policy.
    server.setForwardingEnabled(false);
    Reply refused;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("www.example.org"),
                                                      DnsServer::TypeA, 0x5203)),
                       &refused));
    QCOMPARE(refused.rcode, 5); // REFUSED
    QCOMPARE(upstreamQueries, 1);
}

void DnsTest::dropsNameserversThatWouldLoopBack()
{
    // The state a DC is left in when the installer makes it the host's only
    // resolver: resolv.conf names the loopback stub, and the DC's own address
    // is the only other thing anyone wrote down. Forwarding to either asks this
    // server to ask itself, so both are dropped and nothing is left — which is
    // why out-of-zone names silently stopped resolving. The filter is what
    // turns that into "no forwarder", and the caller can then say so.
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("resolv.conf"));
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Text));
    file.write("# generated\n"
               "nameserver 127.0.0.1\n"
               "nameserver ::1\n"
               "nameserver 10.0.0.10\n"
               "nameserver 192.0.2.53:5353\n"
               "search corp.example.com\n");
    file.close();

    const QStringList written = DnsServer::nameserversIn(path);
    QCOMPARE(written.size(), 4);
    QCOMPARE(written.first(), QStringLiteral("127.0.0.1"));
    QCOMPARE(written.last(), QStringLiteral("192.0.2.53:5353"));

    // 10.0.0.10 is this machine (dcIp), so it loops back just like loopback.
    const QStringList usable =
        DnsServer::usableForwarders(written, {QStringLiteral("10.0.0.10")});
    QCOMPARE(usable, QStringList{QStringLiteral("192.0.2.53:5353")});

    // Only loopback and self left: nothing usable, which is the SERVFAIL case.
    QVERIFY(DnsServer::usableForwarders({QStringLiteral("127.0.0.1"), QStringLiteral("10.0.0.10")},
                                        {QStringLiteral("10.0.0.10")})
                .isEmpty());

    // A file that does not exist contributes nothing rather than throwing.
    QVERIFY(DnsServer::nameserversIn(dir.filePath(QStringLiteral("absent.conf"))).isEmpty());
}

void DnsTest::followsForwarderChangesWhileRunning()
{
    // What `systemctl reload` (SIGHUP) depends on: replacing the list on an
    // already-listening server sends the next new name to the new upstream,
    // with no restart and no rebuilt zone. Before the reload path existed the
    // list was fixed until the process was restarted.
    auto makeUpstream = [](const QByteArray &address, int *count) {
        auto *socket = new QUdpSocket;
        socket->bind(QHostAddress::LocalHost, 0);
        QObject::connect(socket, &QUdpSocket::readyRead, socket, [socket, address, count]() {
            while (socket->hasPendingDatagrams()) {
                QByteArray query;
                query.resize(int(socket->pendingDatagramSize()));
                QHostAddress peer;
                quint16 peerPort = 0;
                const qint64 read = socket->readDatagram(query.data(), query.size(), &peer, &peerPort);
                if (read < 12)
                    continue;
                query.truncate(int(read));
                ++*count;

                QByteArray response;
                put16(response, quint16((quint8(query[0]) << 8) | quint8(query[1])));
                put16(response, 0x8180);
                put16(response, 1);
                put16(response, 1);
                put16(response, 0);
                put16(response, 0);
                response += query.mid(12);
                response.append(char(0xc0));
                response.append(char(0x0c));
                put16(response, DnsServer::TypeA);
                put16(response, 1);
                put32(response, 60);
                put16(response, 4);
                response.append(address);
                socket->writeDatagram(response, peer, peerPort);
            }
        });
        return socket;
    };

    int firstCount = 0;
    int secondCount = 0;
    QUdpSocket *first = makeUpstream(QByteArray::fromHex("c0000201"), &firstCount);
    QUdpSocket *second = makeUpstream(QByteArray::fromHex("c0000202"), &secondCount);
    QVERIFY(first->localPort() != 0);
    QVERIFY(second->localPort() != 0);

    DnsServer server;
    server.setForwardingEnabled(true);
    server.setForwarders({QStringLiteral("127.0.0.1:%1").arg(first->localPort())});
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    Reply before;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("before.example.org"),
                                                      DnsServer::TypeA, 0x5301)),
                       &before));
    QCOMPARE(before.rcode, 0);
    QCOMPARE(firstCount, 1);
    QCOMPARE(secondCount, 0);

    // Same process, same listener, new list: this is the whole reload.
    server.setForwarders({QStringLiteral("127.0.0.1:%1").arg(second->localPort())});

    Reply after;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("after.example.org"),
                                                      DnsServer::TypeA, 0x5302)),
                       &after));
    QCOMPARE(after.rcode, 0);
    QCOMPARE(secondCount, 1);
    QCOMPARE(firstCount, 1); // the old upstream is not consulted any more

    delete first;
    delete second;
}

void DnsTest::reportsMissingForwarderAgainAfterReconfiguration()
{
    // The warning is once per configuration, not once per process: a reload on
    // a DC that still has nothing to forward to has to say so again, or the
    // operator who just fixed dc.conf the wrong way sees silence.
    DnsServer server;
    server.setForwardingEnabled(true);
    server.setForwarders({QStringLiteral("not-an-address")});
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    int reports = 0;
    QString lastDetail;
    QObject::connect(&server, &DnsServer::forwardingUnavailable, &server,
                     [&reports, &lastDetail](const QString &detail) {
                         ++reports;
                         lastDetail = detail;
                     });

    auto asksAndFails = [&server](quint16 id, const char *name) {
        Reply reply;
        return parseReply(exchange(server.serverPort(),
                                   DnsServer::buildQuery(QString::fromLatin1(name),
                                                         DnsServer::TypeA, id)),
                          &reply)
               && reply.rcode == 2; // SERVFAIL
    };

    QVERIFY(asksAndFails(0x5401, "one.example.org"));
    QVERIFY(asksAndFails(0x5402, "two.example.org"));
    QCOMPARE(reports, 1);

    server.setForwarders({QStringLiteral("still-not-an-address")});
    QVERIFY(asksAndFails(0x5403, "three.example.org"));
    QCOMPARE(reports, 2);
    QVERIFY(lastDetail.contains(QStringLiteral("still-not-an-address")));

    // The status line the daemon prints on start-up and on reload asks the same
    // question, so a list that reads as configured but cannot be used is
    // reported as unusable instead of "forwarding to ...".
    QVERIFY(!DnsServer::anyForwarderUsable({QStringLiteral("not-an-address")}));
    QVERIFY(!DnsServer::anyForwarderUsable({QStringLiteral("not-an-address"),
                                           QStringLiteral("still-not-an-address")}));
    QVERIFY(!DnsServer::anyForwarderUsable({}));
    QVERIFY(DnsServer::anyForwarderUsable({QStringLiteral("not-an-address"),
                                          QStringLiteral("127.0.0.1:53")}));
}

void DnsTest::dropsItsOwnListenerFromAConfiguredList()
{
    // A forwarders= line naming this daemon's own port is a loop with extra
    // steps: the query arrives back here, lands outside the zone, and leaves as
    // REFUSED, which the client sees as a bare SERVFAIL. It was reported as an
    // upstream and nothing said otherwise, so the line read as a working
    // configuration. A loopback stub on another port is a real upstream and has
    // to survive the same filter.
    DnsServer server;
    server.setForwardingEnabled(true);
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));
    const QString self = QStringLiteral("127.0.0.1:%1").arg(server.serverPort());

    int reports = 0;
    QString lastDetail;
    QObject::connect(&server, &DnsServer::forwardingUnavailable, &server,
                     [&reports, &lastDetail](const QString &detail) {
                         ++reports;
                         lastDetail = detail;
                     });

    server.setForwarders({self});
    QVERIFY(server.forwarders().contains(self));
    QCOMPARE(server.ignoredForwarders(), QStringList{self});
    QVERIFY(server.effectiveForwarders().isEmpty());

    // Measured against the real listener: the client gets SERVFAIL, not silence.
    Reply reply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                               DnsServer::buildQuery(QStringLiteral("outside.example.org"),
                                                     DnsServer::TypeA, 0x5501)),
                       &reply));
    QCOMPARE(reply.rcode, 2);
    QCOMPARE(reports, 1);
    // The detail names the entry and the reason, so it cannot be confused with
    // "nothing is configured" or "nothing parses".
    QVERIFY(lastDetail.contains(self));
    QVERIFY(lastDetail.contains(QStringLiteral("own listener")));

    // Every spelling that reaches this daemon's own socket: the wildcard binds
    // the host, so 0.0.0.0:<port> and [::]:<port> arrive here just as
    // 127.0.0.1:<port> does, and an operator copying an address out of a bind
    // setting writes the wildcard form first.
    const QString any4 = QStringLiteral("0.0.0.0:%1").arg(server.serverPort());
    server.setForwarders({any4});
    QCOMPARE(server.ignoredForwarders(), QStringList{any4});
    QVERIFY(server.effectiveForwarders().isEmpty());

    Reply wildcard;
    QVERIFY(parseReply(exchange(server.serverPort(),
                               DnsServer::buildQuery(QStringLiteral("wild.example.org"),
                                                     DnsServer::TypeA, 0x5503)),
                       &wildcard));
    QCOMPARE(wildcard.rcode, 2);

    const QString any6 = QStringLiteral("[::]:%1").arg(server.serverPort());
    server.setForwarders({any6});
    QCOMPARE(server.ignoredForwarders(), QStringList{any6});
    QVERIFY(server.effectiveForwarders().isEmpty());

    // Only the port makes an entry this server: another port on the wildcard is
    // some other listener's rule and stays in the list.
    const QString any4Other = QStringLiteral("0.0.0.0:5307");
    server.setForwarders({any4Other});
    QVERIFY(server.ignoredForwarders().isEmpty());
    QCOMPARE(server.effectiveForwarders(), QStringList{any4Other});

    // A loopback upstream on a different port is kept, and answers.
    auto *upstream = new QUdpSocket;
    upstream->bind(QHostAddress::LocalHost, 0);
    QObject::connect(upstream, &QUdpSocket::readyRead, upstream, [upstream]() {
        while (upstream->hasPendingDatagrams()) {
            QByteArray query;
            query.resize(int(upstream->pendingDatagramSize()));
            QHostAddress peer;
            quint16 peerPort = 0;
            const qint64 read =
                upstream->readDatagram(query.data(), query.size(), &peer, &peerPort);
            if (read < 12)
                continue;
            query.truncate(int(read));
            QByteArray response;
            put16(response, quint16((quint8(query[0]) << 8) | quint8(query[1])));
            put16(response, 0x8180);
            put16(response, 1);
            put16(response, 1);
            put16(response, 0);
            put16(response, 0);
            response += query.mid(12);
            response.append(char(0xc0));
            response.append(char(0x0c));
            put16(response, DnsServer::TypeA);
            put16(response, 1); // IN
            put32(response, 60);
            put16(response, 4);
            response.append(QByteArray::fromHex("c0000201"));
            upstream->writeDatagram(response, peer, peerPort);
        }
    });
    const QString local = QStringLiteral("127.0.0.1:%1").arg(upstream->localPort());
    server.setForwarders({self, local});
    QCOMPARE(server.ignoredForwarders(), QStringList{self});
    QCOMPARE(server.effectiveForwarders(), QStringList{local});

    Reply forwarded;
    QVERIFY(parseReply(exchange(server.serverPort(),
                               DnsServer::buildQuery(QStringLiteral("kept.example.org"),
                                                     DnsServer::TypeA, 0x5502)),
                       &forwarded));
    QCOMPARE(forwarded.rcode, 0);
    QCOMPARE(forwarded.answers.size(), 1);

    delete upstream;
}

void DnsTest::separatesAHostFilesForwardingFacts()
{
    // Three host shapes read the same to a client (SERVFAIL) and used to read
    // the same to an operator: "this host's nameservers are loopback or this DC
    // itself". Two of the three are not that, and the sentence sent the operator
    // to look for a loopback instead of at the line that cannot be parsed.
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    auto write = [&dir](const QString &name, const QByteArray &body) {
        const QString path = dir.path() + QLatin1Char('/') + name;
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return QString();
        file.write(body);
        file.close();
        return path;
    };

    // No `nameserver` line at all: the host has nothing configured, which is
    // not a loopback problem and not a parse problem.
    const QString emptyPath = write(QStringLiteral("empty.conf"), "# nothing here\n");
    const auto empty = DnsServer::hostForwarders({emptyPath});
    QVERIFY(empty.usable.isEmpty());
    QVERIFY(empty.read.isEmpty());
    QVERIFY(empty.unparseable.isEmpty());
    QCOMPARE(empty.files, QStringList{emptyPath});
    const QString emptyReason = DnsServer::noForwarderReason({}, QStringLiteral("z.example"), empty);
    QVERIFY(emptyReason.contains(QStringLiteral("no nameserver line")));
    QVERIFY(emptyReason.contains(emptyPath));
    QVERIFY(!emptyReason.contains(QStringLiteral("loopback")));

    // Lines that are not addresses: `#53` is systemd-resolved's port syntax and
    // a bare hostname is what an operator types. Both are dropped by the filter
    // before this point, so the only trace of them is this list.
    const QString badPath = write(QStringLiteral("unparseable.conf"),
                                  "nameserver 192.0.2.1#53\nnameserver dns.example.org\n");
    const auto bad = DnsServer::hostForwarders({badPath});
    QVERIFY(bad.usable.isEmpty());
    QCOMPARE(bad.unparseable,
             QStringList({QStringLiteral("192.0.2.1#53"), QStringLiteral("dns.example.org")}));
    QVERIFY(bad.loopbackOrSelf.isEmpty());
    const QString badReason = DnsServer::noForwarderReason({}, QStringLiteral("z.example"), bad);
    QVERIFY(badReason.contains(QStringLiteral("192.0.2.1#53")));
    QVERIFY(badReason.contains(QStringLiteral("could not be parsed as an address")));
    QVERIFY(!badReason.contains(QStringLiteral("loopback")));

    // A loopback-only host is the one shape the old sentence described.
    const QString loopPath = write(QStringLiteral("loopback.conf"), "nameserver 127.0.0.53\n");
    const auto loop = DnsServer::hostForwarders({loopPath});
    QVERIFY(loop.usable.isEmpty());
    QVERIFY(loop.unparseable.isEmpty());
    QCOMPARE(loop.loopbackOrSelf, QStringList{QStringLiteral("127.0.0.53")});
    const QString loopReason = DnsServer::noForwarderReason({}, QStringLiteral("z.example"), loop);
    QVERIFY(loopReason.contains(QStringLiteral("127.0.0.53")));
    QVERIFY(loopReason.contains(QStringLiteral("loopback")));

    // The fallback file is only consulted for a usable upstream; its entries
    // still count as facts when neither file has one, and a path that does not
    // exist is not the same as a file with no `nameserver` line.
    const auto both = DnsServer::hostForwarders({emptyPath, badPath});
    QVERIFY(both.usable.isEmpty());
    QCOMPARE(both.unparseable.size(), 2);
    const auto missing = DnsServer::hostForwarders({dir.path() + QStringLiteral("/absent.conf")});
    QVERIFY(missing.read.isEmpty());
    QVERIFY(missing.files.isEmpty());
    QVERIFY(DnsServer::noForwarderReason({}, QStringLiteral("z.example"), missing)
                .contains(QStringLiteral("/etc/resolv.conf")));

    // A configured list keeps its own reason, so the new facts cannot swallow it.
    const QString self = QStringLiteral("127.0.0.1:53");
    const QString configured =
        DnsServer::noForwarderReason({self}, QStringLiteral("z.example"), empty);
    QVERIFY(configured.contains(self));
    QVERIFY(configured.contains(QStringLiteral("own listener")));
}

void DnsTest::appliesDynamicUpdates()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("monarchy.example.com"),
                      QStringLiteral("monarchydc1.monarchy.example.com"), QStringLiteral("10.0.0.10"),
                      1389, 3268, QStringLiteral("Default-First-Site-Name"));
    QVERIFY(server.dynamicUpdatesEnabled());

    const quint32 before = soaSerial(
        server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa).first().rdata);

    UpdateRecord add;
    add.name = QStringLiteral("workstation1.monarchy.example.com");
    add.type = DnsServer::TypeA;
    add.rclass = 1;
    add.ttl = 300;
    add.rdata = QByteArray::fromHex("0a000005");
    Reply addReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6001, QStringLiteral("monarchy.example.com"), {}, {add})),
                       &addReply));
    QCOMPARE(addReply.rcode, 0);

    Reply queryReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("workstation1.monarchy.example.com"),
                                                      DnsServer::TypeA, 0x6002)),
                       &queryReply));
    QCOMPARE(queryReply.answers.size(), 1);
    QCOMPARE(queryReply.answers.first().rdata, QByteArray::fromHex("0a000005"));
    QCOMPARE(queryReply.answers.first().ttl, quint32(300));

    // The SOA serial must advance so secondaries know the zone changed.
    const quint32 after = soaSerial(
        server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa).first().rdata);
    QVERIFY(after > before);

    // Deleting the RRset (class ANY, no rdata) removes every A at the name.
    UpdateRecord deleteSet;
    deleteSet.name = add.name;
    deleteSet.type = DnsServer::TypeA;
    deleteSet.rclass = 255;
    Reply deleteReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6003, QStringLiteral("monarchy.example.com"), {},
                                             {deleteSet})),
                       &deleteReply));
    QCOMPARE(deleteReply.rcode, 0);
    QVERIFY(server.records(add.name, DnsServer::TypeA).isEmpty());

    // A single-value delete only removes the matching rdata.
    server.addRecord(add.name, DnsServer::TypeA, 300, QByteArray::fromHex("0a000005"));
    server.addRecord(add.name, DnsServer::TypeA, 300, QByteArray::fromHex("0a000006"));
    UpdateRecord deleteOne;
    deleteOne.name = add.name;
    deleteOne.type = DnsServer::TypeA;
    deleteOne.rclass = 254;
    deleteOne.ttl = 300;
    deleteOne.rdata = QByteArray::fromHex("0a000005");
    Reply deleteOneReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6004, QStringLiteral("monarchy.example.com"), {},
                                             {deleteOne})),
                       &deleteOneReply));
    QCOMPARE(deleteOneReply.rcode, 0);
    QCOMPARE(server.records(add.name, DnsServer::TypeA).size(), 1);
    QCOMPARE(server.records(add.name, DnsServer::TypeA).first().rdata,
             QByteArray::fromHex("0a000006"));

    // The zone apex keeps its SOA whatever the update did.
    QCOMPARE(server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa).size(), 1);
}

void DnsTest::enforcesUpdatePolicy()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("monarchy.example.com"),
                      QStringLiteral("monarchydc1.monarchy.example.com"), QStringLiteral("10.0.0.10"),
                      1389, 3268, QStringLiteral("Default-First-Site-Name"));

    UpdateRecord add;
    add.name = QStringLiteral("rogue.monarchy.example.com");
    add.type = DnsServer::TypeA;
    add.ttl = 60;
    add.rdata = QByteArray::fromHex("0a000009");

    // A prerequisite that cannot be met fails the whole update.
    UpdateRecord inUse;
    inUse.name = QStringLiteral("missing.monarchy.example.com");
    inUse.type = DnsServer::TypeAny;
    inUse.rclass = 255;
    Reply prereqReply;
    QVERIFY(parseReply(
        exchange(server.serverPort(),
                 updatePacket(0x7001, QStringLiteral("monarchy.example.com"), {inUse}, {add})),
        &prereqReply));
    QCOMPARE(prereqReply.rcode, 3); // NXDOMAIN
    QVERIFY(server.records(add.name, DnsServer::TypeA).isEmpty());

    // Records outside the zone are rejected with NOTZONE.
    UpdateRecord outside;
    outside.name = QStringLiteral("rogue.example.org");
    outside.type = DnsServer::TypeA;
    outside.ttl = 60;
    outside.rdata = QByteArray::fromHex("0a000009");
    Reply outsideReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7002, QStringLiteral("monarchy.example.com"), {},
                                             {outside})),
                       &outsideReply));
    QCOMPARE(outsideReply.rcode, 10); // NOTZONE

    // Updating a different zone is NOTAUTH for this server.
    Reply zoneReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7003, QStringLiteral("other.example.com"), {}, {add})),
                       &zoneReply));
    QCOMPARE(zoneReply.rcode, 9); // NOTAUTH

    // Turning updates off makes every UPDATE REFUSED.
    server.setDynamicUpdatesEnabled(false);
    Reply refusedReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7004, QStringLiteral("monarchy.example.com"), {}, {add})),
                       &refusedReply));
    QCOMPARE(refusedReply.rcode, 5); // REFUSED
    QVERIFY(server.records(add.name, DnsServer::TypeA).isEmpty());
}

namespace {

// buildQuery() writes a pre-EDNS query. A client that speaks EDNS appends an
// OPT to the additional section (RFC 6891 §6.1.1): root owner name, type 41,
// the sender's UDP payload size in the class field, and extended rcode,
// version and flags packed into what is a TTL on any other record.
QByteArray withEdns(const QByteArray &query, quint16 udpSize, quint8 version, bool dnssecOk)
{
    QByteArray packet = query;
    packet[11] = char(1); // ARCOUNT = 1
    packet.append('\0');
    put16(packet, 41);
    put16(packet, udpSize);
    put32(packet, (quint32(version) << 16) | (dnssecOk ? 0x8000u : 0u));
    put16(packet, 0);
    return packet;
}

} // namespace

void DnsTest::answersAnEdnsQuery()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    // A version-0 client gets an OPT back: this server's own payload size, its
    // version, and its DO bit echoed. Answering with no OPT at all is what makes
    // a modern resolver treat the server as pre-EDNS and cap it at 512 bytes.
    Reply reply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withEdns(DnsServer::buildQuery(
                                             QStringLiteral("corp.example.com"),
                                             DnsServer::TypeSoa, 0x71),
                                         4096, 0, true)),
                       &reply));
    QCOMPARE(reply.rcode, 0);
    QVERIFY(!reply.answers.isEmpty());
    QCOMPARE(reply.additional.size(), 1);
    const Answer &opt = reply.additional.first();
    QCOMPARE(opt.type, quint16(41));
    QCOMPARE(opt.rclass, quint16(1232)); // the size this server advertises
    QCOMPARE(static_cast<quint8>((opt.ttl >> 24) & 0xff), quint8(0)); // extended rcode
    QCOMPARE(static_cast<quint8>((opt.ttl >> 16) & 0xff), quint8(0)); // version
    QVERIFY2((opt.ttl & 0x8000u) != 0, "the DO bit a client set must be echoed");

    // DO unset: the reply must not claim DNSSEC data the zone does not have.
    Reply plain;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withEdns(DnsServer::buildQuery(
                                             QStringLiteral("corp.example.com"),
                                             DnsServer::TypeSoa, 0x72),
                                         1232, 0, false)),
                       &plain));
    QCOMPARE(plain.additional.size(), 1);
    QCOMPARE(plain.additional.first().ttl & 0x8000u, 0u);

    // A version this server does not implement is BADVERS (16), carried as
    // extended rcode 1 in the OPT with a zero header rcode, and no answer.
    Reply badvers;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withEdns(DnsServer::buildQuery(
                                             QStringLiteral("corp.example.com"),
                                             DnsServer::TypeSoa, 0x73),
                                         4096, 1, false)),
                       &badvers));
    QCOMPARE(badvers.rcode, 0);
    QVERIFY(badvers.answers.isEmpty());
    QCOMPARE(badvers.additional.size(), 1);
    QCOMPARE(badvers.additional.first().type, quint16(41));
    QCOMPARE(static_cast<quint8>((badvers.additional.first().ttl >> 24) & 0xff), quint8(1));
    QCOMPARE(static_cast<quint8>((badvers.additional.first().ttl >> 16) & 0xff), quint8(0));

    // A query without an OPT is still answered without one.
    Reply legacy;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("corp.example.com"),
                                                      DnsServer::TypeSoa, 0x74)),
                       &legacy));
    QCOMPARE(legacy.rcode, 0);
    QVERIFY(legacy.additional.isEmpty());
}

void DnsTest::truncatesADatagramReplyToWhatTheClientCanReceive()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    // An RRset big enough not to fit in 512 bytes: 60 A records at one name.
    // A name with this many addresses is ordinary in a lab (a round-robin
    // service), and it is what makes a datagram reply overflow.
    const QString big = QStringLiteral("big.corp.example.com");
    for (int i = 0; i < 60; ++i) {
        QByteArray rdata;
        rdata.append(char(10));
        rdata.append(char(1));
        rdata.append(char(i / 256));
        rdata.append(char(i % 256));
        server.addRecord(big, DnsServer::TypeA, 60, rdata);
    }

    const QByteArray query = DnsServer::buildQuery(big, DnsServer::TypeAny, 0x81);

    // A pre-EDNS client receives at most 512 bytes. The reply must say so with
    // TC and carry only the records that fit: sending all 60 would produce a
    // datagram the client's 512-byte buffer cuts in half.
    const QByteArray legacy = exchange(server.serverPort(), query);
    QVERIFY(!legacy.isEmpty());
    QVERIFY2(legacy.size() <= 512, qPrintable(QStringLiteral("reply was %1 bytes").arg(legacy.size())));
    Reply legacyReply;
    QVERIFY(parseReply(legacy, &legacyReply));
    QCOMPARE(legacyReply.rcode, 0);
    QVERIFY2(legacyReply.truncated, "a reply that does not fit must set TC");
    QVERIFY(!legacyReply.answers.isEmpty());
    QVERIFY2(legacyReply.answers.size() < 60, "records that do not fit must be left out");

    // A client that advertised a larger buffer gets the whole answer, untruncated.
    Reply roomy;
    QVERIFY(parseReply(exchange(server.serverPort(), withEdns(query, 4096, 0, false)), &roomy));
    QVERIFY2(!roomy.truncated, "4096 bytes is enough for 60 A records");
    QCOMPARE(roomy.answers.size(), 60);
    QCOMPARE(roomy.additional.size(), 1);

    // Advertising the minimum still bounds the reply, and still says TC.
    const QByteArray tight = exchange(server.serverPort(), withEdns(query, 512, 0, false));
    QVERIFY(tight.size() <= 512);
    Reply tightReply;
    QVERIFY(parseReply(tight, &tightReply));
    QVERIFY(tightReply.truncated);
    QVERIFY(tightReply.answers.size() < 60);

    // A size below the 512 floor is treated as 512 (RFC 6891 §6.2.5), not as a
    // reason to send less than the protocol guarantees every client can read.
    const QByteArray tiny = exchange(server.serverPort(), withEdns(query, 200, 0, false));
    QVERIFY(tiny.size() > 200 ? tiny.size() <= 512 : true);
    Reply tinyReply;
    QVERIFY(parseReply(tiny, &tinyReply));
    QVERIFY(!tinyReply.answers.isEmpty());

    // TCP has no size limit: the same query gets every record and no TC, which
    // is what makes the truncated datagram's advice worth following.
    Reply overTcp;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(), query), &overTcp));
    QVERIFY2(!overTcp.truncated, "a length-prefixed reply is not truncated");
    QCOMPARE(overTcp.answers.size(), 60);
}

void DnsTest::refusesZoneTransfers()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadDefaultZone(QStringLiteral("corp.example.com"));

    // Zone transfers are not served. A transfer request must be refused
    // explicitly, not answered as a partial AXFR (one SOA and then nothing),
    // which is neither a transfer nor a refusal and leaves the client hanging.
    const auto checkRefused = [&server](quint16 type, quint16 id) {
        Reply reply;
        QVERIFY(parseReply(exchange(server.serverPort(),
                                    DnsServer::buildQuery(
                                        QStringLiteral("corp.example.com"), type, id)),
                           &reply));
        QCOMPARE(reply.rcode, 5); // REFUSED
        QVERIFY(reply.answers.isEmpty());
        QVERIFY(reply.authority.isEmpty());
    };
    checkRefused(DnsServer::TypeAxfr, 0x5351);
    checkRefused(DnsServer::TypeIxfr, 0x5352);

    // Real transfer clients ask over TCP; the refusal must read the same there.
    Reply tcp;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   DnsServer::buildQuery(
                                       QStringLiteral("corp.example.com"),
                                       DnsServer::TypeAxfr, 0x5353)),
                       &tcp));
    QCOMPARE(tcp.rcode, 5);
    QVERIFY(tcp.answers.isEmpty());
}

void DnsTest::persistsZone()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("dnszone.json"));

    quint32 serial = 0;
    {
        DnsServer server;
        server.loadAdZone(QStringLiteral("monarchy.example.com"),
                          QStringLiteral("monarchydc1.monarchy.example.com"),
                          QStringLiteral("10.0.0.10"), 1389, 3268,
                          QStringLiteral("Default-First-Site-Name"));
        server.addRecord(QStringLiteral("files.monarchy.example.com"), DnsServer::TypeA, 600,
                         QByteArray::fromHex("0a000007"));
        serial = soaSerial(
            server.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa).first().rdata);
        QString error;
        QVERIFY2(server.saveZone(path, &error), qPrintable(error));
    }

    DnsServer restored;
    QString error;
    QVERIFY2(restored.loadZone(path, &error), qPrintable(error));
    QCOMPARE(restored.zone(), QStringLiteral("monarchy.example.com"));
    QCOMPARE(restored.records(QStringLiteral("files.monarchy.example.com"), DnsServer::TypeA).size(),
             1);
    QCOMPARE(restored.records(QStringLiteral("files.monarchy.example.com"), DnsServer::TypeA)
                 .first()
                 .rdata,
             QByteArray::fromHex("0a000007"));
    QCOMPARE(soaSerial(
                 restored.records(QStringLiteral("monarchy.example.com"), DnsServer::TypeSoa)
                     .first()
                     .rdata),
             serial);
    // Service records survive the round trip, including their rdata names.
    const QList<DnsServer::Record> srv = restored.records(
        QStringLiteral("_ldap._tcp.dc._msdcs.monarchy.example.com"), DnsServer::TypeSrv);
    QCOMPARE(srv.size(), 1);
    QCOMPARE(srvTarget(srv.first().rdata), QStringLiteral("monarchydc1.monarchy.example.com"));

    QVERIFY(!restored.loadZone(dir.filePath(QStringLiteral("absent.json")), &error));
}

QTEST_GUILESS_MAIN(DnsTest)
#include "test_dns.moc"
