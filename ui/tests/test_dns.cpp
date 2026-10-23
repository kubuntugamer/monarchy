// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QElapsedTimer>
#include <QHostAddress>
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
    QList<Answer> answers;
    bool parsed = false;
};

bool parseReply(const QByteArray &packet, Reply *reply)
{
    int pos = 0;
    quint16 id = 0;
    quint16 flags = 0;
    quint16 qdcount = 0;
    quint16 ancount = 0;
    quint16 ignored = 0;
    if (!take16(packet, pos, &id) || !take16(packet, pos, &flags) || !take16(packet, pos, &qdcount)
        || !take16(packet, pos, &ancount) || !take16(packet, pos, &ignored)
        || !take16(packet, pos, &ignored))
        return false;
    reply->id = id;
    reply->rcode = flags & 0x0f;
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
    void answersQueriesOverUdp();
    void refusesOutOfZoneQueries();
    void appliesDynamicUpdates();
    void enforcesUpdatePolicy();
    void persistsZone();
};

void DnsTest::publishesAdServiceRecords()
{
    DnsServer server;
    server.loadAdZone(QStringLiteral("monarchy.example.com"),
                      QStringLiteral("monarchydc1.monarchy.example.com"), QStringLiteral("10.0.0.10"),
                      1389, 3268, QStringLiteral("Default-First-Site-Name"));

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
        {QStringLiteral("_kerberos._tcp.monarchy.example.com"), 88},
        {QStringLiteral("_kerberos._tcp.dc._msdcs.monarchy.example.com"), 88},
        {QStringLiteral("_kerberos._udp.monarchy.example.com"), 88},
        {QStringLiteral("_kpasswd._tcp.monarchy.example.com"), 464},
        {QStringLiteral("_kpasswd._udp.monarchy.example.com"), 464},
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
