// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QHash>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QUdpSocket>

#include "DnsServer.h"
#include "Gss.h"
#include "Krb5.h"

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
    bool authoritative = false;
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
    reply->authoritative = (flags & 0x0400) != 0;
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

// Reads a zone transfer off one TCP connection until the message that closes it
// arrives: one message for a zone that fits, several for one that does not. The
// messages are returned in the order they were sent, without their framing.
QList<QByteArray> exchangeTransfer(quint16 port, const QByteArray &request, int timeoutMs = 8000)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, port);
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs && socket.state() != QAbstractSocket::ConnectedState)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    if (socket.state() != QAbstractSocket::ConnectedState)
        return {};

    QByteArray frame;
    put16(frame, quint16(request.size()));
    frame += request;
    socket.write(frame);

    QList<QByteArray> messages;
    QByteArray buffer;
    int soas = 0;
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        buffer += socket.readAll();
        while (buffer.size() >= 2) {
            const int length = (int(quint8(buffer[0])) << 8) | int(quint8(buffer[1]));
            if (buffer.size() < 2 + length)
                break;
            const QByteArray message = buffer.mid(2, length);
            buffer.remove(0, 2 + length);
            messages.append(message);
            Reply parsed;
            if (!parseReply(message, &parsed))
                return messages;
            for (const Answer &answer : parsed.answers) {
                if (answer.type == 6)
                    ++soas;
            }
            // The second SOA is the end of the transfer; a refusal carries no
            // records at all and is the end of the exchange too.
            if (soas >= 2)
                return messages;
            if (parsed.answers.isEmpty() && parsed.rcode != 0)
                return messages;
        }
    }
    return messages;
}

// An IXFR request carrying the version the client holds in the authority
// section, which is where RFC 1995 §3 puts it. The TSIG is added on top, so the
// additional count starts at zero.
QByteArray ixfrQuery(quint16 id, const QString &zone, const QByteArray &clientSoa)
{
    QByteArray packet;
    put16(packet, id);
    put16(packet, 0x0000);
    put16(packet, 1); // one question
    put16(packet, 0); // no answers
    put16(packet, 1); // one authority record: the client's SOA
    put16(packet, 0); // no additional records yet
    packet += nameBytes(zone);
    put16(packet, DnsServer::TypeIxfr);
    put16(packet, 1);
    packet += nameBytes(zone);
    put16(packet, DnsServer::TypeSoa);
    put16(packet, 1);
    put32(packet, 0);
    put16(packet, quint16(clientSoa.size()));
    packet += clientSoa;
    return packet;
}

// An SOA's RDATA with its serial replaced: how a client says which version it has.
QByteArray soaWithSerial(const QByteArray &rdata, quint32 serial)
{
    QByteArray out = rdata;
    int pos = 0;
    readName(out, pos);
    readName(out, pos);
    out[pos] = char((serial >> 24) & 0xff);
    out[pos + 1] = char((serial >> 16) & 0xff);
    out[pos + 2] = char((serial >> 8) & 0xff);
    out[pos + 3] = char(serial & 0xff);
    return out;
}

// --- TSIG (RFC 8945) -------------------------------------------------------
// The server speaks hmac-sha256, so the test computes the same MACs from the
// same key: verifying the reply's MAC here is what proves the signature is over
// the bytes on the wire rather than over something the server chose.
QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    const int block = 64;
    QByteArray k = key.size() > block ? QCryptographicHash::hash(key, QCryptographicHash::Sha256)
                                      : key;
    k.resize(block, '\0');
    QByteArray inner(block, '\0');
    QByteArray outer(block, '\0');
    for (int i = 0; i < block; ++i) {
        inner[i] = char(quint8(k[i]) ^ 0x36);
        outer[i] = char(quint8(k[i]) ^ 0x5c);
    }
    return QCryptographicHash::hash(
        outer + QCryptographicHash::hash(inner + data, QCryptographicHash::Sha256),
        QCryptographicHash::Sha256);
}

QByteArray tsigVariables(const QString &keyName, const QString &algorithm, quint64 timeSigned,
                         quint16 fudge, quint16 error, const QByteArray &other)
{
    QByteArray out;
    out += nameBytes(keyName.toLower());
    put16(out, 255);
    put32(out, 0);
    out += nameBytes(algorithm.toLower());
    for (int shift = 40; shift >= 0; shift -= 8)
        out.append(char((timeSigned >> shift) & 0xff));
    put16(out, fudge);
    put16(out, error);
    put16(out, quint16(other.size()));
    out += other;
    return out;
}

// Appends a TSIG over `message` as it stands: the MAC covers the message with
// the ARCOUNT it had before the TSIG was added, which is what a server seeing
// the sent packet recomputes after decrementing the count.
QByteArray withTsig(const QByteArray &message, const QString &keyName, const QString &algorithm,
                    const QByteArray &secret, quint64 timeSigned, quint16 fudge,
                    QByteArray *macOut = nullptr, quint16 error = 0,
                    const QByteArray &other = {})
{
    QByteArray out = message;
    const QByteArray mac =
        hmacSha256(secret, message + tsigVariables(keyName, algorithm, timeSigned, fudge, error, other));
    if (macOut)
        *macOut = mac;
    const quint16 arcount =
        quint16((quint8(out[10]) << 8) | quint8(out[11]));
    const quint16 next = quint16(arcount + 1);
    out[10] = char((next >> 8) & 0xff);
    out[11] = char(next & 0xff);

    QByteArray rdata;
    rdata += nameBytes(algorithm);
    for (int shift = 40; shift >= 0; shift -= 8)
        rdata.append(char((timeSigned >> shift) & 0xff));
    put16(rdata, fudge);
    put16(rdata, quint16(mac.size()));
    rdata += mac;
    put16(rdata, quint16((quint8(message[0]) << 8) | quint8(message[1])));
    put16(rdata, error);
    put16(rdata, quint16(other.size()));
    rdata += other;

    out += nameBytes(keyName);
    put16(out, 250); // TSIG
    put16(out, 255); // class ANY
    put32(out, 0);   // TTL
    put16(out, quint16(rdata.size()));
    out += rdata;
    return out;
}

struct TsigReply {
    QString algorithm;
    quint64 timeSigned = 0;
    quint16 fudge = 0;
    QByteArray mac;
    quint16 originalId = 0;
    quint16 error = 0;
    QByteArray other;
};

bool parseTsigRdata(const QByteArray &rdata, TsigReply *out)
{
    int pos = 0;
    out->algorithm = readName(rdata, pos);
    if (pos + 10 > rdata.size())
        return false;
    quint64 when = 0;
    for (int i = 0; i < 6; ++i)
        when = (when << 8) | quint8(rdata[pos + i]);
    pos += 6;
    out->timeSigned = when;
    out->fudge = quint16((quint8(rdata[pos]) << 8) | quint8(rdata[pos + 1]));
    pos += 2;
    const int macLength = (quint8(rdata[pos]) << 8) | quint8(rdata[pos + 1]);
    pos += 2;
    if (pos + macLength + 6 > rdata.size())
        return false;
    out->mac = rdata.mid(pos, macLength);
    pos += macLength;
    out->originalId = quint16((quint8(rdata[pos]) << 8) | quint8(rdata[pos + 1]));
    pos += 2;
    out->error = quint16((quint8(rdata[pos]) << 8) | quint8(rdata[pos + 1]));
    pos += 2;
    const int otherLength = (quint8(rdata[pos]) << 8) | quint8(rdata[pos + 1]);
    pos += 2;
    if (pos + otherLength > rdata.size())
        return false;
    out->other = rdata.mid(pos, otherLength);
    return true;
}

// The TSIG a reply carries, or null when it carries none.
const Answer *replyTsig(const Reply &reply)
{
    for (const Answer &answer : reply.additional) {
        if (answer.type == 250)
            return &answer;
    }
    return nullptr;
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
    void publishesTheDomainGuidLocator();
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
    void acceptsEmptyRdataInUpdateSections();
    void acceptsReverseZoneUpdates();
    void enforcesUpdatePolicy();
    void refusesZoneTransfers();
    void transfersTheZoneToASignedPeer();
    void splitsALargeZoneAcrossMessages();
    void answersAnIncrementalRequestWithTheDelta();
    void notifiesTheSecondariesWhenTheZoneMoves();
    void retriesAnAnnouncementUntilTheSecondaryAnswers();
    void announcesTheZoneThatMoved();
    void pullsTheCopyWhenTheMasterAnnouncesIt();
    void remembersTheDifferenceAcrossARestart();
    void gatesATransferOnTheZonesTheKeyMayRead();
    void answersAnEdnsQuery();
    void truncatesADatagramReplyToWhatTheClientCanReceive();
    void answersReverseLookupsForItsOwnAddress();
    void requiresTsigForDynamicUpdates();
    void negotiatesGssTsigAndSignsUpdates();
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

void DnsTest::publishesTheDomainGuidLocator()
{
    // A member confirms the controller it found by asking for the locators under
    // the domain's own GUID, and a client answered NXDOMAIN there stops trusting
    // DNS discovery. The GUID is the one Netlogon hands out: the MD5 of the
    // domain SID with the first three fields written little-endian.
    const QString zone = QStringLiteral("cyberdyne.lan");
    const QString host = QStringLiteral("minerva.cyberdyne.lan");
    const QString guid =
        DnsServer::domainGuidFor(QStringLiteral("S-1-5-21-5926014-2702479734-3490867515"));
    QCOMPARE(guid, QStringLiteral("385867b2-0f2e-4ea5-d5a1-91dfbd86d1cc"));

    DnsServer server;
    server.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 389, 3268,
                      QStringLiteral("Default-First-Site-Name"), 464, 88, guid);

    struct Expectation {
        QString owner;
        quint16 port;
    };
    const QList<Expectation> expectations = {
        {QStringLiteral("_ldap._tcp.") + guid + QStringLiteral(".domains._msdcs.") + zone, 389},
        {QStringLiteral("_gc._tcp.") + guid + QStringLiteral(".domains._msdcs.") + zone, 3268},
    };
    for (const Expectation &expectation : expectations) {
        const QList<DnsServer::Record> records =
            server.records(expectation.owner, DnsServer::TypeSrv);
        QCOMPARE(records.size(), 1);
        int pos = 4; // priority + weight
        quint16 port = 0;
        QVERIFY(take16(records.first().rdata, pos, &port));
        QCOMPARE(port, expectation.port);
        QCOMPARE(srvTarget(records.first().rdata), host);
    }

    // A zone loaded without a GUID publishes nothing at that owner, which is
    // what a zone that is not AD's gets.
    DnsServer plain;
    plain.loadAdZone(zone, host, QStringLiteral("10.0.0.10"), 389, 3268,
                     QStringLiteral("Default-First-Site-Name"), 464, 88);
    QVERIFY(plain.records(expectations.first().owner, DnsServer::TypeSrv).isEmpty());
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

void DnsTest::acceptsReverseZoneUpdates()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    const QString zone = QStringLiteral("monarchy.example.com");
    server.loadAdZone(zone, QStringLiteral("dc1.monarchy.example.com"),
                      QStringLiteral("192.168.5.20"), 1389, 3268,
                      QStringLiteral("Default-First-Site-Name"));
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.monarchy.example.com"),
                                     QStringLiteral("192.168.5.20")));
    const QString reverse = server.reverseZone();
    QCOMPARE(reverse, QStringLiteral("5.168.192.in-addr.arpa"));
    const quint32 before = soaSerial(server.records(reverse, DnsServer::TypeSoa).first().rdata);

    // A member registers its own address: the A record goes into the forward
    // zone and the PTR into the reverse zone, which is the zone this DC derives
    // from its own address. A Windows 2000 client sends the second one, and it
    // was answered NOTAUTH because the zone section was compared with the
    // forward zone alone.
    UpdateRecord ptr;
    ptr.name = QStringLiteral("21.5.168.192.in-addr.arpa");
    ptr.type = DnsServer::TypePtr;
    ptr.rclass = 1;
    ptr.ttl = 1200;
    ptr.rdata = nameBytes(QStringLiteral("workstation5.monarchy.example.com"));
    Reply addReply;
    QVERIFY(parseReply(
        exchange(server.serverPort(), updatePacket(0x6a01, reverse, {}, {ptr})), &addReply));
    QCOMPARE(addReply.rcode, 0);
    QCOMPARE(server.records(ptr.name, DnsServer::TypePtr).size(), 1);
    QCOMPARE(server.records(ptr.name, DnsServer::TypePtr).first().rdata, ptr.rdata);
    const quint32 after = soaSerial(server.records(reverse, DnsServer::TypeSoa).first().rdata);
    QVERIFY2(after > before, "the reverse zone's own serial moves so its secondaries pull");

    // A name below the reverse zone is not the zone, so naming it in the zone
    // section is still not authority: only an apex this server authors is.
    Reply below;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6a02, QStringLiteral("10.5.168.192.in-addr.arpa"),
                                             {}, {ptr})),
                       &below));
    QCOMPARE(below.rcode, 9); // NOTAUTH

    // A zone this server does not author stays refused, copy or not.
    Reply foreign;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6a03, QStringLiteral("elsewhere.example.net"), {},
                                             {ptr})),
                       &foreign));
    QCOMPARE(foreign.rcode, 9); // NOTAUTH
}

void DnsTest::acceptsEmptyRdataInUpdateSections()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    const QString zone = QStringLiteral("monarchy.example.com");
    server.loadAdZone(zone, QStringLiteral("monarchydc1.monarchy.example.com"),
                      QStringLiteral("10.0.0.10"), 1389, 3268,
                      QStringLiteral("Default-First-Site-Name"));
    const QString host = QStringLiteral("workstation1.monarchy.example.com");

    // What Windows 2000 sends to register its own A record: "no CNAME here"
    // (class NONE, no rdata) then "the A RRset is exactly this address"
    // (class IN, value dependent). Empty rdata is part of the encoding, so the
    // pair has to be judged on what it says rather than answered FormErr.
    UpdateRecord noCname;
    noCname.name = host;
    noCname.type = DnsServer::TypeCname;
    noCname.rclass = 254;

    UpdateRecord aValue;
    aValue.name = host;
    aValue.type = DnsServer::TypeA;
    aValue.rclass = 1;
    aValue.rdata = QByteArray::fromHex("0a000005");

    Reply absent;
    QVERIFY(parseReply(exchange(server.serverPort(), updatePacket(0x6101, zone, {noCname, aValue}, {})),
                       &absent));
    QCOMPARE(absent.rcode, 8); // NXRRSET: the address is not there yet (RFC 2136 §3.2.4)

    server.addRecord(host, DnsServer::TypeA, 300, QByteArray::fromHex("0a000005"));
    Reply present;
    QVERIFY(parseReply(exchange(server.serverPort(), updatePacket(0x6102, zone, {noCname, aValue}, {})),
                       &present));
    QCOMPARE(present.rcode, 0);

    // A whole-RRset delete (class ANY, no rdata) followed by an add: the empty
    // record has to stay empty instead of taking the name that follows it.
    UpdateRecord dropCname;
    dropCname.name = QStringLiteral("alias.monarchy.example.com");
    dropCname.type = DnsServer::TypeCname;
    dropCname.rclass = 255;
    server.addRecord(dropCname.name, DnsServer::TypeCname, 300, nameBytes(host));

    UpdateRecord addCname;
    addCname.name = dropCname.name;
    addCname.type = DnsServer::TypeCname;
    addCname.rclass = 1;
    addCname.ttl = 300;
    addCname.rdata = nameBytes(host);

    Reply replace;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x6103, zone, {}, {dropCname, addCname})),
                       &replace));
    QCOMPARE(replace.rcode, 0);
    QCOMPARE(server.records(dropCname.name, DnsServer::TypeCname).size(), 1);
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

void DnsTest::answersReverseLookupsForItsOwnAddress()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("corp.example.com"),
                      QStringLiteral("dc1.corp.example.com"), QStringLiteral("192.168.5.20"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    // `dig -x 192.168.5.20` against an AD DC: the DC is authoritative for the
    // /24 of its own address and holds a PTR in it.
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.corp.example.com"),
                                     QStringLiteral("192.168.5.20")));
    QCOMPARE(server.reverseZone(), QStringLiteral("5.168.192.in-addr.arpa"));

    Reply ptr;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("20.5.168.192.in-addr.arpa"),
                                                      DnsServer::TypePtr, 0x91)),
                       &ptr));
    QCOMPARE(ptr.rcode, 0);
    QVERIFY2(ptr.authoritative, "a PTR in this DC's own reverse zone is authoritative");
    QCOMPARE(ptr.answers.size(), 1);
    QCOMPARE(ptr.answers.first().type, DnsServer::TypePtr);
    int pos = 0;
    QCOMPARE(readName(ptr.answers.first().rdata, pos), QStringLiteral("dc1.corp.example.com"));

    // The forward name the PTR points at still resolves.
    Reply forward;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("dc1.corp.example.com"),
                                                      DnsServer::TypeA, 0x92)),
                       &forward));
    QCOMPARE(forward.answers.size(), 1);

    // An address in the same /24 this DC does not hold: NXDOMAIN, authoritative,
    // and carrying the reverse zone's own SOA so a resolver can cache the
    // absence against it.
    Reply absent;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("21.5.168.192.in-addr.arpa"),
                                                      DnsServer::TypePtr, 0x93)),
                       &absent));
    QCOMPARE(absent.rcode, 3);
    QVERIFY(absent.authoritative);
    QVERIFY(!absent.authority.isEmpty());
    QCOMPARE(absent.authority.first().type, DnsServer::TypeSoa);
    QCOMPARE(absent.authority.first().name, QStringLiteral("5.168.192.in-addr.arpa"));

    // A neighbouring /24 belongs to someone else: it must not be answered as if
    // this server were authoritative for it.
    Reply elsewhere;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("20.5.168.193.in-addr.arpa"),
                                                      DnsServer::TypePtr, 0x94)),
                       &elsewhere));
    QVERIFY2(elsewhere.rcode != 0, "a name outside both zones is not answered here");

    // Starting again on the same address rewrites nothing.
    QVERIFY(!server.repairReverseZone(QStringLiteral("dc1.corp.example.com"),
                                      QStringLiteral("192.168.5.20")));

    // A DC that moves takes its PTR with it, and the abandoned /24 stops
    // pointing at it.
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.corp.example.com"),
                                     QStringLiteral("192.168.9.20")));
    QCOMPARE(server.reverseZone(), QStringLiteral("9.168.192.in-addr.arpa"));
    Reply moved;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("20.9.168.192.in-addr.arpa"),
                                                      DnsServer::TypePtr, 0x95)),
                       &moved));
    QCOMPARE(moved.answers.size(), 1);
    Reply stale;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("20.5.168.192.in-addr.arpa"),
                                                      DnsServer::TypePtr, 0x96)),
                       &stale));
    QVERIFY2(stale.answers.isEmpty(), "the abandoned /24 must not keep pointing at this DC");
}

void DnsTest::requiresTsigForDynamicUpdates()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("corp.example.com"),
                      QStringLiteral("dc1.corp.example.com"), QStringLiteral("192.168.5.20"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));

    const QString keyName = QStringLiteral("update-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    const QByteArray secretBase64 = secret.toBase64();
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secretBase64);
    QCOMPARE(server.updateTsigName(), keyName);

    const QString host = QStringLiteral("tsig1.corp.example.com");
    auto updateFor = [&host](quint16 id, const QByteArray &rdata) {
        UpdateRecord add;
        add.name = host;
        add.type = DnsServer::TypeA;
        add.rclass = 1;
        add.ttl = 300;
        add.rdata = rdata;
        return updatePacket(id, QStringLiteral("corp.example.com"), {}, {add});
    };

    // Unsigned: with a key configured, the update proves nothing and is refused
    // before the zone is touched.
    Reply unsignedReply;
    QVERIFY(parseReply(exchange(server.serverPort(), updateFor(0x8101, QByteArray::fromHex("0a000001"))),
                       &unsignedReply));
    QCOMPARE(unsignedReply.rcode, 9); // NOTAUTH
    QVERIFY(server.records(host, DnsServer::TypeA).isEmpty());

    // Signed with the right key: accepted, and the reply is signed too, with a
    // MAC this test recomputes from the same secret.
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    QByteArray requestMac;
    const QByteArray signedUpdate =
        withTsig(updateFor(0x8102, QByteArray::fromHex("0a000002")), keyName, algorithm,
                 secret, now, 300, &requestMac);
    const QByteArray raw = exchange(server.serverPort(), signedUpdate);
    Reply accepted;
    QVERIFY(parseReply(raw, &accepted));
    QCOMPARE(accepted.rcode, 0);
    QCOMPARE(server.records(host, DnsServer::TypeA).size(), 1);

    const Answer *signedReply = replyTsig(accepted);
    QVERIFY2(signedReply != nullptr, "an accepted signed update must be answered signed");
    TsigReply signature;
    QVERIFY(parseTsigRdata(signedReply->rdata, &signature));
    QCOMPARE(signature.error, quint16(0));
    QCOMPARE(signature.mac.size(), 32);
    QCOMPARE(signature.originalId, quint16(0x8102));

    // The reply MAC covers the request MAC and the reply as sent, minus the TSIG.
    const int tsigStart =
        raw.size() - (nameBytes(keyName).size() + 10 + signedReply->rdata.size());
    QVERIFY(tsigStart > 12);
    QByteArray withoutTsig = raw.left(tsigStart);
    const quint16 arcount = quint16((quint8(withoutTsig[10]) << 8) | quint8(withoutTsig[11]));
    const quint16 fewer = quint16(arcount - 1);
    withoutTsig[10] = char((fewer >> 8) & 0xff);
    withoutTsig[11] = char(fewer & 0xff);
    QByteArray prefix;
    put16(prefix, quint16(requestMac.size()));
    prefix += requestMac;
    QCOMPARE(hmacSha256(secret,
                        prefix + withoutTsig
                            + tsigVariables(keyName, algorithm, signature.timeSigned,
                                            signature.fudge, signature.error, signature.other)),
             signature.mac);

    // Wrong secret: the key is known, the MAC is not, and nothing is written.
    const QString other = QStringLiteral("tsig2.corp.example.com");
    UpdateRecord addOther;
    addOther.name = other;
    addOther.type = DnsServer::TypeA;
    addOther.rclass = 1;
    addOther.ttl = 300;
    addOther.rdata = QByteArray::fromHex("0a000003");
    const QByteArray badSignature =
        withTsig(updatePacket(0x8103, QStringLiteral("corp.example.com"), {}, {addOther}),
                 keyName, algorithm, QByteArray("ffffffffffffffffffffffffffffffff"), now, 300);
    Reply badSigReply;
    QVERIFY(parseReply(exchange(server.serverPort(), badSignature), &badSigReply));
    QCOMPARE(badSigReply.rcode, 9);
    const Answer *badSigTsig = replyTsig(badSigReply);
    QVERIFY(badSigTsig != nullptr);
    TsigReply badSig;
    QVERIFY(parseTsigRdata(badSigTsig->rdata, &badSig));
    QCOMPARE(badSig.error, quint16(16)); // BADSIG
    QCOMPARE(badSig.mac.size(), 0);      // nothing verified, so nothing is claimed
    QVERIFY(server.records(other, DnsServer::TypeA).isEmpty());

    // Another key's name: BADKEY, and the same refusal.
    const QByteArray wrongKey =
        withTsig(updatePacket(0x8104, QStringLiteral("corp.example.com"), {}, {addOther}),
                 QStringLiteral("someone-elses-key"), algorithm, secret, now, 300);
    Reply badKeyReply;
    QVERIFY(parseReply(exchange(server.serverPort(), wrongKey), &badKeyReply));
    QCOMPARE(badKeyReply.rcode, 9);
    const Answer *badKeyTsig = replyTsig(badKeyReply);
    QVERIFY(badKeyTsig != nullptr);
    TsigReply badKey;
    QVERIFY(parseTsigRdata(badKeyTsig->rdata, &badKey));
    QCOMPARE(badKey.error, quint16(17)); // BADKEY
    // The refusal names the key and algorithm the request used, not this
    // server's configured key: the client has to be able to read the error
    // without holding a key the server would accept.
    QCOMPARE(badKeyTsig->name.toLower(), QStringLiteral("someone-elses-key"));
    QCOMPARE(badKey.algorithm, QStringLiteral("hmac-sha256")); // wire name, no root dot
    QVERIFY(badKey.mac.isEmpty());

    // A clock an hour out: the MAC verifies, so the answer is signed, carries
    // BADTIME and the server's own time for the client to correct against.
    QByteArray skewedMac;
    const QByteArray skewed =
        withTsig(updatePacket(0x8105, QStringLiteral("corp.example.com"), {}, {addOther}),
                 keyName, algorithm, secret, now - 3600, 300, &skewedMac);
    const QByteArray skewedRaw = exchange(server.serverPort(), skewed);
    Reply skewedReply;
    QVERIFY(parseReply(skewedRaw, &skewedReply));
    QCOMPARE(skewedReply.rcode, 9);
    const Answer *skewedTsig = replyTsig(skewedReply);
    QVERIFY(skewedTsig != nullptr);
    TsigReply skewedParsed;
    QVERIFY(parseTsigRdata(skewedTsig->rdata, &skewedParsed));
    QCOMPARE(skewedParsed.error, quint16(18)); // BADTIME
    QCOMPARE(skewedParsed.mac.size(), 32);
    QCOMPARE(skewedParsed.other.size(), 6);    // the server's time
    // RFC 8945 §5.2.3: the signed reply echoes the client's own timers, so the
    // client can verify it despite the skew, and carries this server's clock
    // for the client to correct against.
    QCOMPARE(skewedParsed.timeSigned, now - 3600);
    QCOMPARE(skewedParsed.fudge, quint16(300));
    quint64 serverClock = 0;
    for (char byte : skewedParsed.other)
        serverClock = (serverClock << 8) | quint8(byte);
    QVERIFY(serverClock >= now);

    const int skewedStart = skewedRaw.size()
        - (nameBytes(keyName).size() + 10 + skewedTsig->rdata.size());
    QVERIFY(skewedStart > 12);
    QByteArray skewedBody = skewedRaw.left(skewedStart);
    const quint16 skewedArcount =
        quint16((quint8(skewedBody[10]) << 8) | quint8(skewedBody[11]));
    skewedBody[10] = char((quint16(skewedArcount - 1) >> 8) & 0xff);
    skewedBody[11] = char((quint16(skewedArcount - 1)) & 0xff);
    QByteArray skewedPrefix;
    put16(skewedPrefix, quint16(skewedMac.size()));
    skewedPrefix += skewedMac;
    QCOMPARE(hmacSha256(secret,
                        skewedPrefix + skewedBody
                            + tsigVariables(keyName, algorithm, skewedParsed.timeSigned,
                                            skewedParsed.fudge, skewedParsed.error,
                                            skewedParsed.other)),
             skewedParsed.mac);
    QVERIFY(server.records(other, DnsServer::TypeA).isEmpty());

    // With the key cleared, updates go back to being unauthenticated: the
    // default posture, and what STATUS.md documents.
    server.setUpdateTsig(QString(), QString(), QByteArray());
    QVERIFY(server.updateTsigName().isEmpty());
    Reply openReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updateFor(0x8106, QByteArray::fromHex("0a000004"))),
                       &openReply));
    QCOMPARE(openReply.rcode, 0);
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

void DnsTest::transfersTheZoneToASignedPeer()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("corp.example.com"),
                      QStringLiteral("dc1.corp.example.com"), QStringLiteral("192.168.5.20"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    // The same store holds the reverse zone this DC answers for; it is not part
    // of the forward zone and must not travel with a transfer of it.
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.corp.example.com"),
                                     QStringLiteral("192.168.5.20")));
    for (int i = 0; i < 40; ++i) {
        QByteArray rdata;
        rdata.append(char(10));
        rdata.append(char(0));
        rdata.append(char(0));
        rdata.append(char(1 + i));
        server.addRecord(QStringLiteral("host%1.corp.example.com").arg(i), DnsServer::TypeA, 300,
                         rdata);
    }

    const QString keyName = QStringLiteral("transfer-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());

    const auto axfr = [](quint16 id) {
        return DnsServer::buildQuery(QStringLiteral("corp.example.com"), DnsServer::TypeAxfr, id);
    };

    // Unsigned over TCP: the transfer proves nothing, so no zone is handed over.
    Reply unsignedReply;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(), axfr(0x7101)), &unsignedReply));
    QCOMPARE(unsignedReply.rcode, 9); // NOTAUTH
    QVERIFY(unsignedReply.answers.isEmpty());

    // Signed: the whole zone, opened and closed by the SOA.
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    QByteArray requestMac;
    const QByteArray request =
        withTsig(axfr(0x7102), keyName, algorithm, secret, now, 300, &requestMac);
    const QByteArray raw = exchangeTcp(server.serverPort(), request);
    Reply transferred;
    QVERIFY(parseReply(raw, &transferred));
    QCOMPARE(transferred.rcode, 0);
    QVERIFY2(transferred.authoritative, "a transfer is answered authoritatively");
    QVERIFY(!transferred.truncated);
    QCOMPARE(transferred.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(transferred.answers.first().name.toLower(), QStringLiteral("corp.example.com"));
    QCOMPARE(transferred.answers.last().type, DnsServer::TypeSoa);
    QCOMPARE(transferred.answers.first().rdata, transferred.answers.last().rdata);

    QStringList names;
    for (const Answer &answer : transferred.answers)
        names.append(answer.name.toLower());
    for (int i = 0; i < 40; ++i) {
        QVERIFY2(names.contains(QStringLiteral("host%1.corp.example.com").arg(i)),
                 "every record of the zone travels");
    }
    QVERIFY2(names.contains(QStringLiteral("_ldap._tcp.corp.example.com")),
             "the zone's own locator records travel too");
    QVERIFY2(!names.contains(QStringLiteral("20.5.168.192.in-addr.arpa")),
             "the reverse zone in the same store is not part of this zone");
    // The SOA is the only record that appears twice, and the apex keeps the NS
    // and A records a secondary expects to receive with it.
    int soaCount = 0;
    int apexCount = 0;
    for (const Answer &answer : transferred.answers) {
        if (answer.type == DnsServer::TypeSoa)
            ++soaCount;
        if (answer.name.toLower() == QStringLiteral("corp.example.com"))
            ++apexCount;
    }
    QCOMPARE(soaCount, 2);
    QVERIFY(apexCount >= 3);

    // The reply is signed, over a MAC that covers the request MAC and the reply
    // as sent, so a transfer cannot be replayed against a different request.
    const Answer *signedReply = replyTsig(transferred);
    QVERIFY2(signedReply != nullptr, "an authenticated transfer must be answered signed");
    TsigReply signature;
    QVERIFY(parseTsigRdata(signedReply->rdata, &signature));
    QCOMPARE(signature.error, quint16(0));
    QCOMPARE(signature.mac.size(), 32);
    QCOMPARE(signature.originalId, quint16(0x7102));

    const int tsigStart = raw.size() - (nameBytes(keyName).size() + 10 + signedReply->rdata.size());
    QVERIFY(tsigStart > 12);
    QByteArray withoutTsig = raw.left(tsigStart);
    const quint16 arcount = quint16((quint8(withoutTsig[10]) << 8) | quint8(withoutTsig[11]));
    const quint16 fewer = quint16(arcount - 1);
    withoutTsig[10] = char((fewer >> 8) & 0xff);
    withoutTsig[11] = char(fewer & 0xff);
    QByteArray prefix;
    put16(prefix, quint16(requestMac.size()));
    prefix += requestMac;
    QCOMPARE(hmacSha256(secret,
                        prefix + withoutTsig
                            + tsigVariables(keyName, algorithm, signature.timeSigned,
                                            signature.fudge, signature.error, signature.other)),
             signature.mac);

    // Wrong secret: the key name is right and the MAC is not, so the client is
    // told BADSIG and receives no records.
    const QByteArray badSignature =
        withTsig(axfr(0x7103), keyName, algorithm,
                 QByteArray("ffffffffffffffffffffffffffffffff"), now, 300);
    Reply badReply;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(), badSignature), &badReply));
    QCOMPARE(badReply.rcode, 9);
    QVERIFY(badReply.answers.isEmpty());
    const Answer *badTsig = replyTsig(badReply);
    QVERIFY(badTsig != nullptr);
    TsigReply badParsed;
    QVERIFY(parseTsigRdata(badTsig->rdata, &badParsed));
    QCOMPARE(badParsed.error, quint16(16)); // BADSIG
    QCOMPARE(badParsed.mac.size(), 0);

    // A transfer is a stream. The same signed request over UDP is refused, not
    // answered with as much of the zone as one datagram holds.
    Reply udpReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withTsig(axfr(0x7104), keyName, algorithm, secret, now, 300)),
                       &udpReply));
    QCOMPARE(udpReply.rcode, 5); // REFUSED
    QVERIFY(udpReply.answers.isEmpty());

    // An IXFR that names no version cannot be answered with a difference, so it
    // is handed the whole zone — the fallback RFC 1995 §6 asks for — rather than
    // refused. The delta itself is covered by
    // answersAnIncrementalRequestWithTheDelta().
    Reply ixfr;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(DnsServer::buildQuery(
                                                QStringLiteral("corp.example.com"),
                                                DnsServer::TypeIxfr, 0x7105),
                                            keyName, algorithm, secret, now, 300)),
                       &ixfr));
    QCOMPARE(ixfr.rcode, 0);
    QCOMPARE(ixfr.answers.size(), server.zoneContents().size());
    QCOMPARE(ixfr.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(ixfr.answers.last().type, DnsServer::TypeSoa);

    // With the key cleared there is no peer that could authenticate, so the
    // transfer goes back to being refused rather than open — the default.
    server.setUpdateTsig(QString(), QString(), QByteArray());
    Reply openReply;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(axfr(0x7106), keyName, algorithm, secret, now, 300)),
                       &openReply));
    QCOMPARE(openReply.rcode, 5);
    QVERIFY(openReply.answers.isEmpty());
}

// A zone too large for one message is the case a real secondary hits first: the
// 65535-byte framing limit used to turn every big zone into SERVFAIL, so the
// transfer existed and could not be used. It is a stream of signed messages now,
// and this pins the parts a secondary acts on: every message signed over the
// message before it, the question only in the first, the SOA opening the first
// and closing the last, and every record present exactly once.
void DnsTest::splitsALargeZoneAcrossMessages()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("bulk.example.com"),
                      QStringLiteral("dc1.bulk.example.com"), QStringLiteral("10.9.9.9"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    // Roughly 3000 records of forty-odd wire bytes each: several times what one
    // 65535-byte message can hold.
    for (int i = 0; i < 3000; ++i) {
        QByteArray rdata;
        rdata.append(char(10));
        rdata.append(char(1));
        rdata.append(char((i >> 8) & 0xff));
        rdata.append(char(i & 0xff));
        server.addRecord(QStringLiteral("record%1.bulk.example.com").arg(i),
                         DnsServer::TypeA, 300, rdata);
    }
    const int zoneRecords = server.zoneContents().size();
    QVERIFY2(zoneRecords > 2900, qPrintable(QString::number(zoneRecords)));

    const QString keyName = QStringLiteral("bulk-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("fedcba9876543210fedcba9876543210");
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());

    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    QByteArray requestMac;
    const QByteArray request =
        withTsig(DnsServer::buildQuery(QStringLiteral("bulk.example.com"),
                                       DnsServer::TypeAxfr, 0x7201),
                 keyName, algorithm, secret, now, 300, &requestMac);
    const QList<QByteArray> messages = exchangeTransfer(server.serverPort(), request);
    QVERIFY2(messages.size() >= 2, "a zone larger than one message has to be split");

    QList<Answer> travelled;
    QByteArray chain = requestMac;
    for (int i = 0; i < messages.size(); ++i) {
        const QByteArray &raw = messages.at(i);
        QVERIFY2(raw.size() <= 65535, "no message may exceed the TCP length prefix");
        Reply part;
        QVERIFY(parseReply(raw, &part));
        QCOMPARE(part.rcode, 0);
        QVERIFY2(part.authoritative, "every message of a transfer is authoritative");
        QVERIFY(!part.truncated);
        // The question section belongs to the first message; a stream repeating
        // it would make a client that keys on QDCOUNT read a new exchange.
        QCOMPARE(part.qdcount, i == 0 ? quint16(1) : quint16(0));
        QVERIFY2(!part.answers.isEmpty(), "a message with no records is a stall");

        // Each message is signed, and each signature covers the MAC of the one
        // before it (RFC 8945 §5.3.1), so a message cannot be replayed from
        // another transfer or dropped from this one without the chain breaking.
        const Answer *tsig = replyTsig(part);
        QVERIFY2(tsig != nullptr, "every message of a transfer is signed");
        TsigReply signature;
        QVERIFY(parseTsigRdata(tsig->rdata, &signature));
        QCOMPARE(signature.error, quint16(0));
        QCOMPARE(signature.mac.size(), 32);
        QCOMPARE(signature.originalId, quint16(0x7201));
        const int tsigStart = raw.size() - (nameBytes(keyName).size() + 10 + tsig->rdata.size());
        QVERIFY(tsigStart > 12);
        QByteArray withoutTsig = raw.left(tsigStart);
        const quint16 arcount =
            quint16((quint8(withoutTsig[10]) << 8) | quint8(withoutTsig[11]));
        const quint16 fewer = quint16(arcount - 1);
        withoutTsig[10] = char((fewer >> 8) & 0xff);
        withoutTsig[11] = char(fewer & 0xff);
        // The first message covers the request MAC and the whole TSIG variables
        // block; every message after it covers the prior MAC and only its own
        // timers (RFC 8945 §5.3.1). Getting that wrong is invisible here unless
        // it is written this way — a server and a test that share the mistake
        // agree with each other, which is why dig was the check that settled it.
        QByteArray prefix;
        put16(prefix, quint16(chain.size()));
        prefix += chain;
        QByteArray digest = prefix + withoutTsig;
        if (i == 0) {
            digest += tsigVariables(keyName, algorithm, signature.timeSigned, signature.fudge,
                                    signature.error, signature.other);
        } else {
            for (int shift = 40; shift >= 0; shift -= 8)
                digest.append(char((signature.timeSigned >> shift) & 0xff));
            put16(digest, signature.fudge);
        }
        QCOMPARE(hmacSha256(secret, digest), signature.mac);
        chain = signature.mac;
        travelled += part.answers;
    }

    // Everything arrives, in the order a secondary commits it.
    QCOMPARE(travelled.size(), zoneRecords);
    QCOMPARE(travelled.first().type, DnsServer::TypeSoa);
    QCOMPARE(travelled.last().type, DnsServer::TypeSoa);
    QCOMPARE(travelled.first().rdata, travelled.last().rdata);
    int soaCount = 0;
    QList<int> seen(3000, 0);
    for (const Answer &answer : travelled) {
        if (answer.type == DnsServer::TypeSoa) {
            ++soaCount;
            continue;
        }
        if (answer.type != DnsServer::TypeA)
            continue;
        const QString name = answer.name.toLower();
        if (!name.startsWith(QStringLiteral("record")))
            continue;
        const int dot = name.indexOf(QLatin1Char('.'), 6);
        const int index = name.mid(6, dot - 6).toInt();
        if (index >= 0 && index < seen.size())
            ++seen[index];
    }
    QCOMPARE(soaCount, 2);
    for (int i = 0; i < seen.size(); ++i)
        QCOMPARE(seen.at(i), 1); // each record once, none dropped between messages

    // The size of the zone changes nothing about who may pull it: the same zone
    // unsigned is refused, in one message and with no records.
    const QList<QByteArray> refused = exchangeTransfer(
        server.serverPort(),
        DnsServer::buildQuery(QStringLiteral("bulk.example.com"), DnsServer::TypeAxfr, 0x7202));
    QCOMPARE(refused.size(), 1);
    Reply denied;
    QVERIFY(parseReply(refused.first(), &denied));
    QCOMPARE(denied.rcode, 9); // NOTAUTH
    QVERIFY(denied.answers.isEmpty());
}

// IXFR (RFC 1995): a client that names the version it holds is sent the records
// that changed instead of the zone, and the framing is the one the RFC draws —
// it opens with the current SOA, each difference sequence starts with the older
// SOA and starts its additions with the newer one, and the current SOA closes
// the answer.
void DnsTest::answersAnIncrementalRequestWithTheDelta()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("inc.example.com"),
                      QStringLiteral("dc1.inc.example.com"), QStringLiteral("10.30.0.10"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    const QByteArray keepRdata = QByteArray::fromHex("0a1e0001");
    const QByteArray goingRdata = QByteArray::fromHex("0a1e0002");
    const QByteArray arrivedRdata = QByteArray::fromHex("0a1e0003");
    server.addRecord(QStringLiteral("keep.inc.example.com"), DnsServer::TypeA, 300, keepRdata);
    server.addRecord(QStringLiteral("going.inc.example.com"), DnsServer::TypeA, 300, goingRdata);

    const QString keyName = QStringLiteral("inc-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());

    const QList<DnsServer::Record> soa =
        server.records(QStringLiteral("inc.example.com"), DnsServer::TypeSoa);
    QCOMPARE(soa.size(), 1);
    const quint32 before = soaSerial(soa.first().rdata);

    // One update that removes an address and adds another, so the difference has
    // both halves and the untouched record is the control.
    QList<UpdateRecord> updates;
    updates.append({QStringLiteral("arrived.inc.example.com"), DnsServer::TypeA, 1, 300,
                    arrivedRdata});
    updates.append({QStringLiteral("going.inc.example.com"), DnsServer::TypeA, 255, 0, {}});
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    Reply updateReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withTsig(updatePacket(0x7300, QStringLiteral("inc.example.com"),
                                                      {}, updates),
                                         keyName, algorithm, secret, now, 300)),
                       &updateReply));
    QCOMPARE(updateReply.rcode, 0);
    const quint32 after =
        soaSerial(server.records(QStringLiteral("inc.example.com"), DnsServer::TypeSoa)
                      .first()
                      .rdata);
    QVERIFY2(after > before, "an applied update moves the serial");

    Reply delta;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(ixfrQuery(0x7301, QStringLiteral("inc.example.com"),
                                                      soaWithSerial(soa.first().rdata, before)),
                                            keyName, algorithm, secret, now, 300)),
                       &delta));
    QCOMPARE(delta.rcode, 0);
    QVERIFY(delta.authoritative);
    QCOMPARE(delta.answers.size(), 6);
    QCOMPARE(delta.answers.at(0).type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(delta.answers.at(0).rdata), after);
    QCOMPARE(delta.answers.at(1).type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(delta.answers.at(1).rdata), before);
    QCOMPARE(delta.answers.at(2).type, DnsServer::TypeA);
    QCOMPARE(delta.answers.at(2).name.toLower(), QStringLiteral("going.inc.example.com"));
    QCOMPARE(delta.answers.at(2).rdata, goingRdata);
    QCOMPARE(delta.answers.at(3).type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(delta.answers.at(3).rdata), after);
    QCOMPARE(delta.answers.at(4).type, DnsServer::TypeA);
    QCOMPARE(delta.answers.at(4).name.toLower(), QStringLiteral("arrived.inc.example.com"));
    QCOMPARE(delta.answers.at(4).rdata, arrivedRdata);
    QCOMPARE(delta.answers.at(5).type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(delta.answers.at(5).rdata), after);
    for (const Answer &answer : delta.answers) {
        QVERIFY2(answer.name.toLower() != QStringLiteral("keep.inc.example.com"),
                 "a record the update did not touch does not travel in the delta");
    }

    // A client that already holds this version is told so with one SOA.
    Reply current;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(ixfrQuery(0x7302, QStringLiteral("inc.example.com"),
                                                      soaWithSerial(soa.first().rdata, after)),
                                            keyName, algorithm, secret, now, 300)),
                       &current));
    QCOMPARE(current.rcode, 0);
    QCOMPARE(current.answers.size(), 1);
    QCOMPARE(current.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(current.answers.first().rdata), after);

    // A version the journal does not hold gets the whole zone, not an error: the
    // client cannot be brought forward from a version this server no longer has.
    Reply full;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(ixfrQuery(0x7303, QStringLiteral("inc.example.com"),
                                                      soaWithSerial(soa.first().rdata,
                                                                    before - 5)),
                                            keyName, algorithm, secret, now, 300)),
                       &full));
    QCOMPARE(full.rcode, 0);
    QCOMPARE(full.answers.size(), server.zoneContents().size());
    QCOMPARE(full.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(full.answers.last().type, DnsServer::TypeSoa);

    // Over a datagram the answer is the current SOA, which is what RFC 1995 §2
    // has a server say when the difference is not carried in this message.
    Reply datagram;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withTsig(ixfrQuery(0x7304, QStringLiteral("inc.example.com"),
                                                   soaWithSerial(soa.first().rdata, before)),
                                         keyName, algorithm, secret, now, 300)),
                       &datagram));
    QCOMPARE(datagram.rcode, 0);
    QCOMPARE(datagram.answers.size(), 1);
    QCOMPARE(datagram.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(soaSerial(datagram.answers.first().rdata), after);

    // Size and opcode change nothing about who may ask.
    Reply unsignedReply;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   ixfrQuery(0x7305, QStringLiteral("inc.example.com"),
                                             soaWithSerial(soa.first().rdata, before))),
                       &unsignedReply));
    QCOMPARE(unsignedReply.rcode, 9); // NOTAUTH
    QVERIFY(unsignedReply.answers.isEmpty());
}

// A secondary that is told nothing learns about a change when its refresh timer
// next fires, minutes after the change. NOTIFY (RFC 1996) is the announcement
// that turns that wait into a diff pull. This binds a socket as the secondary and
// reads what the primary sends it.
void DnsTest::notifiesTheSecondariesWhenTheZoneMoves()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("notify.example.com"),
                      QStringLiteral("dc1.notify.example.com"), QStringLiteral("10.40.0.10"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    // The default is silence: a DC that was never told about a secondary does not
    // guess one from the zone and start announcing to it.
    QCOMPARE(server.notifyTargets().size(), 0);

    QUdpSocket secondary;
    QVERIFY(secondary.bind(QHostAddress::LocalHost, 0));
    server.setNotifyTargets({QStringLiteral("127.0.0.1:%1").arg(secondary.localPort())});

    const QString keyName = QStringLiteral("notify-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("89abcdef0123456789abcdef01234567");
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());

    // One datagram, pumping the event loop because the server lives in this
    // thread.
    auto awaitDatagram = [](QUdpSocket &socket, int timeoutMs) {
        QByteArray received;
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs && received.isEmpty()) {
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
                received = buffer;
            }
        }
        return received;
    };

    const QList<DnsServer::Record> soa =
        server.records(QStringLiteral("notify.example.com"), DnsServer::TypeSoa);
    QCOMPARE(soa.size(), 1);
    const quint32 before = soaSerial(soa.first().rdata);

    QList<UpdateRecord> updates;
    updates.append({QStringLiteral("added.notify.example.com"), DnsServer::TypeA, 1, 300,
                    QByteArray::fromHex("0a280001")});
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    Reply updateReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                withTsig(updatePacket(0x7400, QStringLiteral("notify.example.com"),
                                                      {}, updates),
                                         keyName, algorithm, secret, now, 300)),
                       &updateReply));
    QCOMPARE(updateReply.rcode, 0);
    const quint32 after = soaSerial(
        server.records(QStringLiteral("notify.example.com"), DnsServer::TypeSoa).first().rdata);
    QVERIFY2(after > before, "an applied update moves the serial");

    const QByteArray announce = awaitDatagram(secondary, 3000);
    QVERIFY2(!announce.isEmpty(), "an applied update tells the secondary the serial moved");
    QVERIFY(announce.size() >= 12);
    const quint16 flags = quint16((quint8(announce[2]) << 8) | quint8(announce[3]));
    QCOMPARE((flags >> 11) & 0x0f, 4); // opcode NOTIFY
    QCOMPARE(flags & 0x8000, 0);       // a request, not an answer
    QVERIFY((flags & 0x0400) != 0);    // authoritative
    Reply notify;
    QVERIFY(parseReply(announce, &notify));
    QCOMPARE(notify.qdcount, quint16(1));
    QCOMPARE(notify.answers.size(), 1);
    QCOMPARE(notify.answers.first().type, DnsServer::TypeSoa);
    QCOMPARE(notify.answers.first().name.toLower(), QStringLiteral("notify.example.com"));
    QCOMPARE(soaSerial(notify.answers.first().rdata), after);

    // Signed with the key the transfer requires, recomputed here from the secret
    // over the bytes as sent: an announcement the secondary cannot check is one
    // it will ignore, and the filtering it does is the point of the signature.
    const Answer *announcedTsig = replyTsig(notify);
    QVERIFY2(announcedTsig != nullptr, "a primary with a key signs what it announces");
    TsigReply signature;
    QVERIFY(parseTsigRdata(announcedTsig->rdata, &signature));
    QCOMPARE(signature.error, quint16(0));
    QCOMPARE(signature.mac.size(), 32);
    QCOMPARE(signature.originalId, notify.id);
    const int tsigStart =
        announce.size() - (nameBytes(keyName).size() + 10 + announcedTsig->rdata.size());
    QVERIFY(tsigStart > 12);
    QByteArray withoutTsig = announce.left(tsigStart);
    const quint16 arcount = quint16((quint8(withoutTsig[10]) << 8) | quint8(withoutTsig[11]));
    const quint16 fewer = quint16(arcount - 1);
    withoutTsig[10] = char((fewer >> 8) & 0xff);
    withoutTsig[11] = char(fewer & 0xff);
    QCOMPARE(hmacSha256(secret,
                        withoutTsig
                            + tsigVariables(keyName, algorithm, signature.timeSigned,
                                            signature.fudge, signature.error, signature.other)),
             signature.mac);

    // The secondary's answer to a NOTIFY carries QR, and it ends the exchange:
    // answering it with an rcode would read as a second one.
    QByteArray ack;
    put16(ack, notify.id);
    put16(ack, quint16((4 << 11) | 0x8000 | 0x0400));
    put16(ack, 0);
    put16(ack, 0);
    put16(ack, 0);
    put16(ack, 0);
    secondary.writeDatagram(ack, QHostAddress::LocalHost, server.serverPort());
    QVERIFY2(awaitDatagram(secondary, 300).isEmpty(),
             "a NOTIFY response ends the exchange instead of starting another");

    // A NOTIFY addressed to this server is a peer that takes it for a secondary.
    // There is no copy here to refresh, and REFUSED says that instead of the
    // NOTIMP an unknowable opcode would get.
    QByteArray asked;
    put16(asked, 0x7402);
    put16(asked, quint16(4 << 11));
    put16(asked, 1);
    put16(asked, 0);
    put16(asked, 0);
    put16(asked, 0);
    asked += nameBytes(QStringLiteral("notify.example.com"));
    put16(asked, DnsServer::TypeSoa);
    put16(asked, 1);
    Reply refusedNotify;
    QVERIFY(parseReply(exchange(server.serverPort(), asked), &refusedNotify));
    QCOMPARE(refusedNotify.rcode, 5); // REFUSED

    // With the key cleared there is nothing to sign with, so the announcement
    // goes out unsigned rather than carrying a TSIG that proves nothing.
    server.setUpdateTsig(QString(), QString(), QByteArray());
    updates.clear();
    updates.append({QStringLiteral("again.notify.example.com"), DnsServer::TypeA, 1, 300,
                    QByteArray::fromHex("0a280002")});
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7403, QStringLiteral("notify.example.com"), {},
                                             updates)),
                       &updateReply));
    QCOMPARE(updateReply.rcode, 0);
    const QByteArray unsignedAnnounce = awaitDatagram(secondary, 3000);
    QVERIFY2(!unsignedAnnounce.isEmpty(), "an announcement is not tied to a key being set");
    Reply plainNotify;
    QVERIFY(parseReply(unsignedAnnounce, &plainNotify));
    QCOMPARE(plainNotify.answers.size(), 1);
    QCOMPARE(plainNotify.answers.first().type, DnsServer::TypeSoa);
    QVERIFY2(replyTsig(plainNotify) == nullptr,
             "no key means no signature, not a signature over nothing");
}

void DnsTest::retriesAnAnnouncementUntilTheSecondaryAnswers()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("retry.example.com"),
                      QStringLiteral("dc1.retry.example.com"), QStringLiteral("10.41.0.10"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));

    QUdpSocket secondary;
    QVERIFY(secondary.bind(QHostAddress::LocalHost, 0));
    server.setNotifyTargets({QStringLiteral("127.0.0.1:%1").arg(secondary.localPort())});
    // The schedule is an argument so this test can watch repeats without waiting
    // out the two-second default: the first repeat after 100 ms, doubling, at
    // most six datagrams.
    server.setNotifyRetry(100, 6);

    QList<UpdateRecord> updates;
    updates.append({QStringLiteral("added.retry.example.com"), DnsServer::TypeA, 1, 300,
                    QByteArray::fromHex("0a290001")});
    Reply updateReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7500, QStringLiteral("retry.example.com"), {},
                                             updates)),
                       &updateReply));
    QCOMPARE(updateReply.rcode, 0);

    auto collect = [](QUdpSocket &socket, int timeoutMs) {
        QList<QByteArray> received;
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
            if (!socket.hasPendingDatagrams() && !socket.waitForReadyRead(20))
                continue;
            while (socket.hasPendingDatagrams()) {
                QByteArray buffer;
                buffer.resize(int(socket.pendingDatagramSize()));
                const qint64 read = socket.readDatagram(buffer.data(), buffer.size());
                if (read > 0) {
                    buffer.truncate(int(read));
                    received.append(buffer);
                }
            }
        }
        return received;
    };

    // A datagram lost in the network is not the end of the announcement: the same
    // message is sent again, with the same id so an answer can be tied to it.
    const QList<QByteArray> repeats = collect(secondary, 1000);
    QVERIFY2(repeats.size() >= 3,
             qPrintable(QStringLiteral("an unanswered announcement is repeated (%1 datagrams)")
                            .arg(repeats.size())));
    Reply first;
    QVERIFY(parseReply(repeats.first(), &first));
    for (const QByteArray &datagram : repeats) {
        Reply repeat;
        QVERIFY(parseReply(datagram, &repeat));
        QCOMPARE(repeat.id, first.id);
        const quint16 flags = quint16((quint8(datagram[2]) << 8) | quint8(datagram[3]));
        QCOMPARE((flags >> 11) & 0x0f, 4); // still a NOTIFY
        QCOMPARE(flags & 0x8000, 0);       // still a request
        QCOMPARE(repeat.answers.size(), 1);
        QCOMPARE(soaSerial(repeat.answers.first().rdata), soaSerial(first.answers.first().rdata));
    }

    // The secondary's answer stops them. On this schedule another datagram would
    // land well inside the window below if the answer were ignored.
    QByteArray ack;
    put16(ack, first.id);
    put16(ack, quint16((4 << 11) | 0x8000 | 0x0400));
    put16(ack, 0);
    put16(ack, 0);
    put16(ack, 0);
    put16(ack, 0);
    secondary.writeDatagram(ack, QHostAddress::LocalHost, server.serverPort());

    QVERIFY2(collect(secondary, 1200).isEmpty(),
             "the secondary's answer ends the announcement");
}

void DnsTest::announcesTheZoneThatMoved()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    server.loadAdZone(QStringLiteral("moved.example.com"),
                      QStringLiteral("dc1.moved.example.com"), QStringLiteral("10.40.0.10"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    // loadAdZone publishes the forward zone; the /24 reverse zone comes from the
    // repair path, and the reverse zone is what this test is about.
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.moved.example.com"),
                                     QStringLiteral("10.40.0.10")));
    const QString forward = QStringLiteral("moved.example.com");
    const QString reverse = server.reverseZone();
    QCOMPARE(reverse, QStringLiteral("0.40.10.in-addr.arpa"));

    QUdpSocket secondary;
    QVERIFY(secondary.bind(QHostAddress::LocalHost, 0));
    server.setNotifyTargets({QStringLiteral("127.0.0.1:%1").arg(secondary.localPort())});

    auto awaitDatagram = [](QUdpSocket &socket, int timeoutMs) {
        QByteArray received;
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs && received.isEmpty()) {
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
                received = buffer;
            }
        }
        return received;
    };

    const quint32 forwardBefore =
        soaSerial(server.records(forward, DnsServer::TypeSoa).first().rdata);
    const quint32 reverseBefore =
        soaSerial(server.records(reverse, DnsServer::TypeSoa).first().rdata);

    // A PTR written into the reverse zone: the update names the forward zone and
    // the record lives under the reverse one, which is a zone this server serves.
    QList<UpdateRecord> ptrUpdate;
    ptrUpdate.append({QStringLiteral("5.") + reverse, DnsServer::TypePtr, 1, 1200,
                      nameBytes(QStringLiteral("moved1.moved.example.com."))});
    Reply ptrReply;
    QVERIFY(parseReply(exchange(server.serverPort(), updatePacket(0x7600, forward, {}, ptrUpdate)),
                       &ptrReply));
    QCOMPARE(ptrReply.rcode, 0);

    // The record moved in the reverse zone, so that is the serial that moves and
    // the zone the announcement names. Announcing the forward zone instead would
    // carry a version nobody changed, and a secondary comparing serials would
    // find nothing to pull while its reverse copy stayed stale.
    QCOMPARE(soaSerial(server.records(forward, DnsServer::TypeSoa).first().rdata), forwardBefore);
    const quint32 reverseAfter =
        soaSerial(server.records(reverse, DnsServer::TypeSoa).first().rdata);
    QVERIFY2(reverseAfter > reverseBefore, "a reverse-zone write moves the reverse serial");

    const QByteArray announce = awaitDatagram(secondary, 3000);
    QVERIFY2(!announce.isEmpty(), "a reverse-zone write is announced");
    Reply notify;
    QVERIFY(parseReply(announce, &notify));
    QCOMPARE(notify.answers.size(), 1);
    QCOMPARE(notify.answers.first().name.toLower(), reverse);
    QCOMPARE(soaSerial(notify.answers.first().rdata), reverseAfter);

    // A forward change announces the forward zone and nothing else.
    QList<UpdateRecord> addressUpdate;
    addressUpdate.append({QStringLiteral("moved2.moved.example.com"), DnsServer::TypeA, 1, 300,
                          QByteArray::fromHex("0a280064")});
    Reply addressReply;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                updatePacket(0x7601, forward, {}, addressUpdate)),
                       &addressReply));
    QCOMPARE(addressReply.rcode, 0);

    const QByteArray forwardAnnounce = awaitDatagram(secondary, 3000);
    QVERIFY2(!forwardAnnounce.isEmpty(), "a forward-zone write is announced");
    Reply forwardNotify;
    QVERIFY(parseReply(forwardAnnounce, &forwardNotify));
    QCOMPARE(forwardNotify.answers.size(), 1);
    QCOMPARE(forwardNotify.answers.first().name.toLower(), forward);
    QVERIFY(soaSerial(forwardNotify.answers.first().rdata) > forwardBefore);
}

void DnsTest::pullsTheCopyWhenTheMasterAnnouncesIt()
{
    const QString keyName = QStringLiteral("update-key");
    // The key as bytes; the server takes it base64-encoded, the test's own
    // HMAC helper takes it decoded.
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    const QString zone = QStringLiteral("sec.example.com");

    DnsServer primary;
    QVERIFY(primary.listen(0));
    primary.loadAdZone(zone, QStringLiteral("dc1.sec.example.com"),
                       QStringLiteral("10.60.0.10"), 389, 3268,
                       QStringLiteral("Default-First-Site-Name"));
    primary.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());
    const quint32 primarySerial =
        soaSerial(primary.records(zone, DnsServer::TypeSoa).first().rdata);

    DnsServer secondary;
    QVERIFY(secondary.listen(0));
    secondary.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());
    secondary.setMaster(QStringLiteral("127.0.0.1:%1").arg(primary.serverPort()), {zone});
    primary.setNotifyTargets({QStringLiteral("127.0.0.1:%1").arg(secondary.serverPort())});

    // Without an announcement: a secondary that starts after its master has a
    // stale copy or none, and its refresh is the pull it makes on its own.
    secondary.refreshSecondaryZones();
    QElapsedTimer startup;
    startup.start();
    while (secondary.secondarySerial(zone) != primarySerial && startup.elapsed() < 5000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    QCOMPARE(secondary.secondarySerial(zone), primarySerial);
    QCOMPARE(secondary.records(QStringLiteral("dc1.sec.example.com"), DnsServer::TypeA).size(), 1);

    // The copy answers like any authoritative zone, which is what a client sees
    // when it is pointed at the secondary.
    Reply copy;
    QVERIFY(parseReply(exchange(secondary.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("dc1.sec.example.com"),
                                                      DnsServer::TypeA, 0x7a00)),
                       &copy));
    QCOMPARE(copy.rcode, 0);
    QVERIFY2(copy.authoritative, "a copied zone is answered as authoritative");
    QCOMPARE(copy.answers.size(), 1);

    // The master moves the serial, announces it, and the secondary pulls that
    // version rather than the one it started with.
    QList<UpdateRecord> updates;
    updates.append({QStringLiteral("copy.sec.example.com"), DnsServer::TypeA, 1, 300,
                    QByteArray::fromHex("0a3c0001")});
    // The master requires the key for updates, and an unsigned update is
    // NOTAUTH; signing it is also what makes the announcement signed, which is
    // what the secondary holds this server to.
    Reply updateReply;
    QVERIFY(parseReply(exchange(primary.serverPort(),
                                withTsig(updatePacket(0x7a01, zone, {}, updates), keyName,
                                         QStringLiteral("hmac-sha256"), secret,
                                         quint64(QDateTime::currentSecsSinceEpoch()), 300)),
                       &updateReply));
    QCOMPARE(updateReply.rcode, 0);
    const quint32 movedSerial = soaSerial(primary.records(zone, DnsServer::TypeSoa).first().rdata);
    QVERIFY(movedSerial > primarySerial);

    QElapsedTimer announced;
    announced.start();
    while (secondary.secondarySerial(zone) != movedSerial && announced.elapsed() < 5000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    QCOMPARE(secondary.secondarySerial(zone), movedSerial);
    QCOMPARE(secondary.records(QStringLiteral("copy.sec.example.com"), DnsServer::TypeA).size(), 1);

    // The master going away is the case the copy exists for.
    primary.close();
    Reply offline;
    QVERIFY(parseReply(exchange(secondary.serverPort(),
                                DnsServer::buildQuery(QStringLiteral("copy.sec.example.com"),
                                                      DnsServer::TypeA, 0x7a02)),
                       &offline));
    QCOMPARE(offline.rcode, 0);
    QCOMPARE(offline.answers.size(), 1);
}

void DnsTest::remembersTheDifferenceAcrossARestart()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("dnszone.json"));
    const QString zone = QStringLiteral("restart.example.com");
    const QString keyName = QStringLiteral("restart-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    const QByteArray keepRdata = QByteArray::fromHex("0a1f0001");
    const QByteArray goingRdata = QByteArray::fromHex("0a1f0002");
    const QByteArray arrivedRdata = QByteArray::fromHex("0a1f0003");
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());

    quint32 before = 0;
    quint32 after = 0;
    {
        DnsServer server;
        QVERIFY(server.listen(0));
        server.loadAdZone(zone, QStringLiteral("dc1.restart.example.com"),
                          QStringLiteral("10.31.0.10"), 389, 3268,
                          QStringLiteral("Default-First-Site-Name"));
        server.addRecord(QStringLiteral("keep.restart.example.com"), DnsServer::TypeA, 300,
                         keepRdata);
        server.addRecord(QStringLiteral("going.restart.example.com"), DnsServer::TypeA, 300,
                         goingRdata);
        server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());
        before = soaSerial(server.records(zone, DnsServer::TypeSoa).first().rdata);
        QString error;
        QVERIFY2(server.saveZone(path, &error), qPrintable(error));

        QList<UpdateRecord> updates;
        updates.append({QStringLiteral("arrived.restart.example.com"), DnsServer::TypeA, 1, 300,
                        arrivedRdata});
        updates.append({QStringLiteral("going.restart.example.com"), DnsServer::TypeA, 255, 0, {}});
        Reply update;
        QVERIFY(parseReply(exchange(server.serverPort(),
                                    withTsig(updatePacket(0x7a00, zone, {}, updates), keyName,
                                             algorithm, secret, now, 300)),
                           &update));
        QCOMPARE(update.rcode, 0);
        after = soaSerial(server.records(zone, DnsServer::TypeSoa).first().rdata);
        QVERIFY(after > before);
        // The daemon saves the zone after every applied update, so the difference
        // has to be in that file or the restart below would never see it.
        QVERIFY2(server.saveZone(path, &error), qPrintable(error));
    }

    DnsServer restored;
    QVERIFY(restored.listen(0));
    QString error;
    QVERIFY2(restored.loadZone(path, &error), qPrintable(error));
    restored.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());
    QCOMPARE(restored.zone(), zone);
    const QList<DnsServer::Record> soa = restored.records(zone, DnsServer::TypeSoa);
    QCOMPARE(soa.size(), 1);
    QCOMPARE(soaSerial(soa.first().rdata), after);

    // The client was at the version before the update; the reloaded server has to
    // answer with the same six-record difference the running one would have, not
    // with the whole zone it would fall back to if the journal had been lost.
    Reply delta;
    QVERIFY(parseReply(exchangeTcp(restored.serverPort(),
                                   withTsig(ixfrQuery(0x7a01, zone,
                                                      soaWithSerial(soa.first().rdata, before)),
                                            keyName, algorithm, secret, now, 300)),
                       &delta));
    QCOMPARE(delta.rcode, 0);
    QVERIFY(delta.authoritative);
    QCOMPARE(delta.answers.size(), 6);
    QCOMPARE(soaSerial(delta.answers.at(0).rdata), after);
    QCOMPARE(soaSerial(delta.answers.at(1).rdata), before);
    QCOMPARE(delta.answers.at(2).name.toLower(), QStringLiteral("going.restart.example.com"));
    QCOMPARE(delta.answers.at(2).rdata, goingRdata);
    QCOMPARE(soaSerial(delta.answers.at(3).rdata), after);
    QCOMPARE(delta.answers.at(4).name.toLower(), QStringLiteral("arrived.restart.example.com"));
    QCOMPARE(delta.answers.at(4).rdata, arrivedRdata);
    QCOMPARE(soaSerial(delta.answers.at(5).rdata), after);
    for (const Answer &answer : delta.answers) {
        QVERIFY2(answer.name.toLower() != QStringLiteral("keep.restart.example.com"),
                 "a restart costs a lagging client its difference only when the serial is gone");
    }
}

void DnsTest::gatesATransferOnTheZonesTheKeyMayRead()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    const QString zone = QStringLiteral("acl.example.com");
    server.loadAdZone(zone, QStringLiteral("dc1.acl.example.com"), QStringLiteral("10.33.0.10"),
                      389, 3268, QStringLiteral("Default-First-Site-Name"));
    server.addRecord(QStringLiteral("files.acl.example.com"), DnsServer::TypeA, 300,
                     QByteArray::fromHex("0a210001"));
    // The same store holds the reverse zone this DC answers for; a transfer of it
    // must carry its records, not the forward zone's.
    QVERIFY(server.repairReverseZone(QStringLiteral("dc1.acl.example.com"),
                                     QStringLiteral("10.33.0.10")));
    const QString keyName = QStringLiteral("acl-key");
    const QString algorithm = QStringLiteral("hmac-sha256.");
    const QByteArray secret = QByteArray("0123456789abcdef0123456789abcdef");
    server.setUpdateTsig(keyName, QStringLiteral("hmac-sha256"), secret.toBase64());
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    const auto axfr = [&zone](quint16 id) {
        return DnsServer::buildQuery(zone, DnsServer::TypeAxfr, id);
    };

    // No list configured: the key keeps the reach it had, so an upgrade does not
    // silently stop serving a peer that used to be served.
    QVERIFY(server.transferZones().isEmpty());
    Reply open;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(axfr(0x7b01), keyName, algorithm, secret, now, 300)),
                       &open));
    QCOMPARE(open.rcode, 0);
    QCOMPARE(open.answers.first().type, DnsServer::TypeSoa);
    QVERIFY(open.answers.size() > 2);

    // Narrowed to a zone this server does not hold: a good MAC is not a licence.
    server.setTransferZones({QStringLiteral("elsewhere.example.com.")});
    QCOMPARE(server.transferZones(), QStringList{QStringLiteral("elsewhere.example.com")});
    Reply refused;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(axfr(0x7b02), keyName, algorithm, secret, now, 300)),
                       &refused));
    QCOMPARE(refused.rcode, 5); // REFUSED
    QVERIFY(refused.answers.isEmpty());

    // The zone the key is narrowed to is still served, so the gate is per zone
    // rather than a blanket refusal whenever a list is set.
    server.setTransferZones({zone.toUpper() + QStringLiteral(".")});
    Reply served;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(axfr(0x7b03), keyName, algorithm, secret, now, 300)),
                       &served));
    QCOMPARE(served.rcode, 0);
    QCOMPARE(served.answers.size(), open.answers.size());

    // A transfer carries the zone that was asked for. Narrowed to the reverse
    // zone, the key is served that zone with its own SOA and PTR, and none of the
    // forward zone's names travel with it.
    const QString reverseZone = QStringLiteral("0.33.10.in-addr.arpa");
    server.setTransferZones({reverseZone});
    Reply reverse;
    QVERIFY(parseReply(exchangeTcp(server.serverPort(),
                                   withTsig(DnsServer::buildQuery(reverseZone, DnsServer::TypeAxfr,
                                                                 0x7b04),
                                            keyName, algorithm, secret, now, 300)),
                       &reverse));
    QCOMPARE(reverse.rcode, 0);
    QCOMPARE(reverse.answers.first().name.toLower(), reverseZone);
    QCOMPARE(reverse.answers.first().type, DnsServer::TypeSoa);
    bool sawPtr = false;
    bool sawForwardName = false;
    for (const Answer &answer : reverse.answers) {
        if (answer.type == DnsServer::TypePtr)
            sawPtr = true;
        if (answer.name.toLower().endsWith(QStringLiteral(".acl.example.com")))
            sawForwardName = true;
    }
    QVERIFY2(sawPtr, "the reverse zone's PTR record travels in its own transfer");
    QVERIFY2(!sawForwardName, "the forward zone does not travel in a reverse zone's transfer");
}

void DnsTest::negotiatesGssTsigAndSignsUpdates()
{
    DnsServer server;
    QVERIFY(server.listen(0));
    const QString zone = QStringLiteral("corp.example.com");
    server.loadAdZone(zone, QStringLiteral("dc1.corp.example.com"),
                      QStringLiteral("192.168.5.20"), 389, 3268,
                      QStringLiteral("Default-First-Site-Name"));
    QVERIFY(!server.gssTsigEnabled());

    const QString keyName = QStringLiteral("gss-key.corp.example.com");
    const QByteArray contextKey(32, 'k'); // AES-256 context key
    const QByteArray clientToken = QByteArrayLiteral("client-token");
    const QByteArray serverToken = QByteArrayLiteral("server-token");

    // RFC 4121 §4.2.6.1 MIC, written out here rather than borrowed from the
    // implementation: header, sequence, then HMAC-SHA1-96 over header|message
    // under the sign usage for the side that made it (23 acceptor, 25
    // initiator, RFC 4121 §7).
    const auto gssMic = [](const QByteArray &data, quint64 seq, const QByteArray &key,
                           bool acceptor) {
        QByteArray token = QByteArrayLiteral("\x04\x04");
        token.append(char((acceptor ? 0x01 : 0x00) | 0x04));
        token.append(char(0xff));
        put16(token, 0xffff);
        put16(token, 0xffff);
        for (int shift = 56; shift >= 0; shift -= 8)
            token.append(char((seq >> shift) & 0xff));
        token += Krb5::checksum(Krb5::kAes256, acceptor ? 23 : 25, key, data + token);
        return token;
    };

    const auto tkeyQuery = [](quint16 id, const QString &name, const QByteArray &token,
                              quint16 mode = 3,
                              const QString &algorithm = QStringLiteral("gss-tsig")) {
        QByteArray packet;
        put16(packet, id);
        put16(packet, 0x0000); // standard query
        put16(packet, 1);      // one question
        put16(packet, 0);
        put16(packet, 0);
        put16(packet, 1); // the TKEY is the one additional record
        packet += nameBytes(name);
        put16(packet, DnsServer::TypeTkey);
        put16(packet, 255); // class ANY
        const quint32 now = quint32(QDateTime::currentSecsSinceEpoch());
        QByteArray rdata;
        rdata += nameBytes(algorithm);
        put32(rdata, now);
        put32(rdata, now + 3600);
        put16(rdata, mode);
        put16(rdata, 0); // no error
        put16(rdata, quint16(token.size()));
        rdata += token;
        put16(rdata, 0);
        packet += nameBytes(name);
        put16(packet, DnsServer::TypeTkey);
        put16(packet, 255);
        put32(packet, 0);
        put16(packet, quint16(rdata.size()));
        packet += rdata;
        return packet;
    };

    const auto appendGssTsig = [](QByteArray message, const QString &name,
                                   const QByteArray &mac, quint64 when) {
        const quint16 arcount = quint16((quint8(message[10]) << 8) | quint8(message[11]));
        const quint16 next = quint16(arcount + 1);
        message[10] = char((next >> 8) & 0xff);
        message[11] = char(next & 0xff);
        QByteArray rdata;
        rdata += nameBytes(QStringLiteral("gss-tsig"));
        for (int shift = 40; shift >= 0; shift -= 8)
            rdata.append(char((when >> shift) & 0xff));
        put16(rdata, 300);
        put16(rdata, quint16(mac.size()));
        rdata += mac;
        put16(rdata, quint16((quint8(message[0]) << 8) | quint8(message[1])));
        put16(rdata, 0);
        put16(rdata, 0);
        message += nameBytes(name);
        put16(message, 250);
        put16(message, 255);
        put32(message, 0);
        put16(message, quint16(rdata.size()));
        message += rdata;
        return message;
    };

    // Without an acceptor there is no context to establish, so a TKEY query is
    // refused rather than answered as if one had been negotiated.
    Reply noAcceptor;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                tkeyQuery(0x8a01, keyName, clientToken)),
                       &noAcceptor));
    QCOMPARE(noAcceptor.rcode, 5); // REFUSED
    QVERIFY(!server.hasGssContext(keyName));

    server.setGssAcceptor([&](const QByteArray &token, DnsServer::GssContext *context,
                              QString *) {
        if (token != clientToken)
            return false;
        context->key = contextKey;
        context->etype = Krb5::kAes256;
        context->principal = QStringLiteral("dc1$@CORP.EXAMPLE.COM");
        context->replyToken = serverToken;
        return true;
    });
    QVERIFY(server.gssTsigEnabled());

    // A GSS-API token in a TKEY query establishes the context; the answer
    // carries the acceptor's token and is signed over the new key with seq 0.
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    const QByteArray tkeyRaw = exchange(server.serverPort(), tkeyQuery(0x8a02, keyName, clientToken));
    Reply tkeyReply;
    QVERIFY(parseReply(tkeyRaw, &tkeyReply));
    QCOMPARE(tkeyReply.rcode, 0);
    QCOMPARE(tkeyReply.answers.size(), 1);
    QCOMPARE(tkeyReply.answers.first().type, quint16(249));
    QCOMPARE(tkeyReply.answers.first().rclass, quint16(255));
    int tkeyPos = 0;
    QCOMPARE(readName(tkeyReply.answers.first().rdata, tkeyPos), QStringLiteral("gss-tsig"));
    tkeyPos += 4 + 4;
    quint16 tkeyMode = 0, tkeyError = 0, keyLength = 0;
    QVERIFY(take16(tkeyReply.answers.first().rdata, tkeyPos, &tkeyMode));
    QVERIFY(take16(tkeyReply.answers.first().rdata, tkeyPos, &tkeyError));
    QVERIFY(take16(tkeyReply.answers.first().rdata, tkeyPos, &keyLength));
    QCOMPARE(tkeyMode, quint16(3));
    QCOMPARE(tkeyError, quint16(0));
    QCOMPARE(tkeyReply.answers.first().rdata.mid(tkeyPos, keyLength), serverToken);
    QVERIFY(server.hasGssContext(keyName));

    const Answer *tkeyTsig = replyTsig(tkeyReply);
    QVERIFY2(tkeyTsig != nullptr, "a completed TKEY negotiation must be signed");
    TsigReply tkeySignature;
    QVERIFY(parseTsigRdata(tkeyTsig->rdata, &tkeySignature));
    QCOMPARE(tkeySignature.algorithm, QStringLiteral("gss-tsig"));
    QCOMPARE(tkeySignature.mac.size(), 28); // 16-byte MIC header + 12-byte HMAC
    const int tkeyTsigStart =
        tkeyRaw.size() - (nameBytes(keyName).size() + 10 + tkeyTsig->rdata.size());
    QByteArray tkeyDigest = tkeyRaw.left(tkeyTsigStart);
    const quint16 tkeyArcount =
        quint16((quint8(tkeyDigest[10]) << 8) | quint8(tkeyDigest[11]));
    tkeyDigest[10] = char((quint16(tkeyArcount - 1) >> 8) & 0xff);
    tkeyDigest[11] = char((quint16(tkeyArcount - 1)) & 0xff);
    tkeyDigest += tsigVariables(keyName, QStringLiteral("gss-tsig"),
                                tkeySignature.timeSigned, tkeySignature.fudge, 0, {});
    QCOMPARE(tkeySignature.mac, gssMic(tkeyDigest, 0, contextKey, true));

    // An UPDATE naming the context is accepted when its MAC is the client's
    // MIC at the next sequence number, and the reply is signed at the server's.
    UpdateRecord add;
    add.name = QStringLiteral("gss1.corp.example.com");
    add.type = DnsServer::TypeA;
    add.rclass = 1;
    add.ttl = 300;
    add.rdata = QByteArray::fromHex("0a0000aa");
    const QByteArray update = updatePacket(0x8a03, zone, {}, {add});
    const QByteArray clientMic = gssMic(
        update + tsigVariables(keyName, QStringLiteral("gss-tsig"), now, 300, 0, {}), 0,
        contextKey, false);
    const QByteArray signedUpdate =
        appendGssTsig(update, keyName, clientMic, now);

    const QByteArray updateRaw = exchange(server.serverPort(), signedUpdate);
    Reply accepted;
    QVERIFY(parseReply(updateRaw, &accepted));
    QCOMPARE(accepted.rcode, 0);
    QCOMPARE(server.records(add.name, DnsServer::TypeA).size(), 1);

    const Answer *updateTsig = replyTsig(accepted);
    QVERIFY(updateTsig != nullptr);
    TsigReply updateSignature;
    QVERIFY(parseTsigRdata(updateTsig->rdata, &updateSignature));
    const int updateTsigStart =
        updateRaw.size() - (nameBytes(keyName).size() + 10 + updateTsig->rdata.size());
    QByteArray updateDigest = updateRaw.left(updateTsigStart);
    const quint16 updateArcount =
        quint16((quint8(updateDigest[10]) << 8) | quint8(updateDigest[11]));
    updateDigest[10] = char((quint16(updateArcount - 1) >> 8) & 0xff);
    updateDigest[11] = char((quint16(updateArcount - 1)) & 0xff);
    QByteArray requestPrefix;
    put16(requestPrefix, quint16(clientMic.size()));
    requestPrefix += clientMic;
    updateDigest = requestPrefix + updateDigest
                   + tsigVariables(keyName, QStringLiteral("gss-tsig"),
                                   updateSignature.timeSigned, updateSignature.fudge, 0, {});
    QCOMPARE(updateSignature.mac, gssMic(updateDigest, 1, contextKey, true));

    // The same bytes again are a replay: the MIC verifies but carries the
    // sequence number the first message used, so nothing is written twice.
    Reply replayed;
    QVERIFY(parseReply(exchange(server.serverPort(), signedUpdate), &replayed));
    QCOMPARE(replayed.rcode, 9); // NOTAUTH
    QCOMPARE(server.records(add.name, DnsServer::TypeA).size(), 1);
    const Answer *replayTsig = replyTsig(replayed);
    QVERIFY(replayTsig != nullptr);
    TsigReply replaySignature;
    QVERIFY(parseTsigRdata(replayTsig->rdata, &replaySignature));
    QCOMPARE(replaySignature.error, quint16(16)); // BADSIG
    QCOMPARE(replaySignature.mac.size(), 0);      // nothing verified, nothing claimed
    QCOMPARE(replayTsig->name.toLower(), keyName);
    QCOMPARE(replaySignature.algorithm, QStringLiteral("gss-tsig"));

    // An UPDATE naming a context this server never issued gets BADKEY, and the
    // refusal still carries a TSIG under the request's own name so a client can
    // tell an unknown key from a dropped packet.
    const QString unknownName = QStringLiteral("unknown.corp.example.com");
    const QByteArray unknownUpdate =
        appendGssTsig(updatePacket(0x8a04, zone, {}, {add}), unknownName,
                      QByteArray(28, 'x'), now);
    Reply unknownReply;
    QVERIFY(parseReply(exchange(server.serverPort(), unknownUpdate), &unknownReply));
    QCOMPARE(unknownReply.rcode, 9); // NOTAUTH
    const Answer *unknownTsig = replyTsig(unknownReply);
    QVERIFY2(unknownTsig != nullptr, "a BADKEY refusal still carries the TSIG RR");
    QCOMPARE(unknownTsig->name.toLower(), unknownName);
    TsigReply unknownSignature;
    QVERIFY(parseTsigRdata(unknownTsig->rdata, &unknownSignature));
    QCOMPARE(unknownSignature.error, quint16(17)); // BADKEY
    QCOMPARE(unknownSignature.mac.size(), 0);
    QCOMPARE(unknownSignature.algorithm, QStringLiteral("gss-tsig"));

    // TKEY failures live in the RR's error field while the header stays NOERROR
    // (RFC 2930 §2.6), and the answer echoes the mode and algorithm asked for.
    const auto parseTkeyError = [](const Reply &reply, quint16 *mode, quint16 *error,
                                   QString *algorithm) {
        if (reply.answers.size() != 1)
            return false;
        int pos = 0;
        *algorithm = readName(reply.answers.first().rdata, pos);
        pos += 4 + 4; // inception, expiration
        return take16(reply.answers.first().rdata, pos, mode)
               && take16(reply.answers.first().rdata, pos, error);
    };

    // A mode this server does not serve is BADMODE (19), not 22 (BADTRUNC), and
    // not a DNS rcode that would blame the transport.
    Reply badMode;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                tkeyQuery(0x8a05, QStringLiteral("mode.corp.example.com"),
                                          {}, 4)),
                       &badMode));
    QCOMPARE(badMode.rcode, 0);
    quint16 modeField = 0, errorField = 0;
    QString reportedAlgorithm;
    QVERIFY(parseTkeyError(badMode, &modeField, &errorField, &reportedAlgorithm));
    QCOMPARE(modeField, quint16(4));
    QCOMPARE(errorField, quint16(19)); // BADMODE
    QCOMPARE(reportedAlgorithm, QStringLiteral("gss-tsig"));

    // An algorithm this server cannot negotiate is BADALG (21), echoed back.
    Reply badAlgorithm;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                tkeyQuery(0x8a06, QStringLiteral("alg.corp.example.com"),
                                          {}, 3, QStringLiteral("hmac-sha256"))),
                       &badAlgorithm));
    QCOMPARE(badAlgorithm.rcode, 0);
    QVERIFY(parseTkeyError(badAlgorithm, &modeField, &errorField, &reportedAlgorithm));
    QCOMPARE(errorField, quint16(21)); // BADALG
    QCOMPARE(reportedAlgorithm, QStringLiteral("hmac-sha256"));

    // Deleting a name this server never issued is BADNAME (20), not a silent
    // success that leaves the client believing the key was retired here.
    Reply badName;
    QVERIFY(parseReply(exchange(server.serverPort(),
                                tkeyQuery(0x8a07, QStringLiteral("absent.corp.example.com"),
                                          {}, 5)),
                       &badName));
    QCOMPARE(badName.rcode, 0);
    QVERIFY(parseTkeyError(badName, &modeField, &errorField, &reportedAlgorithm));
    QCOMPARE(errorField, quint16(20)); // BADNAME
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
