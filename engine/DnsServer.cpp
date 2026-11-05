// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DnsServer.h"

#include <QDate>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>
#include <algorithm>

namespace {

// DNS result codes (RFC 1035 §4.1.1 and RFC 2136 §2.2).
enum : int {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YxDomain = 6,
    YxRrset = 7,
    NxRrset = 8,
    NotAuth = 9,
    NotZone = 10
};

enum : quint16 {
    ClassIn = 1,
    ClassNone = 254,
    ClassAny = 255
};

bool take16(const QByteArray &d, int &pos, quint16 *out) {
    if (pos < 0 || pos + 2 > d.size())
        return false;
    *out = quint16((quint8(d[pos]) << 8) | quint8(d[pos + 1]));
    pos += 2;
    return true;
}

bool take32(const QByteArray &d, int &pos, quint32 *out) {
    if (pos < 0 || pos + 4 > d.size())
        return false;
    *out = (quint32(quint8(d[pos])) << 24) | (quint32(quint8(d[pos + 1])) << 16)
           | (quint32(quint8(d[pos + 2])) << 8) | quint32(quint8(d[pos + 3]));
    pos += 4;
    return true;
}

void wr16(QByteArray &out, quint16 v) {
    out.append(char((v >> 8) & 0xff));
    out.append(char(v & 0xff));
}

void wr32(QByteArray &out, quint32 v) {
    out.append(char((v >> 24) & 0xff));
    out.append(char((v >> 16) & 0xff));
    out.append(char((v >> 8) & 0xff));
    out.append(char(v & 0xff));
}

// Decodes a possibly compressed name starting at `pos`, leaving `pos` on the
// first byte after the name in the original stream.
QString decodeName(const QByteArray &packet, int &pos) {
    QStringList labels;
    int cursor = pos;
    int after = -1;
    int guard = 0;
    while (guard++ < 128) {
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
            const int target = ((len & 0x3f) << 8) | quint8(packet[cursor + 1]);
            if (after < 0)
                after = cursor + 2;
            if (target >= cursor)
                break; // forward pointers are invalid; refuse loops
            cursor = target;
            continue;
        }
        if (cursor + 1 + len > packet.size())
            break;
        labels.append(QString::fromUtf8(packet.mid(cursor + 1, len)));
        cursor += 1 + len;
    }
    if (after < 0)
        after = qMin(cursor + 1, packet.size());
    pos = after;
    return labels.join(QLatin1Char('.'));
}

QByteArray encodeName(const QString &name) {
    QByteArray out;
    for (const QString &label : name.split(QLatin1Char('.'), Qt::SkipEmptyParts)) {
        const QByteArray bytes = label.toUtf8();
        if (bytes.isEmpty() || bytes.size() > 63)
            continue;
        out.append(char(bytes.size()));
        out.append(bytes);
    }
    out.append('\0');
    return out;
}

// Skips an uncompressed name inside rdata.
bool skipName(const QByteArray &data, int &pos) {
    int guard = 0;
    while (pos < data.size() && guard++ < 128) {
        const quint8 len = quint8(data[pos]);
        if (len == 0) {
            pos += 1;
            return true;
        }
        if ((len & 0xc0) != 0)
            return false;
        pos += 1 + len;
    }
    return false;
}

bool isNameBearing(quint16 type) {
    return type == 2 /*NS*/ || type == 5 /*CNAME*/ || type == 6 /*SOA*/ || type == 12 /*PTR*/
           || type == 15 /*MX*/ || type == 33 /*SRV*/;
}

// Update messages carry compressed names inside rdata. Those pointers are only
// valid for the packet that delivered them, so every rdata we store is rewritten
// into its uncompressed form.
QByteArray normalizeRdata(const QByteArray &packet, int rdataStart, quint16 type,
                          const QByteArray &raw) {
    if (!isNameBearing(type))
        return raw;

    QByteArray out;
    int pos = rdataStart;
    auto copyPrefix = [&](int bytes) {
        if (rdataStart + bytes > packet.size())
            return false;
        out.append(packet.mid(rdataStart, bytes));
        pos = rdataStart + bytes;
        return true;
    };

    if (type == 6) { // SOA: mname, rname, then five 32-bit values
        const QString mname = decodeName(packet, pos);
        const QString rname = decodeName(packet, pos);
        if (mname.isEmpty() || rname.isEmpty() || pos + 20 > packet.size())
            return raw;
        out += encodeName(mname);
        out += encodeName(rname);
        out.append(packet.mid(pos, 20));
        return out;
    }

    int prefix = 0;
    if (type == 15) // MX: preference
        prefix = 2;
    else if (type == 33) // SRV: priority, weight, port
        prefix = 6;
    if (!copyPrefix(prefix))
        return raw;
    const QString target = decodeName(packet, pos);
    if (target.isEmpty())
        return raw;
    out += encodeName(target);
    return out;
}

QString targetOfSrv(const QByteArray &rdata) {
    if (rdata.size() < 7)
        return {};
    int pos = 6;
    return decodeName(rdata, pos);
}

// Accepts "192.0.2.1", "192.0.2.1:5353", "2001:db8::1" or
// "[2001:db8::1]:5353". Names are deliberately not resolved here: using the
// system resolver to look up a forwarder would recurse through this server.
bool parseForwarder(const QString &spec, QHostAddress *address, quint16 *port)
{
    QString host = spec.trimmed();
    quint16 value = 53;
    if (host.isEmpty())
        return false;

    if (host.startsWith(QLatin1Char('['))) {
        const int close = host.indexOf(QLatin1Char(']'));
        if (close < 0)
            return false;
        const QString rest = host.mid(close + 1);
        host = host.mid(1, close - 1);
        if (!rest.isEmpty()) {
            if (!rest.startsWith(QLatin1Char(':')))
                return false;
            bool ok = false;
            const uint parsed = rest.mid(1).toUInt(&ok);
            if (!ok || parsed == 0 || parsed > 65535)
                return false;
            value = quint16(parsed);
        }
    } else if (host.count(QLatin1Char(':')) == 1) {
        const int colon = host.indexOf(QLatin1Char(':'));
        bool ok = false;
        const uint parsed = host.mid(colon + 1).toUInt(&ok);
        if (ok) {
            if (parsed == 0 || parsed > 65535)
                return false;
            value = quint16(parsed);
            host = host.left(colon);
        }
    }

    const QHostAddress parsedAddress(host);
    if (parsedAddress.isNull())
        return false;
    *address = parsedAddress;
    *port = value;
    return true;
}

QString cacheKeyFor(const QString &name, quint16 type, quint16 qclass)
{
    return name.toLower() + QLatin1Char('|') + QString::number(type) + QLatin1Char('|')
           + QString::number(qclass);
}

// Records the offset of every TTL field in the answer, authority and
// additional sections (so a cached packet can be aged) and returns the
// smallest TTL. OPT pseudo-records are skipped: their TTL field is flags.
bool collectTtls(const QByteArray &packet, QList<int> *offsets, quint32 *minTtl)
{
    int pos = 0;
    quint16 ignored = 0, qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    if (!take16(packet, pos, &ignored) || !take16(packet, pos, &ignored)
        || !take16(packet, pos, &qdcount) || !take16(packet, pos, &ancount)
        || !take16(packet, pos, &nscount) || !take16(packet, pos, &arcount))
        return false;

    for (int i = 0; i < qdcount; ++i) {
        decodeName(packet, pos);
        quint16 ignored = 0;
        if (!take16(packet, pos, &ignored) || !take16(packet, pos, &ignored))
            return false;
    }

    const int total = int(ancount) + int(nscount) + int(arcount);
    for (int i = 0; i < total; ++i) {
        decodeName(packet, pos);
        quint16 type = 0, ignoredClass = 0, rdlength = 0;
        quint32 ttl = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &ignoredClass))
            return false;
        Q_UNUSED(ignoredClass)
        const int ttlOffset = pos;
        if (!take32(packet, pos, &ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        pos += rdlength;
        if (type == 41) // OPT: TTL carries extended rcode/version/flags
            continue;
        offsets->append(ttlOffset);
        if (ttl < *minTtl)
            *minTtl = ttl;
    }
    return true;
}

} // namespace

struct DnsServer::Message {
    struct Question {
        QString name;
        quint16 type = 0;
        quint16 qclass = 1;
    };

    quint16 id = 0;
    quint16 flags = 0;
    quint16 qdcount = 0;
    quint16 ancount = 0;
    quint16 nscount = 0;
    quint16 arcount = 0;
    QList<Question> questions;
    QList<Record> prerequisites;
    QList<Record> updates;
    QList<Record> additional;
    bool ok = false;
};

namespace {

bool parseRecord(const QByteArray &packet, int &pos, DnsServer::Record *out) {
    DnsServer::Record record;
    record.name = decodeName(packet, pos);
    quint16 type = 0;
    quint16 rclass = 0;
    quint32 ttl = 0;
    quint16 rdlength = 0;
    if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass) || !take32(packet, pos, &ttl)
        || !take16(packet, pos, &rdlength))
        return false;
    if (pos + rdlength > packet.size())
        return false;
    const QByteArray raw = packet.mid(pos, rdlength);
    record.type = type;
    record.rclass = rclass;
    record.ttl = ttl;
    record.rdata = normalizeRdata(packet, pos, type, raw);
    pos += rdlength;
    *out = record;
    return true;
}

bool parseMessage(const QByteArray &packet, DnsServer::Message *message) {
    int pos = 0;
    if (!take16(packet, pos, &message->id) || !take16(packet, pos, &message->flags)
        || !take16(packet, pos, &message->qdcount) || !take16(packet, pos, &message->ancount)
        || !take16(packet, pos, &message->nscount) || !take16(packet, pos, &message->arcount))
        return false;

    for (int i = 0; i < message->qdcount; ++i) {
        DnsServer::Message::Question question;
        question.name = decodeName(packet, pos);
        if (!take16(packet, pos, &question.type) || !take16(packet, pos, &question.qclass))
            return false;
        message->questions.append(question);
    }

    // For a query these are the answer/authority/additional sections. In an
    // UPDATE message the same fields carry the prerequisite, update and
    // additional sections (RFC 2136 §2), so they are collected separately.
    for (int i = 0; i < message->ancount; ++i) {
        DnsServer::Record record;
        if (!parseRecord(packet, pos, &record))
            return false;
        message->prerequisites.append(record);
    }
    for (int i = 0; i < message->nscount; ++i) {
        DnsServer::Record record;
        if (!parseRecord(packet, pos, &record))
            return false;
        message->updates.append(record);
    }
    for (int i = 0; i < message->arcount; ++i) {
        DnsServer::Record record;
        if (!parseRecord(packet, pos, &record))
            return false;
        message->additional.append(record);
    }
    message->ok = true;
    return true;
}

} // namespace

DnsServer::DnsServer(QObject *parent) : QObject(parent) {
    m_socket = new QUdpSocket(this);
    connect(m_socket, &QUdpSocket::readyRead, this, &DnsServer::onReadyRead);

    m_upstreamSocket = new QUdpSocket(this);
    if (!m_upstreamSocket->bind(QHostAddress::Any, 0))
        m_upstreamSocket->bind(QHostAddress::AnyIPv4, 0);
    connect(m_upstreamSocket, &QUdpSocket::readyRead, this, &DnsServer::onUpstreamReadyRead);

    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &DnsServer::onNewTcpConnection);
}

DnsServer::~DnsServer() {
    close();
}

bool DnsServer::listen(quint16 port) {
    // TCP is part of DNS, not a fallback: it binds the same number as UDP. UDP
    // and TCP have separate port spaces, so when the caller asks for port 0 the
    // number the kernel hands the UDP socket can already belong to an unrelated
    // TCP socket, and the pair cannot be completed. Asking for an ephemeral port
    // therefore means "any port that carries both", so draw again rather than
    // failing the listener. A port that was asked for by number is bound once.
    const int attempts = port == 0 ? 16 : 1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (!m_socket->bind(QHostAddress::Any, port))
            return false;
        if (m_tcpServer->isListening()
            || m_tcpServer->listen(QHostAddress::Any, m_socket->localPort()))
            return true;
        m_socket->close();
    }
    return false;
}

void DnsServer::close() {
    const QSet<QTcpSocket *> clients = m_tcpClients;
    m_tcpClients.clear();
    m_tcpClientBuffers.clear();
    for (QTcpSocket *client : clients)
        client->abort();
    m_tcpServer->close();
    m_socket->close();
}

bool DnsServer::isListening() const {
    return m_socket->state() == QAbstractSocket::BoundState;
}

quint16 DnsServer::serverPort() const {
    return m_socket->localPort();
}

void DnsServer::setZone(const QString &zone) {
    m_zone = zone.toLower();
}

QString DnsServer::zone() const {
    return m_zone;
}

void DnsServer::setDynamicUpdatesEnabled(bool enabled) {
    m_updatesEnabled = enabled;
}

bool DnsServer::dynamicUpdatesEnabled() const {
    return m_updatesEnabled;
}

void DnsServer::setForwardingEnabled(bool enabled)
{
    m_forwarding = enabled;
}

bool DnsServer::forwardingEnabled() const
{
    return m_forwarding;
}

void DnsServer::setForwarders(const QStringList &forwarders)
{
    m_forwarders.clear();
    for (const QString &forwarder : forwarders) {
        if (!forwarder.trimmed().isEmpty())
            m_forwarders.append(forwarder.trimmed());
    }
}

QStringList DnsServer::forwarders() const
{
    return m_forwarders;
}

void DnsServer::clearCache()
{
    m_cache.clear();
}

int DnsServer::cachedResponseCount() const
{
    return m_cache.size();
}

QList<DnsServer::Record> &DnsServer::recordList(const QString &name) {
    return m_records[name.toLower()];
}

void DnsServer::addRecord(const QString &name, quint16 type, quint32 ttl, const QByteArray &rdata) {
    QList<Record> &list = recordList(name);
    for (Record &existing : list) {
        if (existing.type == type && existing.rdata == rdata) {
            existing.ttl = ttl;
            return;
        }
    }
    Record record;
    record.name = name.toLower();
    record.type = type;
    record.ttl = ttl;
    record.rdata = rdata;
    list.append(record);
}

void DnsServer::removeRecord(const QString &name, quint16 type) {
    auto it = m_records.find(name.toLower());
    if (it == m_records.end())
        return;
    if (type == 0 || type == TypeAny) {
        m_records.erase(it);
        return;
    }
    it.value().erase(std::remove_if(it.value().begin(), it.value().end(),
                                    [type](const Record &r) { return r.type == type; }),
                     it.value().end());
    if (it.value().isEmpty())
        m_records.erase(it);
}

QList<DnsServer::Record> DnsServer::records(const QString &name, quint16 type) const {
    QList<Record> result;
    auto it = m_records.find(name.toLower());
    if (it == m_records.end())
        return result;
    for (const Record &record : it.value()) {
        if (type == 0 || type == TypeAny || record.type == type)
            result.append(record);
    }
    return result;
}

QByteArray DnsServer::srvRdata(quint16 port, const QString &target) const {
    QByteArray rdata;
    wr16(rdata, 0); // priority
    wr16(rdata, 100); // weight
    wr16(rdata, port);
    rdata += encodeName(target);
    return rdata;
}

namespace {

struct AdSrvSpec {
    QString owner;
    quint16 port;
};

// Every SRV record a DC of this zone publishes, in the order clients ask for
// them. loadAdZone() and repairAdZoneLocators() share it so the set a new
// domain gets and the set an existing one is held to cannot drift apart.
QList<AdSrvSpec> adSrvSpecs(const QString &zoneName, const QString &site, quint16 ldapPort,
                            quint16 gcPort, quint16 kpasswdPort, quint16 kdcPort)
{
    const QString siteLower = site.toLower();
    const QString siteDomain = siteLower + QLatin1String("._sites.") + zoneName;
    const QString msdcs = QStringLiteral("dc._msdcs.") + zoneName;
    const QString siteMsdcs = siteLower + QLatin1String("._sites.") + msdcs;
    const QString gcMsdcs = QStringLiteral("gc._msdcs.") + zoneName;
    return {
        {QStringLiteral("_ldap._tcp.") + zoneName, ldapPort},
        {QStringLiteral("_ldap._tcp.") + msdcs, ldapPort},
        {QStringLiteral("_ldap._tcp.") + siteDomain, ldapPort},
        {QStringLiteral("_ldap._tcp.") + siteMsdcs, ldapPort},
        // The KDC; a dev-ports DC serves Kerberos where `kdcPort` says, so the
        // locator has to follow it rather than assume 88.
        {QStringLiteral("_kerberos._tcp.") + zoneName, kdcPort},
        {QStringLiteral("_kerberos._tcp.") + siteDomain, kdcPort},
        {QStringLiteral("_kerberos._tcp.") + msdcs, kdcPort},
        {QStringLiteral("_kerberos._udp.") + zoneName, kdcPort},
        // The password-change service; the locator points where KpasswdServer
        // listens, which is why it takes the configured port.
        {QStringLiteral("_kpasswd._tcp.") + zoneName, kpasswdPort},
        {QStringLiteral("_kpasswd._udp.") + zoneName, kpasswdPort},
        {QStringLiteral("_gc._tcp.") + zoneName, gcPort},
        {QStringLiteral("_gc._tcp.") + siteDomain, gcPort},
        {QStringLiteral("_ldap._tcp.") + gcMsdcs, gcPort},
        {QStringLiteral("_ldap._tcp.") + siteLower + QLatin1String("._sites.") + gcMsdcs, gcPort},
        {QStringLiteral("_ldap._tcp.pdc._msdcs.") + zoneName, ldapPort},
    };
}

} // namespace

void DnsServer::loadAdZone(const QString &zone, const QString &host, const QString &ip,
                           quint16 ldapPort, quint16 gcPort, const QString &site,
                           quint16 kpasswdPort, quint16 kdcPort) {
    m_records.clear();
    m_zone = zone.toLower();
    // AD style serial: yyyymmdd00. Every applied update bumps it.
    m_serial = QDate::currentDate().toString(QStringLiteral("yyyyMMdd")).toUInt() * 100;

    const QString zoneName = m_zone;
    const QString hostName = host.toLower();
    const QString siteName = site.isEmpty() ? QStringLiteral("Default-First-Site-Name") : site;

    // SOA and NS. The NS target is the nameserver host of the zone.
    QByteArray soa;
    soa += encodeName(QStringLiteral("ns1.") + zoneName);
    soa += encodeName(QStringLiteral("hostmaster.") + zoneName);
    wr32(soa, m_serial);
    wr32(soa, 3600);  // refresh
    wr32(soa, 600);   // retry
    wr32(soa, 86400); // expire
    wr32(soa, 3600);  // minimum
    addRecord(zoneName, TypeSoa, 3600, soa);
    addRecord(zoneName, TypeNs, 3600, encodeName(QStringLiteral("ns1.") + zoneName));

    // Addresses.
    QByteArray address;
    const QHostAddress parsed(ip);
    const QList<QHostAddress> candidates = parsed.isNull()
                                               ? QList<QHostAddress>{QHostAddress(QStringLiteral("127.0.0.1"))}
                                               : QList<QHostAddress>{parsed};
    for (const QHostAddress &addr : candidates) {
        if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
            const quint32 v4 = addr.toIPv4Address();
            address.append(char((v4 >> 24) & 0xff));
            address.append(char((v4 >> 16) & 0xff));
            address.append(char((v4 >> 8) & 0xff));
            address.append(char(v4 & 0xff));
        }
    }
    if (address.isEmpty())
        address = QByteArray::fromHex("7f000001");

    addRecord(hostName, TypeA, 1200, address);
    addRecord(QStringLiteral("ns1.") + zoneName, TypeA, 3600, address);
    // The zone apex resolves to the DC, which is what clients expect when they
    // point their resolver at a domain controller.
    if (hostName != zoneName)
        addRecord(zoneName, TypeA, 600, address);

    for (const AdSrvSpec &spec :
         adSrvSpecs(zoneName, siteName, ldapPort, gcPort, kpasswdPort, kdcPort))
        addRecord(spec.owner, TypeSrv, 600, srvRdata(spec.port, hostName));
}

bool DnsServer::repairAdZoneLocators(const QString &host, quint16 ldapPort, quint16 gcPort,
                                     const QString &site, quint16 kpasswdPort, quint16 kdcPort)
{
    if (m_zone.isEmpty())
        return false;
    const QString hostName = host.toLower();
    const QString siteName = site.isEmpty() ? QStringLiteral("Default-First-Site-Name") : site;
    bool changed = false;
    for (const AdSrvSpec &spec :
         adSrvSpecs(m_zone, siteName, ldapPort, gcPort, kpasswdPort, kdcPort)) {
        const QByteArray wanted = srvRdata(spec.port, hostName);
        const QList<Record> existing = records(spec.owner, TypeSrv);
        // Exactly the record a client should find: leave it alone, so a zone
        // that is already correct is not rewritten on every start.
        if (existing.size() == 1 && existing.first().rdata == wanted)
            continue;
        if (!existing.isEmpty())
            removeRecord(spec.owner, TypeSrv);
        addRecord(spec.owner, TypeSrv, 600, wanted);
        changed = true;
    }
    if (changed)
        bumpSerial();
    return changed;
}

void DnsServer::loadDefaultZone(const QString &zone) {
    loadAdZone(zone, QStringLiteral("dc1.") + zone, QStringLiteral("127.0.0.1"), 389, 3268,
               QStringLiteral("Default-First-Site-Name"));
}

bool DnsServer::inZone(const QString &name) const {
    if (m_zone.isEmpty())
        return false;
    const QString lower = name.toLower();
    return lower == m_zone || lower.endsWith(QLatin1Char('.') + m_zone);
}

void DnsServer::bumpSerial() {
    if (m_serial < 0xffffffffu)
        ++m_serial;
    auto it = m_records.find(m_zone);
    if (it == m_records.end())
        return;
    for (Record &record : it.value()) {
        if (record.type != TypeSoa)
            continue;
        QByteArray &soa = record.rdata;
        int pos = 0;
        if (!skipName(soa, pos) || !skipName(soa, pos) || pos + 4 > soa.size())
            return;
        soa[pos] = char((m_serial >> 24) & 0xff);
        soa[pos + 1] = char((m_serial >> 16) & 0xff);
        soa[pos + 2] = char((m_serial >> 8) & 0xff);
        soa[pos + 3] = char(m_serial & 0xff);
        return;
    }
}

void DnsServer::onReadyRead() {
    while (m_socket->hasPendingDatagrams()) {
        QHostAddress peer;
        quint16 port = 0;
        QByteArray buffer;
        buffer.resize(int(m_socket->pendingDatagramSize()));
        const qint64 read = m_socket->readDatagram(buffer.data(), buffer.size(), &peer, &port);
        if (read <= 0)
            continue;
        buffer.truncate(int(read));
        const QByteArray response = handlePacket(buffer, peer, port);
        if (!response.isEmpty())
            m_socket->writeDatagram(response, peer, port);
    }
}

QByteArray DnsServer::handlePacket(const QByteArray &packet, const QHostAddress &from,
                                   quint16 fromPort, QTcpSocket *tcpClient) {
    Message message;
    if (!parseMessage(packet, &message))
        return buildResponse(packet, {}, FormErr);

    const int opcode = (message.flags >> 11) & 0x0f;
    if (opcode == 5) {
        const int rcode = handleUpdate(message);
        return buildResponse(packet, {}, rcode);
    }
    if (opcode != 0)
        return buildResponse(packet, {}, NotImp);

    // Anything outside our zone that asks for recursion goes upstream; the
    // reply may arrive later, so an empty return means "wait".
    if (m_forwarding && (message.flags & 0x8000) == 0 && (message.flags & 0x0100) != 0
        && message.questions.size() == 1
        && message.questions.first().qclass == ClassIn
        && !inZone(message.questions.first().name)) {
        return forwardQuery(message, packet, from, fromPort, tcpClient);
    }

    QList<Record> answers;
    const int rcode = handleQuery(message, answers);
    if (rcode != NoError)
        answers.clear();
    return buildResponse(packet, answers, rcode);
}

QByteArray DnsServer::forwardQuery(const Message &message, const QByteArray &packet,
                                   const QHostAddress &from, quint16 fromPort,
                                   QTcpSocket *tcpClient)
{
    const Message::Question question = message.questions.first();
    bool dnssecOk = false;
    for (const Record &record : message.additional) {
        if (record.type == 41) // OPT: the DO bit is the top TTL flag
            dnssecOk = (record.ttl & 0x8000) != 0;
    }
    const QString key = cacheKeyFor(question.name, question.type, question.qclass)
                        + (dnssecOk ? QStringLiteral("|do") : QString());

    auto cached = m_cache.find(key);
    if (cached != m_cache.end()) {
        const qint64 age = cached->stored.secsTo(QDateTime::currentDateTimeUtc());
        if (age >= 0 && age < qint64(cached->lifetime))
            return cachedResponse(cached.value(), message.id);
        m_cache.erase(cached);
    }

    if (m_pending.size() >= 1024
        || m_upstreamSocket->state() != QAbstractSocket::BoundState)
        return buildResponse(packet, {}, ServFail);

    const QStringList servers = effectiveForwarders();
    QHostAddress upstream;
    quint16 upstreamPort = 53;
    for (int i = 0; i < servers.size() && upstream.isNull(); ++i) {
        const QString spec = servers.at(int(m_forwarderIndex++) % servers.size());
        parseForwarder(spec, &upstream, &upstreamPort);
    }
    if (upstream.isNull())
        return buildResponse(packet, {}, ServFail);

    quint16 upstreamId = m_nextUpstreamId++;
    int guard = 0;
    while (m_pending.contains(upstreamId) && ++guard < 65536)
        upstreamId = m_nextUpstreamId++;

    PendingQuery pending;
    pending.clientAddress = from;
    pending.clientPort = fromPort;
    pending.tcpClient = tcpClient;
    pending.upstreamAddress = upstream;
    pending.upstreamPort = upstreamPort;
    pending.query = packet;
    pending.cacheKey = key;
    pending.sent = QDateTime::currentDateTimeUtc();
    if (tcpClient)
        pending.upstreamTcp = new QTcpSocket(this);
    m_pending.insert(upstreamId, pending);

    QByteArray upstreamQuery = packet;
    if (upstreamQuery.size() < 2 || upstreamQuery.size() > 65535) {
        m_pending.remove(upstreamId);
        return buildResponse(packet, {}, FormErr);
    }
    upstreamQuery[0] = char((upstreamId >> 8) & 0xff);
    upstreamQuery[1] = char(upstreamId & 0xff);

    if (tcpClient) {
        QTcpSocket *upstreamSocket = pending.upstreamTcp;
        m_upstreamTcpIds.insert(upstreamSocket, upstreamId);
        QObject::connect(upstreamSocket, &QTcpSocket::connected, this,
                         [upstreamSocket, upstreamQuery]() {
                             QByteArray framed;
                             framed.append(char((upstreamQuery.size() >> 8) & 0xff));
                             framed.append(char(upstreamQuery.size() & 0xff));
                             framed.append(upstreamQuery);
                             upstreamSocket->write(framed);
                         });
        QObject::connect(upstreamSocket, &QTcpSocket::readyRead, this,
                         &DnsServer::onUpstreamTcpReadyRead);
        QObject::connect(upstreamSocket, &QTcpSocket::disconnected, this,
                         &DnsServer::onUpstreamTcpDisconnected);
        QObject::connect(upstreamSocket, &QAbstractSocket::errorOccurred, this,
                         [this, upstreamId](QAbstractSocket::SocketError) {
                             failPending(upstreamId);
                         });
        upstreamSocket->connectToHost(upstream, upstreamPort);
    } else if (m_upstreamSocket->writeDatagram(upstreamQuery, upstream, upstreamPort) < 0) {
        m_pending.remove(upstreamId);
        return buildResponse(packet, {}, ServFail);
    }

    QTimer::singleShot(5000, this, [this, upstreamId]() { timeoutPending(upstreamId); });
    return {};
}

void DnsServer::onUpstreamReadyRead()
{
    while (m_upstreamSocket->hasPendingDatagrams()) {
        QHostAddress peer;
        quint16 peerPort = 0;
        QByteArray buffer;
        buffer.resize(int(m_upstreamSocket->pendingDatagramSize()));
        const qint64 read =
            m_upstreamSocket->readDatagram(buffer.data(), buffer.size(), &peer, &peerPort);
        if (read <= 0)
            continue;
        buffer.truncate(int(read));
        if (buffer.size() < 12 || (quint8(buffer[2]) & 0x80) == 0)
            continue;

        const quint16 id = quint16((quint8(buffer[0]) << 8) | quint8(buffer[1]));
        auto pendingIt = m_pending.find(id);
        if (pendingIt == m_pending.end())
            continue;
        // Only the resolver this query was sent to may answer it. A
        // dual-stack socket can report an IPv4 peer as ::ffff:a.b.c.d.
        if (pendingIt->upstreamPort != peerPort
            || !pendingIt->upstreamAddress.isEqual(peer, QHostAddress::ConvertV4MappedToIPv4))
            continue;
        deliverPending(id, buffer);
    }
}

void DnsServer::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections()) {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        m_tcpClients.insert(socket);
        m_tcpClientBuffers.insert(socket, {});
        QObject::connect(socket, &QTcpSocket::readyRead, this, &DnsServer::onTcpClientReadyRead);
        QObject::connect(socket, &QTcpSocket::disconnected, this, [this, socket]() {
            m_tcpClients.remove(socket);
            m_tcpClientBuffers.remove(socket);
            socket->deleteLater();
        });
    }
}

void DnsServer::onTcpClientReadyRead()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    QByteArray &buffer = m_tcpClientBuffers[socket];
    buffer += socket->readAll();
    while (buffer.size() >= 2) {
        const int length = (int(quint8(buffer[0])) << 8) | int(quint8(buffer[1]));
        if (length == 0) {
            buffer.remove(0, 2);
            continue;
        }
        if (buffer.size() < 2 + length)
            return;
        const QByteArray query = buffer.mid(2, length);
        buffer.remove(0, 2 + length);
        const QByteArray response =
            handlePacket(query, socket->peerAddress(), socket->peerPort(), socket);
        if (!response.isEmpty())
            sendTcpResponse(socket, response);
    }
}

void DnsServer::sendTcpResponse(QTcpSocket *socket, const QByteArray &response)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || response.size() > 65535)
        return;
    QByteArray framed;
    framed.append(char((response.size() >> 8) & 0xff));
    framed.append(char(response.size() & 0xff));
    framed.append(response);
    socket->write(framed);
}

void DnsServer::onUpstreamTcpReadyRead()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    const auto idIt = m_upstreamTcpIds.constFind(socket);
    if (idIt == m_upstreamTcpIds.constEnd()) {
        socket->readAll();
        return;
    }
    const quint16 id = idIt.value();
    auto pendingIt = m_pending.find(id);
    if (pendingIt == m_pending.end()) {
        socket->readAll();
        return;
    }

    pendingIt->upstreamTcpBuffer += socket->readAll();
    QByteArray &buffer = pendingIt->upstreamTcpBuffer;
    while (buffer.size() >= 2) {
        const int length = (int(quint8(buffer[0])) << 8) | int(quint8(buffer[1]));
        if (length == 0) {
            buffer.remove(0, 2);
            continue;
        }
        if (buffer.size() < 2 + length)
            return;
        const QByteArray response = buffer.mid(2, length);
        buffer.remove(0, 2 + length);
        if (response.size() >= 12 && (quint8(response[2]) & 0x80) != 0) {
            deliverPending(id, response);
            return;
        }
    }
}

void DnsServer::onUpstreamTcpDisconnected()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    const auto idIt = m_upstreamTcpIds.constFind(socket);
    if (idIt == m_upstreamTcpIds.constEnd())
        return;
    const quint16 id = idIt.value();
    m_upstreamTcpIds.remove(socket);
    failPending(id);
    socket->deleteLater();
}

void DnsServer::deliverPending(quint16 upstreamId, const QByteArray &response)
{
    auto it = m_pending.find(upstreamId);
    if (it == m_pending.end())
        return;
    const PendingQuery pending = it.value();
    m_pending.erase(it);

    if (pending.upstreamTcp) {
        m_upstreamTcpIds.remove(pending.upstreamTcp);
        pending.upstreamTcp->disconnect(this);
        pending.upstreamTcp->abort();
        pending.upstreamTcp->deleteLater();
    }

    QByteArray packet = response;
    if (packet.size() < 12) {
        packet = buildResponse(pending.query, {}, ServFail);
    } else {
        const quint16 clientId =
            pending.query.size() >= 2
                ? quint16((quint8(pending.query[0]) << 8) | quint8(pending.query[1]))
                : quint16((quint8(packet[0]) << 8) | quint8(packet[1]));
        packet[0] = char((clientId >> 8) & 0xff);
        packet[1] = char(clientId & 0xff);
        const quint16 flags = quint16((quint8(packet[2]) << 8) | quint8(packet[3]));
        const quint16 normalized = quint16((flags & ~0x0400) | 0x0080);
        packet[2] = char((normalized >> 8) & 0xff);
        packet[3] = char(normalized & 0xff);
        cacheResponse(pending.cacheKey, packet);
    }

    if (pending.tcpClient) {
        sendTcpResponse(pending.tcpClient, packet);
    } else if (!packet.isEmpty()) {
        m_socket->writeDatagram(packet, pending.clientAddress, pending.clientPort);
    }
}

void DnsServer::failPending(quint16 upstreamId)
{
    deliverPending(upstreamId, {});
}

void DnsServer::timeoutPending(quint16 upstreamId)
{
    failPending(upstreamId);
}

void DnsServer::cacheResponse(const QString &key, const QByteArray &packet)
{
    if (key.isEmpty() || packet.size() < 12 || packet.size() > 4096)
        return;

    const quint16 flags = quint16((quint8(packet[2]) << 8) | quint8(packet[3]));
    if ((flags & 0x0200) != 0) // truncated: a TCP retry may be needed
        return;
    const int rcode = flags & 0x0f;
    if (rcode != NoError && rcode != NxDomain)
        return;

    QList<int> ttlOffsets;
    quint32 minTtl = 0xffffffffu;
    if (!collectTtls(packet, &ttlOffsets, &minTtl))
        return;
    if (ttlOffsets.isEmpty()) {
        // A negative answer without a usable SOA still should not be asked
        // again on every single lookup.
        if (rcode != NxDomain)
            return;
        minTtl = 30;
    }
    if (minTtl == 0 || minTtl == 0xffffffffu)
        return;
    if (minTtl > 86400)
        minTtl = 86400;

    if (m_cache.size() >= 4096) {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        for (auto it = m_cache.begin(); it != m_cache.end();) {
            if (it->stored.secsTo(now) >= qint64(it->lifetime))
                it = m_cache.erase(it);
            else
                ++it;
        }
        if (m_cache.size() >= 4096)
            return;
    }

    CacheEntry entry;
    entry.packet = packet;
    entry.packet[0] = 0;
    entry.packet[1] = 0;
    entry.stored = QDateTime::currentDateTimeUtc();
    entry.lifetime = minTtl;
    entry.ttlOffsets = ttlOffsets;
    m_cache.insert(key, entry);
}

QByteArray DnsServer::cachedResponse(const CacheEntry &entry, quint16 id) const
{
    QByteArray packet = entry.packet;
    if (packet.size() < 12)
        return {};

    packet[0] = char((id >> 8) & 0xff);
    packet[1] = char(id & 0xff);
    const quint16 flags = quint16((quint8(packet[2]) << 8) | quint8(packet[3]));
    const quint16 normalized = quint16((flags & ~0x0400) | 0x0080);
    packet[2] = char((normalized >> 8) & 0xff);
    packet[3] = char(normalized & 0xff);

    const qint64 age =
        qMax<qint64>(0, entry.stored.secsTo(QDateTime::currentDateTimeUtc()));
    for (int offset : entry.ttlOffsets) {
        if (offset < 0 || offset + 4 > packet.size())
            continue;
        const quint32 ttl = (quint32(quint8(packet[offset])) << 24)
                            | (quint32(quint8(packet[offset + 1])) << 16)
                            | (quint32(quint8(packet[offset + 2])) << 8)
                            | quint32(quint8(packet[offset + 3]));
        const quint32 remaining =
            ttl > quint32(age) ? ttl - quint32(age) : 0;
        packet[offset] = char((remaining >> 24) & 0xff);
        packet[offset + 1] = char((remaining >> 16) & 0xff);
        packet[offset + 2] = char((remaining >> 8) & 0xff);
        packet[offset + 3] = char(remaining & 0xff);
    }
    return packet;
}

QStringList DnsServer::effectiveForwarders() const
{
    if (!m_forwarders.isEmpty())
        return m_forwarders;

    const auto readNameservers = [](const QString &path) {
        QStringList servers;
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
            return servers;
        static const QRegularExpression whitespace(QStringLiteral("\\s+"));
        while (!file.atEnd()) {
            const QString line = QString::fromUtf8(file.readLine()).trimmed();
            if (!line.startsWith(QLatin1String("nameserver")))
                continue;
            const QStringList parts = line.split(whitespace, Qt::SkipEmptyParts);
            if (parts.size() >= 2)
                servers.append(parts.at(1));
        }
        return servers;
    };

    QStringList localAddresses;
    for (const QHostAddress &address : QNetworkInterface::allAddresses())
        localAddresses.append(address.toString());

    const auto usable = [&localAddresses](const QStringList &servers) {
        QStringList result;
        for (const QString &spec : servers) {
            QHostAddress address;
            quint16 port = 53;
            if (!parseForwarder(spec, &address, &port))
                continue;
            // Skip ourselves and a local stub: forwarding there would either
            // loop or depend on the resolver this server replaces.
            if (address.isLoopback() || localAddresses.contains(address.toString()))
                continue;
            result.append(spec);
        }
        return result;
    };

    QStringList servers = usable(readNameservers(QStringLiteral("/etc/resolv.conf")));
    if (servers.isEmpty())
        servers = usable(readNameservers(QStringLiteral("/run/systemd/resolve/resolv.conf")));
    return servers;
}

int DnsServer::handleQuery(const Message &message, QList<Record> &answers) {
    if (message.questions.size() != 1)
        return FormErr;
    const Message::Question question = message.questions.first();
    if (!m_zone.isEmpty() && !inZone(question.name))
        return Refused;

    emit queryReceived(question.name, question.type);

    QList<Record> found = records(question.name, question.type);
    if (found.isEmpty() && question.type != TypeCname) {
        // Follow a single CNAME so aliases resolve for the client.
        const QList<Record> cname = records(question.name, TypeCname);
        if (!cname.isEmpty()) {
            found = cname;
            int pos = 0;
            const QString target = decodeName(cname.first().rdata, pos);
            if (!target.isEmpty() && target.compare(question.name, Qt::CaseInsensitive) != 0)
                found += records(target, question.type);
        }
    }
    answers = found;
    return NoError;
}

int DnsServer::handleUpdate(const Message &message) {
    if (!m_updatesEnabled)
        return Refused;
    if (m_zone.isEmpty())
        return NotAuth;
    if (message.questions.size() != 1)
        return FormErr;

    const Message::Question zoneSection = message.questions.first();
    if (zoneSection.name.compare(m_zone, Qt::CaseInsensitive) != 0)
        return NotAuth;
    if (zoneSection.qclass != ClassIn)
        return NotAuth;
    if (zoneSection.type != TypeSoa)
        return FormErr;

    for (const Record &prerequisite : message.prerequisites) {
        if (!inZone(prerequisite.name))
            return NotZone;
    }
    for (const Record &update : message.updates) {
        if (!inZone(update.name))
            return NotZone;
    }

    // --- Prerequisite section (RFC 2136 §2.4) -----------------------------
    for (const Record &pre : message.prerequisites) {
        const QList<Record> atName = records(pre.name, TypeAny);
        if (pre.ttl != 0)
            return FormErr;

        if (pre.rclass == ClassAny && pre.rdata.isEmpty()) {
            if (pre.type == TypeAny) { // name is in use
                if (atName.isEmpty())
                    return NxDomain;
            } else if (records(pre.name, pre.type).isEmpty()) { // RRset exists (value independent)
                return NxRrset;
            }
        } else if (pre.rclass == ClassNone && pre.rdata.isEmpty()) {
            if (pre.type == TypeAny) { // name is not in use
                if (!atName.isEmpty())
                    return YxDomain;
            } else if (!records(pre.name, pre.type).isEmpty()) { // RRset does not exist
                return YxRrset;
            }
        } else if (pre.rclass == ClassIn && !pre.rdata.isEmpty()) {
            // RRset exists (value dependent): the set must match exactly.
            QList<QByteArray> wanted;
            for (const Record &candidate : message.prerequisites) {
                if (candidate.name.compare(pre.name, Qt::CaseInsensitive) == 0
                    && candidate.type == pre.type)
                    wanted.append(candidate.rdata);
            }
            QList<QByteArray> present;
            for (const Record &candidate : records(pre.name, pre.type))
                present.append(candidate.rdata);
            std::sort(wanted.begin(), wanted.end());
            std::sort(present.begin(), present.end());
            if (wanted != present)
                return NxRrset;
        } else {
            return FormErr;
        }
    }

    // --- Update section (RFC 2136 §2.5) -----------------------------------
    bool changed = false;
    for (const Record &update : message.updates) {
        if (update.rclass == ClassIn) {
            if (update.rdata.isEmpty())
                return FormErr;
            addRecord(update.name, update.type, update.ttl, update.rdata);
            changed = true;
        } else if (update.rclass == ClassAny) {
            if (!update.rdata.isEmpty())
                return FormErr;
            removeRecord(update.name, update.type);
            changed = true;
        } else if (update.rclass == ClassNone) {
            if (update.rdata.isEmpty())
                return FormErr;
            auto it = m_records.find(update.name.toLower());
            if (it != m_records.end()) {
                QList<Record> &list = it.value();
                const int before = list.size();
                list.erase(std::remove_if(list.begin(), list.end(),
                                          [&update](const Record &record) {
                                              return record.type == update.type
                                                     && record.rdata == update.rdata;
                                          }),
                           list.end());
                const bool removed = list.size() != before;
                if (list.isEmpty())
                    m_records.erase(it);
                changed = changed || removed;
            }
        } else {
            return FormErr;
        }
        emit updateApplied(update.name, update.type, update.rclass == ClassIn);
    }

    // An update must not delete the zone apex itself into an unservable state.
    if (records(m_zone, TypeSoa).isEmpty()) {
        QByteArray soa;
        soa += encodeName(QStringLiteral("ns1.") + m_zone);
        soa += encodeName(QStringLiteral("hostmaster.") + m_zone);
        wr32(soa, m_serial);
        wr32(soa, 3600);
        wr32(soa, 600);
        wr32(soa, 86400);
        wr32(soa, 3600);
        addRecord(m_zone, TypeSoa, 3600, soa);
        changed = true;
    }
    if (changed)
        bumpSerial();
    return NoError;
}

QByteArray DnsServer::buildResponse(const QByteArray &query, const QList<Record> &answers,
                                    int rcode) const {
    int pos = 0;
    quint16 id = 0;
    quint16 queryFlags = 0;
    quint16 qdcount = 0;
    if (!take16(query, pos, &id) || !take16(query, pos, &queryFlags)
        || !take16(query, pos, &qdcount))
        return {};

    QByteArray response;
    wr16(response, id);
    const quint16 opcode = quint16(queryFlags & 0x7800);
    const quint16 rd = quint16(queryFlags & 0x0100);
    // AA only means something on a successful authoritative answer; RA says
    // this server can recurse for names outside the zone.
    const quint16 aa = rcode == NoError ? quint16(0x0400) : quint16(0);
    const quint16 ra = m_forwarding ? quint16(0x0080) : quint16(0);
    wr16(response, quint16(0x8000 | opcode | rd | ra | aa | quint16(rcode & 0x0f)));
    wr16(response, qdcount);
    wr16(response, quint16(answers.size()));
    wr16(response, 0);
    wr16(response, 0);

    // Echo the question (or, for UPDATE, the zone) section verbatim.
    int qpos = 12;
    for (int i = 0; i < qdcount; ++i) {
        decodeName(query, qpos);
        quint16 ignored = 0;
        if (!take16(query, qpos, &ignored) || !take16(query, qpos, &ignored))
            break;
    }
    if (qpos > query.size())
        return {};
    response.append(query.mid(12, qpos - 12));

    for (const Record &record : answers) {
        response.append(encodeName(record.name));
        wr16(response, record.type);
        wr16(response, ClassIn);
        wr32(response, record.ttl);
        wr16(response, quint16(record.rdata.size()));
        response.append(record.rdata);
    }
    return response;
}

bool DnsServer::saveZone(const QString &path, QString *error) const {
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("zone")] = m_zone;
    root[QStringLiteral("serial")] = double(m_serial);
    QJsonArray recordsArray;
    for (auto it = m_records.constBegin(); it != m_records.constEnd(); ++it) {
        for (const Record &record : it.value()) {
            QJsonObject entry;
            entry[QStringLiteral("name")] = record.name;
            entry[QStringLiteral("type")] = int(record.type);
            entry[QStringLiteral("ttl")] = double(record.ttl);
            entry[QStringLiteral("rdata")] = QString::fromLatin1(record.rdata.toHex());
            recordsArray.append(entry);
        }
    }
    root[QStringLiteral("records")] = recordsArray;

    QFile file(path);
    if (!file.open(QFile::WriteOnly | QFile::Truncate)) {
        if (error)
            *error = QStringLiteral("cannot write %1: %2").arg(path, file.errorString());
        return false;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

bool DnsServer::loadZone(const QString &path, QString *error) {
    QFile file(path);
    if (!file.open(QFile::ReadOnly)) {
        if (error)
            *error = QStringLiteral("cannot read %1: %2").arg(path, file.errorString());
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error)
            *error = QStringLiteral("invalid zone file %1").arg(path);
        return false;
    }
    const QJsonObject root = document.object();
    m_records.clear();
    m_zone = root.value(QStringLiteral("zone")).toString().toLower();
    m_serial = quint32(root.value(QStringLiteral("serial")).toDouble(1));
    for (const QJsonValue &value : root.value(QStringLiteral("records")).toArray()) {
        const QJsonObject entry = value.toObject();
        const QString name = entry.value(QStringLiteral("name")).toString();
        if (name.isEmpty())
            continue;
        addRecord(name, quint16(entry.value(QStringLiteral("type")).toInt()),
                  quint32(entry.value(QStringLiteral("ttl")).toDouble(3600)),
                  QByteArray::fromHex(entry.value(QStringLiteral("rdata")).toString().toLatin1()));
    }
    return true;
}

QByteArray DnsServer::buildQuery(const QString &name, quint16 type, quint16 id) {
    QByteArray packet;
    wr16(packet, id);
    wr16(packet, 0x0100); // standard query, recursion desired
    wr16(packet, 1);
    wr16(packet, 0);
    wr16(packet, 0);
    wr16(packet, 0);
    packet.append(encodeName(name));
    wr16(packet, type);
    wr16(packet, ClassIn);
    return packet;
}
