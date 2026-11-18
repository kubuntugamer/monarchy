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
#include <QCryptographicHash>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>
#include <algorithm>

#include "Gss.h"
#include "Krb5.h"

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

// The UDP payload size this server advertises in its own OPT. 1232 is the size
// the DNS flag day agreed on: it fits in one unfragmented IPv6 datagram and
// leaves room for the EDNS header, so a client that honours it does not build a
// reply this host's path MTU would drop.
constexpr quint16 kEdnsUdpPayloadSize = 1232;
// Root owner name, type, class, TTL and RDLENGTH: an OPT which carries no
// option is 11 bytes on the wire.
constexpr int kOptBytes = 11;

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

// Whether two addresses name the same host. An IPv4 peer seen on a dual-stack
// socket arrives as an IPv4-mapped IPv6 address (::ffff:127.0.0.1), and
// comparing that against a configured IPv4 master as text is false: the
// secondary then refuses the announcement of the master it was told to follow.
bool sameHostAddress(const QHostAddress &left, const QHostAddress &right)
{
    if (left == right)
        return true;
    const quint32 leftV4 = left.toIPv4Address();
    const quint32 rightV4 = right.toIPv4Address();
    return leftV4 != 0 && leftV4 == rightV4;
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

// Finds the request's OPT pseudo-record (RFC 6891 §6.1.1) and returns the
// sender's UDP payload size and TTL word (extended rcode, version, flags). An
// OPT in a query is the only place a client states what it can receive and
// which EDNS version it speaks, so the reply is built from it.
bool findOpt(const QByteArray &packet, quint16 *udpSize, quint32 *ttl)
{
    int pos = 0;
    quint16 ignored = 0, qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    if (!take16(packet, pos, &ignored) || !take16(packet, pos, &ignored)
        || !take16(packet, pos, &qdcount) || !take16(packet, pos, &ancount)
        || !take16(packet, pos, &nscount) || !take16(packet, pos, &arcount))
        return false;
    for (int i = 0; i < qdcount; ++i) {
        decodeName(packet, pos);
        quint16 skip = 0;
        if (!take16(packet, pos, &skip) || !take16(packet, pos, &skip))
            return false;
    }
    const int total = int(ancount) + int(nscount) + int(arcount);
    for (int i = 0; i < total; ++i) {
        decodeName(packet, pos);
        quint16 type = 0, rclass = 0, rdlength = 0;
        quint32 word = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass)
            || !take32(packet, pos, &word) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        pos += rdlength;
        if (type != 41)
            continue;
        *udpSize = rclass;
        *ttl = word;
        return true;
    }
    return false;
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

    // Repeats announcements that have not been answered. The tick is fixed and
    // each entry keeps its own due time, so the doubling schedule reads off the
    // same clock instead of one timer per peer.
    m_notifyTimer = new QTimer(this);
    m_notifyTimer->setInterval(100);
    connect(m_notifyTimer, &QTimer::timeout, this, &DnsServer::pumpNotifies);
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
    m_pendingNotifies.clear();
    if (m_notifyTimer)
        m_notifyTimer->stop();
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
    // The caller is (re)applying configuration, so a still-broken state deserves
    // a fresh report: `systemctl reload` on a DC that still has no upstream
    // should say so again rather than go quiet because start-up already did.
    m_reportedNoForwarder = false;
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
    auto collect = [&result, type](const QList<Record> &list) {
        for (const Record &record : list) {
            if (type == 0 || type == TypeAny || record.type == type)
                result.append(record);
        }
    };
    const auto it = m_records.constFind(name.toLower());
    if (it != m_records.constEnd())
        collect(it.value());
    // A zone this server copies is served from the copy: while the master is
    // unreachable the secondary is the only thing answering, which is what it
    // is for. Records of this DC's own zones come first and shadow a copy.
    if (result.isEmpty()) {
        if (const QList<Record> *copy = secondaryRecords(name))
            collect(*copy);
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

// The A record rdata for an address: four bytes, or empty when the configured
// value is not an IPv4 address. loadAdZone() and repairAdZoneAddresses() encode
// it here so a repaired record compares equal to a freshly built one.
QByteArray ipv4Rdata(const QString &ip)
{
    const QHostAddress parsed(ip);
    if (parsed.isNull() || parsed.protocol() != QAbstractSocket::IPv4Protocol)
        return {};
    const quint32 v4 = parsed.toIPv4Address();
    QByteArray rdata;
    rdata.append(char((v4 >> 24) & 0xff));
    rdata.append(char((v4 >> 16) & 0xff));
    rdata.append(char((v4 >> 8) & 0xff));
    rdata.append(char(v4 & 0xff));
    return rdata;
}

} // namespace

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

// HMAC-SHA256 (RFC 2104). TSIG's hmac-sha256 is the one algorithm this server
// speaks, and Qt gives us the hash but not the MAC.
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

// TSIG variables (RFC 8945 §4.3.3) in the order the MAC covers them. Names are
// canonical — lower case, uncompressed — so a client that sent a mixed-case key
// name still produces the same digest the server computes.
QByteArray tsigVariables(const QString &keyName, const QString &algorithm, quint64 timeSigned,
                         quint16 fudge, quint16 error, const QByteArray &other)
{
    QByteArray out;
    out += encodeName(keyName.toLower());
    wr16(out, 255); // class ANY
    wr32(out, 0);   // TTL
    out += encodeName(algorithm.toLower());
    for (int shift = 40; shift >= 0; shift -= 8)
        out.append(char((timeSigned >> shift) & 0xff));
    wr16(out, fudge);
    wr16(out, error);
    wr16(out, quint16(other.size()));
    out += other;
    return out;
}

struct TsigParts {
    int offset = -1; // where the TSIG RR starts, so the MAC can cover the rest
    QString name;
    QString algorithm;
    quint64 timeSigned = 0;
    quint16 fudge = 0;
    QByteArray mac;
    quint16 originalId = 0;
    quint16 error = 0;
    QByteArray other;
};

// Finds the TSIG RR in the additional section, which is where RFC 8945 puts it.
// A TSIG name with its trailing root dot removed and lower-cased: a configured
// "hmac-sha256." and a wire name that decodes to "hmac-sha256" are the same key.
QString tsigKeyName(const QString &name)
{
    QString out = name.toLower();
    if (out.endsWith(QLatin1Char('.')))
        out.chop(1);
    return out;
}

bool findTsig(const QByteArray &packet, TsigParts *out)
{
    int pos = 4;
    quint16 qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    if (!take16(packet, pos, &qdcount) || !take16(packet, pos, &ancount)
        || !take16(packet, pos, &nscount) || !take16(packet, pos, &arcount))
        return false;
    pos = 12;
    for (int i = 0; i < qdcount; ++i) {
        decodeName(packet, pos);
        quint16 skip = 0;
        if (!take16(packet, pos, &skip) || !take16(packet, pos, &skip))
            return false;
    }
    for (int i = 0; i < int(ancount) + int(nscount); ++i) {
        decodeName(packet, pos);
        quint16 type = 0, rclass = 0, rdlength = 0;
        quint32 ttl = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass)
            || !take32(packet, pos, &ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        pos += rdlength;
    }
    for (int i = 0; i < arcount; ++i) {
        const int start = pos;
        const QString owner = decodeName(packet, pos);
        quint16 type = 0, rclass = 0, rdlength = 0;
        quint32 ttl = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass)
            || !take32(packet, pos, &ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        if (type != 250) {
            pos += rdlength;
            continue;
        }
        int cursor = pos;
        out->offset = start;
        out->name = owner;
        out->algorithm = decodeName(packet, cursor);
        if (cursor + 10 > packet.size())
            return false;
        quint64 signed0 = 0;
        for (int k = 0; k < 6; ++k)
            signed0 = (signed0 << 8) | quint8(packet[cursor + k]);
        cursor += 6;
        out->timeSigned = signed0;
        out->fudge = quint16((quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]));
        cursor += 2;
        const int macLength = (quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]);
        cursor += 2;
        if (macLength < 0 || cursor + macLength + 6 > packet.size())
            return false;
        out->mac = packet.mid(cursor, macLength);
        cursor += macLength;
        out->originalId = quint16((quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]));
        cursor += 2;
        out->error = quint16((quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]));
        cursor += 2;
        const int otherLength = (quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]);
        cursor += 2;
        if (otherLength < 0 || cursor + otherLength > packet.size())
            return false;
        out->other = packet.mid(cursor, otherLength);
        return true;
    }
    return false;
}

// A TKEY RR (RFC 2930), which travels in the additional section of a query and
// carries one GSS-API token. Its RDATA is a sequence of fixed fields around two
// variable ones, so the offsets are kept rather than the whole record: the
// answer echoes the mode and replaces the token.
struct TkeyParts {
    QString name;
    QString algorithm;
    quint32 inception = 0;
    quint32 expiration = 0;
    quint16 mode = 0;
    quint16 error = 0;
    QByteArray keyData;
    QByteArray other;
};

bool findTkey(const QByteArray &packet, TkeyParts *out)
{
    int pos = 4;
    quint16 qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    if (!take16(packet, pos, &qdcount) || !take16(packet, pos, &ancount)
        || !take16(packet, pos, &nscount) || !take16(packet, pos, &arcount))
        return false;
    pos = 12;
    for (int i = 0; i < qdcount; ++i) {
        decodeName(packet, pos);
        quint16 skip = 0;
        if (!take16(packet, pos, &skip) || !take16(packet, pos, &skip))
            return false;
    }
    for (int i = 0; i < int(ancount) + int(nscount); ++i) {
        decodeName(packet, pos);
        quint16 type = 0, rclass = 0, rdlength = 0;
        quint32 ttl = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass)
            || !take32(packet, pos, &ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        pos += rdlength;
    }
    for (int i = 0; i < arcount; ++i) {
        const QString owner = decodeName(packet, pos);
        quint16 type = 0, rclass = 0, rdlength = 0;
        quint32 ttl = 0;
        if (!take16(packet, pos, &type) || !take16(packet, pos, &rclass)
            || !take32(packet, pos, &ttl) || !take16(packet, pos, &rdlength))
            return false;
        if (pos < 0 || pos + rdlength > packet.size())
            return false;
        if (type != 249) {
            pos += rdlength;
            continue;
        }
        int cursor = pos;
        out->name = owner;
        out->algorithm = decodeName(packet, cursor);
        if (cursor + 14 > packet.size())
            return false;
        for (int k = 0; k < 4; ++k)
            out->inception = (out->inception << 8) | quint8(packet[cursor + k]);
        cursor += 4;
        for (int k = 0; k < 4; ++k)
            out->expiration = (out->expiration << 8) | quint8(packet[cursor + k]);
        cursor += 4;
        out->mode = quint16((quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]));
        cursor += 2;
        out->error = quint16((quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]));
        cursor += 2;
        const int keyLength = (quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]);
        cursor += 2;
        if (keyLength < 0 || cursor + keyLength + 2 > packet.size())
            return false;
        out->keyData = packet.mid(cursor, keyLength);
        cursor += keyLength;
        const int otherLength = (quint8(packet[cursor]) << 8) | quint8(packet[cursor + 1]);
        cursor += 2;
        if (otherLength < 0 || cursor + otherLength > packet.size())
            return false;
        out->other = packet.mid(cursor, otherLength);
        return true;
    }
    return false;
}

// A dotted quad as four canonical decimal octets. "01" and "1x" are rejected:
// they are not addresses an AD client could have been configured with, and
// reading them as 1 would derive a reverse zone for a different host.
bool ipv4Octets(const QString &ip, QStringList *octets)
{
    const QStringList parts = ip.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return false;
    for (const QString &part : parts) {
        bool ok = false;
        const int value = part.toInt(&ok);
        if (!ok || value < 0 || value > 255 || QString::number(value) != part)
            return false;
        octets->append(part);
    }
    return true;
}

// AD provisions a /24 reverse zone for a DC's address; "" is not an address.
QString reverseZoneFor(const QString &ip)
{
    QStringList octets;
    if (!ipv4Octets(ip, &octets))
        return {};
    return octets[2] + QLatin1Char('.') + octets[1] + QLatin1Char('.') + octets[0]
           + QStringLiteral(".in-addr.arpa");
}

// The owner name `dig -x` asks for.
QString ptrOwnerFor(const QString &ip)
{
    QStringList octets;
    if (!ipv4Octets(ip, &octets))
        return {};
    return octets[3] + QLatin1Char('.') + octets[2] + QLatin1Char('.') + octets[1]
           + QLatin1Char('.') + octets[0] + QStringLiteral(".in-addr.arpa");
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
    QByteArray address = ipv4Rdata(ip);
    if (address.isEmpty())
        address = QByteArray::fromHex("7f000001");

    addRecord(hostName, TypeA, 1200, address);
    addRecord(QStringLiteral("ns1.") + zoneName, TypeA, 3600, address);
    // The zone apex resolves to the DC, which is what clients expect when they
    // point their resolver at a domain controller.
    if (hostName != zoneName)
        addRecord(zoneName, TypeA, 600, address);

    for (const AdSrvSpec &spec :
         adSrvSpecs(zoneName, siteName, ldapPort, gcPort, kpasswdPort, kdcPort)) {
        // A port of 0 means the service did not bind. No locator is published
        // for it, so a client is never sent to a port nothing answers.
        if (spec.port == 0)
            continue;
        addRecord(spec.owner, TypeSrv, 600, srvRdata(spec.port, hostName));
    }
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
        const QList<Record> existing = records(spec.owner, TypeSrv);
        // A port of 0 is a service this DC is not serving. Its locator is
        // withdrawn rather than repointed: advertising a dead port is the
        // defect being repaired, and a client that finds nothing falls over to
        // another DC instead of timing out against this one.
        if (spec.port == 0) {
            if (!existing.isEmpty()) {
                removeRecord(spec.owner, TypeSrv);
                changed = true;
            }
            continue;
        }
        const QByteArray wanted = srvRdata(spec.port, hostName);
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

bool DnsServer::repairAdZoneAddresses(const QString &host, const QString &ip)
{
    if (m_zone.isEmpty())
        return false;
    const QByteArray wanted = ipv4Rdata(ip);
    if (wanted.isEmpty())
        return false;

    // The same three owners loadAdZone() gives an A record, at the same TTLs.
    struct AddressSpec {
        QString owner;
        quint32 ttl;
    };
    const QString hostName = host.toLower();
    QList<AddressSpec> specs{{
        hostName,
        1200,
    }, {
        QStringLiteral("ns1.") + m_zone,
        3600,
    }};
    if (hostName != m_zone)
        specs.append({m_zone, 600});

    bool changed = false;
    for (const AddressSpec &spec : specs) {
        const QList<Record> existing = records(spec.owner, TypeA);
        // Already the configured address and nothing else: leave it, so a start
        // does not rewrite a correct zone.
        if (existing.size() == 1 && existing.first().rdata == wanted)
            continue;
        if (!existing.isEmpty())
            removeRecord(spec.owner, TypeA);
        addRecord(spec.owner, TypeA, spec.ttl, wanted);
        changed = true;
    }
    if (changed)
        bumpSerial();
    return changed;
}

void DnsServer::setUpdateTsig(const QString &name, const QString &algorithm,
                              const QByteArray &base64Secret)
{
    m_tsigName = name.trimmed();
    m_tsigAlgorithm = algorithm.trimmed();
    if (m_tsigAlgorithm.isEmpty())
        m_tsigAlgorithm = QStringLiteral("hmac-sha256");
    if (!m_tsigAlgorithm.endsWith(QLatin1Char('.')))
        m_tsigAlgorithm += QLatin1Char('.');
    m_tsigSecret = QByteArray::fromBase64(base64Secret.trimmed());
    // A key without a secret, or a secret without a name, is a configuration
    // mistake: leaving it half-set would silently require nothing.
    if (m_tsigName.isEmpty() || m_tsigSecret.isEmpty()) {
        m_tsigName.clear();
        m_tsigAlgorithm.clear();
        m_tsigSecret.clear();
    }
}

QString DnsServer::updateTsigName() const
{
    return m_tsigName;
}

void DnsServer::setTransferZones(const QStringList &zones)
{
    // A zone name here is compared against the zone a question belongs to, so it
    // is stored the way `zoneFor` answers: lower case, no trailing dot.
    m_transferZones.clear();
    for (const QString &entry : zones) {
        QString zone = entry.trimmed().toLower();
        while (zone.endsWith(QLatin1Char('.')))
            zone.chop(1);
        if (!zone.isEmpty())
            m_transferZones.append(zone);
    }
}

QStringList DnsServer::transferZones() const
{
    return m_transferZones;
}

void DnsServer::setNotifyTargets(const QStringList &targets)
{
    m_notifyTargets.clear();
    for (const QString &entry : targets) {
        const QString trimmed = entry.trimmed();
        if (!trimmed.isEmpty())
            m_notifyTargets.append(trimmed);
    }
}

QStringList DnsServer::notifyTargets() const
{
    return m_notifyTargets;
}

QByteArray DnsServer::buildNotify(quint16 id, const QString &zone) const
{
    const QList<Record> soa = records(zone, TypeSoa);
    if (zone.isEmpty() || soa.isEmpty())
        return {};

    QByteArray packet;
    wr16(packet, id);
    // QR clear, opcode NOTIFY, AA set: a primary announcing the version it now
    // holds. Both sections are required by RFC 1996 §4 — the question names the
    // zone, the answer carries its SOA, whose serial is the announcement.
    wr16(packet, quint16((4 << 11) | 0x0400));
    wr16(packet, 1);
    wr16(packet, 1);
    wr16(packet, 0);
    wr16(packet, 0);
    packet += encodeName(zone);
    wr16(packet, TypeSoa);
    wr16(packet, ClassIn);
    packet += encodeName(zone);
    wr16(packet, TypeSoa);
    wr16(packet, ClassIn);
    wr32(packet, soa.first().ttl);
    wr16(packet, quint16(soa.first().rdata.size()));
    packet += soa.first().rdata;

    if (m_tsigName.isEmpty())
        return packet;

    // A NOTIFY this server sends is a request, so its MAC covers this message
    // and the TSIG variables and nothing before it: a one-message exchange has no
    // earlier MAC to chain from. Signing it lets a secondary that already trusts
    // this key tell our announcement from anyone else's — which matters, because
    // the announcement is what makes it pull a zone.
    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    const quint16 fudge = 300;
    const QByteArray mac =
        hmacSha256(m_tsigSecret,
                   packet + tsigVariables(m_tsigName, m_tsigAlgorithm, now, fudge, 0, {}));
    const quint16 arcount = quint16((quint8(packet[10]) << 8) | quint8(packet[11]));
    const quint16 next = quint16(arcount + 1);
    packet[10] = char((next >> 8) & 0xff);
    packet[11] = char(next & 0xff);

    QByteArray rdata;
    rdata += encodeName(m_tsigAlgorithm);
    for (int shift = 40; shift >= 0; shift -= 8)
        rdata.append(char((now >> shift) & 0xff));
    wr16(rdata, fudge);
    wr16(rdata, quint16(mac.size()));
    rdata += mac;
    wr16(rdata, id);
    wr16(rdata, 0);
    wr16(rdata, 0);
    packet += encodeName(m_tsigName);
    wr16(packet, TypeTsig);
    wr16(packet, 255);
    wr32(packet, 0);
    wr16(packet, quint16(rdata.size()));
    packet += rdata;
    return packet;
}

void DnsServer::notifySecondaries(const QString &zone)
{
    if (m_notifyTargets.isEmpty() || !isListening())
        return;
    if (zone.isEmpty() || records(zone, TypeSoa).isEmpty())
        return;
    for (const QString &spec : m_notifyTargets) {
        QHostAddress address;
        quint16 port = 53;
        if (!parseForwarder(spec, &address, &port))
            continue;

        // A newer change replaces whatever was still being announced to that
        // peer: the newer message already names the version it should pull, so
        // repeating the older one would walk it backwards.
        for (int i = m_pendingNotifies.size() - 1; i >= 0; --i) {
            if (m_pendingNotifies.at(i).address == address
                && m_pendingNotifies.at(i).port == port
                && m_pendingNotifies.at(i).zone == zone)
                m_pendingNotifies.removeAt(i);
        }

        PendingNotify entry;
        entry.address = address;
        entry.port = port;
        entry.zone = zone;
        entry.id = m_nextNotifyId++;
        entry.waitMs = m_notifyInitialIntervalMs;
        m_pendingNotifies.append(entry);
        sendNotify(m_pendingNotifies.last());
    }
    if (!m_pendingNotifies.isEmpty() && m_notifyTimer && !m_notifyTimer->isActive())
        m_notifyTimer->start();
}

void DnsServer::sendNotify(PendingNotify &entry)
{
    const QByteArray notify = buildNotify(entry.id, entry.zone);
    if (notify.isEmpty())
        return;
    m_socket->writeDatagram(notify, entry.address, entry.port);
    ++entry.attempts;
    entry.sinceSend.start();
}

void DnsServer::pumpNotifies()
{
    for (int i = m_pendingNotifies.size() - 1; i >= 0; --i) {
        PendingNotify &entry = m_pendingNotifies[i];
        if (entry.attempts >= m_notifyMaxAttempts) {
            // Given up. The secondary still refreshes on its own timer, so an
            // announcement that never got through costs a bounded number of
            // datagrams rather than a retry that never ends.
            m_pendingNotifies.removeAt(i);
            continue;
        }
        const bool due = !entry.sinceSend.isValid()
                         || entry.sinceSend.elapsed() >= qint64(entry.waitMs);
        if (!due)
            continue;
        sendNotify(entry);
        // Doubling rather than a fixed gap: a secondary that is down is not
        // worth a datagram every two seconds, and one that is merely slow is
        // still reached. The gap is applied after the send it follows, so the
        // first repeat lands at `initialIntervalMs` and not twice that.
        entry.waitMs = qMin(entry.waitMs * 2, 16000);
    }
    if (m_pendingNotifies.isEmpty() && m_notifyTimer)
        m_notifyTimer->stop();
}

void DnsServer::setNotifyRetry(int initialIntervalMs, int maxAttempts)
{
    m_notifyInitialIntervalMs = qMax(10, initialIntervalMs);
    m_notifyMaxAttempts = qMax(1, maxAttempts);
}

int DnsServer::verifyTsig(const QByteArray &packet, QByteArray *requestMac,
                          quint16 *error, QByteArray *other, bool *signRefusal,
                          QString *keyName, quint64 *clientTimeSigned, quint16 *clientFudge)
{
    *error = 0;
    *signRefusal = false;
    other->clear();
    if (keyName)
        keyName->clear();
    TsigParts tsig;
    if (!findTsig(packet, &tsig)) {
        // No TSIG at all: this update carries no proof of anything, and there is
        // no key context to sign the refusal with.
        return NotAuth;
    }
    *signRefusal = true;

    // The MAC covers the message without the TSIG RR, with ARCOUNT decremented
    // to what the sender's count would have been had it not appended one. Both
    // algorithms sign this block; only what turns it into a MAC differs.
    QByteArray unsignedMessage = packet.left(tsig.offset);
    if (tsig.offset < 12 || unsignedMessage.size() < 12)
        return FormErr;
    const quint16 arcount =
        quint16((quint8(unsignedMessage[10]) << 8) | quint8(unsignedMessage[11]));
    unsignedMessage[10] = char((quint16(arcount - 1) >> 8) & 0xff);
    unsignedMessage[11] = char((arcount - 1) & 0xff);
    const QByteArray signedBlock =
        unsignedMessage
        + tsigVariables(tsig.name, tsig.algorithm, tsig.timeSigned, tsig.fudge, tsig.error,
                        tsig.other);

    if (keyName)
        *keyName = tsig.name;
    if (clientTimeSigned)
        *clientTimeSigned = tsig.timeSigned;
    if (clientFudge)
        *clientFudge = tsig.fudge;
    if (tsigKeyName(tsig.algorithm) == QStringLiteral("gss-tsig")) {
        // RFC 3645: the TSIG MAC field is a GSS MIC over the message and the
        // variables, under the context key a TKEY negotiation established. The
        // TSIG's owner name identifies the context, so a message cannot name
        // one context and be signed by another.
        pruneGssContexts();
        GssContext *context = gssContextFor(tsig.name);
        if (!context) {
            *error = 17; // BADKEY: no context was negotiated under this name
            return NotAuth;
        }
        quint64 sequence = 0;
        if (!Gss::checkCfxMic(tsig.mac, signedBlock, context->etype, context->key, false,
                              &sequence)
            || sequence != context->recvSeq) {
            // A MIC that verifies but carries the wrong sequence number is a
            // replay, or a message from another position in the stream.
            *error = 16; // BADSIG
            return NotAuth;
        }
        ++context->recvSeq;
        *requestMac = tsig.mac;
    } else {
        if (tsigKeyName(tsig.name) != tsigKeyName(m_tsigName)
            || tsigKeyName(tsig.algorithm) != tsigKeyName(m_tsigAlgorithm)) {
            *error = 17; // BADKEY
            return NotAuth;
        }
        if (hmacSha256(m_tsigSecret, signedBlock) != tsig.mac) {
            *error = 16; // BADSIG
            return NotAuth;
        }
        *requestMac = tsig.mac;
    }

    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    const quint64 skew = now > tsig.timeSigned ? now - tsig.timeSigned
                                               : tsig.timeSigned - now;
    if (skew > quint64(tsig.fudge)) {
        // The key is right and the MAC verified; only the clocks disagree, so
        // this is answered signed with the server's own time for the client to
        // read, which is what BADTIME is for.
        *error = 18; // BADTIME
        for (int shift = 40; shift >= 0; shift -= 8)
            other->append(char((now >> shift) & 0xff));
        return NotAuth;
    }
    return 0;
}

QByteArray DnsServer::signTsigResponse(const QByteArray &response, const QByteArray &requestMac,
                                       quint16 error, const QByteArray &other,
                                       quint64 timeSigned, quint16 fudge,
                                       bool continuedMessage, QByteArray *macOut,
                                       const QString &keyName, bool gssTsig,
                                       bool signWithoutRequestMac,
                                       const QString &errorAlgorithm)
{
    if (macOut)
        macOut->clear();
    if (response.size() < 12)
        return response;

    const QString signName = keyName.isEmpty() ? m_tsigName : keyName;
    QString signAlgorithm = m_tsigAlgorithm;
    GssContext *gss = nullptr;
    // An error reply to an unverifiable key or MAC (BADKEY, BADSIG) is unsigned:
    // the TSIG RR is still present, with a zero-length MAC, under the name and
    // algorithm the request used, so a client can attribute the error even when
    // this server holds no such key (RFC 8945 §5.3.2). `errorAlgorithm` selects
    // that shape and is only meaningful when there is no request MAC to chain
    // from; a validated request always produces a real signature.
    const bool errorOnly = !errorAlgorithm.isEmpty() && requestMac.isEmpty();
    if (errorOnly) {
        if (signName.isEmpty())
            return response;
        signAlgorithm = errorAlgorithm;
    } else if (gssTsig) {
        pruneGssContexts();
        gss = gssContextFor(signName);
        if (!gss)
            return response; // no context, so nothing this reply could prove
        signAlgorithm = QStringLiteral("gss-tsig");
    } else if (signName.isEmpty()) {
        return response;
    }

    const quint64 now = timeSigned != 0 ? timeSigned
                                        : quint64(QDateTime::currentSecsSinceEpoch());
    // A BADTIME reply must echo the client's fudge even when it is small; only a
    // reply that was given no timers at all falls back to the defaults.
    if (fudge == 0 && timeSigned == 0)
        fudge = 300;

    // A response MAC also covers the request's MAC, so a reply cannot be
    // replayed against a different request. An empty request MAC means the MAC
    // could not be checked at all (BADKEY, BADSIG): the reply still identifies
    // the key and the error, and carries a zero-length MAC, which is what
    // RFC 8945 §5.3 asks for rather than a digest that proves nothing. The one
    // exception is the reply to an unsigned TKEY query, which RFC 3645 §3.1.3
    // requires to be signed over the key the exchange just established.
    QByteArray mac;
    if (!requestMac.isEmpty() || signWithoutRequestMac) {
        QByteArray digest;
        if (!requestMac.isEmpty()) {
            QByteArray prefix;
            wr16(prefix, quint16(requestMac.size()));
            prefix += requestMac;
            digest += prefix;
        }
        digest += response;
        // A later message of a transfer covers the prior MAC, the message and
        // only this message's timers: "only the timers are included in the
        // second and subsequent messages, not all the TSIG variables"
        // (RFC 8945 §5.3.1).
        if (continuedMessage) {
            for (int shift = 40; shift >= 0; shift -= 8)
                digest.append(char((now >> shift) & 0xff));
            wr16(digest, fudge);
        } else {
            digest += tsigVariables(signName, signAlgorithm, now, fudge, error, other);
        }
        mac = gss ? Gss::cfxMic(digest, gss->sendSeq++, gss->etype, gss->key, true)
                  : hmacSha256(m_tsigSecret, digest);
    }

    if (macOut)
        *macOut = mac;

    QByteArray signedResponse = response;
    const quint16 arcount =
        quint16((quint8(signedResponse[10]) << 8) | quint8(signedResponse[11]));
    const quint16 next = quint16(arcount + 1);
    signedResponse[10] = char((next >> 8) & 0xff);
    signedResponse[11] = char(next & 0xff);

    QByteArray rdata;
    rdata += encodeName(signAlgorithm);
    for (int shift = 40; shift >= 0; shift -= 8)
        rdata.append(char((now >> shift) & 0xff));
    wr16(rdata, fudge);
    wr16(rdata, quint16(mac.size()));
    rdata += mac;
    wr16(rdata, quint16((quint8(response[0]) << 8) | quint8(response[1])));
    wr16(rdata, error);
    wr16(rdata, quint16(other.size()));
    rdata += other;

    signedResponse += encodeName(signName);
    wr16(signedResponse, 250); // TSIG
    wr16(signedResponse, 255); // class ANY
    wr32(signedResponse, 0);   // TTL 0
    wr16(signedResponse, quint16(rdata.size()));
    signedResponse += rdata;
    return signedResponse;
}

bool DnsServer::repairReverseZone(const QString &host, const QString &ip)
{
    if (m_zone.isEmpty())
        return false;
    const QString wanted = reverseZoneFor(ip);
    if (wanted.isEmpty())
        return false;
    const QString owner = ptrOwnerFor(ip);
    if (owner.isEmpty())
        return false;

    bool changed = false;
    // The reverse zone is derived from dcIp, so an address that moved must take
    // the old zone with it: a leftover PTR in the previous /24 points clients at
    // a name whose address is no longer this DC's.
    if (!m_reverseZone.isEmpty() && m_reverseZone != wanted) {
        for (auto it = m_records.begin(); it != m_records.end();) {
            if (it.key() == m_reverseZone
                || it.key().endsWith(QLatin1Char('.') + m_reverseZone))
                it = m_records.erase(it);
            else
                ++it;
        }
        changed = true;
    }
    m_reverseZone = wanted;

    const QString hostName = host.toLower();
    const QByteArray nameServer = encodeName(hostName.isEmpty() ? QStringLiteral("ns1.") + m_zone
                                                               : hostName);
    // The zone gets its own SOA and NS: a resolver asking for a name this DC does
    // not hold in the /24 is answered authoritatively with this, and caches the
    // absence against it.
    if (records(m_reverseZone, TypeSoa).isEmpty()) {
        QByteArray soa = nameServer;
        soa += encodeName(QStringLiteral("hostmaster.") + m_zone);
        wr32(soa, m_serial);
        wr32(soa, 3600);  // refresh
        wr32(soa, 600);   // retry
        wr32(soa, 86400); // expire
        wr32(soa, 3600);  // minimum
        addRecord(m_reverseZone, TypeSoa, 3600, soa);
        changed = true;
    }
    if (records(m_reverseZone, TypeNs).isEmpty()) {
        addRecord(m_reverseZone, TypeNs, 3600, nameServer);
        changed = true;
    }

    const QByteArray ptr = encodeName(hostName);
    const QList<Record> existing = records(owner, TypePtr);
    if (existing.size() != 1 || existing.first().rdata != ptr) {
        if (!existing.isEmpty())
            removeRecord(owner, TypePtr);
        addRecord(owner, TypePtr, 1200, ptr);
        changed = true;
    }
    if (changed)
        bumpReverseSerial();
    return changed;
}

QString DnsServer::reverseZone() const
{
    return m_reverseZone;
}

void DnsServer::loadDefaultZone(const QString &zone) {
    loadAdZone(zone, QStringLiteral("dc1.") + zone, QStringLiteral("127.0.0.1"), 389, 3268,
               QStringLiteral("Default-First-Site-Name"));
}

QString DnsServer::zoneFor(const QString &name) const {
    const QString lower = name.toLower();
    if (!m_zone.isEmpty()) {
        if (!m_reverseZone.isEmpty()
            && (lower == m_reverseZone || lower.endsWith(QLatin1Char('.') + m_reverseZone)))
            return m_reverseZone;
        if (lower == m_zone || lower.endsWith(QLatin1Char('.') + m_zone))
            return m_zone;
    }
    // A zone served from a copy is a zone this server answers for, so a name in
    // it is in-zone: the authority section of a negative answer and the AA bit
    // both hang off that.
    for (const QString &copied : m_masterZones) {
        if (lower == copied || lower.endsWith(QLatin1Char('.') + copied))
            return copied;
    }
    return {};
}

bool DnsServer::inZone(const QString &name) const {
    return !zoneFor(name).isEmpty();
}

void DnsServer::setGssAcceptor(GssAcceptor acceptor)
{
    m_gssAcceptor = acceptor;
}

bool DnsServer::gssTsigEnabled() const
{
    return bool(m_gssAcceptor);
}

void DnsServer::addGssContext(const QString &name, const GssContext &context)
{
    m_gssContexts.insert(tsigKeyName(name), context);
}

bool DnsServer::hasGssContext(const QString &name) const
{
    return m_gssContexts.contains(tsigKeyName(name));
}

DnsServer::GssContext *DnsServer::gssContextFor(const QString &name)
{
    auto it = m_gssContexts.find(tsigKeyName(name));
    if (it == m_gssContexts.end())
        return nullptr;
    // A context outlives the message that established it only until the
    // Kerberos ticket behind it does; an expired one is dropped rather than
    // answering a MIC nobody can verify.
    if (it->expires != 0 && it->expires <= qint64(QDateTime::currentSecsSinceEpoch())) {
        m_gssContexts.erase(it);
        return nullptr;
    }
    return &it.value();
}

void DnsServer::pruneGssContexts()
{
    const qint64 now = qint64(QDateTime::currentSecsSinceEpoch());
    for (auto it = m_gssContexts.begin(); it != m_gssContexts.end();) {
        if (it->expires != 0 && it->expires <= now)
            it = m_gssContexts.erase(it);
        else
            ++it;
    }
}

QByteArray DnsServer::handleTkey(const QByteArray &packet, const Message &message)
{
    if (message.questions.size() != 1)
        return buildResponse(packet, {}, FormErr);
    const Message::Question question = message.questions.first();
    TkeyParts tkey;
    if (!findTkey(packet, &tkey) || tsigKeyName(tkey.name) != tsigKeyName(question.name))
        return buildResponse(packet, {}, FormErr);
    // Without a GSS acceptor this server cannot negotiate a key at all, and
    // RFC 2930 §3 allows saying so with an ordinary refusal rather than
    // pretending the exchange was understood.
    if (!m_gssAcceptor)
        return buildResponse(packet, {}, Refused);

    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    // A TKEY failure lives in the RR's error field while the header stays
    // NOERROR (RFC 2930 §2.6), and the answer echoes the mode and algorithm the
    // client asked for so it can match the failure to its own request.
    const auto answerWith = [&](const QByteArray &keyData, quint16 tkeyError,
                                quint64 expiration, const QString &algorithm) {
        Record record;
        record.name = tkey.name;
        record.type = TypeTkey;
        record.rclass = ClassAny; // RFC 2930 §2.1: TKEY is class ANY
        record.ttl = 0;
        QByteArray rdata;
        rdata += encodeName(algorithm);
        for (int shift = 24; shift >= 0; shift -= 8)
            rdata.append(char((now >> shift) & 0xff));
        for (int shift = 24; shift >= 0; shift -= 8)
            rdata.append(char((expiration >> shift) & 0xff));
        wr16(rdata, tkey.mode);
        wr16(rdata, tkeyError);
        wr16(rdata, quint16(keyData.size()));
        rdata += keyData;
        wr16(rdata, 0); // no other data
        record.rdata = rdata;
        return buildResponse(packet, {record}, NoError, {}, false);
    };

    if (tsigKeyName(tkey.algorithm) != QStringLiteral("gss-tsig"))
        return answerWith({}, 21, now + 3600, tkey.algorithm); // BADALG

    if (tkey.mode == 5) {
        // Key deletion (RFC 2930 §2.5, §4.2). The answer is signed with the
        // context being retired, which is the last thing that key can prove; a
        // name this server never issued is BADNAME, not a silent success.
        const QString name = tsigKeyName(tkey.name);
        if (!gssContextFor(name))
            return answerWith({}, 20, now + 3600, tkey.algorithm); // BADNAME
        QByteArray answer = answerWith({}, 0, now + 3600, tkey.algorithm);
        answer = signTsigResponse(answer, {}, 0, {}, 0, 0, false, nullptr, name, true, true);
        m_gssContexts.remove(name);
        return answer;
    }
    if (tkey.mode != 3) // only GSS-API negotiation is served here
        return answerWith({}, 19, now + 3600, tkey.algorithm); // BADMODE

    GssContext context;
    QString error;
    if (!m_gssAcceptor(tkey.keyData, &context, &error) || context.key.isEmpty()
        || !Krb5::isSupportedEtype(context.etype)) {
        // The token did not produce a context, so there is nothing to sign with:
        // the TKEY error carries BADKEY and the header stays NOERROR, which is
        // how a client reads "the negotiation was understood and failed".
        return answerWith({}, 17, now + 3600, tkey.algorithm);
    }
    if (context.expires == 0)
        context.expires = qint64(now) + 3600;
    const QString name = tsigKeyName(tkey.name);
    m_gssContexts.insert(name, context);
    // RFC 3645 §4.1.3: a completed negotiation is answered signed over the key
    // it just established, even though the query itself was unsigned.
    return signTsigResponse(
        answerWith(context.replyToken, 0, quint64(context.expires),
                   QStringLiteral("gss-tsig")),
        {}, 0, {}, 0, 0, false, nullptr, name, true, true);
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

void DnsServer::bumpReverseSerial() {
    if (m_reverseZone.isEmpty())
        return;
    auto it = m_records.find(m_reverseZone);
    if (it == m_records.end())
        return;
    for (Record &record : it.value()) {
        if (record.type != TypeSoa)
            continue;
        QByteArray &soa = record.rdata;
        int pos = 0;
        if (!skipName(soa, pos) || !skipName(soa, pos) || pos + 4 > soa.size())
            return;
        const quint32 serial = (quint32(quint8(soa[pos])) << 24)
                               | (quint32(quint8(soa[pos + 1])) << 16)
                               | (quint32(quint8(soa[pos + 2])) << 8)
                               | quint32(quint8(soa[pos + 3]));
        const quint32 next = serial + 1;
        soa[pos] = char((next >> 24) & 0xff);
        soa[pos + 1] = char((next >> 16) & 0xff);
        soa[pos + 2] = char((next >> 8) & 0xff);
        soa[pos + 3] = char(next & 0xff);
        return;
    }
}

namespace {

// The serial a SOA rdata carries: two names, then the 32-bit serial.
quint32 serialFromSoaRdata(const QByteArray &rdata)
{
    int pos = 0;
    if (!skipName(rdata, pos) || !skipName(rdata, pos) || pos + 4 > rdata.size())
        return 0;
    return (quint32(quint8(rdata[pos])) << 24) | (quint32(quint8(rdata[pos + 1])) << 16)
           | (quint32(quint8(rdata[pos + 2])) << 8) | quint32(quint8(rdata[pos + 3]));
}

} // namespace

void DnsServer::setMaster(const QString &master, const QStringList &zones)
{
    m_master = master.trimmed();
    QStringList normalized;
    for (const QString &zone : zones) {
        QString name = zone.trimmed().toLower();
        while (name.endsWith(QLatin1Char('.')))
            name.chop(1);
        if (!name.isEmpty() && !normalized.contains(name))
            normalized.append(name);
    }
    m_masterZones = normalized;
}

QString DnsServer::master() const
{
    return m_master;
}

QStringList DnsServer::masterZones() const
{
    return m_masterZones;
}

void DnsServer::refreshSecondaryZones()
{
    if (m_master.isEmpty() || m_masterZones.isEmpty())
        return;
    for (const QString &zone : m_masterZones)
        startSecondaryPull(zone);
}

quint32 DnsServer::secondarySerial(const QString &zone) const
{
    const QList<Record> soa = records(zone, TypeSoa);
    if (soa.isEmpty())
        return 0;
    return serialFromSoaRdata(soa.first().rdata);
}

const QList<DnsServer::Record> *DnsServer::secondaryRecords(const QString &name) const
{
    const auto it = m_secondary.constFind(name.toLower());
    if (it == m_secondary.constEnd() || it->isEmpty())
        return nullptr;
    return &it.value();
}

QByteArray DnsServer::buildTransferQuery(const QString &zone, quint16 id) const
{
    QByteArray packet;
    wr16(packet, id);
    // A standard query, RD clear: a transfer is asked of the zone's own master,
    // and a recursive lookup of a zone name would be answered from its cache.
    wr16(packet, 0x0000);
    wr16(packet, 1);
    wr16(packet, 0);
    wr16(packet, 0);
    wr16(packet, 0);
    packet += encodeName(zone);
    wr16(packet, TypeAxfr);
    wr16(packet, ClassIn);
    return packet;
}

QByteArray DnsServer::signTsigRequest(const QByteArray &packet, QByteArray *macOut) const
{
    if (macOut)
        macOut->clear();
    if (m_tsigName.isEmpty() || packet.size() < 12)
        return packet;

    const quint64 now = quint64(QDateTime::currentSecsSinceEpoch());
    const quint16 fudge = 300;
    const quint16 id = quint16((quint8(packet[0]) << 8) | quint8(packet[1]));
    const QByteArray mac =
        hmacSha256(m_tsigSecret,
                   packet + tsigVariables(m_tsigName, m_tsigAlgorithm, now, fudge, 0, {}));

    QByteArray signedPacket = packet;
    const quint16 arcount =
        quint16((quint8(signedPacket[10]) << 8) | quint8(signedPacket[11]));
    const quint16 next = quint16(arcount + 1);
    signedPacket[10] = char((next >> 8) & 0xff);
    signedPacket[11] = char(next & 0xff);

    QByteArray rdata;
    rdata += encodeName(m_tsigAlgorithm);
    for (int shift = 40; shift >= 0; shift -= 8)
        rdata.append(char((now >> shift) & 0xff));
    wr16(rdata, fudge);
    wr16(rdata, quint16(mac.size()));
    rdata += mac;
    wr16(rdata, id);
    wr16(rdata, 0);
    wr16(rdata, 0);
    signedPacket += encodeName(m_tsigName);
    wr16(signedPacket, TypeTsig);
    wr16(signedPacket, 255);
    wr32(signedPacket, 0);
    wr16(signedPacket, quint16(rdata.size()));
    signedPacket += rdata;
    if (macOut)
        *macOut = mac;
    return signedPacket;
}

bool DnsServer::verifySecondaryMessage(const QByteArray &packet, const QByteArray &requestMac,
                                       const QByteArray &priorMac, bool first,
                                       QByteArray *macOut, QByteArray *payload) const
{
    if (macOut)
        macOut->clear();
    if (payload)
        payload->clear();
    if (m_tsigName.isEmpty() || packet.size() < 12)
        return false;
    TsigParts tsig;
    if (!findTsig(packet, &tsig) || tsig.offset < 12)
        return false;

    QByteArray unsignedMessage = packet.left(tsig.offset);
    const quint16 arcount =
        quint16((quint8(unsignedMessage[10]) << 8) | quint8(unsignedMessage[11]));
    unsignedMessage[10] = char((quint16(arcount - 1) >> 8) & 0xff);
    unsignedMessage[11] = char((quint16(arcount - 1)) & 0xff);

    const QByteArray &covered = first ? requestMac : priorMac;
    QByteArray prefix;
    wr16(prefix, quint16(covered.size()));
    prefix += covered;
    QByteArray digest = prefix + unsignedMessage;
    if (first) {
        digest += tsigVariables(tsig.name, tsig.algorithm, tsig.timeSigned, tsig.fudge,
                                tsig.error, tsig.other);
    } else {
        for (int shift = 40; shift >= 0; shift -= 8)
            digest.append(char((tsig.timeSigned >> shift) & 0xff));
        wr16(digest, tsig.fudge);
    }
    if (hmacSha256(m_tsigSecret, digest) != tsig.mac)
        return false;
    if (macOut)
        *macOut = tsig.mac;
    if (payload)
        *payload = unsignedMessage;
    return true;
}

void DnsServer::startSecondaryPull(const QString &zone)
{
    if (m_master.isEmpty() || !m_masterZones.contains(zone))
        return;
    if (m_pull) {
        if (m_pull->zone != zone && !m_pullQueue.contains(zone))
            m_pullQueue.append(zone);
        return;
    }

    QHostAddress address;
    quint16 port = 53;
    if (!parseForwarder(m_master, &address, &port)) {
        emit secondaryZoneFailed(zone, tr("%1 is not an address to pull from").arg(m_master));
        return;
    }
    if (m_tsigName.isEmpty()) {
        emit secondaryZoneFailed(
            zone, tr("no TSIG key is configured, so a copy of %1 could not be trusted").arg(zone));
        return;
    }

    auto *pull = new SecondaryPull;
    pull->zone = zone;
    auto *socket = new QTcpSocket(this);
    pull->socket = socket;
    auto *deadline = new QTimer(this);
    deadline->setSingleShot(true);
    pull->deadline = deadline;
    m_pull = pull;

    connect(deadline, &QTimer::timeout, this, [this]() {
        finishSecondaryPull(false, tr("the master did not finish the transfer in time"));
    });
    connect(socket, &QTcpSocket::connected, this, [this]() {
        if (!m_pull || !m_pull->socket)
            return;
        const QByteArray query = buildTransferQuery(m_pull->zone, m_nextPullId++);
        const QByteArray signedQuery = signTsigRequest(query, &m_pull->requestMac);
        QByteArray framed;
        framed.append(char((signedQuery.size() >> 8) & 0xff));
        framed.append(char(signedQuery.size() & 0xff));
        framed.append(signedQuery);
        m_pull->socket->write(framed);
    });
    connect(socket, &QTcpSocket::readyRead, this, &DnsServer::onSecondaryReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, [this]() {
        if (m_pull)
            finishSecondaryPull(
                false, tr("the master closed the connection before the transfer ended"));
    });
    connect(socket, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (m_pull && m_pull->socket)
            finishSecondaryPull(false, m_pull->socket->errorString());
    });
    deadline->start(15000);
    socket->connectToHost(address, port);
}

void DnsServer::onSecondaryReadyRead()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket || !m_pull || m_pull->socket != socket) {
        if (socket)
            socket->readAll();
        return;
    }

    // Kept as a member rather than a local: finishSecondaryPull() deletes the
    // pull, so every use below has to happen before that call returns.
    SecondaryPull *pull = m_pull;
    pull->buffer += socket->readAll();
    while (pull->buffer.size() >= 2) {
        const int length = (int(quint8(pull->buffer[0])) << 8) | int(quint8(pull->buffer[1]));
        if (length == 0) {
            pull->buffer.remove(0, 2);
            continue;
        }
        if (pull->buffer.size() < 2 + length)
            return;
        const QByteArray message = pull->buffer.mid(2, length);
        pull->buffer.remove(0, 2 + length);

        const bool first = pull->chain.isEmpty();
        QByteArray mac;
        QByteArray payload;
        if (!verifySecondaryMessage(message, pull->requestMac, pull->chain, first, &mac, &payload)) {
            finishSecondaryPull(
                false, tr("a message of the transfer did not verify against the configured key"));
            return;
        }
        Message parsed;
        if (!parseMessage(payload, &parsed) || (parsed.flags & 0x8000) == 0) {
            finishSecondaryPull(false, tr("the master sent a message that is not an answer"));
            return;
        }
        const int rcode = parsed.flags & 0x000f;
        if (rcode != 0) {
            finishSecondaryPull(
                false, tr("the master refused the transfer with rcode %1").arg(rcode));
            return;
        }
        pull->chain = mac;

        // The answer section of a transfer message lands in `prerequisites`:
        // parseMessage() collects the answer section there, which is where
        // UPDATE and NOTIFY keep theirs too.
        for (const Record &record : parsed.prerequisites) {
            const QString owner = record.name.toLower();
            if (owner != pull->zone && !owner.endsWith(QLatin1Char('.') + pull->zone)) {
                finishSecondaryPull(
                    false, tr("the master sent %1, which is outside %2").arg(owner, pull->zone));
                return;
            }
            if (record.type == TypeSoa) {
                if (pull->soaCount == 0)
                    pull->serial = serialFromSoaRdata(record.rdata);
                ++pull->soaCount;
                if (pull->soaCount == 2) {
                    // The closing SOA: the stream is complete and the copy
                    // replaces whatever was served before.
                    finishSecondaryPull(true, {});
                    return;
                }
            }
            pull->collected.append(record);
        }
    }
}

void DnsServer::finishSecondaryPull(bool ok, const QString &detail)
{
    SecondaryPull *pull = m_pull;
    if (!pull)
        return;
    m_pull = nullptr;
    if (pull->socket) {
        pull->socket->close();
        pull->socket->deleteLater();
    }
    if (pull->deadline) {
        pull->deadline->stop();
        pull->deadline->deleteLater();
    }

    if (ok) {
        // A transfer replaces the zone rather than merging into it: a record the
        // master dropped has to disappear here too, or this server keeps serving
        // something the zone no longer contains.
        for (auto it = m_secondary.begin(); it != m_secondary.end();) {
            const QString owner = it.key();
            if (owner == pull->zone || owner.endsWith(QLatin1Char('.') + pull->zone))
                it = m_secondary.erase(it);
            else
                ++it;
        }
        for (const Record &record : pull->collected)
            m_secondary[record.name.toLower()].append(record);
        emit secondaryZoneUpdated(pull->zone, pull->serial);
    } else {
        // The previous copy is deliberately left in place: a master that is down
        // is exactly when the copy is the only thing answering.
        emit secondaryZoneFailed(pull->zone, detail);
    }

    const QString zone = pull->zone;
    delete pull;
    if (!m_pullQueue.isEmpty()) {
        const QString next = m_pullQueue.takeFirst();
        QTimer::singleShot(0, this, [this, next]() { startSecondaryPull(next); });
    }
    Q_UNUSED(zone)
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
    // A datagram reply is bounded by the client's receive size; a TCP reply is
    // length-prefixed and bounded only by what the protocol allows.
    const bool udp = tcpClient == nullptr;
    Message message;
    if (!parseMessage(packet, &message))
        return buildResponse(packet, {}, FormErr, {}, udp);

    const int opcode = (message.flags >> 11) & 0x0f;
    if (opcode == 5) {
        // TSIG (RFC 8945) or GSS-TSIG (RFC 3645). An update is the one message
        // that changes the zone, so when a key is configured — a shared secret
        // or a negotiated context — it is the one message that must prove where
        // it came from.
        QByteArray requestMac;
        quint16 tsigError = 0;
        QByteArray other;
        bool signRefusal = false;
        QString tsigKey;
        quint64 clientTime = 0;
        quint16 clientFudge = 0;
        TsigParts present;
        const bool carriesTsig = findTsig(packet, &present);
        const bool gssAttempt =
            carriesTsig && tsigKeyName(present.algorithm) == QStringLiteral("gss-tsig");
        if (!m_tsigName.isEmpty() || gssAttempt) {
            const int verdict = verifyTsig(packet, &requestMac, &tsigError, &other,
                                           &signRefusal, &tsigKey, &clientTime, &clientFudge);
            if (verdict != 0) {
                QByteArray refusal = buildResponse(packet, {}, verdict, {}, udp);
                // A refusal to something that carried a TSIG is answered with a
                // TSIG too: that is how the client learns which end failed.
                if (signRefusal && !requestMac.isEmpty()) {
                    // BADTIME: the MAC verified and only the clocks disagree.
                    // RFC 8945 §5.2.3 has the reply carry the client's own time
                    // and fudge, so it verifies despite the skew, and this
                    // server's time in Other Data for the client to correct to.
                    refusal = signTsigResponse(refusal, requestMac, tsigError, other,
                                               clientTime, clientFudge, false, nullptr,
                                               tsigKey, gssAttempt);
                } else if (signRefusal) {
                    // BADKEY/BADSIG: unsigned, with a zero-length MAC, but the
                    // RR is present under the name and algorithm the request
                    // used so the error is readable even when no such key exists
                    // here (RFC 8945 §5.3.2).
                    refusal = signTsigResponse(refusal, {}, tsigError, other, 0, 0, false,
                                               nullptr, tsigKey, gssAttempt, false,
                                               present.algorithm);
                }
                return refusal;
            }
        }
        const int rcode = handleUpdate(message);
        QByteArray answer = buildResponse(packet, {}, rcode, {}, udp);
        if (gssAttempt && !requestMac.isEmpty())
            answer = signTsigResponse(answer, requestMac, 0, {}, 0, 0, false, nullptr,
                                      tsigKey, true);
        else if (!m_tsigName.isEmpty() && !requestMac.isEmpty())
            answer = signTsigResponse(answer, requestMac, 0, {});
        return answer;
    }
    if (opcode == 4) {
        // NOTIFY (RFC 1996). A NOTIFY that arrives with QR set is a secondary
        // answering one of ours, and answering that with an rcode would read as
        // a second exchange. One with QR clear is a peer asking this server to
        // pull a zone, which it does not do: REFUSED says so, rather than NOTIMP
        // pretending the opcode is unknown now that this server speaks it.
        if ((message.flags & 0x8000) != 0) {
            // The answer to an announcement still in flight. It echoes the id,
            // which is what says which announcement is settled; any answer ends
            // the repeats, a refusal included, because the peer has spoken and
            // another datagram would not change its mind.
            for (int i = 0; i < m_pendingNotifies.size(); ++i) {
                if (m_pendingNotifies.at(i).id == message.id) {
                    m_pendingNotifies.removeAt(i);
                    break;
                }
            }
            return {};
        }
        // A NOTIFY this server is a secondary for: the zone is one it copies and
        // the datagram comes from the master it copies from. It is answered and
        // the pull is queued, so the answer goes out before the transfer starts
        // rather than the master waiting on this server's TCP client.
        if (message.questions.size() == 1) {
            QString zone = message.questions.first().name.toLower();
            while (zone.endsWith(QLatin1Char('.')))
                zone.chop(1);
            QHostAddress masterAddress;
            quint16 masterPort = 53;
            if (!m_master.isEmpty() && parseForwarder(m_master, &masterAddress, &masterPort)
                && sameHostAddress(masterAddress, from) && m_masterZones.contains(zone)) {
                // A master that signs its announcements is held to it: an
                // unsigned one from the right address would let anyone who can
                // forge a source address make this server pull.
                if (!m_tsigName.isEmpty()) {
                    QByteArray requestMac;
                    quint16 tsigError = 0;
                    QByteArray other;
                    bool signRefusal = false;
                    const int verdict =
                        verifyTsig(packet, &requestMac, &tsigError, &other, &signRefusal);
                    if (verdict != 0) {
                        QByteArray refusal = buildResponse(packet, {}, verdict, {}, udp);
                        if (signRefusal)
                            refusal = signTsigResponse(refusal, requestMac, tsigError, other);
                        return refusal;
                    }
                }
                const QString announced = zone;
                QTimer::singleShot(0, this, [this, announced]() {
                    startSecondaryPull(announced);
                });
                return buildResponse(packet, {}, NoError, {}, udp);
            }
        }
        return buildResponse(packet, {}, Refused, {}, udp);
    }
    if (opcode != 0)
        return buildResponse(packet, {}, NotImp, {}, udp);

    // GSS-TSIG negotiation (RFC 3645): a TKEY query carries one GSS-API token
    // and is the only message that may establish the context a later UPDATE
    // names in its TSIG.
    if (message.questions.size() == 1 && message.questions.first().type == TypeTkey)
        return handleTkey(packet, message);

    // Zone transfers (RFC 5936) are answered here rather than by handleQuery():
    // a transfer's answer is the whole zone, not the records at one name, and
    // it is gated on authentication the query path knows nothing about.
    if (message.questions.size() == 1) {
        const Message::Question &question = message.questions.first();
        if (question.type == TypeAxfr || question.type == TypeIxfr)
            return handleTransferRequest(packet, message, udp, tcpClient);
    }

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
    // A negative answer carries the zone's SOA in AUTHORITY so the client knows
    // how long it may cache the absence (RFC 2308 §3). Without it a resolver
    // treats the answer as uncacheable and asks again every time.
    //
    // "Negative answer" is narrower than "no answer": it is a NODATA or
    // NXDOMAIN for a name this zone holds, in class IN. Attaching the SOA to a
    // refusal put an IN-class record under a CHAOS question, and a client that
    // checks the class calls the whole packet malformed (dig: "Message parser
    // reports malformed message packet") instead of reading the refusal.
    QList<Record> authority;
    if (answers.isEmpty() && (rcode == NoError || rcode == NxDomain)
        && message.questions.size() == 1 && message.questions.first().qclass == ClassIn
        && inZone(message.questions.first().name)) {
        const QList<Record> soa = records(zoneFor(message.questions.first().name), TypeSoa);
        if (!soa.isEmpty())
            authority.append(soa.first());
    }
    if (rcode != NoError)
        answers.clear();
    return buildResponse(packet, answers, rcode, authority, udp);
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
        return buildResponse(packet, {}, ServFail, {}, tcpClient == nullptr);

    const QStringList servers = effectiveForwarders();
    QHostAddress upstream;
    quint16 upstreamPort = 53;
    for (int i = 0; i < servers.size() && upstream.isNull(); ++i) {
        const QString spec = servers.at(int(m_forwarderIndex++) % servers.size());
        parseForwarder(spec, &upstream, &upstreamPort);
    }
    if (upstream.isNull()) {
        // Nothing to ask. A resolver that is also its host's only resolver has
        // no upstream left once the loopback entries are dropped, and the
        // operator sees only "this server does not resolve anything". Say why,
        // once, instead of answering in silence.
        if (!m_reportedNoForwarder) {
            m_reportedNoForwarder = true;
            // Four different reasons read the same to a client and must not
            // read the same here: nothing configured, a configured list that
            // names only this server, a host file with no `nameserver` line, a
            // host file whose lines are not addresses, and a host file naming
            // only loopback. The last three used to arrive as one sentence that
            // named loopback for all of them.
            const QStringList configured = forwarders();
            if (servers.isEmpty() && (configured.isEmpty() || !anyForwarderUsable(configured)))
                emit forwardingUnavailable(
                    tr("no forwarder is configured, and %1")
                        .arg(noForwarderReason(configured, zone(), hostForwarders())));
            else if (servers.isEmpty())
                emit forwardingUnavailable(
                    tr("%1 is this DC's own listener, so names outside %2 cannot be "
                       "resolved")
                        .arg(configured.join(QStringLiteral(", ")))
                        .arg(zone()));
            else
                emit forwardingUnavailable(tr("no forwarder could be parsed from %1")
                                               .arg(servers.join(QStringLiteral(", "))));
        }
        return buildResponse(packet, {}, ServFail, {}, tcpClient == nullptr);
    }

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
        return buildResponse(packet, {}, FormErr, {}, tcpClient == nullptr);
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
        return buildResponse(packet, {}, ServFail, {}, tcpClient == nullptr);
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

QStringList DnsServer::nameserversIn(const QString &path)
{
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
}

QStringList DnsServer::usableForwarders(const QStringList &nameservers,
                                        const QStringList &localAddresses)
{
    QStringList result;
    for (const QString &spec : nameservers) {
        QHostAddress address;
        quint16 port = 53;
        if (!parseForwarder(spec, &address, &port))
            continue;
        // Skip ourselves and a local stub: forwarding there would either loop
        // or depend on the resolver this server replaces. What is left is the
        // whole difference between a forwarding resolver and one that answers
        // SERVFAIL to everything outside its zone.
        if (address.isLoopback() || localAddresses.contains(address.toString()))
            continue;
        result.append(spec);
    }
    return result;
}

DnsServer::HostForwarders DnsServer::hostForwarders(const QStringList &paths)
{
    QStringList localAddresses;
    for (const QHostAddress &address : QNetworkInterface::allAddresses())
        localAddresses.append(address.toString());

    // systemd-resolved's stub file names only 127.0.0.53, so the addresses it
    // actually asks are in the file beside it. When /etc/resolv.conf has no
    // usable entry left, that is where the real upstream is.
    const QStringList candidates = paths.isEmpty()
        ? QStringList{QStringLiteral("/etc/resolv.conf"),
                      QStringLiteral("/run/systemd/resolve/resolv.conf")}
        : paths;

    HostForwarders host;
    for (const QString &path : candidates) {
        const QStringList entries = nameserversIn(path);
        // A file that does not exist contributes no facts at all, so "the host
        // has no nameserver" cannot be claimed on the strength of a path this
        // machine never had.
        if (entries.isEmpty() && !QFile::exists(path))
            continue;
        host.files.append(path);
        host.read += entries;
        const QStringList usable = usableForwarders(entries, localAddresses);
        for (const QString &spec : entries) {
            QHostAddress address;
            quint16 port = 53;
            if (!parseForwarder(spec, &address, &port))
                host.unparseable.append(spec);
            else if (!usable.contains(spec))
                host.loopbackOrSelf.append(spec);
        }
        if (host.usable.isEmpty())
            host.usable = usable;
    }
    return host;
}

QStringList DnsServer::systemForwarders()
{
    return hostForwarders().usable;
}

QString DnsServer::noForwarderReason(const QStringList &configured,
                                     const QString &zone,
                                     const HostForwarders &host)
{
    if (!configured.isEmpty())
        return tr("%1 is this DC's own listener, so names outside %2 cannot be "
                  "resolved")
            .arg(configured.join(QStringLiteral(", ")))
            .arg(zone);
    if (host.read.isEmpty())
        return tr("this host has no nameserver line in %1")
            .arg(host.files.isEmpty() ? QStringLiteral("/etc/resolv.conf")
                                      : host.files.join(QStringLiteral(", ")));
    if (!host.unparseable.isEmpty())
        return tr("%1 in this host's nameservers could not be parsed as an address")
            .arg(host.unparseable.join(QStringLiteral(", ")));
    return tr("this host's nameservers (%1) are loopback or this DC itself")
        .arg(host.loopbackOrSelf.join(QStringLiteral(", ")));
}

bool DnsServer::anyForwarderUsable(const QStringList &specs)
{
    for (const QString &spec : specs) {
        QHostAddress address;
        quint16 port = 53;
        if (parseForwarder(spec, &address, &port))
            return true;
    }
    return false;
}

bool DnsServer::isOwnListener(const QString &spec) const
{
    QHostAddress address;
    quint16 port = 53;
    if (!parseForwarder(spec, &address, &port))
        return false;
    // The number is what makes it this server: a local stub resolver on its own
    // port is a real upstream, and the loopback filter that keeps the host's
    // nameserver list from looping back here would throw it away.
    if (port != serverPort())
        return false;
    // The wildcard is the shape most likely to be copied: an operator reading a
    // bind setting types 0.0.0.0:53, and as a destination the kernel delivers
    // that to this host's socket, so it reaches this daemon exactly as
    // 127.0.0.1:53 does. It is neither loopback nor in the interface list.
    // isNull() is not the answer here: a parsed 0.0.0.0 is a valid IPv4 address
    // and is not equal to QHostAddress::Any either — both were measured — so the
    // all-zero checks are written out.
    const bool wildcard = (address.protocol() == QAbstractSocket::IPv4Protocol
                           && address.toIPv4Address() == 0)
                          || address == QHostAddress(QHostAddress::AnyIPv6);
    if (wildcard || address.isNull() || address.isLoopback())
        return true;
    for (const QHostAddress &local : QNetworkInterface::allAddresses()) {
        if (local == address)
            return true;
    }
    return false;
}

QStringList DnsServer::ignoredForwarders() const
{
    QStringList result;
    for (const QString &spec : m_forwarders) {
        if (isOwnListener(spec))
            result.append(spec);
    }
    return result;
}

QStringList DnsServer::effectiveForwarders() const
{
    if (m_forwarders.isEmpty())
        return systemForwarders();
    // Only the key's own entries are filtered here. A configured list is read
    // as written, except for the one entry that cannot work: this server asking
    // itself gets REFUSED back, which reaches the client as an empty SERVFAIL.
    QStringList result;
    for (const QString &spec : m_forwarders) {
        if (!isOwnListener(spec))
            result.append(spec);
    }
    return result;
}

// The serial field of an SOA RDATA: after the two names, four big-endian octets.

quint32 DnsServer::zoneSerial() const
{
    const QList<Record> soa = records(m_zone, TypeSoa);
    if (soa.isEmpty())
        return 0;
    return serialFromSoaRdata(soa.first().rdata);
}

QList<DnsServer::Record> DnsServer::soaAtSerial(quint32 serial) const
{
    QList<Record> out;
    const QList<Record> soa = records(m_zone, TypeSoa);
    if (soa.isEmpty())
        return out;
    Record record = soa.first();
    int pos = 0;
    if (!skipName(record.rdata, pos) || !skipName(record.rdata, pos)
        || pos + 4 > record.rdata.size())
        return out;
    record.rdata[pos] = char((serial >> 24) & 0xff);
    record.rdata[pos + 1] = char((serial >> 16) & 0xff);
    record.rdata[pos + 2] = char((serial >> 8) & 0xff);
    record.rdata[pos + 3] = char(serial & 0xff);
    out.append(record);
    return out;
}

void DnsServer::recordDelta(quint32 from, const QList<Record> &before,
                            const QList<Record> &after)
{
    // Identity for a difference is the whole RR: name, type, TTL and RDATA. A TTL
    // change is a modification, and RFC 1995 §4 says a modification travels as a
    // removal followed by the new copy, not as a silent difference a client
    // applying only additions would never see.
    const auto key = [](const Record &record) {
        QByteArray out = record.name.toLower().toUtf8();
        out.append(char((record.type >> 8) & 0xff));
        out.append(char(record.type & 0xff));
        out.append(char((record.ttl >> 24) & 0xff));
        out.append(char((record.ttl >> 16) & 0xff));
        out.append(char((record.ttl >> 8) & 0xff));
        out.append(char(record.ttl & 0xff));
        out.append(record.rdata);
        return out;
    };
    QMap<QByteArray, QList<Record>> oldByKey;
    QMap<QByteArray, QList<Record>> newByKey;
    QSet<QByteArray> keys;
    for (const Record &record : before) {
        if (record.type == TypeSoa)
            continue; // the serial is carried by the delta's own SOA records
        oldByKey[key(record)].append(record);
        keys.insert(key(record));
    }
    for (const Record &record : after) {
        if (record.type == TypeSoa)
            continue;
        newByKey[key(record)].append(record);
        keys.insert(key(record));
    }
    ZoneDelta delta;
    delta.from = from;
    delta.to = m_serial;
    for (const QByteArray &k : keys) {
        const QList<Record> oldRecords = oldByKey.value(k);
        const QList<Record> newRecords = newByKey.value(k);
        // Counted, not set-compared: the same address held twice at one name is
        // two records, and dropping one of them is a change.
        if (oldRecords.size() > newRecords.size())
            delta.removed += oldRecords.mid(newRecords.size());
        else if (newRecords.size() > oldRecords.size())
            delta.added += newRecords.mid(oldRecords.size());
    }
    if (delta.removed.isEmpty() && delta.added.isEmpty())
        return; // a serial bump that changed no record is not a difference
    m_journal.append(delta);
    while (m_journal.size() > 64)
        m_journal.removeFirst();
}

QList<DnsServer::Record> DnsServer::incrementalResponse(quint32 clientSerial) const
{
    QList<Record> out;
    if (m_zone.isEmpty() || clientSerial == 0)
        return out;
    const quint32 current = zoneSerial();
    int start = -1;
    for (int i = 0; i < m_journal.size(); ++i) {
        if (m_journal.at(i).from == clientSerial) {
            start = i;
            break;
        }
    }
    if (start < 0)
        return out;
    // The deltas have to be a chain that actually reaches the version this
    // server holds; a gap means the client's copy would not become ours, so it
    // is handed the whole zone instead.
    QList<int> chain;
    quint32 expect = clientSerial;
    for (int i = start; i < m_journal.size(); ++i) {
        if (m_journal.at(i).from != expect)
            break;
        chain.append(i);
        expect = m_journal.at(i).to;
    }
    if (chain.isEmpty() || expect != current)
        return out;

    // RFC 1995 §4: the list of difference sequences "is preceded and followed by
    // a copy of the server's current version of the SOA", and each sequence
    // starts with the older SOA and starts its additions with the newer one.
    out.append(soaAtSerial(current));
    for (int index : chain) {
        const ZoneDelta &delta = m_journal.at(index);
        out += soaAtSerial(delta.from);
        out += delta.removed;
        out += soaAtSerial(delta.to);
        out += delta.added;
    }
    out.append(soaAtSerial(current));
    return out;
}

QList<DnsServer::Record> DnsServer::zoneContents() const
{
    return zoneContentsFor(m_zone);
}

QList<DnsServer::Record> DnsServer::zoneContentsFor(const QString &zone) const
{
    QList<Record> result;
    if (zone.isEmpty())
        return result;
    const QList<Record> soa = records(zone, TypeSoa);
    if (soa.isEmpty())
        return result;
    // A transfer opens and closes with the same SOA: the first record tells the
    // client the serial it is about to receive, the last one says the transfer
    // is complete and may be committed.
    result.append(soa.first());
    QString apex = zone.toLower();
    if (apex.endsWith(QLatin1Char('.')))
        apex.chop(1);
    const QString suffix = QLatin1Char('.') + apex;
    for (auto it = m_records.constBegin(); it != m_records.constEnd(); ++it) {
        QString name = it.key();
        if (name.endsWith(QLatin1Char('.')))
            name.chop(1);
        // The reverse zone this DC also answers for is in the same store, and is
        // not part of this zone: a secondary that asked for the forward zone
        // must not be handed PTR records for names it did not ask about.
        if (name != apex && !name.endsWith(suffix))
            continue;
        for (const Record &record : it.value()) {
            if (name == apex && record.type == TypeSoa)
                continue; // already written first, and again at the end
            result.append(record);
        }
    }
    result.append(soa.first());
    return result;
}

QByteArray DnsServer::handleTransferRequest(const QByteArray &packet, const Message &message,
                                            bool udp, QTcpSocket *tcpClient)
{
    const Message::Question question = message.questions.first();
    if (question.qclass != ClassIn || !inZone(question.name))
        return buildResponse(packet, {}, Refused, {}, udp);
    const QString zone = zoneFor(question.name);
    // A full transfer is a sequence of messages over a stream, not a datagram
    // (RFC 5936 §4.2): a UDP request cannot be answered with a zone, and part of
    // one is worse than a refusal because the client may commit it. An IXFR
    // request may arrive as a datagram, and RFC 1995 §2 has an answer for that.
    if (udp && question.type != TypeIxfr)
        return buildResponse(packet, {}, Refused, {}, udp);
    // With no key configured there is no peer that could prove anything, and an
    // open transfer would hand the whole directory's DNS data to any address
    // that can reach the port. Refused is the default posture.
    if (m_tsigName.isEmpty())
        return buildResponse(packet, {}, Refused, {}, udp);

    QByteArray requestMac;
    quint16 tsigError = 0;
    QByteArray other;
    bool signRefusal = false;
    QString tsigKey;
    const int verdict =
        verifyTsig(packet, &requestMac, &tsigError, &other, &signRefusal, &tsigKey);
    if (verdict != 0) {
        QByteArray refusal = buildResponse(packet, {}, verdict, {}, udp);
        if (signRefusal)
            refusal = signTsigResponse(refusal, requestMac, tsigError, other);
        return refusal;
    }

    // The key proves who is asking; this says what it may read. An empty list
    // leaves the older posture alone — the one configured key may transfer every
    // zone this server holds — while a host that lists zones narrows that key to
    // them. Refused is answered signed, since the client has proved its key and
    // an unsigned refusal would look like a server that did not understand it.
    if (!m_transferZones.isEmpty() && !m_transferZones.contains(zone))
        return signTsigResponse(buildResponse(packet, {}, Refused, {}, udp), requestMac, 0, {});

    if (udp) {
        // IXFR over a datagram: the current SOA, which is what RFC 1995 §2 tells
        // a server to send when the difference is not carried in this message. It
        // costs the client one round trip and keeps a datagram from carrying half
        // a delta.
        // The SOA of the zone that was asked for: the forward zone's serial says
        // nothing about the reverse zone, and a client would cache the wrong one.
        const QList<Record> zoneSoa = records(zone, TypeSoa);
        const QByteArray answer =
            buildResponse(packet, zoneSoa.isEmpty() ? soaAtSerial(zoneSerial()) : zoneSoa.mid(0, 1),
                          NoError, {}, true);
        return signTsigResponse(answer, requestMac, 0, {});
    }

    QList<Record> answers;
    // The journal is the forward zone's history: a serial from the reverse zone
    // means nothing against it, so a reverse-zone IXFR falls through to the whole
    // zone, which is the fallback RFC 1995 §6 asks for anyway.
    if (question.type == TypeIxfr && zone == m_zone) {
        // The version the client holds arrives as the SOA in the request's
        // authority section, which the parser keeps in `updates` for that
        // section; a client that puts it in the answer section is served the same
        // way rather than told its request was malformed.
        quint32 clientSerial = 0;
        for (const Record &record : message.updates) {
            if (record.type == TypeSoa) {
                clientSerial = serialFromSoaRdata(record.rdata);
                break;
            }
        }
        if (clientSerial == 0) {
            for (const Record &record : message.prerequisites) {
                if (record.type == TypeSoa) {
                    clientSerial = serialFromSoaRdata(record.rdata);
                    break;
                }
            }
        }
        if (clientSerial != 0) {
            const quint32 current = zoneSerial();
            // RFC 1982 arithmetic: a client at or ahead of this version is
            // answered with one SOA, which says there is nothing to send it.
            if (qint32(quint32(clientSerial - current)) >= 0)
                answers = soaAtSerial(current);
            else
                answers = incrementalResponse(clientSerial);
        }
    }
    // No journal entry for that version: the whole zone, which is the fallback
    // RFC 1995 §6 asks a server to make rather than an error.
    if (answers.isEmpty())
        answers = zoneContentsFor(zone);
    if (answers.isEmpty())
        return buildResponse(packet, {}, ServFail, {}, udp);

    // One TCP message is capped at 65535 bytes by its length prefix. A zone that
    // does not fit used to be answered SERVFAIL, which meant no zone larger than
    // about 64 KiB could ever be secondaried. It is sent as a stream instead:
    // as many messages as the records need, each signed over the one before it,
    // with the question section in the first message only.
    const quint64 stamp = quint64(QDateTime::currentSecsSinceEpoch());
    const quint16 fudge = 300;
    // The room a message has is what is left after the envelope (header, question
    // and any OPT) and the TSIG RR that follows every message. Measured from the
    // bytes rather than assumed, so a client that sends a long question or an OPT
    // cannot produce a message the framer would drop.
    const QByteArray envelope = buildResponse(packet, {}, NoError, {}, false);
    if (envelope.size() < 12)
        return buildResponse(packet, {}, ServFail, {}, udp);
    const int tsigBytes =
        signTsigResponse(envelope, requestMac, 0, {}, stamp, fudge).size() - envelope.size();
    const int budget = 65535 - envelope.size() - tsigBytes;
    if (budget <= 0)
        return buildResponse(packet, {}, ServFail, {}, udp);

    // Records are packed in the order the transfer promises them, so the SOA that
    // opens the zone stays first and the one that closes it stays last.
    QList<QList<Record>> batches;
    int used = 0;
    for (const Record &record : answers) {
        const int size = encodeName(record.name).size() + 10 + record.rdata.size();
        // A record that cannot fit in a message of its own is not something this
        // framing can carry; failing here is visible, where a message over the
        // limit would be dropped and reach the client as a hang.
        if (size > budget)
            return buildResponse(packet, {}, ServFail, {}, udp);
        if (batches.isEmpty() || used + size > budget) {
            batches.append(QList<Record>());
            used = 0;
        }
        batches.last().append(record);
        used += size;
    }
    // Without a socket there is nothing to send the first messages on, and a
    // truncated stream is worse than a refusal.
    if (batches.size() > 1 && !tcpClient)
        return buildResponse(packet, {}, ServFail, {}, udp);

    QByteArray chain = requestMac;
    for (int i = 0; i < batches.size(); ++i) {
        QByteArray message = buildResponse(packet, batches.at(i), NoError, {}, false, i == 0);
        QByteArray mac;
        message = signTsigResponse(message, chain, 0, {}, stamp, fudge, i > 0, &mac);
        chain = mac;
        if (i + 1 == batches.size())
            return message;
        sendTcpResponse(tcpClient, message);
    }
    return {};
}

int DnsServer::handleQuery(const Message &message, QList<Record> &answers) {
    if (message.questions.size() != 1)
        return FormErr;
    const Message::Question question = message.questions.first();
    if (!m_zone.isEmpty() && !inZone(question.name))
        return Refused;

    emit queryReceived(question.name, question.type);

    // Zone transfers are not served. A transfer request must not produce a
    // partial AXFR-style reply (one SOA and then nothing), so refuse it
    // explicitly rather than answering it as an ordinary query.
    if (question.type == TypeAxfr || question.type == TypeIxfr)
        return Refused;

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
    if (!found.isEmpty())
        return NoError;
    // Two different negatives, and a client acts on the difference: a name that
    // is not in the zone is NXDOMAIN, while a name that exists without this type
    // is an empty NOERROR. Answering the first as the second told every client
    // and every cache that the name merely had no A record, so a negative lookup
    // was retried instead of cached (RFC 2308 §2.1).
    // `records()` also reads the copy of a zone this server is secondary for,
    // so a name the master never sent is NXDOMAIN here too.
    if (records(question.name, TypeAny).isEmpty())
        return NxDomain;
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
    // The zone as it stands, taken before the write so the difference this update
    // makes can be journalled for an IXFR client (RFC 1995 §4) rather than
    // guessed at from the update message, which does not record what it removed.
    const QList<Record> beforeUpdate = zoneContents();
    const quint32 serialBefore = m_serial;
    bool changed = false;
    // Which zones this update wrote into. The forward zone's serial used to move
    // for a PTR as well, and the reverse zone's never did: the reverse copy then
    // carried a serial older than its own contents, and the announcement named a
    // zone whose version had not changed.
    bool forwardTouched = false;
    bool reverseTouched = false;
    for (const Record &update : message.updates) {
        if (!m_reverseZone.isEmpty() && zoneFor(update.name) == m_reverseZone)
            reverseTouched = true;
        else
            forwardTouched = true;
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
        forwardTouched = true;
    }
    if (changed) {
        if (forwardTouched) {
            bumpSerial();
            recordDelta(serialBefore, beforeUpdate, zoneContents());
        }
        if (reverseTouched)
            bumpReverseSerial();
        // Each zone that moved is announced by name, because that is the zone a
        // secondary compares serials against: this turns a change into a diff
        // pull instead of a full transfer minutes later. The journal is the
        // forward zone's history, so a reverse change tells its secondaries to
        // pull rather than handing them a delta.
        if (forwardTouched)
            notifySecondaries(m_zone);
        if (reverseTouched)
            notifySecondaries(m_reverseZone);
    }
    return NoError;
}

QByteArray DnsServer::buildResponse(const QByteArray &query, const QList<Record> &answers,
                                    int rcode, const QList<Record> &authority, bool udp,
                                    bool includeQuestion) const {
    int pos = 0;
    quint16 id = 0;
    quint16 queryFlags = 0;
    quint16 qdcount = 0;
    if (!take16(query, pos, &id) || !take16(query, pos, &queryFlags)
        || !take16(query, pos, &qdcount))
        return {};

    // EDNS0 (RFC 6891). A client that sent an OPT gets one back, carrying this
    // server's own UDP payload size and echoing its DO bit; a client that asked
    // for a version this server does not implement gets BADVERS instead of an
    // answer, because answering a version you do not speak is how a client
    // concludes you do. A query without an OPT is answered without one, which is
    // what a pre-EDNS client expects.
    quint16 clientUdpSize = 0;
    quint32 optTtl = 0;
    const bool hasOpt = findOpt(query, &clientUdpSize, &optTtl);
    const quint8 optVersion = quint8((optTtl >> 16) & 0xff);
    const bool badVersion = hasOpt && optVersion != 0;
    const QList<Record> noAnswers;
    // BADVERS is 16, and a 4-bit header rcode cannot carry it: the low nibble
    // goes in the header (0) and the high byte in the OPT TTL (RFC 6891
    // §6.1.3). It carries no answer either — a server that cannot read the
    // request's version cannot claim to have answered it.
    const QList<Record> &answersToWrite = badVersion ? noAnswers : answers;
    if (badVersion)
        rcode = NoError;
    const quint16 optExtendedRcode = badVersion ? quint16(1) : quint16(0);

    QByteArray response;
    wr16(response, id);
    const quint16 opcode = quint16(queryFlags & 0x7800);
    const quint16 rd = quint16(queryFlags & 0x0100);
    // AA only means something on a successful authoritative answer; RA says
    // this server can recurse for names outside the zone.
    // AA is about who answered, not whether the name existed: a NXDOMAIN from
    // this zone is as authoritative as a positive answer, and a resolver keeps
    // it only if it believes that.
    const quint16 aa = (rcode == NoError || rcode == NxDomain) ? quint16(0x0400)
                                                              : quint16(0);
    const quint16 ra = m_forwarding ? quint16(0x0080) : quint16(0);
    wr16(response, quint16(0x8000 | opcode | rd | ra | aa | quint16(rcode & 0x0f)));
    wr16(response, includeQuestion ? qdcount : quint16(0));
    wr16(response, quint16(answersToWrite.size()));
    wr16(response, quint16(authority.size()));
    wr16(response, hasOpt ? quint16(1) : quint16(0));

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
    // Parsed either way — the question is where the answer section starts — but
    // written only when this message is meant to carry it.
    if (includeQuestion)
        response.append(query.mid(12, qpos - 12));

    // Truncation (RFC 1035 §4.2.1, RFC 6891 §6.2.5). A datagram reply must fit
    // what the client said it can receive: 512 bytes unless it sent an OPT, in
    // which case its advertised size, and never less than 512. Sending more
    // instead produces a reply the client's buffer silently cuts — a mangled
    // packet it cannot tell from a corrupt one. So the records that fit are
    // written, the rest are dropped, and TC says to retry over TCP, where the
    // same query gets the whole answer.
    const int recordBudget = udp ? (hasOpt ? qMax<int>(clientUdpSize, 512) : 512)
                                     - (hasOpt ? kOptBytes : 0)
                               : 0;
    bool truncated = false;
    int writtenAnswers = 0;
    int writtenAuthority = 0;
    for (int section = 0; section < 2 && !truncated; ++section) {
        const bool inAnswers = section == 0;
        for (const Record &record : inAnswers ? answersToWrite : authority) {
            QByteArray encoded;
            encoded.append(encodeName(record.name));
            wr16(encoded, record.type);
            // A zone record is IN; a TKEY answer is class ANY (RFC 2930 §2.1)
            // and carries that class in the record itself.
            wr16(encoded, record.rclass == 0 ? ClassIn : record.rclass);
            wr32(encoded, record.ttl);
            wr16(encoded, quint16(record.rdata.size()));
            encoded.append(record.rdata);
            if (udp && response.size() + encoded.size() > recordBudget) {
                truncated = true;
                break;
            }
            response.append(encoded);
            if (inAnswers)
                ++writtenAnswers;
            else
                ++writtenAuthority;
        }
    }
    if (truncated) {
        response[2] = char(quint8(response.at(2)) | 0x02); // TC
        response[6] = char((writtenAnswers >> 8) & 0xff);
        response[7] = char(writtenAnswers & 0xff);
        response[8] = char((writtenAuthority >> 8) & 0xff);
        response[9] = char(writtenAuthority & 0xff);
    }

    if (hasOpt) {
        // The responder's own payload size goes in the class field; the TTL
        // word is extended rcode, version 0 and the flags with DO echoed.
        response.append('\0');
        wr16(response, 41);
        wr16(response, kEdnsUdpPayloadSize);
        const quint16 flags = quint16(optTtl & 0x8000);
        wr32(response, (quint32(optExtendedRcode) << 24) | quint32(flags));
        wr16(response, 0);
    }
    return response;
}

bool DnsServer::saveZone(const QString &path, QString *error) const {
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("zone")] = m_zone;
    root[QStringLiteral("serial")] = double(m_serial);
    if (!m_reverseZone.isEmpty())
        root[QStringLiteral("reverseZone")] = m_reverseZone;
    // One shape for a record wherever it travels: the zone's own list and each
    // half of a remembered difference.
    const auto recordToObject = [](const Record &record) {
        QJsonObject entry;
        entry[QStringLiteral("name")] = record.name;
        entry[QStringLiteral("type")] = int(record.type);
        entry[QStringLiteral("ttl")] = double(record.ttl);
        entry[QStringLiteral("rdata")] = QString::fromLatin1(record.rdata.toHex());
        return entry;
    };
    QJsonArray recordsArray;
    for (auto it = m_records.constBegin(); it != m_records.constEnd(); ++it) {
        for (const Record &record : it.value())
            recordsArray.append(recordToObject(record));
    }
    root[QStringLiteral("records")] = recordsArray;

    // The journal rides in the zone file. A daemon that restarts still holds the
    // differences that let a lagging client be brought forward, instead of being
    // handed the whole zone for a change it was only a little behind on; a zone
    // written before this key existed loads with an empty journal.
    QJsonArray journalArray;
    for (const ZoneDelta &delta : m_journal) {
        QJsonObject entry;
        entry[QStringLiteral("from")] = double(delta.from);
        entry[QStringLiteral("to")] = double(delta.to);
        QJsonArray removed;
        for (const Record &record : delta.removed)
            removed.append(recordToObject(record));
        QJsonArray added;
        for (const Record &record : delta.added)
            added.append(recordToObject(record));
        entry[QStringLiteral("removed")] = removed;
        entry[QStringLiteral("added")] = added;
        journalArray.append(entry);
    }
    root[QStringLiteral("journal")] = journalArray;

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
    m_reverseZone = root.value(QStringLiteral("reverseZone")).toString().toLower();
    for (const QJsonValue &value : root.value(QStringLiteral("records")).toArray()) {
        const QJsonObject entry = value.toObject();
        const QString name = entry.value(QStringLiteral("name")).toString();
        if (name.isEmpty())
            continue;
        addRecord(name, quint16(entry.value(QStringLiteral("type")).toInt()),
                  quint32(entry.value(QStringLiteral("ttl")).toDouble(3600)),
                  QByteArray::fromHex(entry.value(QStringLiteral("rdata")).toString().toLatin1()));
    }

    // A difference the zone file carries is a difference this server can still
    // answer for, so a restart does not turn an IXFR into an AXFR. Entries that
    // do not carry the bounds they were written with are dropped rather than
    // given a made-up version, and the journal keeps at most the same 64 changes
    // the running one does.
    m_journal.clear();
    for (const QJsonValue &value : root.value(QStringLiteral("journal")).toArray()) {
        const QJsonObject entry = value.toObject();
        if (!entry.contains(QStringLiteral("from")) || !entry.contains(QStringLiteral("to")))
            continue;
        ZoneDelta delta;
        delta.from = quint32(entry.value(QStringLiteral("from")).toDouble());
        delta.to = quint32(entry.value(QStringLiteral("to")).toDouble());
        const auto recordsOf = [&entry](const QString &key) {
            QList<Record> records;
            for (const QJsonValue &element : entry.value(key).toArray()) {
                const QJsonObject object = element.toObject();
                const QString recordName = object.value(QStringLiteral("name")).toString();
                if (recordName.isEmpty())
                    continue;
                Record record;
                record.name = recordName;
                record.type = quint16(object.value(QStringLiteral("type")).toInt());
                record.ttl = quint32(object.value(QStringLiteral("ttl")).toDouble(3600));
                record.rdata = QByteArray::fromHex(
                    object.value(QStringLiteral("rdata")).toString().toLatin1());
                records.append(record);
            }
            return records;
        };
        delta.removed = recordsOf(QStringLiteral("removed"));
        delta.added = recordsOf(QStringLiteral("added"));
        if (delta.removed.isEmpty() && delta.added.isEmpty())
            continue; // a difference that changes no record was never journalled
        m_journal.append(delta);
    }
    while (m_journal.size() > 64)
        m_journal.removeFirst();
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
