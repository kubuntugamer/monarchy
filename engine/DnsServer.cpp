// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DnsServer.h"

#include <QDate>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
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
}

DnsServer::~DnsServer() {
    close();
}

bool DnsServer::listen(quint16 port) {
    return m_socket->bind(QHostAddress::Any, port);
}

void DnsServer::close() {
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

void DnsServer::loadAdZone(const QString &zone, const QString &host, const QString &ip,
                           quint16 ldapPort, quint16 gcPort, const QString &site) {
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

    const QString siteLower = siteName.toLower();
    const QString siteDomain = siteLower + QLatin1String("._sites.") + zoneName;
    const QString msdcs = QStringLiteral("dc._msdcs.") + zoneName;
    const QString siteMsdcs = siteLower + QLatin1String("._sites.") + msdcs;
    const QString gcMsdcs = QStringLiteral("gc._msdcs.") + zoneName;

    struct SrvSpec { QString owner; quint16 port; };
    const QList<SrvSpec> specs = {
        {QStringLiteral("_ldap._tcp.") + zoneName, ldapPort},
        {QStringLiteral("_ldap._tcp.") + msdcs, ldapPort},
        {QStringLiteral("_ldap._tcp.") + siteDomain, ldapPort},
        {QStringLiteral("_ldap._tcp.") + siteMsdcs, ldapPort},
        {QStringLiteral("_kerberos._tcp.") + zoneName, 88},
        {QStringLiteral("_kerberos._tcp.") + siteDomain, 88},
        {QStringLiteral("_kerberos._tcp.") + msdcs, 88},
        {QStringLiteral("_kerberos._udp.") + zoneName, 88},
        {QStringLiteral("_kpasswd._tcp.") + zoneName, 464},
        {QStringLiteral("_kpasswd._udp.") + zoneName, 464},
        {QStringLiteral("_gc._tcp.") + zoneName, gcPort},
        {QStringLiteral("_gc._tcp.") + siteDomain, gcPort},
        {QStringLiteral("_ldap._tcp.") + gcMsdcs, gcPort},
        {QStringLiteral("_ldap._tcp.") + siteLower + QLatin1String("._sites.") + gcMsdcs, gcPort},
        {QStringLiteral("_ldap._tcp.pdc._msdcs.") + zoneName, ldapPort},
    };
    for (const SrvSpec &spec : specs)
        addRecord(spec.owner, TypeSrv, 600, srvRdata(spec.port, hostName));
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
        const QByteArray response = handlePacket(buffer);
        if (!response.isEmpty())
            m_socket->writeDatagram(response, peer, port);
    }
}

QByteArray DnsServer::handlePacket(const QByteArray &packet) {
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

    QList<Record> answers;
    const int rcode = handleQuery(message, answers);
    if (rcode != NoError)
        answers.clear();
    return buildResponse(packet, answers, rcode);
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
    // AA only means something on a successful authoritative answer.
    const quint16 aa = rcode == NoError ? quint16(0x0400) : quint16(0);
    wr16(response, quint16(0x8000 | opcode | rd | aa | quint16(rcode & 0x0f)));
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
