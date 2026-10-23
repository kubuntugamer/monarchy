// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DNSSERVER_H
#define DNSSERVER_H

#include <QObject>
#include <QUdpSocket>
#include <QMap>
#include <QString>
#include <QList>
#include <QByteArray>

// AD-integrated DNS server (UDP, RFC 1035 + RFC 2136). It serves one
// authoritative forward zone that belongs to the domain, publishes the
// service locator records a domain controller is required to register
// (MS-ADTS 6.1.1.2), and applies dynamic updates to that zone in memory and
// on disk.
//
// This is not a recursive resolver: queries for names outside the zone are
// answered with REFUSED, and updates that do not name the zone are answered
// with NOTAUTH/NOTZONE.
class DnsServer : public QObject
{
    Q_OBJECT
public:
    explicit DnsServer(QObject *parent = nullptr);
    ~DnsServer() override;

    bool listen(quint16 port = 1053);
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    // Parsed wire message; defined in the implementation.
    struct Message;

    struct Record {
        QString name;
        quint16 type = 0;
        quint32 ttl = 0;
        QByteArray rdata;
        // Class is only meaningful inside an UPDATE message, where it selects
        // between adding (IN), deleting an RRset (ANY) and deleting one RR
        // (NONE). Stored records are always IN.
        quint16 rclass = 1;
    };

    // Record types used by this server.
    enum RecordType : quint16 {
        TypeA = 1,
        TypeNs = 2,
        TypeCname = 5,
        TypeSoa = 6,
        TypePtr = 12,
        TypeMx = 15,
        TypeTxt = 16,
        TypeSrv = 33,
        TypeAaaa = 28,
        TypeAny = 255
    };

    // The zone this server is authoritative for (empty when none is loaded).
    void setZone(const QString &zone);
    QString zone() const;

    // Loads an empty zone: SOA, NS, the apex A record and the complete set of
    // domain-controller SRV records for `host`/`ip`. `site` is the AD site the
    // DC belongs to, which decides the _sites._msdcs record names.
    void loadAdZone(const QString &zone, const QString &host, const QString &ip,
                    quint16 ldapPort, quint16 gcPort, const QString &site);

    // Legacy entry point: builds the zone for `dc1.<zone>` on 127.0.0.1.
    void loadDefaultZone(const QString &zone);

    void addRecord(const QString &name, quint16 type, quint32 ttl, const QByteArray &rdata);
    void removeRecord(const QString &name, quint16 type);
    QList<Record> records(const QString &name, quint16 type) const;

    // Dynamic updates. When disabled, every UPDATE message is answered with
    // REFUSED; the default allows secure-channel-style updates from any peer,
    // which callers should keep on a trusted interface only.
    void setDynamicUpdatesEnabled(bool enabled);
    bool dynamicUpdatesEnabled() const;

    // Zone persistence. `saveZone` writes the zone as JSON, `loadZone` reads
    // it back and restores the zone name and SOA serial.
    bool saveZone(const QString &path, QString *error = nullptr) const;
    bool loadZone(const QString &path, QString *error = nullptr);

    // Builds a DNS message for tests and tools: a single-question query.
    static QByteArray buildQuery(const QString &name, quint16 type, quint16 id = 0x1234);

signals:
    void queryReceived(const QString &name, quint16 type);
    void updateApplied(const QString &name, quint16 type, bool added);

private slots:
    void onReadyRead();

private:
    QByteArray handlePacket(const QByteArray &packet);
    // Returns the rcode; fills `answers` for standard queries.
    int handleQuery(const Message &message, QList<Record> &answers);
    int handleUpdate(const Message &message);
    QByteArray buildResponse(const QByteArray &query, const QList<Record> &answers, int rcode) const;

    void bumpSerial();
    bool inZone(const QString &name) const;
    QByteArray srvRdata(quint16 port, const QString &target) const;
    QList<Record> &recordList(const QString &name);

    QUdpSocket *m_socket = nullptr;
    QMap<QString, QList<Record>> m_records; // lower-case owner name -> records
    QString m_zone;
    quint32 m_serial = 1;
    bool m_updatesEnabled = true;
};

#endif // DNSSERVER_H
