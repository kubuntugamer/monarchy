// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DNSSERVER_H
#define DNSSERVER_H

#include <QObject>
#include <QUdpSocket>
#include <QTcpServer>
#include <QDateTime>
#include <QHash>
#include <QHostAddress>
#include <QMap>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QList>
#include <QByteArray>

class QTcpSocket;

// AD-integrated DNS server (UDP, RFC 1035 + RFC 2136). It serves one
// authoritative forward zone that belongs to the domain, publishes the
// service locator records a domain controller is required to register
// (MS-ADTS 6.1.1.2), and applies dynamic updates to that zone in memory and
// on disk.
//
// Recursion is opt-in. When enabled, queries for names outside the zone are
// forwarded to upstream resolvers and the answers are cached for their TTL;
// with recursion disabled they are answered with REFUSED. Updates that do not
// name the zone are always answered with NOTAUTH/NOTZONE.
class DnsServer : public QObject
{
    Q_OBJECT
public:
    explicit DnsServer(QObject *parent = nullptr);
    ~DnsServer() override;

    // Binds both UDP and TCP on `port`: RFC 1035 clients retry a truncated
    // UDP answer over TCP, and the server forwards TCP queries over TCP.
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
                    quint16 ldapPort, quint16 gcPort, const QString &site,
                    quint16 kpasswdPort = 464, quint16 kdcPort = 88);

    // Legacy entry point: builds the zone for `dc1.<zone>` on 127.0.0.1.
    void loadDefaultZone(const QString &zone);

    // Adds or corrects the SRV locators loadAdZone() would publish for this DC
    // at these ports, in a zone that was loaded from disk: a zone provisioned
    // by an older build, or one whose records were edited away, is repaired in
    // place instead of advertising a service nothing answers. Records that are
    // already right are left untouched. Returns true when the zone changed.
    bool repairAdZoneLocators(const QString &host, quint16 ldapPort, quint16 gcPort,
                             const QString &site, quint16 kpasswdPort = 464,
                             quint16 kdcPort = 88);

    // Holds the DC's own A records (host, ns1 and the zone apex) to the address
    // it is configured with. A zone loaded from disk can carry the address of a
    // machine that has since moved, and dcIp is the authority on where this DC
    // answers; records that already match are left untouched. Returns true when
    // the zone changed.
    bool repairAdZoneAddresses(const QString &host, const QString &ip);

    void addRecord(const QString &name, quint16 type, quint32 ttl, const QByteArray &rdata);
    void removeRecord(const QString &name, quint16 type);
    QList<Record> records(const QString &name, quint16 type) const;

    // Dynamic updates. When disabled, every UPDATE message is answered with
    // REFUSED; the default allows secure-channel-style updates from any peer,
    // which callers should keep on a trusted interface only.
    void setDynamicUpdatesEnabled(bool enabled);
    bool dynamicUpdatesEnabled() const;

    // Caching forwarder. `forwarders` entries are "address" or
    // "address:port" (port 53 by default); an empty list reads the host's
    // /etc/resolv.conf, falling back to systemd-resolved's upstream file, and
    // ignores loopback/self addresses so it never queries itself.
    void setForwardingEnabled(bool enabled);
    bool forwardingEnabled() const;
    void setForwarders(const QStringList &forwarders);
    QStringList forwarders() const;
    void clearCache();
    int cachedResponseCount() const;

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
    void onUpstreamReadyRead();
    void onNewTcpConnection();
    void onTcpClientReadyRead();
    void onUpstreamTcpReadyRead();
    void onUpstreamTcpDisconnected();

private:
    struct PendingQuery {
        QHostAddress clientAddress;
        quint16 clientPort = 0;
        QPointer<QTcpSocket> tcpClient; // null when the client used UDP
        QHostAddress upstreamAddress;
        quint16 upstreamPort = 53;
        QPointer<QTcpSocket> upstreamTcp; // null when UDP was used upstream
        QByteArray upstreamTcpBuffer;
        QByteArray query;
        QString cacheKey;
        QDateTime sent;
    };

    struct CacheEntry {
        QByteArray packet; // transaction ID zeroed; TTLs as received
        QDateTime stored;
        quint32 lifetime = 0;
        QList<int> ttlOffsets;
    };

    QByteArray handlePacket(const QByteArray &packet, const QHostAddress &from, quint16 fromPort,
                            QTcpSocket *tcpClient = nullptr);
    QByteArray forwardQuery(const Message &message, const QByteArray &packet,
                            const QHostAddress &from, quint16 fromPort, QTcpSocket *tcpClient);
    QByteArray cachedResponse(const CacheEntry &entry, quint16 id) const;
    void cacheResponse(const QString &key, const QByteArray &packet);
    void deliverPending(quint16 upstreamId, const QByteArray &response);
    void failPending(quint16 upstreamId);
    void sendTcpResponse(QTcpSocket *socket, const QByteArray &response);
    void timeoutPending(quint16 upstreamId);
    QStringList effectiveForwarders() const;
    // Returns the rcode; fills `answers` for standard queries.
    int handleQuery(const Message &message, QList<Record> &answers);
    int handleUpdate(const Message &message);
    QByteArray buildResponse(const QByteArray &query, const QList<Record> &answers, int rcode,
                             const QList<Record> &authority = {}) const;

    void bumpSerial();
    bool inZone(const QString &name) const;
    QByteArray srvRdata(quint16 port, const QString &target) const;
    QList<Record> &recordList(const QString &name);

    QUdpSocket *m_socket = nullptr;
    QUdpSocket *m_upstreamSocket = nullptr;
    QTcpServer *m_tcpServer = nullptr;
    QSet<QTcpSocket *> m_tcpClients;
    QHash<QTcpSocket *, QByteArray> m_tcpClientBuffers;
    QHash<QTcpSocket *, quint16> m_upstreamTcpIds;
    QMap<QString, QList<Record>> m_records; // lower-case owner name -> records
    QHash<quint16, PendingQuery> m_pending;
    QHash<QString, CacheEntry> m_cache;
    QStringList m_forwarders;
    QString m_zone;
    quint32 m_serial = 1;
    quint16 m_nextUpstreamId = 1;
    quint16 m_forwarderIndex = 0;
    bool m_updatesEnabled = true;
    bool m_forwarding = false;
};

#endif // DNSSERVER_H
