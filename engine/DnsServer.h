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
        TypeAaaa = 28,
        TypeSrv = 33,
        TypeTsig = 250,
        TypeIxfr = 251,
        TypeAxfr = 252,
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

    // The reverse zone AD provisions for a DC's address: /24 of the dotted
    // quad, holding a PTR for the DC. The zone is derived from the address, not
    // authored, so this both repairs it in place and withdraws the previous one
    // when the DC moves. Returns true when the zone changed.
    bool repairReverseZone(const QString &host, const QString &ip);
    QString reverseZone() const;

    void addRecord(const QString &name, quint16 type, quint32 ttl, const QByteArray &rdata);
    void removeRecord(const QString &name, quint16 type);
    QList<Record> records(const QString &name, quint16 type) const;

    // Dynamic updates. When disabled, every UPDATE message is answered with
    // REFUSED; the default allows secure-channel-style updates from any peer,
    // which callers should keep on a trusted interface only.
    void setDynamicUpdatesEnabled(bool enabled);
    bool dynamicUpdatesEnabled() const;

    // A shared-secret TSIG key (RFC 8945) that UPDATE messages must be signed
    // with, given as the base64 secret from the key file. With a key set, an
    // update that is unsigned, signed by another key, or carrying a MAC that
    // does not verify is refused; without one, updates stay unauthenticated.
    // The same key is the only way to be served a zone transfer: unsigned, or
    // signed with the wrong secret, gets no zone. hmac-sha256 is the algorithm
    // this server speaks.
    void setUpdateTsig(const QString &name, const QString &algorithm, const QByteArray &base64Secret);
    QString updateTsigName() const;

    // The zones the configured key may transfer, lower case and without a
    // trailing dot. Empty — the default — keeps the older posture, where the one
    // key may read every zone this server holds; a list narrows it to those
    // zones, so a key handed to a partner for the reverse zone cannot also pull
    // the forward zone out of this server. A transfer of a zone that is not in
    // the list is refused after the key has been proved, and the refusal is
    // signed, because the client has shown it holds the key.
    void setTransferZones(const QStringList &zones);
    QStringList transferZones() const;

    // Secondaries to tell when the zone's serial moves (RFC 1996), as
    // "address" or "address:port" entries like the forwarders. An applied update
    // that changes the zone sends each of them the SOA it now holds, signed with
    // the transfer key when one is configured, so a secondary pulls the
    // difference instead of waiting out its refresh interval. An empty list —
    // the default — announces nothing: a DC that has never been told about a
    // secondary does not invent one from the zone's NS records.
    void setNotifyTargets(const QStringList &targets);
    QStringList notifyTargets() const;

    // Caching forwarder. `forwarders` entries are "address" or
    // "address:port" (port 53 by default); an empty list reads the host's
    // /etc/resolv.conf, falling back to systemd-resolved's upstream file, and
    // ignores loopback/self addresses so it never queries itself.
    void setForwardingEnabled(bool enabled);
    bool forwardingEnabled() const;
    void setForwarders(const QStringList &forwarders);
    QStringList forwarders() const;
    // The upstreams an out-of-zone name would actually be asked about: the
    // configured list minus this server's own listener, or the host's
    // nameservers once the ones that would loop back here are dropped. An empty
    // result is why every out-of-zone query would be answered SERVFAIL, so
    // forwardingUnavailable() reports it once.
    QStringList effectiveForwarders() const;
    // The configured entries effectiveForwarders() dropped for naming this
    // server itself. A caller reports them rather than dropping them silently:
    // a forwarders= line that lists a dead entry as an upstream reads like a
    // working configuration right up until the first out-of-zone query.
    QStringList ignoredForwarders() const;
    // Whether `spec` asks this server: the port it is listening on, at a
    // loopback or local address. A loopback address on any other port is a
    // local stub resolver, which is a legitimate upstream and is kept.
    bool isOwnListener(const QString &spec) const;
    // What this host's resolver files say, kept as separate facts because they
    // mean different things to an operator and read the same when collapsed:
    // no `nameserver` line at all is a host with nothing configured, a line that
    // is not an address is a broken host file, and a line naming loopback is a
    // host that is its own resolver. Reporting the first two as the third sends
    // an operator to edit a file that is already right.
    struct HostForwarders {
        QStringList usable;         // what an out-of-zone query would be sent to
        QStringList unparseable;    // `nameserver` values that are not address[:port]
        QStringList loopbackOrSelf; // dropped for naming loopback or this machine
        QStringList read;           // every `nameserver` value read, in order
        QStringList files;          // the resolver files those values came from
    };
    // Reads `paths` in order and stops at the first file with a usable entry, as
    // systemForwarders() does. Defaults to /etc/resolv.conf and the file beside
    // systemd-resolved's stub; the argument exists so a test can pin the
    // classification without this host's resolv.conf becoming a fixture.
    static HostForwarders hostForwarders(const QStringList &paths = QStringList());
    // The same lookup and filter, for callers that seed dc.conf with what this
    // host can actually resolve through (the provisioner and the installer)
    // rather than serve queries.
    static QStringList systemForwarders();
    // Why an out-of-zone query would go unanswered, for the query path's
    // once-only warning. One function so the two callers that report this
    // cannot disagree about a host file that was never an address.
    static QString noForwarderReason(const QStringList &configured,
                                     const QString &zone,
                                     const HostForwarders &host);
    // The filter on its own: `nameservers` minus loopback and this machine's
    // own addresses. Static so a test can pin it without this host's
    // /etc/resolv.conf becoming a fixture.
    static QStringList usableForwarders(const QStringList &nameservers,
                                        const QStringList &localAddresses);
    // Whether any entry of `specs` parses as address[:port]. A list that
    // filters down to something real but unparseable is not a working
    // configuration, and reporting it as one is how a reload line came to
    // promise forwarding the next query answered SERVFAIL for.
    static bool anyForwarderUsable(const QStringList &specs);
    // The `nameserver` entries of one resolv.conf-style file, in order.
    static QStringList nameserversIn(const QString &path);
    void clearCache();
    int cachedResponseCount() const;

    // Every record of the forward zone, opened and closed by its SOA, in the
    // form an AXFR reply carries. The reverse zone lives in the same store, so
    // names outside `zone()` are filtered out rather than transferred.
    QList<Record> zoneContents() const;
    // The same, for the zone a transfer asked about: this server holds the
    // reverse zone beside the forward one, and a client that asks for it must be
    // handed that zone's SOA and names rather than the forward zone's.
    QList<Record> zoneContentsFor(const QString &zone) const;
    // Answers one AXFR/IXFR request: the whole zone to a peer that proves it
    // holds the configured TSIG key, over TCP; a refusal otherwise. A zone too
    // large for one message is sent as several messages (RFC 5936 §2.2), each
    // signed over the one before it: every message but the last goes to
    // `tcpClient` here, and the last is returned for the caller to write.
    QByteArray handleTransferRequest(const QByteArray &packet, const Message &message, bool udp,
                                     QTcpSocket *tcpClient);

    // The serial in the zone's own SOA, and that SOA carrying `serial`: what an
    // IXFR reply opens with, marks each delta with, and closes with.
    quint32 zoneSerial() const;
    QList<Record> soaAtSerial(quint32 serial) const;

    // Zone persistence. `saveZone` writes the zone as JSON, `loadZone` reads
    // it back and restores the zone name and SOA serial.
    bool saveZone(const QString &path, QString *error = nullptr) const;
    bool loadZone(const QString &path, QString *error = nullptr);

    // Builds a DNS message for tests and tools: a single-question query.
    static QByteArray buildQuery(const QString &name, quint16 type, quint16 id = 0x1234);

signals:
    void queryReceived(const QString &name, quint16 type);
    void updateApplied(const QString &name, quint16 type, bool added);
    // Emitted once, when an out-of-zone query could not be sent because no
    // usable forwarder was configured or discovered. The query is answered
    // SERVFAIL either way; this is what makes a DC that has become its host's
    // only resolver say so instead of looking like a resolver that refuses.
    void forwardingUnavailable(const QString &detail);

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
    // Returns the rcode; fills `answers` for standard queries.
    int handleQuery(const Message &message, QList<Record> &answers);
    int handleUpdate(const Message &message);
    // `udp` says the reply will be sent in one datagram, so it must fit what the
    // client said it can receive; a TCP reply has no such limit.
    // `includeQuestion` is false for the second and later messages of a zone
    // transfer: the question section belongs to the first message only, and
    // repeating it makes a client read the stream as a new exchange.
    QByteArray buildResponse(const QByteArray &query, const QList<Record> &answers, int rcode,
                             const QList<Record> &authority = {}, bool udp = false,
                             bool includeQuestion = true) const;

    // 0 when the request's TSIG verifies, otherwise the rcode to answer with.
    // A verified request leaves its MAC in `requestMac`; `error` is the TSIG
    // error field the reply must carry, `other` its other-data.
    int verifyTsig(const QByteArray &packet, QByteArray *requestMac, quint16 *error,
                         QByteArray *other, bool *signRefusal) const;
    // `timeSigned` and `fudge` of 0 mean this server's clock now and 300.
    // `continuedMessage` marks the second and later messages of a transfer,
    // whose MAC covers the prior MAC and this message's timers but not the TSIG
    // variables block (RFC 8945 §5.3.1). `macOut` receives the MAC the message
    // carried, which is what the next message in the stream signs over.
    QByteArray signTsigResponse(const QByteArray &response, const QByteArray &requestMac,
                                quint16 error, const QByteArray &other,
                                quint64 timeSigned = 0, quint16 fudge = 0,
                                bool continuedMessage = false,
                                QByteArray *macOut = nullptr) const;

    // One change the zone went through, kept so a client that lags behind is
    // handed the records that came and went instead of the whole zone
    // (RFC 1995 §4). Bounded and oldest first, and written into the zone file
    // with the records, so a restart keeps the differences a client may still
    // need; a serial it no longer holds gets the whole zone, which is the
    // fallback the RFC asks for rather than an error.
    struct ZoneDelta {
        quint32 from = 0;
        quint32 to = 0;
        QList<Record> removed;
        QList<Record> added;
    };
    // The difference from `clientSerial` to the current version, or empty when
    // this server cannot build one (unknown serial, or a gap in the chain).
    QList<Record> incrementalResponse(quint32 clientSerial) const;
    void recordDelta(quint32 from, const QList<Record> &before, const QList<Record> &after);

    // One NOTIFY message (RFC 1996 §4): QR clear, opcode NOTIFY, AA set, the
    // zone as a single SOA question and the SOA being announced as its one
    // answer — signed as a request when a key is configured.
    QByteArray buildNotify(quint16 id) const;
    void notifySecondaries();

    void bumpSerial();
    void bumpReverseSerial();
    // The zone a name belongs to: the reverse zone when this DC is authoritative
    // for it, otherwise the forward zone, or empty when the name is neither.
    QString zoneFor(const QString &name) const;
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
    QString m_reverseZone;                  // derived in-addr.arpa zone, if any
    QString m_tsigName;                     // configured update key, if any
    QStringList m_transferZones;            // zones that key may transfer, if narrowed
    QString m_tsigAlgorithm;
    QByteArray m_tsigSecret;
    QList<ZoneDelta> m_journal;
    QStringList m_notifyTargets;
    quint16 m_nextNotifyId = 1;
    QHash<quint16, PendingQuery> m_pending;
    QHash<QString, CacheEntry> m_cache;
    QStringList m_forwarders;
    QString m_zone;
    quint32 m_serial = 1;
    quint16 m_nextUpstreamId = 1;
    quint16 m_forwarderIndex = 0;
    bool m_updatesEnabled = true;
    bool m_forwarding = false;
    bool m_reportedNoForwarder = false;
};

#endif // DNSSERVER_H
