// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DCSERVICE_H
#define DCSERVICE_H

#include "Drs.h"

#include <QByteArray>
#include <QObject>
#include <QStringList>

class LdapServer;
class DnsServer;
class Kdc;
class KpasswdServer;
class SamrServer;
class LsadServer;
class NetlogonServer;
class SrvsvcServer;
class BrowserServer;
class DrsServer;
class EpmServer;
class Smb2Server;
class ReplicationAgent;
class QTimer;
class QSettings;

// The domain controller as a standalone unit: loads the provisioned domain's
// dc.conf, owns every service endpoint (LDAP, KDC, DNS, SAMR, LSAD, Netlogon,
// srvsvc, DRSUAPI, EPM, SMB2) and their wiring, and reports what happened to clients
// of the directory. The headless daemon is its only permanent host — exactly
// as LSASS hosts the directory on a Windows DC — so the directory lives as
// long as the service does, not as long as a console window is open; the
// management console is purely a client, like dsa.msc.
class DcService : public QObject
{
    Q_OBJECT

public:
    // The service refuses to start without a provisioned domain: it never
    // serves a demo store.
    explicit DcService(QObject *parent = nullptr);

    // dcDir names the provisioned domain directory (dc.conf next to it).
    // Empty means the platform application-data directory, the same location
    // the provisioner writes to by default.
    bool start(const QString &dcDir = QString());

    // Persist the store and the DNS zone; the console calls this on close and
    // the daemon on shutdown. A write at the time it happens is already on
    // disk, so this is the last flush for uncommitted session edits.
    void stop();

    // The `forwarders=` list from a parsed dc.conf, in every shape the key is
    // written in: the provisioner's quoted string list, the bare `a, b` the
    // installer writes (and a hand edit following the error message asks for),
    // and a space-separated list. QSettings reads a value containing a comma as
    // a QStringList and toString() on that is the empty string, so the bare
    // forms used to read as "no forwarders" and silently fall back to the
    // host's nameservers. Static so a test can pin that without a live daemon.
    static QStringList forwardersFrom(const QSettings &config);
    // Re-read forwarders= and forwarding= from dc.conf and apply them to the
    // running DNS server. The daemon calls this on SIGHUP (`systemctl reload`):
    // the forwarder list is otherwise fixed at start-up, and an operator who
    // edits dc.conf should not have to restart the whole DC — LDAP, the KDC and
    // every open SMB session — to change which upstream the zone forwards to.
    // When dc.conf names no forwarders the list is whichever nameservers the
    // host has now, resolved per query, and the message says which of the two
    // is in effect.
    void reloadForwarders();

    // Naming context of the provisioned domain.
    QString baseDn() const { return m_baseDn; }

    // The DNS zone the engine serves, empty when there is none.
    QString dnsZone() const;

signals:
    void statusMessage(const QString &message);

private:
    // The pull runs on a cadence, not a fixed tick: a link carrying
    // DRS_PER_SYNC is pulled only inside the slots its REPLTIMES schedule sets,
    // everything else keeps replicaIntervalSeconds. Both re-arm the single-shot
    // timer after each cycle and after a link is added, changed or retired.
    void runReplicaCycle();
    void armReplicaTimer();
    // One place reports which upstreams are in effect, at start-up and on
    // reload, so the line an operator reads is the same in both cases.
    void reportForwarders();
    // Says who a moved serial is announced to, so a dnsNotify= line that does
    // nothing is visible at startup rather than as a secondary that stays stale.
    void reportSecondaries();
    // A replication link lives in the directory, the way AD keeps its topology:
    // DsReplicaAdd writes a connection object under this DC's NTDS Settings and
    // DsReplicaDel removes it, so a partner an administrator registered is still
    // there after a restart instead of living only in the running process.
    bool storeReplicaLink(const ReplicaSource &link);
    void removeReplicaLink(const QString &address);
    void loadReplicaLinks();
    // A destination that replicates from this DC is kept the way AD keeps it,
    // as the repsTo attribute of this DSA, so a partner that announced itself
    // with DsReplicaUpdateRefs is still a destination after a restart.
    bool storeReplicaDestination(const ReplicaDestination &destination);
    void loadReplicaDestinations();
    // The KCC pass: every DSA another DC published in this site is a source this
    // one can reach, so the connections its intrasite topology needs are added
    // here instead of waiting for an administrator to call DsReplicaAdd on each
    // DC in turn. Run at start-up and before each pull, because a partner the
    // configuration NC only just learned of should become a source in that same
    // cycle.
    void synchronizeTopology();
    // The trust clock: a trust password older than 30 days is replaced, the
    // inter-realm keys re-derived and the account beside the trust dated, which
    // is what the next rotation is measured from (MS-ADTS 6.1.6.2). Swept at
    // start-up and hourly, because the interval is measured in days.
    void rotateTrustPasswords();
    // This DSA's own NTDS Settings object: the one under this DC's Server
    // object, so a partner's DSA replicated into the store is never mistaken
    // for it.
    QString ownNtdsSettingsDn() const;
    // The NTDS Settings object of this DSA: the parent a connection object is
    // written under, found in the store rather than spelled out from dc.conf.
    QString ntdsSettingsDn() const;

    LdapServer *m_ldapServer = nullptr;
    DnsServer *m_dnsServer = nullptr;
    Kdc *m_kdc = nullptr;
    KpasswdServer *m_kpasswdServer = nullptr;
    SamrServer *m_samrServer = nullptr;
    LsadServer *m_lsadServer = nullptr;
    NetlogonServer *m_netlogonServer = nullptr;
    SrvsvcServer *m_srvsvcServer = nullptr;
    BrowserServer *m_browserServer = nullptr;
    DrsServer *m_drsServer = nullptr;
    EpmServer *m_epmServer = nullptr;
    Smb2Server *m_smbServer = nullptr;
    ReplicationAgent *m_replicationAgent = nullptr;
    QTimer *m_replicaTimer = nullptr;
    QTimer *m_trustTimer = nullptr;
    int m_replicaIntervalSeconds = 300;
    QByteArray m_replicaSchedule;
    quint32 m_replicaFlags = 0;

    bool m_started = false;
    // Store and zone locations resolved from dc.conf at start-up.
    QString m_dcDir;
    QString m_storePath;
    // True while loadReplicaDestinations() replays what the store holds: the
    // write-back handler must not treat that as a fresh registration.
    bool m_loadingReplicaDestinations = false;
    QString m_zonePath;
    QString m_baseDn;
    // This DC's own host name, as dc.conf names it: the Server object it
    // publishes, and the one the KCC must not link to itself.
    QString m_dcHost;
};

#endif // DCSERVICE_H
