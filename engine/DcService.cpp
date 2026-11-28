// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DcService.h"

#include "DnsServer.h"
#include "Drs.h"
#include "Gss.h"
#include "Epm.h"
#include "Kdc.h"
#include "Kpasswd.h"
#include "LdapServer.h"
#include "Lsad.h"
#include "Netlogon.h"
#include "Srvsvc.h"
#include "Browser.h"
#include "Rpc.h"
#include "Ntlm.h"
#include "Pac.h"
#include "Samr.h"
#include "Smb2.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>

#include <QTimer>

#include "ReplicaTopology.h"
#include "ReplicationAgent.h"
#include "TrustPassword.h"
#include "resultsmodel.h"

DcService::DcService(QObject *parent)
    : QObject(parent)
{
}

// One pull, then the next cycle is armed from whatever the link asks for. The
// timer is single-shot precisely because that delay is a function of the clock
// and the schedule, not a fixed interval.
void DcService::runReplicaCycle()
{
    // The KCC looks at the site before the pull: a partner the last cycle's
    // configuration NC made known here becomes a source now, not at the next
    // start of the daemon.
    synchronizeTopology();
    if (!m_replicationAgent || m_replicationAgent->source().isEmpty())
        return;
    QString error;
    if (m_replicationAgent->pullOnce(&error) < 0) {
        emit statusMessage(tr("Replication pull from %1 failed: %2")
                               .arg(m_replicationAgent->source(), error));
    }
    armReplicaTimer();
}

// This DSA's own vertex in the configuration NC and the links kept under it.
QString DcService::ntdsSettingsDn() const
{
    return m_ldapServer ? ReplicaTopology::ntdsSettingsDn(m_ldapServer->objects()) : QString();
}

QString DcService::ownNtdsSettingsDn() const
{
    if (!m_ldapServer)
        return QString();
    const QString server = QStringLiteral("CN=%1,CN=Servers,")
                               .arg(m_dcHost.section(QLatin1Char('.'), 0, 0).toUpper());
    for (const DirectoryObject &object : m_ldapServer->objects()) {
        if (object.id.startsWith(QStringLiteral("CN=NTDS Settings,"), Qt::CaseInsensitive)
            && object.id.contains(server, Qt::CaseInsensitive)) {
            return object.id;
        }
    }
    // A store provisioned before the Server object carried the DC's name still
    // has exactly one DSA, which is this one.
    return ntdsSettingsDn();
}

void DcService::synchronizeTopology()
{
    if (!m_ldapServer || !m_drsServer)
        return;
    const QString selfDn = ownNtdsSettingsDn();
    if (selfDn.isEmpty())
        return;
    const QList<ReplicaSource> created = ReplicaTopology::synchronize(m_ldapServer, selfDn);
    if (created.isEmpty())
        return;
    if (!m_storePath.isEmpty())
        m_ldapServer->saveToFile(m_storePath);
    for (const ReplicaSource &link : created) {
        emit statusMessage(tr("The KCC added a connection from %1 in this site.")
                               .arg(link.address));
        // Registering it is what makes it pulled from; the connection object is
        // already in the store, and the agent's handler records it again as a
        // no-op.
        m_drsServer->addReplicaSource(link);
    }
}

bool DcService::storeReplicaLink(const ReplicaSource &link)
{
    if (!m_ldapServer)
        return false;
    QString error;
    if (!ReplicaTopology::store(m_ldapServer, link, &error)) {
        emit statusMessage(
            tr("The replication link to %1 is not kept across a restart: %2.")
                .arg(link.address, error));
        return false;
    }
    if (!m_storePath.isEmpty())
        m_ldapServer->saveToFile(m_storePath);
    emit statusMessage(tr("Replication link to %1 kept as %2 in the directory.")
                           .arg(link.address, ReplicaTopology::linkDn(ntdsSettingsDn(), link.address)));
    return true;
}

void DcService::removeReplicaLink(const QString &address)
{
    if (!m_ldapServer)
        return;
    QString error;
    if (!ReplicaTopology::remove(m_ldapServer, address, &error)) {
        emit statusMessage(
            tr("The replication link to %1 was retired but its connection object stayed: %2.")
                .arg(address, error));
        return;
    }
    if (!m_storePath.isEmpty())
        m_ldapServer->saveToFile(m_storePath);
    emit statusMessage(tr("Replication link to %1 retired from the directory.").arg(address));
}

// The trust clock: every 30 days the DC that holds the PDC emulator role gives
// an interdomain trust a new password (MS-ADTS 6.1.6.2) and stores it as the
// trust's secret, which is what the channel a peer opens authenticates with
// (Netlogon reads trustAuthIncoming). The account beside the trust carries the
// same password, so its pwdLastSet is the instant the next rotation is measured
// from — set here every time, because that is the write which dates it.
void DcService::rotateTrustPasswords()
{
    if (!m_ldapServer)
        return;
    const QList<DirectoryObject> objects = m_ldapServer->objects();
    const QList<TrustPassword::Rotation> due =
        TrustPassword::due(objects, QDateTime::currentSecsSinceEpoch());
    if (due.isEmpty())
        return;
    const QString realm = m_ldapServer->identity().realm;
    bool changed = false;
    for (const TrustPassword::Rotation &rotation : due) {
        DirectoryObject trust;
        for (const DirectoryObject &object : objects) {
            if (object.id.compare(rotation.trustDn, Qt::CaseInsensitive) == 0) {
                trust = object;
                break;
            }
        }
        if (trust.id.isEmpty())
            continue;
        const QString password = TrustPassword::generate();
        // The secret and the inter-realm keys derived from it are attributes the
        // server makes, not ones a client may write: the LDAP modify path
        // refuses them whatever rights the caller holds.
        QString error;
        if (!m_ldapServer->setDerivedAttributes(
                rotation.trustDn,
                TrustPassword::rotationAttributes(trust, realm, password), &error)) {
            emit statusMessage(tr("The trust password for %1 could not be written: %2")
                                   .arg(rotation.flatName, error));
            continue;
        }
        // The secret is on the trust object now; the account beside it is dated
        // by the same password, because a write to it is what moves pwdLastSet.
        if (!m_ldapServer->setNtHash(rotation.accountDn, Ntlm::ntowfV1(password),
                                     &error)) {
            emit statusMessage(tr("The trust password for %1 was changed, but its "
                                  "account was not dated: %2")
                                   .arg(rotation.flatName, error));
            continue;
        }
        changed = true;
        emit statusMessage(tr("Changed the trust password for %1 after %2 days.")
                               .arg(rotation.flatName)
                               .arg(rotation.ageSeconds / (24 * 60 * 60)));
    }
    if (changed && !m_storePath.isEmpty())
        m_ldapServer->saveToFile(m_storePath);
}

void DcService::loadReplicaLinks()
{
    if (!m_ldapServer || !m_drsServer)
        return;

    // A connection object in AD names the source DSA and applies to every naming
    // context that DSA holds, so one link becomes one source per naming context
    // this DC replicates — the same list the agent was given above.
    QStringList namingContexts{m_baseDn};
    for (const DirectoryObject &object : m_ldapServer->objects()) {
        if (!object.id.isEmpty())
            continue;
        for (const QString &key : {QStringLiteral("configurationNamingContext"),
                                   QStringLiteral("schemaNamingContext")}) {
            const QString root = object.attributes.value(key);
            if (!root.isEmpty() && !namingContexts.contains(root, Qt::CaseInsensitive))
                namingContexts.append(root);
        }
    }

    const QList<ReplicaSource> restored =
        ReplicaTopology::links(m_ldapServer->objects(), namingContexts);
    for (const ReplicaSource &link : restored)
        m_drsServer->addReplicaSource(link);
    if (!restored.isEmpty()) {
        emit statusMessage(tr("Restored %1 replication link%2 from the directory.")
                               .arg(restored.size())
                               .arg(restored.size() == 1 ? QString() : QStringLiteral("s")));
    }
}

void DcService::armReplicaTimer()
{
    if (!m_replicaTimer || !m_replicationAgent) {
        if (m_replicaTimer)
            m_replicaTimer->stop();
        return;
    }
    if (m_replicationAgent->source().isEmpty()) {
        m_replicaTimer->stop();
        return;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const qint64 delay = ReplicationAgent::nextCycleDelayMs(
        m_replicaSchedule, m_replicaFlags, m_replicaIntervalSeconds, now);
    if (delay < 0) {
        // A schedule with no bit set names no window at all; sleeping forever
        // would hide that, so the pull parks until the link is edited.
        emit statusMessage(
            tr("The replication schedule for %1 allows no interval; the pull stays "
               "idle until the schedule changes.")
                .arg(m_replicationAgent->source()));
        m_replicaTimer->stop();
        return;
    }
    // Re-check at least once a day, so a clock change or a schedule this process
    // did not see cannot park a pull for a week.
    m_replicaTimer->start(
        int(qBound<qint64>(qint64(1000), delay, qint64(24) * 3600 * 1000)));
}

QString DcService::dnsZone() const
{
    return m_dnsServer ? m_dnsServer->zone() : QString();
}

QStringList DcService::forwardersFrom(const QSettings &config)
{
    // toStringList() is a one-element list for a plain QString and the stored
    // list for the comma form, so this one call covers every shape; each entry
    // is then split on the separators a handwritten value may still carry.
    const QStringList entries = config.value(QStringLiteral("forwarders")).toStringList();
    QStringList forwarders;
    for (const QString &entry : entries)
        forwarders += entry.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    return forwarders;
}

void DcService::reportForwarders()
{
    if (!m_dnsServer)
        return;
    if (!m_dnsServer->forwardingEnabled()) {
        emit statusMessage(tr("DNS forwarding is off, so names outside %1 are answered REFUSED.")
                               .arg(m_dnsServer->zone()));
        return;
    }
    const QStringList effective = m_dnsServer->effectiveForwarders();
    // Which list is in effect matters: a recorded key keeps working when the
    // host has nothing left to read, and a host list changes under the process.
    // Saying "to 192.168.1.1" without saying where it came from is what made a
    // correct log line look like proof the configuration was doing the work.
    const QString source = m_dnsServer->forwarders().isEmpty()
                               ? tr("this host's nameservers")
                               : tr("dc.conf");
    const QStringList ignored = m_dnsServer->ignoredForwarders();
    const QString confPath = m_dcDir + QStringLiteral("/dc.conf");
    if (effective.isEmpty()) {
        // Naming the entry is the whole point: "are loopback" about a list the
        // operator typed by hand reads as if the file were wrong somewhere else.
        if (!ignored.isEmpty()) {
            emit statusMessage(tr("No usable DNS forwarder in %1: %2 is this DC's own "
                                  "listener, so names outside %3 will not resolve. Set "
                                  "forwarders= in %4.")
                                   .arg(source)
                                   .arg(ignored.join(QStringLiteral(", ")))
                                   .arg(m_dnsServer->zone())
                                   .arg(confPath));
            return;
        }
        // Nothing was configured here, so the answer is in the host's files and
        // it is one of three different things. "Loopback or this DC itself" is
        // true for one of them; said about a `nameserver 192.0.2.1#53` line it
        // tells an operator to look for a loopback that is not there, and the
        // file that actually needs the edit is named nowhere.
        const DnsServer::HostForwarders host = DnsServer::hostForwarders();
        const QString where = host.files.isEmpty()
            ? QStringLiteral("/etc/resolv.conf")
            : host.files.join(QStringLiteral(", "));
        if (host.read.isEmpty())
            emit statusMessage(tr("No usable DNS forwarder: this host has no nameserver "
                                  "line in %1, so names outside %2 will not resolve. Set "
                                  "forwarders= in %3.")
                                   .arg(where)
                                   .arg(m_dnsServer->zone())
                                   .arg(confPath));
        else if (!host.unparseable.isEmpty())
            emit statusMessage(tr("No usable DNS forwarder: %1 in this host's nameservers "
                                  "could not be parsed as an address, so names outside "
                                  "%2 will not resolve. Set forwarders= in %3.")
                                   .arg(host.unparseable.join(QStringLiteral(", ")))
                                   .arg(m_dnsServer->zone())
                                   .arg(confPath));
        else
            emit statusMessage(tr("No usable DNS forwarder: this host's nameservers (%1) "
                                  "are loopback or this DC itself, so names outside %2 "
                                  "will not resolve. Set forwarders= in %3.")
                                   .arg(host.loopbackOrSelf.join(QStringLiteral(", ")))
                                   .arg(m_dnsServer->zone())
                                   .arg(confPath));
        return;
    }
    // A recorded list that survives the loopback filter but parses as nothing
    // is not a working configuration: the first out-of-zone query after this
    // line would be answered SERVFAIL. Report the same reason the query path
    // will, rather than a status line that reads like forwarding is set up.
    if (!DnsServer::anyForwarderUsable(effective)) {
        emit statusMessage(tr("No usable DNS forwarder in %1: no forwarder could be parsed "
                              "from %2, so names outside %3 will not resolve. Set "
                              "forwarders= in %4.")
                               .arg(source)
                               .arg(effective.join(QStringLiteral(", ")))
                               .arg(m_dnsServer->zone())
                               .arg(confPath));
        return;
    }
    QString line = tr("Forwarding names outside %1 to %2 (from %3).")
                       .arg(m_dnsServer->zone())
                       .arg(effective.join(QStringLiteral(", ")))
                       .arg(source);
    // Saying which entry is not in use, rather than only which are, is the
    // difference between an operator seeing an upstream list they typed and
    // understanding why one of them never answers.
    if (!ignored.isEmpty()) {
        line += QLatin1Char(' ')
                + tr("Ignoring %1, which is this DC's own listener.")
                      .arg(ignored.join(QStringLiteral(", ")));
    }
    emit statusMessage(line);
}

void DcService::reportSecondaries()
{
    if (!m_dnsServer)
        return;
    const QStringList targets = m_dnsServer->notifyTargets();
    if (targets.isEmpty())
        return;
    emit statusMessage(tr("Announcing %1 to %2 whenever its serial moves.")
                           .arg(m_dnsServer->zone())
                           .arg(targets.join(QStringLiteral(", "))));
}

namespace {

// A TSIG key in dc.conf makes dynamic updates require a signature over that key
// (RFC 8945). Called on start and on SIGHUP, so a key added or rotated in the
// file takes effect without a restart; an empty name clears it, which is how a
// DC goes back to unauthenticated updates.
void applyDnsUpdateKey(DnsServer *server, const QSettings &config)
{
    server->setUpdateTsig(config.value(QStringLiteral("dnsTsigName")).toString(),
                          config.value(QStringLiteral("dnsTsigAlgorithm"),
                                       QStringLiteral("hmac-sha256")).toString(),
                          config.value(QStringLiteral("dnsTsigSecret")).toString().toLatin1());
}

// The secondaries to announce a moved serial to (RFC 1996), read the way the
// forwarders are: a stored list, or one value with commas or spaces in it. An
// empty list announces nothing, which is the default and stays the default until
// an operator names a secondary in dc.conf.
QStringList transferZonesFrom(const QSettings &config)
{
    // `dnsTransferZones` narrows the configured key to the zones it may transfer;
    // unset means the key keeps the reach it had, so no existing deployment
    // changes behaviour by upgrading.
    const QStringList entries = config.value(QStringLiteral("dnsTransferZones")).toStringList();
    QStringList zones;
    for (const QString &entry : entries) {
        const QStringList parts =
            entry.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
        for (const QString &part : parts) {
            QString zone = part.trimmed().toLower();
            while (zone.endsWith(QLatin1Char('.')))
                zone.chop(1);
            if (!zone.isEmpty())
                zones.append(zone);
        }
    }
    return zones;
}

// The master a copy is pulled from and the zones copied from it. `dnsMaster` is
// one "address" or "address:port"; `dnsMasterZones` lists the zones, either as
// a stored list or one value with commas or spaces. Both are needed: a master
// with no zones copies nothing, and zones with no master have nowhere to ask.
void applyDnsMaster(DnsServer *server, const QSettings &config)
{
    QStringList masters;
    for (const QString &entry : config.value(QStringLiteral("dnsMaster")).toStringList())
        masters += entry.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    QStringList zones;
    for (const QString &entry : config.value(QStringLiteral("dnsMasterZones")).toStringList())
        zones += entry.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    server->setMaster(masters.value(0), zones);
}

QStringList notifyTargetsFrom(const QSettings &config)
{
    const QStringList entries = config.value(QStringLiteral("dnsNotify")).toStringList();
    QStringList targets;
    for (const QString &entry : entries)
        targets += entry.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    return targets;
}

} // namespace

void DcService::reloadForwarders()
{
    if (!m_dnsServer)
        return;
    const QString path = m_dcDir + QStringLiteral("/dc.conf");
    const QSettings dcConfig(path, QSettings::IniFormat);
    m_dnsServer->setForwarders(forwardersFrom(dcConfig));
    m_dnsServer->setForwardingEnabled(dcConfig.value(QStringLiteral("forwarding"), true).toBool());
    applyDnsUpdateKey(m_dnsServer, dcConfig);
    m_dnsServer->setNotifyTargets(notifyTargetsFrom(dcConfig));
    m_dnsServer->setTransferZones(transferZonesFrom(dcConfig));
    applyDnsMaster(m_dnsServer, dcConfig);
    emit statusMessage(tr("Re-read the DNS forwarder configuration from %1 on SIGHUP.").arg(path));
    reportForwarders();
    reportSecondaries();
}

void DcService::stop()
{
    if (!m_started)
        return;
    // A stopped daemon sweeps nothing: the trust clock starts again with the
    // next start, and a rotation it missed is due then.
    if (m_trustTimer)
        m_trustTimer->stop();
    // Persist to the configured location, which is private/ for a
    // provisioned domain, so edits survive a restart of that domain.
    if (m_ldapServer && m_ldapServer->isListening()) {
        const QString storePath = m_storePath.isEmpty()
            ? QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/directory.json")
            : m_storePath;
        QDir().mkpath(QFileInfo(storePath).absolutePath());
        m_ldapServer->saveToFile(storePath);
    }
    if (m_dnsServer && m_dnsServer->isListening() && !m_zonePath.isEmpty()) {
        QDir().mkpath(QFileInfo(m_zonePath).absolutePath());
        m_dnsServer->saveZone(m_zonePath);
    }
}

bool DcService::start(const QString &dcDir)
{
    const QString resolvedDcDir =
        dcDir.isEmpty() ? QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) : dcDir;
    QDir().mkpath(resolvedDcDir);
    m_dcDir = resolvedDcDir;

    // `monarchy-provision` writes its store and `dc.conf` here; without a
    // provisioned domain the service either falls back to the sample
    // directory (console) or refuses to serve one (daemon).
    m_ldapServer = new LdapServer(this);
    // A client write is committed before it is answered, as a DC persists what
    // it accepted: a backup tool that copies the store while this process runs
    // then captures the change instead of yesterday's state.
    m_ldapServer->setPersistHook([this]() {
        if (!m_storePath.isEmpty())
            m_ldapServer->saveToFile(m_storePath);
    });
    const QSettings dcConfig(resolvedDcDir + QStringLiteral("/dc.conf"), QSettings::IniFormat);
    // AD's LmCompatibilityLevel decides whether an NTLMv1 challenge response is
    // answered at all: 0-4 accept it — the levels below 4 only decide what a
    // client sends — and 5 refuses LM and NTLM. The default is 3, a domain
    // controller's documented default, which accepts it.
    const int lmCompatibilityLevel =
        dcConfig.value(QStringLiteral("lmCompatibilityLevel"),
                       Ntlm::kDefaultLmCompatibilityLevel).toInt();
    m_ldapServer->setLmCompatibilityLevel(lmCompatibilityLevel);
    // AD's RestrictAnonymous. Its default is the version's: 0 on Windows 2000,
    // where an unbound search is answered with what Anonymous Logon may read,
    // and 1 from Server 2003, where only the root DSE answers. This DC emulates
    // the 2000 default; the stricter rule stays available for a store that wants
    // credentials before any read.
    m_ldapServer->setRestrictAnonymous(
        dcConfig.value(QStringLiteral("restrictAnonymous"), 0).toInt());
    m_storePath = dcConfig.value(QStringLiteral("storePath"),
                                 resolvedDcDir + QStringLiteral("/directory.json")).toString();
    m_baseDn = dcConfig.value(QStringLiteral("baseDn"),
                              QStringLiteral("DC=corp,DC=example,DC=com")).toString();
    const QString dnsDomain = dcConfig.value(QStringLiteral("dnsDomain"),
                                             QStringLiteral("MONARCHY.EXAMPLE.COM")).toString();
    const int ldapPort = dcConfig.value(QStringLiteral("ldapPort"), 1389).toInt();

    const QString dcHost = dcConfig.value(QStringLiteral("dcHost"),
                                          QStringLiteral("dc1.") + dnsDomain).toString();
    m_dcHost = dcHost;
    const QString dcIp = dcConfig.value(QStringLiteral("dcIp"),
                                        QStringLiteral("127.0.0.1")).toString();
    // A development DC keeps its RPC endpoints — SAMR, LSAD, Netlogon, DRSR and
    // the endpoint mapper — on loopback, because any account that authenticates
    // can administer this directory and there is no per-account RPC
    // authorization yet (STATUS.md section 4). rpcAddress is how an operator
    // takes that on: 0.0.0.0, or this host's address, is what a domain join from
    // another machine needs. Before this key existed the endpoints could not
    // leave loopback at all, so the trade could not even be made deliberately.
    QHostAddress rpcAddress = QHostAddress::LocalHost;
    const QString rpcAddressText =
        dcConfig.value(QStringLiteral("rpcAddress"), QString()).toString().trimmed();
    if (!rpcAddressText.isEmpty() && !rpcAddress.setAddress(rpcAddressText)) {
        emit statusMessage(
            tr("rpcAddress %1 is not an address; RPC endpoints stay on loopback.")
                .arg(rpcAddressText));
        rpcAddress = QHostAddress::LocalHost;
    }
    const QString rpcLabel = rpcAddress.toString();
    // The address the endpoint mapper's towers name has to be one a client can
    // reach: a loopback-only DC says 127.0.0.1, and a DC that serves its network
    // names the address it publishes for itself. It named 127.0.0.1 either way.
    QHostAddress advertisedAddress = QHostAddress::LocalHost;
    if (!rpcAddress.isLoopback() && !advertisedAddress.setAddress(dcIp)) {
        emit statusMessage(tr("dcIp %1 is not an address; the endpoint mapper keeps naming "
                              "127.0.0.1.")
                               .arg(dcIp));
        advertisedAddress = QHostAddress::LocalHost;
    }
    const QString siteName = dcConfig.value(QStringLiteral("siteName"),
                                            QStringLiteral("Default-First-Site-Name")).toString();
    m_zonePath = dcConfig.value(QStringLiteral("zonePath"),
                                resolvedDcDir + QStringLiteral("/private/dnszone.json")).toString();
    if (!m_ldapServer->loadFromFile(m_storePath)) {
        emit statusMessage(tr("No provisioned domain under %1; refusing to serve a demo store.")
                               .arg(resolvedDcDir));
        return false;
    }
    m_ldapServer->loadSecretsFromFile(
        dcConfig.value(QStringLiteral("secretsPath"),
                       resolvedDcDir + QStringLiteral("/private/secrets.json")).toString());

    // TLS for StartTLS: the certificate the provisioner created for this DC. A
    // domain provisioned without one still serves plaintext LDAP and refuses the
    // StartTLS request, which is what the client is told.
    const QString tlsCertPath = dcConfig.value(QStringLiteral("tlsCertPath")).toString();
    const QString tlsKeyPath = dcConfig.value(QStringLiteral("tlsKeyPath")).toString();
    if (!tlsCertPath.isEmpty() && !tlsKeyPath.isEmpty()) {
        QString tlsError;
        if (!m_ldapServer->loadTlsCredentials(tlsCertPath, tlsKeyPath, &tlsError))
            emit statusMessage(tr("StartTLS unavailable: %1").arg(tlsError));
    }

    // Kerberos: the KDC signs against the same store, so a password set in the
    // console works for kinit, NTLM and simple bind at once.
    m_kdc = new Kdc(this);
    KerberosRealmConfig krbRealm;
    krbRealm.realm = dcConfig.value(QStringLiteral("realm"), dnsDomain.toUpper()).toString();
    krbRealm.netbios = dcConfig.value(QStringLiteral("netbiosDomain"), QString()).toString();
    krbRealm.domainSid = dcConfig.value(QStringLiteral("domainSid"), QString()).toString();
    krbRealm.dcHost = dcHost;
    m_kdc->setRealm(krbRealm);
    m_kdc->setObjectProvider([this]() { return m_ldapServer->objects(); });
    m_ldapServer->setKdc(m_kdc);

    // The DSA's published identity, taken from the same config that named the
    // realm: the root DSE answers with this instead of leaving a client to
    // guess which directory agent it reached.
    LdapServer::Identity identity;
    identity.realm = krbRealm.realm;
    identity.netbios = krbRealm.netbios;
    identity.dnsDomain = dnsDomain;
    identity.dcHost = dcHost;
    identity.siteName = siteName;
    m_ldapServer->setIdentity(identity);
    const int kdcPort = dcConfig.value(QStringLiteral("kdcPort"), 8888).toInt();
    // The port the socket actually bound, or 0 when it did not. What the zone
    // advertises is derived from these, never from the configuration alone: a
    // listener that failed would otherwise publish a locator nothing answers.
    quint16 boundKdcPort = 0;
    if (!m_kdc->listen(quint16(kdcPort))) {
        emit statusMessage(tr("Kerberos KDC failed to listen on port %1.").arg(kdcPort));
    } else {
        boundKdcPort = m_kdc->serverPort();
        emit statusMessage(tr("Kerberos realm %1 served on port %2.")
                               .arg(m_kdc->realm().realm)
                               .arg(boundKdcPort));
    }

    // Serve the store over LDAP.
    if (!m_ldapServer->listen(quint16(ldapPort))) {
        emit statusMessage(tr("LDAP server failed to listen on %1.").arg(ldapPort));
    } else {
        emit statusMessage(tr("Monarchy DC listening on port %1.").arg(m_ldapServer->serverPort()));
    }
    if (!m_ldapServer->isListening()) {
        // The directory is the one thing a DC cannot do without.
        return false;
    }
    const quint16 boundLdapPort = m_ldapServer->serverPort();

    // Global Catalog: the same store on 3268, which is what the `_gc._tcp`
    // locator record has always pointed at. The root DSE reports
    // isGlobalCatalogReady from whether this listener actually came up, so a
    // port that is taken is visible to the client instead of assumed away.
    const int gcPort = dcConfig.value(QStringLiteral("gcPort"), 3268).toInt();
    quint16 boundGcPort = 0;
    if (!m_ldapServer->listenGc(quint16(gcPort))) {
        emit statusMessage(tr("Global Catalog failed to listen on port %1.").arg(gcPort));
    } else {
        boundGcPort = m_ldapServer->gcServerPort();
        emit statusMessage(tr("Global Catalog served on port %1.").arg(boundGcPort));
    }

    // A domain provisioned before kpasswd existed has no kadmin/changepw
    // principal, and the KDC could not issue the ticket the service verifies.
    // Creating it here is what promotion does on Windows, and it is idempotent:
    // a domain that already has the principal is left untouched.
    {
        bool haveKpasswdPrincipal = false;
        for (const DirectoryObject &object : m_ldapServer->objects()) {
            for (const QString &spn : Krb5::servicePrincipalNames(object)) {
                if (spn.compare(QLatin1String("kadmin/changepw"), Qt::CaseInsensitive) == 0)
                    haveKpasswdPrincipal = true;
            }
        }
        if (!haveKpasswdPrincipal && !m_baseDn.isEmpty()) {
            DirectoryObject principal;
            principal.id = QStringLiteral("CN=kadmin,CN=Users,%1").arg(m_baseDn);
            principal.name = QStringLiteral("kadmin");
            principal.type = QStringLiteral("User");
            principal.kind = ObjectKind::User;
            principal.container = QStringLiteral("Users");
            principal.attributes.insert(QStringLiteral("cn"), QStringLiteral("kadmin"));
            principal.attributes.insert(QStringLiteral("sAMAccountName"),
                                        QStringLiteral("kadmin"));
            principal.attributes.insert(QStringLiteral("userAccountControl"),
                                        QStringLiteral("512"));
            principal.attributes.insert(QStringLiteral("servicePrincipalName"),
                                        QStringLiteral("kadmin/changepw"));
            principal.attributes.insert(QStringLiteral("showInAdvancedViewOnly"),
                                        QStringLiteral("TRUE"));
            principal.attributes.insert(
                QStringLiteral("objectClass"),
                QStringLiteral("top;person;organizationalPerson;user"));
            Krb5::storeRandomKeys(principal);
            principal.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"),
                                        QStringLiteral("1"));
            QString error;
            if (!m_ldapServer->addAccount(&principal, &error)) {
                emit statusMessage(
                    tr("Could not add the kpasswd service principal: %1").arg(error));
            } else {
                if (!m_storePath.isEmpty())
                    m_ldapServer->saveToFile(m_storePath);
                emit statusMessage(tr("Added the kadmin/changepw service principal."));
            }
        }
    }

    // Windows registers a DC's service principal names in both the short and the
    // domain-qualified shape: `ldap/<dc fqdn>` and `ldap/<dc fqdn>/<domain>`. A
    // member asks the KDC for the qualified one when it needs a ticket for LDAP
    // in a named domain, and a KDC that answers S_PRINCIPAL_UNKNOWN to it leaves
    // the client without a DC. A domain provisioned before this existed carries
    // only the short form, so the qualified one is added here, once.
    {
        const QString account =
            dcHost.section(QLatin1Char('.'), 0, 0).toUpper() + QLatin1Char('$');
        const QString qualified =
            QStringLiteral("ldap/%1/%2").arg(dcHost.toLower(), dnsDomain.toLower());
        for (const DirectoryObject &object : m_ldapServer->objects()) {
            if (object.attributes.value(QStringLiteral("sAMAccountName"))
                    .compare(account, Qt::CaseInsensitive) != 0)
                continue;
            QStringList spns = Krb5::servicePrincipalNames(object);
            bool haveQualified = false;
            for (const QString &spn : spns) {
                if (spn.compare(qualified, Qt::CaseInsensitive) == 0)
                    haveQualified = true;
            }
            if (haveQualified)
                continue;
            spns.append(qualified);
            QMap<QString, QString> attributes;
            attributes.insert(QStringLiteral("servicePrincipalName"),
                              joinAttributeValues(spns));
            if (!m_ldapServer->modifyObject(object.id, attributes)) {
                emit statusMessage(
                    tr("Could not add the %1 service principal.").arg(qualified));
            } else {
                if (!m_storePath.isEmpty())
                    m_ldapServer->saveToFile(m_storePath);
                emit statusMessage(tr("Added the %1 service principal.").arg(qualified));
            }
        }
    }

    // Kerberos change password (RFC 3244) on 464, the port the zone's
    // `_kpasswd` locator records name. The password is written through the same
    // path an LDAP or SAMR change takes, so the new password works for
    // Kerberos, NTLM and simple bind at once.
    m_kpasswdServer = new KpasswdServer(this);
    m_kpasswdServer->setKdc(m_kdc);
    m_kpasswdServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    m_kpasswdServer->setPasswordWriter([this](const QString &dn, const QString &password,
                                              QString *error) {
        LdapServer::ModifyChange change;
        change.operation = 2; // replace
        change.type = QStringLiteral("unicodePwd");
        change.values = QStringList{password};
        const int result = m_ldapServer->applyModify(dn, {change});
        if (result != 0 && error)
            *error = result == 19
                         ? QStringLiteral("rejected by the domain password policy")
                         : QStringLiteral("account not found (%1)").arg(result);
        if (result == 0 && !m_storePath.isEmpty())
            m_ldapServer->saveToFile(m_storePath);
        return result == 0;
    });
    connect(m_kpasswdServer, &KpasswdServer::requestReceived, this,
            &DcService::statusMessage);
    const int kpasswdPort = dcConfig.value(QStringLiteral("kpasswdPort"), 464).toInt();
    quint16 boundKpasswdPort = 0;
    if (!m_kpasswdServer->listen(quint16(kpasswdPort))) {
        emit statusMessage(tr("kpasswd failed to listen on port %1.").arg(kpasswdPort));
    } else {
        boundKpasswdPort = m_kpasswdServer->serverPort();
        emit statusMessage(
            tr("Kerberos password change served on port %1.").arg(boundKpasswdPort));
    }

    // Remote management: the SAMR interface over DCE/RPC, backed by the same
    // store this process serves over LDAP, so an account created through either
    // protocol is immediately visible to the other. Loopback only: the endpoint
    // has no RPC authentication yet.
    m_samrServer = new SamrServer(this);
    Samr::Config samrConfig;
    samrConfig.realm = krbRealm.realm;
    samrConfig.netbios = krbRealm.netbios;
    samrConfig.domainSid = krbRealm.domainSid;
    samrConfig.baseDn = m_baseDn;
    m_samrServer->setConfig(samrConfig);
    m_samrServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    m_samrServer->setDomainNames(samrConfig.netbios, dcHost.section(QLatin1Char('.'), 0, 0).toUpper(),
                                 dnsDomain);
    // Writes from SAMR land in the store this process serves over LDAP, so an
    // account created by a Windows tool is visible to a directory search.
    // A DC persists what a client changes, so a restart does not undo it.
    const auto persist = [this]() {
        if (!m_storePath.isEmpty())
            m_ldapServer->saveToFile(m_storePath);
    };
    Samr::WriteBackend writes;
    writes.create = [this, persist](DirectoryObject *object, QString *error) {
        const bool ok = m_ldapServer->addAccount(object, error);
        if (ok)
            persist();
        return ok;
    };
    writes.set = [this, persist](const QString &dn, const QString &attribute,
                                 const QString &value, QString *error) {
        Q_UNUSED(error)
        const bool ok = m_ldapServer->modifyObject(dn, {{attribute, value}});
        if (ok)
            persist();
        return ok;
    };
    // A password set over SAMR goes through the same password path an LDAP
    // write does, so the NTLM hash, the Kerberos keys and the simple-bind
    // verifier all move together: the new password works for all three at once.
    writes.setPassword = [this, persist](const QString &dn, const QString &password,
                                         QString *error) {
        LdapServer::ModifyChange change;
        change.operation = 2; // replace
        change.type = QStringLiteral("unicodePwd");
        change.values = QStringList{password};
        const int result = m_ldapServer->applyModify(dn, {change});
        if (result != 0 && error)
            *error = result == 19
                         ? QStringLiteral("rejected by the domain password policy")
                         : QStringLiteral("account not found (%1)").arg(result);
        if (result == 0)
            persist();
        return result == 0;
    };
    // A hash set is the credential of record, so the store drops whatever the
    // previous password left behind: NTLM and RC4 Kerberos then follow the hash.
    writes.setNtHash = [this, persist](const QString &dn, const QByteArray &ntHash,
                                       QString *error) {
        const bool ok = m_ldapServer->setNtHash(dn, ntHash, error);
        if (ok)
            persist();
        return ok;
    };
    writes.remove = [this, persist](const QString &dn, QString *error) {
        Q_UNUSED(error)
        const bool ok = m_ldapServer->removeObject(dn);
        if (ok)
            persist();
        return ok;
    };
    writes.addMember = [this, persist](const QString &groupDn, const QString &memberDn,
                                       QString *error) {
        LdapServer::ModifyChange change;
        change.operation = 0; // add
        change.type = QStringLiteral("member");
        change.values = QStringList{memberDn};
        const int result = m_ldapServer->applyModify(groupDn, {change});
        if (result != 0 && error)
            *error = QStringLiteral("add member failed (%1)").arg(result);
        if (result == 0)
            persist();
        return result == 0;
    };
    writes.removeMember = [this, persist](const QString &groupDn, const QString &memberDn,
                                          QString *error) {
        LdapServer::ModifyChange change;
        change.operation = 1; // delete
        change.type = QStringLiteral("member");
        change.values = QStringList{memberDn};
        const int result = m_ldapServer->applyModify(groupDn, {change});
        if (result != 0 && error)
            *error = QStringLiteral("remove member failed (%1)").arg(result);
        if (result == 0)
            persist();
        return result == 0;
    };
    m_samrServer->setWriteBackend(writes);
    // NTLMSSP over RPC: the challenge is answered from the stored NT hash, the
    // same credential simple and SASL binds use.
    // One authenticator serves both management endpoints, so an account that can
    // open SAMR can open the LSA policy too, with the same credential.
    const Rpc::Authenticator authenticator =
        [this, lmCompatibilityLevel](const Rpc::AuthRequest &request, Ntlm::SessionKeys *keys) {
            for (const DirectoryObject &object : m_ldapServer->objects()) {
                const QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.compare(request.user, Qt::CaseInsensitive) != 0 || object.id.isEmpty())
                    continue;
                const QByteArray ntHash = QByteArray::fromHex(
                    object.attributes.value(QStringLiteral("ntHash")).toLatin1());
                if (ntHash.size() != 16)
                    return false;
                return Ntlm::verifyResponse(ntHash, request.user, request.domain,
                                            request.challenge, request.ntResponse,
                                            request.lmResponse, request.flags,
                                            lmCompatibilityLevel, keys);
            }
            return false;
        };
    m_samrServer->setAuthenticator(authenticator);
    // Kerberos over RPC: the bind carries an AP-REQ that the KDC accepts, and
    // the per-call tokens are sealed under the acceptor subkey it hands back.
    m_samrServer->setKerberosAcceptor(
        [this](const QByteArray &apReq, Rpc::KerberosContext *context, QString *error) {
            Kdc::ApResult result;
            if (!m_kdc->acceptDceApReq(apReq, &result, error))
                return false;
            context->user = result.clientPrincipal;
            context->key = result.contextKey;
            context->etype = result.contextEtype;
            context->ticketKey = result.sessionKey;
            context->ticketEtype = result.contextEtype;
            context->replyToken = result.replyToken;
            context->recvSeq = result.recvSeq;
            context->sendSeq = result.sendSeq;
            return true;
        },
        [this](const QByteArray &token, const Rpc::KerberosContext &context, QString *error) {
            return m_kdc->finishDceApReq(token, context.key, context.etype, context.ticketKey,
                                         context.ticketEtype, context.sendSeq, error);
        });
    const int samrPort = dcConfig.value(QStringLiteral("samrPort"), 1035).toInt();
    if (!m_samrServer->listen(quint16(samrPort), rpcAddress)) {
        emit statusMessage(tr("SAMR endpoint failed to listen on port %1.").arg(samrPort));
    } else {
        emit statusMessage(tr("SAMR served on %1:%2.")
                               .arg(rpcLabel)
                               .arg(m_samrServer->serverPort()));
    }

    // LSAD on its own endpoint: the domain identity a client reads before it
    // joins, browses or administers anything. Same security provider as SAMR, so
    // one directory credential opens both.
    m_lsadServer = new LsadServer(this);
    m_lsadServer->setAuthenticator(authenticator);
    m_lsadServer->setDomainNames(krbRealm.netbios,
                                 dcHost.section(QLatin1Char('.'), 0, 0).toUpper(),
                                 dnsDomain, krbRealm.domainSid);
    // The realm is what a trust password derives its inter-realm keys from, so
    // LSAD has to know it as well as the KDC does.
    m_lsadServer->setRealm(krbRealm.realm);
    m_lsadServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    // Account rights are an attribute of the account, so a right granted over
    // lsarpc is the same object data LDAP serves and survives a restart.
    Lsad::WriteBackend lsadWrites;
    lsadWrites.setRights = [this, persist](const QString &dn, const QStringList &rights,
                                           QString *error) {
        const bool ok = m_ldapServer->modifyObject(
            dn, {{QStringLiteral("userRight"), joinAttributeValues(rights)}});
        if (!ok && error)
            *error = QStringLiteral("account not found (%1)").arg(dn);
        if (ok)
            persist();
        return ok;
    };
    // Trusts live under CN=System as trustedDomain objects, so an LDAP search
    // finds the same partner and direction the trust calls report, and the
    // object is written to the same persisted store as everything else.
    lsadWrites.createTrust = [this, persist](DirectoryObject *object, QString *error) {
        if (!object || object->id.isEmpty()) {
            if (error)
                *error = QStringLiteral("trust object has no distinguished name");
            return false;
        }
        m_ldapServer->addObject(*object);
        persist();
        return true;
    };
    // A trust secret comes with the inter-realm keys derived from it, and those
    // are server-derived attributes the LDAP modify path refuses — so this is
    // the store write from the call that owns them, not a client's modify.
    lsadWrites.updateTrust = [this, persist](const QString &dn,
                                              const QMap<QString, QString> &attributes,
                                              QString *error) {
        const bool ok = m_ldapServer->setDerivedAttributes(dn, attributes, error);
        if (!ok && error)
            *error = QStringLiteral("trust not found (%1)").arg(dn);
        if (ok)
            persist();
        return ok;
    };
    lsadWrites.createTrustAccount = [this, persist](DirectoryObject *object, QString *error) {
        if (!m_ldapServer->addAccount(object, error))
            return false;
        persist();
        return true;
    };
    lsadWrites.removeTrust = [this, persist](const QString &dn, QString *error) {
        if (!m_ldapServer->removeObject(dn)) {
            if (error)
                *error = QStringLiteral("trust not found (%1)").arg(dn);
            return false;
        }
        persist();
        return true;
    };
    m_lsadServer->setWriteBackend(lsadWrites);
    const int lsadPort = dcConfig.value(QStringLiteral("lsadPort"), 1036).toInt();
    if (!m_lsadServer->listen(quint16(lsadPort), rpcAddress)) {
        emit statusMessage(tr("LSAD endpoint failed to listen on port %1.").arg(lsadPort));
    } else {
        emit statusMessage(tr("LSAD served on %1:%2.")
                               .arg(rpcLabel)
                               .arg(m_lsadServer->serverPort()));
    }

    // Netlogon: the secure channel a joined machine opens to prove its machine
    // account and to have the DC validate a user's logon. It reads and writes
    // the same store as SAMR and LSAD, so a machine password set over
    // NetrServerPasswordSet2 is the credential the next channel authenticates
    // with, and a user validated here is the account LDAP serves.
    m_netlogonServer = new NetlogonServer(this);
    Netlogon::Config netlogonConfig;
    netlogonConfig.realm = krbRealm.realm;
    netlogonConfig.netbios = krbRealm.netbios;
    netlogonConfig.domainSid = krbRealm.domainSid;
    netlogonConfig.baseDn = m_baseDn;
    netlogonConfig.dnsDomain = dnsDomain;
    netlogonConfig.dcName = dcHost.section(QLatin1Char('.'), 0, 0).toUpper();
    netlogonConfig.dcHost = dcHost;
    netlogonConfig.dcIp = dcIp;
    netlogonConfig.siteName = siteName;
    m_netlogonServer->setConfig(netlogonConfig);
    m_netlogonServer->setLmCompatibilityLevel(lmCompatibilityLevel);
    m_netlogonServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    Netlogon::WriteBackend netlogonWrites;
    netlogonWrites.setNtHash = [this, persist](const QString &dn, const QByteArray &ntHash,
                                               QString *error) {
        const bool ok = m_ldapServer->setNtHash(dn, ntHash, error);
        if (ok)
            persist();
        return ok;
    };
    // A validated logon is recorded on the account, so the directory shows the
    // same lastLogon, lastLogonTimestamp and logonCount a Windows DC would.
    netlogonWrites.updateAccount = [this, persist](const QString &dn,
                                                    const QMap<QString, QString> &attributes,
                                                    QString *error) {
        const bool ok = m_ldapServer->modifyObject(dn, attributes);
        if (!ok && error)
            *error = QStringLiteral("account not found (%1)").arg(dn);
        if (ok)
            persist();
        return ok;
    };
    // The trust-password write lands on the trusted domain object, and the
    // inter-realm keys are re-derived with it, so the KDC and the channel keep
    // one secret.
    netlogonWrites.updateTrust = [this, persist](const QString &dn,
                                                 const QMap<QString, QString> &attributes,
                                                 QString *error) {
        const bool ok = m_ldapServer->setDerivedAttributes(dn, attributes, error);
        if (!ok && error)
            *error = QStringLiteral("trust not found (%1)").arg(dn);
        if (ok)
            persist();
        return ok;
    };
    m_netlogonServer->setWriteBackend(netlogonWrites);
    connect(m_netlogonServer, &NetlogonServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int netlogonPort = dcConfig.value(QStringLiteral("netlogonPort"), 1037).toInt();
    if (!m_netlogonServer->listen(quint16(netlogonPort), rpcAddress)) {
        emit statusMessage(tr("Netlogon endpoint failed to listen on port %1.")
                               .arg(netlogonPort));
    } else {
        emit statusMessage(tr("Netlogon served on %1:%2.")
                               .arg(rpcLabel)
                               .arg(m_netlogonServer->serverPort()));
    }

    // Replication (MS-DRSR): what a partner — or a DCSync-style tool — calls
    // to pull the directory. The same store, the same configuration and the
    // same authenticator SAMR and LSAD answer behind; TCP only, because
    // Windows exposes no drsuapi pipe.
    m_drsServer = new DrsServer(this);
    Samr::Config drsConfig;
    drsConfig.realm = krbRealm.realm;
    drsConfig.netbios = krbRealm.netbios;
    drsConfig.domainSid = krbRealm.domainSid;
    drsConfig.baseDn = m_baseDn;
    m_drsServer->setConfig(drsConfig);
    m_drsServer->setDomainNames(drsConfig.netbios,
                                dcHost.section(QLatin1Char('.'), 0, 0).toUpper(),
                                dnsDomain);
    // Tombstones are part of what a replication partner has to see: the live
    // store alone would leave a deleted object alive on the other side.
    m_drsServer->setObjectProvider([this]() {
        return m_ldapServer->objects() + m_ldapServer->tombstones();
    });
    m_drsServer->setAuthenticator(authenticator);
    connect(m_drsServer, &DrsServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int drsPort = dcConfig.value(QStringLiteral("drsPort"), 1038).toInt();
    if (!m_drsServer->listen(quint16(drsPort), rpcAddress)) {
        emit statusMessage(tr("DRSR endpoint failed to listen on port %1.")
                               .arg(drsPort));
    } else {
        emit statusMessage(tr("DRSR served on %1:%2.")
                               .arg(rpcLabel)
                               .arg(m_drsServer->serverPort()));
    }

    // Share enumeration (srvsvc): what a client lists when it asks which
    // shares this server offers, over \pipe\srvsvc or the TCP endpoint. The
    // shares are the same ones SMB2 serves, so they are filled in once the
    // SYSVOL tree's paths are resolved below.
    m_srvsvcServer = new SrvsvcServer(this);
    m_srvsvcServer->setAuthenticator(authenticator);
    connect(m_srvsvcServer, &SrvsvcServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int srvsvcPort = dcConfig.value(QStringLiteral("srvsvcPort"), 1039).toInt();
    if (!m_srvsvcServer->listen(quint16(srvsvcPort), rpcAddress)) {
        emit statusMessage(tr("srvsvc endpoint failed to listen on port %1.")
                               .arg(srvsvcPort));
    } else {
        emit statusMessage(tr("srvsvc served on %1:%2.")
                               .arg(rpcLabel)
                               .arg(m_srvsvcServer->serverPort()));
    }

    // The browser endpoint (\piperowser) a 2000 member's logon enumerates
    // through. It has no TCP listener: the pipe is the only transport Windows
    // uses for it, and the pipe is what the logon opens.
    m_browserServer = new BrowserServer(this);
    m_browserServer->setAuthenticator(authenticator);
    connect(m_browserServer, &BrowserServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });

    // Pull replication: when dc.conf names a partner, this DC takes changes from
    // it on its own schedule instead of waiting for an administrator to ask. The
    // cursor lives in the agent, so each pull asks only for what is new, and a
    // pull that fails part-way is retried from where it stopped.
    m_replicationAgent = new ReplicationAgent(this);
    // The replica password belongs beside this domain's other secrets, not in
    // dc.conf: the provisioner writes private/secrets.json readable only by its
    // owner, while dc.conf is ordinary configuration. An inline value is still
    // honoured so an existing domain keeps working, but it is reported.
    const QString replicaSecretsPath =
        dcConfig.value(QStringLiteral("secretsPath"),
                       resolvedDcDir + QStringLiteral("/private/secrets.json"))
            .toString();
    const auto replicaPasswordFromSecrets = [](const QString &path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
            return QString();
        return QJsonDocument::fromJson(file.readAll())
            .object()
            .value(QStringLiteral("replicaPassword"))
            .toString();
    };
    QString replicaPassword = replicaPasswordFromSecrets(replicaSecretsPath);
    if (replicaPassword.isEmpty()) {
        replicaPassword = dcConfig.value(QStringLiteral("replicaPassword")).toString();
        if (!replicaPassword.isEmpty()) {
            emit statusMessage(
                tr("Replica credentials are being read from dc.conf; move replicaPassword "
                   "into %1, which is readable only by its owner.")
                    .arg(replicaSecretsPath));
        }
    }
    m_replicationAgent->setCredentials(
        dcConfig.value(QStringLiteral("replicaDomain"), krbRealm.netbios).toString(),
        dcConfig.value(QStringLiteral("replicaUser")).toString(), replicaPassword);
    // A DC holds three naming contexts and replicates all of them: its own
    // domain, and the forest's configuration and schema partitions. The roots
    // are in the store's root DSE attributes, so the list follows the tree
    // rather than being spelled out here.
    {
        QStringList namingContexts;
        const QString configured = dcConfig.value(QStringLiteral("replicaNamingContext")).toString();
        namingContexts.append(configured.isEmpty() ? m_baseDn : configured);
        for (const DirectoryObject &object : m_ldapServer->objects()) {
            if (!object.id.isEmpty())
                continue;
            for (const QString &key : {QStringLiteral("configurationNamingContext"),
                                       QStringLiteral("schemaNamingContext")}) {
                const QString root = object.attributes.value(key);
                if (!root.isEmpty() && !namingContexts.contains(root, Qt::CaseInsensitive))
                    namingContexts.append(root);
            }
        }
        m_replicationAgent->setNamingContexts(namingContexts);
    }
    m_replicationAgent->setSink([this](const QList<DirectoryObject> &objects) {
        return m_ldapServer->applyReplication(objects);
    });
    connect(m_replicationAgent, &ReplicationAgent::pulled, this,
            [this](const QString &summary) { emit statusMessage(summary); });

    m_replicaIntervalSeconds =
        qMax(1, dcConfig.value(QStringLiteral("replicaIntervalSeconds"), 300).toInt());
    m_replicaTimer = new QTimer(this);
    m_replicaTimer->setSingleShot(true);
    connect(m_replicaTimer, &QTimer::timeout, this, &DcService::runReplicaCycle);

    const auto parseAddress = [](const QString &address, QString *host, quint16 *port) {
        ReplicaTopology::splitAddress(address, host, port);
    };

    connect(m_drsServer, &DrsServer::replicaSourceAdded, this,
            [this, parseAddress](const QString &address, const QString &) {
                QString host;
                quint16 port = 0;
                parseAddress(address, &host, &port);
                m_replicationAgent->setSource(host, port);
                // One copy for both reads: replicaSources() hands back a list by
                // value, so a reference taken from a temporary would dangle.
                const QList<ReplicaSource> links = m_drsServer->replicaSources();
                // The link just registered carries the cadence it asked for.
                if (!links.isEmpty()) {
                    m_replicaSchedule = links.last().schedule;
                    m_replicaFlags = links.last().options;
                }
                armReplicaTimer();
                // The link goes into the directory as a connection object, so the
                // next start of this daemon pulls from the partner again without
                // anyone re-registering it.
                if (!links.isEmpty())
                    storeReplicaLink(links.last());
                emit statusMessage(tr("Replication source %1 registered.").arg(address));
            });

    // DsReplicaMod edits a link in place. Only a change to the address the agent
    // is actually pulling from retargets it; editing another link leaves the
    // running pull alone.
    connect(m_drsServer, &DrsServer::replicaSourceModified, this,
            [this, parseAddress](const QString &previous, const QString &address,
                                 const QString &) {
                QString previousHost;
                quint16 previousPort = 0;
                parseAddress(previous, &previousHost, &previousPort);
                if (!m_replicationAgent->source().startsWith(previousHost, Qt::CaseInsensitive))
                    return;
                QString host;
                quint16 port = 0;
                parseAddress(address, &host, &port);
                m_replicationAgent->setSource(host, port);
                // A schedule edit arrives on the same signal, so the retargeted
                // pull reads the link's current cadence rather than the old one.
                m_replicaSchedule.clear();
                m_replicaFlags = 0;
                for (const ReplicaSource &link : m_drsServer->replicaSources()) {
                    if (link.address.compare(address, Qt::CaseInsensitive) == 0) {
                        m_replicaSchedule = link.schedule;
                        m_replicaFlags = link.options;
                        break;
                    }
                }
                armReplicaTimer();
                emit statusMessage(tr("Replication source %1 changed to %2.")
                                       .arg(previous, address));
            });

    // A source retired with DsReplicaDel stops being pulled from; the agent
    // keeps its cursor, so re-adding the same partner resumes where it left off.
    connect(m_drsServer, &DrsServer::replicaSourceRemoved, this,
            [this, parseAddress](const QString &address, const QString &) {
                // Retiring a link retires its connection object too, whether or
                // not it is the one currently being pulled from.
                removeReplicaLink(address);
                QString host;
                quint16 port = 0;
                parseAddress(address, &host, &port);
                if (!m_replicationAgent->source().startsWith(host, Qt::CaseInsensitive))
                    return;
                m_replicationAgent->setSource(QString(), 0);
                m_replicaSchedule.clear();
                m_replicaFlags = 0;
                armReplicaTimer();
                emit statusMessage(tr("Replication source %1 retired.").arg(address));
            });

    const QString replicaHost = dcConfig.value(QStringLiteral("replicaHost")).toString();
    if (!replicaHost.isEmpty()) {
        m_replicationAgent->setSource(
            replicaHost, quint16(dcConfig.value(QStringLiteral("replicaPort"), 0).toInt()));
        // dc.conf names no link, so no schedule governs this pull: it keeps the
        // configured interval.
        m_replicaSchedule.clear();
        m_replicaFlags = 0;
        armReplicaTimer();
        emit statusMessage(tr("Pulling replication from %1 every %2s.")
                               .arg(m_replicationAgent->source())
                               .arg(m_replicaIntervalSeconds));
    }

    // Topology first, then the links: a partner another DC published in this
    // site is a source even when nobody registered it at this DC.
    synchronizeTopology();

    // A trust's password has its own clock, so it is swept at start-up and then
    // hourly: a trust that reaches 30 days is rotated within the hour instead of
    // waiting for the next restart.
    rotateTrustPasswords();
    if (!m_trustTimer) {
        m_trustTimer = new QTimer(this);
        connect(m_trustTimer, &QTimer::timeout, this, &DcService::rotateTrustPasswords);
    }
    m_trustTimer->start(60 * 60 * 1000);

    // Links an administrator registered earlier are connection objects in the
    // directory, so they are read back here and pulled from again instead of
    // being forgotten with the process that registered them.
    loadReplicaLinks();

    // When neither dc.conf nor the store names a partner, the agent stays idle
    // (empty source) and no timer is armed. Report that so the administrator can
    // tell the difference between "no partner yet" and "a partner was removed"
    // — and so a restored link is not announced next to a line saying there is
    // none.
    if (m_replicationAgent->source().isEmpty()) {
        emit statusMessage(
            tr("No replication partner configured; add one with DsReplicaAdd or set "
               "replicaHost in dc.conf."));
    }

    // The endpoint mapper: the answer a client gets when it knows an interface
    // UUID and a protocol but not the port (ncacn_epm, port 135 by default).
    // Every entry here is a port an endpoint above actually bound, so a lookup
    // never advertises something that refuses the connection.
    m_epmServer = new EpmServer(this);
    m_epmServer->setHostName(dcHost.section(QLatin1Char('.'), 0, 0));
    m_epmServer->setAdvertisedAddress(advertisedAddress);
    {
        QList<Epm::Entry> entries;
        const Rpc::Interface lsad = Lsad::interface();
        Epm::Entry lsadEntry;
        lsadEntry.uuid = lsad.uuid;
        lsadEntry.major = lsad.major;
        lsadEntry.minor = lsad.minor;
        lsadEntry.port = m_lsadServer->serverPort();
        lsadEntry.annotation = QStringLiteral("lsarpc");
        entries.append(lsadEntry);
        // The same endpoint reached the way Windows addresses it: through the
        // named pipe SMB2 now serves.
        Epm::Entry lsadPipe = lsadEntry;
        lsadPipe.port = 0;
        lsadPipe.pipe = QStringLiteral("lsarpc");
        entries.append(lsadPipe);

        const Rpc::Interface samr = Samr::interface();
        Epm::Entry samrEntry;
        samrEntry.uuid = samr.uuid;
        samrEntry.major = samr.major;
        samrEntry.minor = samr.minor;
        samrEntry.port = m_samrServer->serverPort();
        samrEntry.annotation = QStringLiteral("samr");
        entries.append(samrEntry);
        Epm::Entry samrPipe = samrEntry;
        samrPipe.port = 0;
        samrPipe.pipe = QStringLiteral("samr");
        entries.append(samrPipe);

        // Netlogon, like the others, is advertised both ways: the TCP endpoint
        // and the named pipe a Windows member addresses it through.
        const Rpc::Interface netlogon = Netlogon::interface();
        Epm::Entry netlogonEntry;
        netlogonEntry.uuid = netlogon.uuid;
        netlogonEntry.major = netlogon.major;
        netlogonEntry.minor = netlogon.minor;
        netlogonEntry.port = m_netlogonServer->serverPort();
        netlogonEntry.annotation = QStringLiteral("netlogon");
        entries.append(netlogonEntry);
        Epm::Entry netlogonPipe = netlogonEntry;
        netlogonPipe.port = 0;
        netlogonPipe.pipe = QStringLiteral("netlogon");
        entries.append(netlogonPipe);

        // srvsvc: the share list, advertised on the TCP endpoint and on the
        // pipe a Windows client opens as \pipe\srvsvc.
        const Rpc::Interface srvsvc = Srvsvc::interface();
        Epm::Entry srvsvcEntry;
        srvsvcEntry.uuid = srvsvc.uuid;
        srvsvcEntry.major = srvsvc.major;
        srvsvcEntry.minor = srvsvc.minor;
        srvsvcEntry.port = m_srvsvcServer->serverPort();
        srvsvcEntry.annotation = QStringLiteral("srvsvc");
        entries.append(srvsvcEntry);
        Epm::Entry srvsvcPipe = srvsvcEntry;
        srvsvcPipe.port = 0;
        srvsvcPipe.pipe = QStringLiteral("srvsvc");
        entries.append(srvsvcPipe);

        // The browser service is reachable only on its pipe, as on Windows: a
        // client asks for it by name, never for a port.
        const Rpc::Interface browser = Browser::interface();
        Epm::Entry browserPipe;
        browserPipe.uuid = browser.uuid;
        browserPipe.major = browser.major;
        browserPipe.minor = browser.minor;
        browserPipe.pipe = QStringLiteral("browser");
        entries.append(browserPipe);

        // DRSUAPI, where a replication partner asks which port to pull
        // changes on. Advertised as TCP only: there is no drsuapi pipe.
        if (m_drsServer->isListening()) {
            const Rpc::Interface drs = Drs::interface();
            Epm::Entry drsEntry;
            drsEntry.uuid = drs.uuid;
            drsEntry.major = drs.major;
            drsEntry.minor = drs.minor;
            drsEntry.port = m_drsServer->serverPort();
            drsEntry.annotation = QStringLiteral("drsuapi");
            entries.append(drsEntry);
        }

        const Rpc::Interface epm = Epm::interface();
        Epm::Entry epmEntry;
        epmEntry.uuid = epm.uuid;
        epmEntry.major = epm.major;
        epmEntry.minor = epm.minor;
        epmEntry.port = 135;
        epmEntry.annotation = QStringLiteral("epmapper");
        entries.append(epmEntry);
        Epm::Entry epmPipe = epmEntry;
        epmPipe.port = 0;
        epmPipe.pipe = QStringLiteral("epmapper");
        entries.append(epmPipe);

        m_epmServer->setEntries(entries);
    }
    const int epmPort = dcConfig.value(QStringLiteral("epmPort"), 135).toInt();
    if (!m_epmServer->listen(quint16(epmPort), rpcAddress)) {
        emit statusMessage(
            tr("Endpoint mapper failed to listen on port %1 (port 135 needs root).")
                .arg(epmPort));
    } else {
        // The advertised port is the one that actually bound, and the entry for
        // the mapper itself is corrected to it, so a lookup never names a port
        // the server is not on.
        QList<Epm::Entry> entries = m_epmServer->entries();
        for (Epm::Entry &entry : entries) {
            if (entry.uuid == Epm::interface().uuid)
                entry.port = m_epmServer->serverPort();
        }
        m_epmServer->setEntries(entries);
        emit statusMessage(tr("Endpoint mapper served on %1:%2, advertising %3.")
                               .arg(rpcLabel)
                               .arg(m_epmServer->serverPort())
                               .arg(advertisedAddress.toString()));
    }

    // SMB2 and the named pipes the management interfaces are addressed by on a
    // Windows network: \\dc\pipe\samr and \\dc\pipe\lsarpc carry the same
    // DCE/RPC the TCP endpoints do, into the same handlers, behind the same
    // authenticator.
    m_smbServer = new Smb2Server(this);
    m_smbServer->setAuthenticator(authenticator);
    // A refused SMB1 logon names the rule that refused it, so the level the
    // domain is running at is on the line rather than inferred from it.
    m_smbServer->setLmCompatibilityLevel(lmCompatibilityLevel);
    // Kerberos session setup is plain GSS-API, not DCE/RPC: the AP-REP is sealed
    // under the service ticket's session key instead of the initiator's subkey,
    // so this is the acceptor the LDAP SASL bind uses, not the RPC one.
    m_smbServer->setKerberosAcceptor(
        [this](const QByteArray &apReq, Rpc::KerberosContext *context, QString *error) {
            Kdc::ApResult result;
            if (!m_kdc->acceptApReq(apReq, &result, error))
                return false;
            context->user = result.clientPrincipal;
            context->key = result.contextKey;
            context->etype = result.contextEtype;
            context->replyToken = result.replyToken;
            return true;
        });
    m_smbServer->setDomainNames(krbRealm.netbios,
                                dcHost.section(QLatin1Char('.'), 0, 0).toUpper(), dnsDomain);
    m_smbServer->addPipe(QStringLiteral("samr"), m_samrServer->rpc());
    m_smbServer->addPipe(QStringLiteral("lsarpc"), m_lsadServer->rpc());
    m_smbServer->addPipe(QStringLiteral("epmapper"), m_epmServer->rpc());
    m_smbServer->addPipe(QStringLiteral("netlogon"), m_netlogonServer->rpc());
    m_smbServer->addPipe(QStringLiteral("srvsvc"), m_srvsvcServer->rpc());
    // A Windows 2000 member's logon enumerates the domain through this pipe,
    // and an open that fails stops the logon before any Netlogon call.
    m_smbServer->addPipe(QStringLiteral("browser"), m_browserServer->rpc());
    // `net group /domain` finishes on the downlevel RAP list rather than the
    // SAMR one, so the same groups answer both.
    m_smbServer->setRapGroups([this]() { return m_samrServer->globalGroupNames(); });

    // The domain's SYSVOL tree and the NETLOGON scripts it contains, served as
    // the disk shares a member reads its GPOs and logon scripts from. The
    // provisioner wrote them; a directory that predates this build is created
    // so the shares always name something that exists.
    QString domainSysvol = dcConfig.value(QStringLiteral("sysvol")).toString();
    if (domainSysvol.isEmpty())
        domainSysvol = resolvedDcDir + QStringLiteral("/sysvol/") + dnsDomain;
    QDir().mkpath(domainSysvol + QStringLiteral("/Policies"));
    QDir().mkpath(domainSysvol + QStringLiteral("/scripts"));
    // `\\dc\SYSVOL` is the directory that holds the domain's folder, exactly as
    // on Windows (%SystemRoot%\SYSVOL\sysvol), so a GPO path of
    // `\\dc\SYSVOL\<domain>\Policies\{GUID}` resolves; NETLOGON is the domain's
    // scripts directory under it.
    const QString sysvolShare = QFileInfo(domainSysvol).absolutePath();
    m_smbServer->addShare(QStringLiteral("SYSVOL"), sysvolShare, false);
    m_smbServer->addShare(QStringLiteral("NETLOGON"), domainSysvol + QStringLiteral("/scripts"),
                          false);
    // SYSVOL and NETLOGON are writable for the accounts that administer the
    // domain — a GPO is edited over SMB, and a logon script is dropped there —
    // and read-only for every other authenticated member, which is what a
    // Windows DC's ACL on the share root achieves. The groups are AD's own: 512
    // Domain Admins, 518 Schema Admins, 519 Enterprise Admins. A principal the
    // directory does not resolve is not an administrator.
    m_smbServer->setWritePolicy([this](const QString &principal) {
        QString name = principal;
        const int slash = name.indexOf(QLatin1Char('\\'));
        if (slash >= 0)
            name = name.mid(slash + 1);
        const int at = name.indexOf(QLatin1Char('@'));
        if (at > 0)
            name = name.left(at);
        if (name.isEmpty())
            return false;
        const QList<DirectoryObject> objects = m_ldapServer->objects();
        for (const DirectoryObject &object : objects) {
            if (object.kind != ObjectKind::User)
                continue;
            if (object.attributes.value(QStringLiteral("sAMAccountName"))
                    .compare(name, Qt::CaseInsensitive)
                != 0)
                continue;
            for (const QString &groupDn : object.memberOf) {
                for (const DirectoryObject &group : objects) {
                    if (group.kind != ObjectKind::Group
                        || group.id.compare(groupDn, Qt::CaseInsensitive) != 0)
                        continue;
                    const quint32 rid = Pac::ridOf(group);
                    if (rid == 512 || rid == 518 || rid == 519)
                        return true;
                }
            }
            return false;
        }
        return false;
    });
    emit statusMessage(tr("SYSVOL and NETLOGON shared from %1.").arg(sysvolShare));

    // What NetrShareEnum reports: the two shares above, plus IPC$, which is not
    // a file share but is what every Windows server lists. Level 2 answers
    // carry the local path SMB2 serves the share from.
    QList<Srvsvc::Share> shareList;
    Srvsvc::Share sysvolReported;
    sysvolReported.name = QStringLiteral("SYSVOL");
    sysvolReported.comment = QStringLiteral("Logon server share");
    sysvolReported.path = sysvolShare;
    shareList.append(sysvolReported);
    Srvsvc::Share netlogonReported;
    netlogonReported.name = QStringLiteral("NETLOGON");
    netlogonReported.comment = QStringLiteral("Logon server share");
    netlogonReported.path = domainSysvol + QStringLiteral("/scripts");
    shareList.append(netlogonReported);
    Srvsvc::Share ipcReported;
    ipcReported.name = QStringLiteral("IPC$");
    ipcReported.type = Srvsvc::kTypeIpc;
    ipcReported.comment = QStringLiteral("Remote IPC");
    shareList.append(ipcReported);
    m_srvsvcServer->setShares(shareList);

    connect(m_smbServer, &Smb2Server::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int smbPort = dcConfig.value(QStringLiteral("smbPort"), 445).toInt();
    if (!m_smbServer->listen(quint16(smbPort))) {
        emit statusMessage(
            tr("SMB2 failed to listen on port %1 (port 445 needs root).").arg(smbPort));
    } else {
        emit statusMessage(
            tr("SMB2 served on %1:%2.").arg(QHostAddress(QHostAddress::Any).toString())
                .arg(m_smbServer->serverPort()));
    }
    // Windows 2000 and other NetBIOS-first clients open their machine channel
    // and logon over TCP 139; without this they connect, get a reset from the
    // kernel, and report only "the system could not log you on".
    const int netbiosPort =
        dcConfig.value(QStringLiteral("netbiosPort"), 139).toInt();
    if (netbiosPort > 0 && netbiosPort != smbPort) {
        if (!m_smbServer->listenNetbios(quint16(netbiosPort))) {
            emit statusMessage(tr("NetBIOS session service failed to listen on port %1 "
                                  "(port 139 needs root).")
                                   .arg(netbiosPort));
        } else {
            emit statusMessage(tr("NetBIOS session service served on port %1.")
                                   .arg(netbiosPort));
        }
    }

    // The zone belongs to the domain: a provisioned DC ships one in private/,
    // and an unprovisioned console synthesises the same AD service records for
    // itself so the domain resolves consistently either way.
    m_dnsServer = new DnsServer(this);
    // GSS-TSIG: the TKEY exchange is accepted by the KDC's Kerberos acceptor,
    // the same one LDAP's SASL bind uses, so the ticket a member already holds
    // is what authorises its DNS registration. A ticket for anything but this
    // DC's DNS service is not a DNS registration right: it is refused before a
    // context exists.
    if (m_kdc) {
        m_dnsServer->setGssAcceptor(
            [this](const QByteArray &token, DnsServer::GssContext *context, QString *error) {
                Kdc::ApResult result;
                QByteArray apReq = token;
                bool spnego = false;
                const QByteArray inner = Gss::kerberosToken(token);
                if (!inner.isEmpty()) {
                    apReq = inner;
                    spnego = true;
                }
                if (!m_kdc->acceptApReq(apReq, &result, error))
                    return false;
                if (!result.servicePrincipal.startsWith(QStringLiteral("DNS/"),
                                                        Qt::CaseInsensitive)) {
                    if (error)
                        *error = QStringLiteral("the ticket is not for DNS/%1")
                                     .arg(m_dnsServer->zone());
                    return false;
                }
                context->key = result.contextKey;
                context->etype = result.contextEtype;
                context->principal = result.clientPrincipal;
                context->recvSeq = result.clientSeq;
                context->sendSeq = 0;
                // The acceptor's AP-REP is the TKEY key data. A SPNEGO client
                // reads it inside a NegTokenResp, which is the form it parsed.
                context->replyToken =
                    spnego ? Gss::spnegoResponse(1, QStringLiteral("1.2.840.113554.1.2.2"),
                                                 result.replyToken)
                           : result.replyToken;
                return true;
            });
    }
    // Out-of-zone names are resolved through the forwarders in dc.conf, or the
    // host's own nameservers when none are listed. This is what lets the DC be
    // the machine's resolver: it answers its zone authoritatively and caches
    // everything else.
    m_dnsServer->setForwarders(forwardersFrom(dcConfig));
    m_dnsServer->setForwardingEnabled(dcConfig.value(QStringLiteral("forwarding"), true).toBool());
    applyDnsUpdateKey(m_dnsServer, dcConfig);
    m_dnsServer->setNotifyTargets(notifyTargetsFrom(dcConfig));
    m_dnsServer->setTransferZones(transferZonesFrom(dcConfig));
    // A zone copied from a master is served from the copy until the pull
    // succeeds, so the pull starts with the server rather than on the first
    // announcement: after a restart the copy would otherwise be missing exactly
    // while the master is also restarting.
    applyDnsMaster(m_dnsServer, dcConfig);
    m_dnsServer->refreshSecondaryZones();
    // The GUID a member asks for under domains._msdcs is the domain NC's
    // objectGUID, which is what the locator answer states: taken from the store
    // so the zone and the answer cannot name two different domains.
    const QString domainGuid = m_ldapServer
                                   ? m_ldapServer->domainGuid().toString(QUuid::WithoutBraces)
                                   : QString();
    if (!m_dnsServer->loadZone(m_zonePath)) {
        m_dnsServer->loadAdZone(dnsDomain, dcHost, dcIp, boundLdapPort, boundGcPort, siteName,
                                boundKpasswdPort, boundKdcPort, domainGuid);
    }
    // A zone loaded from disk may predate a service this build serves — the
    // kpasswd locators, for one — or name an address this machine no longer
    // holds, so the DC holds its own zone to what it actually answers and where
    // it actually is before it serves it. The ports are the ones that bound,
    // not the ones configured: a listener that failed leaves no locator behind
    // pointing at a port nothing answers, and dcIp is the authority for the
    // address records rather than whatever the zone was written with.
    const bool addressRepaired = m_dnsServer->repairAdZoneAddresses(dcHost, dcIp);
    const bool locatorsRepaired = m_dnsServer->repairAdZoneLocators(
        dcHost, boundLdapPort, boundGcPort, siteName, boundKpasswdPort, boundKdcPort, domainGuid);
    // AD publishes a reverse zone for the DC's own address; `dig -x` against a
    // domain controller is answered from it, so this DC holds one too.
    const bool reverseRepaired = m_dnsServer->repairReverseZone(dcHost, dcIp);
    if (addressRepaired || locatorsRepaired || reverseRepaired) {
        QString zoneError;
        if (!m_zonePath.isEmpty() && !m_dnsServer->saveZone(m_zonePath, &zoneError))
            emit statusMessage(tr("Could not persist the repaired zone: %1").arg(zoneError));
        else
            emit statusMessage(tr("Repaired the domain's service locator records."));
    }
    connect(m_dnsServer, &DnsServer::forwardingUnavailable, this,
            [this](const QString &detail) {
                emit statusMessage(
                    tr("DNS forwarding unavailable, so out-of-zone names are answered "
                       "SERVFAIL: %1. Set forwarders= in dc.conf or provision with "
                       "--forwarder.")
                        .arg(detail));
            });
    if (!m_dnsServer->listen(quint16(dcConfig.value(QStringLiteral("dnsPort"), 1053).toInt()))) {
        emit statusMessage(tr("DNS server failed to bind its port."));
    } else {
        emit statusMessage(tr("Authoritative for %1 on port %2.")
                               .arg(m_dnsServer->zone())
                               .arg(m_dnsServer->serverPort()));
        // A DC pointed at itself for everything is a trap: the installer makes
        // it the host's only resolver, and from then on the host's nameservers
        // are the DC's own address — which is dropped as a loop, leaving
        // nothing to forward to. Report which upstreams are in effect so an
        // empty set is visible at startup rather than as a silent SERVFAIL.
        reportForwarders();
        reportSecondaries();
    }

    m_started = true;
    return true;
}
