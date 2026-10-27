// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DcService.h"

#include "DnsServer.h"
#include "Drs.h"
#include "Epm.h"
#include "Kdc.h"
#include "LdapServer.h"
#include "Lsad.h"
#include "Netlogon.h"
#include "Rpc.h"
#include "Ntlm.h"
#include "Samr.h"
#include "Smb2.h"
#include "../backend/SampleData.h"

#include <QDir>
#include <QFileInfo>
#include <QSettings>
#include <QStandardPaths>

DcService::DcService(bool allowSampleFallback, QObject *parent)
    : QObject(parent)
    , m_allowSampleFallback(allowSampleFallback)
{
}

QString DcService::dnsZone() const
{
    return m_dnsServer ? m_dnsServer->zone() : QString();
}

void DcService::stop()
{
    if (!m_started)
        return;
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

    // `monarchy-provision` writes its store and `dc.conf` here; without a
    // provisioned domain the service either falls back to the sample
    // directory (console) or refuses to serve one (daemon).
    m_ldapServer = new LdapServer(this);
    const QSettings dcConfig(resolvedDcDir + QStringLiteral("/dc.conf"), QSettings::IniFormat);
    m_storePath = dcConfig.value(QStringLiteral("storePath"),
                                 resolvedDcDir + QStringLiteral("/directory.json")).toString();
    m_baseDn = dcConfig.value(QStringLiteral("baseDn"),
                              QStringLiteral("DC=corp,DC=example,DC=com")).toString();
    const QString dnsDomain = dcConfig.value(QStringLiteral("dnsDomain"),
                                             QStringLiteral("MONARCHY.EXAMPLE.COM")).toString();
    const int ldapPort = dcConfig.value(QStringLiteral("ldapPort"), 1389).toInt();
    const QString dcHost = dcConfig.value(QStringLiteral("dcHost"),
                                          QStringLiteral("dc1.") + dnsDomain).toString();
    const QString dcIp = dcConfig.value(QStringLiteral("dcIp"),
                                        QStringLiteral("127.0.0.1")).toString();
    const QString siteName = dcConfig.value(QStringLiteral("siteName"),
                                            QStringLiteral("Default-First-Site-Name")).toString();
    m_zonePath = dcConfig.value(QStringLiteral("zonePath"),
                                resolvedDcDir + QStringLiteral("/private/dnszone.json")).toString();
    if (!m_ldapServer->loadFromFile(m_storePath)) {
        if (!m_allowSampleFallback) {
            emit statusMessage(tr("No provisioned domain under %1; refusing to serve a demo store.")
                                   .arg(resolvedDcDir));
            return false;
        }
        m_ldapServer->setObjects(sampleObjects());
    } else {
        m_ldapServer->loadSecretsFromFile(
            dcConfig.value(QStringLiteral("secretsPath"),
                           resolvedDcDir + QStringLiteral("/private/secrets.json")).toString());
    }

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
    const int kdcPort = dcConfig.value(QStringLiteral("kdcPort"), 8888).toInt();
    if (!m_kdc->listen(quint16(kdcPort))) {
        emit statusMessage(tr("Kerberos KDC failed to listen on port %1.").arg(kdcPort));
    } else {
        emit statusMessage(tr("Kerberos realm %1 served on port %2.")
                               .arg(m_kdc->realm().realm)
                               .arg(m_kdc->serverPort()));
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
        [this](const Rpc::AuthRequest &request, Ntlm::SessionKeys *keys) {
            for (const DirectoryObject &object : m_ldapServer->objects()) {
                const QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
                if (account.compare(request.user, Qt::CaseInsensitive) != 0 || object.id.isEmpty())
                    continue;
                const QByteArray ntHash = QByteArray::fromHex(
                    object.attributes.value(QStringLiteral("ntHash")).toLatin1());
                if (ntHash.size() != 16)
                    return false;
                if (!Ntlm::verifyNtlmv2(ntHash, request.user, request.domain, request.challenge,
                                        request.ntResponse))
                    return false;
                return Ntlm::sessionKeys(ntHash, request.user, request.domain,
                                         request.ntResponse.left(16), keys, request.flags);
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
    if (!m_samrServer->listen(quint16(samrPort))) {
        emit statusMessage(tr("SAMR endpoint failed to listen on port %1.").arg(samrPort));
    } else {
        emit statusMessage(tr("SAMR served on 127.0.0.1:%1.").arg(m_samrServer->serverPort()));
    }

    // LSAD on its own endpoint: the domain identity a client reads before it
    // joins, browses or administers anything. Same security provider as SAMR, so
    // one directory credential opens both.
    m_lsadServer = new LsadServer(this);
    m_lsadServer->setAuthenticator(authenticator);
    m_lsadServer->setDomainNames(krbRealm.netbios,
                                 dcHost.section(QLatin1Char('.'), 0, 0).toUpper(),
                                 dnsDomain, krbRealm.domainSid);
    m_lsadServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    // Account rights are an attribute of the account, so a right granted over
    // lsarpc is the same object data LDAP serves and survives a restart.
    Lsad::WriteBackend lsadWrites;
    lsadWrites.setRights = [this, persist](const QString &dn, const QStringList &rights,
                                           QString *error) {
        const bool ok = m_ldapServer->modifyObject(
            dn, {{QStringLiteral("userRight"), rights.join(QStringLiteral("; "))}});
        if (!ok && error)
            *error = QStringLiteral("account not found (%1)").arg(dn);
        if (ok)
            persist();
        return ok;
    };
    m_lsadServer->setWriteBackend(lsadWrites);
    const int lsadPort = dcConfig.value(QStringLiteral("lsadPort"), 1036).toInt();
    if (!m_lsadServer->listen(quint16(lsadPort))) {
        emit statusMessage(tr("LSAD endpoint failed to listen on port %1.").arg(lsadPort));
    } else {
        emit statusMessage(tr("LSAD served on 127.0.0.1:%1.").arg(m_lsadServer->serverPort()));
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
    m_netlogonServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    Netlogon::WriteBackend netlogonWrites;
    netlogonWrites.setNtHash = [this, persist](const QString &dn, const QByteArray &ntHash,
                                               QString *error) {
        const bool ok = m_ldapServer->setNtHash(dn, ntHash, error);
        if (ok)
            persist();
        return ok;
    };
    m_netlogonServer->setWriteBackend(netlogonWrites);
    connect(m_netlogonServer, &NetlogonServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int netlogonPort = dcConfig.value(QStringLiteral("netlogonPort"), 1037).toInt();
    if (!m_netlogonServer->listen(quint16(netlogonPort))) {
        emit statusMessage(tr("Netlogon endpoint failed to listen on port %1.")
                               .arg(netlogonPort));
    } else {
        emit statusMessage(
            tr("Netlogon served on 127.0.0.1:%1.").arg(m_netlogonServer->serverPort()));
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
    m_drsServer->setObjectProvider([this]() { return m_ldapServer->objects(); });
    m_drsServer->setAuthenticator(authenticator);
    connect(m_drsServer, &DrsServer::requestReceived, this,
            [this](const QString &operation) { emit statusMessage(operation); });
    const int drsPort = dcConfig.value(QStringLiteral("drsPort"), 1038).toInt();
    if (!m_drsServer->listen(quint16(drsPort))) {
        emit statusMessage(tr("DRSR endpoint failed to listen on port %1.")
                               .arg(drsPort));
    } else {
        emit statusMessage(
            tr("DRSR served on 127.0.0.1:%1.").arg(m_drsServer->serverPort()));
    }

    // The endpoint mapper: the answer a client gets when it knows an interface
    // UUID and a protocol but not the port (ncacn_epm, port 135 by default).
    // Every entry here is a port an endpoint above actually bound, so a lookup
    // never advertises something that refuses the connection.
    m_epmServer = new EpmServer(this);
    m_epmServer->setHostName(dcHost.section(QLatin1Char('.'), 0, 0));
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
    if (!m_epmServer->listen(quint16(epmPort))) {
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
        emit statusMessage(
            tr("Endpoint mapper served on 127.0.0.1:%1.").arg(m_epmServer->serverPort()));
    }

    // SMB2 and the named pipes the management interfaces are addressed by on a
    // Windows network: \\dc\pipe\samr and \\dc\pipe\lsarpc carry the same
    // DCE/RPC the TCP endpoints do, into the same handlers, behind the same
    // authenticator.
    m_smbServer = new Smb2Server(this);
    m_smbServer->setAuthenticator(authenticator);
    m_smbServer->setDomainNames(krbRealm.netbios,
                                dcHost.section(QLatin1Char('.'), 0, 0).toUpper(), dnsDomain);
    m_smbServer->addPipe(QStringLiteral("samr"), m_samrServer->rpc());
    m_smbServer->addPipe(QStringLiteral("lsarpc"), m_lsadServer->rpc());
    m_smbServer->addPipe(QStringLiteral("epmapper"), m_epmServer->rpc());
    m_smbServer->addPipe(QStringLiteral("netlogon"), m_netlogonServer->rpc());
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

    // The zone belongs to the domain: a provisioned DC ships one in private/,
    // and an unprovisioned console synthesises the same AD service records for
    // itself so the domain resolves consistently either way.
    m_dnsServer = new DnsServer(this);
    if (!m_dnsServer->loadZone(m_zonePath)) {
        m_dnsServer->loadAdZone(dnsDomain, dcHost, dcIp, quint16(ldapPort), 3268, siteName);
    }
    if (!m_dnsServer->listen(quint16(dcConfig.value(QStringLiteral("dnsPort"), 1053).toInt()))) {
        emit statusMessage(tr("DNS server failed to bind its port."));
    } else {
        emit statusMessage(tr("Authoritative for %1 on port %2.")
                               .arg(m_dnsServer->zone())
                               .arg(m_dnsServer->serverPort()));
    }

    m_started = true;
    return true;
}
