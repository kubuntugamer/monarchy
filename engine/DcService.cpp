// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DcService.h"

#include "DnsServer.h"
#include "Drs.h"
#include "Epm.h"
#include "Kdc.h"
#include "Kpasswd.h"
#include "LdapServer.h"
#include "Lsad.h"
#include "Netlogon.h"
#include "Rpc.h"
#include "Ntlm.h"
#include "Samr.h"
#include "Smb2.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>

#include <QTimer>

#include "ReplicationAgent.h"
#include "resultsmodel.h"

DcService::DcService(QObject *parent)
    : QObject(parent)
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

    // Global Catalog: the same store on 3268, which is what the `_gc._tcp`
    // locator record has always pointed at. The root DSE reports
    // isGlobalCatalogReady from whether this listener actually came up, so a
    // port that is taken is visible to the client instead of assumed away.
    const int gcPort = dcConfig.value(QStringLiteral("gcPort"), 3268).toInt();
    if (!m_ldapServer->listenGc(quint16(gcPort))) {
        emit statusMessage(tr("Global Catalog failed to listen on port %1.").arg(gcPort));
    } else {
        emit statusMessage(
            tr("Global Catalog served on port %1.").arg(m_ldapServer->gcServerPort()));
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
    if (!m_kpasswdServer->listen(quint16(kpasswdPort))) {
        emit statusMessage(tr("kpasswd failed to listen on port %1.").arg(kpasswdPort));
    } else {
        emit statusMessage(tr("Kerberos password change served on port %1.")
                               .arg(m_kpasswdServer->serverPort()));
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
    lsadWrites.updateTrust = [this, persist](const QString &dn,
                                              const QMap<QString, QString> &attributes,
                                              QString *error) {
        const bool ok = m_ldapServer->modifyObject(dn, attributes);
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
    // Tombstones are part of what a replication partner has to see: the live
    // store alone would leave a deleted object alive on the other side.
    m_drsServer->setObjectProvider([this]() {
        return m_ldapServer->objects() + m_ldapServer->tombstones();
    });
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
    m_replicationAgent->setNamingContext(
        dcConfig.value(QStringLiteral("replicaNamingContext"), m_baseDn).toString());
    m_replicationAgent->setSink([this](const QList<DirectoryObject> &objects) {
        return m_ldapServer->applyReplication(objects);
    });
    connect(m_replicationAgent, &ReplicationAgent::pulled, this,
            [this](const QString &summary) { emit statusMessage(summary); });

    const int replicaSeconds =
        qMax(1, dcConfig.value(QStringLiteral("replicaIntervalSeconds"), 300).toInt());
    m_replicaTimer = new QTimer(this);
    m_replicaTimer->setInterval(replicaSeconds * 1000);
    connect(m_replicaTimer, &QTimer::timeout, this, [this]() {
        if (m_replicationAgent->source().isEmpty())
            return;
        QString error;
        if (m_replicationAgent->pullOnce(&error) < 0) {
            emit statusMessage(tr("Replication pull from %1 failed: %2")
                                   .arg(m_replicationAgent->source(), error));
        }
    });

    // A DRS address is a bare host, host:port, or an ncacn_ip_tcp binding; the
    // agent needs the host and the port separately.
    const auto parseAddress = [](const QString &address, QString *host, quint16 *port) {
        *host = address;
        *port = 0;
        if (host->startsWith(QStringLiteral("ncacn_ip_tcp:")))
            host->remove(0, 13);
        const int bracket = host->indexOf(QLatin1Char('['));
        if (bracket >= 0) {
            *port = quint16(host->mid(bracket + 1).remove(QLatin1Char(']')).toUShort());
            host->truncate(bracket);
        } else if (host->count(QLatin1Char(':')) == 1) {
            *port = quint16(host->section(QLatin1Char(':'), 1).toUShort());
            *host = host->section(QLatin1Char(':'), 0, 0);
        }
    };

    connect(m_drsServer, &DrsServer::replicaSourceAdded, this,
            [this, parseAddress](const QString &address, const QString &) {
                QString host;
                quint16 port = 0;
                parseAddress(address, &host, &port);
                m_replicationAgent->setSource(host, port);
                if (!m_replicaTimer->isActive())
                    m_replicaTimer->start();
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
                if (!m_replicaTimer->isActive())
                    m_replicaTimer->start();
                emit statusMessage(tr("Replication source %1 changed to %2.")
                                       .arg(previous, address));
            });

    // A source retired with DsReplicaDel stops being pulled from; the agent
    // keeps its cursor, so re-adding the same partner resumes where it left off.
    connect(m_drsServer, &DrsServer::replicaSourceRemoved, this,
            [this, parseAddress](const QString &address, const QString &) {
                QString host;
                quint16 port = 0;
                parseAddress(address, &host, &port);
                if (!m_replicationAgent->source().startsWith(host, Qt::CaseInsensitive))
                    return;
                m_replicationAgent->setSource(QString(), 0);
                m_replicaTimer->stop();
                emit statusMessage(tr("Replication source %1 retired.").arg(address));
            });

    const QString replicaHost = dcConfig.value(QStringLiteral("replicaHost")).toString();
    if (!replicaHost.isEmpty()) {
        m_replicationAgent->setSource(
            replicaHost, quint16(dcConfig.value(QStringLiteral("replicaPort"), 0).toInt()));
        m_replicaTimer->start();
        emit statusMessage(tr("Pulling replication from %1 every %2s.")
                               .arg(m_replicationAgent->source())
                               .arg(replicaSeconds));
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
    m_smbServer->addShare(QStringLiteral("SYSVOL"), sysvolShare);
    m_smbServer->addShare(QStringLiteral("NETLOGON"), domainSysvol + QStringLiteral("/scripts"));
    emit statusMessage(tr("SYSVOL and NETLOGON shared from %1.").arg(sysvolShare));

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
    // Out-of-zone names are resolved through the forwarders in dc.conf, or the
    // host's own nameservers when none are listed. This is what lets the DC be
    // the machine's resolver: it answers its zone authoritatively and caches
    // everything else.
    const QStringList forwarders =
        dcConfig.value(QStringLiteral("forwarders")).toString()
            .split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    m_dnsServer->setForwarders(forwarders);
    m_dnsServer->setForwardingEnabled(dcConfig.value(QStringLiteral("forwarding"), true).toBool());
    if (!m_dnsServer->loadZone(m_zonePath)) {
        m_dnsServer->loadAdZone(dnsDomain, dcHost, dcIp, quint16(ldapPort), quint16(gcPort),
                                siteName, quint16(kpasswdPort), quint16(kdcPort));
    }
    // A zone loaded from disk may predate a service this build serves — the
    // kpasswd locators, for one — so the DC holds its own zone to what it
    // actually answers before it serves it.
    if (m_dnsServer->repairAdZoneLocators(dcHost, quint16(ldapPort), quint16(gcPort), siteName,
                                          quint16(kpasswdPort), quint16(kdcPort))) {
        QString zoneError;
        if (!m_zonePath.isEmpty() && !m_dnsServer->saveZone(m_zonePath, &zoneError))
            emit statusMessage(tr("Could not persist the repaired zone: %1").arg(zoneError));
        else
            emit statusMessage(tr("Repaired the domain's service locator records."));
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
