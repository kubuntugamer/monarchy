// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRS_H
#define DRS_H

#include <QByteArray>
#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QUuid>

#include <functional>

#include "Ntlm.h"
#include "Rpc.h"
#include "Samr.h"
#include "resultsmodel.h"

// DRSUAPI (MS-DRSR, reference/specs/samba-drsuapi.idl): the replication
// interface. The DC answers DsBind / DsUnbind and DsGetNCChanges against the
// same store SAMR, LSAD, Netlogon and LDAP serve, filtered by uSNChanged the
// way AD serves change state, plus DsCrackNames and DsGetDomainControllerInfo
// for the name and DC lookups a DCSync-style client makes first.
// DsReplicaSync and DsReplicaUpdateRefs are
// answered as the lifecycle calls a replication cycle makes; other calls are
// refused with kWerrNotSupported rather than described falsely.

namespace Drs {

Rpc::Interface interface();

// The canonical MS-DRSR §5.12.2 prefix map: entry id → partial binary OID
// (DER encoding of the OID with the final sub-identifier's bytes stripped).
QList<QPair<quint32, QByteArray>> prefixTable();
QByteArray partialBinaryOid(const char *oidText);

// Stable per-DC identity, derived from the domain SID and DC name so cursors
// and GUID checks survive a restart without a store write.
QUuid invocationId(const QString &domainSid, const QString &dcName);
QUuid sourceDsaGuid(const QString &domainSid, const QString &dcName);

} // namespace Drs

class DrsServer : public QObject
{
    Q_OBJECT

public:
    explicit DrsServer(QObject *parent = nullptr);

    void setConfig(const Samr::Config &config);
    void setDomainNames(const QString &netbios, const QString &serverName,
                        const QString &dnsDomain);
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);
    void setAuthenticator(Rpc::Authenticator authenticator);
    void setInvocationId(const QUuid &invocationId) { m_invocationId = invocationId; }
    void setSourceDsaGuid(const QUuid &guid) { m_sourceDsaGuid = guid; }

    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // One request in, one response out (endpoint and tests).
    QByteArray handleCall(quint16 opnum, const QByteArray &stub);

signals:
    void requestReceived(const QString &operation);

private:
    QByteArray drsBind(const QByteArray &stub);
    QByteArray drsUnbind(const QByteArray &stub);
    QByteArray drsReplicaSync(const QByteArray &stub);
    QByteArray drsUpdateRefs(const QByteArray &stub);
    QByteArray drsGetNCChanges(const QByteArray &stub);
    QByteArray drsDomainControllerInfo(const QByteArray &stub);
    QByteArray drsCrackNames(const QByteArray &stub);

    QList<DirectoryObject> directory() const;
    quint64 storeUsn(const DirectoryObject &object) const;
    QString baseDn() const { return m_config.baseDn; }

    Samr::Config m_config;
    QString m_dnsDomain;
    QUuid m_invocationId;
    QUuid m_sourceDsaGuid;
    RpcServer *m_rpc = nullptr;
    std::function<QList<DirectoryObject>()> m_provider;
    QHash<QUuid, QString> m_handles; // bind handle → principal state
};

#endif // DRS_H
