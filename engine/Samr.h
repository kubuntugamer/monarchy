// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SAMR_H
#define SAMR_H

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

#include <functional>

#include "Rpc.h"
#include "resultsmodel.h"

// SAMR (MS-SAMR), the Security Account Manager remote interface: the one ADUC,
// usrmgr and every provisioning script use to list and manage accounts. It runs
// over DCE/RPC (Rpc.h) with NDR marshalling (Ndr.h) and is backed by the same
// directory the LDAP and Kerberos sides serve.
namespace Samr {

struct Config {
    QString realm;
    QString netbios;
    QString domainSid; // "S-1-5-21-x-y-z"
    QString baseDn;    // "DC=corp,DC=example,DC=com", where new accounts land
};

// What the RPC server needs from the directory to honour writes. The LDAP
// engine implements it, so an account created over SAMR is the same object a
// search returns, with the same SID and group membership.
struct WriteBackend {
    // Allocates the object's relative id, stamps objectSid and stores it.
    std::function<bool(DirectoryObject *object, QString *error)> create;
    std::function<bool(const QString &dn, const QString &attribute, const QString &value,
                       QString *error)> set;
    // Sets the account credential: the verifiers AD keeps for simple bind,
    // NTLM and Kerberos, stamped with a fresh pwdLastSet. Refuses a password
    // the domain policy rejects.
    std::function<bool(const QString &dn, const QString &password, QString *error)> setPassword;
    // Sets the credential from an NT hash instead of a password, which is what
    // a SamrSetInformationUser class 18 call carries.
    std::function<bool(const QString &dn, const QByteArray &ntHash, QString *error)> setNtHash;
    std::function<bool(const QString &dn, QString *error)> remove;
    std::function<bool(const QString &groupDn, const QString &memberDn, QString *error)> addMember;
    std::function<bool(const QString &groupDn, const QString &memberDn, QString *error)> removeMember;
};

// Opnums this implementation answers.
enum Opnum : quint16 {
    OpConnect = 0,
    OpCloseHandle = 1,
    OpLookupDomainInSamServer = 5,
    OpEnumerateDomainsInSamServer = 6,
    OpOpenDomain = 7,
    OpQueryInformationDomain = 8,
    OpCreateGroupInDomain = 10,
    OpEnumerateGroupsInDomain = 11,
    OpEnumerateUsersInDomain = 13,
    // MS-SAMR function 0x14/0x15, after OpenGroup (0x13).
    OpQueryInformationGroup = 20,
    OpSetInformationGroup = 21,
    OpLookupNamesInDomain = 17,
    OpLookupIdsInDomain = 18,
    OpOpenGroup = 19,
    OpAddMemberToGroup = 22,
    OpDeleteGroup = 23,
    OpRemoveMemberFromGroup = 24,
    OpGetMembersInGroup = 25,
    OpOpenUser = 34,
    OpGetGroupsForUser = 39,
    OpDeleteUser = 35,
    // SamrQueryInformationUser (36) is the pre-revision form of the (2) call:
    // same [in] handle + [in] class, same [out] Buffer union + NTSTATUS.
    OpQueryInformationUser = 36,
    OpQueryInformationUser2 = 47,
    OpCreateUser2 = 50,
    // Both set-information calls take the same union: 37 is
    // SamrSetInformationUser (the one class 18 hash sets arrive on), 58 is
    // SamrSetInformationUser2.
    OpSetInformationUser = 37,
    OpSetInformationUser2 = 58,
    // SamrConnect2 (57) is what ADUC, Samba's tools and most scripts open the
    // server with; SamrConnect (0) is the original and SamrConnect5 (64) the
    // revision-negotiating form. All three return a server handle.
    OpConnect2 = 57,
    OpConnect4 = 62,
    OpConnect5 = 64
};

Rpc::Interface interface();

} // namespace Samr

class SamrServer : public QObject
{
    Q_OBJECT

public:
    explicit SamrServer(QObject *parent = nullptr);

    void setConfig(const Samr::Config &config);
    Samr::Config config() const { return m_config; }
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);
    void setWriteBackend(Samr::WriteBackend backend);
    // RPC authentication (NTLMSSP): the endpoint verifies the client's bind
    // against the same directory it serves.
    void setAuthenticator(Rpc::Authenticator authenticator);
    // RPC authentication (Kerberos): the bind's AP-REQ is accepted by the KDC,
    // which is also what seals the per-call tokens afterwards.
    void setKerberosAcceptor(Rpc::KerberosAcceptor acceptor, Rpc::KerberosFinisher finisher);
    void setDomainNames(const QString &domain, const QString &serverName,
                        const QString &dnsDomain = QString());

    // The DC serves SAMR on the loopback address. Authentication (NTLMSSP and
    // Kerberos) is in place, but there is no per-account authorization model
    // behind it, so the endpoint is not published on the network yet.
    bool listen(quint16 port = 0, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // One NDR request in, one NDR response out. Used by the RPC endpoint and by
    // the tests, so the marshalling can be checked without a socket.
    // `sessionKey` is the NTLM session key the call authenticated with; the
    // password information classes cannot be decoded without it.
    QByteArray handleCall(quint16 opnum, const QByteArray &stub,
                          const QByteArray &sessionKey = QByteArray());

signals:
    void requestReceived(const QString &operation);

private:
    struct Handle {
        enum Kind { None, Server, Domain, User, Group } kind = None;
        QString dn;   // domain or user object
        quint32 rid = 0;
    };

    QList<DirectoryObject> directory() const;
    QList<DirectoryObject> users() const;
    QList<DirectoryObject> groups() const;
    QByteArray newHandle(Handle::Kind kind, const QString &dn, quint32 rid);
    bool lookupHandle(const QByteArray &handle, Handle::Kind kind, Handle *out) const;

    Samr::Config m_config;
    std::function<QList<DirectoryObject>()> m_provider;
    Samr::WriteBackend m_writes;
    RpcServer *m_rpc = nullptr;
    QHash<QByteArray, Handle> m_handles;
};

#endif // SAMR_H
