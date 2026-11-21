// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DIRECTORYSERVICE_H
#define DIRECTORYSERVICE_H

#include "resultsmodel.h"

#include <QObject>
#include <QFuture>
#include <QString>
#include <QStringList>

class ConnectionService;

// Directory read/write service. Speaks real LDAP: OpenLDAP client when built
// with MONARCHY_WITH_LDAP, otherwise the built-in wire client (backend/LdapClient).
class DirectoryService : public QObject
{
    Q_OBJECT
public:
    explicit DirectoryService(ConnectionService *connection, QObject *parent = nullptr);
    ConnectionService *connection() const { return m_connection; }

    QFuture<QList<DirectoryObject>> search(const QString &baseDn, const QString &filter,
                                           const QStringList &attributes, int pageSize = 1000);
    QFuture<QList<DirectoryObject>> listContainers(const QString &parentDn);
    QFuture<QMap<QString, QString>> getAttributes(const QString &dn);
    QFuture<bool> addObject(const DirectoryObject &object);
    QFuture<bool> removeObject(const QString &dn);
    QFuture<bool> modifyObject(const QString &dn, const QMap<QString, QString> &attributes);
    // Reads a multi-valued attribute, adds/removes single values and writes the
    // result back on one connection, so concurrent edits cannot drop entries.
    QFuture<bool> modifyValues(const QString &dn, const QString &attribute,
                               const QStringList &add, const QStringList &remove);

    void setBaseDn(const QString &baseDn) { m_baseDn = baseDn; }
    QString baseDn() const { return m_baseDn; }

signals:
    void error(const QString &message);
    // A create was refused by the server. The console cannot leave that in the
    // status bar: a rejected New > User looks exactly like nothing happening.
    void creationRejected(const QString &name, const QString &reason);
    // A read was refused with insufficientAccessRights (50): the session is
    // anonymous or lacks the right. The console answers this with a sign-in
    // prompt instead of an empty container.
    void authorizationRequired();

private:
#ifdef MONARCHY_WITH_LDAP
    // Turns a failed write's LDAP result into the status-bar explanation. A
    // handle outlives the server it was opened on: when this DC is restarted the
    // console's connection dies, and every write then fails on this side without
    // reaching the directory, so "nothing happened" has to come with a reason.
    void reportLdapFailure(int rc);
#endif
    ConnectionService *m_connection = nullptr;
    QString m_baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
};

#endif // DIRECTORYSERVICE_H