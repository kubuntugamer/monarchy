// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef REPLICATIONAGENT_H
#define REPLICATIONAGENT_H

#include <QList>
#include <QObject>
#include <QString>

#include <functional>

#include "resultsmodel.h"

// The DRA half of a pull: what a DC runs to take changes from a partner on its
// own schedule, instead of waiting for an administrator to call DsReplicaSync.
// It composes the wire client (DrsClient) with the store's apply path
// (LdapServer::applyReplication) and keeps the USN cursor between pulls, so
// each one asks only for what the last one did not already take.
class ReplicationAgent : public QObject
{
    Q_OBJECT

public:
    // Applies one cycle's objects to the local store and returns how many it
    // acted on; LdapServer::applyReplication is this tree's implementation.
    using Sink = std::function<int(const QList<DirectoryObject> &)>;

    explicit ReplicationAgent(QObject *parent = nullptr);

    // A DC publishes DRSUAPI on a dynamic port, so the port may be left 0 and
    // resolved through the source's endpoint mapper.
    void setSource(const QString &host, quint16 port = 0);
    void setEpmPort(quint16 port) { m_epmPort = port; }
    void setCredentials(const QString &domain, const QString &user, const QString &password);
    void setNamingContext(const QString &dn);
    void setSink(Sink sink) { m_sink = std::move(sink); }

    QString source() const;
    quint64 lastUsn() const { return m_lastUsn; }
    quint32 cycles() const { return m_cycles; }

    // One pull: connect, bind, follow fMoreData until the source is drained,
    // apply each cycle, unbind. Returns the objects applied, or -1 with `error`
    // set. The cursor advances only over cycles the store has taken, so a pull
    // that fails part-way is retried from the same place rather than skipping
    // changes.
    int pullOnce(QString *error = nullptr);

signals:
    void pulled(const QString &summary);

private:
    QString m_host;
    quint16 m_port = 0;
    quint16 m_epmPort = 135;
    QString m_domain;
    QString m_user;
    QString m_password;
    bool m_credentialsSet = false;
    QString m_nc;
    Sink m_sink;
    quint64 m_lastUsn = 0;
    quint32 m_cycles = 0;
};

#endif // REPLICATIONAGENT_H
