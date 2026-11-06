// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ReplicationAgent.h"

#include "DrsClient.h"

ReplicationAgent::ReplicationAgent(QObject *parent)
    : QObject(parent)
{
}

void ReplicationAgent::setSource(const QString &host, quint16 port)
{
    m_host = host;
    m_port = port;
}

void ReplicationAgent::setCredentials(const QString &domain, const QString &user,
                                      const QString &password)
{
    m_domain = domain;
    m_user = user;
    m_password = password;
    m_credentialsSet = !user.isEmpty() && !password.isEmpty();
}

void ReplicationAgent::setNamingContext(const QString &dn)
{
    m_nc = dn;
}

QString ReplicationAgent::source() const
{
    if (m_host.isEmpty())
        return QString();
    return QStringLiteral("%1:%2").arg(m_host).arg(m_port == 0 ? m_epmPort : m_port);
}

int ReplicationAgent::pullOnce(QString *error)
{
    auto fail = [error](const QString &text) {
        if (error)
            *error = text;
        return -1;
    };

    if (m_host.isEmpty())
        return fail(QStringLiteral("no replication source configured"));
    if (m_nc.isEmpty())
        return fail(QStringLiteral("no naming context configured"));
    if (!m_sink)
        return fail(QStringLiteral("no store to apply the changes to"));

    DrsClient client;
    client.setPeer(m_host, m_port);
    client.setEpmPort(m_epmPort);
    if (m_credentialsSet)
        client.setCredentials(m_domain, m_user, m_password);

    QString step;
    if (!client.connectToPeer(&step))
        return fail(step);
    if (!client.bindInterface(&step)) {
        client.close();
        return fail(step);
    }
    if (!client.dsBind(&step)) {
        client.close();
        return fail(step);
    }

    int applied = 0;
    quint64 from = m_lastUsn;
    quint32 cycles = 0;
    bool moreData = true;
    while (moreData && cycles < 1000) {
        QList<DirectoryObject> objects;
        quint64 usnHigh = 0;
        QString cycleError;
        if (!client.getNCChanges(m_nc, from, &objects, &usnHigh, &moreData, &cycleError)) {
            client.close();
            return fail(cycleError);
        }
        applied += m_sink(objects);
        // The cursor moves over this cycle's high-water mark only after the
        // store has taken it.
        from = usnHigh;
        ++cycles;
    }

    m_lastUsn = from;
    m_cycles += cycles;

    client.dsUnbind();
    client.close();

    emit pulled(QStringLiteral("pulled %1 object(s) from %2 in %3 cycle(s)")
                    .arg(applied)
                    .arg(source())
                    .arg(cycles));
    return applied;
}
