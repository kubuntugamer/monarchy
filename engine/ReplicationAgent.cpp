// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ReplicationAgent.h"

#include "DrsClient.h"

#include <QTimeZone>

namespace {

// The slot a REPLTIMES bit addresses: 15-minute units counted from Sunday
// 00:00 UTC, 672 to the week.
int slotIndex(const QDateTime &utc)
{
    const QDateTime stamp = utc.toUTC();
    // QDate::dayOfWeek is Monday=1 .. Sunday=7; the schedule's week opens on
    // Sunday, so Sunday is day 0 here.
    const int daysSinceSunday = stamp.date().dayOfWeek() % 7;
    const int secondsOfDay =
        stamp.time().hour() * 3600 + stamp.time().minute() * 60 + stamp.time().second();
    return daysSinceSunday * 96 + secondsOfDay / ReplicationAgent::kSlotSeconds;
}

bool bitSet(const QByteArray &schedule, int slot)
{
    // Within a byte the earliest slot is the most significant bit.
    const quint8 octet = quint8(schedule.at(slot / 8));
    return (octet & (0x80u >> (slot % 8))) != 0;
}

} // namespace

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

bool ReplicationAgent::slotAllowed(const QByteArray &schedule, const QDateTime &utc)
{
    if (schedule.size() != kScheduleBytes || !utc.isValid())
        return false;
    return bitSet(schedule, slotIndex(utc));
}

QDateTime ReplicationAgent::nextSlotStart(const QByteArray &schedule, const QDateTime &utc)
{
    if (schedule.size() != kScheduleBytes || !utc.isValid())
        return QDateTime();
    const qint64 seconds = utc.toUTC().toSecsSinceEpoch();
    // Start at the first boundary strictly after `utc`, then walk the 672 that
    // follow it: the same weekday next week addresses the same slot index, so
    // one pass covers every future slot the schedule can allow.
    qint64 boundary = seconds - (seconds % kSlotSeconds) + kSlotSeconds;
    for (int i = 0; i < kSlotsPerWeek; ++i, boundary += kSlotSeconds) {
        const QDateTime candidate = QDateTime::fromSecsSinceEpoch(boundary, QTimeZone::utc());
        if (bitSet(schedule, slotIndex(candidate)))
            return candidate;
    }
    return QDateTime();
}

qint64 ReplicationAgent::nextCycleDelayMs(const QByteArray &schedule, quint32 flags,
                                          int intervalSeconds, const QDateTime &utc)
{
    const qint64 fallback = qint64(qMax(1, intervalSeconds)) * 1000;
    if (!utc.isValid())
        return fallback;
    // MS-DRSR's REPS_FROM: the schedule identifies the intervals a cycle is
    // initiated in only when periodic replication is enabled, which is what
    // DRS_PER_SYNC says. Without it the cycle is event-driven, and for this
    // agent that is the configured interval.
    if ((flags & kDrsPerSync) == 0 || schedule.size() != kScheduleBytes)
        return fallback;
    const QDateTime next = nextSlotStart(schedule, utc);
    if (!next.isValid())
        return -1;
    return qMax<qint64>(1000, utc.toUTC().msecsTo(next));
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
