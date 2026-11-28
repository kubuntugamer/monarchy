// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ReplicaTopology.h"

#include "LdapServer.h"
#include "resultsmodel.h"

#include <algorithm>

namespace ReplicaTopology {

void splitAddress(const QString &address, QString *host, quint16 *port)
{
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
}

QString ntdsSettingsDn(const QList<DirectoryObject> &objects)
{
    for (const DirectoryObject &object : objects) {
        if (object.id.isEmpty())
            continue;
        if (object.attributes.value(QStringLiteral("objectClass"))
                .contains(QStringLiteral("nTDSDSA"), Qt::CaseInsensitive))
            return object.id;
    }
    return QString();
}

QString linkDn(const QString &ntdsDn, const QString &address)
{
    QString host;
    quint16 port = 0;
    splitAddress(address, &host, &port);
    const QString cn = port == 0 ? host : QStringLiteral("%1_%2").arg(host).arg(port);
    return QStringLiteral("CN=%1,%2").arg(cn, ntdsDn);
}

namespace {

bool hasClass(const DirectoryObject &object, const QString &name)
{
    const QStringList classes = object.attributes.value(QStringLiteral("objectClass"))
                                    .split(QLatin1Char(';'), Qt::SkipEmptyParts);
    for (const QString &candidate : classes) {
        if (candidate.trimmed().compare(name, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

// The object AD keeps one replication path in, under the destination DSA's own
// NTDS Settings. A link DsReplicaAdd made and one the KCC made differ only in
// the markers the second carries: NTDSCONN_OPT_IS_GENERATED (MS-ADTS
// 6.1.1.2.2.1.2.1.2) says the KCC may change or delete its own object while an
// administrator's is used but never modified, and a generated connection is
// enabled and carries FLAG_CONFIG_ALLOW_RENAME | FLAG_CONFIG_ALLOW_MOVE.
DirectoryObject connectionObject(const QList<DirectoryObject> &objects, const QString &ntdsDn,
                                 const ReplicaSource &link, bool generated)
{
    const QString dn = ReplicaTopology::linkDn(ntdsDn, link.address);

    // A level-2 add names the source DSA, and that DN is the fromServer AD
    // writes. A level-1 add carries only the address, so the source server is
    // named from it — the address stays what the pull actually uses.
    QString host;
    quint16 port = 0;
    ReplicaTopology::splitAddress(link.address, &host, &port);
    QString fromServer = link.sourceDsaDn;
    if (fromServer.isEmpty()) {
        QString configNc;
        for (const DirectoryObject &object : objects) {
            if (object.id.isEmpty()) {
                configNc = object.attributes.value(QStringLiteral("configurationNamingContext"));
                break;
            }
        }
        fromServer = QStringLiteral("CN=NTDS Settings,CN=%1,CN=Servers,"
                                    "CN=Default-First-Site-Name,CN=Sites,%2")
                         .arg(host, configNc);
    }

    DirectoryObject object;
    object.id = dn;
    object.name = dn.section(QLatin1Char('='), 1).section(QLatin1Char(','), 0, 0);
    object.type = QStringLiteral("NTDS Connection");
    object.kind = ObjectKind::Container;
    object.container = QStringLiteral("Console Root");
    object.attributes.insert(QStringLiteral("objectClass"),
                             QStringLiteral("top;nTDSConnection"));
    object.attributes.insert(QStringLiteral("cn"), object.name);
    object.attributes.insert(QStringLiteral("fromServer"), fromServer);
    // The RPC-over-IP transport every link here uses.
    object.attributes.insert(QStringLiteral("transportType"),
                             QStringLiteral("22b70c67-d228-4a38-b335-1c7dcb4a3c71"));
    quint32 options = link.options;
    if (generated) {
        options |= 0x1u; // NTDSCONN_OPT_IS_GENERATED
        object.attributes.insert(QStringLiteral("enabledConnection"), QStringLiteral("TRUE"));
        // FLAG_CONFIG_ALLOW_RENAME (0x40000000) | FLAG_CONFIG_ALLOW_MOVE (0x20000000)
        object.attributes.insert(QStringLiteral("systemFlags"), QString::number(0x60000000u));
    }
    object.attributes.insert(QStringLiteral("options"), QString::number(options));
    if (!link.schedule.isEmpty())
        object.attributes.insert(QStringLiteral("schedule"), link.schedule.toHex());
    return object;
}

} // namespace

bool store(LdapServer *ldap, const ReplicaSource &link, QString *error)
{
    if (!ldap) {
        if (error)
            *error = QStringLiteral("no directory");
        return false;
    }
    const QList<DirectoryObject> objects = ldap->objects();
    const QString ntdsDn = ntdsSettingsDn(objects);
    if (ntdsDn.isEmpty()) {
        if (error)
            *error = QStringLiteral("the store has no NTDS Settings object");
        return false;
    }
    const QString dn = linkDn(ntdsDn, link.address);
    for (const DirectoryObject &existing : objects) {
        if (existing.id.compare(dn, Qt::CaseInsensitive) == 0)
            return true; // already recorded, e.g. read back at start-up
    }
    ldap->addObject(connectionObject(objects, ntdsDn, link, false));
    return true;
}

bool remove(LdapServer *ldap, const QString &address, QString *error)
{
    if (!ldap) {
        if (error)
            *error = QStringLiteral("no directory");
        return false;
    }
    const QString ntdsDn = ntdsSettingsDn(ldap->objects());
    if (ntdsDn.isEmpty()) {
        if (error)
            *error = QStringLiteral("the store has no NTDS Settings object");
        return false;
    }
    const QString dn = linkDn(ntdsDn, address);
    for (const DirectoryObject &existing : ldap->objects()) {
        if (existing.id.compare(dn, Qt::CaseInsensitive) == 0)
            return ldap->removeObject(dn);
    }
    return true; // no object, nothing to retire
}

QList<ReplicaSource> links(const QList<DirectoryObject> &objects,
                           const QStringList &namingContexts)
{
    QList<ReplicaSource> restored;
    const QString ntdsDn = ntdsSettingsDn(objects);
    if (ntdsDn.isEmpty())
        return restored;

    const QString suffix = QLatin1Char(',') + ntdsDn;
    for (const DirectoryObject &object : objects) {
        if (!object.id.endsWith(suffix, Qt::CaseInsensitive))
            continue;
        if (!object.attributes.value(QStringLiteral("objectClass"))
                 .contains(QStringLiteral("nTDSConnection"), Qt::CaseInsensitive))
            continue;

        // The name carries the address back: <host>, or <host>_<port> when the
        // link was registered against a non-default DRS port.
        QString address = object.attributes.value(QStringLiteral("cn"));
        if (address.isEmpty())
            address = object.id.mid(3).section(QLatin1Char(','), 0, 0);
        const int underscore = address.lastIndexOf(QLatin1Char('_'));
        if (underscore > 0 && address.mid(underscore + 1).toUShort() != 0)
            address = address.left(underscore) + QLatin1Char(':') + address.mid(underscore + 1);

        ReplicaSource shape;
        shape.address = address;
        shape.options = object.attributes.value(QStringLiteral("options")).toUInt();
        shape.schedule =
            QByteArray::fromHex(object.attributes.value(QStringLiteral("schedule")).toLatin1());
        const QString fromServer = object.attributes.value(QStringLiteral("fromServer"));
        if (fromServer.contains(QLatin1String("CN=NTDS Settings"), Qt::CaseInsensitive))
            shape.sourceDsaDn = fromServer;

        for (const QString &nc : namingContexts) {
            ReplicaSource link = shape;
            link.ncDn = nc;
            restored.append(link);
        }
    }
    return restored;
}

namespace {

// CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,... → the site DN,
// i.e. everything from CN=<site> onwards.
QString siteOf(const QString &ntdsDn)
{
    const QString marker = QStringLiteral("CN=Servers,");
    const int at = ntdsDn.indexOf(marker, 0, Qt::CaseInsensitive);
    if (at < 0)
        return QString();
    return ntdsDn.mid(at + marker.size());
}

} // namespace

QList<PublishedDsa> intrasiteDsas(const QList<DirectoryObject> &objects,
                                  const QString &selfNtdsDn)
{
    QList<PublishedDsa> dsas;
    const QString site = siteOf(selfNtdsDn);
    if (site.isEmpty())
        return dsas;
    const QString suffix = QLatin1Char(',') + site;

    for (const DirectoryObject &server : objects) {
        if (server.id.isEmpty())
            continue;
        if (!server.id.endsWith(suffix, Qt::CaseInsensitive))
            continue;
        if (!hasClass(server, QStringLiteral("server")))
            continue;
        const QString host = server.attributes.value(QStringLiteral("dNSHostName"));
        if (host.isEmpty())
            continue; // nothing to address it by, so it cannot be pulled from

        // The DSA is the server's own NTDS Settings child; a server object
        // without one is not a DC that is running.
        const QString ntdsDn = QStringLiteral("CN=NTDS Settings,%1").arg(server.id);
        for (const DirectoryObject &candidate : objects) {
            if (candidate.id.compare(ntdsDn, Qt::CaseInsensitive) != 0)
                continue;
            if (!hasClass(candidate, QStringLiteral("nTDSDSA")))
                continue;
            PublishedDsa dsa;
            dsa.host = host;
            dsa.ntdsDn = candidate.id;
            dsas.append(dsa);
            break;
        }
    }

    std::sort(dsas.begin(), dsas.end(), [](const PublishedDsa &a, const PublishedDsa &b) {
        return a.ntdsDn.compare(b.ntdsDn, Qt::CaseInsensitive) < 0;
    });
    return dsas;
}

QList<ReplicaSource> intrasiteTopology(const QList<DirectoryObject> &objects,
                                       const QString &selfNtdsDn)
{
    QList<ReplicaSource> inbound;
    const QList<PublishedDsa> dsas = intrasiteDsas(objects, selfNtdsDn);
    if (dsas.size() < 2)
        return inbound;

    int self = -1;
    for (int i = 0; i < dsas.size() && self < 0; ++i) {
        if (dsas.at(i).ntdsDn.compare(selfNtdsDn, Qt::CaseInsensitive) == 0)
            self = i;
    }
    if (self < 0)
        return inbound; // this DSA is not published in its own site

    // The predecessor: with two DSAs that is the other one, with three it is a
    // ring (which is the full mesh a site that small has), and every DSA that
    // computes it from the same store gets the same edge.
    const int previous = (self + dsas.size() - 1) % dsas.size();
    ReplicaSource link;
    link.address = dsas.at(previous).host;
    link.sourceDsaDn = dsas.at(previous).ntdsDn;
    link.options = 0x1u; // NTDSCONN_OPT_IS_GENERATED

    // Intrasite connections take their schedule from the site's own NTDS Site
    // Settings when the store publishes one; with none they run always, which
    // an empty schedule means here.
    const QString settingsDn =
        QStringLiteral("CN=NTDS Site Settings,%1").arg(siteOf(selfNtdsDn));
    for (const DirectoryObject &object : objects) {
        if (object.id.compare(settingsDn, Qt::CaseInsensitive) != 0)
            continue;
        link.schedule =
            QByteArray::fromHex(object.attributes.value(QStringLiteral("schedule")).toLatin1());
        break;
    }

    inbound.append(link);
    return inbound;
}

QList<ReplicaSource> synchronize(LdapServer *ldap, const QString &selfNtdsDn)
{
    QList<ReplicaSource> created;
    if (!ldap || selfNtdsDn.isEmpty())
        return created;

    const QList<DirectoryObject> objects = ldap->objects();
    for (const ReplicaSource &link : intrasiteTopology(objects, selfNtdsDn)) {
        // A connection object already naming that DSA, or carrying the same
        // address, is already the path: the KCC does not add a second one for a
        // source this DSA can reach.
        const QString dn = linkDn(selfNtdsDn, link.address);
        bool present = false;
        const QString suffix = QLatin1Char(',') + selfNtdsDn;
        for (const DirectoryObject &object : objects) {
            if (!object.id.endsWith(suffix, Qt::CaseInsensitive))
                continue;
            if (!hasClass(object, QStringLiteral("nTDSConnection")))
                continue;
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0
                || object.attributes.value(QStringLiteral("fromServer"))
                       .compare(link.sourceDsaDn, Qt::CaseInsensitive)
                       == 0) {
                present = true;
                break;
            }
        }
        if (present)
            continue;
        ldap->addObject(connectionObject(objects, selfNtdsDn, link, true));
        created.append(link);
    }
    return created;
}

} // namespace ReplicaTopology
