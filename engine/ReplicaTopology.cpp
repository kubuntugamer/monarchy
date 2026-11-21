// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ReplicaTopology.h"

#include "LdapServer.h"
#include "resultsmodel.h"

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

    // A level-2 add names the source DSA, and that DN is the fromServer AD
    // writes. A level-1 add carries only the address, so the source server is
    // named from it — the address stays what the pull actually uses.
    QString host;
    quint16 port = 0;
    splitAddress(link.address, &host, &port);
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
    object.attributes.insert(QStringLiteral("options"), QString::number(link.options));
    if (!link.schedule.isEmpty())
        object.attributes.insert(QStringLiteral("schedule"), link.schedule.toHex());
    ldap->addObject(object);
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

} // namespace ReplicaTopology
