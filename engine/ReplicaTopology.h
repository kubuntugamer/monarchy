// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef REPLICATOPOLOGY_H
#define REPLICATOPOLOGY_H

#include "Drs.h"

#include <QList>
#include <QString>
#include <QStringList>

class LdapServer;

// AD keeps a replication link in the directory: DsReplicaAdd writes an
// nTDSConnection object under the DC's own NTDS Settings, and the DRA reads
// those objects back when it starts, which is what makes a registered partner
// outlive the process that registered it. These functions are that round trip.
//
// The object is named after the address it pulls from rather than after the
// source DSA's GUID: DsReplicaDel carries the address and not the GUID, so a
// name derived from the address is the one that can be found again when the
// link is retired.
namespace ReplicaTopology {

// "host", "host:port" or "ncacn_ip_tcp:host[port]" → host and port separately.
void splitAddress(const QString &address, QString *host, quint16 *port);

// This DSA's own vertex in the configuration NC, empty when the store has none.
QString ntdsSettingsDn(const QList<DirectoryObject> &objects);

// CN=<host>[_<port>],<NTDS Settings DN>.
QString linkDn(const QString &ntdsDn, const QString &address);

// Record one link as a connection object. An object already there is left
// alone, so reading a link back and storing it again changes nothing.
bool store(LdapServer *ldap, const ReplicaSource &link, QString *error);

// Retire the connection object an address names.
bool remove(LdapServer *ldap, const QString &address, QString *error);

// The links the directory holds, one entry per naming context each applies to:
// a connection object in AD names the source DSA and covers every NC it holds.
QList<ReplicaSource> links(const QList<DirectoryObject> &objects,
                           const QStringList &namingContexts);

} // namespace ReplicaTopology

#endif // REPLICATOPOLOGY_H
