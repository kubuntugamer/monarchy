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
// `selfNtdsDn` is the DSA the connection belongs to; empty takes the store's
// only one, which is what a single-DC store has.
bool store(LdapServer *ldap, const ReplicaSource &link, QString *error,
           const QString &selfNtdsDn = QString());

// Retire the connection object an address names.
bool remove(LdapServer *ldap, const QString &address, QString *error,
            const QString &selfNtdsDn = QString());

// The links the directory holds, one entry per naming context each applies to:
// a connection object in AD names the source DSA and covers every NC it holds.
// Only this DSA's own connections are links: a partner's connection objects
// replicate here too, under its NTDS Settings, and pulling from those would
// make each DC pull whatever the other happens to hold a link for.
QList<ReplicaSource> links(const QList<DirectoryObject> &objects,
                           const QStringList &namingContexts,
                           const QString &selfNtdsDn = QString());

// One DSA published in the configuration NC: the host name its Server object
// carries and the NTDS Settings object that is its vertex.
struct PublishedDsa {
    QString host;
    QString ntdsDn;
};

// Every DSA in the site this one belongs to, sorted by NTDS Settings DN. The
// sort is what makes the topology each DC computes the same one: no process
// state and no private knowledge, only the DN order both stores agree on.
QList<PublishedDsa> intrasiteDsas(const QList<DirectoryObject> &objects,
                                  const QString &selfNtdsDn);

// The inbound connection this DSA's KCC computes for itself: the predecessor in
// that order, so two DSAs pull from each other and three form a ring, which for
// three is also the full mesh every site that small has. Empty when the site
// holds only this DSA.
QList<ReplicaSource> intrasiteTopology(const QList<DirectoryObject> &objects,
                                       const QString &selfNtdsDn);

// The destinations another DC announced with DsReplicaUpdateRefs: the DSAs
// that replicate a naming context from this one. AD keeps them as the source
// DSA's repsTo, one value per destination, which is where these are read from
// and written to, so an announcement outlives the process that received it.
QList<ReplicaDestination> destinations(const QList<DirectoryObject> &objects,
                                       const QString &selfNtdsDn);

// Replace the repsTo values with exactly `destinations`: a registration adds
// one and a list that no longer names a destination is how one is forgotten.
// Empty takes the attribute off the object.
bool storeDestinations(LdapServer *ldap, const QList<ReplicaDestination> &destinations,
                       QString *error, const QString &selfNtdsDn = QString());

// Store the connections intrasiteTopology names that are not already there, as
// the KCC's own: NTDSCONN_OPT_IS_GENERATED set, enabled, and with
// FLAG_CONFIG_ALLOW_RENAME | FLAG_CONFIG_ALLOW_MOVE. A source an administrator
// already gave this DSA — any connection object naming that DSA or address — is
// left alone rather than duplicated. Returns the links it created.
QList<ReplicaSource> synchronize(LdapServer *ldap, const QString &selfNtdsDn);

} // namespace ReplicaTopology

#endif // REPLICATOPOLOGY_H
