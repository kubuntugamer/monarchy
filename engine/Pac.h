// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PAC_H
#define PAC_H

#include <QByteArray>
#include <QList>
#include <QString>

#include "resultsmodel.h"

// The Privilege Attribute Certificate (MS-PAC) AD puts in every ticket: the
// client's SID, domain SID, group RIDs and logon information, sealed with the
// service key and again with the krbtgt key. Services use it for authorization
// without another directory lookup.
namespace Pac {

// Keys the two signatures are made with: the service's own key for the server
// checksum, krbtgt for the KDC checksum.
struct Keys {
    QByteArray serviceKey;
    int serviceEtype = 0;
    QByteArray kdcKey;
    int kdcEtype = 0;

    bool isValid() const { return !serviceKey.isEmpty() && !kdcKey.isEmpty(); }
};

// Builds a PAC for `client`. Group RIDs come from the groups in `directory`
// that list the client, the primary group is Domain Users (513). `authtime`
// is the ticket's authentication time, which the PAC carries in its
// PAC_CLIENT_INFO so verifiers can match it against the ticket.
QByteArray build(const DirectoryObject &client, const QString &realm, const QString &netbios,
                 const QString &domainSid, const QList<DirectoryObject> &directory,
                 const Keys &keys, qint64 authtime = 0);

// Re-signs an existing PAC for a new service (TGT -> service ticket).
QByteArray resign(const QByteArray &pac, const Keys &keys);

// Verifies the server and KDC signatures; returns false on any damage.
bool verify(const QByteArray &pac, const Keys &keys);

// AuthorizationData carrying the PAC as AD-IF-RELEVANT { AD-WIN2K-PAC }.
QByteArray authorizationData(const QByteArray &pac);
// Pulls the PAC back out of an EncTicketPart's authorization-data.
QByteArray extract(const QByteArray &authorizationData);

// Directory RID of an object, from its objectSid (0 when it has none).
quint32 ridOf(const DirectoryObject &object);

// What a service reads out of KERB_VALIDATION_INFO for authorization: the
// account's RID, its primary group and every group it belongs to.
struct Identity {
    quint32 userId = 0;
    quint32 primaryGroupId = 0;
    QList<quint32> groupIds;

    bool isMemberOf(quint32 rid) const
    {
        return rid != 0 && (primaryGroupId == rid || groupIds.contains(rid));
    }
};

// Parses LOGON_INFO out of a PAC. Returns false when the buffer is missing or
// malformed; the signatures must already have been verified.
bool readIdentity(const QByteArray &pac, Identity *identity);

} // namespace Pac

#endif // PAC_H
