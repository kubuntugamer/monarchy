// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DCSERVICE_H
#define DCSERVICE_H

#include <QObject>

class LdapServer;
class DnsServer;
class Kdc;
class SamrServer;
class LsadServer;
class NetlogonServer;
class DrsServer;
class EpmServer;
class Smb2Server;

// The domain controller as a standalone unit: loads the provisioned domain's
// dc.conf, owns every service endpoint (LDAP, KDC, DNS, SAMR, LSAD, Netlogon,
// DRSUAPI, EPM, SMB2) and their wiring, and reports what happened to clients
// of the directory. The headless daemon is its only permanent host — exactly
// as LSASS hosts the directory on a Windows DC — so the directory lives as
// long as the service does, not as long as a console window is open; the
// management console is purely a client, like dsa.msc.
class DcService : public QObject
{
    Q_OBJECT

public:
    // A client-side host (tests, tooling) may fall back to the sample
    // directory when no domain is provisioned; the daemon never serves a demo
    // store, so it passes false and refuses to start without one.
    explicit DcService(bool allowSampleFallback = true, QObject *parent = nullptr);

    // dcDir names the provisioned domain directory (dc.conf next to it).
    // Empty means the platform application-data directory, the same location
    // the provisioner writes to by default.
    bool start(const QString &dcDir = QString());

    // Persist the store and the DNS zone; the console calls this on close and
    // the daemon on shutdown. A write at the time it happens is already on
    // disk, so this is the last flush for uncommitted session edits.
    void stop();

    // Naming context of the provisioned domain (or the sample fallback).
    QString baseDn() const { return m_baseDn; }

    // The DNS zone the engine serves, empty when there is none.
    QString dnsZone() const;

signals:
    void statusMessage(const QString &message);

private:
    LdapServer *m_ldapServer = nullptr;
    DnsServer *m_dnsServer = nullptr;
    Kdc *m_kdc = nullptr;
    SamrServer *m_samrServer = nullptr;
    LsadServer *m_lsadServer = nullptr;
    NetlogonServer *m_netlogonServer = nullptr;
    DrsServer *m_drsServer = nullptr;
    EpmServer *m_epmServer = nullptr;
    Smb2Server *m_smbServer = nullptr;

    const bool m_allowSampleFallback = true;
    bool m_started = false;
    // Store and zone locations resolved from dc.conf at start-up.
    QString m_storePath;
    QString m_zonePath;
    QString m_baseDn;
};

#endif // DCSERVICE_H
