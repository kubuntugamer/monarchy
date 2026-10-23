// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef CONNECTIONSERVICE_H
#define CONNECTIONSERVICE_H

#include <QObject>
#include <QFuture>
#include <QString>

#ifdef MONARCHY_WITH_LDAP
#include <ldap.h>
#endif

struct ConnectionProfile {
    QString server = QStringLiteral("localhost");
    int port = 389;
    QString baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    QString bindDn;
    QString password;
    bool useKerberos = false;
    bool useTls = false;
};

// Manages a connection to a directory server. The default backend speaks real
// LDAP v3 over TCP via LdapClient (backend/LdapClient). MONARCHY_WITH_LDAP swaps
// in the system OpenLDAP client for SASL/GSSAPI support.
class ConnectionService : public QObject
{
    Q_OBJECT
public:
    explicit ConnectionService(QObject *parent = nullptr);

#ifdef MONARCHY_WITH_LDAP
    LDAP *ldapHandle() const;
#endif

    QFuture<bool> connect(const ConnectionProfile &profile);
    void disconnect();
    bool isConnected() const { return m_connected; }
    QString baseDn() const { return m_baseDn; }
    QString server() const { return m_server; }
    int port() const { return m_port; }
    QString bindDn() const { return m_bindDn; }
    QString password() const { return m_password; }

signals:
    void connectedChanged(bool connected);
    void error(const QString &message);

private:
#ifdef MONARCHY_WITH_LDAP
    LDAP *m_ld = nullptr;
#endif
    bool m_connected = false;
    QString m_baseDn;
    QString m_server;
    int m_port = 389;
    QString m_bindDn;
    QString m_password;
};

#endif // CONNECTIONSERVICE_H