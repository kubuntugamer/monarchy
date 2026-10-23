// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ConnectionService.h"
#include "LdapClient.h"

#include <QtConcurrent>

#ifdef MONARCHY_WITH_LDAP
#include <ldap.h>
#endif

ConnectionService::ConnectionService(QObject *parent)
    : QObject(parent)
{
}

QFuture<bool> ConnectionService::connect(const ConnectionProfile &profile)
{
    return QtConcurrent::run([this, profile]() {
#ifdef MONARCHY_WITH_LDAP
        LDAP *ld = nullptr;
        int rc = ldap_initialize(&ld, (profile.useTls ? QStringLiteral("ldaps://") : QStringLiteral("ldap://"))
                                          .append(profile.server).append(':').append(QString::number(profile.port)).toUtf8().constData());
        if (rc != LDAP_SUCCESS) {
            QMetaObject::invokeMethod(this, [this, rc] {
                emit error(QStringLiteral("ldap_initialize failed: %1").arg(rc));
            }, Qt::QueuedConnection);
            return false;
        }

        // Protocol version 3.
        int version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

        if (profile.useTls && !profile.useTls) { /* placeholder */ }

        if (profile.useKerberos) {
            rc = ldap_sasl_bind_s(ld, nullptr, "GSSAPI", nullptr, nullptr, nullptr, nullptr);
        } else if (!profile.bindDn.isEmpty()) {
            QByteArray dn = profile.bindDn.toUtf8();
            QByteArray pw = profile.password.toUtf8();
            struct berval cred = { (ber_len_t)pw.size(), pw.data() };
            rc = ldap_sasl_bind_s(ld, dn.constData(), LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
        } else {
            rc = ldap_sasl_bind_s(ld, nullptr, LDAP_SASL_SIMPLE, nullptr, nullptr, nullptr, nullptr);
        }

        if (rc != LDAP_SUCCESS) {
            const char *msg = ldap_err2string(rc);
            QMetaObject::invokeMethod(this, [this, msg] {
                emit error(QString::fromUtf8(msg));
            }, Qt::QueuedConnection);
            if (ld) ldap_unbind_ext_s(ld, nullptr, nullptr);
            return false;
        }

        m_ld = ld;

        m_server = profile.server;
        m_port = profile.port;
        m_bindDn = profile.bindDn;
        m_password = profile.password;
        m_baseDn = profile.baseDn.isEmpty() ? QStringLiteral("DC=corp,DC=example,DC=com")
                                           : profile.baseDn;
        m_connected = true;
        QMetaObject::invokeMethod(this, [this] { emit connectedChanged(true); },
                                  Qt::QueuedConnection);
        return true;
#else
        // Real LDAP v3 over TCP: probe the server with a bind.
        {
            if (profile.useTls || profile.useKerberos) {
                const QString message = QStringLiteral(
                    "This build supports plain LDAP simple binds only. "
                    "Rebuild with -DMONARCHY_WITH_LDAP=ON for LDAPS and Kerberos/GSSAPI.");
                QMetaObject::invokeMethod(this, [this, message] { emit error(message); },
                                          Qt::QueuedConnection);
                return false;
            }
            LdapClient client;
            QString err;
            if (!client.open(profile.server, quint16(profile.port), &err)) {
                QMetaObject::invokeMethod(this, [this, err] { emit error(err); },
                                          Qt::QueuedConnection);
                return false;
            }
            if (!client.bind(profile.bindDn, profile.password, &err)) {
                QMetaObject::invokeMethod(this, [this, err] { emit error(err); },
                                          Qt::QueuedConnection);
                client.close();
                return false;
            }
            client.close();
        }
        m_server = profile.server;
        m_port = profile.port;
        m_bindDn = profile.bindDn;
        m_password = profile.password;
        m_baseDn = profile.baseDn.isEmpty() ? QStringLiteral("DC=corp,DC=example,DC=com")
                                           : profile.baseDn;
        m_connected = true;
        QMetaObject::invokeMethod(this, [this] { emit connectedChanged(true); },
                                  Qt::QueuedConnection);
        return true;
#endif
    });
}

void ConnectionService::disconnect()
{
#ifdef MONARCHY_WITH_LDAP
    if (m_ld) {
        ldap_unbind_ext_s(m_ld, nullptr, nullptr);
        m_ld = nullptr;
    }
#endif
    m_connected = false;
    m_baseDn.clear();
    m_server.clear();
    emit connectedChanged(false);
}

#ifdef MONARCHY_WITH_LDAP
LDAP *ConnectionService::ldapHandle() const
{
    return m_ld;
}
#endif