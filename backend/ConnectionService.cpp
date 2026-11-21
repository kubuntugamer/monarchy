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
        QString baseDn = profile.baseDn;
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
        } else if (!profile.bindDn.isEmpty() && !profile.password.isEmpty()) {
            QByteArray dn = profile.bindDn.toUtf8();
            QByteArray pw = profile.password.toUtf8();
            struct berval cred = { (ber_len_t)pw.size(), pw.data() };
            rc = ldap_sasl_bind_s(ld, dn.constData(), LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
        } else {
            // A DN with no password is AD's "unauthenticated bind", which the DC
            // refuses with invalid credentials (49). A profile that remembers the
            // bind DN but not the password — every launch, since the password is
            // never written to disk — would then never connect at all. Bind
            // anonymously instead, the way AD's own tools fall back to the
            // logged-on session.
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

        // The naming context the way AD's own tools find it: ask the root DSE
        // instead of guessing a DN. dc.conf is not readable by the account the
        // console runs as, so on a real install this is the only source of the
        // browse base.
        if (baseDn.isEmpty()) {
            char *attrs[] = { const_cast<char *>("defaultNamingContext"), nullptr };
            LDAPMessage *res = nullptr;
            if (ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0,
                                  nullptr, nullptr, nullptr, 0, &res) == LDAP_SUCCESS) {
                struct berval **values = ldap_get_values_len(
                    ld, ldap_first_entry(ld, res), "defaultNamingContext");
                if (values && values[0] && values[0]->bv_len > 0)
                    baseDn = QString::fromUtf8(values[0]->bv_val, int(values[0]->bv_len));
                if (values)
                    ldap_value_free_len(values);
            }
            if (res)
                ldap_msgfree(res);
            if (baseDn.isEmpty()) {
                const QString message =
                    QStringLiteral("The server at %1:%2 publishes no naming context; "
                                   "enter a base DN to browse it.")
                        .arg(profile.server)
                        .arg(profile.port);
                QMetaObject::invokeMethod(this, [this, message] { emit error(message); },
                                          Qt::QueuedConnection);
                ldap_unbind_ext_s(ld, nullptr, nullptr);
                return false;
            }
        }

        m_ld = ld;

        m_server = profile.server;
        m_port = profile.port;
        m_bindDn = profile.bindDn;
        m_password = profile.password;
        m_baseDn = baseDn;
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
            // A DN with no password is AD's "unauthenticated bind", refused with
            // invalid credentials (49); the password is never written to disk, so
            // a saved profile always looks like that on launch. Bind anonymously
            // instead, the way AD's own tools fall back to the logged-on session.
            const bool useBindDn = !profile.bindDn.isEmpty() && !profile.password.isEmpty();
            if (!client.bind(useBindDn ? profile.bindDn : QString(),
                             useBindDn ? profile.password : QString(), &err)) {
                QMetaObject::invokeMethod(this, [this, err] { emit error(err); },
                                          Qt::QueuedConnection);
                client.close();
                return false;
            }
            if (baseDn.isEmpty()) {
                // Take the naming context from the root DSE, the way AD's own
                // tools do, instead of guessing a DN that may not exist here.
                const QList<LdapClient::Entry> rootDse =
                    client.search(QString(), 0, QStringLiteral("(objectClass=*)"),
                                  {QStringLiteral("defaultNamingContext")}, &err);
                const QStringList naming = rootDse.isEmpty()
                                               ? QStringList()
                                               : rootDse.first().attrs.value(
                                                     QStringLiteral("defaultNamingContext"));
                if (naming.isEmpty() || naming.first().isEmpty()) {
                    const QString message =
                        QStringLiteral("The server at %1:%2 publishes no naming context; "
                                       "enter a base DN to browse it.")
                            .arg(profile.server)
                            .arg(profile.port);
                    QMetaObject::invokeMethod(this, [this, message] { emit error(message); },
                                              Qt::QueuedConnection);
                    client.close();
                    return false;
                }
                baseDn = naming.first();
            }
            client.close();
        }
        m_server = profile.server;
        m_port = profile.port;
        m_bindDn = profile.bindDn;
        m_password = profile.password;
        m_baseDn = baseDn;
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