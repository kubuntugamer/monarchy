// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DirectoryService.h"
#include "ConnectionService.h"
#include "LdapClient.h"

#include <QSet>
#include <QtConcurrent>

#ifdef MONARCHY_WITH_LDAP
#include <ldap.h>
#include <cstdlib>
#include <cstring>
#endif

namespace {

// Build the attribute set for a newly created entry. Callers often set the
// display fields (name/description/kind) rather than duplicating them in the
// attribute map, so fill in the schema-required values here.
QMap<QString, QString> attributesForAdd(const DirectoryObject &object)
{
    QMap<QString, QString> attributes = object.attributes;
    if (!object.name.isEmpty() && !attributes.contains(QStringLiteral("cn")))
        attributes.insert(QStringLiteral("cn"), object.name);
    if (!object.description.isEmpty() && !attributes.contains(QStringLiteral("description")))
        attributes.insert(QStringLiteral("description"), object.description);
    if (!attributes.contains(QStringLiteral("objectClass"))) {
        switch (object.kind) {
        case ObjectKind::User:
            attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
            break;
        case ObjectKind::Group:
            attributes.insert(QStringLiteral("objectClass"), QStringLiteral("group"));
            break;
        case ObjectKind::Computer:
            attributes.insert(QStringLiteral("objectClass"), QStringLiteral("computer"));
            break;
        case ObjectKind::Ou:
            attributes.insert(QStringLiteral("objectClass"), QStringLiteral("organizationalUnit"));
            break;
        default:
            attributes.insert(QStringLiteral("objectClass"), QStringLiteral("top"));
            break;
        }
    }
    return attributes;
}

// Attributes maintained by the server; a client must not replace them.
bool isServerMaintainedAttribute(const QString &name)
{
    static const QSet<QString> names = {
        QStringLiteral("distinguishedname"),
        QStringLiteral("objectclass"),
        QStringLiteral("objectguid"),
        QStringLiteral("objectsid"),
        QStringLiteral("usncreated"),
        QStringLiteral("usnchanged"),
        QStringLiteral("whencreated"),
        QStringLiteral("whenchanged"),
        QStringLiteral("instancetype"),
        QStringLiteral("samaccounttype"),
        QStringLiteral("memberof"),
        QStringLiteral("userpasswordhash"),
        QStringLiteral("userpasswordsalt"),
        QStringLiteral("passwordscheme"),
    };
    return names.contains(name.toLower());
}

// Map an LDAP entry to the console's DirectoryObject view.
DirectoryObject objectFromEntry(const LdapClient::Entry &e)
{
    DirectoryObject obj;
    obj.id = e.dn;

    const QStringList cns = e.attrs.value(QStringLiteral("cn"));
    if (!cns.isEmpty())
        obj.name = cns.first();
    if (obj.name.isEmpty()) {
        const QString firstRdn = e.dn.section(QLatin1Char(','), 0, 0);
        obj.name = firstRdn.mid(firstRdn.indexOf(QLatin1Char('=')) + 1);
    }

    const QStringList descs = e.attrs.value(QStringLiteral("description"));
    if (!descs.isEmpty())
        obj.description = descs.first();

    for (auto it = e.attrs.constBegin(); it != e.attrs.constEnd(); ++it)
        obj.attributes.insert(it.key(), it.value().join(QStringLiteral("; ")));

    const QString oc = e.attrs.value(QStringLiteral("objectClass")).join(QLatin1Char(' ')).toLower();
    if (oc.contains(QStringLiteral("computer")))
        obj.kind = ObjectKind::Computer;
    else if (oc.contains(QStringLiteral("organizationalunit")))
        obj.kind = ObjectKind::Ou;
    else if (oc.contains(QStringLiteral("group")))
        obj.kind = ObjectKind::Group;
    else if (oc.contains(QStringLiteral("user")))
        obj.kind = ObjectKind::User;
    else
        obj.kind = ObjectKind::Unknown;

    obj.type = (obj.kind == ObjectKind::User) ? QStringLiteral("User")
              : (obj.kind == ObjectKind::Group) ? QStringLiteral("Security Group")
              : (obj.kind == ObjectKind::Computer) ? QStringLiteral("Computer")
              : (obj.kind == ObjectKind::Ou) ? QStringLiteral("Organizational Unit")
              : QStringLiteral("Object");

    const QStringList members = e.attrs.value(QStringLiteral("member"));
    if (!members.isEmpty())
        obj.members = members;
    const QStringList memberOf = e.attrs.value(QStringLiteral("memberOf"));
    if (!memberOf.isEmpty())
        obj.memberOf = memberOf;

    // Console container heuristic (until the tree loads OUs from the server):
    // AD keeps users and groups in CN=Users and computers in CN=Computers, but
    // the console presents them as separate nodes. Map those two parents by
    // object kind; every other container keeps its real RDN name.
    const QString parentRdn = e.dn.section(QLatin1Char(','), 1, 1);
    const QString parentName = parentRdn.mid(parentRdn.indexOf(QLatin1Char('=')) + 1);
    if (parentRdn.compare(QStringLiteral("CN=Users"), Qt::CaseInsensitive) == 0) {
        obj.container = (obj.kind == ObjectKind::Group) ? QStringLiteral("Groups")
                                                        : QStringLiteral("Users");
    } else if (parentRdn.compare(QStringLiteral("CN=Computers"), Qt::CaseInsensitive) == 0) {
        obj.container = QStringLiteral("Computers");
    } else {
        obj.container = parentName;
    }
    if (obj.container.isEmpty())
        obj.container = QStringLiteral("Console Root");

    return obj;
}

} // namespace

DirectoryService::DirectoryService(ConnectionService *connection, QObject *parent)
    : QObject(parent)
    , m_connection(connection)
{
}

QFuture<QList<DirectoryObject>> DirectoryService::search(const QString &baseDn, const QString &filter,
                                                         const QStringList &attributes, int pageSize)
{
#ifdef MONARCHY_WITH_LDAP
    if (m_connection && m_connection->ldapHandle()) {
        return QtConcurrent::run([this, baseDn, filter, attributes, pageSize]() {
            QList<DirectoryObject> result;
            LDAP *ld = m_connection->ldapHandle();
            const QString base = baseDn.isEmpty() ? m_connection->baseDn() : baseDn;
            QByteArray baseUtf8 = base.toUtf8();
            QByteArray filterUtf8 = filter.isEmpty() ? QByteArray("(objectClass=*)") : filter.toUtf8();

            LDAPMessage *res = nullptr;
            int rc = ldap_search_ext_s(ld, baseUtf8.constData(), LDAP_SCOPE_SUBTREE,
                                      filterUtf8.constData(), nullptr, 0, nullptr, nullptr,
                                      nullptr, pageSize, &res);
            if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
                return result;
            }

            for (LDAPMessage *e = ldap_first_entry(ld, res); e != nullptr; e = ldap_next_entry(ld, e)) {
                LdapClient::Entry entry;
                char *dn = ldap_get_dn(ld, e);
                if (dn) {
                    entry.dn = QString::fromUtf8(dn);
                    ldap_memfree(dn);
                }
                BerElement *ber = nullptr;
                char *type = ldap_first_attribute(ld, e, &ber);
                while (type) {
                    QStringList vals;
                    struct berval **bvals = ldap_get_values_len(ld, e, type);
                    for (struct berval **valsIt = bvals; valsIt && *valsIt; ++valsIt)
                        vals.append(QString::fromUtf8((*valsIt)->bv_val, int((*valsIt)->bv_len)));
                    if (bvals)
                        ldap_value_free_len(bvals);
                    entry.attrs.insert(QString::fromUtf8(type), vals);
                    ldap_memfree(type);
                    type = ldap_next_attribute(ld, e, ber);
                }
                if (ber)
                    ber_free(ber, 0);
                if (!entry.dn.isEmpty())
                    result.append(objectFromEntry(entry));
            }

            if (res) ldap_msgfree(res);
            return result;
        });
    }
#endif
    // Real LDAP v3 over TCP via the wire client.
    return QtConcurrent::run([this, baseDn, filter, attributes]() {
        QList<DirectoryObject> result;
        if (!m_connection || !m_connection->isConnected()) {
            emit error(QStringLiteral("Not connected to a directory server."));
            return result;
        }
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)) {
            emit error(err);
            return result;
        }
        if (!client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return result;
        }
        const QString base = baseDn.isEmpty() ? m_connection->baseDn() : baseDn;
        const auto entries = client.search(base, 2 /*subtree*/, filter, attributes, &err);
        if (!err.isEmpty())
            emit error(err);
        for (const LdapClient::Entry &e : entries) {
            if (e.dn.isEmpty()) // root DSE is not a console object
                continue;
            result.append(objectFromEntry(e));
        }
        client.close();
        return result;
    });
}

QFuture<QList<DirectoryObject>> DirectoryService::listContainers(const QString &parentDn)
{
    return search(parentDn, QStringLiteral("(objectClass=container)"), QStringList());
}

QFuture<bool> DirectoryService::modifyValues(const QString &dn, const QString &attribute,
                                            const QStringList &add, const QStringList &remove)
{
#ifdef MONARCHY_WITH_LDAP
    // Same handle as the rest of the OpenLDAP build, so the operation honours
    // whatever transport (LDAPS/StartTLS/GSSAPI) the connection was opened with.
    if (m_connection && m_connection->ldapHandle()) {
        return QtConcurrent::run([this, dn, attribute, add, remove]() {
            LDAP *ld = m_connection->ldapHandle();
            const QByteArray dnUtf8 = dn.toUtf8();
            const QByteArray attrUtf8 = attribute.toUtf8();
            char *attrs[2] = {const_cast<char *>(attrUtf8.constData()), nullptr};

            LDAPMessage *res = nullptr;
            int rc = ldap_search_ext_s(ld, dnUtf8.constData(), LDAP_SCOPE_BASE,
                                       "(objectClass=*)", attrs, 0, nullptr, nullptr, nullptr, 1,
                                       &res);
            if (rc != LDAP_SUCCESS) {
                emit error(QString::fromUtf8(ldap_err2string(rc)));
                if (res) ldap_msgfree(res);
                return false;
            }

            QStringList values;
            if (LDAPMessage *entry = ldap_first_entry(ld, res)) {
                struct berval **found = ldap_get_values_len(ld, entry, attrUtf8.constData());
                for (struct berval **it = found; it && *it; ++it)
                    values.append(QString::fromUtf8((*it)->bv_val, int((*it)->bv_len)));
                if (found) ldap_value_free_len(found);
            }
            if (res) ldap_msgfree(res);

            for (const QString &value : add) {
                if (!values.contains(value, Qt::CaseInsensitive))
                    values.append(value);
            }
            for (const QString &value : remove) {
                for (int i = values.size() - 1; i >= 0; --i) {
                    if (values.at(i).compare(value, Qt::CaseInsensitive) == 0)
                        values.removeAt(i);
                }
            }

            QList<QByteArray> storage;
            storage.reserve(values.size());
            for (const QString &value : values)
                storage.append(value.toUtf8());
            struct berval **bvals =
                (struct berval **)calloc(storage.size() + 1, sizeof(struct berval *));
            for (int i = 0; i < storage.size(); ++i) {
                bvals[i] = (struct berval *)calloc(1, sizeof(struct berval));
                bvals[i]->bv_len = size_t(storage[i].size());
                bvals[i]->bv_val = (char *)malloc(size_t(storage[i].size()) + 1);
                memcpy(bvals[i]->bv_val, storage[i].constData(), size_t(storage[i].size()));
                bvals[i]->bv_val[storage[i].size()] = '\0';
            }
            bvals[storage.size()] = nullptr;

            LDAPMod mod;
            memset(&mod, 0, sizeof(mod));
            mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
            mod.mod_type = const_cast<char *>(attrUtf8.constData());
            mod.mod_vals.modv_bvals = bvals;
            LDAPMod *mods[2] = {&mod, nullptr};

            rc = ldap_modify_ext_s(ld, dnUtf8.constData(), mods, nullptr, nullptr);
            for (int i = 0; i < storage.size(); ++i) {
                free(bvals[i]->bv_val);
                free(bvals[i]);
            }
            free(bvals);
            if (rc != LDAP_SUCCESS)
                emit error(QString::fromUtf8(ldap_err2string(rc)));
            return rc == LDAP_SUCCESS;
        });
    }
#endif
    return QtConcurrent::run([this, dn, attribute, add, remove]() {
        if (!m_connection || !m_connection->isConnected()) {
            emit error(QStringLiteral("Not connected to a directory server."));
            return false;
        }
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)
            || !client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return false;
        }
        QStringList values;
        const auto entries = client.search(dn, 0 /*base*/, QStringLiteral("(objectClass=*)"),
                                           QStringList{attribute}, &err);
        if (!entries.isEmpty())
            values = entries.first().attrs.value(attribute);
        for (const QString &value : add) {
            if (!values.contains(value, Qt::CaseInsensitive))
                values.append(value);
        }
        for (const QString &value : remove) {
            for (int i = values.size() - 1; i >= 0; --i) {
                if (values.at(i).compare(value, Qt::CaseInsensitive) == 0)
                    values.removeAt(i);
            }
        }
        QMap<QString, QStringList> change;
        change.insert(attribute, values);
        const bool ok = client.modify(dn, change, &err);
        if (!ok)
            emit error(err);
        client.close();
        return ok;
    });
}

QFuture<QMap<QString, QString>> DirectoryService::getAttributes(const QString &dn)
{
    return QtConcurrent::run([this, dn]() {
        QMap<QString, QString> attrs;
        attrs.insert(QStringLiteral("distinguishedName"), dn);
        if (!m_connection || !m_connection->isConnected())
            return attrs;
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)) {
            emit error(err);
            return attrs;
        }
        if (!client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return attrs;
        }
        const auto entries = client.search(dn, 0 /*base*/, QStringLiteral("(objectClass=*)"),
                                           QStringList(), &err);
        if (!entries.isEmpty()) {
            for (auto it = entries.first().attrs.constBegin(); it != entries.first().attrs.constEnd(); ++it)
                attrs.insert(it.key(), it.value().join(QStringLiteral("; ")));
        }
        client.close();
        return attrs;
    });
}

QFuture<bool> DirectoryService::addObject(const DirectoryObject &object)
{
#ifdef MONARCHY_WITH_LDAP
    if (m_connection && m_connection->ldapHandle()) {
        return QtConcurrent::run([this, object]() {
            LDAP *ld = m_connection->ldapHandle();
            const QMap<QString, QString> attributes = attributesForAdd(object);
            LDAPMod **mods = (LDAPMod **)calloc(attributes.size() + 1, sizeof(LDAPMod *));
            int i = 0;
            for (auto it = attributes.begin(); it != attributes.end(); ++it) {
                LDAPMod *m = (LDAPMod *)calloc(1, sizeof(LDAPMod));
                m->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
                m->mod_type = strdup(it.key().toUtf8().constData());
                struct berval **bvals = (struct berval **)calloc(2, sizeof(struct berval *));
                bvals[0] = (struct berval *)calloc(1, sizeof(struct berval));
                QByteArray v = it.value().toUtf8();
                bvals[0]->bv_val = (char *)malloc(v.size() + 1);
                memcpy(bvals[0]->bv_val, v.constData(), v.size());
                bvals[0]->bv_val[v.size()] = '\0';
                bvals[0]->bv_len = v.size();
                bvals[1] = nullptr;
                m->mod_vals.modv_bvals = bvals;
                mods[i++] = m;
            }
            mods[i] = nullptr;
            QByteArray dn = object.id.toUtf8();
            LDAPMod **modsPtr = mods;
            int rc = ldap_add_ext_s(ld, dn.constData(), modsPtr, nullptr, nullptr);
            for (int j = 0; j < i; j++) {
                if (mods[j]->mod_type) free(mods[j]->mod_type);
                if (mods[j]->mod_vals.modv_bvals) {
                    if (mods[j]->mod_vals.modv_bvals[0] && mods[j]->mod_vals.modv_bvals[0]->bv_val)
                        free(mods[j]->mod_vals.modv_bvals[0]->bv_val);
                    if (mods[j]->mod_vals.modv_bvals[0]) free(mods[j]->mod_vals.modv_bvals[0]);
                    free(mods[j]->mod_vals.modv_bvals);
                }
                free(mods[j]);
            }
            free(mods);
            return rc == LDAP_SUCCESS;
        });
    }
#endif
    return QtConcurrent::run([this, object]() {
        if (!m_connection || !m_connection->isConnected())
            return false;
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)) {
            emit error(err);
            return false;
        }
        if (!client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return false;
        }
        QMap<QString, QStringList> attrs;
        const QMap<QString, QString> attributes = attributesForAdd(object);
        for (auto it = attributes.constBegin(); it != attributes.constEnd(); ++it)
            attrs.insert(it.key(), it.value().split(QStringLiteral("; ")));
        const bool ok = client.add(object.id, attrs, &err);
        if (!ok)
            emit error(err);
        client.close();
        return ok;
    });
}

QFuture<bool> DirectoryService::removeObject(const QString &dn)
{
#ifdef MONARCHY_WITH_LDAP
    if (m_connection && m_connection->ldapHandle()) {
        return QtConcurrent::run([this, dn]() {
            LDAP *ld = m_connection->ldapHandle();
            QByteArray d = dn.toUtf8();
            return ldap_delete_ext_s(ld, d.constData(), nullptr, nullptr) == LDAP_SUCCESS;
        });
    }
#endif
    return QtConcurrent::run([this, dn]() {
        if (!m_connection || !m_connection->isConnected())
            return false;
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)) {
            emit error(err);
            return false;
        }
        if (!client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return false;
        }
        const bool ok = client.del(dn, &err);
        if (!ok)
            emit error(err);
        client.close();
        return ok;
    });
}

QFuture<bool> DirectoryService::modifyObject(const QString &dn, const QMap<QString, QString> &attributes)
{
#ifdef MONARCHY_WITH_LDAP
    if (m_connection && m_connection->ldapHandle()) {
        return QtConcurrent::run([this, dn, attributes]() {
            LDAP *ld = m_connection->ldapHandle();
            LDAPMod **mods = (LDAPMod **)calloc(attributes.size() + 1, sizeof(LDAPMod *));
            int i = 0;
            for (auto it = attributes.begin(); it != attributes.end(); ++it) {
                if (isServerMaintainedAttribute(it.key()))
                    continue;
                LDAPMod *m = (LDAPMod *)calloc(1, sizeof(LDAPMod));
                m->mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
                m->mod_type = strdup(it.key().toUtf8().constData());
                struct berval **bvals = (struct berval **)calloc(2, sizeof(struct berval *));
                bvals[0] = (struct berval *)calloc(1, sizeof(struct berval));
                QByteArray v = it.value().toUtf8();
                bvals[0]->bv_val = (char *)malloc(v.size() + 1);
                memcpy(bvals[0]->bv_val, v.constData(), v.size());
                bvals[0]->bv_val[v.size()] = '\0';
                bvals[0]->bv_len = v.size();
                bvals[1] = nullptr;
                m->mod_vals.modv_bvals = bvals;
                mods[i++] = m;
            }
            mods[i] = nullptr;
            QByteArray d = dn.toUtf8();
            int rc = ldap_modify_ext_s(ld, d.constData(), mods, nullptr, nullptr);
            for (int j = 0; j < i; j++) {
                if (mods[j]->mod_type) free(mods[j]->mod_type);
                if (mods[j]->mod_vals.modv_bvals) {
                    if (mods[j]->mod_vals.modv_bvals[0] && mods[j]->mod_vals.modv_bvals[0]->bv_val)
                        free(mods[j]->mod_vals.modv_bvals[0]->bv_val);
                    if (mods[j]->mod_vals.modv_bvals[0]) free(mods[j]->mod_vals.modv_bvals[0]);
                    free(mods[j]->mod_vals.modv_bvals);
                }
                free(mods[j]);
            }
            free(mods);
            return rc == LDAP_SUCCESS;
        });
    }
#endif
    return QtConcurrent::run([this, dn, attributes]() {
        if (!m_connection || !m_connection->isConnected())
            return false;
        LdapClient client;
        QString err;
        if (!client.open(m_connection->server(), quint16(m_connection->port()), &err)) {
            emit error(err);
            return false;
        }
        if (!client.bind(m_connection->bindDn(), m_connection->password(), &err)) {
            emit error(err);
            client.close();
            return false;
        }
        QMap<QString, QStringList> mods;
        for (auto it = attributes.constBegin(); it != attributes.constEnd(); ++it) {
            if (isServerMaintainedAttribute(it.key()))
                continue;
            // A password is one value and may contain the list separator.
            const bool password = it.key().compare(QLatin1String("unicodePwd"),
                                                   Qt::CaseInsensitive) == 0
                                  || it.key().compare(QLatin1String("userPassword"),
                                                      Qt::CaseInsensitive) == 0;
            mods.insert(it.key(), password ? QStringList{it.value()}
                                           : it.value().split(QStringLiteral("; ")));
        }
        if (mods.isEmpty())
            return true;
        const bool ok = client.modify(dn, mods, &err);
        if (!ok)
            emit error(err);
        client.close();
        return ok;
    });
}
