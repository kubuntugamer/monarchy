// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "AdminService.h"

#include <QtConcurrent>

AdminService::AdminService(DirectoryService *directory, QObject *parent)
    : QObject(parent)
    , m_directory(directory)
{
}

QFuture<bool> AdminService::createUser(const QString &name, const QString &containerDn, const QString &password)
{
    DirectoryObject obj;
    obj.kind = ObjectKind::User;
    obj.name = name.trimmed();
    obj.type = QStringLiteral("User");
    obj.description = tr("Newly created user");
    obj.container = containerDn;
    obj.id = QStringLiteral("CN=%1,%2").arg(obj.name, containerDn);
    QString account = obj.name; account.remove(QLatin1Char(' ')); account = account.toLower();
    obj.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    obj.attributes.insert(QStringLiteral("cn"), obj.name);
    obj.attributes.insert(QStringLiteral("sAMAccountName"), account);
    // AD's password attribute; the server stores a salted verifier, never this.
    obj.attributes.insert(QStringLiteral("unicodePwd"), password);
    obj.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));

    if (!m_directory) return QtConcurrent::run([]() { return false; });
    return m_directory->addObject(obj);
}

QFuture<bool> AdminService::createGroup(const QString &name, const QString &containerDn)
{
    DirectoryObject obj;
    obj.kind = ObjectKind::Group;
    obj.name = name.trimmed();
    obj.type = QStringLiteral("Security Group");
    obj.description = tr("Newly created group");
    obj.container = containerDn;
    obj.id = QStringLiteral("CN=%1,%2").arg(obj.name, containerDn);
    obj.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("group"));
    obj.attributes.insert(QStringLiteral("cn"), obj.name);
    obj.attributes.insert(QStringLiteral("groupType"), QStringLiteral("Security"));

    if (!m_directory) return QtConcurrent::run([]() { return false; });
    return m_directory->addObject(obj);
}

QFuture<bool> AdminService::createComputer(const QString &name, const QString &containerDn)
{
    DirectoryObject obj;
    obj.kind = ObjectKind::Computer;
    obj.name = name.trimmed().toUpper();
    obj.type = QStringLiteral("Computer");
    obj.description = tr("Newly created computer");
    obj.container = containerDn;
    obj.id = QStringLiteral("CN=%1,%2").arg(obj.name, containerDn);
    obj.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("computer"));
    obj.attributes.insert(QStringLiteral("cn"), obj.name);
    obj.attributes.insert(QStringLiteral("dNSHostName"), name.toLower() + QStringLiteral(".corp.example.com"));

    if (!m_directory) return QtConcurrent::run([]() { return false; });
    return m_directory->addObject(obj);
}

QFuture<bool> AdminService::createOu(const QString &name, const QString &parentDn)
{
    DirectoryObject obj;
    obj.kind = ObjectKind::Ou;
    obj.name = name.trimmed();
    obj.type = QStringLiteral("Organizational Unit");
    obj.description = tr("Newly created OU");
    obj.container = parentDn;
    obj.id = QStringLiteral("OU=%1,%2").arg(obj.name, parentDn);
    obj.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("organizationalUnit"));
    obj.attributes.insert(QStringLiteral("ou"), obj.name);

    if (!m_directory) return QtConcurrent::run([]() { return false; });
    return m_directory->addObject(obj);
}

QFuture<bool> AdminService::resetPassword(const QString &userDn, const QString &newPassword, bool mustChange)
{
    if (!m_directory) return QtConcurrent::run([]() { return false; });
    QMap<QString, QString> attrs;
    attrs.insert(QStringLiteral("unicodePwd"), newPassword);
    if (mustChange) attrs.insert(QStringLiteral("pwdLastSet"), QStringLiteral("0"));
    return m_directory->modifyObject(userDn, attrs);
}

QFuture<bool> AdminService::addMember(const QString &groupDn, const QString &memberDn)
{
    if (!m_directory) return QtConcurrent::run([]() { return false; });
    // Read-modify-write on one connection: appending a member must never drop
    // the members already in the group.
    return m_directory->modifyValues(groupDn, QStringLiteral("member"), {memberDn}, {});
}

QFuture<bool> AdminService::removeMember(const QString &groupDn, const QString &memberDn)
{
    if (!m_directory) return QtConcurrent::run([]() { return false; });
    return m_directory->modifyValues(groupDn, QStringLiteral("member"), {}, {memberDn});
}

QFuture<bool> AdminService::addUserToGroup(const QString &userDn, const QString &groupDn)
{
    return addMember(groupDn, userDn);
}

QFuture<bool> AdminService::removeUserFromGroup(const QString &userDn, const QString &groupDn)
{
    return removeMember(groupDn, userDn);
}