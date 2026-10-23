// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "SampleData.h"

#include <QStringList>

namespace {

DirectoryObject makeUser(const QString &name, const QString &givenName,
                         const QString &surname, const QString &description,
                         const QString &office, const QString &telephone,
                         const QString &email, const QStringList &memberOf)
{
    DirectoryObject object;
    object.kind = ObjectKind::User;
    object.name = name;
    object.type = QStringLiteral("User");
    object.description = description;
    object.container = QStringLiteral("Users");
    object.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(name);
    object.memberOf = memberOf;

    QString account = name;
    account.remove(QLatin1Char(' '));
    account = account.toLower();

    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    object.attributes.insert(QStringLiteral("sAMAccountName"), account);
    object.attributes.insert(QStringLiteral("givenName"), givenName);
    object.attributes.insert(QStringLiteral("sn"), surname);
    object.attributes.insert(QStringLiteral("displayName"), name);
    object.attributes.insert(QStringLiteral("description"), description);
    object.attributes.insert(QStringLiteral("physicalDeliveryOfficeName"), office);
    object.attributes.insert(QStringLiteral("telephoneNumber"), telephone);
    object.attributes.insert(QStringLiteral("mail"), email);
    object.attributes.insert(QStringLiteral("wWWHomePage"),
                             QStringLiteral("https://corp.example.com/people/%1").arg(account));
    object.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    object.attributes.insert(QStringLiteral("distinguishedName"), object.id);
    return object;
}

DirectoryObject makeGroup(const QString &name, const QString &scope,
                          const QString &description, const QStringList &members,
                          const QStringList &memberOf = {})
{
    DirectoryObject object;
    object.kind = ObjectKind::Group;
    object.name = name;
    object.type = QStringLiteral("Security Group");
    object.description = description;
    object.container = QStringLiteral("Groups");
    object.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(name);
    object.members = members;
    object.memberOf = memberOf;

    QString account = name;
    account.remove(QLatin1Char(' '));
    account = account.toLower();

    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("group"));
    object.attributes.insert(QStringLiteral("sAMAccountName"), account);
    object.attributes.insert(QStringLiteral("groupScope"), scope);
    object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("Security"));
    object.attributes.insert(QStringLiteral("description"), description);
    object.attributes.insert(QStringLiteral("member"), members.join(QStringLiteral("; ")));
    object.attributes.insert(QStringLiteral("distinguishedName"), object.id);
    return object;
}

DirectoryObject makeComputer(const QString &name, const QString &description,
                             const QString &operatingSystem, bool domainController)
{
    DirectoryObject object;
    object.kind = ObjectKind::Computer;
    object.name = name;
    object.type = QStringLiteral("Computer");
    object.description = description;
    object.container = QStringLiteral("Computers");
    object.id = domainController
        ? QStringLiteral("CN=%1,OU=Domain Controllers,DC=corp,DC=example,DC=com").arg(name)
        : QStringLiteral("CN=%1,CN=Computers,DC=corp,DC=example,DC=com").arg(name);
    object.memberOf = {QStringLiteral("Domain Computers")};

    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("computer"));
    object.attributes.insert(QStringLiteral("dNSHostName"),
                             name.toLower() + QStringLiteral(".corp.example.com"));
    object.attributes.insert(QStringLiteral("operatingSystem"), operatingSystem);
    object.attributes.insert(QStringLiteral("description"), description);
    object.attributes.insert(QStringLiteral("isDomainController"),
                             domainController ? QStringLiteral("yes") : QStringLiteral("no"));
    object.attributes.insert(QStringLiteral("distinguishedName"), object.id);
    return object;
}

} // namespace

QList<DirectoryObject> sampleObjects()
{
    const QStringList domainUsers = {QStringLiteral("Domain Users")};

    return {
        makeUser(QStringLiteral("Administrator"), QString(), QString(),
                 QStringLiteral("Built-in account for administering the domain"),
                 QStringLiteral("IT"), QStringLiteral("555-0100"),
                 QStringLiteral("administrator@corp.example.com"),
                 {QStringLiteral("Domain Admins"), QStringLiteral("Domain Users"),
                  QStringLiteral("Enterprise Admins")}),
        makeUser(QStringLiteral("Guest"), QString(), QString(),
                 QStringLiteral("Built-in account for guest access to the domain"),
                 QString(), QString(), QString(),
                 domainUsers),
        makeUser(QStringLiteral("Alice Chen"), QStringLiteral("Alice"),
                 QStringLiteral("Chen"),
                 QStringLiteral("Sales team lead"),
                 QStringLiteral("Sales"), QStringLiteral("555-0142"),
                 QStringLiteral("alice.chen@corp.example.com"),
                 {QStringLiteral("Domain Admins"), QStringLiteral("Domain Users")}),
        makeUser(QStringLiteral("Bob Martinez"), QStringLiteral("Bob"),
                 QStringLiteral("Martinez"),
                 QStringLiteral("Engineering workstation user"),
                 QStringLiteral("Engineering"), QStringLiteral("555-0177"),
                 QStringLiteral("bob.martinez@corp.example.com"),
                 domainUsers),
        makeGroup(QStringLiteral("Domain Admins"), QStringLiteral("Global"),
                  QStringLiteral("Designated administrators of the domain"),
                  {QStringLiteral("Administrator"), QStringLiteral("Alice Chen")},
                  {QStringLiteral("Enterprise Admins")}),
        makeGroup(QStringLiteral("Domain Users"), QStringLiteral("Global"),
                  QStringLiteral("All domain users"),
                  {QStringLiteral("Administrator"), QStringLiteral("Guest"),
                   QStringLiteral("Alice Chen"), QStringLiteral("Bob Martinez")}),
        makeGroup(QStringLiteral("Domain Computers"), QStringLiteral("Global"),
                  QStringLiteral("All workstations and servers joined to the domain"),
                  {QStringLiteral("DC01"), QStringLiteral("WORKSTATION01"),
                   QStringLiteral("WORKSTATION02"), QStringLiteral("FILE01")}),
        makeGroup(QStringLiteral("Enterprise Admins"), QStringLiteral("Universal"),
                  QStringLiteral("Designated administrators of the enterprise"),
                  {QStringLiteral("Administrator")}),
        makeComputer(QStringLiteral("DC01"),
                     QStringLiteral("Domain controller for corp.example.com"),
                     QStringLiteral("Windows Server 2022"), true),
        makeComputer(QStringLiteral("WORKSTATION01"),
                     QStringLiteral("Finance workstation"),
                     QStringLiteral("Windows 11 Enterprise"), false),
        makeComputer(QStringLiteral("WORKSTATION02"),
                     QStringLiteral("Engineering workstation"),
                     QStringLiteral("Windows 11 Enterprise"), false),
        makeComputer(QStringLiteral("FILE01"),
                     QStringLiteral("File server"),
                     QStringLiteral("Windows Server 2022"), false),
    };
}