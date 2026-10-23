// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Development probe: serves DRSUAPI on a port so an external client (impacket
// dcsync, etc.) can drive replication against it.
#include <QCoreApplication>
#include <QDebug>

#include "Drs.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QList<DirectoryObject> objects;

    DirectoryObject domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.name = QStringLiteral("corp.example.com");
    domain.type = QStringLiteral("Domain");
    objects.append(domain);

    auto add = [&](const QString &name, const QString &account, const QString &sid,
                   const QStringList &memberOf) {
        DirectoryObject o;
        o.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(name);
        o.name = name;
        o.type = memberOf.isEmpty() ? QStringLiteral("User") : QStringLiteral("Security Group");
        o.attributes.insert(QStringLiteral("sAMAccountName"), account);
        o.attributes.insert(QStringLiteral("objectSid"), sid);
        o.attributes.insert(QStringLiteral("userPrincipalName"),
                            account + QStringLiteral("@corp.example.com"));
        o.attributes.insert(QStringLiteral("userAccountControl"),
                            memberOf.isEmpty() ? QStringLiteral("512") : QStringLiteral("514"));
        o.memberOf = memberOf;
        objects.append(o);
        return o;
    };
    DirectoryObject users =
        add(QStringLiteral("Users"), QStringLiteral("Users"), QStringLiteral("S-1-5-21-1-2-3-513"), {});
    users.id = QStringLiteral("CN=Users,DC=corp,DC=example,DC=com");
    users.members = QStringList{
        QStringLiteral("CN=Administrator,CN=Users,DC=corp,DC=example,DC=com"),
        QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com")};
    add(QStringLiteral("Administrator"), QStringLiteral("Administrator"),
        QStringLiteral("S-1-5-21-1-2-3-500"), {users.id});
    add(QStringLiteral("alice"), QStringLiteral("alice"),
        QStringLiteral("S-1-5-21-1-2-3-1001"), {users.id});

    DrsServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([objects]() { return objects; });
    QObject::connect(&server, &DrsServer::requestReceived,
                     [](const QString &line) { qWarning("RPC: %s", qPrintable(line)); });
    if (!server.listen(argc > 1 ? quint16(atoi(argv[1])) : 0)) {
        qWarning("listen failed");
        return 1;
    }
    qWarning("PORT %d", server.serverPort());
    return app.exec();
}
