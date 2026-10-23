// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Development probe: serves SAMR on a port so an external client can drive it.
#include <QCoreApplication>
#include <QDebug>

#include "Samr.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QList<DirectoryObject> objects;
    auto add = [&](const QString &name, const QString &account, const QString &sid) {
        DirectoryObject o;
        o.id = QStringLiteral("CN=%1,CN=Users,DC=corp,DC=example,DC=com").arg(name);
        o.name = name;
        o.type = QStringLiteral("User");
        o.attributes.insert(QStringLiteral("sAMAccountName"), account);
        o.attributes.insert(QStringLiteral("objectSid"), sid);
        o.attributes.insert(QStringLiteral("displayName"), name);
        objects.append(o);
    };
    add(QStringLiteral("Administrator"), QStringLiteral("Administrator"), QStringLiteral("S-1-5-21-1-2-3-500"));
    add(QStringLiteral("alice"), QStringLiteral("alice"), QStringLiteral("S-1-5-21-1-2-3-1001"));

    SamrServer server;
    Samr::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);
    server.setObjectProvider([objects]() { return objects; });
    QObject::connect(&server, &SamrServer::requestReceived,
                     [](const QString &line) { qWarning("RPC: %s", qPrintable(line)); });
    if (!server.listen(argc > 1 ? quint16(atoi(argv[1])) : 0)) {
        qWarning("listen failed");
        return 1;
    }
    qWarning("PORT %d", server.serverPort());
    return app.exec();
}
