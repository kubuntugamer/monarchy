// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Development probe for the Netlogon endpoint: reads "<opnum> <hex stub>"
// lines, answers with the response stub as hex. Not shipped. It exists so an
// independent NDR client (Samba's pidl decoder) can drive the endpoint without
// a provisioned domain or a listening socket.

#include <QCoreApplication>
#include <QDebug>
#include <QTextStream>

#include "Netlogon.h"
#include "Ntlm.h"
#include "resultsmodel.h"

namespace {

DirectoryObject account(const QString &dn, const QString &name, const QString &sid,
                        const QString &password, const QString &kind, ObjectKind objectKind)
{
    DirectoryObject object;
    object.id = dn;
    object.name = name;
    object.type = kind;
    object.kind = objectKind;
    object.attributes.insert(QStringLiteral("cn"), name);
    object.attributes.insert(QStringLiteral("sAMAccountName"), name);
    object.attributes.insert(QStringLiteral("objectSid"), sid);
    object.attributes.insert(QStringLiteral("ntHash"),
                             QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
    return object;
}

QList<DirectoryObject> sampleDirectory()
{
    QList<DirectoryObject> objects;

    DirectoryObject dc = account(QStringLiteral("CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=com"),
                                 QStringLiteral("DC1$"), QStringLiteral("S-1-5-21-1-2-3-1000"),
                                 QStringLiteral("Mach!neP@ss1"), QStringLiteral("Computer"),
                                 ObjectKind::Computer);
    dc.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("532480"));
    objects.append(dc);

    DirectoryObject user = account(QStringLiteral("CN=Alice,CN=Users,DC=corp,DC=example,DC=com"),
                                   QStringLiteral("alice"), QStringLiteral("S-1-5-21-1-2-3-1001"),
                                   QStringLiteral("AliceP@ss1"), QStringLiteral("User"),
                                   ObjectKind::User);
    user.attributes.insert(QStringLiteral("displayName"), QStringLiteral("Alice A"));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    user.memberOf.append(QStringLiteral("CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com"));
    objects.append(user);

    DirectoryObject group;
    group.id = QStringLiteral("CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com");
    group.name = QStringLiteral("Domain Users");
    group.type = QStringLiteral("Security Group");
    group.kind = ObjectKind::Group;
    group.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("Domain Users"));
    group.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-513"));
    group.members.append(user.id);
    objects.append(group);

    return objects;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    Netlogon::Config config;
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.netbios = QStringLiteral("CORP");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    config.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.dcHost = QStringLiteral("dc1.corp.example.com");
    config.dcIp = QStringLiteral("127.0.0.1");
    config.siteName = QStringLiteral("Default-First-Site-Name");

    NetlogonServer server;
    server.setConfig(config);
    QList<DirectoryObject> objects = sampleDirectory();
    server.setObjectProvider([&objects]() { return objects; });
    Netlogon::WriteBackend writes;
    writes.setNtHash = [&objects](const QString &dn, const QByteArray &ntHash, QString *error) {
        Q_UNUSED(error)
        for (DirectoryObject &object : objects) {
            if (object.id.compare(dn, Qt::CaseInsensitive) == 0) {
                object.attributes.insert(QStringLiteral("ntHash"),
                                         QString::fromLatin1(ntHash.toHex()));
                return true;
            }
        }
        return false;
    };
    server.setWriteBackend(writes);

    QTextStream in(stdin);
    QTextStream out(stdout);
    QString line;
    while (in.readLineInto(&line)) {
        const QStringList parts = line.trimmed().split(QLatin1Char(' '));
        if (parts.size() != 2)
            continue;
        bool ok = false;
        const quint16 opnum = parts.at(0).toUShort(&ok);
        if (!ok)
            continue;
        const QByteArray stub = QByteArray::fromHex(parts.at(1).toLatin1());
        const QByteArray response = server.handleCall(opnum, stub);
        out << QString::fromLatin1(response.toHex()) << Qt::endl;
        out.flush();
    }
    return 0;
}
