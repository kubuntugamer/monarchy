// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * DEDICATION:
 * This project is respectfully dedicated to Mr. Raymond Barry (ITT Technical Institute, Arnold MO, c. 2000-2005).
 * Thank you for serving as my early reference guide to the foundational mechanics of Active Directory.
 *
 * We finally got it running natively on Linux without the Windows Server 2000 installation media.
 * Consider this your official exemption from the Microsoft Client Access License (CAL) registry.
 * The "Nobodies" send their regards.
 */

// The headless domain controller. Monarchy's engine is standalone now — the
// console is only ever a client, exactly like dsa.msc on a real DC — so the
// directory services run as a proper service: they start without a logged-in
// user, survive console crashes and closing windows, and a client on the
// network talks to the daemon's ports the way it would to the LSASS-hosted
// services on a Windows DC.
//
//   monarchy-dcd              serve the default provisioned domain
//   monarchy-dcd --dcdir DIR  serve the domain provisioned under DIR
//
// Privileged ports (epm 135, smb 445) need root or `cap_net_bind_service`;
// every other endpoint uses its unprivileged default from dc.conf.

#include "DcService.h"

#include <QCoreApplication>
#include <QStandardPaths>

#include <cstdio>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    // Same identity the provisioner and the console use, so the default
    // application-data directory (and therefore dc.conf) resolves alike.
    QCoreApplication::setOrganizationName(QStringLiteral("monarchy"));
    QCoreApplication::setApplicationName(QStringLiteral("Monarchy"));

    QString dcDir;
    const QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        const QString arg = args.at(i);
        if (arg == QStringLiteral("--dcdir") && i + 1 < args.size())
            dcDir = args.at(++i);
        else if (arg.startsWith(QStringLiteral("--dcdir=")))
            dcDir = arg.mid(qstrlen("--dcdir="));
        else if (arg == QStringLiteral("-h") || arg == QStringLiteral("--help")
                 || arg == QStringLiteral("-help")) {
            std::printf("%s\n",
                        "Usage: monarchy-dcd [--dcdir DIR]\n"
                        "Runs the Monarchy domain controller as a headless service:\n"
                        "LDAP, KDC, DNS, SAMR, LSAD, Netlogon, DRSUAPI, EPM and SMB2,\n"
                        "configured from the dc.conf the provisioner wrote.\n");
            return 0;
        }
    }

    // A daemon does not serve a demo store: without a provisioned domain it
    // stops and reports, instead of answering LDAP with sample objects.
    DcService service(false);
    QObject::connect(&service, &DcService::statusMessage,
                     [](const QString &message) { std::printf("%s\n", qPrintable(message)); });
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &service, &DcService::stop);
    if (!service.start(dcDir))
        return 1;

    return app.exec();
}
