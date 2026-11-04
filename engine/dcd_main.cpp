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
#include <QFileInfo>
#include <QSocketNotifier>
#include <QStandardPaths>

#include <csignal>
#include <cstdio>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// Exit status for a missing domain, matching sysexits.h's EX_CONFIG. The unit
// lists it in RestartPreventExitStatus=, so an unprovisioned machine fails once
// and visibly at boot instead of restarting forever.
constexpr int kExitConfig = 78;

int g_signalPipe[2] = {-1, -1};

void onTerminationSignal(int signalNumber)
{
    const unsigned char byte = static_cast<unsigned char>(signalNumber);
    // write(2) is async-signal-safe; the QSocketNotifier drains the other end.
    const ssize_t written = ::write(g_signalPipe[1], &byte, 1);
    (void)written;
}

// SIGTERM is what `systemctl stop` and `systemctl restart` send. Turning it
// into QCoreApplication::quit() runs DcService::stop(), which flushes the
// directory and DNS zone, instead of letting the process die mid-write.
bool installTerminationHandlers()
{
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, g_signalPipe) != 0)
        return false;
    struct sigaction action {};
    action.sa_handler = onTerminationSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    ::sigaction(SIGTERM, &action, nullptr);
    ::sigaction(SIGINT, &action, nullptr);
    return true;
}

} // namespace

int main(int argc, char *argv[])
{
    // systemd captures stdout through a pipe, where stdio would otherwise
    // buffer status lines until exit and leave `journalctl -u monarchy-dcd`
    // empty while the service is running.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

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

    // A daemon does not serve a demo store. Check the configuration before
    // constructing anything so an unprovisioned boot reports one clear error
    // (and a non-restarting status) rather than a crash loop.
    const QString resolvedDcDir =
        dcDir.isEmpty() ? QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) : dcDir;
    if (!QFileInfo::exists(resolvedDcDir + QStringLiteral("/dc.conf"))) {
        std::fprintf(stderr,
                     "monarchy-dcd: no provisioned domain under %s (dc.conf is missing).\n"
                     "Create one with monarchy-provision, then start the service again.\n",
                     qPrintable(resolvedDcDir));
        return kExitConfig;
    }

    if (!installTerminationHandlers()) {
        std::fprintf(stderr, "monarchy-dcd: could not install termination handlers.\n");
        return 1;
    }
    auto *termination = new QSocketNotifier(g_signalPipe[0], QSocketNotifier::Read, &app);
    QObject::connect(termination, &QSocketNotifier::activated, &app,
                     [&app, termination]() {
                         unsigned char signalNumber = 0;
                         if (::read(g_signalPipe[0], &signalNumber, 1) <= 0)
                             return;
                         termination->setEnabled(false);
                         std::printf("Received signal %d; stopping.\n", int(signalNumber));
                         app.quit();
                     });

    DcService service(false);
    QObject::connect(&service, &DcService::statusMessage,
                     [](const QString &message) { std::printf("%s\n", qPrintable(message)); });
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &service, &DcService::stop);
    if (!service.start(dcDir))
        return 1;

    return app.exec();
}
