// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// monarchy-provision — creates an AD-shaped domain tree from Monarchy's own code.
// No Samba, no system directory server: the resulting store is loaded and
// served by Monarchy's LDAP engine.

#include "DnsServer.h"
#include "Provisioner.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTextStream>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("monarchy-provision"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));
    app.setOrganizationName(QStringLiteral("monarchy"));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("Provision a Monarchy domain from source (no Samba required)."));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption realmOption(QStringLiteral("realm"),
                                   QStringLiteral("Kerberos realm (default: MONARCHY.EXAMPLE.COM)."),
                                   QStringLiteral("realm"), QStringLiteral("MONARCHY.EXAMPLE.COM"));
    QCommandLineOption domainOption(QStringLiteral("domain"),
                                    QStringLiteral("NetBIOS domain name (default: first realm label)."),
                                    QStringLiteral("domain"));
    QCommandLineOption passOption(QStringLiteral("adminpass"),
                                  QStringLiteral("Administrator password. It is visible in the "
                                                 "process table and in a sudo log; prefer "
                                                 "--adminpass-stdin."),
                                  QStringLiteral("password"));
    QCommandLineOption passStdinOption(
        QStringLiteral("adminpass-stdin"),
        QStringLiteral("Read the Administrator password from standard input."));
    QCommandLineOption dirOption(QStringLiteral("targetdir"),
                                 QStringLiteral("Target directory."),
                                 QStringLiteral("path"));
    QCommandLineOption ipOption(QStringLiteral("dc-ip"),
                                QStringLiteral("Address published in the domain DNS zone "
                                               "(default: 127.0.0.1)."),
                                QStringLiteral("address"), QStringLiteral("127.0.0.1"));
    QCommandLineOption hostOption(QStringLiteral("dc-host"),
                                  QStringLiteral("Domain controller hostname or FQDN "
                                                 "(default: <domain-label>DC1.<realm>)."),
                                  QStringLiteral("host"));
    QCommandLineOption kdcPortOption(QStringLiteral("kdc-port"),
                                QStringLiteral("Port the KDC serves (default: native 88)."),
                                QStringLiteral("port"));
    QCommandLineOption netlogonPortOption(QStringLiteral("netlogon-port"),
                                QStringLiteral("Port Netlogon serves (default: 1037)."),
                                QStringLiteral("port"));
    QCommandLineOption drsPortOption(QStringLiteral("drs-port"),
                                QStringLiteral("Port DRSUAPI serves (default: 1038)."),
                                QStringLiteral("port"));
    QCommandLineOption devPortsOption(QStringLiteral("dev-ports"),
                                QStringLiteral("Provision the unprivileged port set "
                                               "(1389/1053/8888/1035/1036, GC 13268, "
                                               "SMB/mapper 31445/31035) a rootless console "
                                               "run or a second DC on this host can bind."));
    QCommandLineOption forwarderOption(QStringLiteral("forwarder"),
                                QStringLiteral("Upstream resolver for out-of-zone DNS "
                                               "(repeatable; address or address:port)."),
                                QStringLiteral("address"));
    QCommandLineOption forceOption(QStringLiteral("force"),
                                   QStringLiteral("Overwrite an existing domain store."));
    QCommandLineOption promoteOption(
        QStringLiteral("promote-from"),
        QStringLiteral("Promote a second domain controller from a copy of an existing "
                       "controller's directory. The copy's realm, SID, naming contexts and "
                       "site are used; --adminpass is the credential this DC pulls with."),
        QStringLiteral("path"));
    QCommandLineOption replicaHostOption(
        QStringLiteral("replica-host"),
        QStringLiteral("Host of the DC a promoted DC pulls from (default: the copied "
                       "dc.conf's dcHost)."),
        QStringLiteral("host"));
    QCommandLineOption replicaPortOption(
        QStringLiteral("replica-port"),
        QStringLiteral("DRS port of that DC (default: the copied dc.conf's drsPort)."),
        QStringLiteral("port"));
    QCommandLineOption replicaUserOption(
        QStringLiteral("replica-user"),
        QStringLiteral("Account a promoted DC pulls as (default: Administrator)."),
        QStringLiteral("user"));

    parser.addOption(realmOption);
    parser.addOption(domainOption);
    parser.addOption(passOption);
    parser.addOption(passStdinOption);
    parser.addOption(dirOption);
    parser.addOption(ipOption);
    parser.addOption(hostOption);
    parser.addOption(kdcPortOption);
    parser.addOption(netlogonPortOption);
    parser.addOption(drsPortOption);
    parser.addOption(devPortsOption);
    parser.addOption(forwarderOption);
    parser.addOption(forceOption);
    parser.addOption(promoteOption);
    parser.addOption(replicaHostOption);
    parser.addOption(replicaPortOption);
    parser.addOption(replicaUserOption);
    parser.addPositionalArgument(QStringLiteral("targetdir"),
                                 QStringLiteral("Target directory (same as --targetdir)."),
                                 QStringLiteral("[targetdir]"));

    parser.process(app);

    ProvisionConfig config;
    config.realm = parser.value(realmOption);
    config.netbiosDomain = parser.isSet(domainOption)
        ? parser.value(domainOption)
        : config.realm.section(QLatin1Char('.'), 0, 0).toUpper();
    if (parser.isSet(passStdinOption)) {
        QTextStream in(stdin);
        config.adminPassword = in.readLine();
        if (config.adminPassword.endsWith(QLatin1Char('\r')))
            config.adminPassword.chop(1);
    } else {
        config.adminPassword = parser.value(passOption);
        // An argument is recorded in the process table and in sudo's log; the
        // environment is not, so a script that has the password already can
        // hand it over this way instead.
        if (config.adminPassword.isEmpty())
            config.adminPassword = qEnvironmentVariable("MONARCHY_ADMINPASS");
    }
    config.targetDir = parser.isSet(dirOption) ? parser.value(dirOption)
                                               : parser.positionalArguments().value(0);
    config.dcIp = parser.value(ipOption);
    config.dcHost = parser.value(hostOption);
    config.kdcPort = parser.isSet(kdcPortOption)
        ? quint16(parser.value(kdcPortOption).toUInt())
        : config.kdcPort; // default: native 88 with the rest of the well-known set
    config.netlogonPort = parser.isSet(netlogonPortOption)
        ? quint16(parser.value(netlogonPortOption).toUInt())
        : config.netlogonPort;
    config.drsPort = parser.isSet(drsPortOption)
        ? quint16(parser.value(drsPortOption).toUInt())
        : config.drsPort;
    config.devPorts = parser.isSet(devPortsOption);
    if (config.devPorts && !parser.isSet(kdcPortOption))
        config.kdcPort = 8888; // rootless development binding
    config.forwarders = parser.values(forwarderOption);
    // A DC that becomes its host's only resolver has no upstream to read once
    // the installer has pointed /etc/resolv.conf at it, so the upstreams are
    // recorded here while they are still this host's real ones. --forwarder
    // overrides the discovered list.
    if (config.forwarders.isEmpty())
        config.forwarders = DnsServer::systemForwarders();
    config.force = parser.isSet(forceOption);
    config.promoteFrom = parser.value(promoteOption);
    config.replicaHost = parser.value(replicaHostOption);
    if (parser.isSet(replicaPortOption))
        config.replicaPort = quint16(parser.value(replicaPortOption).toUInt());
    if (parser.isSet(replicaUserOption))
        config.replicaUser = parser.value(replicaUserOption);
    const bool promote = !config.promoteFrom.trimmed().isEmpty();

    QTextStream out(stdout);
    QTextStream err(stderr);

    if (config.targetDir.isEmpty()) {
        err << "monarchy-provision: --targetdir is required\n";
        return 2;
    }
    if (config.adminPassword.isEmpty()) {
        // For a promote the password is the pull credential rather than a new
        // administrator's; without it the DC would start and never replicate.
        err << (promote
                    ? "monarchy-provision: the password a promoted DC pulls with is "
                      "required (--adminpass, --adminpass-stdin or MONARCHY_ADMINPASS)\n"
                    : "monarchy-provision: an Administrator password is required "
                      "(--adminpass, --adminpass-stdin or MONARCHY_ADMINPASS)\n");
        return 2;
    }

    const ProvisionResult result = promote ? promoteDomain(config) : provisionDomain(config);
    if (!result.ok) {
        err << "monarchy-provision: " << result.error << '\n';
        return 1;
    }

    if (promote)
        out << "Promoted " << result.dcHost << " into " << result.dnsDomain << "\n";
    else
        out << "Provisioned " << config.realm << " (" << config.netbiosDomain << ")\n";
    out << "  base DN:   " << result.baseDn << '\n'
        << "  domain SID: " << result.domainSid << '\n'
        << "  objects:   " << result.objectCount << '\n'
        << "  store:     " << result.storePath << '\n'
        << "  secrets:   " << result.secretsPath << '\n'
        << "  dc host:   " << result.dcHost << '\n'
        << "  config:    " << result.configPath << '\n'
        << "  forwarders: "
        << (config.forwarders.isEmpty() ? QStringLiteral("(none: out-of-zone names "
                                                       "will not resolve)")
                                       : config.forwarders.join(QStringLiteral(", ")))
        << '\n'
        << "  krb5.conf: " << result.krb5ConfPath << '\n'
        << "  dns zone:  " << result.zonePath << '\n'
        << "  sysvol:    " << result.sysvolPath << '\n';
    return 0;
}
