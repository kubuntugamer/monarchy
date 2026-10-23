// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// monarchy-provision — creates an AD-shaped domain tree from Monarchy's own code.
// No Samba, no system directory server: the resulting store is loaded and
// served by Monarchy's LDAP engine.

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
                                  QStringLiteral("Administrator password."),
                                  QStringLiteral("password"));
    QCommandLineOption dirOption(QStringLiteral("targetdir"),
                                 QStringLiteral("Target directory."),
                                 QStringLiteral("path"));
    QCommandLineOption ipOption(QStringLiteral("dc-ip"),
                                QStringLiteral("Address published in the domain DNS zone "
                                               "(default: 127.0.0.1)."),
                                QStringLiteral("address"), QStringLiteral("127.0.0.1"));
    QCommandLineOption kdcPortOption(QStringLiteral("kdc-port"),
                                QStringLiteral("Port the KDC serves (default: 8888)."),
                                QStringLiteral("port"), QStringLiteral("8888"));
    QCommandLineOption forceOption(QStringLiteral("force"),
                                   QStringLiteral("Overwrite an existing domain store."));

    parser.addOption(realmOption);
    parser.addOption(domainOption);
    parser.addOption(passOption);
    parser.addOption(dirOption);
    parser.addOption(ipOption);
    parser.addOption(kdcPortOption);
    parser.addOption(forceOption);
    parser.addPositionalArgument(QStringLiteral("targetdir"),
                                 QStringLiteral("Target directory (same as --targetdir)."),
                                 QStringLiteral("[targetdir]"));

    parser.process(app);

    ProvisionConfig config;
    config.realm = parser.value(realmOption);
    config.netbiosDomain = parser.isSet(domainOption)
        ? parser.value(domainOption)
        : config.realm.section(QLatin1Char('.'), 0, 0).toUpper();
    config.adminPassword = parser.value(passOption);
    config.targetDir = parser.isSet(dirOption) ? parser.value(dirOption)
                                               : parser.positionalArguments().value(0);
    config.dcIp = parser.value(ipOption);
    config.kdcPort = quint16(parser.value(kdcPortOption).toUInt());
    config.force = parser.isSet(forceOption);

    QTextStream out(stdout);
    QTextStream err(stderr);

    if (config.targetDir.isEmpty()) {
        err << "monarchy-provision: --targetdir is required\n";
        return 2;
    }
    if (config.adminPassword.isEmpty()) {
        err << "monarchy-provision: --adminpass is required\n";
        return 2;
    }

    const ProvisionResult result = provisionDomain(config);
    if (!result.ok) {
        err << "monarchy-provision: " << result.error << '\n';
        return 1;
    }

    out << "Provisioned " << config.realm << " (" << config.netbiosDomain << ")\n"
        << "  base DN:   " << result.baseDn << '\n'
        << "  domain SID: " << result.domainSid << '\n'
        << "  objects:   " << result.objectCount << '\n'
        << "  store:     " << result.storePath << '\n'
        << "  secrets:   " << result.secretsPath << '\n'
        << "  dc host:   " << result.dcHost << '\n'
        << "  config:    " << result.configPath << '\n'
        << "  krb5.conf: " << result.krb5ConfPath << '\n'
        << "  dns zone:  " << result.zonePath << '\n'
        << "  sysvol:    " << result.sysvolPath << '\n';
    return 0;
}
