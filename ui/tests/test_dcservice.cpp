// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>
#include <QMap>
#include <QSettings>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>

#include <unistd.h>

#include "DcService.h"
#include "Provisioner.h"

namespace {

// DcService reads every port out of dc.conf, so the same file is the list of
// what the daemon promises. A test with the numbers spelled out would keep
// passing if the provisioner and the daemon ever disagreed about them.
QMap<QString, quint16> declaredPorts(const QString &dcDir)
{
    QSettings conf(dcDir + QStringLiteral("/dc.conf"), QSettings::IniFormat);
    QMap<QString, quint16> ports;
    for (const QString &key : conf.allKeys()) {
        if (!key.endsWith(QStringLiteral("Port")))
            continue;
        bool ok = false;
        const uint value = conf.value(key).toUInt(&ok);
        if (ok && value != 0)
            ports.insert(key, static_cast<quint16>(value));
    }
    return ports;
}

// A listener that answered a connect proves more than a log line: it is the
// difference between a tower naming a port and a client reaching it. The socket
// is closed immediately, so the client that connects next is the only one that
// will speak on it — DcService accepts a new connection per client.
bool accepts(quint16 port)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, port);
    return socket.waitForConnected(3000);
}

quint16 freePort()
{
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0))
        return 0;
    const quint16 port = server.serverPort();
    server.close();
    return port;
}

QStringList spokenMessages(const QSignalSpy &spy)
{
    QStringList spoken;
    spoken.reserve(spy.size());
    for (const QList<QVariant> &args : spy)
        spoken.append(args.at(0).toString());
    return spoken;
}

} // namespace

class DcServiceTest : public QObject
{
    Q_OBJECT

private slots:
    void ownsEveryPortItAdvertises();
};

// The failure this catches is the one issue #3 was filed for: a DC that
// publishes a locator to a port whose listener never came up. The daemon
// reports that in its log and keeps serving the rest, so only a test that walks
// its own configuration can see it.
void DcServiceTest::ownsEveryPortItAdvertises()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    ProvisionConfig config;
    config.realm = QStringLiteral("PORTS.EXAMPLE.ORG");
    config.netbiosDomain = QStringLiteral("PORTS");
    config.adminPassword = QStringLiteral("Secret123!");
    config.targetDir = dir.path();
    // The unprivileged set: this suite has to pass without root. 135 and 445
    // stay native under --dev-ports, so they are asserted only where the host
    // lets this process bind them.
    config.devPorts = true;
    const ProvisionResult result = provisionDomain(config);
    QVERIFY2(result.ok, qPrintable(result.error));

    // The provisioner pins the catalog at 3268 in every port set, and netlogon
    // and DRSUAPI keep one number in both, so a host that already serves a
    // domain holds them. Move only what is already taken: what this suite
    // proves is that the daemon follows dc.conf, not which numbers provisioning
    // picked, and every key left alone still proves the normal mapping.
    const QString confPath = dir.path() + QStringLiteral("/dc.conf");
    {
        QSettings conf(confPath, QSettings::IniFormat);
        QStringList moved;
        for (const QString &key : conf.allKeys()) {
            if (!key.endsWith(QStringLiteral("Port")))
                continue;
            const quint16 port = static_cast<quint16>(conf.value(key).toUInt());
            if (port == 0 || !accepts(port))
                continue;
            const quint16 replacement = freePort();
            QVERIFY2(replacement != 0,
                     qPrintable(QStringLiteral("the kernel offered no port to replace %1")
                                    .arg(key)));
            conf.setValue(key, replacement);
            moved.append(QStringLiteral("%1 %2->%3").arg(key).arg(port).arg(replacement));
        }
        conf.sync();
        if (!moved.isEmpty())
            qInfo("ports already held by another process: %s", qPrintable(moved.join(", ")));
    }

    DcService service;
    QSignalSpy messages(&service, &DcService::statusMessage);
    QVERIFY2(service.start(dir.path()),
             "the daemon refused to start on a domain it had just provisioned");

    const QMap<QString, quint16> ports = declaredPorts(dir.path());
    QVERIFY2(ports.size() >= 8,
             qPrintable(QStringLiteral("dc.conf declares only %1 ports, so this test "
                                       "would prove almost nothing")
                            .arg(ports.size())));

    const bool privileged = geteuid() == 0;
    const QStringList spoken = spokenMessages(messages);

    int proved = 0;
    for (auto it = ports.constBegin(); it != ports.constEnd(); ++it) {
        const quint16 port = it.value();

        if (port <= 1024 && !privileged) {
            // A privileged port this process cannot take has to be reported, not
            // assumed: the zone derives its locators from what actually bound.
            const QString number = QString::number(port);
            bool reported = false;
            for (const QString &line : spoken) {
                if (line.contains(number) && line.contains(QStringLiteral("failed to listen")))
                    reported = true;
            }
            QVERIFY2(reported,
                     qPrintable(QStringLiteral("%1 (%2) could not be bound and the daemon "
                                               "did not say so")
                                    .arg(it.key())
                                    .arg(port)));
            continue;
        }

        QVERIFY2(accepts(port),
                 qPrintable(QStringLiteral("%1 (%2) is declared in dc.conf but nothing "
                                           "accepts a connection there")
                                    .arg(it.key())
                                    .arg(port)));
        ++proved;
    }
    QVERIFY2(proved >= 8,
             qPrintable(QStringLiteral("only %1 declared ports were proved reachable")
                            .arg(proved)));

    // The directory is the one endpoint a DC cannot do without, so its port is
    // not optional: assert it was among the ones that answered.
    const quint16 ldapPort = ports.value(QStringLiteral("ldapPort"));
    QVERIFY2(ldapPort != 0 && accepts(ldapPort),
             "the provisioned ldapPort accepted no connection");

    service.stop();
}

QTEST_GUILESS_MAIN(DcServiceTest)

#include "test_dcservice.moc"
