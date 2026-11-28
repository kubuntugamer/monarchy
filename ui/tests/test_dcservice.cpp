// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>
#include <QFile>
#include <QMap>
#include <QProcess>
#include <QSettings>
#include <QStandardPaths>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>

#include <unistd.h>

#include "DcService.h"
#include "Drs.h"
#include "LdapServer.h"
#include "Ndr.h"
#include "Provisioner.h"
#include "ReplicaTopology.h"
#include "ldap_wire_helpers.h"

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

// Provisioning picks the documented ports, so two of these suites can collide
// on a host that already serves them. Move only what is already taken: what a
// test proves is that the daemon follows its own dc.conf, not which numbers
// provisioning picked.
void moveTakenPorts(const QString &dcDir)
{
    const QString confPath = dcDir + QStringLiteral("/dc.conf");
    QSettings conf(confPath, QSettings::IniFormat);
    QStringList moved;
    for (const QString &key : conf.allKeys()) {
        if (!key.endsWith(QStringLiteral("Port")))
            continue;
        const quint16 port = static_cast<quint16>(conf.value(key).toUInt());
        if (port == 0 || !accepts(port))
            continue;
        const quint16 replacement = freePort();
        if (replacement == 0)
            continue;
        conf.setValue(key, replacement);
        moved.append(QStringLiteral("%1 %2->%3").arg(key).arg(port).arg(replacement));
    }
    conf.sync();
    if (!moved.isEmpty())
        qInfo("ports already held by another process: %s", qPrintable(moved.join(", ")));
}

void appendLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

quint32 readLe32(const QByteArray &data, int offset)
{
    return quint32(quint8(data.at(offset)))
           | (quint32(quint8(data.at(offset + 1))) << 8)
           | (quint32(quint8(data.at(offset + 2))) << 16)
           | (quint32(quint8(data.at(offset + 3))) << 24);
}

// The DsBind arm the wire accepts, and the DsReplicaAdd level-1 arm from the
// reference IDL (MS-DRSR 4.1.28, `drsuapi_DsReplicaAddRequest1`).
QByteArray bindRequest()
{
    QByteArray stub;
    appendLe32(stub, 0x00020000u);   // puuidClientDsa referent
    stub.append(QByteArray(16, '\x11'));
    appendLe32(stub, 0x00020001u);   // pextClient referent
    appendLe32(stub, 52);            // DRS_EXTENSIONS.cb
    appendLe32(stub, 52);            // rgb conformant count
    stub.append(QByteArray(52, '\0'));
    return stub;
}

QByteArray replicaAddRequest(const QByteArray &handle, const QString &ncDn,
                             const QString &address)
{
    QByteArray out = handle;
    appendLe32(out, 1u);              // level
    appendLe32(out, 0x00020004u);     // naming_context referent
    appendLe32(out, 0x00020008u);     // source_dsa_address referent
    out.append(QByteArray(84, '\0')); // schedule[84]
    appendLe32(out, 0u);              // options

    const quint32 units = quint32(ncDn.size() + 1);
    appendLe32(out, units);
    appendLe32(out, 0u);
    appendLe32(out, 0u);
    out.append(QByteArray(16 + 28, '\0'));
    appendLe32(out, units * 2);
    out.append(Ndr::utf16le(ncDn + QChar(u'\0')));
    while (out.size() % 4 != 0)
        out.append('\0');

    const quint32 addressUnits = quint32(address.size() + 1);
    appendLe32(out, addressUnits);
    out.append(Ndr::utf16le(address + QChar(u'\0')));
    while (out.size() % 4 != 0)
        out.append('\0');
    return out;
}

// The DsReplicaDel arm (MS-DRSR 4.1.20), whose address is a UTF-8 octet string
// rather than the wide string DsReplicaAdd takes.
QByteArray replicaDelRequest(const QByteArray &handle, const QString &ncDn,
                             const QString &address)
{
    QByteArray out = handle;
    appendLe32(out, 1u);          // level
    appendLe32(out, 0x00020004u); // naming_context referent
    appendLe32(out, 0x00020008u); // source_dsa_address referent
    appendLe32(out, 0u);          // options

    const quint32 units = quint32(ncDn.size() + 1);
    appendLe32(out, units);
    appendLe32(out, 0u);
    appendLe32(out, 0u);
    out.append(QByteArray(16 + 28, '\0'));
    appendLe32(out, units * 2);
    out.append(Ndr::utf16le(ncDn + QChar(u'\0')));
    while (out.size() % 4 != 0)
        out.append('\0');

    const QByteArray utf8 = (address + QChar(u'\0')).toUtf8();
    appendLe32(out, quint32(utf8.size())); // max count, terminator included
    appendLe32(out, 0u);                   // offset
    appendLe32(out, quint32(utf8.size())); // actual count
    out.append(utf8);
    while (out.size() % 4 != 0)
        out.append('\0');
    return out;
}

// One LDAP request and the one response it produces. The daemon runs in this
// thread, so the wait has to return to the event loop (ldapwire::Reader spins
// it) instead of blocking the socket: a blocking read here would deadlock
// against the server it is waiting for.
QByteArray ldapRoundTrip(QTcpSocket &socket, ldapwire::Reader &reader,
                         const QByteArray &request)
{
    if (socket.write(request) != request.size())
        return QByteArray();
    socket.flush();
    return reader.next();
}

} // namespace

class DcServiceTest : public QObject
{
    Q_OBJECT

private slots:
    void ownsEveryPortItAdvertises();
    void readsEveryShapeOfForwardersKey();
    void writerAndReaderAgreeOnForwarders();
    void keepsReplicaLinkAsAConnectionObject();
    void kccAddsTheConnectionASecondDcInTheSiteNeeds();
    void commitsClientWritesWhileItRuns();
};

// The writer and the reader of `forwarders=` met nowhere in a test before this:
// the provisioner test checks the string it stored with QSettings, which is not
// how the daemon reads it. QSettings reads a comma-containing value as a
// QStringList, and toString() on that is empty, so a recorded list of two
// upstreams read as none and the DC silently fell back to the host's
// nameservers — including across the SIGHUP reload, which has the same reader.
void DcServiceTest::readsEveryShapeOfForwardersKey()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    // One file per shape, never one file rewritten. QSettings answers a rewrite
    // that keeps the byte count from the values it already parsed: measured on
    // this host, writing `192.0.2.1,192.0.2.2` and then `192.0.2.1;192.0.2.2`
    // to one path returned the first value twice. A row asserted against that
    // cache passes without the reader ever seeing the file, which is how a
    // semicolon row passed here and failed in CI.
    int shape = 0;
    auto read = [&dir, &shape](const QByteArray &forwardersLine) {
        const QString path = dir.path() + QStringLiteral("/dc-%1.conf").arg(++shape);
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return QStringList{QStringLiteral("<write failed>")};
        file.write("[General]\nrealm=PROBE.EXAMPLE.ORG\n" + forwardersLine + "\n");
        file.close();
        const QSettings conf(path, QSettings::IniFormat);
        return DcService::forwardersFrom(conf);
    };

    // What the installer writes, and what a hand edit following the daemon's
    // own "Set forwarders= in dc.conf" advice looks like.
    QCOMPARE(read("forwarders=192.0.2.1,192.0.2.2"),
             QStringList({"192.0.2.1", "192.0.2.2"}));
    QCOMPARE(read("forwarders=192.0.2.1, 192.0.2.2"),
             QStringList({"192.0.2.1", "192.0.2.2"}));
    // What the provisioner writes through QSettings::setValue (quoted).
    QCOMPARE(read("forwarders=\"192.0.2.53, 192.0.2.54:5353\""),
             QStringList({"192.0.2.53", "192.0.2.54:5353"}));
    // Space separated, and the single-upstream host. A semicolon inside an
    // unquoted INI value is not asserted, and not because of a Qt version: the
    // INI reader ends the value at `;` here too, so `192.0.2.1;192.0.2.2`
    // reaches the daemon as `192.0.2.1` and the second address is gone before
    // forwardersFrom() can split on it. The reader still splits on `;` for a
    // value that arrives whole.
    QCOMPARE(read("forwarders=192.0.2.1 192.0.2.2"),
             QStringList({"192.0.2.1", "192.0.2.2"}));
    QCOMPARE(read("forwarders=192.168.1.1"), QStringList({"192.168.1.1"}));
    // Pinned as it behaves, not as one might wish: the unquoted semicolon form
    // loses the second address inside the INI reader, so the reader hands back
    // one upstream and nothing downstream can report the loss. The README tells
    // operators to use commas or spaces.
    QCOMPARE(read("forwarders=192.0.2.1;192.0.2.2"), QStringList({"192.0.2.1"}));
    // No key and an empty key both mean "use the host's nameservers".
    QCOMPARE(read(QByteArray()), QStringList());
    QCOMPARE(read("forwarders="), QStringList());
}

// The rows above pin what the reader does with shapes a test author wrote by
// hand. They cannot fail when the writer emits a shape nobody thought to write
// down, and the writer here is not a C++ function that a test could call: it is
// `record_dc_conf_forwarders()` in the install script, which builds the line
// with shell word splitting and inserts it with sed. So this drives that
// function itself, out of the script's own text, and hands the file it produced
// to the reader the daemon uses. A change to how the installer joins its
// upstreams is a change to what this asserts, without this file being edited.
void DcServiceTest::writerAndReaderAgreeOnForwarders()
{
    const QString script = QStringLiteral(MONARCHY_SCRIPT_DIR "/install-monarchy.sh");
    QVERIFY2(QFile::exists(script), qPrintable(script));
    if (QStandardPaths::findExecutable(QStringLiteral("bash")).isEmpty())
        QSKIP("bash is not installed");

    // Lifted by its own boundaries, so the assertion follows the script rather
    // than a copy of it. log()/warn() are the only helpers the function calls.
    const QString runner = QStringLiteral(
        "set -euo pipefail\n"
        "log() { :; }\n"
        "warn() { :; }\n"
        "eval \"$(sed -n '/^record_dc_conf_forwarders()/,/^}/p' \"$1\")\"\n"
        "DCDIR=$2\n"
        "record_dc_conf_forwarders\n");

    // Pin the extracted writer text itself: record_dc_conf_forwarders() must
    // build the forwarders= value via a joined variable (the installer's
    // comma-joining logic). Assert on the sed-extracted function body, not on
    // the runner source that evals it.
    QProcess sed;
    sed.start(QStringLiteral("sed"),
              {QStringLiteral("-n"),
               QStringLiteral("/^record_dc_conf_forwarders()/,/^}/p"),
               script});
    QVERIFY2(sed.waitForFinished(10000),
             "sed could not extract record_dc_conf_forwarders()");
    QCOMPARE(sed.exitStatus(), QProcess::NormalExit);
    QCOMPARE(sed.exitCode(), 0);
    const QString extracted = QString::fromUtf8(sed.readAllStandardOutput());
    QVERIFY2(!extracted.isEmpty(),
             qPrintable(QStringLiteral("no record_dc_conf_forwarders() found in %1")
                            .arg(script)));
    QVERIFY2(extracted.contains(QStringLiteral("joined=")),
             qPrintable(QStringLiteral("extracted record_dc_conf_forwarders() does not "
                                       "contain 'joined=':\n%1")
                            .arg(extracted)));

    // The installer's own function, run against a dc.conf and a resolv.conf
    // this test chose.
    auto runWriter = [&script, &runner](const QString &dcDir, const QString &resolvPath) {
        QProcess proc;
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(QStringLiteral("MONARCHY_RESOLV_CONF"), resolvPath);
        proc.setProcessEnvironment(env);
        proc.start(QStringLiteral("bash"), {QStringLiteral("-c"), runner,
                                            QStringLiteral("bash"), script, dcDir});
        if (!proc.waitForFinished(30000))
            return false;
        if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
            qWarning("writer failed: %s%s", qPrintable(proc.readAllStandardError()),
                     qPrintable(proc.readAllStandardOutput()));
            return false;
        }
        return true;
    };

    struct Written {
        QString line;      // the value the installer put after `forwarders=`
        QStringList read;  // what the daemon's reader makes of the same file
        QByteArray bytes;
    };

    // One throwaway domain per host shape, with a resolv.conf this test chose.
    // The host's own nameservers cannot be used: a machine with one upstream
    // makes the installer write one address, and a one-address value reads
    // correctly even through the comma bug this test exists to catch.
    auto write = [&runWriter](const QString &nameservers, Written &out) {
        QTemporaryDir dir;
        if (!dir.isValid())
            return false;
        const QString conf = dir.path() + QStringLiteral("/dc.conf");
        const QString resolvPath = dir.path() + QStringLiteral("/resolv.conf");
        QFile resolv(resolvPath);
        if (!resolv.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return false;
        resolv.write(nameservers.toUtf8());
        resolv.close();

        QFile file(conf);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return false;
        // The file the installer meets on a host it provisioned earlier: no
        // forwarders key yet, and an owner it will try to restore.
        file.write("[General]\n"
                   "realm=PROBE.EXAMPLE.ORG\n"
                   "dnsDomain=probe.example.org\n"
                   "dcIp=127.0.0.1\n");
        file.close();

        if (!runWriter(dir.path(), resolvPath))
            return false;
        if (QFile::exists(conf + QStringLiteral(".new")))
            return false; // the installer left its scratch file behind

        QFile written(conf);
        if (!written.open(QIODevice::ReadOnly))
            return false;
        out.bytes = written.readAll();
        written.close();
        out.line.clear();
        for (const QString &line : QString::fromUtf8(out.bytes).split(QLatin1Char('\n'))) {
            if (line.startsWith(QStringLiteral("forwarders="))) {
                if (!out.line.isEmpty())
                    return false; // the key was written twice
                out.line = line.mid(QStringLiteral("forwarders=").size());
            }
        }
        const QSettings recordedConf(conf, QSettings::IniFormat);
        out.read = DcService::forwardersFrom(recordedConf);
        return true;
    };

    // Two upstreams plus the loopback resolver a host normally has: the value
    // becomes a comma list, which is the shape that read as no forwarders at
    // all before the reader asked for a list.
    const QString twoHosts =
        QStringLiteral("nameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver 192.0.2.2\n");
    Written two;
    QVERIFY(write(twoHosts, two));
    QVERIFY2(!two.line.isEmpty(), qPrintable(QString::fromUtf8(two.bytes)));
    QVERIFY2(!two.line.contains(QLatin1Char(';')),
             qPrintable(two.line)); // a semicolon would lose an address silently
    QCOMPARE(two.read, QStringList({"192.0.2.1", "192.0.2.2"}));

    // One upstream: a plain string, which must still read as one address.
    Written one;
    QVERIFY(write(QStringLiteral("nameserver 127.0.0.53\nnameserver 192.0.2.1\n"), one));
    QCOMPARE(one.read, QStringList({"192.0.2.1"}));

    // Only loopback resolvers: the installer writes no key at all, and the
    // daemon must fall back to the host's nameservers rather than to an empty
    // list that would answer SERVFAIL for every name outside the zone.
    Written none;
    QVERIFY(write(QStringLiteral("nameserver 127.0.0.53\n"), none));
    QVERIFY2(none.line.isEmpty(), qPrintable(QString::fromUtf8(none.bytes)));
    QVERIFY(none.read.isEmpty());

    // Re-running the installer is what an operator does after a failed first
    // run: a key that is already there must be the one that stays, or the
    // reload path reads a different upstream than the one that was in effect.
    QTemporaryDir rerun;
    QVERIFY(rerun.isValid());
    const QString conf = rerun.path() + QStringLiteral("/dc.conf");
    const QString resolvPath = rerun.path() + QStringLiteral("/resolv.conf");
    QFile resolv(resolvPath);
    QVERIFY(resolv.open(QIODevice::WriteOnly | QIODevice::Truncate));
    resolv.write("nameserver 192.0.2.1\n");
    resolv.close();
    QFile seeded(conf);
    QVERIFY(seeded.open(QIODevice::WriteOnly | QIODevice::Truncate));
    seeded.write("[General]\nforwarders=192.0.2.9\n");
    seeded.close();
    QVERIFY(runWriter(rerun.path(), resolvPath));
    QFile kept(conf);
    QVERIFY(kept.open(QIODevice::ReadOnly));
    const QSettings keptConf(conf, QSettings::IniFormat);
    QCOMPARE(DcService::forwardersFrom(keptConf), QStringList({"192.0.2.9"}));
    QCOMPARE(kept.readAll(), QByteArray("[General]\nforwarders=192.0.2.9\n"));
}

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
    // domain holds them. Move only what is already taken: every key left alone
    // still proves the normal mapping.
    moveTakenPorts(dir.path());

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

// The link an administrator registers with DsReplicaAdd is a connection object
// under this DC's NTDS Settings, and that object is what a restarted daemon
// reads back. Without it the partner would live only in the process that
// registered it, which is exactly what AD does not do.
void DcServiceTest::keepsReplicaLinkAsAConnectionObject()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    ProvisionConfig config;
    config.realm = QStringLiteral("LINKS.EXAMPLE.ORG");
    config.netbiosDomain = QStringLiteral("LINKS");
    config.adminPassword = QStringLiteral("Secret123!");
    config.targetDir = dir.path();
    config.devPorts = true;
    const ProvisionResult result = provisionDomain(config);
    QVERIFY2(result.ok, qPrintable(result.error));
    moveTakenPorts(dir.path());

    const QString address = QStringLiteral("127.0.0.1:1038");

    // The first service is scoped: a restart is a new process owning the same
    // directory, and the listeners of the old one have to be gone for the new
    // one to take the ports the store's dc.conf names.
    {
        DcService service;
        QVERIFY2(service.start(dir.path()),
                 "the daemon refused to start on a domain it had just provisioned");

        DrsServer *drs = service.findChild<DrsServer *>();
        QVERIFY2(drs, "the running service has no DRSUAPI endpoint");
        const QByteArray handle = drs->handleCall(0, bindRequest()).mid(64, 20);
        QCOMPARE(readLe32(drs->handleCall(5, replicaAddRequest(handle, service.baseDn(), address)),
                          0),
                 quint32(0));

        const QString storePath = dir.path() + QStringLiteral("/private/directory.json");
        QFile store(storePath);
        QVERIFY2(store.open(QIODevice::ReadOnly), qPrintable(storePath));
        const QByteArray saved = store.readAll();
        store.close();
        QVERIFY2(saved.contains("nTDSConnection"),
                 "DsReplicaAdd left no connection object in the store");
        QVERIFY2(saved.contains("CN=127.0.0.1_1038,"),
                 "the connection object is not named after the address it pulls from");
        service.stop();
    }

    const QString storePath = dir.path() + QStringLiteral("/private/directory.json");
    {
        DcService restarted;
        QSignalSpy messages(&restarted, &DcService::statusMessage);
        QVERIFY2(restarted.start(dir.path()),
                 "the daemon refused to start again on the directory it had just written");

        bool restored = false;
        bool pulled = false;
        for (const QString &line : spokenMessages(messages)) {
            QVERIFY2(!line.contains(QStringLiteral("No replication partner")),
                     "the restarted daemon forgot the link the store held");
            if (line.contains(QStringLiteral("Restored"))
                && line.contains(QStringLiteral("from the directory")))
                restored = true;
            if (line.contains(address) && line.contains(QStringLiteral("registered")))
                pulled = true;
        }
        QVERIFY2(restored, "the restarted daemon did not report reading the link back");
        QVERIFY2(pulled, "the restarted daemon did not pull from the link it read back");

        // DsReplicaDel retires the link, so the connection object it was kept as
        // has to go with it rather than being restored for ever.
        DrsServer *drs = restarted.findChild<DrsServer *>();
        QVERIFY2(drs, "the restarted service has no DRSUAPI endpoint");
        const QByteArray handle = drs->handleCall(0, bindRequest()).mid(64, 20);
        QCOMPARE(readLe32(drs->handleCall(6, replicaDelRequest(handle, restarted.baseDn(), address)),
                          0),
                 quint32(0));
        restarted.stop();
    }

    QFile retired(storePath);
    QVERIFY2(retired.open(QIODevice::ReadOnly), qPrintable(storePath));
    QVERIFY2(!retired.readAll().contains("nTDSConnection"),
             "DsReplicaDel retired the source but left its connection object behind");
    retired.close();

    {
        DcService again;
        QSignalSpy messages(&again, &DcService::statusMessage);
        QVERIFY2(again.start(dir.path()),
                 "the daemon refused to start on the directory after the link was retired");
        bool none = false;
        for (const QString &line : spokenMessages(messages)) {
            QVERIFY2(!(line.contains(QStringLiteral("Restored"))
                       && line.contains(QStringLiteral("from the directory"))),
                     "the retired link was restored again");
            if (line.contains(QStringLiteral("No replication partner")))
                none = true;
        }
        QVERIFY2(none, "the daemon did not report that no partner is left after the deletion");
        again.stop();
    }
}

// Replication is what makes a partner's own Server object appear in this store,
// and the KCC's job is to turn that into a link without an administrator naming
// it at both ends. This drives the daemon-side wiring that the topology unit
// cases cannot see: the pass at start-up, the message it reports, and the link
// landing in the store as a generated connection object.
void DcServiceTest::kccAddsTheConnectionASecondDcInTheSiteNeeds()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    ProvisionConfig config;
    config.realm = QStringLiteral("KCC.EXAMPLE.ORG");
    config.netbiosDomain = QStringLiteral("KCC");
    config.adminPassword = QStringLiteral("Secret123!");
    config.targetDir = dir.path();
    config.devPorts = true;
    const ProvisionResult result = provisionDomain(config);
    QVERIFY2(result.ok, qPrintable(result.error));
    moveTakenPorts(dir.path());

    // The store as the daemon left it, plus the objects replication would bring
    // from a second DC in the same site.
    const QString storePath = dir.path() + QStringLiteral("/private/directory.json");
    const QString configNc =
        QStringLiteral("CN=Configuration,%1").arg(result.baseDn);
    const QString serversDn =
        QStringLiteral("CN=Servers,CN=Default-First-Site-Name,CN=Sites,%1").arg(configNc);
    const QString partnerHost =
        QStringLiteral("dc2.%1").arg(result.dnsDomain.toLower());
    {
        LdapServer store;
        QVERIFY2(store.loadFromFile(storePath), qPrintable(storePath));
        QList<DirectoryObject> objects = store.objects();

        DirectoryObject server;
        server.id = QStringLiteral("CN=DC2,%1").arg(serversDn);
        server.name = QStringLiteral("DC2");
        server.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("top;server"));
        server.attributes.insert(QStringLiteral("cn"), QStringLiteral("DC2"));
        server.attributes.insert(QStringLiteral("dNSHostName"), partnerHost);
        objects.append(server);

        DirectoryObject ntds;
        ntds.id = QStringLiteral("CN=NTDS Settings,%1").arg(server.id);
        ntds.name = QStringLiteral("NTDS Settings");
        ntds.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("top;nTDSDSA"));
        objects.append(ntds);

        store.setObjects(objects);
        QVERIFY2(store.saveToFile(storePath), qPrintable(storePath));
    }

    const QString selfDn = QStringLiteral("CN=NTDS Settings,CN=%1,%2")
                               .arg(result.dcHost.section(QLatin1Char('.'), 0, 0).toUpper(),
                                    serversDn);
    {
        DcService service;
        QSignalSpy messages(&service, &DcService::statusMessage);
        QVERIFY2(service.start(dir.path()),
                 "the daemon refused to start with a partner published in its site");

        bool connected = false;
        bool pulling = false;
        for (const QString &line : spokenMessages(messages)) {
            if (line.contains(QStringLiteral("The KCC added a connection"))
                && line.contains(partnerHost))
                connected = true;
            if (line.contains(partnerHost) && line.contains(QStringLiteral("registered")))
                pulling = true;
        }
        QVERIFY2(connected, "the KCC never added the connection its site needs");
        QVERIFY2(pulling, "the connection the KCC added was not registered as a source");
        service.stop();
    }

    // What the next start reads: a generated connection object under this DSA's
    // own NTDS Settings, naming DC2 and marked as the KCC's to manage.
    LdapServer reread;
    QVERIFY2(reread.loadFromFile(storePath), qPrintable(storePath));
    bool found = false;
    for (const DirectoryObject &object : reread.objects()) {
        if (!object.id.endsWith(QLatin1Char(',') + selfDn, Qt::CaseInsensitive))
            continue;
        if (!object.id.contains(partnerHost, Qt::CaseInsensitive))
            continue;
        found = true;
        QCOMPARE(object.attributes.value(QStringLiteral("options")), QStringLiteral("1"));
        QCOMPARE(object.attributes.value(QStringLiteral("enabledConnection")),
                 QStringLiteral("TRUE"));
        QCOMPARE(object.attributes.value(QStringLiteral("fromServer")),
                 QStringLiteral("CN=NTDS Settings,CN=DC2,%1").arg(serversDn));
    }
    QVERIFY2(found, "no KCC connection object for the partner was kept in the store");
}

// A DC persists what a client changed before it answers. This matters to the
// customers who back up with their own tools: a tape or CD-R job copies
// private/directory.json while the daemon runs, so a write that lives only in
// memory is silently missing from the backup. The store is read back here with
// the service still running, which is exactly what that job sees.
void DcServiceTest::commitsClientWritesWhileItRuns()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    ProvisionConfig config;
    config.realm = QStringLiteral("BACKUP.EXAMPLE.ORG");
    config.netbiosDomain = QStringLiteral("BACKUP");
    config.adminPassword = QStringLiteral("Secret123!");
    config.targetDir = dir.path();
    config.devPorts = true;
    const ProvisionResult result = provisionDomain(config);
    QVERIFY2(result.ok, qPrintable(result.error));
    moveTakenPorts(dir.path());

    DcService service;
    QVERIFY2(service.start(dir.path()),
             "the daemon refused to start on a domain it had just provisioned");

    const quint16 ldapPort = declaredPorts(dir.path()).value(QStringLiteral("ldapPort"));
    QVERIFY2(ldapPort != 0, "dc.conf declares no ldapPort");

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, ldapPort);
    QVERIFY2(socket.waitForConnected(5000), "the LDAP port accepted no connection");
    ldapwire::Reader reader(&socket);

    const QByteArray adminDn = QStringLiteral("CN=Administrator,CN=Users,%1")
                                   .arg(service.baseDn())
                                   .toUtf8();
    const QByteArray bind = ldapRoundTrip(
        socket, reader, ldapwire::bindRequest(1, adminDn, QByteArrayLiteral("Secret123!")));
    QVERIFY2(!bind.isEmpty(), "the DC answered no bind");
    QCOMPARE(ldapwire::resultCode(bind), 0);

    const QString dn = QStringLiteral("CN=TapeCopy,CN=Users,%1").arg(service.baseDn());
    const QByteArray add = ldapRoundTrip(
        socket, reader,
        ldapwire::addRequest(
                    2, dn.toUtf8(),
                    {{QByteArrayLiteral("objectClass"),
                      {QByteArrayLiteral("top"), QByteArrayLiteral("person"),
                       QByteArrayLiteral("organizationalPerson"), QByteArrayLiteral("user")}},
                     {QByteArrayLiteral("cn"), {QByteArrayLiteral("TapeCopy")}},
                     {QByteArrayLiteral("sAMAccountName"), {QByteArrayLiteral("tapecopy")}}}));
    QVERIFY2(!add.isEmpty(), "the DC answered no add");
    QCOMPARE(ldapwire::resultCode(add), 0);

    // Read the store the way a backup job does: while this process still runs,
    // with no stop() in between.
    QFile store(dir.path() + QStringLiteral("/private/directory.json"));
    QVERIFY2(store.open(QIODevice::ReadOnly), "the store is not where the provisioner put it");
    const QByteArray saved = store.readAll();
    store.close();
    QVERIFY2(saved.contains("TapeCopy"),
             "the add was answered but the store a backup would copy does not have the entry");
    QVERIFY2(saved.contains("tapecopy"),
             "the account name the client added is missing from the store on disk");

    service.stop();
}

QTEST_GUILESS_MAIN(DcServiceTest)

#include "test_dcservice.moc"
