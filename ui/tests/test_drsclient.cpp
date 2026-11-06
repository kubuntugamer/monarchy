// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The outbound half of replication: a client that binds a peer's DRSUAPI
// endpoint, pulls a GetNCChanges cycle and hands the decoded objects to
// LdapServer::applyReplication. The marshal layer is exercised against replies
// the server built with no socket at all; the convergence case runs the whole
// thing over loopback, with the peer's server on its own thread because the
// client blocks while it waits and a same-thread peer would never accept.

#include <QtTest>

#include <QMutex>
#include <QMutexLocker>
#include <QSemaphore>
#include <QThread>

#include <functional>
#include <utility>

#include "Drs.h"
#include "DrsClient.h"
#include "LdapServer.h"

namespace {

const QString kBaseDn = QStringLiteral("DC=corp,DC=example,DC=com");

Samr::Config config()
{
    Samr::Config out;
    out.realm = QStringLiteral("CORP.EXAMPLE.COM");
    out.netbios = QStringLiteral("CORP");
    out.baseDn = kBaseDn;
    out.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    return out;
}

DirectoryObject domainObject()
{
    DirectoryObject domain;
    domain.id = kBaseDn;
    domain.name = QStringLiteral("corp.example.com");
    domain.type = QStringLiteral("Domain");
    domain.attributes.insert(QStringLiteral("uSNChanged"), QStringLiteral("1"));
    return domain;
}

DirectoryObject alice()
{
    DirectoryObject user;
    user.id = QStringLiteral("CN=alice,CN=Users,") + kBaseDn;
    user.name = QStringLiteral("alice");
    user.type = QStringLiteral("User");
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("userPrincipalName"),
                           QStringLiteral("alice@corp.example.com"));
    user.attributes.insert(QStringLiteral("objectGUID"),
                           QStringLiteral("{33333333-3333-3333-3333-333333333333}"));
    user.attributes.insert(QStringLiteral("uSNChanged"), QStringLiteral("2"));
    return user;
}

QList<DirectoryObject> fixture()
{
    return QList<DirectoryObject>{domainObject(), alice()};
}

const DirectoryObject *liveObject(const LdapServer &store, const QString &name)
{
    for (const DirectoryObject &object : store.objects()) {
        if (object.name == name)
            return &object;
    }
    return nullptr;
}

// The store the peer serves, guarded because the peer reads it on its own
// thread while the test rewrites it between cycles.
struct SharedObjects {
    QMutex mutex;
    QList<DirectoryObject> objects;

    QList<DirectoryObject> snapshot()
    {
        QMutexLocker lock(&mutex);
        return objects;
    }
    void set(const QList<DirectoryObject> &next)
    {
        QMutexLocker lock(&mutex);
        objects = next;
    }
};

// A DrsServer with its own event loop, so a blocking client on the test thread
// can talk to it.
class DrsServerThread : public QThread
{
public:
    DrsServerThread(std::function<QList<DirectoryObject>()> provider, Samr::Config config,
                    bool rejectAuthentication = false)
        : m_provider(std::move(provider))
        , m_config(std::move(config))
        , m_rejectAuthentication(rejectAuthentication)
    {
    }

    void waitUntilListening()
    {
        m_ready.acquire();
    }

    quint16 port() const { return m_port; }

protected:
    void run() override
    {
        DrsServer server;
        server.setConfig(m_config);
        server.setObjectProvider(m_provider);
        if (m_rejectAuthentication) {
            server.setAuthenticator([](const Rpc::AuthRequest &, Ntlm::SessionKeys *) {
                return false;
            });
        }
        const bool listening = server.listen(0);
        m_port = listening ? server.serverPort() : 0;
        m_ready.release();
        if (listening)
            exec();
    }

private:
    std::function<QList<DirectoryObject>()> m_provider;
    Samr::Config m_config;
    bool m_rejectAuthentication = false;
    quint16 m_port = 0;
    QSemaphore m_ready;
};

} // namespace

class DrsClientTest : public QObject
{
    Q_OBJECT

private slots:
    // The wire layer alone: a bind reply and a GetNCChanges reply produced by
    // the server, decoded without a socket. If this fails the framing is
    // wrong, not the network.
    void marshalRoundTripWithoutASocket()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([]() { return fixture(); });

        QByteArray handle;
        quint32 werr = 1;
        QVERIFY(DrsWire::parseDsBindReply(server.handleCall(0, DrsWire::dsBindRequest()),
                                          &handle, &werr));
        QCOMPARE(werr, quint32(0));
        QCOMPARE(handle.size(), DrsWire::kHandleSize);

        QList<DirectoryObject> objects;
        quint64 usnHigh = 0;
        bool moreData = true;
        QVERIFY(DrsWire::parseGetNCChangesReply(
            server.handleCall(3, DrsWire::getNCChangesRequest(handle, kBaseDn, 0, 1000)),
            &objects, &usnHigh, &moreData, &werr));
        QCOMPARE(werr, quint32(0));
        QVERIFY(!moreData);
        QCOMPARE(objects.size(), 2);
        QVERIFY(usnHigh > 0);

        const DirectoryObject *user = nullptr;
        for (const DirectoryObject &object : objects) {
            if (object.name == QStringLiteral("alice"))
                user = &object;
        }
        QVERIFY(user != nullptr);
        QCOMPARE(user->type, QStringLiteral("User"));
        QCOMPARE(user->attributes.value(QStringLiteral("sAMAccountName")),
                 QStringLiteral("alice"));
        QVERIFY(!user->attributes.value(QStringLiteral("objectGUID")).isEmpty());
    }

    // A capped cycle reports fMoreData and the cursor it reached, and asking
    // again from that cursor delivers the rest. This is the loop a pull
    // replication runs.
    void batchingAsksAgainUntilMoreDataIsFalse()
    {
        DrsServer server;
        server.setConfig(config());
        server.setObjectProvider([]() { return fixture(); });

        QByteArray handle;
        quint32 werr = 1;
        QVERIFY(DrsWire::parseDsBindReply(server.handleCall(0, DrsWire::dsBindRequest()),
                                          &handle, &werr));

        QStringList delivered;
        quint64 fromUsn = 0;
        bool moreData = true;
        int cycles = 0;
        while (moreData && cycles < 10) {
            QList<DirectoryObject> objects;
            quint64 usnHigh = 0;
            QVERIFY(DrsWire::parseGetNCChangesReply(
                server.handleCall(3, DrsWire::getNCChangesRequest(handle, kBaseDn, fromUsn, 1)),
                &objects, &usnHigh, &moreData, &werr));
            QCOMPARE(werr, quint32(0));
            QVERIFY(objects.size() <= 1);
            for (const DirectoryObject &object : objects)
                delivered.append(object.id);
            QVERIFY(usnHigh >= fromUsn);
            fromUsn = usnHigh;
            ++cycles;
        }
        QVERIFY(!moreData);
        QCOMPARE(cycles, 2);
        QCOMPARE(delivered.size(), 2);
    }

    // The whole path over a socket: bind, DsBind, GetNCChanges, apply. The
    // second store must end up holding what the first one serves, and must
    // follow a later deletion instead of keeping a stale copy.
    void secondDcConvergesOverTheRpcWire()
    {
        LdapServer source;
        source.addObject(domainObject());
        source.addObject(alice());

        SharedObjects shared;
        shared.set(source.objects() + source.tombstones());

        DrsServerThread peer([&shared]() { return shared.snapshot(); }, config());
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), peer.port());
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY2(client.dsBind(&error), qPrintable(error));

        LdapServer target;
        target.addObject(domainObject());

        quint64 fromUsn = 0;
        bool moreData = false;
        int cycles = 0;
        do {
            QList<DirectoryObject> objects;
            quint64 usnHigh = 0;
            QVERIFY2(client.getNCChanges(kBaseDn, fromUsn, &objects, &usnHigh, &moreData,
                                         &error),
                     qPrintable(error));
            target.applyReplication(objects);
            fromUsn = usnHigh;
            ++cycles;
        } while (moreData && cycles < 10);

        const DirectoryObject *aliceOnTarget = liveObject(target, QStringLiteral("alice"));
        QVERIFY(aliceOnTarget != nullptr);
        QCOMPARE(aliceOnTarget->attributes.value(QStringLiteral("sAMAccountName")),
                 QStringLiteral("alice"));
        QCOMPARE(aliceOnTarget->attributes.value(QStringLiteral("objectGUID")).toLower(),
                 QStringLiteral("{33333333-3333-3333-3333-333333333333}"));

        // The deletion travels the same way: the source keeps a tombstone and
        // the target turns its live copy into one.
        QVERIFY(source.removeObject(alice().id));
        shared.set(source.objects() + source.tombstones());
        QList<DirectoryObject> deletion;
        quint64 deletionUsn = 0;
        moreData = false;
        QVERIFY2(client.getNCChanges(kBaseDn, 0, &deletion, &deletionUsn, &moreData, &error),
                 qPrintable(error));
        QVERIFY(target.applyReplication(deletion) >= 1);
        QVERIFY(liveObject(target, QStringLiteral("alice")) == nullptr);
        QCOMPARE(target.tombstones().size(), 1);

        QVERIFY2(client.dsUnbind(&error), qPrintable(error));
        client.close();
        peer.quit();
        QVERIFY(peer.wait(5000));
    }

    // The authentication leg is not implemented on this client, and it says so
    // rather than pretending: an endpoint that requires authentication accepts
    // the transport bind and faults the call.
    void anAuthenticatedPeerRefusesTheCallNotTheBind()
    {
        DrsServerThread peer([]() { return fixture(); }, config(), true);
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), peer.port());
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY(!client.dsBind(&error));
        QVERIFY2(error.contains(QStringLiteral("faulted")), qPrintable(error));
        client.close();
        peer.quit();
        QVERIFY(peer.wait(5000));
    }
};

QTEST_MAIN(DrsClientTest)
#include "test_drsclient.moc"
