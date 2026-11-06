// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The outbound half of replication: a client that binds a peer's DRSUAPI
// endpoint, authenticates with NTLMSSP, pulls a GetNCChanges cycle and hands
// the decoded objects to LdapServer::applyReplication. The marshal layer is
// exercised against replies the server built with no socket at all; the
// convergence cases run the whole thing over loopback, with the peer's server
// on its own thread because the client blocks while it waits.

#include <QtTest>

#include <QHash>
#include <QHostAddress>
#include <QMutex>
#include <QMutexLocker>
#include <QSemaphore>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>

#include <functional>
#include <utility>

#include "Drs.h"
#include "DrsClient.h"
#include "LdapServer.h"
#include "Ntlm.h"
#include "ReplicationAgent.h"

namespace {

const QString kBaseDn = QStringLiteral("DC=corp,DC=example,DC=com");
const QString kDomain = QStringLiteral("CORP");
const QString kAccount = QStringLiteral("svc-repl");
const QString kPassword = QStringLiteral("R3pl!cate-2026");

Samr::Config config()
{
    Samr::Config out;
    out.realm = QStringLiteral("CORP.EXAMPLE.COM");
    out.netbios = kDomain;
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

// The acceptor side, wired the way DcService wires it: the password's NT hash
// verifies the NTLMv2 response and derives the keys the per-PDU signatures use.
Rpc::Authenticator passwordAuthenticator(const QString &domain, const QString &user,
                                         const QString &password)
{
    const QByteArray ntHash = Ntlm::ntowfV1(password);
    return [domain, user, ntHash](const Rpc::AuthRequest &request, Ntlm::SessionKeys *keys) {
        if (request.user.compare(user, Qt::CaseInsensitive) != 0
            || request.domain.compare(domain, Qt::CaseInsensitive) != 0)
            return false;
        if (!Ntlm::verifyNtlmv2(ntHash, request.user, request.domain, request.challenge,
                                request.ntResponse))
            return false;
        return Ntlm::sessionKeys(ntHash, request.user, request.domain,
                                 request.ntResponse.left(16), keys, request.flags);
    };
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

// A stand-in for a host's endpoint mapper: it answers the DCE bind and then an
// ept_lookup with a tower naming the port the peer actually serves on. Windows
// registers DRSUAPI the same way, on a port nobody configured by hand.
class EpmStubServer : public QObject
{
public:
    explicit EpmStubServer(quint16 dynamicPort) : m_dynamicPort(dynamicPort)
    {
        m_server.listen(QHostAddress::LocalHost, 0);
        connect(&m_server, &QTcpServer::newConnection, this, [this]() {
            while (QTcpSocket *socket = m_server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::readyRead, this,
                        [this, socket]() { onData(socket); });
                connect(socket, &QObject::destroyed, this,
                        [this, socket]() { m_buffers.remove(socket); });
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            }
        });
    }

    quint16 port() const { return m_server.serverPort(); }

private:
    void onData(QTcpSocket *socket)
    {
        QByteArray &buffer = m_buffers[socket];
        buffer.append(socket->readAll());
        while (buffer.size() >= 16) {
            const quint16 length = quint16(quint8(buffer.at(8)) | (quint8(buffer.at(9)) << 8));
            if (length < 16 || buffer.size() < length)
                break;
            const QByteArray pdu = buffer.left(length);
            buffer.remove(0, length);
            answer(socket, pdu);
        }
    }

    void answer(QTcpSocket *socket, const QByteArray &pdu)
    {
        const quint8 type = quint8(pdu.at(2));
        const quint32 callId = quint32(quint8(pdu.at(12)))
                               | (quint32(quint8(pdu.at(13))) << 8)
                               | (quint32(quint8(pdu.at(14))) << 16)
                               | (quint32(quint8(pdu.at(15))) << 24);
        if (type == 11)
            socket->write(bindAck(callId));
        else if (type == 0)
            socket->write(lookupReply(callId));
    }

    static void appendLe16(QByteArray &out, quint16 value)
    {
        out.append(char(value & 0xff));
        out.append(char((value >> 8) & 0xff));
    }
    static void appendLe32(QByteArray &out, quint32 value)
    {
        appendLe16(out, quint16(value & 0xffff));
        appendLe16(out, quint16(value >> 16));
    }
    static QByteArray responsePdu(quint8 type, quint32 callId, const QByteArray &body)
    {
        const int overhead = type == 2 ? 24 : 16; // a response echoes the call header
        const quint16 total = quint16(overhead + body.size());
        QByteArray out;
        out.append(char(5));    // rpc_vers
        out.append(char(0));    // rpc_vers_minor
        out.append(char(type)); // PTYPE
        out.append(char(0x03)); // first | last fragment
        out.append(char(0x10)); // little-endian
        out.append(QByteArray(3, '\0'));
        appendLe16(out, total);
        out.append(QByteArray(2, '\0')); // auth_length
        appendLe32(out, callId);
        if (type == 2)
            out.append(QByteArray(8, '\0')); // alloc_hint, context, cancel, reserved
        out.append(body);
        return out;
    }

    QByteArray bindAck(quint32 callId) const
    {
        QByteArray body;
        appendLe16(body, 5840);   // max_xmit_frag
        appendLe16(body, 5840);   // max_recv_frag
        appendLe32(body, 0x1001); // assoc_group
        appendLe16(body, 0);      // secondary address length
        appendLe16(body, 0);
        body.append(char(1)); // one presented context
        body.append(QByteArray(3, '\0'));
        appendLe16(body, 0); // acceptance
        appendLe16(body, 0); // reason
        body.append(Rpc::kNdrSyntaxUuid);
        appendLe32(body, 2); // NDR32
        return responsePdu(12, callId, body);
    }

    QByteArray lookupReply(quint32 callId) const
    {
        // Floors name their protocol in the left-hand side; the transport floor
        // carries the port in network order.
        QByteArray tower;
        appendLe16(tower, 2); // two floors
        appendLe16(tower, 16);
        tower.append(Rpc::kNdrSyntaxUuid); // the interface's own floor
        appendLe16(tower, 4);
        appendLe16(tower, 3);
        appendLe16(tower, 0);
        appendLe16(tower, 16);
        tower.append(QByteArray::fromHex("8a885d041ceb11c99fe808002b104860")); // TCP
        appendLe16(tower, 4);
        tower.append(char((m_dynamicPort >> 8) & 0xff));
        tower.append(char(m_dynamicPort & 0xff));
        appendLe16(tower, 0);
        appendLe16(tower, 0); // a tower closes with the first floor's length

        QByteArray stub;
        stub.append(QByteArray(20, '\0')); // ept_lookup_handle
        appendLe32(stub, 1);               // one entry
        appendLe32(stub, 0);               // entry status
        appendLe32(stub, quint32(tower.size()));
        appendLe32(stub, 0); // octet-string offset
        stub.append(tower);
        while (stub.size() % 4 != 0)
            stub.append('\0');
        return responsePdu(2, callId, stub);
    }

    QTcpServer m_server;
    quint16 m_dynamicPort;
    QHash<QTcpSocket *, QByteArray> m_buffers;
};

// A DrsServer with its own event loop, so a blocking client on the test thread
// can talk to it. It stands behind an endpoint mapper, as a DC does.
class DrsServerThread : public QThread
{
public:
    DrsServerThread(std::function<QList<DirectoryObject>()> provider, Samr::Config config,
                    Rpc::Authenticator authenticator = {})
        : m_provider(std::move(provider))
        , m_config(std::move(config))
        , m_authenticator(std::move(authenticator))
    {
    }

    ~DrsServerThread() override
    {
        // A test that fails before it quits the peer must not turn into an
        // abort: destroy the thread only once its event loop has stopped.
        quit();
        wait(5000);
    }

    void waitUntilListening()
    {
        m_ready.acquire();
    }

    quint16 port() const { return m_port; }
    quint16 epmPort() const { return m_epmPort; }

protected:
    void run() override
    {
        DrsServer server;
        server.setConfig(m_config);
        server.setObjectProvider(m_provider);
        if (m_authenticator) {
            server.setDomainNames(kDomain, QStringLiteral("DC01"),
                                  QStringLiteral("corp.example.com"));
            server.setAuthenticator(m_authenticator);
        }
        QObject::connect(&server, &DrsServer::requestReceived, [](const QString &line) {
            qWarning("DRS: %s", qPrintable(line));
        });
        const bool listening = server.listen(0);
        m_port = listening ? server.serverPort() : 0;
        EpmStubServer epm(m_port);
        m_epmPort = epm.port();
        m_ready.release();
        if (listening)
            exec();
    }

private:
    std::function<QList<DirectoryObject>()> m_provider;
    Samr::Config m_config;
    Rpc::Authenticator m_authenticator;
    quint16 m_port = 0;
    quint16 m_epmPort = 0;
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

    // The whole path over a socket, authenticated: bind, NTLMSSP, DsBind,
    // signed and sealed GetNCChanges, apply. The second store must end up
    // holding what the first one serves, and must follow a later deletion.
    void anAuthenticatedPeerAnswersASealedSession()
    {
        LdapServer source;
        source.addObject(domainObject());
        source.addObject(alice());

        SharedObjects shared;
        shared.set(source.objects() + source.tombstones());

        DrsServerThread peer([&shared]() { return shared.snapshot(); }, config(),
                             passwordAuthenticator(kDomain, kAccount, kPassword));
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), peer.port());
        client.setCredentials(kDomain, kAccount, kPassword);
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY(client.isAuthenticated());
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

        // The deletion travels the same signed session.
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

    // A host without a port is enough: the endpoint mapper names the DRSUAPI
    // port, and the session then runs exactly as it does with a known port.
    void aDynamicPeerPortIsFoundThroughTheEndpointMapper()
    {
        DrsServerThread peer([]() { return fixture(); }, config());
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);
        QVERIFY(peer.epmPort() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), 0);
        client.setEpmPort(peer.epmPort());
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QCOMPARE(client.peerPort(), peer.port());
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY2(client.dsBind(&error), qPrintable(error));

        QList<DirectoryObject> objects;
        quint64 usnHigh = 0;
        bool moreData = false;
        QVERIFY2(client.getNCChanges(kBaseDn, 0, &objects, &usnHigh, &moreData, &error),
                 qPrintable(error));
        QCOMPARE(objects.size(), 2);

        client.close();
        peer.quit();
        QVERIFY(peer.wait(5000));
    }

    // The agent is the DRA half: a partner named once, pulled when asked,
    // applying into a real store with a cursor that survives between pulls.
    void aPullAgentConvergesTwoStores()
    {
        SharedObjects shared;
        shared.set(fixture());

        DrsServerThread peer([&shared]() { return shared.snapshot(); }, config());
        peer.start();
        peer.waitUntilListening();

        LdapServer target;
        ReplicationAgent agent;
        agent.setSource(QStringLiteral("127.0.0.1"), peer.port());
        agent.setNamingContext(kBaseDn);
        agent.setSink([&target](const QList<DirectoryObject> &objects) {
            return target.applyReplication(objects);
        });

        QString error;
        const int first = agent.pullOnce(&error);
        QVERIFY2(first >= 0, qPrintable(error));
        QCOMPARE(first, 2);
        QVERIFY(liveObject(target, QStringLiteral("alice")) != nullptr);
        QVERIFY(agent.lastUsn() > 0);

        // The cursor is the point: a second pull takes nothing new.
        QCOMPARE(agent.pullOnce(&error), 0);

        peer.quit();
        QVERIFY(peer.wait(5000));
    }

    // A deletion reaches the other store through the same agent, and the store
    // keeps it as a tombstone rather than forgetting the object ever existed.
    void aPullAgentCarriesDeletions()
    {
        LdapServer source;
        source.addObject(domainObject());
        source.addObject(alice());

        SharedObjects shared;
        shared.set(source.objects() + source.tombstones());

        DrsServerThread peer([&shared]() { return shared.snapshot(); }, config());
        peer.start();
        peer.waitUntilListening();

        LdapServer target;
        ReplicationAgent agent;
        agent.setSource(QStringLiteral("127.0.0.1"), peer.port());
        agent.setNamingContext(kBaseDn);
        agent.setSink([&target](const QList<DirectoryObject> &objects) {
            return target.applyReplication(objects);
        });

        QString error;
        QVERIFY2(agent.pullOnce(&error) >= 0, qPrintable(error));
        QVERIFY(liveObject(target, QStringLiteral("alice")) != nullptr);

        QVERIFY(source.removeObject(alice().id));
        shared.set(source.objects() + source.tombstones());
        const int second = agent.pullOnce(&error);
        QVERIFY2(second >= 1,
                 qPrintable(QStringLiteral("applied=%1 cursor=%2 error=%3")
                                .arg(second)
                                .arg(agent.lastUsn())
                                .arg(error)));
        QVERIFY(liveObject(target, QStringLiteral("alice")) == nullptr);
        QCOMPARE(target.tombstones().size(), 1);

        peer.quit();
        QVERIFY(peer.wait(5000));
    }

    // A wrong password completes the transport bind and the challenge, then the
    // first call is refused: the client never gets a usable session.
    void aWrongPasswordIsRefused()
    {
        DrsServerThread peer([]() { return fixture(); }, config(),
                             passwordAuthenticator(kDomain, kAccount, kPassword));
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), peer.port());
        client.setCredentials(kDomain, kAccount, QStringLiteral("not-the-password"));
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY(!client.dsBind(&error));
        // A rejected AUTHENTICATE ends the session: the peer either faults the
        // next call or, as this tree's server does, hangs up so no call can be
        // served without a completed authentication.
        QVERIFY2(error.contains(QStringLiteral("faulted"))
                     || error.contains(QStringLiteral("closed")),
                 qPrintable(error));
        client.close();
        peer.quit();
        QVERIFY(peer.wait(5000));
    }

    // With no credentials the client sends no verifier, and a peer that
    // enforces authentication refuses the call rather than serving it.
    void anAuthenticatedPeerRefusesAnUnboundCall()
    {
        DrsServerThread peer([]() { return fixture(); }, config(),
                             [](const Rpc::AuthRequest &, Ntlm::SessionKeys *) { return false; });
        peer.start();
        peer.waitUntilListening();
        QVERIFY(peer.port() != 0);

        DrsClient client;
        client.setPeer(QStringLiteral("127.0.0.1"), peer.port());
        QString error;
        QVERIFY2(client.connectToPeer(&error), qPrintable(error));
        QVERIFY2(client.bindInterface(&error), qPrintable(error));
        QVERIFY(!client.isAuthenticated());
        QVERIFY(!client.dsBind(&error));
        QVERIFY2(error.contains(QStringLiteral("faulted")), qPrintable(error));
        client.close();
        peer.quit();
        QVERIFY(peer.wait(5000));
    }
};

QTEST_MAIN(DrsClientTest)
#include "test_drsclient.moc"
