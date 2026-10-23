// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QElapsedTimer>
#include <QProcess>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTemporaryDir>

#include "LdapServer.h"
#include "Provisioner.h"
#include "SampleData.h"

namespace {

// Minimal BER writer, enough to build the requests this suite sends.
QByteArray tlv(char tag, const QByteArray &content)
{
    QByteArray out;
    out.append(tag);
    const int len = content.size();
    if (len < 0x80) {
        out.append(char(len));
    } else if (len <= 0xff) {
        out.append(char(0x81));
        out.append(char(len));
    } else {
        out.append(char(0x82));
        out.append(char((len >> 8) & 0xff));
        out.append(char(len & 0xff));
    }
    out.append(content);
    return out;
}

QByteArray ldapInt(int value)
{
    QByteArray out;
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
    return out;
}

QByteArray ldapMessage(int id, char opTag, const QByteArray &opContent)
{
    QByteArray body = tlv(0x02, ldapInt(id));
    body += tlv(opTag, opContent);
    return tlv(0x30, body);
}

QByteArray startTlsRequest(int id)
{
    return ldapMessage(id, char(0x77),
                       tlv(char(0x80), QByteArray("1.3.6.1.4.1.1466.20037")));
}

QByteArray bindRequest(int id, const QByteArray &dn, const QByteArray &password)
{
    QByteArray inner = tlv(0x02, ldapInt(3));
    inner += tlv(0x04, dn);
    inner += tlv(char(0x80), password);
    return ldapMessage(id, char(0x60), inner);
}

// Subtree search for (objectClass=*) with no attributes requested.
QByteArray searchRequest(int id, const QByteArray &base)
{
    QByteArray inner = tlv(0x04, base);
    inner += tlv(char(0x0a), QByteArray(1, char(2))); // scope: wholeSubtree
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    return ldapMessage(id, char(0x63), inner);
}

bool nextElement(const QByteArray &data, int *pos, int *tag, QByteArray *content)
{
    if (*pos + 2 > data.size())
        return false;
    *tag = (unsigned char)data.at((*pos)++);
    int length = (unsigned char)data.at((*pos)++);
    if (length & 0x80) {
        const int count = length & 0x7f;
        if (*pos + count > data.size())
            return false;
        length = 0;
        for (int i = 0; i < count; ++i)
            length = (length << 8) | (unsigned char)data.at((*pos)++);
    }
    if (*pos + length > data.size())
        return false;
    *content = data.mid(*pos, length);
    *pos += length;
    return true;
}

// Total size of the BER element at the head of `data`, or -1 when the header is
// still incomplete.
int frameSize(const QByteArray &data)
{
    if (data.size() < 2)
        return -1;
    int length = (unsigned char)data.at(1);
    int header = 2;
    if (length & 0x80) {
        const int count = length & 0x7f;
        if (data.size() < 2 + count)
            return -1;
        length = 0;
        for (int i = 0; i < count; ++i)
            length = (length << 8) | (unsigned char)data.at(2 + i);
        header = 2 + count;
    }
    return header + length;
}

// Reads LDAP messages off a socket while letting the server's event loop run:
// the test thread must return to the loop for the server to accept and answer.
class Reader
{
public:
    explicit Reader(QIODevice *device) : m_device(device) {}

    QByteArray next(int timeoutMs)
    {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            const int size = frameSize(m_buffer);
            if (size > 0 && m_buffer.size() >= size) {
                const QByteArray out = m_buffer.left(size);
                m_buffer.remove(0, size);
                return out;
            }
            if (m_device->bytesAvailable() > 0)
                m_buffer += m_device->readAll();
            else
                QTest::qWait(5);
        }
        return QByteArray();
    }

    // Any bytes that arrived but were not a complete LDAP message.
    QByteArray leftover() { return m_buffer + m_device->readAll(); }

private:
    QIODevice *m_device;
    QByteArray m_buffer;
};

// Result code of the first protocol op in an LDAPMessage, or -1.
int resultCode(const QByteArray &message)
{
    int pos = 0, tag = 0;
    QByteArray content;
    if (!nextElement(message, &pos, &tag, &content) || tag != 0x30)
        return -1;
    int inner = 0, msgIdTag = 0, opTag = 0;
    QByteArray ignored, op;
    if (!nextElement(content, &inner, &msgIdTag, &ignored) || msgIdTag != 0x02)
        return -1;
    if (!nextElement(content, &inner, &opTag, &op))
        return -1;
    int opPos = 0, rcTag = 0;
    QByteArray rc;
    if (!nextElement(op, &opPos, &rcTag, &rc) || rcTag != 0x0a || rc.size() != 1)
        return -1;
    return (unsigned char)rc.at(0);
}

// Protocol op tag of an LDAPMessage, or -1.
int operationTag(const QByteArray &message)
{
    int pos = 0, tag = 0;
    QByteArray content;
    if (!nextElement(message, &pos, &tag, &content) || tag != 0x30)
        return -1;
    int inner = 0, msgIdTag = 0, opTag = 0;
    QByteArray ignored;
    if (!nextElement(content, &inner, &msgIdTag, &ignored))
        return -1;
    if (!nextElement(content, &inner, &opTag, &ignored))
        return -1;
    return opTag;
}

// Provisions a throwaway domain, which is also what creates its DC certificate.
bool provision(QTemporaryDir &dir, ProvisionResult *result)
{
    ProvisionConfig config;
    config.realm = QStringLiteral("MONARCHY.TLS.TEST");
    config.netbiosDomain = QStringLiteral("MONARCHY");
    config.adminPassword = QStringLiteral("P@ssw0rd123!");
    config.targetDir = dir.path();
    config.force = true;
    *result = provisionDomain(config);
    return result->ok;
}

} // namespace

class TlsTest : public QObject
{
    Q_OBJECT

private slots:
    void refusesStartTlsWithoutCertificate();
    void upgradesAndServesLdapOverTls();
    void abortsWhenPlaintextFollowsStartTls();
    void independentClientVerifiesProvisionedCertificate();
};

// Without credentials the request must be refused, not answered with a success
// that leaves the connection in the clear — and the connection stays usable.
void TlsTest::refusesStartTlsWithoutCertificate()
{
    LdapServer server;
    server.setObjects(sampleObjects());
    QVERIFY(!server.tlsAvailable());
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    QCOMPARE(client.write(startTlsRequest(1)), qint64(startTlsRequest(1).size()));
    const QByteArray response = reader.next(5000);
    QVERIFY(!response.isEmpty());
    QCOMPARE(resultCode(response), 52); // unavailable

    // The refusal does not end the session: a plaintext bind still works.
    client.write(bindRequest(2, "CN=Alice Chen,OU=Users,DC=corp,DC=example,DC=com", "secret"));
    const QByteArray bindResponse = reader.next(5000);
    QVERIFY(!bindResponse.isEmpty());
    QCOMPARE(resultCode(bindResponse), 0);
}

// The full StartTLS upgrade against a real, provisioned DC identity: the client
// handshakes with TLS, checks the server certificate, then binds and searches
// through the encrypted stream.
void TlsTest::upgradesAndServesLdapOverTls()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("Qt has no TLS backend (OpenSSL) available");

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    ProvisionResult provisioned;
    QVERIFY2(provision(dir, &provisioned), qPrintable(provisioned.error));
    QVERIFY2(provisioned.tlsEnabled, qPrintable(provisioned.tlsError));

    LdapServer server;
    QVERIFY(server.loadFromFile(provisioned.storePath));
    QVERIFY(server.loadSecretsFromFile(provisioned.secretsPath));
    QString tlsError;
    QVERIFY2(server.loadTlsCredentials(provisioned.tlsCertPath, provisioned.tlsKeyPath, &tlsError),
             qPrintable(tlsError));
    QVERIFY(server.tlsAvailable());
    QVERIFY(server.listen(0));

    QSslSocket client;
    QSslConfiguration config = client.sslConfiguration();
    config.setPeerVerifyMode(QSslSocket::VerifyPeer);
    // The provisioned certificate is the only trust anchor this client has, so
    // a successful handshake proves the server presented it.
    config.setCaCertificates(QSslCertificate::fromPath(provisioned.tlsCertPath));
    client.setSslConfiguration(config);
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);

    client.write(startTlsRequest(1));
    const QByteArray response = reader.next(5000);
    QVERIFY(!response.isEmpty());
    QCOMPARE(resultCode(response), 0);

    client.startClientEncryption();
    // The server lives in this thread, so the handshake only advances while the
    // event loop runs: QTRY pumps it, a blocking wait would starve the server.
    QTRY_VERIFY_WITH_TIMEOUT(client.isEncrypted()
                                 || client.state() == QAbstractSocket::UnconnectedState,
                             10000);
    QVERIFY2(client.isEncrypted(), qPrintable(client.errorString()));
    QVERIFY(!client.sessionCipher().name().isEmpty());

    // The certificate the client validated is the one provisioning created.
    const QSslCertificate peer = client.peerCertificate();
    QVERIFY(!peer.isNull());
    QCOMPARE(peer.subjectInfo(QSslCertificate::CommonName).value(0), provisioned.dcHost);
    const QList<QString> san = peer.subjectAlternativeNames().values(QSsl::DnsEntry);
    QVERIFY2(san.contains(provisioned.dcHost), qPrintable(san.join(QLatin1Char(','))));
    QVERIFY(peer.isSelfSigned());

    // A wrong password over TLS is still refused.
    const QByteArray adminDn =
        QStringLiteral("CN=Administrator,CN=Users,%1").arg(provisioned.baseDn).toUtf8();
    client.write(bindRequest(2, adminDn, "wrong-password"));
    QCOMPARE(resultCode(reader.next(5000)), 49);

    // The real password authenticates over the encrypted stream.
    client.write(bindRequest(3, adminDn, "P@ssw0rd123!"));
    QCOMPARE(resultCode(reader.next(5000)), 0);

    // And LDAP works inside it: a subtree search returns an entry.
    client.write(searchRequest(4, provisioned.baseDn.toUtf8()));
    const QByteArray entry = reader.next(5000);
    QVERIFY(!entry.isEmpty());
    QCOMPARE(operationTag(entry), 0x64); // SearchResultEntry
}

// After the upgrade the stream is TLS: bytes that are not TLS records are not
// answered as LDAP, and the connection is dropped.
void TlsTest::abortsWhenPlaintextFollowsStartTls()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("Qt has no TLS backend (OpenSSL) available");

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    ProvisionResult provisioned;
    QVERIFY2(provision(dir, &provisioned), qPrintable(provisioned.error));
    QVERIFY2(provisioned.tlsEnabled, qPrintable(provisioned.tlsError));

    LdapServer server;
    QVERIFY(server.loadFromFile(provisioned.storePath));
    QVERIFY(server.loadTlsCredentials(provisioned.tlsCertPath, provisioned.tlsKeyPath));
    QVERIFY(server.listen(0));

    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(client.waitForConnected(3000));
    Reader reader(&client);
    client.write(startTlsRequest(1));
    QCOMPARE(resultCode(reader.next(5000)), 0);

    // A client that ignores the upgrade and speaks plaintext LDAP.
    client.write(bindRequest(2, "CN=Administrator,CN=Users,DC=monarchy,DC=tls,DC=test",
                             "P@ssw0rd123!"));

    // No LDAP response can arrive, and the server closes the connection.
    QTRY_COMPARE_WITH_TIMEOUT(client.state(), QAbstractSocket::UnconnectedState, 5000);
    const QByteArray leftover = reader.leftover();
    QVERIFY2(leftover.isEmpty() || (unsigned char)leftover.at(0) != 0x30,
             "the server answered plaintext LDAP on a TLS connection");
}

// openssl's own client performs the LDAP StartTLS exchange and validates the
// provisioned certificate as its trust anchor: proof that this is TLS on the
// wire, not only a Qt-to-Qt agreement.
void TlsTest::independentClientVerifiesProvisionedCertificate()
{
    const QString openssl = QStandardPaths::findExecutable(QStringLiteral("openssl"));
    if (openssl.isEmpty())
        QSKIP("openssl not installed");

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    ProvisionResult provisioned;
    QVERIFY2(provision(dir, &provisioned), qPrintable(provisioned.error));
    QVERIFY2(provisioned.tlsEnabled, qPrintable(provisioned.tlsError));

    LdapServer server;
    QVERIFY(server.loadFromFile(provisioned.storePath));
    QVERIFY(server.loadTlsCredentials(provisioned.tlsCertPath, provisioned.tlsKeyPath));
    QVERIFY(server.listen(0));

    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(openssl, {QStringLiteral("s_client"),
                            QStringLiteral("-starttls"), QStringLiteral("ldap"),
                            QStringLiteral("-connect"),
                            QStringLiteral("127.0.0.1:%1").arg(server.serverPort()),
                            QStringLiteral("-CAfile"), provisioned.tlsCertPath,
                            QStringLiteral("-verify_return_error"),
                            QStringLiteral("-brief"),
                            QStringLiteral("-ign_eof")});
    QVERIFY(process.waitForStarted(5000));

    QByteArray output;
    QElapsedTimer timer;
    timer.start();
    while (!output.contains("Verification") && timer.elapsed() < 20000
           && process.state() != QProcess::NotRunning) {
        if (process.bytesAvailable() > 0)
            output += process.readAll();
        else
            QTest::qWait(20);
    }
    process.kill();
    process.waitForFinished(5000);
    output += process.readAll();

    QVERIFY2(output.contains("Verification: OK"), output.constData());
    QVERIFY2(output.contains("CONNECTION ESTABLISHED"), output.constData());
}

QTEST_MAIN(TlsTest)
#include "test_tls.moc"
