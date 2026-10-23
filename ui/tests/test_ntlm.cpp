// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QElapsedTimer>
#include <QHostAddress>
#include <QTcpSocket>
#include <QRandomGenerator>

#include "LdapServer.h"
#include "Ntlm.h"
#include "SampleData.h"

namespace {

void putLen(QByteArray &out, int len)
{
    if (len < 0x80) {
        out.append(char(len));
        return;
    }
    QByteArray tmp;
    int value = len;
    while (value > 0) {
        tmp.prepend(char(value & 0xff));
        value >>= 8;
    }
    out.append(char(0x80 | tmp.size()));
    out.append(tmp);
}

void putTLV(QByteArray &out, quint8 tag, const QByteArray &value)
{
    out.append(char(tag));
    putLen(out, value.size());
    out.append(value);
}

void putInt(QByteArray &out, quint8 tag, int value)
{
    QByteArray body;
    if (value == 0) {
        body.append('\0');
    } else {
        int v = value;
        while (v > 0) {
            body.prepend(char(v & 0xff));
            v >>= 8;
        }
        if (body.at(0) & 0x80)
            body.prepend('\0');
    }
    putTLV(out, tag, body);
}

bool takeTLV(const QByteArray &data, int &pos, quint8 *tag, QByteArray *value)
{
    if (pos >= data.size())
        return false;
    *tag = quint8(data.at(pos++));
    if (pos >= data.size())
        return false;
    int len = quint8(data.at(pos++));
    if (len & 0x80) {
        const int bytes = len & 0x7f;
        if (bytes == 0 || pos + bytes > data.size())
            return false;
        len = 0;
        for (int i = 0; i < bytes; ++i)
            len = (len << 8) | quint8(data.at(pos++));
    }
    if (len < 0 || pos + len > data.size())
        return false;
    *value = data.mid(pos, len);
    pos += len;
    return true;
}

void putLE16(QByteArray &out, quint16 v)
{
    out.append(char(v & 0xff));
    out.append(char((v >> 8) & 0xff));
}

void putLE32(QByteArray &out, quint32 v)
{
    out.append(char(v & 0xff));
    out.append(char((v >> 8) & 0xff));
    out.append(char((v >> 16) & 0xff));
    out.append(char((v >> 24) & 0xff));
}

quint32 readLE32(const QByteArray &data, int pos)
{
    if (pos + 4 > data.size())
        return 0;
    return quint32(quint8(data[pos])) | (quint32(quint8(data[pos + 1])) << 8)
           | (quint32(quint8(data[pos + 2])) << 16) | (quint32(quint8(data[pos + 3])) << 24);
}

quint16 readLE16(const QByteArray &data, int pos)
{
    if (pos + 2 > data.size())
        return 0;
    return quint16(quint8(data[pos]) | (quint8(data[pos + 1]) << 8));
}

void putField(QByteArray &out, int length, int offset)
{
    putLE16(out, quint16(length));
    putLE16(out, quint16(length));
    putLE32(out, quint32(offset));
}

QByteArray field(const QByteArray &data, int pos)
{
    const int length = readLE16(data, pos);
    const int offset = int(readLE32(data, pos + 4));
    if (length <= 0 || offset + length > data.size())
        return {};
    return data.mid(offset, length);
}

QByteArray negotiateToken()
{
    const quint32 flags = 0x00000001u | 0x00000200u | 0x00080000u | 0x00800000u
                          | 0x20000000u | 0x80000000u; // unicode, ntlm, ess, target info, 128, 56
    QByteArray token("NTLMSSP\0", 8);
    putLE32(token, 1);
    putLE32(token, flags);
    return token;
}

// NTLMv2 AUTHENTICATE for a user whose NT hash is `ntHash`.
QByteArray authenticateToken(const QByteArray &ntHash, const QString &user, const QString &domain,
                             const QByteArray &serverChallenge, const QByteArray &targetInfo,
                             quint32 flags = 0x00000001u | 0x00000200u | 0x00080000u)
{
    QByteArray clientChallenge(8, '\0');
    for (int i = 0; i < 8; ++i)
        clientChallenge[i] = char(QRandomGenerator::system()->generate() & 0xff);

    QByteArray blob;
    blob.append(char(1)); // RespType
    blob.append(char(1)); // HiRespType
    blob.append(QByteArray(2, '\0'));
    blob.append(QByteArray(4, '\0'));
    blob.append(QByteArray(8, '\0')); // timestamp (not validated)
    blob.append(clientChallenge);
    blob.append(QByteArray(4, '\0'));
    blob.append(targetInfo);

    const QByteArray responseKey =
        Ntlm::hmacMd5(ntHash, Ntlm::utf16le(user.toUpper() + domain));
    const QByteArray proof =
        Ntlm::hmacMd5(responseKey, serverChallenge + blob).left(16);
    const QByteArray ntResponse = proof + blob;

    const QByteArray lmResponse(24, '\0');
    const QByteArray domainBytes = Ntlm::utf16le(domain);
    const QByteArray userBytes = Ntlm::utf16le(user);
    const QByteArray workstationBytes = Ntlm::utf16le(QStringLiteral("CLIENT"));

    QByteArray token("NTLMSSP\0", 8);
    putLE32(token, 3);
    int offset = 64;
    putField(token, lmResponse.size(), offset);
    offset += lmResponse.size();
    putField(token, ntResponse.size(), offset);
    offset += ntResponse.size();
    putField(token, domainBytes.size(), offset);
    offset += domainBytes.size();
    putField(token, userBytes.size(), offset);
    offset += userBytes.size();
    putField(token, workstationBytes.size(), offset);
    offset += workstationBytes.size();
    putField(token, 0, offset);
    putLE32(token, flags);

    token.append(lmResponse);
    token.append(ntResponse);
    token.append(domainBytes);
    token.append(userBytes);
    token.append(workstationBytes);
    return token;
}

QByteArray saslBindRequest(int msgId, const QByteArray &token, const QByteArray &mechanism = "NTLM")
{
    QByteArray sasl;
    putTLV(sasl, 0x04, mechanism);
    putTLV(sasl, 0x04, token);

    QByteArray inner;
    putInt(inner, 0x02, 3);
    putTLV(inner, 0x04, QByteArray());
    putTLV(inner, 0x83, sasl); // authenticationChoice [3] SASL

    QByteArray msg;
    putInt(msg, 0x02, msgId);
    putTLV(msg, 0x60, inner);
    QByteArray packet;
    putTLV(packet, 0x30, msg);
    return packet;
}

struct BindReply {
    int resultCode = -1;
    QByteArray saslCreds;
    bool parsed = false;
};

BindReply exchange(QTcpSocket &socket, const QByteArray &request, int timeoutMs = 3000)
{
    BindReply reply;
    socket.write(request);
    socket.flush();

    QByteArray buffer;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        buffer += socket.readAll();
        int pos = 0;
        quint8 tag = 0;
        QByteArray body;
        if (!takeTLV(buffer, pos, &tag, &body)) {
            if (!socket.waitForReadyRead(20))
                continue;
            continue;
        }
        if (tag != 0x30)
            continue;
        int inner = 0;
        quint8 itag = 0;
        QByteArray ignored;
        QByteArray op;
        if (!takeTLV(body, inner, &itag, &ignored))
            continue;
        if (!takeTLV(body, inner, &itag, &op))
            continue;
        if (itag != 0x61)
            continue;
        int opos = 0;
        quint8 ftag = 0;
        QByteArray code;
        if (!takeTLV(op, opos, &ftag, &code))
            continue;
        reply.resultCode = code.isEmpty() ? 0 : quint8(code.at(0));
        while (opos < op.size()) {
            quint8 partTag = 0;
            QByteArray part;
            if (!takeTLV(op, opos, &partTag, &part))
                break;
            if (partTag == 0x87)
                reply.saslCreds = part;
        }
        reply.parsed = true;
        return reply;
    }
    return reply;
}

QByteArray searchRequest(int msgId, const QByteArray &base)
{
    QByteArray filter;
    putTLV(filter, 0x87, QByteArrayLiteral("objectClass")); // present [7]

    QByteArray inner;
    putTLV(inner, 0x04, base);
    putInt(inner, 0x0a, 2); // wholeSubtree
    putInt(inner, 0x0a, 0); // neverDerefAliases
    putInt(inner, 0x02, 0); // sizeLimit
    putInt(inner, 0x02, 0); // timeLimit
    putTLV(inner, 0x01, QByteArray(1, '\0')); // typesOnly false
    inner.append(filter);
    putTLV(inner, 0x30, QByteArray()); // no requested attributes

    QByteArray msg;
    putInt(msg, 0x02, msgId);
    putTLV(msg, 0x63, inner);
    QByteArray packet;
    putTLV(packet, 0x30, msg);
    return packet;
}

quint32 readBE32(const QByteArray &data)
{
    return (quint32(quint8(data.at(0))) << 24) | (quint32(quint8(data.at(1))) << 16)
           | (quint32(quint8(data.at(2))) << 8) | quint32(quint8(data.at(3)));
}

// Reads one RFC 4422 framed SASL message (4-octet length, then the token).
QByteArray readFramed(QTcpSocket &socket, int timeoutMs = 3000)
{
    QByteArray buffer;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        buffer += socket.readAll();
        if (buffer.size() >= 4) {
            const int length = int(readBE32(buffer));
            if (length > 0 && buffer.size() >= 4 + length)
                return buffer.mid(4, length);
        }
        socket.waitForReadyRead(20);
    }
    return {};
}

void writeFramed(QTcpSocket &socket, const QByteArray &token)
{
    // RFC 4422 framing: the length is a 4-octet network-byte-order integer.
    QByteArray framed;
    const quint32 length = quint32(token.size());
    framed.append(char((length >> 24) & 0xff));
    framed.append(char((length >> 16) & 0xff));
    framed.append(char((length >> 8) & 0xff));
    framed.append(char(length & 0xff));
    framed.append(token);
    socket.write(framed);
    socket.flush();
}

// Runs NEGOTIATE and AUTHENTICATE with the given extra flags and returns the
// session keys the client would derive, the same ones the server derives.
bool bindWithFlags(const QByteArray &ntHash, QTcpSocket &socket, quint32 extraFlags,
                   Ntlm::SessionKeys *keys)
{
    // unicode, ntlm, extended session security, target info, 128-bit session
    // keys, as a Windows client sends for NTLMv2.
    const quint32 base = 0x00000001u | 0x00000200u | 0x00080000u | 0x00800000u | 0x20000000u;
    QByteArray negotiate("NTLMSSP\0", 8);
    putLE32(negotiate, 1);
    putLE32(negotiate, base | extraFlags);

    const BindReply challengeReply = exchange(socket, saslBindRequest(1, negotiate));
    if (!challengeReply.parsed || challengeReply.resultCode != 14)
        return false;

    const QByteArray serverChallenge = challengeReply.saslCreds.mid(24, 8);
    const QByteArray targetInfo = field(challengeReply.saslCreds, 40);
    const QByteArray token = authenticateToken(ntHash, QStringLiteral("alicechen"),
                                               QStringLiteral("CORP"), serverChallenge,
                                               targetInfo, base | extraFlags);
    const BindReply reply = exchange(socket, saslBindRequest(2, token));
    if (!reply.parsed || reply.resultCode != 0)
        return false;

    const QByteArray ntResponse = field(token, 20);
    return Ntlm::sessionKeys(ntHash, QStringLiteral("alicechen"), QStringLiteral("CORP"),
                             ntResponse.left(16), keys, base | extraFlags);
}

// Result code of the SearchResultDone in a stream of LDAP PDUs, -1 when the
// stream does not contain one.
int resultCodeFromStream(const QByteArray &stream)
{
    int pos = 0;
    while (pos < stream.size()) {
        quint8 tag = 0;
        QByteArray body;
        if (!takeTLV(stream, pos, &tag, &body) || tag != 0x30)
            return -1;
        int inner = 0;
        quint8 itag = 0;
        QByteArray ignored;
        if (!takeTLV(body, inner, &itag, &ignored))
            return -1;
        if (!takeTLV(body, inner, &itag, &body))
            return -1;
        if (itag != 0x65)
            continue;
        int opos = 0;
        quint8 ftag = 0;
        QByteArray code;
        if (!takeTLV(body, opos, &ftag, &code) || ftag != 0x0a)
            return -1;
        return code.isEmpty() ? 0 : quint8(code.at(0));
    }
    return -1;
}

} // namespace

class NtlmTest : public QObject
{
    Q_OBJECT

private slots:
    void primitivesMatchPublishedVectors();
    void challengePublishesDnsNames();
    void sessionSecurityMatchesReferenceImplementation();
    void authenticatesWithNtlmv2();
    void signedSessionCarriesLdap();
    void sealedSessionCarriesLdap();
    void sealedSessionRejectsTampering();
    void rejectsWrongPassword();
    void rejectsDisabledAccount();
    void neverReturnsCredentialMaterial();
};

void NtlmTest::primitivesMatchPublishedVectors()
{
    // NTOWFv1 test vectors (MS-NLMP §4.2.2 / "NT hash" of well-known passwords).
    QCOMPARE(Ntlm::ntowfV1(QStringLiteral("Password")).toHex(),
             QByteArray("a4f49c406510bdcab6824ee7c30fd852"));
    QCOMPARE(Ntlm::ntowfV1(QStringLiteral("123456")).toHex(),
             QByteArray("32ed87bdb5fdc5e9cba88547376818d4"));
    QCOMPARE(Ntlm::utf16le(QStringLiteral("AB")), QByteArray::fromHex("41004200"));

    // HMAC-MD5 test vectors (RFC 2202 §2).
    QCOMPARE(Ntlm::hmacMd5(QByteArray(16, '\x0b'), QByteArray("Hi There")).toHex(),
             QByteArray("9294727a3638bb1c13f48ef8158bfc9d"));
    QCOMPARE(Ntlm::hmacMd5(QByteArray("Jefe"), QByteArray("what do ya want for nothing?")).toHex(),
             QByteArray("750c783e6ab0b503eaa86e310a5db738"));
    QCOMPARE(Ntlm::secureEquals(QByteArray("abc"), QByteArray("abc")), true);
    QCOMPARE(Ntlm::secureEquals(QByteArray("abc"), QByteArray("abd")), false);
}

void NtlmTest::challengePublishesDnsNames()
{
    // A client that builds a service principal (RPC does) needs the DNS names in
    // the CHALLENGE's target info, not just the NetBIOS ones: without AV 3/4 a
    // client aborts before it ever sends AUTHENTICATE.
    const QByteArray challenge(8, '\x11');
    const QByteArray token = Ntlm::challengeToken(challenge, QStringLiteral("MONARCHY"),
                                                  QStringLiteral("MONARCHYDC1"),
                                                  QStringLiteral("monarchy.test"));
    QVERIFY(token.startsWith(QByteArrayLiteral("NTLMSSP\0")));
    // AV pairs are UTF-16LE, so look for the exact encoded names.
    const QByteArray dnsDomain = QByteArrayLiteral("monarchy.test");
    QByteArray encoded;
    for (char c : dnsDomain) {
        encoded.append(c);
        encoded.append('\0');
    }
    QVERIFY(token.contains(encoded));
    const QByteArray dnsHost = QByteArrayLiteral("monarchydc1.monarchy.test");
    QByteArray encodedHost;
    for (char c : dnsHost) {
        encodedHost.append(c);
        encodedHost.append('\0');
    }
    QVERIFY(token.contains(encodedHost));
    // The eight-byte server challenge travels verbatim.
    QVERIFY(token.contains(challenge));
}

void NtlmTest::sessionSecurityMatchesReferenceImplementation()
{
    // Vectors produced by impacket's independent MS-NLMP implementation
    // (impacket.ntlm.NTOWFv2/SIGNKEY/SEALKEY/MAC plus pycryptodome's ARC4) for
    // user "jsmith", domain "CORP", password "Str0ng-Pass!", server challenge
    // 1122334455667788 and a fixed NTLMv2 blob.
    const QByteArray blob = QByteArray::fromHex("020102000000000000000000000000000000000000000000");
    const QByteArray challenge = QByteArray::fromHex("1122334455667788");
    const QByteArray responseKey = Ntlm::hmacMd5(
        Ntlm::ntowfV1(QStringLiteral("Str0ng-Pass!")),
        Ntlm::utf16le(QStringLiteral("JSMITH") + QStringLiteral("CORP")));
    QCOMPARE(responseKey.toHex(), QByteArray("7740bbef700c3b998b109c4be00f1092"));

    const QByteArray ntProof = Ntlm::hmacMd5(responseKey, challenge + blob);
    QCOMPARE(ntProof.toHex(), QByteArray("e89d8ff3946ec0c570ec0ae831c2c63b"));

    Ntlm::SessionKeys keys;
    QVERIFY(Ntlm::sessionKeys(Ntlm::ntowfV1(QStringLiteral("Str0ng-Pass!")),
                              QStringLiteral("jsmith"), QStringLiteral("CORP"), ntProof,
                              &keys));
    QCOMPARE(keys.sessionBaseKey.toHex(), QByteArray("f2f6f9402e25d6fa9fcd48d2b9451a12"));
    QCOMPARE(keys.clientSigningKey.toHex(), QByteArray("28ac81d5fb4e9f0460c9f56c9cebb132"));
    QCOMPARE(keys.serverSigningKey.toHex(), QByteArray("98f4ba72895ed6792cfcd01438799e42"));
    QCOMPARE(keys.clientSealingKey.toHex(), QByteArray("ad6d108e9e83576b5398be6e1e93d67d"));
    QCOMPARE(keys.serverSealingKey.toHex(), QByteArray("3fcaa4f9ddd8b8079872540d28e49e7c"));

    QCOMPARE(Ntlm::mac(keys.clientSigningKey, 0, QByteArrayLiteral("hello Monarchy")).toHex(),
             QByteArray("98584ed5dd4a92c2"));

    // The RC4 keystream carries across messages, so the second token depends on
    // the first one having been sealed.
    Ntlm::Sealer sealer(keys.clientSealingKey);
    QVERIFY(sealer.isValid());
    QCOMPARE(sealer.apply(QByteArrayLiteral("hello Monarchy")).toHex(),
             QByteArray("fedb7519e4f25f9ddf620532c2ca"));
    QCOMPARE(sealer.apply(QByteArrayLiteral("second")).toHex(), QByteArray("0f98e16a943d"));
    QCOMPARE(Ntlm::mac(keys.clientSigningKey, 1, QByteArrayLiteral("second")).toHex(),
             QByteArray("2f673dea88cf1c4e"));

    // MS-NLMP §3.4.5.1: 128-bit session security exports the session base key
    // unchanged, while 56- and 40-bit truncate and pad it.
    QCOMPARE(Ntlm::exportedSessionKey(keys.sessionBaseKey, Ntlm::kNegotiate128),
             keys.sessionBaseKey);
    QCOMPARE(Ntlm::exportedSessionKey(keys.sessionBaseKey, Ntlm::kNegotiate56),
             keys.sessionBaseKey.left(7) + QByteArray(1, char(0xa0)));
    QCOMPARE(Ntlm::exportedSessionKey(keys.sessionBaseKey, 0),
             keys.sessionBaseKey.left(5) + QByteArray(1, char(0xa0)));

    // A complete sealed token, byte for byte as impacket's SEAL() builds it
    // for the same keys: version(4) || checksum(8) || sequence(4) || sealed
    // message. The RC4 keystream carries into the next token.
    Ntlm::Sealer tokenSealer(keys.clientSealingKey);
    QCOMPARE(Ntlm::sealMessage(keys.clientSealingKey, keys.clientSigningKey, &tokenSealer, 0,
                               QByteArrayLiteral("hello Monarchy")).toHex(),
             QByteArray("0100000098584ed5dd4a92c200000000fedb7519e4f25f9ddf620532c2ca"));
    QCOMPARE(Ntlm::sealMessage(keys.clientSealingKey, keys.clientSigningKey, &tokenSealer, 1,
                               QByteArrayLiteral("second")).toHex(),
             QByteArray("010000002f673dea88cf1c4e010000000f98e16a943d"));

    // And it opens again with the same keys and state...
    Ntlm::Sealer opener(keys.clientSealingKey);
    QByteArray opened;
    QVERIFY(Ntlm::unsealMessage(keys.clientSealingKey, keys.clientSigningKey, &opener, 0,
                                QByteArray::fromHex("0100000098584ed5dd4a92c200000000fedb7519e4f25f9ddf620532c2ca"),
                                &opened));
    QCOMPARE(opened, QByteArrayLiteral("hello Monarchy"));
    // ...but not with the wrong sequence number.
    Ntlm::Sealer wrongSeq(keys.clientSealingKey);
    QVERIFY(!Ntlm::unsealMessage(keys.clientSealingKey, keys.clientSigningKey, &wrongSeq, 7,
                                 QByteArray::fromHex("0100000098584ed5dd4a92c200000000fedb7519e4f25f9ddf620532c2ca"),
                                 &opened));

    // Sealing is its own inverse with the same key and state, and not with a
    // different key.
    Ntlm::Sealer writer(keys.clientSealingKey);
    Ntlm::Sealer mirror(keys.clientSealingKey);
    QCOMPARE(mirror.apply(writer.apply(QByteArrayLiteral("round trip"))),
             QByteArrayLiteral("round trip"));
    Ntlm::Sealer wrong(QByteArray(16, 'x'));
    QVERIFY(wrong.apply(writer.apply(QByteArrayLiteral("round trip")))
            != QByteArrayLiteral("round trip"));
}

void NtlmTest::authenticatesWithNtlmv2()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    const QString password = QStringLiteral("Str0ng-Pass!");

    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    // 1. NEGOTIATE -> CHALLENGE
    const BindReply challengeReply = exchange(socket, saslBindRequest(1, negotiateToken()));
    QVERIFY(challengeReply.parsed);
    QCOMPARE(challengeReply.resultCode, 14); // saslBindInProgress
    QVERIFY(!challengeReply.saslCreds.isEmpty());

    const QByteArray challenge = challengeReply.saslCreds;
    QVERIFY(challenge.startsWith("NTLMSSP\0"));
    const QByteArray serverChallenge = challenge.mid(24, 8);
    const QByteArray targetInfo = field(challenge, 40);

    // 2. AUTHENTICATE -> success, using only the NT hash like a real client.
    const QByteArray token = authenticateToken(Ntlm::ntowfV1(password),
                                               QStringLiteral("alicechen"), QStringLiteral("CORP"),
                                               serverChallenge, targetInfo);
    const BindReply reply = exchange(socket, saslBindRequest(2, token));
    QVERIFY(reply.parsed);
    QCOMPARE(reply.resultCode, 0);
}

void NtlmTest::signedSessionCarriesLdap()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    const QString password = QStringLiteral("Str0ng-Pass!");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    Ntlm::SessionKeys keys;
    QVERIFY(bindWithFlags(Ntlm::ntowfV1(password), socket, Ntlm::kNegotiateSign, &keys));

    // Integrity only: the PDU travels in the clear with a 16-byte signature.
    const QByteArray request = searchRequest(3, QByteArrayLiteral("DC=corp,DC=example,DC=com"));
    writeFramed(socket, Ntlm::signMessage(keys.clientSigningKey, 0, request));

    QByteArray plain;
    const QByteArray token = readFramed(socket);
    QVERIFY(!token.isEmpty());
    QVERIFY(Ntlm::unsealMessage(QByteArray(), keys.serverSigningKey, nullptr, 0, token, &plain));
    QCOMPARE(resultCodeFromStream(plain), 0);

    // A second message continues the sequence, which both sides must track.
    writeFramed(socket, Ntlm::signMessage(keys.clientSigningKey, 1,
                                         searchRequest(4, QByteArrayLiteral("DC=corp,DC=example,DC=com"))));
    const QByteArray second = readFramed(socket);
    QVERIFY(!second.isEmpty());
    QByteArray secondPlain;
    QVERIFY(Ntlm::unsealMessage(QByteArray(), keys.serverSigningKey, nullptr, 1, second,
                                &secondPlain));
    QCOMPARE(resultCodeFromStream(secondPlain), 0);
}

void NtlmTest::sealedSessionCarriesLdap()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    const QString password = QStringLiteral("Str0ng-Pass!");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    Ntlm::SessionKeys keys;
    QVERIFY(bindWithFlags(Ntlm::ntowfV1(password), socket, Ntlm::kNegotiateSign | Ntlm::kNegotiateSeal,
                          &keys));

    Ntlm::Sealer clientOut(keys.clientSealingKey);
    Ntlm::Sealer clientIn(keys.serverSealingKey);
    QVERIFY(clientOut.isValid());

    const QByteArray request = searchRequest(3, QByteArrayLiteral("DC=corp,DC=example,DC=com"));
    writeFramed(socket, Ntlm::sealMessage(keys.clientSealingKey, keys.clientSigningKey, &clientOut, 0,
                                          request));

    const QByteArray token = readFramed(socket);
    QVERIFY(!token.isEmpty());
    // The payload is confidential: the DN does not appear on the wire.
    QVERIFY(!token.contains(QByteArrayLiteral("Alice")));
    QVERIFY(!token.contains(QByteArrayLiteral("DC=corp")));

    QByteArray plain;
    QVERIFY(Ntlm::unsealMessage(keys.serverSealingKey, keys.serverSigningKey, &clientIn, 0, token,
                                &plain));
    QCOMPARE(resultCodeFromStream(plain), 0);
    // The reply really carries the directory: a search entry is present.
    QVERIFY(plain.contains(QByteArrayLiteral("Alice"))
            || plain.contains(QByteArrayLiteral("CN=Alice Chen")));
}

void NtlmTest::sealedSessionRejectsTampering()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    const QString password = QStringLiteral("Str0ng-Pass!");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    Ntlm::SessionKeys keys;
    QVERIFY(bindWithFlags(Ntlm::ntowfV1(password), socket, Ntlm::kNegotiateSign | Ntlm::kNegotiateSeal,
                          &keys));

    Ntlm::Sealer clientOut(keys.clientSealingKey);
    QByteArray token = Ntlm::sealMessage(keys.clientSealingKey, keys.clientSigningKey, &clientOut, 0,
                                         searchRequest(3, QByteArrayLiteral("DC=corp,DC=example,DC=com")));
    token[token.size() - 1] = char(quint8(token.at(token.size() - 1)) ^ 0x5a);
    writeFramed(socket, token);

    // A bad MAC must not produce an answer: the server drops the connection.
    QElapsedTimer timer;
    timer.start();
    bool answered = false;
    while (timer.elapsed() < 2000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        if (socket.state() == QAbstractSocket::UnconnectedState)
            break;
        if (socket.bytesAvailable() > 0 && !socket.readAll().isEmpty())
            answered = true;
        socket.waitForReadyRead(20);
    }
    QVERIFY(!answered);
    QCOMPARE(socket.state(), QAbstractSocket::UnconnectedState);
}

void NtlmTest::rejectsWrongPassword()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{QStringLiteral("Str0ng-Pass!")};
    setPassword.rawValue = QStringLiteral("Str0ng-Pass!").toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    const BindReply challengeReply = exchange(socket, saslBindRequest(1, negotiateToken()));
    QCOMPARE(challengeReply.resultCode, 14);
    const QByteArray serverChallenge = challengeReply.saslCreds.mid(24, 8);
    const QByteArray targetInfo = field(challengeReply.saslCreds, 40);

    const QByteArray token = authenticateToken(Ntlm::ntowfV1(QStringLiteral("Wrong-Pass!")),
                                               QStringLiteral("alicechen"), QStringLiteral("CORP"),
                                               serverChallenge, targetInfo);
    const BindReply reply = exchange(socket, saslBindRequest(2, token));
    QVERIFY(reply.parsed);
    QCOMPARE(reply.resultCode, 49); // invalidCredentials
}

void NtlmTest::rejectsDisabledAccount()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    const QString password = QStringLiteral("Str0ng-Pass!");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    LdapServer::ModifyChange disable;
    disable.operation = 2;
    disable.type = QStringLiteral("userAccountControl");
    disable.values = QStringList{QStringLiteral("514")};
    QCOMPARE(server.applyModify(aliceDn, {disable}), 0);

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(3000));

    const BindReply challengeReply = exchange(socket, saslBindRequest(1, negotiateToken()));
    QCOMPARE(challengeReply.resultCode, 14);
    const QByteArray token = authenticateToken(Ntlm::ntowfV1(password), QStringLiteral("alicechen"),
                                               QStringLiteral("CORP"),
                                               challengeReply.saslCreds.mid(24, 8),
                                               field(challengeReply.saslCreds, 40));
    const BindReply reply = exchange(socket, saslBindRequest(2, token));
    QVERIFY(reply.parsed);
    QCOMPARE(reply.resultCode, 49);
}

void NtlmTest::neverReturnsCredentialMaterial()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    const QString aliceDn = QStringLiteral("CN=Alice Chen,CN=Users,DC=corp,DC=example,DC=com");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{QStringLiteral("Str0ng-Pass!")};
    setPassword.rawValue = QStringLiteral("Str0ng-Pass!").toUtf8();
    QCOMPARE(server.applyModify(aliceDn, {setPassword}), 0);

    for (const DirectoryObject &object : server.objects()) {
        if (object.id != aliceDn)
            continue;
        // The hash is stored for authentication...
        QCOMPARE(object.attributes.value(QStringLiteral("ntHash")).size(), 32);
        // ...and a client cannot overwrite it.
        LdapServer::ModifyChange forge;
        forge.operation = 2;
        forge.type = QStringLiteral("ntHash");
        forge.values = QStringList{QStringLiteral("deadbeef")};
        QCOMPARE(server.applyModify(aliceDn, {forge}), 19); // constraintViolation
    }
}

QTEST_GUILESS_MAIN(NtlmTest)
#include "test_ntlm.moc"
