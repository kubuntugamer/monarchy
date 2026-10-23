// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtTest>

#include "Aes.h"
#include "Des.h"
#include "Netlogon.h"
#include "Ndr.h"
#include "Ntlm.h"

namespace {

void appendLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void appendLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

void appendLe64(QByteArray &out, quint64 value)
{
    appendLe32(out, quint32(value & 0xffffffffu));
    appendLe32(out, quint32(value >> 32));
}

quint16 readLe16(const QByteArray &data, int offset)
{
    return quint16(quint8(data.at(offset)) | (quint16(quint8(data.at(offset + 1))) << 8));
}

quint32 readLe32(const QByteArray &data, int offset)
{
    return quint32(quint8(data.at(offset))) | (quint32(quint8(data.at(offset + 1))) << 8)
           | (quint32(quint8(data.at(offset + 2))) << 16)
           | (quint32(quint8(data.at(offset + 3))) << 24);
}

void appendStringArray(QByteArray &out, const QString &text, bool align = true)
{
    const QByteArray chars = Ndr::utf16le(text) + QByteArray(2, '\0');
    const quint32 count = quint32(text.size() + 1);
    appendLe32(out, count);
    appendLe32(out, 0);
    appendLe32(out, count);
    out.append(chars);
    if (align) {
        while (out.size() % 4 != 0)
            out.append('\0');
    }
}

QByteArray challengeRequest(const QString &computer, const QByteArray &clientChallenge)
{
    QByteArray stub;
    appendLe32(stub, 0); // NULL server_name
    appendStringArray(stub, computer);
    stub.append(clientChallenge);
    return stub;
}

void appendPointerString(QByteArray &out, const QString &text, quint32 referent)
{
    appendLe32(out, referent);
    if (referent != 0)
        appendStringArray(out, text);
}

QByteArray authenticateRequest(const QString &account, const QString &computer,
                               const QByteArray &credential, quint32 flags)
{
    QByteArray stub;
    appendLe32(stub, 0); // NULL server_name
    appendStringArray(stub, account, false);
    appendLe16(stub, 2); // SEC_CHAN_WKSTA
    while (stub.size() % 4 != 0)
        stub.append('\0');
    appendStringArray(stub, computer);
    stub.append(credential);
    appendLe32(stub, flags);
    return stub;
}

QByteArray expectedSessionKey(const QByteArray &ntHash, const QByteArray &client,
                              const QByteArray &server, quint32 flags)
{
    if (flags & Netlogon::kNegSupportsAes) {
        QMessageAuthenticationCode mac(QCryptographicHash::Sha256, ntHash);
        mac.addData(client + server);
        return mac.result().left(16);
    }
    if (flags & Netlogon::kNegStrongKeys) {
        const QByteArray digest = QCryptographicHash::hash(
            QByteArray(4, '\0') + client + server, QCryptographicHash::Md5);
        QMessageAuthenticationCode mac(QCryptographicHash::Md5, ntHash);
        mac.addData(digest);
        return mac.result();
    }

    QByteArray sum;
    for (int at = 0; at < 8; at += 4) {
        const quint32 value = readLe32(client, at) + readLe32(server, at);
        for (int byte = 0; byte < 4; ++byte)
            sum.append(char((value >> (8 * byte)) & 0xff));
    }
    const QByteArray firstKey = Des::keyFromPassword(ntHash.left(7));
    const QByteArray secondKey = Des::keyFromPassword(ntHash.mid(9, 7));
    const QByteArray first = Des::encryptBlock(firstKey, sum);
    return Des::encryptBlock(secondKey, first) + QByteArray(8, '\0');
}

QByteArray expectedCredential(const QByteArray &input, const QByteArray &sessionKey, quint32 flags)
{
    if (flags & Netlogon::kNegSupportsAes) {
        QByteArray output;
        QByteArray iv(16, '\0');
        for (char value : input) {
            const QByteArray block = Aes::encryptBlock(sessionKey, iv);
            const char encrypted = char(quint8(value) ^ quint8(block.at(0)));
            output.append(encrypted);
            iv.remove(0, 1);
            iv.append(encrypted);
        }
        return output;
    }
    const QByteArray first = Des::keyFromPassword(sessionKey.left(7));
    const QByteArray second = Des::keyFromPassword(sessionKey.mid(7, 7));
    return Des::encryptBlock(second, Des::encryptBlock(first, input));
}

QByteArray ntlmV2Response(const QByteArray &ntHash, const QString &user, const QString &domain,
                          const QByteArray &challenge)
{
    QByteArray blob = QByteArray::fromHex("0101000000000000");
    appendLe32(blob, 0); // timestamp (the verifier currently ignores clock skew)
    blob.append(QByteArray::fromHex("a1a2a3a4a5a6a7a8"));
    blob.append(QByteArray(4, '\0'));
    const QByteArray targetInfo = Ntlm::targetInfo(domain, QStringLiteral("DC1"));
    blob.append(targetInfo);
    const QByteArray responseKey =
        Ntlm::hmacMd5(ntHash, Ntlm::utf16le(user.toUpper() + domain));
    return Ntlm::hmacMd5(responseKey, challenge + blob).left(16) + blob;
}

QByteArray nextCredential(const QByteArray &seed, quint32 timestamp,
                          const QByteArray &sessionKey, quint32 flags, bool server)
{
    QByteArray input;
    appendLe32(input, readLe32(seed, 0) + timestamp + (server ? 1u : 0u));
    input.append(seed.mid(4, 4));
    return expectedCredential(input, sessionKey, flags);
}

QByteArray authenticatorRequest(const QByteArray &credential, quint32 timestamp)
{
    QByteArray out;
    out.append(credential);
    appendLe32(out, timestamp);
    return out;
}

void appendNetworkLogon(QByteArray &out, quint16 validationLevel, const QByteArray &ntResponse,
                        quint32 extraFlags = 0)
{
    // These call-level fields precede the deferred NETLOGON_LEVEL referent.
    appendLe16(out, validationLevel);
    if (extraFlags != 0) {
        while (out.size() % 4 != 0) out.append(char(0));
        appendLe32(out, extraFlags);
    }
    while (out.size() % 4 != 0) out.append(char(0));

    // NETLOGON_LOGON_IDENTITY_INFO has deferred domain, account and workstation.
    appendLe16(out, 8); appendLe16(out, 8); // domain Length and MaximumLength
    appendLe32(out, 0x00020001u); // domain buffer
    appendLe32(out, 3); // parameter_control
    while (out.size() % 8 != 0) out.append(char(0)); // OLD_LARGE_INTEGER alignment
    appendLe64(out, 0); // Reserved
    appendLe16(out, 10); appendLe16(out, 10); appendLe32(out, 0x00020002u); // account buffer
    appendLe16(out, 12); appendLe16(out, 12); appendLe32(out, 0x00020003u); // workstation
    out.append(QByteArray::fromHex("0102030405060708")); // challenge
    while (out.size() % 4 != 0) out.append(char(0));
    appendLe16(out, quint16(ntResponse.size())); appendLe16(out, quint16(ntResponse.size()));
    appendLe32(out, 0x00020004u);
    appendLe16(out, 0); appendLe16(out, 0); appendLe32(out, 0);

    // Deferred unique-pointer referents are carried separately from the
    // conformant string payloads; the NDR pointer IDs were in the fixed struct.
    auto appendDeferredString = [&out](const QString &value, quint32 referent) {
        Q_UNUSED(referent)
        while (out.size() % 4 != 0) out.append(char(0));
        const quint32 count = quint32(value.size());
        appendLe32(out, count); appendLe32(out, 0); appendLe32(out, count);
        out.append(Ndr::utf16le(value));
        while (out.size() % 4 != 0) out.append(char(0));
    };
    appendDeferredString(QStringLiteral("CORP"), 0x00020001u);
    appendDeferredString(QStringLiteral("alice"), 0x00020002u);
    appendDeferredString(QStringLiteral("CLIENT"), 0x00020003u);
    while (out.size() % 4 != 0) out.append(char(0));
    appendLe32(out, quint32(ntResponse.size())); appendLe32(out, 0);
    appendLe32(out, quint32(ntResponse.size()));
    out.append(ntResponse);
    while (out.size() % 4 != 0) out.append(char(0));
    appendLe32(out, 0); // NULL LM response array

}

} // namespace

class NetlogonTest : public QObject
{
    Q_OBJECT

private slots:
    void secureChannelNegotiatesCrypto_data();
    void secureChannelNegotiatesCrypto();
    void legacySamLogonAuthenticatesSecureChannel_data();
    void legacySamLogonAuthenticatesSecureChannel();
};

void NetlogonTest::secureChannelNegotiatesCrypto_data()
{
    QTest::addColumn<quint32>("requestedFlags");
    QTest::addColumn<quint32>("expectedFlags");
    QTest::newRow("legacy-des") << quint32(0) << quint32(0);
    QTest::newRow("strong-key-des") << Netlogon::kNegStrongKeys << Netlogon::kNegStrongKeys;
    QTest::newRow("aes") << (Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes)
                          << (Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes);
}

void NetlogonTest::legacySamLogonAuthenticatesSecureChannel_data()
{
    QTest::addColumn<quint16>("opnum");
    QTest::addColumn<bool>("withFlags");
    QTest::newRow("sam-logon") << quint16(Netlogon::OpLogonSamLogon) << false;
    QTest::newRow("sam-logon-with-flags") << quint16(Netlogon::OpLogonSamLogonWithFlags) << true;
}

void NetlogonTest::legacySamLogonAuthenticatesSecureChannel()
{
    QFETCH(quint16, opnum);
    QFETCH(bool, withFlags);

    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    DirectoryObject machine;
    machine.id = QStringLiteral("CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=com");
    machine.kind = ObjectKind::Computer;
    machine.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("DC1$"));
    machine.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1000"));
    const QByteArray machineHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    machine.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(machineHash.toHex()));

    DirectoryObject user;
    user.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1100"));
    const QByteArray userHash = Ntlm::ntowfV1(QStringLiteral("Alice!Password123"));
    user.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(userHash.toHex()));
    user.attributes.insert(QStringLiteral("primaryGroupID"), QStringLiteral("513"));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    user.attributes.insert(QStringLiteral("displayName"), QStringLiteral("Alice Example"));
    server.setObjectProvider([machine, user]() { return QList<DirectoryObject>{machine, user}; });

    const QByteArray clientChallenge = QByteArray::fromHex("1112131415161718");
    const QByteArray challengeReply = server.handleCall(
        Netlogon::OpServerReqChallenge, challengeRequest(QStringLiteral("DC1"), clientChallenge));
    const QByteArray serverChallenge = challengeReply.left(8);
    const quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes;
    const QByteArray sessionKey = expectedSessionKey(machineHash, clientChallenge, serverChallenge,
                                                     flags);
    const QByteArray authenticateReply = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                            expectedCredential(clientChallenge, sessionKey, flags), flags));
    QCOMPARE(readLe32(authenticateReply, 16), quint32(0));
    const QByteArray channelSeed = expectedCredential(serverChallenge, sessionKey, flags);
    const quint32 timestamp = 42;
    const QByteArray requestCredential = nextCredential(channelSeed, timestamp, sessionKey, flags, false);
    const QByteArray userChallenge = QByteArray::fromHex("0102030405060708");
    const QByteArray ntResponse = ntlmV2Response(userHash, QStringLiteral("alice"),
                                                QStringLiteral("CORP"), userChallenge);

    QByteArray request;
    appendLe32(request, 0); // NULL LogonServer pointer
    appendPointerString(request, QStringLiteral("DC1"), 0x00021000u); // ComputerName
    appendLe32(request, 0x00021001u); // Authenticator pointer
    request.append(authenticatorRequest(requestCredential, timestamp));
    appendLe32(request, 0x00021002u); // ReturnAuthenticator pointer
    request.append(QByteArray(12, '\0'));
    appendLe16(request, 2); // LogonLevel
    appendLe16(request, 2); // NETLOGON_LEVEL's NDR32 union discriminator
    appendLe32(request, 0x00021003u); // LogonNetwork referent
    // netr_LogonSamLogon marshals validation metadata before the deferred
    // network-info referent; nested strings and challenge arrays follow it.
    appendNetworkLogon(request, 3, ntResponse, withFlags ? 0x00000020u : 0u);
    if (qEnvironmentVariableIsSet("MONARCHY_RPC_TRACE"))
        qWarning("SamLogon stub=%s", request.toHex().constData());
    const QByteArray reply = server.handleCall(opnum, request);
    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("legacy SamLogon returned %1 bytes: %2")
                                               .arg(reply.size()).arg(readLe32(reply, 0), 8, 16, QLatin1Char('0'))));
    QCOMPARE(readLe32(reply, 0), quint32(0x0002f210u));
    QCOMPARE(reply.mid(4, 8), nextCredential(channelSeed, timestamp, sessionKey, flags, true));
    QCOMPARE(readLe32(reply, 12), timestamp);
    QCOMPARE(readLe16(reply, 16), quint16(3));
    // Validation pointer and success status precede the deferred SAM_INFO2.
    QCOMPARE(readLe32(reply, 20), quint32(0x0002f200u));
    QCOMPARE(readLe32(reply, 24), quint32(1));
    const int statusOffset = withFlags ? 32 : 28;
    QCOMPARE(readLe32(reply, statusOffset), quint32(0));
    QVERIFY(reply.contains(Ndr::utf16le(QStringLiteral("alice"))));
}

void NetlogonTest::secureChannelNegotiatesCrypto()
{
    QFETCH(quint32, requestedFlags);
    QFETCH(quint32, expectedFlags);

    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    DirectoryObject machine;
    machine.id = QStringLiteral("CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=com");
    machine.kind = ObjectKind::Computer;
    machine.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("DC1$"));
    machine.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1000"));
    const QByteArray ntHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    machine.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(ntHash.toHex()));
    server.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });

    const QByteArray clientChallenge = QByteArray::fromHex("0102030405060708");
    const QByteArray challengeReply = server.handleCall(
        Netlogon::OpServerReqChallenge, challengeRequest(QStringLiteral("DC1"), clientChallenge));
    QCOMPARE(challengeReply.size(), 12);
    QCOMPARE(readLe32(challengeReply, 8), quint32(0));
    const QByteArray serverChallenge = challengeReply.left(8);

    const QByteArray sessionKey = expectedSessionKey(ntHash, clientChallenge, serverChallenge,
                                                     expectedFlags);
    const QByteArray clientCredential =
        expectedCredential(clientChallenge, sessionKey, expectedFlags);
    const QByteArray authReply = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"), clientCredential,
                            requestedFlags));
    QCOMPARE(authReply.size(), 20);
    QCOMPARE(authReply.left(8), expectedCredential(serverChallenge, sessionKey, expectedFlags));
    QCOMPARE(readLe32(authReply, 8), expectedFlags);
    QCOMPARE(readLe32(authReply, 12), quint32(1000));
    QCOMPARE(readLe32(authReply, 16), quint32(0));

    // The original no-flags Authenticate opnum is the Windows 2000-era entry
    // point; it must use the legacy DES credential and return just that value
    // and NTSTATUS (no flags or RID fields).
    if (requestedFlags == 0) {
        NetlogonServer legacyServer;
        legacyServer.setConfig(config);
        legacyServer.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });
        const QByteArray legacyChallenge = legacyServer.handleCall(
            Netlogon::OpServerReqChallenge,
            challengeRequest(QStringLiteral("DC1"), QByteArray::fromHex("1112131415161718")));
        const QByteArray legacyServerChallenge = legacyChallenge.left(8);
        const QByteArray legacyKey = expectedSessionKey(ntHash,
            QByteArray::fromHex("1112131415161718"), legacyServerChallenge, 0);
        const QByteArray legacyCredential = expectedCredential(
            QByteArray::fromHex("1112131415161718"), legacyKey, 0);
        const QByteArray legacyReply = legacyServer.handleCall(
            Netlogon::OpServerAuthenticate,
            authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                                legacyCredential, 0));
        QCOMPARE(legacyReply.size(), 12);
        QCOMPARE(legacyReply.left(8), expectedCredential(legacyServerChallenge, legacyKey, 0));
        QCOMPARE(readLe32(legacyReply, 8), quint32(0));

        NetlogonServer flagsServer;
        flagsServer.setConfig(config);
        flagsServer.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });
        const QByteArray flagsChallenge = flagsServer.handleCall(
            Netlogon::OpServerReqChallenge,
            challengeRequest(QStringLiteral("DC1"), QByteArray::fromHex("2122232425262728")));
        const QByteArray flagsServerChallenge = flagsChallenge.left(8);
        const QByteArray flagsKey = expectedSessionKey(ntHash, QByteArray::fromHex("2122232425262728"),
                                                       flagsServerChallenge, 0);
        const QByteArray flagsCredential = expectedCredential(
            QByteArray::fromHex("2122232425262728"), flagsKey, 0);
        const QByteArray flagsReply = flagsServer.handleCall(
            Netlogon::OpServerAuthenticate2,
            authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                                flagsCredential, 0));
        QCOMPARE(flagsReply.size(), 16);
        QCOMPARE(flagsReply.left(8), expectedCredential(flagsServerChallenge, flagsKey, 0));
        QCOMPARE(readLe32(flagsReply, 8), quint32(0));
        QCOMPARE(readLe32(flagsReply, 12), quint32(0));
    }

}

#include "test_netlogon.moc"
QTEST_GUILESS_MAIN(NetlogonTest)
