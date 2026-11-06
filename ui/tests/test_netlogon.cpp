// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtTest>

#include "Aes.h"
#include "Des.h"
#include "Netlogon.h"
#include "Ndr.h"
#include "Krb5.h"
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
                        quint32 extraFlags = 0,
                        const QString &workstation = QStringLiteral("CLIENT"))
{
    while (out.size() % 4 != 0) out.append(char(0));

    // NETLOGON_LOGON_IDENTITY_INFO has deferred domain, account and workstation.
    appendLe16(out, 8); appendLe16(out, 8); // domain Length and MaximumLength
    appendLe32(out, 0x00020001u); // domain buffer
    appendLe32(out, 3); // parameter_control
    while (out.size() % 4 != 0) out.append(char(0)); // OLD_LARGE_INTEGER is 4-aligned
    appendLe64(out, 0); // Reserved
    appendLe16(out, 10); appendLe16(out, 10); appendLe32(out, 0x00020002u); // account buffer
    // The deferred array names the characters only; the header's Length agrees
    // with it, which is what parseNetworkInfo checks before reading it.
    const quint16 workstationBytes = quint16(workstation.size() * 2);
    appendLe16(out, workstationBytes); appendLe16(out, workstationBytes);
    appendLe32(out, 0x00020003u); // workstation
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
    appendDeferredString(workstation, 0x00020003u);
    while (out.size() % 4 != 0) out.append(char(0));
    appendLe32(out, quint32(ntResponse.size())); appendLe32(out, 0);
    appendLe32(out, quint32(ntResponse.size()));
    out.append(ntResponse);
    while (out.size() % 4 != 0) out.append(char(0));
    // The LM header above is all a NULL LM response marshals: its referent is
    // zero, so there is no deferred array to write.

    // validation_level follows the whole logon-information parameter, deferred
    // strings and responses included; extra_flags follows it.
    appendLe16(out, validationLevel);
    if (extraFlags != 0) {
        while (out.size() % 4 != 0) out.append(char(0));
        appendLe32(out, extraFlags);
    }
}

QByteArray uniqueString(const QString &text, quint32 referent)
{
    QByteArray out;
    appendLe32(out, referent);
    appendStringArray(out, text);
    return out;
}

QByteArray passwordSetRequest(const QString &account, const QString &computer,
                              const QByteArray &credential, quint32 timestamp,
                              const QByteArray &cipherText, quint32 length)
{
    QByteArray stub;
    appendLe32(stub, 0); // NULL server_name
    appendStringArray(stub, account, false);
    appendLe16(stub, 2); // SEC_CHAN_WKSTA
    while (stub.size() % 4 != 0) stub.append('\0');
    appendStringArray(stub, computer);
    stub.append(credential);
    appendLe32(stub, timestamp);
    stub.append(cipherText);
    appendLe32(stub, length);
    return stub;
}

QByteArray getDcNameRequest(const QString &domain)
{
    QByteArray stub;
    appendStringArray(stub, QString()); // DomainControllerName: not yet known
    stub.append(uniqueString(domain, 0x00022000u));
    return stub;
}

DirectoryObject machineAccount(const QByteArray &ntHash)
{
    DirectoryObject machine;
    machine.id = QStringLiteral("CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=com");
    machine.name = QStringLiteral("DC1");
    machine.kind = ObjectKind::Computer;
    machine.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("DC1$"));
    machine.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1000"));
    machine.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(ntHash.toHex()));
    return machine;
}

struct ChannelFixture {
    bool ok = false;
    QByteArray sessionKey;
    QByteArray seed;
    quint32 flags = 0;
};

// The client half of MS-NRPC 3.1.4.4.1-3.1.4.4.3, computed independently of
// the server: challenge, session key from the machine hash, and the first
// credential over the client challenge.
ChannelFixture openChannel(NetlogonServer &server, const QByteArray &machineHash,
                           quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes)
{
    ChannelFixture out;
    out.flags = flags;
    const QByteArray clientChallenge = QByteArray::fromHex("1112131415161718");
    const QByteArray challengeReply = server.handleCall(
        Netlogon::OpServerReqChallenge,
        challengeRequest(QStringLiteral("DC1"), clientChallenge));
    if (challengeReply.size() != 12 || readLe32(challengeReply, 8) != 0)
        return out;
    const QByteArray serverChallenge = challengeReply.left(8);
    out.sessionKey = expectedSessionKey(machineHash, clientChallenge, serverChallenge, flags);
    const QByteArray authReply = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                            expectedCredential(clientChallenge, out.sessionKey, flags), flags));
    if (authReply.size() != 20 || readLe32(authReply, 16) != 0)
        return out;
    out.seed = authReply.left(8);
    out.ok = true;
    return out;
}

// A SamLogon the way the logon-hours case builds it: the caller's channel
// credential, a timestamp, and the workstation the caller names.
QByteArray samLogonRequest(const QString &workstation, const QByteArray &requestCredential,
                           quint32 timestamp, const QByteArray &ntResponse)
{
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
    appendNetworkLogon(request, 3, ntResponse, 0, workstation);
    return request;
}

// A DC with one machine account and one user account carrying `workstations`
// as its userWorkstations value.
struct WorkstationLogon {
    NetlogonServer server;
    ChannelFixture channel;
    QByteArray userHash;
    bool wroteBack = false;
};

void prepareWorkstationLogon(WorkstationLogon *fixture, const QString &workstations)
{
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    fixture->server.setConfig(config);

    const QByteArray machineHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    DirectoryObject machine = machineAccount(machineHash);

    fixture->userHash = Ntlm::ntowfV1(QStringLiteral("Alice!Password123"));
    DirectoryObject user;
    user.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1100"));
    user.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(fixture->userHash.toHex()));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    if (!workstations.isEmpty())
        user.attributes.insert(QStringLiteral("userWorkstations"), workstations);
    fixture->server.setObjectProvider([machine, user]() {
        return QList<DirectoryObject>{machine, user};
    });

    Netlogon::WriteBackend writes;
    writes.updateAccount = [fixture](const QString &, const QMap<QString, QString> &, QString *) {
        fixture->wroteBack = true;
        return true;
    };
    fixture->server.setWriteBackend(writes);
    fixture->channel = openChannel(fixture->server, machineHash);
}

QByteArray dsrGetDcNameEx2Request(const QString &domain)
{
    QByteArray stub;
    appendLe32(stub, 0); // NULL ServerName
    appendLe32(stub, 0); // NULL AccountName
    appendLe32(stub, 0x1cu); // DomainControllerFlags
    stub.append(uniqueString(domain, 0x00023000u));
    appendLe32(stub, 0); // NULL DomainGuid
    appendLe32(stub, 0); // NULL SiteName
    appendLe32(stub, 0); // Flags
    return stub;
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
    void refusesALogonOutsideLogonHours();
    void refusesALogonFromAnotherWorkstation();
    void allowsALogonFromAListedWorkstation();
    void passwordSet2WritesTheMachineHash();
    void rejectsAChannelCredentialFromTheWrongPassword();
    void dcLocatorNamesThisDc();
    void trustChannelUsesTheTrustSecret();
    void reportsTheTrustAccountRid();
    void answersTheLegacyLocatorCalls();
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

    QString writtenDn;
    QMap<QString, QString> writtenAttributes;
    Netlogon::WriteBackend writes;
    writes.updateAccount = [&writtenDn, &writtenAttributes](
                               const QString &dn, const QMap<QString, QString> &attributes,
                               QString *) {
        writtenDn = dn;
        writtenAttributes = attributes;
        return true;
    };
    server.setWriteBackend(writes);

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
    // netr_LogonSamLogon marshals the whole network-info referent, deferred
    // strings and responses included, before validation_level.
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
    // The validation's referent fills the middle of the stub; the authoritative
    // byte and the status (ExtraFlags, when asked for, between them) end it.
    QCOMPARE(readLe32(reply, 20), quint32(0x0002f200u));
    QCOMPARE(readLe32(reply, int(reply.size()) - 4), quint32(0));
    if (withFlags)
        QCOMPARE(readLe32(reply, int(reply.size()) - 8), quint32(0x00000020u));
    QVERIFY(reply.contains(Ndr::utf16le(QStringLiteral("alice"))));

    // A validated logon is recorded on the account: the DC that answered also
    // writes down that it did.
    QCOMPARE(writtenDn, user.id);
    QVERIFY(writtenAttributes.value(QStringLiteral("lastLogon")).toULongLong() != 0);
    QCOMPARE(writtenAttributes.value(QStringLiteral("logonCount")), QStringLiteral("1"));
    // The previous logon was never recorded, so the replicated stamp is due.
    QVERIFY(writtenAttributes.contains(QStringLiteral("lastLogonTimestamp")));
}

// An account whose logonHours exclude the current hour is refused the way a
// Windows DC refuses it, and a logon that did not happen leaves no last-logon
// stamp behind.
void NetlogonTest::refusesALogonOutsideLogonHours()
{
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
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    // 21 bytes with every bit clear: no hour of the week is allowed.
    user.attributes.insert(QStringLiteral("logonHours"),
                           QString::fromLatin1(QByteArray(21, '\0').toHex()));
    server.setObjectProvider([machine, user]() { return QList<DirectoryObject>{machine, user}; });

    bool wroteBack = false;
    Netlogon::WriteBackend writes;
    writes.updateAccount = [&wroteBack](const QString &, const QMap<QString, QString> &, QString *) {
        wroteBack = true;
        return true;
    };
    server.setWriteBackend(writes);

    const QByteArray clientChallenge = QByteArray::fromHex("2122232425262728");
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
    const quint32 timestamp = 43;
    const QByteArray requestCredential = nextCredential(channelSeed, timestamp, sessionKey, flags, false);
    // appendNetworkLogon() marshals a fixed client challenge; the response has
    // to be computed over that same eight bytes.
    const QByteArray userChallenge = QByteArray::fromHex("0102030405060708");
    const QByteArray ntResponse = ntlmV2Response(userHash, QStringLiteral("alice"),
                                                QStringLiteral("CORP"), userChallenge);

    QByteArray request;
    appendLe32(request, 0);
    appendPointerString(request, QStringLiteral("DC1"), 0x00021000u);
    appendLe32(request, 0x00021001u);
    request.append(authenticatorRequest(requestCredential, timestamp));
    appendLe32(request, 0x00021002u);
    request.append(QByteArray(12, '\0'));
    appendLe16(request, 2);
    appendLe16(request, 2);
    appendLe32(request, 0x00021003u);
    appendNetworkLogon(request, 3, ntResponse, 0);

    const QByteArray reply = server.handleCall(Netlogon::OpLogonSamLogon, request);
    // The credentials were right, so the answer is the hour restriction rather
    // than a wrong-password status.
    QCOMPARE(reply.size(), 4);
    QCOMPARE(readLe32(reply, 0), quint32(0xc000006eu));
    QVERIFY(!wroteBack);
}

// An account whose userWorkstations list does not name the caller is refused
// with the workstation status Windows uses, and nothing is stamped.
void NetlogonTest::refusesALogonFromAnotherWorkstation()
{
    WorkstationLogon logon;
    prepareWorkstationLogon(&logon, QStringLiteral("WS1, WS2"));
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 43;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        logon.userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = logon.server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("CLIENT"), credential, timestamp, ntResponse));

    QCOMPARE(reply.size(), 4);
    QCOMPARE(readLe32(reply, 0), quint32(0xc0000070u));
    QVERIFY(!logon.wroteBack);
}

// The same account logs on when the caller names a listed workstation: the list
// is a set of NetBIOS names, so case does not matter.
void NetlogonTest::allowsALogonFromAListedWorkstation()
{
    WorkstationLogon logon;
    prepareWorkstationLogon(&logon, QStringLiteral("WS1, WS2"));
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 44;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        logon.userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = logon.server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("ws2"), credential, timestamp, ntResponse));

    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("SamLogon returned %1 bytes")
                                              .arg(reply.size())));
    QCOMPARE(readLe32(reply, 0), quint32(0x0002f210u));
    // Validation level 3 and its pointer, then the validation, authoritative
    // byte and status at the end.
    QCOMPARE(readLe16(reply, 16), quint16(3));
    QCOMPARE(readLe32(reply, 20), quint32(0x0002f200u));
    QCOMPARE(readLe32(reply, int(reply.size()) - 4), quint32(0));
    QVERIFY(reply.contains(Ndr::utf16le(QStringLiteral("alice"))));
    QVERIFY(logon.wroteBack);
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

void NetlogonTest::passwordSet2WritesTheMachineHash()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const QByteArray oldHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const DirectoryObject machine = machineAccount(oldHash);
    server.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });

    QString writtenDn;
    QByteArray writtenHash;
    Netlogon::WriteBackend writes;
    writes.setNtHash = [&writtenDn, &writtenHash](const QString &dn, const QByteArray &hash,
                                                  QString *) {
        writtenDn = dn;
        writtenHash = hash;
        return true;
    };
    server.setWriteBackend(writes);

    const ChannelFixture channel = openChannel(server, oldHash);
    QVERIFY(channel.ok);

    // MS-NRPC 3.1.4.4.5: the 512-byte buffer is the new password, UTF-16LE and
    // right-justified, RC4-ciphered under the channel's session key.
    const QByteArray password = Ndr::utf16le(QStringLiteral("N3w!Machine#42")) + QByteArray(2, '\0');
    QByteArray plain(512, '\0');
    plain.replace(512 - password.size(), password.size(), password);
    const quint32 timestamp = 77;
    const QByteArray reply = server.handleCall(
        Netlogon::OpServerPasswordSet2,
        passwordSetRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                           nextCredential(channel.seed, timestamp, channel.sessionKey, channel.flags,
                                          false),
                           timestamp, Krb5::rc4(channel.sessionKey, plain),
                           quint32(password.size())));
    QCOMPARE(reply.size(), 16);
    QCOMPARE(readLe32(reply, 8), timestamp);
    QCOMPARE(readLe32(reply, 12), quint32(0));
    QCOMPARE(writtenDn, machine.id);
    // Only the hash of the new password reaches the directory.
    QCOMPARE(writtenHash, Ntlm::ntowfV1(QStringLiteral("N3w!Machine#42")));
}

void NetlogonTest::rejectsAChannelCredentialFromTheWrongPassword()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const QByteArray ntHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const DirectoryObject machine = machineAccount(ntHash);
    server.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });

    const quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes;
    const QByteArray clientChallenge = QByteArray::fromHex("1112131415161718");
    const QByteArray challengeReply = server.handleCall(
        Netlogon::OpServerReqChallenge,
        challengeRequest(QStringLiteral("DC1"), clientChallenge));
    QCOMPARE(challengeReply.size(), 12);
    const QByteArray serverChallenge = challengeReply.left(8);

    // A client that does not know the machine password derives a different
    // key, so its credential cannot match the one the server computes.
    const QByteArray wrongKey = expectedSessionKey(
        Ntlm::ntowfV1(QStringLiteral("not-the-machine-password")), clientChallenge,
        serverChallenge, flags);
    const QByteArray reply = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("DC1$"), QStringLiteral("DC1"),
                            expectedCredential(clientChallenge, wrongKey, flags), flags));
    QCOMPARE(reply.size(), 4);
    QCOMPARE(readLe32(reply, 0), quint32(0xc0000022u)); // STATUS_ACCESS_DENIED

    // An account the directory does not hold is refused by name.
    const QByteArray unknown = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("GHOST$"), QStringLiteral("GHOST"),
                            QByteArray(8, '\0'), flags));
    QCOMPARE(unknown.size(), 4);
    QCOMPARE(readLe32(unknown, 0), quint32(0xc0000064u)); // STATUS_NO_SUCH_USER
}

// A partner DC opens the trust channel with the trusted domain's account name
// and the trust secret, not a machine password. The secret the LSAD calls store
// is the one used, so creating a trust over lsarpc is what enables its channel.
void NetlogonTest::trustChannelUsesTheTrustSecret()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    DirectoryObject trust;
    trust.id = QStringLiteral("CN=FABRIKAM,CN=System,DC=corp,DC=example,DC=com");
    trust.name = QStringLiteral("FABRIKAM");
    trust.attributes.insert(QStringLiteral("objectClass"),
                            QStringLiteral("top;leaf;trustedDomain"));
    trust.attributes.insert(QStringLiteral("flatName"), QStringLiteral("FABRIKAM"));
    trust.attributes.insert(QStringLiteral("trustPartner"), QStringLiteral("fabrikam.local"));
    trust.attributes.insert(QStringLiteral("securityIdentifier"),
                            QStringLiteral("S-1-5-21-9-8-7"));
    trust.attributes.insert(QStringLiteral("trustDirection"), QStringLiteral("3"));
    const QString secret = QStringLiteral("Trust!Secret9");
    trust.attributes.insert(QStringLiteral("trustAuthIncoming"),
                            QStringLiteral("2:")
                                + QString::fromLatin1(secret.toUtf8().toHex()));
    server.setObjectProvider([trust]() { return QList<DirectoryObject>{trust}; });

    const QByteArray ntHash = Ntlm::ntowfV1(secret);
    const QByteArray clientChallenge = QByteArray::fromHex("1020304050607080");
    const QByteArray challengeReply = server.handleCall(
        Netlogon::OpServerReqChallenge,
        challengeRequest(QStringLiteral("PARTNERDC"), clientChallenge));
    QCOMPARE(readLe32(challengeReply, 8), quint32(0));
    const QByteArray serverChallenge = challengeReply.left(8);

    const quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes;
    const QByteArray sessionKey =
        expectedSessionKey(ntHash, clientChallenge, serverChallenge, flags);
    const QByteArray reply = server.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("FABRIKAM$"), QStringLiteral("PARTNERDC"),
                            expectedCredential(clientChallenge, sessionKey, flags), flags));
    QCOMPARE(readLe32(reply, reply.size() - 4), quint32(0));
    QCOMPARE(readLe32(reply, 8), flags);
    QCOMPARE(readLe32(reply, 12), quint32(7)); // the trust's SID, not a machine RID
    QCOMPARE(reply.left(8), expectedCredential(serverChallenge, sessionKey, flags));

    // A channel for a domain this DC has no inbound trust with has no secret to
    // check against, so it is not an account at all.
    trust.attributes.insert(QStringLiteral("trustDirection"), QStringLiteral("2")); // outbound only
    NetlogonServer outbound;
    outbound.setConfig(config);
    outbound.setObjectProvider([trust]() { return QList<DirectoryObject>{trust}; });
    const QByteArray outboundChallenge = outbound.handleCall(
        Netlogon::OpServerReqChallenge,
        challengeRequest(QStringLiteral("PARTNERDC"), clientChallenge));
    const QByteArray outboundKey = expectedSessionKey(
        ntHash, clientChallenge, outboundChallenge.left(8), flags);
    const QByteArray refused = outbound.handleCall(
        Netlogon::OpServerAuthenticate3,
        authenticateRequest(QStringLiteral("FABRIKAM$"), QStringLiteral("PARTNERDC"),
                            expectedCredential(clientChallenge, outboundKey, flags), flags));
    QCOMPARE(readLe32(refused, refused.size() - 4), quint32(0xc0000064u)); // NO_SUCH_USER
}

// NetrLogonGetTrustRid names the disabled account kept for an inbound trust;
// a domain this DC has no trust with gets ERROR_NO_SUCH_DOMAIN.
void NetlogonTest::reportsTheTrustAccountRid()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    DirectoryObject trust;
    trust.id = QStringLiteral("CN=FABRIKAM,CN=System,DC=corp,DC=example,DC=com");
    trust.attributes.insert(QStringLiteral("objectClass"),
                            QStringLiteral("top;leaf;trustedDomain"));
    trust.attributes.insert(QStringLiteral("flatName"), QStringLiteral("FABRIKAM"));
    trust.attributes.insert(QStringLiteral("trustPartner"), QStringLiteral("fabrikam.local"));
    trust.attributes.insert(QStringLiteral("trustDirection"), QStringLiteral("3"));

    DirectoryObject account;
    account.id = QStringLiteral("CN=FABRIKAM$,CN=Users,DC=corp,DC=example,DC=com");
    account.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("FABRIKAM$"));
    account.attributes.insert(QStringLiteral("objectSid"),
                              QStringLiteral("S-1-5-21-1-2-3-1001"));
    server.setObjectProvider([trust, account]() {
        return QList<DirectoryObject>{trust, account};
    });

    const auto request = [](const QString &domain) {
        QByteArray stub;
        appendLe32(stub, 0);          // server_name: NULL
        appendLe32(stub, 0x00020001); // domain_name present
        appendStringArray(stub, domain);
        return stub;
    };

    const QByteArray reply =
        server.handleCall(Netlogon::OpLogonGetTrustRid, request(QStringLiteral("FABRIKAM")));
    QCOMPARE(reply.size(), 8);
    QCOMPARE(readLe32(reply, 0), quint32(1001));
    QCOMPARE(readLe32(reply, 4), quint32(0));

    // The partner's DNS name names the same trust.
    const QByteArray byDns = server.handleCall(Netlogon::OpLogonGetTrustRid,
                                               request(QStringLiteral("fabrikam.local")));
    QCOMPARE(readLe32(byDns, 0), quint32(1001));

    const QByteArray unknown =
        server.handleCall(Netlogon::OpLogonGetTrustRid, request(QStringLiteral("CONTOSO")));
    QCOMPARE(readLe32(unknown, unknown.size() - 4), quint32(1355)); // ERROR_NO_SUCH_DOMAIN
}

// The pre-DsRGetDcName locator a Windows 2000 client uses: any DC in a served
// domain, and the site a computer sits in.
void NetlogonTest::answersTheLegacyLocatorCalls()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.siteName = QStringLiteral("Default-First-Site-Name");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const auto anyDcRequest = [](const QString &domain) {
        QByteArray stub;
        appendLe32(stub, 0);          // logon_server: NULL
        appendLe32(stub, 0x00020001); // domainname present
        appendStringArray(stub, domain);
        return stub;
    };
    const QByteArray reply =
        server.handleCall(Netlogon::OpGetAnyDCName, anyDcRequest(QStringLiteral("CORP")));
    QCOMPARE(readLe32(reply, reply.size() - 4), quint32(0));
    QVERIFY(readLe32(reply, 0) != 0); // the dcname pointer
    QVERIFY(reply.contains(Ndr::utf16le(QStringLiteral("\\\\DC1"))));

    const QByteArray unknown =
        server.handleCall(Netlogon::OpGetAnyDCName, anyDcRequest(QStringLiteral("CONTOSO")));
    QCOMPARE(readLe32(unknown, 0), quint32(0)); // NULL dcname
    QCOMPARE(readLe32(unknown, unknown.size() - 4), quint32(1355)); // NO_SUCH_DOMAIN

    // DsRGetSiteName with a NULL computer name still answers this DC's site.
    QByteArray siteRequest;
    appendLe32(siteRequest, 0);
    const QByteArray site =
        server.handleCall(Netlogon::OpDsRGetSiteName, siteRequest);
    QCOMPARE(readLe32(site, site.size() - 4), quint32(0));
    QVERIFY(site.contains(Ndr::utf16le(QStringLiteral("Default-First-Site-Name"))));
}

void NetlogonTest::dcLocatorNamesThisDc()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.dcHost = QStringLiteral("dc1.corp.example.com");
    config.dcIp = QStringLiteral("10.0.0.10");
    config.siteName = QStringLiteral("Default-First-Site-Name");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const QByteArray dcNameReply =
        server.handleCall(Netlogon::OpGetDcName, getDcNameRequest(QStringLiteral("CORP")));
    QVERIFY(dcNameReply.contains(Ndr::utf16le(QStringLiteral("\\\\DC1"))));
    QCOMPARE(readLe32(dcNameReply, dcNameReply.size() - 4), quint32(0));

    const QByteArray dcNameRefused =
        server.handleCall(Netlogon::OpGetDcName, getDcNameRequest(QStringLiteral("OTHER")));
    QCOMPARE(dcNameRefused.size(), 4);
    QCOMPARE(readLe32(dcNameRefused, 0), quint32(0xc0000064u)); // STATUS_NO_SUCH_USER

    // The Ex2 arm carries the site, the address and the NBT_SERVER bits a
    // client needs to pick this DC. It answers for the DNS domain as well as
    // the NetBIOS name.
    const QByteArray ex2Reply = server.handleCall(
        Netlogon::OpDsRGetDcNameEx2, dsrGetDcNameEx2Request(QStringLiteral("corp.example.com")));
    QVERIFY(ex2Reply.size() > 64);
    QVERIFY(ex2Reply.contains(Ndr::utf16le(config.dcHost)));
    QVERIFY(ex2Reply.contains(Ndr::utf16le(config.dcIp)));
    QVERIFY(ex2Reply.contains(Ndr::utf16le(config.dnsDomain)));
    QVERIFY(ex2Reply.contains(Ndr::utf16le(config.siteName)));
    QCOMPARE(readLe32(ex2Reply, ex2Reply.size() - 4), quint32(0));
}

#include "test_netlogon.moc"
QTEST_GUILESS_MAIN(NetlogonTest)
