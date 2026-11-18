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
#include "Schannel.h"

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

// The characters a deferred lsa_String points at: a conformant array of its own
// counts and then the UTF-16 payload. `align` is the alignment of whatever
// follows it, which NDR pads to: 4 for the next header or byte array, 2 for a
// uint16 such as validation_level.
void appendDeferredString(QByteArray &out, const QString &value, int align = 4)
{
    while (out.size() % 4 != 0) out.append(char(0));
    const quint32 count = quint32(value.size());
    appendLe32(out, count); appendLe32(out, 0); appendLe32(out, count);
    out.append(Ndr::utf16le(value));
    while (out.size() % align != 0) out.append(char(0));
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
    appendDeferredString(out, QStringLiteral("CORP"));
    appendDeferredString(out, QStringLiteral("alice"));
    appendDeferredString(out, workstation);
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

// netr_PasswordInfo: the identity a network logon also carries, then the two
// 16-byte one-way functions of the password itself, in place, so this arm ends
// where netr_NetworkInfo's challenge and response headers begin. The interactive
// (1) and service (3) classes marshal it.
void appendPasswordLogon(QByteArray &out, quint16 validationLevel, const QByteArray &ntOwf,
                         const QString &workstation = QStringLiteral("CLIENT1"))
{
    while (out.size() % 4 != 0) out.append(char(0));

    appendLe16(out, 8); appendLe16(out, 8); appendLe32(out, 0x00020001u); // domain "CORP"
    appendLe32(out, 3); // parameter_control
    while (out.size() % 4 != 0) out.append(char(0)); // OLD_LARGE_INTEGER is 4-aligned
    appendLe64(out, 0); // Reserved
    appendLe16(out, 10); appendLe16(out, 10); appendLe32(out, 0x00020002u); // "alice"
    // An odd-length workstation pins the rule validation_level depends on: the
    // level is 2-aligned and comes straight after these UTF-16 characters.
    const quint16 workstationBytes = quint16(workstation.size() * 2);
    appendLe16(out, workstationBytes); appendLe16(out, workstationBytes);
    appendLe32(out, 0x00020003u);

    out.append(QByteArray(16, '\0')); // lmpassword: ignored, no LM hash is stored
    out.append(ntOwf);

    appendDeferredString(out, QStringLiteral("CORP"));
    appendDeferredString(out, QStringLiteral("alice"));
    appendDeferredString(out, workstation, 2);

    appendLe16(out, validationLevel);
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
    // What the client asked with, which NetrLogonGetCapabilities level 2 answers.
    quint32 requestedFlags = 0;
};

// The client half of MS-NRPC 3.1.4.4.1-3.1.4.4.3, computed independently of
// the server: challenge, session key from the machine hash, and the first
// credential over the client challenge.
ChannelFixture openChannel(NetlogonServer &server, const QByteArray &machineHash,
                           quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes)
{
    ChannelFixture out;
    out.flags = flags;
    out.requestedFlags = flags;
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
    // The chain starts from the credential the challenge produced — the one the
    // client sent — because that is what `netlogon_creds_first_step` stores as
    // the seed. The reply credential is what the next step derives from it.
    out.seed = expectedCredential(clientChallenge, out.sessionKey, flags);
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
    QString writtenDn;
    QMap<QString, QString> writtenAttributes;
};

void prepareWorkstationLogon(WorkstationLogon *fixture, const QString &workstations,
                             const QMap<QString, QString> &accountAttributes = {})
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
    for (auto it = accountAttributes.cbegin(); it != accountAttributes.cend(); ++it)
        user.attributes.insert(it.key(), it.value());

    // The domain object carries the password policy the logon paths read. AD's
    // default is 42 days before a password expires and one day before it may be
    // changed again.
    DirectoryObject domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.name = QStringLiteral("CORP");
    domain.type = QStringLiteral("domainDNS");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3"));
    domain.attributes.insert(QStringLiteral("maxPwdAge"),
                             QStringLiteral("-36288000000000"));
    domain.attributes.insert(QStringLiteral("minPwdAge"),
                             QStringLiteral("-864000000000"));

    fixture->server.setObjectProvider([machine, user, domain]() {
        return QList<DirectoryObject>{machine, user, domain};
    });

    Netlogon::WriteBackend writes;
    writes.updateAccount = [fixture](const QString &dn, const QMap<QString, QString> &attributes,
                                     QString *) {
        fixture->wroteBack = true;
        fixture->writtenDn = dn;
        fixture->writtenAttributes = attributes;
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
    void logonGetCapabilitiesReportsTheChannelFlags();
    void sealsThePipeWithTheChannelKey();
    void legacySamLogonAuthenticatesSecureChannel_data();
    void legacySamLogonAuthenticatesSecureChannel();
    void refusesALogonOutsideLogonHours();
    void countsRefusedPasswords();
    void locksTheAccountAfterTheThreshold();
    void refusesALogonFromAnotherWorkstation();
    void allowsALogonFromAListedWorkstation();
    void refusesAnExpiredPassword();
    void refusesAPasswordThatMustChange();
    void allowsAnAgedPasswordThatNeverExpires();
    void interactiveAndServiceLogonClasses_data();
    void interactiveAndServiceLogonClasses();
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
    // The seed the chain continues from is the client credential the challenge
    // produced, not the server's reply to it: `netlogon_creds_first_step` stores
    // exactly that, and the next call derives from seed + timestamp.
    const QByteArray channelSeed = expectedCredential(clientChallenge, sessionKey, flags);
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

    // The seed the chain continues from is the client credential the challenge
    // produced, not the server's reply to it: `netlogon_creds_first_step` stores
    // exactly that, and the next call derives from seed + timestamp.
    const QByteArray channelSeed = expectedCredential(clientChallenge, sessionKey, flags);
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

// A refused password raises badPwdCount and stamps badPasswordTime; the next
// success writes the counter back to zero and bumps logonCount. That pair is
// what a lockout policy and an administrator reading the account start from.
void NetlogonTest::countsRefusedPasswords()
{
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");

    const QByteArray machineHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const QByteArray userHash = Ntlm::ntowfV1(QStringLiteral("Alice!Password123"));
    DirectoryObject machine = machineAccount(machineHash);
    DirectoryObject user;
    user.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1100"));
    user.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(userHash.toHex()));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    user.attributes.insert(QStringLiteral("badPwdCount"), QStringLiteral("0"));

    // The provider answers with what the directory would hold after each write,
    // so a second refusal sees the counter the first one stored.
    QMap<QString, QString> stored;
    QList<QMap<QString, QString>> writes;
    NetlogonServer server;
    server.setConfig(config);
    server.setObjectProvider([machine, user, &stored]() {
        DirectoryObject current = user;
        for (auto it = stored.cbegin(); it != stored.cend(); ++it)
            current.attributes.insert(it.key(), it.value());
        return QList<DirectoryObject>{machine, current};
    });
    Netlogon::WriteBackend backend;
    backend.updateAccount = [&stored, &writes](const QString &, const QMap<QString, QString> &changes,
                                               QString *) {
        writes.append(changes);
        for (auto it = changes.cbegin(); it != changes.cend(); ++it)
            stored.insert(it.key(), it.value());
        return true;
    };
    server.setWriteBackend(backend);

    const auto wrongPassword = [&]() {
        ChannelFixture channel = openChannel(server, machineHash);
        const quint32 timestamp = 51;
        const QByteArray credential = nextCredential(channel.seed, timestamp,
                                                     channel.sessionKey, channel.flags, false);
        const QByteArray ntResponse = ntlmV2Response(
            Ntlm::ntowfV1(QStringLiteral("Not!ThePassword9")), QStringLiteral("alice"),
            QStringLiteral("CORP"), QByteArray::fromHex("0102030405060708"));
        return server.handleCall(
            Netlogon::OpLogonSamLogon,
            samLogonRequest(QStringLiteral("CLIENT"), credential, timestamp, ntResponse));
    };

    QCOMPARE(readLe32(wrongPassword(), 0), quint32(0xc000006au)); // STATUS_WRONG_PASSWORD
    QCOMPARE(writes.size(), 1);
    QCOMPARE(writes.last().value(QStringLiteral("badPwdCount")), QStringLiteral("1"));
    QVERIFY(writes.last().value(QStringLiteral("badPasswordTime")).toLongLong() > 0);

    QCOMPARE(readLe32(wrongPassword(), 0), quint32(0xc000006au));
    QCOMPARE(writes.last().value(QStringLiteral("badPwdCount")), QStringLiteral("2"));

    ChannelFixture channel = openChannel(server, machineHash);
    QVERIFY(channel.ok);
    const quint32 timestamp = 52;
    const QByteArray credential = nextCredential(channel.seed, timestamp, channel.sessionKey,
                                                 channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("CLIENT"), credential, timestamp, ntResponse));
    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("SamLogon returned %1 bytes")
                                              .arg(reply.size())));
    QCOMPARE(writes.last().value(QStringLiteral("badPwdCount")), QStringLiteral("0"));
    QCOMPARE(writes.last().value(QStringLiteral("logonCount")), QStringLiteral("1"));
    // The answer carries the post-logon counters back to the caller: the
    // authenticator and validation header are 24 bytes, and logon_count and
    // bad_password_count follow the six NTTIMEs and six string headers.
    QCOMPARE(readLe16(reply, 24 + 96), quint16(1)); // logon_count
    QCOMPARE(readLe16(reply, 24 + 98), quint16(0)); // bad_password_count
}

// The domain policy is what turns a counted refusal into a lockout: at the
// threshold the DC stamps lockoutTime and refuses even the right password until
// the duration runs out, after which the account opens again.
void NetlogonTest::locksTheAccountAfterTheThreshold()
{
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");

    const QByteArray machineHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const QByteArray userHash = Ntlm::ntowfV1(QStringLiteral("Alice!Password123"));
    DirectoryObject machine = machineAccount(machineHash);
    DirectoryObject domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.kind = ObjectKind::Domain;
    domain.attributes.insert(QStringLiteral("lockoutThreshold"), QStringLiteral("2"));
    domain.attributes.insert(QStringLiteral("lockoutDuration"),
                             QStringLiteral("-18000000000"));
    domain.attributes.insert(QStringLiteral("lockoutObservationWindow"),
                             QStringLiteral("-18000000000"));
    DirectoryObject user;
    user.id = QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com");
    user.kind = ObjectKind::User;
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("alice"));
    user.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-1100"));
    user.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(userHash.toHex()));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    user.attributes.insert(QStringLiteral("badPwdCount"), QStringLiteral("0"));
    user.attributes.insert(QStringLiteral("badPasswordTime"), QStringLiteral("0"));
    user.attributes.insert(QStringLiteral("lockoutTime"), QStringLiteral("0"));

    QMap<QString, QString> stored;
    NetlogonServer server;
    server.setConfig(config);
    server.setObjectProvider([machine, domain, user, &stored]() {
        DirectoryObject current = user;
        for (auto it = stored.cbegin(); it != stored.cend(); ++it)
            current.attributes.insert(it.key(), it.value());
        return QList<DirectoryObject>{machine, domain, current};
    });
    Netlogon::WriteBackend backend;
    backend.updateAccount = [&stored](const QString &, const QMap<QString, QString> &changes,
                                      QString *) {
        for (auto it = changes.cbegin(); it != changes.cend(); ++it)
            stored.insert(it.key(), it.value());
        return true;
    };
    server.setWriteBackend(backend);

    const auto attempt = [&](const QByteArray &ntHash) {
        ChannelFixture channel = openChannel(server, machineHash);
        const quint32 timestamp = 61;
        const QByteArray credential = nextCredential(channel.seed, timestamp,
                                                     channel.sessionKey, channel.flags, false);
        const QByteArray ntResponse = ntlmV2Response(
            ntHash, QStringLiteral("alice"), QStringLiteral("CORP"),
            QByteArray::fromHex("0102030405060708"));
        return server.handleCall(
            Netlogon::OpLogonSamLogon,
            samLogonRequest(QStringLiteral("CLIENT"), credential, timestamp, ntResponse));
    };
    const QByteArray wrongHash = Ntlm::ntowfV1(QStringLiteral("Not!ThePassword9"));

    QCOMPARE(readLe32(attempt(wrongHash), 0), quint32(0xc000006au));
    // Below the threshold nothing is locked, so the account's own lockoutTime
    // is still what it was.
    QVERIFY(!stored.contains(QStringLiteral("lockoutTime")));
    QCOMPARE(readLe32(attempt(wrongHash), 0), quint32(0xc000006au));
    const quint64 lockedAt = stored.value(QStringLiteral("lockoutTime")).toULongLong();
    QVERIFY(lockedAt > 0);

    // The right password is refused while the lockout stands, and the attempt
    // does not count as another bad password.
    QCOMPARE(readLe32(attempt(userHash), 0), quint32(0xc0000234u));
    QCOMPARE(stored.value(QStringLiteral("lockoutTime")).toULongLong(), lockedAt);
    QCOMPARE(stored.value(QStringLiteral("badPwdCount")), QStringLiteral("2"));

    // Once the duration has passed the account is open again, and the good
    // logon lifts the lockout.
    stored.insert(QStringLiteral("lockoutTime"),
                  QString::number(lockedAt - 2 * 18000000000ull));
    const QByteArray reply = attempt(userHash);
    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("SamLogon returned %1 bytes")
                                              .arg(reply.size())));
    QCOMPARE(stored.value(QStringLiteral("lockoutTime")), QStringLiteral("0"));
    QCOMPARE(stored.value(QStringLiteral("badPwdCount")), QStringLiteral("0"));
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

// A password older than the domain's maxPwdAge is proved but not accepted: the
// caller is told the credit has expired, which is what a Windows DC answers so
// the workstation can send the user to the change-password prompt.
void NetlogonTest::refusesAnExpiredPassword()
{
    WorkstationLogon logon;
    const qint64 stale = QDateTime::currentSecsSinceEpoch() - 60 * 86400;
    prepareWorkstationLogon(&logon, QString(),
                            {{QStringLiteral("pwdLastSet"), QString::number(stale)}});
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 51;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        logon.userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = logon.server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("WS1"), credential, timestamp, ntResponse));

    QCOMPARE(reply.size(), 4);
    QCOMPARE(readLe32(reply, 0), quint32(0xc0000071u)); // STATUS_PASSWORD_EXPIRED
    QVERIFY(!logon.wroteBack);
}

// pwdLastSet zero is the other case a client distinguishes: an administrator
// demanded a change, which AD reports as a must-change rather than an expiry.
void NetlogonTest::refusesAPasswordThatMustChange()
{
    WorkstationLogon logon;
    prepareWorkstationLogon(&logon, QString(), {{QStringLiteral("pwdLastSet"), QStringLiteral("0")}});
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 52;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        logon.userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = logon.server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("WS1"), credential, timestamp, ntResponse));

    QCOMPARE(reply.size(), 4);
    QCOMPARE(readLe32(reply, 0), quint32(0xc0000224u)); // STATUS_PASSWORD_MUST_CHANGE
    QVERIFY(!logon.wroteBack);
}

// DONT_EXPIRE_PASSWORD is how a service account keeps a credential that never
// ages out, and it overrides the domain's maximum age.
void NetlogonTest::allowsAnAgedPasswordThatNeverExpires()
{
    WorkstationLogon logon;
    const qint64 stale = QDateTime::currentSecsSinceEpoch() - 60 * 86400;
    prepareWorkstationLogon(
        &logon, QString(),
        {{QStringLiteral("pwdLastSet"), QString::number(stale)},
         {QStringLiteral("userAccountControl"), QStringLiteral("66048")}}); // 512 | 0x10000
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 53;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    const QByteArray ntResponse = ntlmV2Response(
        logon.userHash, QStringLiteral("alice"), QStringLiteral("CORP"),
        QByteArray::fromHex("0102030405060708"));
    const QByteArray reply = logon.server.handleCall(
        Netlogon::OpLogonSamLogon,
        samLogonRequest(QStringLiteral("WS1"), credential, timestamp, ntResponse));

    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("SamLogon returned %1 bytes")
                                              .arg(reply.size())));
    QCOMPARE(readLe32(reply, 0), quint32(0x0002f210u));
    QCOMPARE(readLe32(reply, int(reply.size()) - 4), quint32(0));
    QVERIFY(logon.wroteBack);
}

// The interactive (1) and service (3) classes send netr_PasswordInfo: the
// password's own NT one-way function instead of a challenge and its response.
// It is compared to the stored hash, so a wrong one is a wrong password rather
// than a malformed request, and the workstation the class names is the one the
// account's restriction is checked against.
void NetlogonTest::interactiveAndServiceLogonClasses_data()
{
    QTest::addColumn<quint16>("logonLevel");
    QTest::addColumn<bool>("correctPassword");
    QTest::newRow("interactive") << quint16(1) << true;
    QTest::newRow("service") << quint16(3) << true;
    QTest::newRow("interactive-wrong-hash") << quint16(1) << false;
}

void NetlogonTest::interactiveAndServiceLogonClasses()
{
    QFETCH(quint16, logonLevel);
    QFETCH(bool, correctPassword);

    WorkstationLogon logon;
    prepareWorkstationLogon(&logon, QStringLiteral("WS1,WS2"));
    QVERIFY(logon.channel.ok);

    const quint32 timestamp = 61;
    const QByteArray credential = nextCredential(logon.channel.seed, timestamp,
                                                 logon.channel.sessionKey, logon.channel.flags, false);
    QByteArray owf = logon.userHash;
    if (!correctPassword)
        owf[0] = char(quint8(owf.at(0)) ^ 0x5a);

    QByteArray request;
    appendLe32(request, 0); // NULL LogonServer pointer
    appendPointerString(request, QStringLiteral("DC1"), 0x00021000u); // ComputerName
    appendLe32(request, 0x00021001u); // Authenticator pointer
    request.append(authenticatorRequest(credential, timestamp));
    appendLe32(request, 0x00021002u); // ReturnAuthenticator pointer
    request.append(QByteArray(12, '\0'));
    appendLe16(request, logonLevel); // LogonLevel: the class, not the validation
    appendLe16(request, logonLevel); // NETLOGON_LEVEL's NDR32 union discriminator
    appendLe32(request, 0x00021003u); // LogonInteractive/Service referent
    appendPasswordLogon(request, 3, owf, QStringLiteral("WS1"));

    const QByteArray reply = logon.server.handleCall(Netlogon::OpLogonSamLogon, request);
    if (!correctPassword) {
        QCOMPARE(reply.size(), 4);
        QCOMPARE(readLe32(reply, 0), quint32(0xc000006au)); // STATUS_WRONG_PASSWORD
        // A refused password is a counted failure, but not a logon.
        QCOMPARE(logon.writtenAttributes.value(QStringLiteral("badPwdCount")), QStringLiteral("1"));
        QVERIFY(!logon.writtenAttributes.contains(QStringLiteral("logonCount")));
        return;
    }

    QVERIFY2(reply.size() > 24, qPrintable(QStringLiteral("SamLogon returned %1 bytes: %2")
                                               .arg(reply.size())
                                               .arg(readLe32(reply, 0), 8, 16, QLatin1Char('0'))));
    QCOMPARE(readLe32(reply, 0), quint32(0x0002f210u));
    QCOMPARE(readLe32(reply, 12), timestamp);
    QCOMPARE(readLe16(reply, 16), quint16(3)); // the validation level asked for
    QCOMPARE(readLe32(reply, int(reply.size()) - 4), quint32(0));
    QVERIFY(reply.contains(Ndr::utf16le(QStringLiteral("alice"))));
    // A validated password logon is recorded on the account like a network one.
    QCOMPARE(logon.writtenDn, QStringLiteral("CN=alice,CN=Users,DC=corp,DC=example,DC=com"));
    QCOMPARE(logon.writtenAttributes.value(QStringLiteral("logonCount")), QStringLiteral("1"));
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

// MS-NRPC 3.5.4.4.10 (opnum 21). A client runs this before it trusts a channel:
// the capabilities it reads back have to be the flags the authentication
// negotiated, so a machine whose traffic was redirected to a server that
// negotiated a weaker channel sees the difference. Samba calls it right after
// NetrServerAuthenticate3 and treats "procedure not found" as a downgrade
// whenever NETLOGON_NEG_SUPPORTS_AES is on the channel.
QByteArray capabilitiesRequest(const QString &serverName, const QString &computer,
                               const QByteArray &credential, quint32 timestamp, quint32 queryLevel)
{
    QByteArray stub;
    // server_name is a `[in] [string]` and travels in place; computer_name is
    // `[in,unique] [string]` and carries a referent. This is the order and the
    // padding `net ads join` puts on the wire (captured from the sealed call).
    appendStringArray(stub, serverName);
    appendPointerString(stub, computer, 0x00020000u + quint32(stub.size()));
    stub.append(credential);
    appendLe32(stub, timestamp);
    stub.append(QByteArray(12, '\0')); // the client's own return_authenticator
    appendLe32(stub, queryLevel);
    return stub;
}

// The seed the next call derives from: the input of the reply credential, which
// `netlogon_creds_step` stores as the new seed.
QByteArray advanceSeed(const QByteArray &seed, quint32 timestamp)
{
    QByteArray out;
    appendLe32(out, readLe32(seed, 0) + timestamp + 1);
    out.append(seed.mid(4, 4));
    return out;
}

void NetlogonTest::logonGetCapabilitiesReportsTheChannelFlags()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const QByteArray ntHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const DirectoryObject machine = machineAccount(ntHash);
    server.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });

    const quint32 flags = Netlogon::kNegStrongKeys | Netlogon::kNegPasswordSet2
                          | Netlogon::kNegSupportsAes;
    const ChannelFixture channel = openChannel(server, ntHash, flags);
    QVERIFY(channel.ok);

    // Level 1 answers the flags the channel negotiated, level 2 the flags the
    // client asked with; the client compares both against what it holds and
    // reads the discriminant in front of the arm (`Bad switch value` otherwise).
    quint32 timestamp = 41;
    QByteArray seed = channel.seed;
    for (const quint32 level : {1u, 2u}) {
        const QByteArray request = capabilitiesRequest(
            QStringLiteral("\\\\DC1"), QStringLiteral("DC1"),
            nextCredential(seed, timestamp, channel.sessionKey, channel.flags, false), timestamp,
            level);
        const QByteArray reply = server.handleCall(Netlogon::OpLogonGetCapabilities, request);
        QCOMPARE(reply.size(), 24);
        QCOMPARE(readLe32(reply, 8), timestamp);
        QCOMPARE(readLe32(reply, 12), level);
        QCOMPARE(readLe32(reply, 16), level == 2 ? channel.requestedFlags : flags);
        QCOMPARE(readLe32(reply, 20), quint32(0));
        seed = advanceSeed(seed, timestamp);
        timestamp += 2; // what `netlogon_creds_client_authenticator` does
    }

    // A credential the channel did not produce is refused, and the channel is
    // not stepped: the refusal answers before anything is derived.
    const QByteArray wrong = server.handleCall(
        Netlogon::OpLogonGetCapabilities,
        capabilitiesRequest(QStringLiteral("\\\\DC1"), QStringLiteral("DC1"), QByteArray(8, '\0'),
                            timestamp, 1));
    QCOMPARE(wrong.size(), 4);
    QCOMPARE(readLe32(wrong, 0), quint32(0xc0000022u)); // STATUS_ACCESS_DENIED

    // Query levels are 1 and 2; anything else would have no arm to return.
    const QByteArray unknownLevel = server.handleCall(
        Netlogon::OpLogonGetCapabilities,
        capabilitiesRequest(QStringLiteral("\\\\DC1"), QStringLiteral("DC1"), QByteArray(8, '\0'),
                            timestamp, 3));
    QCOMPARE(unknownLevel.size(), 4);
    QCOMPARE(readLe32(unknownLevel, 0), quint32(0xc000000du)); // STATUS_INVALID_PARAMETER
}

// The DCE/RPC framing a Netlogon client uses once its channel exists: a bind
// that carries an NL_AUTH_MESSAGE, then requests whose stub is sealed under the
// channel key and whose signature is an NL_AUTH_SIGNATURE.
QByteArray rpcBindPdu(const QByteArray &token, quint8 authType, quint8 authLevel,
                      quint32 contextId)
{
    QByteArray body;
    appendLe16(body, 4280); // max_xmit
    appendLe16(body, 4280); // max_recv
    appendLe32(body, 1);    // assoc_group
    body.append(char(1));   // one presentation context
    body.append(QByteArray(3, '\0'));
    appendLe16(body, 0);    // context id
    body.append(char(1));   // one transfer syntax
    body.append(char(0));
    body.append(Netlogon::interface().uuid);
    appendLe16(body, Netlogon::interface().major);
    appendLe16(body, Netlogon::interface().minor);
    body.append(Rpc::kNdrSyntaxUuid);
    appendLe16(body, 2);
    appendLe16(body, 0);
    while (body.size() % 4 != 0)
        body.append(char(0));

    QByteArray pdu;
    pdu.append(char(5)); // version
    pdu.append(char(0));
    pdu.append(char(11)); // MTYPE_BIND
    pdu.append(char(3));  // first + last frag
    appendLe32(pdu, 0x00000010u); // drep: little-endian, ASCII, IEEE float
    appendLe16(pdu, quint16(16 + body.size() + (token.isEmpty() ? 0 : 8 + token.size())));
    appendLe16(pdu, quint16(token.size()));
    appendLe32(pdu, 1); // call id
    pdu.append(body);
    if (!token.isEmpty()) {
        pdu.append(char(authType));
        pdu.append(char(authLevel));
        pdu.append(char(0)); // pad
        pdu.append(char(0));
        appendLe32(pdu, contextId);
        pdu.append(token);
    }
    return pdu;
}

QByteArray rpcRequestPdu(quint16 opnum, const QByteArray &stub, const QByteArray &signature,
                         bool sealed)
{
    QByteArray payload = stub;
    const int pad = (4 - (payload.size() % 4)) % 4;
    payload.append(QByteArray(pad, '\0'));

    QByteArray pdu;
    pdu.append(char(5));
    pdu.append(char(0));
    pdu.append(char(0)); // MTYPE_REQUEST
    pdu.append(char(3));
    appendLe32(pdu, 0x00000010u); // drep
    appendLe16(pdu, quint16(24 + payload.size() + (signature.isEmpty() ? 0 : 8 + signature.size())));
    appendLe16(pdu, quint16(signature.size()));
    appendLe32(pdu, 2); // call id
    appendLe32(pdu, quint32(stub.size())); // alloc_hint
    appendLe16(pdu, 0);  // context id
    appendLe16(pdu, opnum);
    pdu.append(payload);
    if (!signature.isEmpty()) {
        pdu.append(char(Schannel::AuthType));
        pdu.append(char(sealed ? 6 : 5));
        pdu.append(char(pad));
        pdu.append(char(0));
        appendLe32(pdu, 7); // auth_context_id
        pdu.append(signature);
    }
    return pdu;
}

// What the client's schannel provider sends as the bind's auth_value: the NDR
// NL_AUTH_MESSAGE, whose strings are NUL-terminated and in place.
QByteArray bindMessage(quint32 flags, const QString &domain, const QString &computer)
{
    QByteArray out;
    appendLe32(out, Schannel::NegotiateRequest);
    appendLe32(out, flags);
    out.append(domain.toLatin1());
    out.append(char(0));
    out.append(computer.toLatin1());
    out.append(char(0));
    return out;
}

void NetlogonTest::sealsThePipeWithTheChannelKey()
{
    NetlogonServer server;
    Netlogon::Config config;
    config.netbios = QStringLiteral("CORP");
    config.realm = QStringLiteral("CORP.EXAMPLE.COM");
    config.dnsDomain = QStringLiteral("corp.example.com");
    config.dcName = QStringLiteral("DC1");
    config.domainSid = QStringLiteral("S-1-5-21-1-2-3");
    server.setConfig(config);

    const QByteArray ntHash = Ntlm::ntowfV1(QStringLiteral("Mach!neP@ss1"));
    const DirectoryObject machine = machineAccount(ntHash);
    server.setObjectProvider([machine]() { return QList<DirectoryObject>{machine}; });

    // The flags a client that takes up authenticated RPC asks with.
    const ChannelFixture channel =
        openChannel(server, ntHash, Netlogon::kNegStrongKeys | Netlogon::kNegSupportsAes
                                        | Netlogon::kNegAuthenticatedRpc);
    QVERIFY(channel.ok);

    // The endpoint resolves the channel a bind names, and it is the same key the
    // authenticate exchange agreed on.
    Rpc::SchannelCredentials credentials;
    QVERIFY(server.schannelCredentials(QStringLiteral("CORP"), QStringLiteral("DC1"), &credentials));
    QCOMPARE(credentials.sessionKey, channel.sessionKey);
    QVERIFY(credentials.negotiateFlags & Netlogon::kNegAuthenticatedRpc);
    QCOMPARE(credentials.account, QStringLiteral("DC1$"));
    // A channel of another domain is not a credential for this one.
    QVERIFY(!server.schannelCredentials(QStringLiteral("OTHER"), QStringLiteral("DC1"),
                                        &credentials));

    std::unique_ptr<RpcServer::Channel> pipe(server.rpc()->newChannel());
    const QByteArray ack = pipe->feed(
        rpcBindPdu(bindMessage(Schannel::FlagNetbiosDomain | Schannel::FlagNetbiosComputer,
                               QStringLiteral("CORP"), QStringLiteral("DC1")),
                   Schannel::AuthType, 6, 7));
    QCOMPARE(quint8(ack.at(2)), quint8(12)); // MTYPE_BIND_ACK
    QCOMPARE(readLe16(ack, 10), quint16(12)); // the NL_AUTH_MESSAGE it answers with
    const QByteArray answer = ack.right(12);
    QCOMPARE(readLe32(answer, 0), quint32(Schannel::NegotiateResponse));
    QCOMPARE(readLe32(answer, 4), quint32(0));

    // A sealed request: the stub pads to four bytes, the signature seals it.
    const quint32 timestamp = 77;
    const QByteArray stub = capabilitiesRequest(
        QStringLiteral("\\\\DC1"), QStringLiteral("DC1"),
        nextCredential(channel.seed, timestamp, channel.sessionKey, channel.flags, false), timestamp,
        1);
    const auto sealedRequest = [&](quint64 seq, const QByteArray &key) {
        QByteArray payload = stub;
        while (payload.size() % 4 != 0)
            payload.append(char(0));
        QByteArray sealed;
        const QByteArray signature =
            Schannel::sign(channel.flags, key, seq, true, payload, true, &sealed);
        return rpcRequestPdu(Netlogon::OpLogonGetCapabilities, stub, signature, true)
            .replace(24, payload.size(), sealed);
    };

    const QByteArray reply = pipe->feed(sealedRequest(0, channel.sessionKey));
    QVERIFY(!reply.isEmpty());
    QCOMPARE(quint8(reply.at(2)), quint8(2)); // MTYPE_RESPONSE
    const QByteArray signature = reply.right(Schannel::signatureSize(channel.flags));
    QByteArray opened = reply.mid(24, reply.size() - 24 - 8 - signature.size());
    QVERIFY(Schannel::open(channel.flags, channel.sessionKey, 1, false, signature, &opened));
    QCOMPARE(readLe32(opened, 8), timestamp);
    QCOMPARE(readLe32(opened, 12), quint32(1)); // the query_level discriminant
    QCOMPARE(readLe32(opened, 16), channel.flags);
    QCOMPARE(readLe32(opened, 20), quint32(0));

    // Both sides advance one counter per PDU, so the next request is at 2 and
    // its reply at 3: a receiver that did not advance them would refuse it.
    const QByteArray second = pipe->feed(sealedRequest(2, channel.sessionKey));
    QVERIFY(!second.isEmpty());
    const QByteArray secondSignature = second.right(Schannel::signatureSize(channel.flags));
    QByteArray secondOpened = second.mid(24, second.size() - 24 - 8 - secondSignature.size());
    QVERIFY(Schannel::open(channel.flags, channel.sessionKey, 3, false, secondSignature,
                           &secondOpened));

    // A key the channel did not agree on is not a seal: the call is dropped, not
    // served and not answered.
    QVERIFY(pipe->feed(sealedRequest(4, QByteArray(16, '\x5a'))).isEmpty());

    // And a bind naming a computer this DC holds no channel for is refused, not
    // accepted unauthenticated.
    std::unique_ptr<RpcServer::Channel> stranger(server.rpc()->newChannel());
    const QByteArray refused = stranger->feed(
        rpcBindPdu(bindMessage(Schannel::FlagNetbiosDomain | Schannel::FlagNetbiosComputer,
                               QStringLiteral("CORP"), QStringLiteral("ELSEWHERE")),
                   Schannel::AuthType, 6, 7));
    QCOMPARE(quint8(refused.at(2)), quint8(12));
    QCOMPARE(readLe16(refused, 10), quint16(0)); // no verifier: there is no key
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

    // DsrEnumerateDomainTrusts (40): the call a Windows 2000 join makes after
    // opening the Netlogon pipe. The [out,ref] list is inline — the count and
    // the array pointer, with no referent id — and stopping at a bare WERROR
    // leaves the client unable to unmarshal the answer ("The stub received bad
    // data"). This forest holds one domain and no trusts, so the list is empty
    // but well formed.
    QByteArray trustRequest;
    appendLe32(trustRequest, 0); // NULL server_name
    appendLe32(trustRequest, 0); // trust_flags
    const QByteArray trusts =
        server.handleCall(Netlogon::OpDsrEnumerateDomainTrusts, trustRequest);
    QCOMPARE(trusts.size(), 12);
    QCOMPARE(readLe32(trusts, 0), quint32(0)); // count
    QCOMPARE(readLe32(trusts, 4), quint32(0)); // NULL array
    QCOMPARE(readLe32(trusts, 8), quint32(0)); // WERROR
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
