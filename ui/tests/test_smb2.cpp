// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "Epm.h"
#include "Ntlm.h"
#include "Smb2.h"
#include "Gss.h"
#include "Smb3Crypto.h"

namespace {

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

void putLe64(QByteArray &out, quint64 value)
{
    putLe32(out, quint32(value & 0xffffffffu));
    putLe32(out, quint32((value >> 32) & 0xffffffffu));
}

quint16 readLe16(const QByteArray &data, int at)
{
    return quint16(quint8(data.at(at)) | (quint16(quint8(data.at(at + 1))) << 8));
}

quint32 readLe32(const QByteArray &data, int at)
{
    return quint32(quint8(data.at(at))) | (quint32(quint8(data.at(at + 1))) << 8)
           | (quint32(quint8(data.at(at + 2))) << 16)
           | (quint32(quint8(data.at(at + 3))) << 24);
}

quint64 readLe64(const QByteArray &data, int at)
{
    return quint64(readLe32(data, at)) | (quint64(readLe32(data, at + 4)) << 32);
}

// The 64-byte SMB2 header every request starts with.
QByteArray header(quint16 command, quint64 messageId, quint64 sessionId, quint32 treeId)
{
    QByteArray h;
    h.append(QByteArray("\376SMB", 4));
    putLe16(h, 64);          // StructureSize
    putLe16(h, 1);           // CreditCharge
    putLe32(h, 0);           // Status
    putLe16(h, command);
    putLe16(h, 1);           // CreditRequest
    putLe32(h, 0);           // Flags
    putLe32(h, 0);           // NextCommand
    putLe64(h, messageId);
    putLe32(h, 0);           // reserved (async: AsyncId)
    putLe32(h, treeId);
    putLe64(h, sessionId);
    h.append(QByteArray(16, '\0')); // signature
    return h;
}

QByteArray nbt(const QByteArray &message)
{
    QByteArray framed;
    framed.append(char(0));
    framed.append(char((message.size() >> 16) & 0xff));
    framed.append(char((message.size() >> 8) & 0xff));
    framed.append(char(message.size() & 0xff));
    framed.append(message);
    return framed;
}

// An SMB1 negotiate, the first message Windows 2000 sends once a NetBIOS
// session (TCP 139) has been accepted.
QByteArray smb1Negotiate()
{
    QByteArray message = QByteArray("\377SMB", 4);
    message.append(char(0x72));          // SMB_COM_NEGOTIATE
    message.append(QByteArray(4, '\0')); // Status
    message.append(char(0x18));          // Flags
    message.append(QByteArray(2, '\0')); // Flags2
    message.append(QByteArray(12, '\0')); // PID high, signature, reserved
    message.append(QByteArray(2, '\0')); // TID
    message.append(QByteArray(2, '\0')); // PID
    message.append(QByteArray(2, '\0')); // UID
    message.append(QByteArray(2, '\0')); // MID
    message.append(char(0));             // WordCount
    const QByteArray dialects = QByteArray("\002NT LM 0.12\0", 12);
    putLe16(message, quint16(dialects.size()));
    message.append(dialects);
    return message;
}

// One reply, unframed.
QByteArray bodyOf(const QByteArray &framed)
{
    if (framed.size() < 4)
        return QByteArray();
    return framed.mid(4 + 64);
}

quint32 statusOf(const QByteArray &framed)
{
    return readLe32(framed, 4 + 8);
}

QByteArray utf16(const QString &text)
{
    QByteArray out;
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
    return out;
}

QByteArray ntlmNegotiate()
{
    QByteArray token("NTLMSSP", 7);
    token.append(char(0));
    putLe32(token, 1);          // NEGOTIATE_MESSAGE
    putLe32(token, 0x00000201); // flags: unicode, NTLM, session security
    return token;
}

// A SPNEGO offer that names Kerberos and carries no token, the way a client
// with no ticket for this server starts: mechTypes only. impacket's SMB2 client
// offers Kerberos alone in that state.
QByteArray spnegoMechOffer()
{
    const QByteArray krb5 = QByteArray::fromHex("06092a864886f712010202");
    QByteArray mechList(1, char(0x30));
    mechList.append(char(krb5.size()));
    mechList.append(krb5);
    QByteArray mechTypes(1, char(0xa0));
    mechTypes.append(char(mechList.size()));
    mechTypes.append(mechList);
    QByteArray init(1, char(0x30));
    init.append(char(mechTypes.size()));
    init.append(mechTypes);
    QByteArray token(1, char(0x60));
    token.append(char(init.size() + 10));
    token.append(QByteArray::fromHex("06062b0601050502")); // SPNEGO OID
    token.append(char(0xa0));
    token.append(char(init.size()));
    token.append(init);
    return token;
}

// An AUTHENTICATE the server's parser accepts. The authenticator this test
// installs accepts any response, so the token only has to be well formed.
QByteArray ntlmAuthenticate(const QString &domain, const QString &user,
                            const QByteArray &response)
{
    const QByteArray d = utf16(domain);
    const QByteArray u = utf16(user);
    QByteArray token("NTLMSSP", 7);
    token.append(char(0));
    putLe32(token, 3); // AUTHENTICATE_MESSAGE
    int offset = 64;
    const auto field = [&offset](const QByteArray &data) {
        QByteArray f;
        putLe16(f, quint16(data.size()));
        putLe16(f, quint16(data.size()));
        putLe32(f, quint32(offset));
        offset += data.size();
        return f;
    };
    token.append(field(QByteArray())); // LmChallengeResponse
    token.append(field(response));     // NtChallengeResponse
    token.append(field(d));
    token.append(field(u));
    token.append(field(QByteArray())); // Workstation
    token.append(field(QByteArray())); // EncryptedRandomSessionKey
    putLe32(token, 0x00000201);
    token.append(response);
    token.append(d);
    token.append(u);
    return token;
}

QByteArray sessionSetup(quint64 messageId, const QByteArray &token)
{
    QByteArray body;
    putLe16(body, 9);   // StructureSize
    putLe16(body, 0);   // Flags
    putLe32(body, 0);   // SecurityMode, Capabilities
    putLe32(body, 0);   // Channel
    putLe16(body, 64 + 24); // SecurityBufferOffset
    putLe16(body, quint16(token.size()));
    putLe64(body, 0);   // PreviousSessionId
    body.append(token);
    return header(Smb2::CmdSessionSetup, messageId, 0, 0) + body;
}

QByteArray treeConnectTo(quint64 messageId, quint64 sessionId, const QString &share)
{
    const QByteArray path = utf16(QStringLiteral("\\\\127.0.0.1\\") + share);
    QByteArray body;
    putLe16(body, 9);          // StructureSize
    putLe16(body, 0);          // Reserved
    putLe16(body, 64 + 8);     // PathOffset
    putLe16(body, quint16(path.size()));
    body.append(path);
    return header(Smb2::CmdTreeConnect, messageId, sessionId, 0) + body;
}

QByteArray createRequest(quint64 messageId, quint64 sessionId, quint32 treeId,
                         const QString &name, quint32 options, quint32 access,
                         quint32 disposition = 1 /* FILE_OPEN */)
{
    const QByteArray encoded = utf16(name);
    QByteArray body;
    putLe16(body, 57);      // StructureSize
    body.append(char(0));   // SecurityFlags
    body.append(char(0));   // RequestedOplockLevel
    putLe32(body, 2);       // ImpersonationLevel: impersonation
    putLe64(body, 0);       // SmbCreateFlags
    putLe64(body, 0);       // Reserved
    putLe32(body, access);  // DesiredAccess
    putLe32(body, 0);       // FileAttributes
    putLe32(body, 7);       // ShareAccess
    putLe32(body, disposition); // CreateDisposition
    putLe32(body, options); // CreateOptions
    putLe16(body, quint16(name.isEmpty() ? 0 : 64 + 56)); // NameOffset
    putLe16(body, quint16(encoded.size()));
    putLe32(body, 0);       // CreateContextsOffset
    putLe32(body, 0);       // CreateContextsLength
    body.append(encoded);
    return header(Smb2::CmdCreate, messageId, sessionId, treeId) + body;
}

QByteArray readRequest(quint64 messageId, quint64 sessionId, quint32 treeId, quint64 id,
                       quint64 offset, quint32 length)
{
    QByteArray body;
    putLe16(body, 49); // StructureSize
    body.append(char(0)); // Padding
    body.append(char(0)); // Flags
    putLe32(body, length);
    putLe64(body, offset);
    putLe64(body, id);
    putLe64(body, id);
    putLe32(body, 0);  // MinimumCount
    putLe32(body, 0);  // Channel
    putLe32(body, 0);  // RemainingBytes
    putLe16(body, 0);  // ReadChannelInfoOffset
    putLe16(body, 0);  // ReadChannelInfoLength
    return header(Smb2::CmdRead, messageId, sessionId, treeId) + body;
}

QByteArray queryDirectoryRequest(quint64 messageId, quint64 sessionId, quint32 treeId,
                                 quint64 id, const QString &pattern, quint8 infoClass)
{
    const QByteArray encoded = utf16(pattern);
    QByteArray body;
    putLe16(body, 33); // StructureSize
    body.append(char(infoClass));
    body.append(char(0)); // Flags: no restart
    putLe32(body, 0);     // FileIndex
    putLe64(body, id);
    putLe64(body, id);
    putLe16(body, quint16(pattern.isEmpty() ? 0 : 64 + 32)); // FileNameOffset
    putLe16(body, quint16(encoded.size()));
    putLe32(body, 65536); // OutputBufferLength
    body.append(encoded);
    return header(Smb2::CmdQueryDirectory, messageId, sessionId, treeId) + body;
}

QByteArray setInfoRequest(quint64 messageId, quint64 sessionId, quint32 treeId, quint64 id)
{
    QByteArray body;
    putLe16(body, 33); // StructureSize
    body.append(char(1)); // InfoType: file
    body.append(char(0x0d)); // FileDispositionInformation
    putLe32(body, 1);  // BufferLength
    putLe16(body, 64 + 32); // BufferOffset
    putLe16(body, 0);  // Reserved
    putLe32(body, 0);  // AdditionalInformation
    putLe64(body, id);
    putLe64(body, id);
    body.append(char(1)); // DeleteFile
    return header(Smb2::CmdSetInfo, messageId, sessionId, treeId) + body;
}

// A set-info carrying one file info class and its buffer, as a client sends it.
QByteArray setInfoBuffer(quint64 messageId, quint64 sessionId, quint32 treeId, quint64 id,
                         quint8 infoClass, const QByteArray &buffer)
{
    QByteArray body;
    putLe16(body, 33); // StructureSize
    body.append(char(1)); // InfoType: SMB2_0_INFO_FILE
    body.append(char(infoClass));
    putLe32(body, quint32(buffer.size()));
    putLe16(body, quint16(buffer.isEmpty() ? 0 : 64 + 32)); // BufferOffset
    putLe16(body, 0);  // Reserved
    putLe32(body, 0);  // AdditionalInformation
    putLe64(body, id);
    putLe64(body, id);
    body.append(buffer);
    return header(Smb2::CmdSetInfo, messageId, sessionId, treeId) + body;
}

QByteArray writeRequest(quint64 messageId, quint64 sessionId, quint32 treeId, quint64 id,
                        quint64 offset, const QByteArray &data)
{
    QByteArray body;
    putLe16(body, 49);
    putLe16(body, 64 + 48); // DataOffset
    putLe32(body, quint32(data.size()));
    putLe64(body, offset);
    putLe64(body, id);   // FileId
    putLe64(body, id);
    putLe32(body, 0);    // Channel
    putLe32(body, 0);    // RemainingBytes
    putLe16(body, 0);    // WriteChannelInfoOffset
    putLe16(body, 0);    // WriteChannelInfoLength
    putLe32(body, 0);    // Flags
    body.append(data);
    return header(Smb2::CmdWrite, messageId, sessionId, treeId) + body;
}

QByteArray closeRequest(quint64 messageId, quint64 sessionId, quint32 treeId, quint64 id)
{
    QByteArray body;
    putLe16(body, 24); // StructureSize
    putLe16(body, 0);  // Flags
    putLe32(body, 0);  // Reserved
    putLe64(body, id);
    putLe64(body, id);
    return header(Smb2::CmdClose, messageId, sessionId, treeId) + body;
}

} // namespace

class Smb2Test : public QObject
{
    Q_OBJECT

private slots:
    void negotiatesTheHighestOfferedDialect();
    void opensATreeAndAPipe();
    void refusesAnUnknownPipeAndUnknownShare();
    void carriesADceBindThroughThePipe();
    void servesADiskShareReadOnly();
    void writesADiskShareForAnAdministratorOnly();
    void signsWithAesCmacAsTheStandardDoes();
    void answersSmb311WithThePreauthContext();
    void sealsWithAesCcmAsTheStandardDoes();
    void sealsAThreeOneOneSession();
    void acceptsASessionOverTheNetbiosSessionService();
    void selectsNtlmsspWhenTheOfferCarriesNoToken();
};

// A client that lists Kerberos and sends nothing yet has not failed to
// authenticate: it is asking the server to pick a mechanism. Answering with a
// reject ended that client's logon before it sent the NTLMSSP message it was
// perfectly able to send, so the answer is accept-incomplete naming NTLMSSP and
// the exchange carries on from there.
void Smb2Test::selectsNtlmsspWhenTheOfferCarriesNoToken()
{
    Smb2Server server;
    server.setAuthenticator([](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
        keys->sessionBaseKey = QByteArray(16, 'k');
        return true;
    });

    QByteArray reply = server.feed(nbt(sessionSetup(1, spnegoMechOffer())));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusMoreProcessingRequired));
    const QByteArray answer = bodyOf(reply);
    const QByteArray token = answer.mid(8, readLe16(answer, 6));
    QCOMPARE(token, Gss::spnegoResponse(1, QStringLiteral("1.3.6.1.4.1.311.2.2.10"),
                                       QByteArray()));

    // The client takes the hint and the logon finishes in the usual two rounds.
    reply = server.feed(nbt(sessionSetup(2, ntlmNegotiate())));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusMoreProcessingRequired));
    reply = server.feed(nbt(sessionSetup(3, ntlmAuthenticate(
        QStringLiteral("CYBERDYNE"), QStringLiteral("alice"),
        QByteArray(16, 'r') + QByteArray(40, 'b')))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
}

// Windows 2000 does not use TCP 445: it opens a NetBIOS session to the server
// name on 139, and only then speaks SMB1 on that socket. The session request has
// to be acknowledged before anything else, or the client resets the connection
// and reports only that it could not log on.
void Smb2Test::acceptsASessionOverTheNetbiosSessionService()
{
    Smb2Server server;

    QByteArray request(1, char(0x81)); // SESSION REQUEST
    QByteArray body;
    body.append(char(0));                 // session request
    body.append(QByteArray(32, ' '));     // called name, space padded
    body.append(QByteArray(32, ' '));     // calling name
    request.append(char((body.size() >> 16) & 0xff));
    request.append(char((body.size() >> 8) & 0xff));
    request.append(char(body.size() & 0xff));
    request.append(body);

    const QByteArray reply = server.feed(request + nbt(smb1Negotiate()));

    QVERIFY(reply.size() > 4);
    QCOMPARE(reply.left(4), QByteArray("\202\000\000\000", 4)); // POSITIVE SESSION RESPONSE
    // What follows is the SMB1 negotiate answer, in its own NBSS frame.
    QCOMPARE(quint8(reply.at(4)), quint8(0));
    QCOMPARE(reply.mid(8, 4), QByteArray("\377SMB", 4));
    QCOMPARE(quint8(reply.at(12)), quint8(0x72)); // SMB_COM_NEGOTIATE
}

void Smb2Test::negotiatesTheHighestOfferedDialect()
{
    Smb2Server server;
    QByteArray request = header(Smb2::CmdNegotiate, 0, 0, 0);
    QByteArray body;
    putLe16(body, 36); // StructureSize
    putLe16(body, 2);  // DialectCount
    putLe16(body, 1);  // SecurityMode: signing enabled
    putLe16(body, 0);  // Reserved
    putLe32(body, 0);  // Capabilities
    body.append(QByteArray(16, '\0')); // ClientGuid
    putLe64(body, 0);  // ClientStartTime
    putLe16(body, Smb2::Dialect202);
    putLe16(body, Smb2::Dialect210);
    request.append(body);

    const QByteArray reply = server.feed(nbt(request));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QCOMPARE(readLe16(reply, 4 + 64 + 4), quint16(Smb2::Dialect210));
    QCOMPARE(readLe16(bodyOf(reply), 0), quint16(65)); // StructureSize
}

void Smb2Test::opensATreeAndAPipe()
{
    Smb2Server server;
    EpmServer endpoint;
    server.addPipe(QStringLiteral("epmapper"), endpoint.rpc());

    // Tree connect to \\server\IPC$.
    const QByteArray path = utf16(QStringLiteral("\\\\127.0.0.1\\IPC$"));
    QByteArray request = header(Smb2::CmdTreeConnect, 1, 0x00010001, 0);
    putLe16(request, 64 + 0); // StructureSize placeholder
    request.replace(64, 2, QByteArray::fromHex("0900"));
    putLe16(request, 64 + 2);
    request.replace(64 + 2, 0, QByteArray());
    putLe16(request, 64 + 4);
    request.replace(64 + 4, 0, QByteArray());
    putLe16(request, 64 + 6);
    request.replace(64 + 6, 0, QByteArray());
    // PathOffset/PathLength are measured from the SMB2 header start.
    QByteArray fixedPart = request.left(64);
    QByteArray tcon;
    putLe16(tcon, 9);  // StructureSize
    putLe16(tcon, 0);  // Flags
    putLe16(tcon, 64 + 8); // PathOffset
    putLe16(tcon, quint16(path.size()));
    tcon.append(path);
    request = fixedPart + tcon;

    QByteArray reply = server.feed(nbt(request));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));

    // Create on \epmapper in that tree.
    const QByteArray name = utf16(QStringLiteral("epmapper"));
    QByteArray createHeader = header(Smb2::CmdCreate, 2, 0x00010001, 1);
    QByteArray createBody;
    putLe16(createBody, 57); // StructureSize
    createBody.append(char(0)); // SecurityFlags
    createBody.append(char(0)); // RequestedOplockLevel
    putLe32(createBody, 2);     // ImpersonationLevel
    putLe64(createBody, 0);     // SmbCreateFlags
    putLe64(createBody, 0);     // Reserved
    putLe32(createBody, 0x0012019f); // DesiredAccess
    putLe32(createBody, 0);          // FileAttributes
    putLe32(createBody, 7);          // ShareAccess
    putLe32(createBody, 1);          // CreateDisposition: FILE_OPEN
    putLe32(createBody, 0x40);       // CreateOptions
    putLe16(createBody, 64 + 56);    // NameOffset
    putLe16(createBody, quint16(name.size()));
    putLe32(createBody, 0);          // CreateContextsOffset
    putLe32(createBody, 0);          // CreateContextsLength
    createBody.append(name);

    reply = server.feed(nbt(createHeader + createBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QByteArray body = bodyOf(reply);
    QCOMPARE(readLe16(body, 0), quint16(89));
    QVERIFY(readLe64(body, 64) != 0); // FileId.Persistent

    // Close it again.
    QByteArray closeBody;
    putLe16(closeBody, 24);
    putLe16(closeBody, 0);
    putLe32(closeBody, 0);
    putLe64(closeBody, readLe64(body, 64));
    putLe64(closeBody, readLe64(body, 72));
    reply = server.feed(nbt(header(Smb2::CmdClose, 3, 0x00010001, 1) + closeBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
}

void Smb2Test::refusesAnUnknownPipeAndUnknownShare()
{
    Smb2Server server;
    EpmServer endpoint;
    server.addPipe(QStringLiteral("epmapper"), endpoint.rpc());

    QByteArray reply = server.feed(nbt(header(Smb2::CmdCreate, 1, 1, 1)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusObjectNameNotFound));

    // A share other than IPC$ is not something this server exposes.
    const QByteArray path = utf16(QStringLiteral("\\\\127.0.0.1\\DATA"));
    QByteArray tcon;
    putLe16(tcon, 9);
    putLe16(tcon, 0);
    putLe16(tcon, 64 + 8);
    putLe16(tcon, quint16(path.size()));
    tcon.append(path);
    reply = server.feed(nbt(header(Smb2::CmdTreeConnect, 2, 1, 0) + tcon));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusBadNetworkName));
}

// The whole point of the pipe: a DCE/RPC bind goes in as a write and the
// bind_ack comes back out of a read, through the endpoint's own bind path.
void Smb2Test::carriesADceBindThroughThePipe()
{
    Smb2Server server;
    EpmServer endpoint;
    const QList<Epm::Entry> entries;
    endpoint.setEntries(entries);
    server.addPipe(QStringLiteral("epmapper"), endpoint.rpc());
    server.addPipe(QStringLiteral("samr"), endpoint.rpc());

    const QByteArray path = utf16(QStringLiteral("\\\\127.0.0.1\\IPC$"));
    QByteArray tcon;
    putLe16(tcon, 9);
    putLe16(tcon, 0);
    putLe16(tcon, 64 + 8);
    putLe16(tcon, quint16(path.size()));
    tcon.append(path);
    QByteArray reply = server.feed(nbt(header(Smb2::CmdTreeConnect, 1, 1, 0) + tcon));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));

    const QByteArray name = utf16(QStringLiteral("epmapper"));
    QByteArray createBody;
    putLe16(createBody, 57);
    createBody.append(char(0));
    createBody.append(char(0));
    putLe32(createBody, 2);
    putLe64(createBody, 0);
    putLe64(createBody, 0);
    putLe32(createBody, 0x0012019f);
    putLe32(createBody, 0);
    putLe32(createBody, 7);
    putLe32(createBody, 1);
    putLe32(createBody, 0x40);
    putLe16(createBody, 64 + 56);
    putLe16(createBody, quint16(name.size()));
    putLe32(createBody, 0);
    putLe32(createBody, 0);
    createBody.append(name);
    reply = server.feed(nbt(header(Smb2::CmdCreate, 2, 1, 1) + createBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const QByteArray created = bodyOf(reply);
    const quint64 handle = readLe64(created, 64);

    // A DCE/RPC bind for the endpoint mapper itself (v3.0, NDR32). The header
    // is DCE 1.1 12.6.3.1: version, type, flags, data representation, the two
    // fragment lengths, the call id, then the presentation context list.
    QByteArray bind;
    bind.append(char(5));    // rpc_vers
    bind.append(char(0));    // rpc_vers_minor
    bind.append(char(11));   // ptype: bind
    bind.append(char(0x03)); // first and last fragment
    bind.append(char(0x10)); // data representation: little endian
    bind.append(char(0));
    bind.append(char(0));
    bind.append(char(0));
    // drep is four bytes, so frag_length sits at 8 and the call id at 12.
    putLe16(bind, 0);        // frag_length, patched below
    putLe16(bind, 0);        // auth_length
    putLe32(bind, 1);        // call id
    putLe16(bind, 4280);     // max_xmit_frag
    putLe16(bind, 4280);     // max_recv_frag
    putLe32(bind, 0);        // assoc_group_id
    bind.append(char(1));    // num_contexts
    bind.append(QByteArray(3, '\0'));
    putLe16(bind, 0);        // context id
    putLe16(bind, 1);        // transfer syntax count
    bind.append(Epm::interface().uuid);
    putLe16(bind, Epm::interface().major);
    putLe16(bind, Epm::interface().minor);
    bind.append(QByteArray::fromHex("04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60"));
    putLe16(bind, 2);
    putLe16(bind, 0);
    bind[8] = char(bind.size() & 0xff);
    bind[9] = char((bind.size() >> 8) & 0xff);

    QByteArray writeBody;
    putLe16(writeBody, 49);
    putLe16(writeBody, 64 + 48); // DataOffset
    putLe32(writeBody, quint32(bind.size()));
    putLe64(writeBody, 0);
    putLe64(writeBody, handle);
    putLe64(writeBody, handle);
    putLe32(writeBody, 0);
    putLe32(writeBody, 0);
    putLe16(writeBody, 0);
    putLe16(writeBody, 0);
    putLe32(writeBody, 0);
    writeBody.append(bind);
    reply = server.feed(nbt(header(Smb2::CmdWrite, 3, 1, 1) + writeBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QCOMPARE(readLe32(bodyOf(reply), 4), quint32(bind.size())); // Count

    // Read the bind_ack back out of the same pipe.
    QByteArray readBody;
    putLe16(readBody, 49);
    readBody.append(char(0));
    readBody.append(char(0));
    putLe32(readBody, 4096);
    putLe64(readBody, 0);
    putLe64(readBody, handle);
    putLe64(readBody, handle);
    putLe32(readBody, 0);
    putLe32(readBody, 0);
    putLe32(readBody, 0);
    putLe16(readBody, 0);
    putLe16(readBody, 0);
    reply = server.feed(nbt(header(Smb2::CmdRead, 4, 1, 1) + readBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const QByteArray read = bodyOf(reply);
    const quint32 dataLength = readLe32(read, 4);
    QVERIFY(dataLength >= 16);
    const QByteArray pdu = read.mid(16, int(dataLength));
    QCOMPARE(quint8(pdu.at(2)), quint8(12)); // bind_ack
}

// A disk share is what a member reads its GPOs through: tree connect, open,
// positional read, a directory listing in the class the redirector asked for,
// and a refusal for every write.
void Smb2Test::servesADiskShareReadOnly()
{
    QTemporaryDir root;
    QVERIFY(root.isValid());
    const QString sysvol = root.filePath(QStringLiteral("sysvol/CYBERDYNE.LAN"));
    const QString guid = QStringLiteral("{31B2F340-016D-11D2-945F-00C04FB984F9}");
    QVERIFY(QDir().mkpath(sysvol + QStringLiteral("/Policies/") + guid
                          + QStringLiteral("/Machine")));
    QFile policy(sysvol + QStringLiteral("/Policies/") + guid
                 + QStringLiteral("/Machine/registry.pol"));
    QVERIFY(policy.open(QIODevice::WriteOnly));
    const QByteArray content("PReg\x01\x00\x00\x00contents", 16);
    policy.write(content);
    policy.close();

    Smb2Server server;
    // The share root is the directory holding the domain folder, so the GPO
    // path from LDAP (\\dc\SYSVOL\<domain>\Policies\...) resolves as written.
    server.addShare(QStringLiteral("SYSVOL"), root.filePath(QStringLiteral("sysvol")));
    // Any principal the directory authenticated; the token itself is proved by
    // the Netlogon and SAMR suites, this one is about what a session may read.
    server.setAuthenticator([](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
        keys->sessionBaseKey = QByteArray(16, 'k');
        return true;
    });

    // No session, no share: the answer an anonymous client gets.
    QByteArray reply = server.feed(nbt(treeConnectTo(1, 0, QStringLiteral("SYSVOL"))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusBadNetworkName));

    server.feed(nbt(sessionSetup(2, ntlmNegotiate())));
    reply = server.feed(nbt(sessionSetup(3, ntlmAuthenticate(
        QStringLiteral("CYBERDYNE"), QStringLiteral("alice"),
        QByteArray(16, 'r') + QByteArray(40, 'b')))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const quint64 sessionId = readLe64(reply, 4 + 40);
    QVERIFY(sessionId != 0);

    reply = server.feed(nbt(treeConnectTo(4, sessionId, QStringLiteral("SYSVOL"))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const QByteArray tconBody = bodyOf(reply);
    QCOMPARE(quint8(tconBody.at(2)), quint8(1)); // ShareType: disk
    QCOMPARE(readLe32(tconBody, 4) & 1u, 1u);    // ShareFlags: read-only
    const quint32 treeId = readLe32(reply, 4 + 36);

    const QString relative = QStringLiteral("CYBERDYNE.LAN/Policies/") + guid
                             + QStringLiteral("/Machine/registry.pol");
    reply = server.feed(nbt(createRequest(5, sessionId, treeId, relative, 0x40, 0x00120089u)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QByteArray body = bodyOf(reply);
    QCOMPARE(readLe16(body, 0), quint16(89));
    QCOMPARE(quint64(readLe64(body, 48)), quint64(content.size())); // EndOfFile
    const quint64 fileId = readLe64(body, 64);

    reply = server.feed(nbt(readRequest(6, sessionId, treeId, fileId, 0, 64)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    body = bodyOf(reply);
    QCOMPARE(quint32(readLe32(body, 4)), quint32(content.size()));
    QCOMPARE(body.mid(16, content.size()), content);

    // A write and a delete-on-close are both refused.
    QByteArray writeBody;
    putLe16(writeBody, 17);
    putLe16(writeBody, 64 + 16); // DataOffset
    putLe32(writeBody, 4);       // Length
    putLe64(writeBody, fileId);
    putLe64(writeBody, fileId);
    putLe16(writeBody, 0);
    putLe16(writeBody, 0);
    writeBody.append(QByteArray(4, 'x'));
    reply = server.feed(nbt(header(Smb2::CmdWrite, 7, sessionId, treeId) + writeBody));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusAccessDenied));
    reply = server.feed(nbt(setInfoRequest(8, sessionId, treeId, fileId)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusAccessDenied));

    // The Policies directory lists the policy GUID.
    reply = server.feed(nbt(createRequest(9, sessionId, treeId,
                                          QStringLiteral("CYBERDYNE.LAN/Policies"),
                                          0x01, 0x00100001u)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const quint64 directoryId = readLe64(bodyOf(reply), 64);
    QCOMPARE(quint8(bodyOf(reply).at(56)) & 0x10, 0x10); // FILE_ATTRIBUTE_DIRECTORY

    reply = server.feed(nbt(queryDirectoryRequest(10, sessionId, treeId, directoryId,
                                                  QStringLiteral("*"), 0x25)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    body = bodyOf(reply);
    const quint32 length = readLe32(body, 4);
    const QByteArray listing = body.mid(8, length);
    // Walk the chain the way a redirector does, collecting names.
    QStringList names;
    int at = 0;
    const auto decode = [&listing](int offset, int length) {
        QString text;
        for (int i = 0; i + 1 < length; i += 2)
            text.append(QChar(quint16(quint8(listing.at(offset + i))
                                      | (quint16(quint8(listing.at(offset + i + 1))) << 8))));
        return text;
    };
    while (at + 104 <= listing.size()) {
        const quint32 next = readLe32(listing, at);
        const quint32 nameLength = readLe32(listing, at + 60);
        names.append(decode(at + 104, int(nameLength)));
        if (next == 0)
            break;
        at += int(next);
    }
    QVERIFY(names.contains(QStringLiteral(".")));
    QVERIFY(names.contains(guid));

    // A second query drains nothing more.
    reply = server.feed(nbt(queryDirectoryRequest(11, sessionId, treeId, directoryId,
                                                  QStringLiteral("*"), 0x25)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusNoMoreFiles));
}

// A writable disk share is how a GPO is edited and a logon script dropped: the
// account that administers the domain creates, writes, truncates, renames and
// deletes; a member who is not an administrator meets the share's read-only
// flag and the refusals behind it.
void Smb2Test::writesADiskShareForAnAdministratorOnly()
{
    QTemporaryDir root;
    QVERIFY(root.isValid());
    const QString sysvol = root.filePath(QStringLiteral("sysvol"));
    QVERIFY(QDir().mkpath(sysvol + QStringLiteral("/Policies")));

    Smb2Server server;
    server.addShare(QStringLiteral("SYSVOL"), sysvol, false);
    server.setAuthenticator([](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
        keys->sessionBaseKey = QByteArray(16, 'k');
        return true;
    });
    server.setWritePolicy([](const QString &principal) {
        return principal.endsWith(QStringLiteral("\\Administrator"), Qt::CaseInsensitive);
    });

    server.feed(nbt(sessionSetup(1, ntlmNegotiate())));
    QByteArray reply = server.feed(nbt(sessionSetup(2, ntlmAuthenticate(
        QStringLiteral("CYBERDYNE"), QStringLiteral("Administrator"),
        QByteArray(16, 'r') + QByteArray(40, 'b')))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const quint64 sessionId = readLe64(reply, 4 + 40);

    reply = server.feed(nbt(treeConnectTo(3, sessionId, QStringLiteral("SYSVOL"))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QCOMPARE(readLe32(bodyOf(reply), 4) & 1u, 0u); // ShareFlags: writable
    const quint32 treeId = readLe32(reply, 4 + 36);

    // FILE_CREATE of a name that is not there yet, for data write access.
    const QString name = QStringLiteral("Policies/logon.bat");
    reply = server.feed(nbt(createRequest(4, sessionId, treeId, name, 0x40, 0x00120116u, 2)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QByteArray body = bodyOf(reply);
    QCOMPARE(readLe32(body, 4), quint32(2)); // CreateAction: FILE_CREATED
    const quint64 fileId = readLe64(body, 64);

    const QByteArray script("@echo off\r\nnet use h: \\\\dc\\home\r\n");
    reply = server.feed(nbt(writeRequest(5, sessionId, treeId, fileId, 0, script)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QCOMPARE(readLe32(bodyOf(reply), 4), quint32(script.size()));

    // A positional rewrite lands where the offset names.
    reply = server.feed(nbt(writeRequest(6, sessionId, treeId, fileId, 0, QByteArray("@rem "))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));

    // FileEndOfFileInformation shortens it, and the closing handle sees that:
    // the rewritten prefix plus the original byte at offset 5, nothing more.
    QByteArray endOfFile;
    putLe64(endOfFile, 6);
    reply = server.feed(nbt(setInfoBuffer(7, sessionId, treeId, fileId, 0x14, endOfFile)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    reply = server.feed(nbt(closeRequest(8, sessionId, treeId, fileId)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));

    QFile written(sysvol + QLatin1Char('/') + name);
    QVERIFY(written.open(QIODevice::ReadOnly));
    QCOMPARE(written.readAll(), QByteArray("@rem  "));
    written.close();

    // A rename, then the delete-on-close a client sends for a file it removes.
    const QString renamed = QStringLiteral("Policies/startup.bat");
    QByteArray rename;
    putLe64(rename, 0);                     // ReplaceIfExists
    putLe64(rename, 0);                     // RootDirectory
    putLe32(rename, quint32(renamed.size() * 2));
    rename.append(utf16(renamed));
    reply = server.feed(nbt(createRequest(9, sessionId, treeId, name, 0x40, 0x00120116u)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const quint64 renameId = readLe64(bodyOf(reply), 64);
    reply = server.feed(nbt(setInfoBuffer(10, sessionId, treeId, renameId, 0x0a, rename)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    reply = server.feed(nbt(setInfoBuffer(11, sessionId, treeId, renameId, 0x0d, QByteArray(1, '\1'))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    reply = server.feed(nbt(closeRequest(12, sessionId, treeId, renameId)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QVERIFY(!QFileInfo::exists(sysvol + QStringLiteral("/Policies/logon.bat")));
    QVERIFY(!QFileInfo::exists(sysvol + QStringLiteral("/Policies/startup.bat")));

    // A member who does not administer the domain sees a read-only share and is
    // refused the same creation, which is what the ACL on a Windows DC does.
    server.feed(nbt(sessionSetup(13, ntlmNegotiate())));
    reply = server.feed(nbt(sessionSetup(14, ntlmAuthenticate(
        QStringLiteral("CYBERDYNE"), QStringLiteral("alice"),
        QByteArray(16, 'r') + QByteArray(40, 'c')))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const quint64 memberSession = readLe64(reply, 4 + 40);
    reply = server.feed(nbt(treeConnectTo(15, memberSession, QStringLiteral("SYSVOL"))));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    QCOMPARE(readLe32(bodyOf(reply), 4) & 1u, 1u); // ShareFlags: read-only
    const quint32 memberTree = readLe32(reply, 4 + 36);
    reply = server.feed(nbt(createRequest(16, memberSession, memberTree,
                                          QStringLiteral("Policies/member.bat"), 0x40,
                                          0x00120116u, 2)));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusAccessDenied));
    QVERIFY(!QFileInfo::exists(sysvol + QStringLiteral("/Policies/member.bat")));
}

// RFC 4493 §4: the AES-128 CMAC of four messages under one key. A 3.x session
// is only as good as this, since every message it sends is signed with it.
void Smb2Test::signsWithAesCmacAsTheStandardDoes()
{
    const QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QCOMPARE(Smb3::cmac(key, QByteArray()).toHex(),
             QByteArray("bb1d6929e95937287fa37d129b756746"));
    QCOMPARE(Smb3::cmac(key, QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a")).toHex(),
             QByteArray("070a16b46b4d4144f79bdd9dd04a287c"));
    QCOMPARE(Smb3::cmac(key, QByteArray::fromHex(
                 "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                 "30c81c46a35ce411")).toHex(),
             QByteArray("dfa66747de9ae63030ca32611497c827"));
    QCOMPARE(Smb3::cmac(key, QByteArray::fromHex(
                 "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                 "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"))
                 .toHex(),
             QByteArray("51f0bebf7e3b9d92fc49741779363cfe"));
    // The 3.0.2 signing key is the session key expanded through the KDF whose
    // context is the constant "SmbSign"; 2.x has no such step.
    QCOMPARE(Smb3::signingKey(QByteArray(16, 'k'), Smb2::Dialect210, QByteArray()),
             QByteArray(16, 'k'));
    QCOMPARE(Smb3::signingKey(QByteArray(16, 'k'), Smb2::Dialect302, QByteArray()).size(), 16);
}

// A 3.1.1 negotiate answer is read by two clients that disagree about almost
// everything, so its shape is pinned here: the dialect, the two contexts, and
// the preauth one laid out as ContextType, DataLength, four reserved bytes, then
// the hash count, the salt length, the algorithm and the salt — in that order,
// which is what both Samba's client and smbprotocol parse.
void Smb2Test::answersSmb311WithThePreauthContext()
{
    Smb2Server server;
    QByteArray request = header(Smb2::CmdNegotiate, 0, 0, 0);
    QByteArray body;
    putLe16(body, 36); // StructureSize
    putLe16(body, 4);  // DialectCount
    putLe16(body, 1);  // SecurityMode
    putLe16(body, 0);  // Reserved
    putLe32(body, 0);  // Capabilities
    body.append(QByteArray(16, '\0')); // ClientGuid
    putLe64(body, 0);  // ClientStartTime
    putLe16(body, Smb2::Dialect202);
    putLe16(body, Smb2::Dialect210);
    putLe16(body, Smb2::Dialect302);
    putLe16(body, Smb2::Dialect311);
    request.append(body);

    const QByteArray reply = server.feed(nbt(request));
    QCOMPARE(statusOf(reply), quint32(Smb2::StatusSuccess));
    const QByteArray answer = bodyOf(reply);
    QCOMPARE(readLe16(answer, 0), quint16(65));                  // StructureSize
    QCOMPARE(readLe16(answer, 2), quint16(1));                   // signing enabled
    QCOMPARE(readLe16(answer, 4), quint16(Smb2::Dialect311));    // dialect
    QCOMPARE(readLe16(answer, 6), quint16(3));                   // preauth, signing, cipher
    QCOMPARE(readLe32(answer, 60), quint32(Smb2::kHeaderSize + 64)); // context offset
    // body, preauth, pad to the next 8-byte boundary, signing, then the cipher
    // context with its four bytes of padding.
    QCOMPARE(answer.size(), 64 + 46 + 2 + 12 + 4 + 16);
    QCOMPARE(readLe16(answer, 64), quint16(0x0001));             // PREAUTH_INTEGRITY
    QCOMPARE(readLe16(answer, 66), quint16(38));                 // DataLength
    QCOMPARE(readLe16(answer, 72), quint16(1));                  // HashAlgorithmCount
    QCOMPARE(readLe16(answer, 74), quint16(32));                 // SaltLength
    QCOMPARE(readLe16(answer, 76), quint16(1));                  // SHA-512
    QCOMPARE(readLe16(answer, 112), quint16(0x0008));            // SIGNING_CAPABILITIES
    QCOMPARE(readLe16(answer, 114), quint16(4));                 // DataLength
    QCOMPARE(readLe16(answer, 120), quint16(1));                 // one algorithm
    QCOMPARE(readLe16(answer, 122), quint16(0x0001));            // AES-CMAC
    // ENCRYPTION_CAPABILITIES: without it a 3.1.1 client decides the server
    // cannot encrypt and refuses to turn encryption on, whatever the capability
    // bits say.
    QCOMPARE(readLe16(answer, 128), quint16(0x0002));            // ENCRYPTION_CAPABILITIES
    QCOMPARE(readLe16(answer, 130), quint16(4));                 // DataLength
    QCOMPARE(readLe16(answer, 136), quint16(1));                 // one cipher
    QCOMPARE(readLe16(answer, 138), quint16(0x0001));            // AES-128-CCM
    // 3.0.x has no context to say it in, so it rides the capability bits.
    QByteArray older = header(Smb2::CmdNegotiate, 0, 0, 0);
    QByteArray olderBody;
    putLe16(olderBody, 36);
    putLe16(olderBody, 1);
    putLe16(olderBody, 1);
    putLe16(olderBody, 0);
    putLe32(olderBody, 0);
    olderBody.append(QByteArray(16, '\0'));
    putLe64(olderBody, 0);
    putLe16(olderBody, Smb2::Dialect302);
    older.append(olderBody);
    const QByteArray olderAnswer = bodyOf(server.feed(nbt(older)));
    QCOMPARE(readLe16(olderAnswer, 4), quint16(Smb2::Dialect302));
    QCOMPARE(readLe16(olderAnswer, 6), quint16(0));              // no contexts
    QCOMPARE(readLe32(olderAnswer, 24) & 0x40u, quint32(0x40));   // CAP_ENCRYPTION
}

// RFC 3610 packet vector #1 — an 8-byte tag over eight bytes of associated data
// and twenty-three bytes of message — is the published CCM vector that exercises
// both the AAD encoding and a tag shorter than the block. The rest pins what SMB
// actually uses: a 12-byte nonce, the 52-byte transform header as the associated
// data and the whole 16-byte tag, and a tag that does not verify opening nothing
// at all.
void Smb2Test::sealsWithAesCcmAsTheStandardDoes()
{
    const QByteArray key = QByteArray::fromHex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    const QByteArray nonce = QByteArray::fromHex("00000003020100a0a1a2a3a4a5");
    const QByteArray aad = QByteArray::fromHex("0001020304050607");
    const QByteArray plain =
        QByteArray::fromHex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    const QByteArray sealed = QByteArray::fromHex(
        "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
    QCOMPARE(Smb3::ccmEncrypt(key, nonce, aad, plain, 8), sealed);
    QCOMPARE(Smb3::ccmDecrypt(key, nonce, aad, sealed, 8), plain);

    QByteArray transform(52, '\0');
    transform[0] = char(0xfd);
    transform.replace(1, 3, QByteArray("SMB", 3));
    const QByteArray message = transform + QByteArray(60, 'm');
    QByteArray small;
    for (int i = 0; i < 12; ++i)
        small.append(char(i + 1));
    const QByteArray boxed = Smb3::ccmEncrypt(key, small, transform, message);
    QCOMPARE(boxed.size(), message.size() + 16);
    QCOMPARE(Smb3::ccmDecrypt(key, small, transform, boxed), message);
    QByteArray tampered = boxed;
    tampered[tampered.size() - 1] = char(quint8(tampered.at(tampered.size() - 1)) ^ 0x01);
    QVERIFY(Smb3::ccmDecrypt(key, small, transform, tampered).isEmpty());
}

// A 3.1.1 session that turns encryption on: the client derives the same cipher
// key the server did from the preauth chain, seals an echo in a transform header
// and must get a sealed, signed answer back that opens.
void Smb2Test::sealsAThreeOneOneSession()
{
    Smb2Server server;
    server.setAuthenticator([](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
        keys->sessionBaseKey = QByteArray(16, 'k');
        return true;
    });

    QByteArray negotiate = header(Smb2::CmdNegotiate, 0, 0, 0);
    QByteArray body;
    putLe16(body, 36);
    putLe16(body, 1);
    putLe16(body, 1);
    putLe16(body, 0);
    putLe32(body, 0);
    body.append(QByteArray(16, '\0'));
    putLe64(body, 0);
    putLe16(body, Smb2::Dialect311);
    negotiate.append(body);
    const QByteArray negotiateReply = server.feed(nbt(negotiate));
    QCOMPARE(statusOf(negotiateReply), quint32(Smb2::StatusSuccess));

    const QByteArray setupOne = sessionSetup(1, ntlmNegotiate());
    const QByteArray replyOne = server.feed(nbt(setupOne));
    QCOMPARE(statusOf(replyOne), quint32(Smb2::StatusMoreProcessingRequired));
    const QByteArray setupTwo = sessionSetup(2, ntlmAuthenticate(
        QStringLiteral("CYBERDYNE"), QStringLiteral("alice"),
        QByteArray(16, 'r') + QByteArray(40, 'b')));
    const QByteArray replyTwo = server.feed(nbt(setupTwo));
    QCOMPARE(statusOf(replyTwo), quint32(Smb2::StatusSuccess));
    const quint64 sessionId = readLe64(replyTwo, 4 + 40);

    QByteArray preauth = Smb3::preauthUpdate(QByteArray(), negotiate);
    preauth = Smb3::preauthUpdate(preauth, negotiateReply.mid(4));
    preauth = Smb3::preauthUpdate(preauth, setupOne);
    preauth = Smb3::preauthUpdate(preauth, replyOne.mid(4));
    preauth = Smb3::preauthUpdate(preauth, setupTwo);

    // The server's two directions, derived from the same session key and the
    // same hash but different labels.
    QByteArray toClient; // SMBS2CCipherKey
    QByteArray fromClient; // SMBC2SCipherKey
    Smb3::encryptionKeys(QByteArray(16, 'k'), Smb2::Dialect311, preauth, &toClient, &fromClient);
    QCOMPARE(toClient.size(), 16);
    QCOMPARE(fromClient.size(), 16);
    QVERIFY(toClient != fromClient);
    const QByteArray signingKey = Smb3::signingKey(QByteArray(16, 'k'), Smb2::Dialect311, preauth);

    QByteArray echoBody;
    putLe16(echoBody, 4);
    putLe16(echoBody, 0);
    const QByteArray echo = header(Smb2::CmdEcho, 3, sessionId, 0) + echoBody;

    // The transform header's nonce field is 16 bytes; AES-CCM uses its first 11
    // and what the tag covers starts at the nonce, not at the protocol id.
    QByteArray nonce;
    for (int i = 0; i < 11; ++i)
        nonce.append(char(0xa0 + i));
    QByteArray transform;
    transform.append(char(0xfd));
    transform.append(QByteArray("SMB", 3));
    transform.append(QByteArray(16, '\0'));
    transform.append(nonce);
    transform.append(QByteArray(5, '\0'));
    putLe32(transform, quint32(echo.size()));
    putLe16(transform, 0);
    putLe16(transform, 0x0001);
    putLe64(transform, sessionId);
    QCOMPARE(transform.size(), 52);

    // The tag goes in the header's signature field; the ciphertext follows it.
    const QByteArray sealedEcho = Smb3::ccmEncrypt(fromClient, nonce, transform.mid(20), echo);
    transform.replace(4, 16, sealedEcho.right(16));
    const QByteArray reply =
        server.feed(nbt(transform + sealedEcho.left(sealedEcho.size() - 16)));
    QVERIFY(reply.size() > 4 + 52 + 16);
    QCOMPARE(quint8(reply.at(4)), quint8(0xfd));
    const QByteArray replyHeader = reply.mid(4, 52);
    QCOMPARE(readLe16(replyHeader, 42), quint16(0x0001)); // encrypted
    QCOMPARE(readLe64(replyHeader, 44), sessionId);
    const QByteArray opened =
        Smb3::ccmDecrypt(toClient, replyHeader.mid(20, 11), replyHeader.mid(20),
                         reply.mid(56) + replyHeader.mid(4, 16));
    QVERIFY(!opened.isEmpty());
    QCOMPARE(readLe32(replyHeader, 36), quint32(opened.size()));
    QCOMPARE(readLe16(opened, 12), quint16(Smb2::CmdEcho));
    QCOMPARE(readLe32(opened, 8), quint32(Smb2::StatusSuccess));
    QByteArray zeroed = opened;
    zeroed.replace(48, 16, QByteArray(16, '\0'));
    QCOMPARE(opened.mid(48, 16), Smb3::cmac(signingKey, zeroed).left(16));

    // A tag that does not verify is not a message.
    QByteArray tampered = transform + sealedEcho.left(sealedEcho.size() - 16);
    tampered[4] = char(quint8(tampered.at(4)) ^ 0x80); // a tag that does not verify
    QVERIFY(server.feed(nbt(tampered)).isEmpty());
}

QTEST_MAIN(Smb2Test)
#include "test_smb2.moc"
