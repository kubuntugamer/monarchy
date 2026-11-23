// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QCryptographicHash>
#include <QFile>
#include <QTemporaryDir>

#include "Gss.h"
#include "Ntlm.h"
#include "Rpc.h"
#include "Smb1.h"

// SMB1 is the only dialect Windows 2000 speaks, so the disk shares a member
// reads its policy from have to be served over it: tree connect to SYSVOL or
// NETLOGON, open a file by its case-insensitive path, read it at an offset, and
// be refused when it asks to write.
namespace {

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe32(QByteArray &out, quint32 value)
{
    putLe16(out, quint16(value & 0xffff));
    putLe16(out, quint16((value >> 16) & 0xffff));
}

quint16 readLe16(const QByteArray &data, int at)
{
    return quint16(quint8(data.at(at)) | (quint16(quint8(data.at(at + 1))) << 8));
}

quint32 readLe32(const QByteArray &data, int at)
{
    return quint32(readLe16(data, at)) | (quint32(readLe16(data, at + 2)) << 16);
}

QByteArray frame(const QByteArray &message)
{
    QByteArray out(4, '\0');
    const int size = message.size();
    out[0] = char((size >> 24) & 0xff);
    out[1] = char((size >> 16) & 0xff);
    out[2] = char((size >> 8) & 0xff);
    out[3] = char(size & 0xff);
    return out + message;
}

QByteArray utf16le(const QString &text)
{
    QByteArray out;
    for (const QChar ch : text) {
        putLe16(out, ch.unicode());
    }
    return out;
}

// One SMB1 message: header, word count, words, byte count, data bytes.
QByteArray smb(quint8 command, quint16 tid, quint16 uid, const QByteArray &words,
               const QByteArray &data)
{
    QByteArray out("\377SMB", 4);
    out.append(char(command));
    out.append(QByteArray(4, '\0'));  // status
    out.append(char(0x18));           // TFLAGS: canonical paths, case-insensitive
    putLe16(out, 0x8001);             // FLAGS2: long names + Unicode
    putLe16(out, 0);                  // PID high
    out.append(QByteArray(8, '\0'));  // signature
    putLe16(out, 0);                  // reserved
    putLe16(out, tid);
    putLe16(out, 0x1234);             // PID
    putLe16(out, uid);
    putLe16(out, 0x42);               // MID
    out.append(char(words.size() / 2));
    out.append(words);
    putLe16(out, quint16(data.size()));
    out.append(data);
    return out;
}

// A type-3 NTLMSSP message. The test's authenticator accepts any proof, so the
// response only has to be well formed for the parser.
QByteArray authenticateToken(const QString &user, const QString &domain)
{
    QByteArray domainBytes = utf16le(domain);
    QByteArray userBytes = utf16le(user);
    const QByteArray ntResponse(24, 'x');
    const int fixed = 64;
    const int domainAt = fixed + ntResponse.size();
    const int userAt = domainAt + domainBytes.size();

    QByteArray out("NTLMSSP", 7);
    out.append(char(0));
    putLe32(out, 3);
    putLe16(out, 0);                 // LM response length
    putLe16(out, 0);
    putLe32(out, fixed);             // LM response offset
    putLe16(out, quint16(ntResponse.size()));
    putLe16(out, quint16(ntResponse.size()));
    putLe32(out, fixed);             // NT response offset
    putLe16(out, quint16(domainBytes.size()));
    putLe16(out, quint16(domainBytes.size()));
    putLe32(out, domainAt);
    putLe16(out, quint16(userBytes.size()));
    putLe16(out, quint16(userBytes.size()));
    putLe32(out, userAt);
    putLe16(out, 0);                 // workstation length
    putLe16(out, 0);
    putLe32(out, userAt + userBytes.size());
    putLe16(out, 0);                 // session key length
    putLe16(out, 0);
    putLe32(out, userAt + userBytes.size());
    putLe32(out, 0x00000001u);       // NEGOTIATE_UNICODE
    out.append(ntResponse);
    out.append(domainBytes);
    out.append(userBytes);
    return out;
}

QByteArray negotiateMessage()
{
    QByteArray dialects;
    dialects.append(char(0x02));
    dialects.append("NT LM 0.12", 10);
    dialects.append(char(0));
    return smb(Smb1::CmdNegotiate, 0, 0, QByteArray(), dialects);
}

QByteArray sessionSetupMessage(const QByteArray &token)
{
    QByteArray words;
    words.append(char(0xff));        // AndXCommand
    words.append(char(0));
    putLe16(words, 0);               // AndXOffset
    putLe16(words, 4356);            // MaxBufferSize
    putLe16(words, 50);              // MaxMpxCount
    putLe16(words, 1);               // VcNumber
    putLe32(words, 0);               // SessionKey
    putLe16(words, quint16(token.size())); // SecurityBlobLength
    putLe32(words, 0);               // Reserved
    putLe32(words, 0);               // Capabilities
    return smb(Smb1::CmdSessionSetupAndX, 0, 0, words, token);
}

// The pre-extended-security session setup: the LM and NT responses inline, the
// account and domain as terminated strings after them, and no security blob.
// Samba's client sends this form with `client use spnego = no`, and a Windows
// 2000 machine's Netlogon path sends it too.
QByteArray legacySetupMessage(const QString &user, const QString &domain)
{
    const QByteArray lm(24, '\0');
    const QByteArray nt(48, 'n');
    QByteArray names = utf16le(user);
    names.append(QByteArray(2, '\0'));
    names.append(utf16le(domain));
    names.append(QByteArray(2, '\0'));
    QByteArray words;
    words.append(char(0xff));        // AndXCommand
    words.append(char(0));
    putLe16(words, 0);               // AndXOffset
    putLe16(words, 4356);            // MaxBufferSize
    putLe16(words, 50);              // MaxMpxCount
    putLe16(words, 1);               // VcNumber
    putLe32(words, 0);               // SessionKey
    putLe16(words, quint16(lm.size())); // PasswordLength
    putLe16(words, quint16(nt.size())); // UnicodePasswordLength
    putLe32(words, 0);               // Reserved
    putLe32(words, 0);               // Capabilities
    QByteArray data = lm + nt + names;
    return smb(Smb1::CmdSessionSetupAndX, 0, 0, words, data);
}

// A GSS-SPNEGO NegTokenInit the way a Windows 2000 member sends it when it
// holds a TGT: mechTypes lists Kerberos first and NTLMSSP last, and the
// mechToken is a Kerberos AP-REQ. This SMB1 endpoint speaks NTLMSSP only, so it
// has to select NTLMSSP from that list rather than end the session.
QByteArray spnegoKerberosToken()
{
    const QByteArray krb5Oid = QByteArray::fromHex("06092a864886f712010202");
    const QByteArray ntlmOid = QByteArray::fromHex("060a2b06010401823702020a");
    QByteArray mechList(1, char(0x30));
    mechList.append(char(krb5Oid.size() + ntlmOid.size()));
    mechList.append(krb5Oid);
    mechList.append(ntlmOid);
    QByteArray init(1, char(0x30));
    init.append(char(mechList.size() + 7));
    init.append(mechList);
    init.append(QByteArray::fromHex("a2050403aabbcc")); // dummy mechToken
    QByteArray token(1, char(0x60));
    // The outer body is the SPNEGO OID (8 bytes), the [0] header (2 bytes) and
    // the NegTokenInit itself.
    token.append(char(init.size() + 10));
    token.append(QByteArray::fromHex("06062b0601050502")); // SPNEGO OID
    token.append(QByteArray(1, char(0xa0)));
    token.append(char(init.size()));
    token.append(init);
    return token;
}

QByteArray treeConnectMessage(const QString &path)
{
    QByteArray words;
    words.append(char(0xff));
    words.append(char(0));
    putLe16(words, 0);               // AndXOffset
    putLe16(words, 0);               // Flags
    putLe16(words, 0);               // PasswordLength
    // Unicode is negotiated, so the path is UTF-16 with a two-byte terminator.
    QByteArray data = utf16le(path);
    data.append(QByteArray(2, '\0'));
    data.append("A:\0", 3);
    return smb(Smb1::CmdTreeConnectAndX, 0xffff, 0x1234, words, data);
}

QByteArray ntCreateMessage(quint16 tid, const QString &name)
{
    const QByteArray nameBytes = utf16le(name);
    QByteArray words(48, '\0');
    words[0] = char(0xff);           // AndXCommand
    words[5] = char(nameBytes.size() & 0xff);
    words[6] = char((nameBytes.size() >> 8) & 0xff);
    QByteArray data(1, '\0');        // the name starts on an even offset
    data.append(nameBytes);
    data.append(QByteArray(2, '\0'));
    return smb(Smb1::CmdNtCreateAndX, tid, 0x1234, words, data);
}

// A Windows client includes the UTF-16 terminator in NameLength, so the name
// arrives with a trailing NUL. It must still resolve to the file.
QByteArray terminatedNtCreateMessage(quint16 tid, const QString &name)
{
    const QByteArray nameBytes = utf16le(name) + QByteArray(2, '\0');
    QByteArray words(48, '\0');
    words[0] = char(0xff);
    words[5] = char(nameBytes.size() & 0xff);
    words[6] = char((nameBytes.size() >> 8) & 0xff);
    QByteArray data(1, '\0');
    data.append(nameBytes);
    return smb(Smb1::CmdNtCreateAndX, tid, 0x1234, words, data);
}

// TRANS2 QUERY_FILE_INFORMATION: parameters are the FID and the information
// level, and the setup word carries the subcommand.
QByteArray queryFileMessage(quint16 tid, quint16 fid, quint16 level)
{
    QByteArray parameters;
    putLe16(parameters, fid);
    putLe16(parameters, level);
    QByteArray words(28, '\0');
    words[26] = char(1); // SetupCount
    words[18] = char(parameters.size() & 0xff);
    words[19] = char((parameters.size() >> 8) & 0xff);
    const quint16 parameterOffset = quint16(32 + 1 + 30 + 2 + 1);
    words[20] = char(parameterOffset & 0xff);
    words[21] = char((parameterOffset >> 8) & 0xff);
    putLe16(words, 0x0007); // QUERY_FILE_INFORMATION
    QByteArray data(1, '\0');
    data.append(parameters);
    return smb(Smb1::CmdTrans2, tid, 0x1234, words, data);
}

QString decodeUtf16(const QByteArray &bytes)
{
    QString out;
    for (int i = 0; i + 1 < bytes.size(); i += 2)
        out.append(QChar(quint16(quint8(bytes.at(i)) | (quint16(quint8(bytes.at(i + 1))) << 8))));
    return out;
}

// TRANS2 FIND_FIRST2: the search attributes, how many entries the client will
// take, the flags, the information level, a storage type it does not use, and
// the pattern. Setup[0] carries the subcommand.
QByteArray findFirstMessage(quint16 tid, const QString &pattern, quint16 level,
                            quint16 maxEntries, quint16 flags = 0)
{
    QByteArray parameters;
    putLe16(parameters, 0x0016); // SearchAttributes: directory | archive | read-only
    putLe16(parameters, maxEntries);
    putLe16(parameters, flags);
    putLe16(parameters, level);
    putLe32(parameters, 0); // SearchStorageType, unused by this server
    QByteArray name = utf16le(pattern);
    name.append(QByteArray(2, '\0'));
    parameters.append(name);

    QByteArray words(28, '\0');
    words[26] = char(1); // SetupCount
    words[18] = char(parameters.size() & 0xff);
    words[19] = char((parameters.size() >> 8) & 0xff);
    const quint16 parameterOffset = quint16(32 + 1 + 30 + 2 + 1);
    words[20] = char(parameterOffset & 0xff);
    words[21] = char((parameterOffset >> 8) & 0xff);
    putLe16(words, 0x0001); // FIND_FIRST2
    QByteArray data(1, '\0');
    data.append(parameters);
    return smb(Smb1::CmdTrans2, tid, 0x1234, words, data);
}

// TRANS2 FIND_NEXT2: the search the client is continuing, how many more it will
// take, and the level it asked with.
QByteArray findNextMessage(quint16 tid, quint16 searchId, quint16 maxEntries, quint16 level)
{
    QByteArray parameters;
    putLe16(parameters, searchId);
    putLe16(parameters, maxEntries);
    putLe16(parameters, level);
    putLe32(parameters, 0); // ResumeKey
    putLe16(parameters, 0); // Flags
    parameters.append(QByteArray(2, '\0'));

    QByteArray words(28, '\0');
    words[26] = char(1);
    words[18] = char(parameters.size() & 0xff);
    words[19] = char((parameters.size() >> 8) & 0xff);
    const quint16 parameterOffset = quint16(32 + 1 + 30 + 2 + 1);
    words[20] = char(parameterOffset & 0xff);
    words[21] = char((parameterOffset >> 8) & 0xff);
    putLe16(words, 0x0002); // FIND_NEXT2
    QByteArray data(1, '\0');
    data.append(parameters);
    return smb(Smb1::CmdTrans2, tid, 0x1234, words, data);
}

// TRANS2 FIND_CLOSE2: the search the client is done with. Windows echoes the id
// it named, so the client can match the answer to the call it made.
QByteArray findCloseMessage(quint16 tid, quint16 searchId)
{
    QByteArray parameters;
    putLe16(parameters, searchId);

    QByteArray words(28, '\0');
    words[26] = char(1);
    words[18] = char(parameters.size() & 0xff);
    words[19] = char((parameters.size() >> 8) & 0xff);
    const quint16 parameterOffset = quint16(32 + 1 + 30 + 2 + 1);
    words[20] = char(parameterOffset & 0xff);
    words[21] = char((parameterOffset >> 8) & 0xff);
    putLe16(words, 0x0004); // FIND_CLOSE2
    QByteArray data(1, '\0');
    data.append(parameters);
    return smb(Smb1::CmdTrans2, tid, 0x1234, words, data);
}

// SMB_COM_TRANSACTION to a pipe the client has already opened, addressed the
// way Windows 2000 addresses it: the name field is `\PIPE\` with the pipe name
// left empty, Setup[0] is the subcommand, Setup[1] the handle, and the
// parameters sit between the name and the data.
// `inData` puts the payload in Trans_Data instead of Trans_Parameters, which is
// where MS-CIFS and Windows 2000 carry a pipe PDU; the parameter field is where
// this server used to look, and where an SMB1 bind from impacket arrives.
QByteArray pipeTransactMessage(quint16 tid, quint16 fid, quint16 subcommand,
                               const QByteArray &payload, bool inData = false)
{
    QByteArray words(28, '\0');
    const char lo = char(payload.size() & 0xff);
    const char hi = char((payload.size() >> 8) & 0xff);
    if (inData) {
        words[2] = lo;
        words[3] = hi;  // TotalDataCount
        words[22] = lo;
        words[23] = hi; // DataCount
    } else {
        words[0] = lo;
        words[1] = hi;  // TotalParameterCount
        words[18] = lo;
        words[19] = hi; // ParameterCount
    }
    words[20] = char(84); // ParameterOffset
    words[21] = char(0);
    words[24] = char(84); // DataOffset
    words[25] = char(0);
    words[26] = char(2);  // SetupCount
    putLe16(words, subcommand);
    putLe16(words, fid);

    QByteArray data(1, '\0'); // Pad1
    data.append(utf16le(QStringLiteral("\\PIPE\\")));
    data.append(QByteArray(2, '\0')); // the empty pipe name's terminator
    data.append(QByteArray(2, '\0')); // Pad2, so the payload starts at 84
    data.append(payload);
    return smb(Smb1::CmdTrans, tid, 0x1234, words, data);
}

QByteArray readMessage(quint16 tid, quint16 fid, quint32 offset, quint16 count)
{
    QByteArray words(24, '\0');
    words[0] = char(0xff);
    words[4] = char(fid & 0xff);
    words[5] = char((fid >> 8) & 0xff);
    words[6] = char(offset & 0xff);
    words[7] = char((offset >> 8) & 0xff);
    words[8] = char((offset >> 16) & 0xff);
    words[9] = char((offset >> 24) & 0xff);
    words[10] = char(count & 0xff);
    words[11] = char((count >> 8) & 0xff);
    return smb(Smb1::CmdReadAndX, tid, 0x1234, words, QByteArray());
}

QByteArray writeMessage(quint16 tid, quint16 fid, const QByteArray &payload)
{
    QByteArray words(28, '\0');
    words[0] = char(0xff);
    words[4] = char(fid & 0xff);
    words[5] = char((fid >> 8) & 0xff);
    words[20] = char(payload.size() & 0xff);
    words[21] = char((payload.size() >> 8) & 0xff);
    const quint16 dataOffset = quint16(32 + 1 + words.size() + 2);
    words[22] = char(dataOffset & 0xff);
    words[23] = char((dataOffset >> 8) & 0xff);
    QByteArray data(1, '\0');
    data.append(payload);
    return smb(Smb1::CmdWriteAndX, tid, 0x1234, words, data);
}

// Replies are NetBIOS-framed; the SMB message starts after the four-byte header.
QByteArray payloadOf(const QByteArray &framed)
{
    return framed.mid(4);
}

quint32 statusOf(const QByteArray &framed)
{
    const QByteArray message = payloadOf(framed);
    return message.size() >= 9 ? readLe32(message, 5) : 0xffffffffu;
}

quint16 tidOf(const QByteArray &framed)
{
    return readLe16(payloadOf(framed), 24);
}

// Signs one message the way a client does: FLAGS2 says it is signed, the
// sequence number goes into the signature field, and the first eight bytes of
// MD5(session key || message) replace that field (MS-CIFS 3.2.4.1).
QByteArray signedMessage(QByteArray message, const QByteArray &key, quint32 sequence)
{
    const quint16 flags2 = quint16(readLe16(message, 10) | 0x0004);
    message[10] = char(flags2 & 0xff);
    message[11] = char((flags2 >> 8) & 0xff);
    QByteArray field;
    putLe32(field, sequence);
    field.append(QByteArray(4, '\0'));
    message.replace(14, 8, field);
    QByteArray macInput = key;
    macInput.append(message);
    message.replace(14, 8, QCryptographicHash::hash(macInput, QCryptographicHash::Md5).left(8));
    return message;
}

// Checks a reply the way the client did: put the expected sequence number where
// the signature sits and see whether the MAC covers the rest of the message.
bool signatureMatches(const QByteArray &framed, const QByteArray &key, quint32 sequence)
{
    QByteArray message = payloadOf(framed);
    if (!(readLe16(message, 10) & 0x0004))
        return false;
    const QByteArray received = message.mid(14, 8);
    QByteArray field;
    putLe32(field, sequence);
    field.append(QByteArray(4, '\0'));
    message.replace(14, 8, field);
    QByteArray macInput = key;
    macInput.append(message);
    return received
        == QCryptographicHash::hash(macInput, QCryptographicHash::Md5).left(8);
}

} // namespace

class Smb1Test : public QObject
{
    Q_OBJECT

private slots:
    void readsAPolicyFileFromSysvol();
    void opensATerminatedNameAndReportsAttributes();
    void listsADirectoryOverFindFirst2();
    void refusesAnAnonymousTreeConnect();
    void acceptsTheNullSessionAWindows2000LogonStartsWith();
    void refusesAnUnknownShare();
    void refusesTraversalOutOfTheShare();
    void refusesWrites();
    void answersARawNtlmTokenWithoutSpnego();
    void acceptsPreExtendedSecuritySessionSetup();
    void namesItselfAfterTheSecurityBlob();
    void acceptsTheKerberosTicketAWindows2000MemberOffers();
    void setsTheStateOfAnOpenPipe();
    void signsAndVerifiesASignedSession();
    void signsAPreExtendedSecuritySessionTheWayTheClientKeysIt();

private:
    QTemporaryDir m_root;
    QByteArray m_fileBytes;
    QString m_fileRelative;
    // An RPC endpoint for the pipe cases. It is never bound: the state request
    // is answered by the pipe layer and must not reach the endpoint at all.
    RpcServer m_pipeEndpoint;

    Smb1::Session *plainSession();
    Smb1::Session *pipeSession();
    Smb1::Session *authenticatedSession();
    quint16 connectShare(Smb1::Session *session, const QString &share);
};

Smb1::Session *Smb1Test::plainSession()
{
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    shares.insert(QStringLiteral("netlogon"), m_root.filePath(QStringLiteral("scripts")));

    return new Smb1::Session(
        QHash<QString, RpcServer *>(),
        [](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"), QStringLiteral("monarchy.test"),
        shares);
}

// The IPC$ share with `\pipe\netlogon` behind it, unauthenticated: a 2000
// client opens its pipe through an anonymous IPC$ session for the browse path.
Smb1::Session *Smb1Test::pipeSession()
{
    QHash<QString, RpcServer *> pipes;
    pipes.insert(QStringLiteral("netlogon"), &m_pipeEndpoint);

    return new Smb1::Session(
        pipes,
        [](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"), QStringLiteral("monarchy.test"),
        QHash<QString, QString>());
}

// A GPO-shaped tree: SYSVOL\<domain>\Policies\{GUID}\Machine\Registry.pol.
Smb1::Session *Smb1Test::authenticatedSession()
{
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    shares.insert(QStringLiteral("netlogon"), m_root.filePath(QStringLiteral("scripts")));

    auto *session = new Smb1::Session(
        QHash<QString, RpcServer *>(),
        [](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"), QStringLiteral("monarchy.test"),
        shares);
    session->feed(negotiateMessage());
    const QByteArray reply = session->feed(sessionSetupMessage(
        authenticateToken(QStringLiteral("alice"), QStringLiteral("MONARCHY"))));
    if (statusOf(reply) != 0) {
        delete session;
        return nullptr;
    }
    return session;
}

quint16 Smb1Test::connectShare(Smb1::Session *session, const QString &share)
{
    const QByteArray reply =
        session->feed(treeConnectMessage(QStringLiteral("\\\\dc1\\") + share));
    if (statusOf(reply) != 0)
        return 0;
    return tidOf(reply);
}

void Smb1Test::readsAPolicyFileFromSysvol()
{
    QVERIFY(m_root.isValid());
    m_fileRelative = QStringLiteral("sysvol/monarchy.test/Policies/{11111111-2222-3333-4444-"
                                    "555555555555}/Machine/Registry.pol");
    m_fileBytes = QByteArray::fromHex("50572d5290000000"); // PReg header, enough to be real
    const QString absolute = m_root.filePath(m_fileRelative);
    QVERIFY(QDir().mkpath(QFileInfo(absolute).absolutePath()));
    QFile file(absolute);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write(m_fileBytes);
    file.close();

    QScopedPointer<Smb1::Session> session(authenticatedSession());
    QVERIFY2(session, "the authenticated session setup was refused");

    const quint16 tid = connectShare(session.data(), QStringLiteral("SYSVOL"));
    QVERIFY2(tid != 0, "tree connect to SYSVOL was refused");

    // The path is sent in the case a GPO client builds it in, while the store
    // on disk uses different case: the share has to resolve it.
    const QByteArray createReply = session->feed(ntCreateMessage(tid, QStringLiteral("SYSVOL\\MONARCHY.TEST\\policies\\{11111111-2222-3333-4444-"
                            "555555555555}\\machine\\registry.POL")));
    QCOMPARE(statusOf(createReply), quint32(0));
    const QByteArray created = payloadOf(createReply);
    // Words begin at 33: AndXCommand(1), AndXReserved(1), AndXOffset(2), then
    // OplockLevel(1) and the FID.
    const quint16 fid = readLe16(created, 38);
    QVERIFY(fid != 0);
    // EndOfFile follows the four timestamps, attributes and allocation size,
    // so a client can size its buffer from the open.
    QCOMPARE(readLe32(created, 88), quint32(m_fileBytes.size()));

    const QByteArray readReply = session->feed(readMessage(tid, fid, 0, 64));
    QCOMPARE(statusOf(readReply), quint32(0));
    const QByteArray read = payloadOf(readReply);
    const int wordsAt = 33;
    const quint16 dataCount = readLe16(read, wordsAt + 10);
    const quint16 dataOffset = readLe16(read, wordsAt + 12);
    QCOMPARE(read.mid(dataOffset, dataCount), m_fileBytes);

    // A second read at an offset returns the tail, not the start.
    const QByteArray tailReply = session->feed(readMessage(tid, fid, 4, 64));
    QCOMPARE(statusOf(tailReply), quint32(0));
    const QByteArray tail = payloadOf(tailReply);
    QCOMPARE(tail.mid(readLe16(tail, wordsAt + 12), readLe16(tail, wordsAt + 10)),
             m_fileBytes.mid(4));
}

void Smb1Test::opensATerminatedNameAndReportsAttributes()
{
    QVERIFY(m_root.isValid());
    const QString absolute = m_root.filePath(QStringLiteral("sysvol/gpt.ini"));
    QVERIFY(QDir().mkpath(QFileInfo(absolute).absolutePath()));
    QFile file(absolute);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write("[General]\r\nVersion=0\r\n");
    file.close();
    const QFileInfo expected(absolute);

    QScopedPointer<Smb1::Session> session(authenticatedSession());
    QVERIFY(session);
    const quint16 tid = connectShare(session.data(), QStringLiteral("SYSVOL"));
    QVERIFY(tid != 0);

    const QByteArray createReply = session->feed(
        terminatedNtCreateMessage(tid, QStringLiteral("sysvol\\GPT.INI")));
    QCOMPARE(statusOf(createReply), quint32(0));
    const quint16 fid = readLe16(payloadOf(createReply), 38);

    // A real client asks for SMB_QUERY_FILE_ALL_INFO by handle before it reads.
    const QByteArray queryReply = session->feed(queryFileMessage(tid, fid, 0x0107));
    QCOMPARE(statusOf(queryReply), quint32(0));
    const QByteArray query = payloadOf(queryReply);
    const quint16 dataCount = readLe16(query, 33 + 12);
    const quint16 dataOffset = readLe16(query, 33 + 14);
    const QByteArray info = query.mid(dataOffset, dataCount);
    QCOMPARE(info.size(), int(94 + 4 /* sizeof(FileName) */ + 14 /* UTF-16 "GPT.INI" */));
    QCOMPARE(readLe32(info, 32), quint32(0x80));                    // FileAttributes
    QCOMPARE(readLe32(info, 48), quint32(expected.size()));         // EndOfFile
    QCOMPARE(info.at(61), char(0));                                 // Directory
    QCOMPARE(readLe32(info, 94), quint32(14));                       // FileNameLength
    // The name reported is the one on disk, as Windows reports it.
    QCOMPARE(info.mid(98), utf16le(QStringLiteral("gpt.ini")));
}

void Smb1Test::refusesAnAnonymousTreeConnect()
{
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    Smb1::Session session(QHash<QString, RpcServer *>(),
                          [](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
                              *keys = Ntlm::SessionKeys();
                              return true;
                          },
                          QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
                          QStringLiteral("monarchy.test"), shares);
    session.feed(negotiateMessage());
    const QByteArray reply =
        session.feed(treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")));
    QCOMPARE(statusOf(reply), Smb1::kStatusAccessDenied);
}

// Windows 2000 opens its machine channel with a Type 3 message that names no
// user and carries no response. Refusing it makes the client log off and gives
// up on the whole logon, so the null session is accepted — and stays anonymous.
void Smb1Test::acceptsTheNullSessionAWindows2000LogonStartsWith()
{
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    Smb1::Session session(QHash<QString, RpcServer *>(),
                          [](const Rpc::AuthRequest &, Ntlm::SessionKeys *) {
                              return true;
                          },
                          QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
                          QStringLiteral("monarchy.test"), shares);
    session.feed(negotiateMessage());

    QByteArray nullSession("NTLMSSP", 7);
    nullSession.append(char(0));
    putLe32(nullSession, 3);
    putLe16(nullSession, 1);          // LM response length
    putLe16(nullSession, 1);
    putLe32(nullSession, 64);
    putLe16(nullSession, 0);          // NT response length
    putLe16(nullSession, 0);
    putLe32(nullSession, 64);
    putLe16(nullSession, 0);          // domain length
    putLe16(nullSession, 0);
    putLe32(nullSession, 64);
    putLe16(nullSession, 0);          // user length
    putLe16(nullSession, 0);
    putLe32(nullSession, 64);
    putLe16(nullSession, 0);          // workstation length
    putLe16(nullSession, 0);
    putLe32(nullSession, 64);
    putLe16(nullSession, 0);          // session key length
    putLe16(nullSession, 0);
    putLe32(nullSession, 64);
    putLe32(nullSession, 0x00008201u); // flags
    nullSession.append(char(0));       // the empty LM response

    QCOMPARE(statusOf(session.feed(sessionSetupMessage(nullSession))),
             Smb1::kStatusSuccess);
    // An anonymous session is not the machine account: the domain's files stay
    // closed to it, exactly as they are to any other unknown caller.
    QCOMPARE(statusOf(session.feed(treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")))),
             Smb1::kStatusAccessDenied);
}

void Smb1Test::refusesAnUnknownShare()
{
    QScopedPointer<Smb1::Session> session(authenticatedSession());
    QVERIFY(session);
    const QByteArray reply =
        session->feed(treeConnectMessage(QStringLiteral("\\\\dc1\\ADMIN$")));
    QCOMPARE(statusOf(reply), Smb1::kStatusBadNetworkName);
}

void Smb1Test::refusesTraversalOutOfTheShare()
{
    QScopedPointer<Smb1::Session> session(authenticatedSession());
    QVERIFY(session);
    const quint16 tid = connectShare(session.data(), QStringLiteral("SYSVOL"));
    QVERIFY(tid != 0);
    const QByteArray reply =
        session->feed(ntCreateMessage(tid, QStringLiteral("..\\..\\etc\\passwd")));
    QCOMPARE(statusOf(reply), Smb1::kStatusObjectNameNotFound);
}

void Smb1Test::refusesWrites()
{
    QVERIFY(m_root.isValid());
    const QString path = m_root.filePath(QStringLiteral("sysvol/readme.txt"));
    QVERIFY(QDir().mkpath(QFileInfo(path).absolutePath()));
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write("policy");
    file.close();

    QScopedPointer<Smb1::Session> session(authenticatedSession());
    QVERIFY(session);
    const quint16 tid = connectShare(session.data(), QStringLiteral("SYSVOL"));
    QVERIFY(tid != 0);
    const QByteArray createReply =
        session->feed(ntCreateMessage(tid, QStringLiteral("sysvol\\readme.txt")));
    QCOMPARE(statusOf(createReply), quint32(0));
    const quint16 fid = readLe16(payloadOf(createReply), 38);
    const QByteArray writeReply =
        session->feed(writeMessage(tid, fid, QByteArray("tampered")));
    QCOMPARE(statusOf(writeReply), Smb1::kStatusAccessDenied);
    // The file is untouched.
    QFile after(path);
    QVERIFY(after.open(QIODevice::ReadOnly));
    QCOMPARE(after.readAll(), QByteArray("policy"));
}

// Before extended security, the client put its LM and NT responses in the
// session-setup request itself and the account name behind them, with no
// security blob of any kind. A Windows 2000 machine's Netlogon path and
// Samba's non-SPNEGO client both send this form; reading it as an extended
// request with an empty blob answered every one of them LOGON_FAILURE, so the
// pipe they came for was never reached.
void Smb1Test::acceptsPreExtendedSecuritySessionSetup()
{
    QByteArray words;
    words.append(char(0xff)); // AndXCommand
    words.append(char(0));    // AndXReserved
    putLe16(words, 0);        // AndXOffset
    putLe16(words, 4356);     // MaxBufferSize
    putLe16(words, 50);       // MaxMpxCount
    putLe16(words, 1);        // VcNumber
    putLe32(words, 0);        // SessionKey
    putLe16(words, 24);       // OEMPasswordLength
    putLe16(words, 24);       // UnicodePasswordLength
    putLe32(words, 0);        // Reserved
    putLe32(words, 0);        // Capabilities

    // The responses are computed over the challenge the negotiate reply
    // carried, which is eight zero bytes because it advertised none. This
    // test's authenticator accepts any proof, so their contents only have to
    // be the right lengths.
    QByteArray data(24, 'l');
    data.append(QByteArray(24, 'n'));
    const QByteArray user = utf16le(QStringLiteral("alice"));
    data.append(user);
    data.append(QByteArray(2, '\0'));
    const QByteArray domain = utf16le(QStringLiteral("MONARCHY"));
    data.append(domain);
    data.append(QByteArray(2, '\0'));
    data.append(QByteArray("Windows NT\0", 11));
    data.append(QByteArray("Monarchy\0", 9));

    QScopedPointer<Smb1::Session> session(plainSession());
    QVERIFY(session);
    session->feed(negotiateMessage());
    const QByteArray reply =
        session->feed(smb(Smb1::CmdSessionSetupAndX, 0, 0, words, data));
    QCOMPARE(statusOf(reply), quint32(0));
    const QByteArray payload = payloadOf(reply);
    // AndX plus Action, and no security-blob word: this answer has to look
    // like the request's own dialect, or the client parses the words after it
    // as a length it never sent.
    QCOMPARE(quint8(payload.at(32)), quint8(3));
    QVERIFY(readLe16(payload, 33 + 6) > 0); // ByteCount: the native names

    // The session is authenticated, so the pipe share opens.
    const quint16 tid = connectShare(session.data(), QStringLiteral("IPC$"));
    QVERIFY(tid != 0);

    // A request whose responses say nothing is refused rather than treated as
    // an anonymous logon.
    QByteArray empty(words);
    empty.replace(14, 2, QByteArray(2, '\0'));
    empty.replace(16, 2, QByteArray(2, '\0'));
    QScopedPointer<Smb1::Session> anonymous(plainSession());
    QVERIFY(anonymous);
    anonymous->feed(negotiateMessage());
    QCOMPARE(statusOf(anonymous->feed(smb(Smb1::CmdSessionSetupAndX, 0, 0, empty, QByteArray()))),
             Smb1::kStatusLogonFailure);
}

// Windows 2000 sends the session-setup token as raw NTLMSSP with no GSS
// wrapper, and drops the session when the reply comes back wrapped; Samba and
// impacket send the wrapper and read a wrapped answer. Both have to be served
// in the form they arrived in.
void Smb1Test::answersARawNtlmTokenWithoutSpnego()
{
    QByteArray rawType1("NTLMSSP", 7);
    rawType1.append(char(0));
    putLe32(rawType1, 1);            // NEGOTIATE
    putLe32(rawType1, 0x00008201u);  // UNICODE | NTLM

    QScopedPointer<Smb1::Session> session(plainSession());
    QVERIFY(session);
    session->feed(negotiateMessage());

    const QByteArray challengeReply = session->feed(sessionSetupMessage(rawType1));
    QCOMPARE(statusOf(challengeReply), Smb1::kStatusMoreProcessingRequired);
    const QByteArray challenge = payloadOf(challengeReply);
    // Words: AndXCommand(2), AndXOffset(2), Action(2), SecurityBlobLength(2).
    const quint16 challengeLength = readLe16(challenge, 33 + 6);
    QVERIFY(challengeLength > 32);
    QCOMPARE(challenge.mid(43, 8), QByteArray("NTLMSSP", 8));
    QCOMPARE(readLe32(challenge, 43 + 8), quint32(2)); // CHALLENGE, not a NegTokenResp

    // The authenticating message is answered with a raw, empty blob.
    const QByteArray acceptReply = session->feed(sessionSetupMessage(
        authenticateToken(QStringLiteral("alice"), QStringLiteral("MONARCHY"))));
    QCOMPARE(statusOf(acceptReply), quint32(0));
    QCOMPARE(readLe16(payloadOf(acceptReply), 33 + 6), quint16(0));

    // A wrapped token still gets its SPNEGO answer, so the wrapper is not
    // dropped for clients that do speak it.
    QScopedPointer<Smb1::Session> wrapped(plainSession());
    QVERIFY(wrapped);
    wrapped->feed(negotiateMessage());
    QByteArray wrappedToken("\x60\x81\x00", 3);
    wrappedToken.append(rawType1);
    const QByteArray wrappedReply = wrapped->feed(sessionSetupMessage(wrappedToken));
    QCOMPARE(statusOf(wrappedReply), Smb1::kStatusMoreProcessingRequired);
    const QByteArray wrappedBlob = payloadOf(wrappedReply);
    QVERIFY(readLe16(wrappedBlob, 33 + 6) > 32);
    QCOMPARE(wrappedBlob.at(43), char(0xa1)); // NegTokenResp

    // A Windows 2000 member offers Kerberos first and NTLMSSP last. The SMB1
    // endpoint cannot accept the Kerberos AP-REQ, so it must select NTLMSSP
    // from the offered list and continue; answering LOGON_FAILURE dropped the
    // session before the client ever opened the Netlogon pipe.
    QScopedPointer<Smb1::Session> kerberos(plainSession());
    QVERIFY(kerberos);
    kerberos->feed(negotiateMessage());
    const QByteArray kerberosReply =
        kerberos->feed(sessionSetupMessage(spnegoKerberosToken()));
    QCOMPARE(statusOf(kerberosReply), Smb1::kStatusMoreProcessingRequired);
    const QByteArray kerberosBlob = payloadOf(kerberosReply);
    QVERIFY(readLe16(kerberosBlob, 33 + 6) > 0);
    QCOMPARE(kerberosBlob.at(43), char(0xa1)); // NegTokenResp
    QVERIFY(kerberosBlob.contains(QByteArray::fromHex("2b06010401823702020a")));
}

// MS-CIFS 2.2.4.6.3 lists NativeOS and NativeLanMan after the security blob,
// and a client that parses the answer by that definition reads both from the
// bytes the blob does not cover. Sending the bare blob put a client into the
// strings' first byte: impacket's SMB1 client stopped with "Can't find NUL
// terminator in field 'NativeLanMan'" and answered itself LOGON_FAILURE without
// ever sending a Type 3, which looks exactly like a DC that refused the
// password. The strings follow the blob, in the request's own encoding.
void Smb1Test::namesItselfAfterTheSecurityBlob()
{
    QByteArray type1("NTLMSSP", 7);
    type1.append(char(0));
    putLe32(type1, 1);            // NEGOTIATE
    putLe32(type1, 0x00008201u);  // UNICODE | NTLM

    // The non-Unicode request: FLAGS2 keeps long names and drops the Unicode
    // bit, which is what impacket's SMB1 session setup carries.
    QScopedPointer<Smb1::Session> ascii(plainSession());
    QVERIFY(ascii);
    ascii->feed(negotiateMessage());
    QByteArray request = sessionSetupMessage(type1);
    request.replace(10, 2, QByteArray::fromHex("0100"));
    const QByteArray reply = ascii->feed(request);
    QCOMPARE(statusOf(reply), Smb1::kStatusMoreProcessingRequired);
    const QByteArray payload = payloadOf(reply);
    // WordCount 4: AndX, Action, SecurityBlobLength. ByteCount starts at 41 and
    // the blob at 43.
    QCOMPARE(quint8(payload.at(32)), quint8(4));
    const int blobLength = readLe16(payload, 39);
    QVERIFY(blobLength > 0);
    QVERIFY2(payload.mid(43 + blobLength).endsWith(QByteArray("Monarchy\0Monarchy\0", 18)),
             qPrintable(QString::fromLatin1(payload.mid(43 + blobLength).toHex())));

    // Every Windows client asks in UTF-16, so the same fields go back that way.
    QScopedPointer<Smb1::Session> wide(plainSession());
    QVERIFY(wide);
    wide->feed(negotiateMessage());
    const QByteArray wideReply = wide->feed(sessionSetupMessage(type1));
    QCOMPARE(statusOf(wideReply), Smb1::kStatusMoreProcessingRequired);
    const QByteArray widePayload = payloadOf(wideReply);
    QByteArray expected = utf16le(QStringLiteral("Monarchy"));
    expected.append(QByteArray(2, '\0'));
    expected.append(utf16le(QStringLiteral("Monarchy")));
    expected.append(QByteArray(2, '\0'));
    QVERIFY2(widePayload.endsWith(expected),
             qPrintable(QString::fromLatin1(widePayload.right(48).toHex())));
}

// The other half of that choice: when the session can accept Kerberos, it does,
// because the member holds a ticket for this server. The exchange finishes in
// one round trip and the session is usable at once.
void Smb1Test::acceptsTheKerberosTicketAWindows2000MemberOffers()
{
    const QByteArray acceptorReply = QByteArray::fromHex("6b05020300000001");
    // An AES-256 context key: 32 bytes, which is what a session key is unless
    // the client forced RC4. SMB1 signs with all of it.
    const QByteArray contextKey = QByteArray::fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Smb1::Session session(QHash<QString, RpcServer *>(),
                          [](const Rpc::AuthRequest &, Ntlm::SessionKeys *) { return false; },
                          QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
                          QStringLiteral("monarchy.test"));
    session.setKerberosAcceptor([&](const QByteArray &apReq,
                                    Rpc::KerberosContext *context, QString *) {
        if (apReq != QByteArray::fromHex("aabbcc"))
            return false;
        context->user = QStringLiteral("NEURALNODE0$@MONARCHY.TEST");
        context->key = contextKey;
        context->replyToken = acceptorReply;
        return true;
    });
    session.feed(negotiateMessage());
    QVERIFY(Gss::carriesKerberos(spnegoKerberosToken()));
    QCOMPARE(Gss::kerberosToken(spnegoKerberosToken()), QByteArray::fromHex("aabbcc"));

    const QByteArray reply = session.feed(sessionSetupMessage(spnegoKerberosToken()));
    QCOMPARE(statusOf(reply), quint32(0));
    const QByteArray blob = payloadOf(reply);
    QCOMPARE(blob.at(43), char(0xa1));            // NegTokenResp
    QCOMPARE(quint8(blob.at(43 + 8)), quint8(0)); // negState accept-completed
    QVERIFY(blob.contains(acceptorReply));        // the AP-REP the acceptor built

    // The ticket named the principal, so the session opens the pipe share the
    // Netlogon channel rides on. That request is signed, and the reply is signed
    // with the whole context key: a client keys its MAC with all 32 bytes, so a
    // server that used the first 16 answered ACCESS_DENIED to this very message
    // ("smb1_signing_good: BAD SIG: seq 1") whenever the ticket was AES-256.
    const QByteArray signedRequest = signedMessage(
        treeConnectMessage(QStringLiteral("\\\\dc1\\IPC$")), contextKey, 1);
    const QByteArray treeReply = session.feed(signedRequest);
    QCOMPARE(statusOf(treeReply), quint32(0));
    QVERIFY(signatureMatches(treeReply, contextKey, 2));
    QVERIFY(!signatureMatches(treeReply, contextKey.left(16), 2));
}

// Windows 2000 sets a named pipe's handle state on the handle it has already
// opened, before it binds DCE/RPC on that pipe. The DC answered NOT_SUPPORTED,
// and dcpromo stopped at "The RPC server is unavailable" having just opened
// \pipe\NETLOGON: the bind it wanted to send next was never sent.
void Smb1Test::setsTheStateOfAnOpenPipe()
{
    QScopedPointer<Smb1::Session> session(pipeSession());
    QVERIFY(session);
    const quint16 tid = connectShare(session.data(), QStringLiteral("IPC$"));
    QVERIFY(tid != 0);
    const QByteArray createReply =
        session->feed(ntCreateMessage(tid, QStringLiteral("pipe\\NETLOGON")));
    QCOMPARE(statusOf(createReply), quint32(0));
    const quint16 fid = readLe16(payloadOf(createReply), 38);

    // The state a 2000 client sets here is message mode, and the only thing the
    // caller can observe is whether the request was accepted.
    const QByteArray stateReply =
        session->feed(pipeTransactMessage(tid, fid, 0x0001, QByteArray("\0\1", 2)));
    QCOMPARE(statusOf(stateReply), quint32(0));
    // The reply is the transaction block and nothing else: ten words, zero
    // counts, an empty byte block. An unexpected byte block would show up here.
    QCOMPARE(stateReply.size(), 4 + 32 + 1 + 20 + 2);
    const QByteArray message = payloadOf(stateReply);
    QCOMPARE(quint8(message.at(32)), quint8(10));     // WordCount
    QCOMPARE(readLe16(message, 33), quint16(0));      // TotalParameterCount
    QCOMPARE(readLe16(message, 39), quint16(0));      // ParameterCount
    QCOMPARE(readLe16(message, 53), quint16(0));      // ByteCount

    // A pipe subcommand that is not implemented is still refused, so the answer
    // above is this one shape and not a blanket reply to every transaction.
    QCOMPARE(statusOf(session->feed(pipeTransactMessage(tid, fid, 0x0021,
                                                       QByteArray("\0\1", 2)))),
             Smb1::kStatusNotSupported);

    // A state request that carries no state value is refused the way Samba's
    // api_SNPHS refuses the same shape.
    QCOMPARE(statusOf(session->feed(pipeTransactMessage(tid, fid, 0x0001, QByteArray()))),
             Smb1::kStatusInvalidParameter);

    // The handle has to be one this session opened, or the state would be set
    // on nothing in particular.
    QCOMPARE(statusOf(session->feed(pipeTransactMessage(tid, 0x7777, 0x0001,
                                                       QByteArray("\0\1", 2)))),
             Smb1::kStatusInvalidHandle);

    // The bind this client sends next, byte for byte as it went on the wire: a
    // DCE/RPC bind for NETLOGON carried in Trans_Data. The answer has to come
    // back in Trans_Data, which is where the client reads it, and it has to be
    // the DCE/RPC reply rather than an empty block.
    const QByteArray bind = QByteArray::fromHex(
        "05000b03100000004800000001000000b810b810000000000100000000000100"
        "785634123412cdabef0001234567cffb01000000045d888aeb1cc9119fe808002b104860"
        "02000000");
    const QByteArray bindReply =
        session->feed(pipeTransactMessage(tid, fid, 0x0026, bind, true));
    QCOMPARE(statusOf(bindReply), quint32(0));
    const QByteArray answer = payloadOf(bindReply);
    const quint16 dataCount = readLe16(answer, 35); // TotalDataCount
    QVERIFY(dataCount > 0);
    QCOMPARE(readLe16(answer, 39), quint16(0)); // ParameterCount
    QCOMPARE(readLe16(answer, 45), dataCount);  // DataCount
    // The offset the reply names has to be where the PDU actually starts.
    const quint16 dataOffset = readLe16(answer, 47);
    QCOMPARE(answer.mid(int(dataOffset), 2), QByteArray("\x05\x00", 2));

    // A client that sent the PDU in the parameter field still reads its answer
    // there, so the field it used is the field that carries the reply.
    const QByteArray paramReply =
        session->feed(pipeTransactMessage(tid, fid, 0x0026, bind));
    QCOMPARE(statusOf(paramReply), quint32(0));
    const QByteArray paramMessage = payloadOf(paramReply);
    QVERIFY(readLe16(paramMessage, 39) > 0);                   // ParameterCount
    QCOMPARE(readLe16(paramMessage, 45), quint16(0));          // DataCount
    QCOMPARE(paramMessage.mid(int(readLe16(paramMessage, 41)), 2),
             QByteArray("\x05\x00", 2)); // a DCE/RPC 5.0 PDU at ParameterOffset
}

// A directory listing, which is the first thing a 2000 workstation does after
// it authenticates. Measured with Samba's client pinned to NT1: `ls` in SYSVOL
// lists the domain directory, and a pattern that matches nothing in an empty
// NETLOGON answers NO_SUCH_FILE, which is what Windows answers rather than an
// empty success. The chain bytes matter as much as the names: the client walks
// NextEntryOffset and reads the name at the offset its information level fixes.
void Smb1Test::listsADirectoryOverFindFirst2()
{
    QDir root(m_root.path());
    QVERIFY(root.mkpath(QStringLiteral("lsdir/nested")));
    const auto writeFile = [&root](const QString &relative) {
        QFile file(root.filePath(relative));
        QVERIFY2(file.open(QIODevice::WriteOnly), qPrintable(relative));
        file.write("x");
    };
    writeFile(QStringLiteral("lsdir/alpha.txt"));
    writeFile(QStringLiteral("lsdir/beta.log"));
    writeFile(QStringLiteral("lsdir/nested/inner.txt"));
    writeFile(QStringLiteral("lsdir/nested/deeper.txt"));

    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    Smb1::Session session(
        QHash<QString, RpcServer *>(),
        [](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"), QStringLiteral("monarchy.test"),
        shares);
    session.feed(negotiateMessage());
    QByteArray type1("NTLMSSP", 7);
    type1.append(char(0));
    putLe32(type1, 1);
    putLe32(type1, 0x00008201u);
    session.feed(sessionSetupMessage(type1));
    QCOMPARE(statusOf(session.feed(sessionSetupMessage(
                 authenticateToken(QStringLiteral("alice"), QStringLiteral("MONARCHY"))))),
             quint32(0));
    const QByteArray treeReply =
        session.feed(treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")));
    QCOMPARE(statusOf(treeReply), quint32(0));
    const quint16 tid = readLe16(payloadOf(treeReply), 24);

    // Ask for one entry per call, so the continuation is exercised the way a
    // client that pages a big directory walks it.
    quint16 searchId = 0;
    QStringList seen;
    bool endOfSearch = false;
    for (int round = 0; round < 8 && !endOfSearch; ++round) {
        const QByteArray reply = round == 0
            ? session.feed(findFirstMessage(tid, QStringLiteral("\\lsdir\\*"), 0x0101, 1))
            : session.feed(findNextMessage(tid, searchId, 1, 0x0101));
        QCOMPARE(statusOf(reply), quint32(0));
        const QByteArray message = payloadOf(reply);
        const QByteArray parameters =
            message.mid(int(readLe16(message, 41)), int(readLe16(message, 39)));
        const QByteArray data =
            message.mid(int(readLe16(message, 47)), int(readLe16(message, 45)));

        if (round == 0) {
            searchId = readLe16(parameters, 0);
            QVERIFY2(searchId >= 0x200, "the search id is the session's, not the client's");
        }
        // FIND_FIRST2 answers SearchID first, and FIND_NEXT2 does not repeat it
        // (MS-CIFS 2.2.6.4 against 2.2.6.6), so the same two fields sit two
        // bytes earlier on a continuation.
        const int countAt = round == 0 ? 2 : 0;
        const int endAt = round == 0 ? 4 : 2;
        QCOMPARE(readLe16(parameters, countAt), quint16(1)); // SearchCount
        endOfSearch = readLe16(parameters, endAt) != 0;

        // One record, so nothing follows it: NextEntryOffset is zero, the name
        // length is a byte count, and SMB_FIND_FILE_DIRECTORY_INFO puts the
        // name at offset 64.
        QCOMPARE(readLe32(data, 0), quint32(0));
        const quint32 nameBytes = readLe32(data, 60);
        QVERIFY2(nameBytes > 0 && 64 + int(nameBytes) <= data.size(),
                 qPrintable(QStringLiteral("name length %1, data %2")
                                .arg(nameBytes).arg(data.size())));
        seen.append(decodeUtf16(data.mid(64, int(nameBytes))));
        // The attributes say which entry is a directory, and the directory's
        // size is reported as zero rather than as the size of its inode.
        // NextEntryOffset, FileIndex, four timestamps and two sizes come first,
        // so FileAttributes sits at 56 and the name length at 60.
        const quint32 attributes = readLe32(data, 56);
        QCOMPARE((attributes & 0x10u) != 0, seen.last() == QStringLiteral("nested"));
        if (seen.last() == QStringLiteral("nested"))
            QCOMPARE(readLe32(data, 40), quint32(0));
    }

    // QDir answers in name order, and every entry is here exactly once.
    QCOMPARE(seen, QStringList({QStringLiteral("alpha.txt"), QStringLiteral("beta.log"),
                                QStringLiteral("nested")}));

    // A wildcard narrows the same directory to one name, and the reply that
    // carries the last entry says so in EndOfSearch.
    const QByteArray txtReply =
        session.feed(findFirstMessage(tid, QStringLiteral("\\lsdir\\*.txt"), 0x0101, 10));
    QCOMPARE(statusOf(txtReply), quint32(0));
    const QByteArray txtMessage = payloadOf(txtReply);
    const QByteArray txtParams =
        txtMessage.mid(int(readLe16(txtMessage, 41)), int(readLe16(txtMessage, 39)));
    const QByteArray txtData =
        txtMessage.mid(int(readLe16(txtMessage, 47)), int(readLe16(txtMessage, 45)));
    QCOMPARE(readLe16(txtParams, 2), quint16(1)); // only alpha.txt
    QCOMPARE(readLe16(txtParams, 4), quint16(1)); // EndOfSearch
    QCOMPARE(decodeUtf16(txtData.mid(64, int(readLe32(txtData, 60)))),
             QStringLiteral("alpha.txt"));

    // A directory named without a wildcard lists what is inside it: this is
    // what `ls nested` sends, and answering with the directory itself instead
    // of its contents would make a client show one entry where there are two.
    const QByteArray subReply =
        session.feed(findFirstMessage(tid, QStringLiteral("\\lsdir\\nested"), 0x0101, 10));
    QCOMPARE(statusOf(subReply), quint32(0));
    const QByteArray subMessage = payloadOf(subReply);
    const QByteArray subParams =
        subMessage.mid(int(readLe16(subMessage, 41)), int(readLe16(subMessage, 39)));
    QCOMPARE(readLe16(subParams, 2), quint16(2));

    // A pattern that matches nothing is an error rather than an empty success,
    // because a client parses the first record out of the data block.
    QCOMPARE(statusOf(session.feed(
                 findFirstMessage(tid, QStringLiteral("\\lsdir\\*.zzz"), 0x0101, 10))),
             Smb1::kStatusNoSuchFile);
    // A directory that does not exist is named as such.
    QCOMPARE(statusOf(session.feed(
                 findFirstMessage(tid, QStringLiteral("\\nosuch\\*"), 0x0101, 10))),
             Smb1::kStatusObjectNameNotFound);
    // Continuing a search this session never opened is refused, so a client
    // cannot read another session's listing by guessing an id.
    QCOMPARE(statusOf(session.feed(findNextMessage(tid, 0x9999, 1, 0x0101))),
             Smb1::kStatusInvalidHandle);

    // A client closes the search it opened when it is done, and that call is
    // what retires the handle: a FIND_NEXT2 naming it afterwards is refused, so
    // a session cannot keep a search alive behind the client's back.
    QCOMPARE(statusOf(session.feed(findCloseMessage(tid, searchId))), quint32(0));
    QCOMPARE(statusOf(session.feed(findNextMessage(tid, searchId, 1, 0x0101))),
             Smb1::kStatusInvalidHandle);
    // A repeated close answers success rather than a refusal, which is what this
    // server does today; the refusal above is what shows the id was retired, and
    // this line is here so that staying that way is a decision rather than an
    // accident nobody looked at.
    QCOMPARE(statusOf(session.feed(findCloseMessage(tid, searchId))), quint32(0));
}

// A client that signs has to get signed replies and have its own signatures
// checked. Samba's dcerpc-over-SMB1 transport signs every PDU whatever the
// `client signing` setting says, which is how this was measured: with no reply
// signing, tree connect to SYSVOL and the Netlogon pipe both died on
// `smb1_signing_good: BAD SIG`, and the DC answered a flag it did not honour.
// The pre-extended form carries no negotiated flags, so the key the client
// signs with has to be built the way its own client builds it: Samba's
// smb1_signing_activate concatenates the user session key with the NTLM
// response it sent. Signing with the 16-byte key alone was refused
// `smb1_signing_good: BAD SIG: seq 1` on every reply while an unsigned session
// over the same form worked, which is why this went unnoticed.
void Smb1Test::signsAPreExtendedSecuritySessionTheWayTheClientKeysIt()
{
    const QByteArray baseKey = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    // legacySetupMessage sends a 48-byte NT response, so the MAC key is the
    // base key followed by those bytes.
    const QByteArray macKey = baseKey + QByteArray(48, 'n');
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    Smb1::Session session(
        QHash<QString, RpcServer *>(),
        [&baseKey](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            keys->sessionBaseKey = baseKey;
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
        QStringLiteral("monarchy.test"), shares);

    session.feed(negotiateMessage());
    QByteArray setup = legacySetupMessage(QStringLiteral("Administrator"),
                                          QStringLiteral("MONARCHY"));
    setup[10] = char(readLe16(setup, 10) | 0x0004);
    const QByteArray reply = session.feed(setup);
    QCOMPARE(statusOf(reply), quint32(0));
    QVERIFY2(signatureMatches(reply, macKey, 1),
             "the legacy session-setup reply is not keyed the way the client keys it");
    QVERIFY2(!signatureMatches(reply, baseKey, 1),
             "the reply was signed with the bare session base key");

    // One sequence numbers both directions here too, so the client's seq 2 tree
    // connect is answered by seq 3.
    const QByteArray treeReply = session.feed(signedMessage(
        treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")), macKey, 2));
    QCOMPARE(statusOf(treeReply), quint32(0));
    QVERIFY2(signatureMatches(treeReply, macKey, 3), "the reply to seq 2 is not seq 3");
}

void Smb1Test::signsAndVerifiesASignedSession()
{
    const QByteArray key = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    QHash<QString, QString> shares;
    shares.insert(QStringLiteral("sysvol"), m_root.path());
    Smb1::Session session(
        QHash<QString, RpcServer *>(),
        [&key](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            keys->sessionBaseKey = key;
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
        QStringLiteral("monarchy.test"), shares);

    // Before a session key exists there is nothing to sign with, and a reply
    // that claimed a signature would be lying.
    const QByteArray negotiateReply = session.feed(negotiateMessage());
    QCOMPARE(readLe16(payloadOf(negotiateReply), 10) & 0x0004, quint16(0));

    QByteArray type1("NTLMSSP", 7);
    type1.append(char(0));
    putLe32(type1, 1);
    putLe32(type1, 0x00008201u);
    QCOMPARE(statusOf(session.feed(sessionSetupMessage(type1))),
             Smb1::kStatusMoreProcessingRequired);

    // A client that means to sign says so on the session-setup request, before it
    // has a key to sign with, and the accepted reply is then sequence number 1.
    QByteArray type3Setup = sessionSetupMessage(
        authenticateToken(QStringLiteral("alice"), QStringLiteral("MONARCHY")));
    type3Setup[10] = char(readLe16(type3Setup, 10) | 0x0004);
    const QByteArray acceptReply = session.feed(type3Setup);
    QCOMPARE(statusOf(acceptReply), quint32(0));
    QVERIFY2(signatureMatches(acceptReply, key, 1), "the first signed reply is not seq 1");

    // One sequence numbers both directions, so the client's seq 2 request is
    // answered by seq 3. Samba's client verified exactly this: it logged
    // "seq 1: got good", signed its tree connect as 2, and expected 3 back.
    const QByteArray treeReply = session.feed(signedMessage(
        treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")), key, 2));
    QCOMPARE(statusOf(treeReply), quint32(0));
    QVERIFY2(signatureMatches(treeReply, key, 3), "the reply to seq 2 is not seq 3");

    // A signature that does not cover the message is refused before dispatch, so
    // a signed request cannot be altered in flight and still be executed.
    QByteArray forged = signedMessage(
        treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")), key, 4);
    forged[24] = char(0x77); // a TID the signature above never covered
    QCOMPARE(statusOf(session.feed(forged)), Smb1::kStatusAccessDenied);

    // Once the connection is signing, its replies stay signed: the sequence
    // belongs to the session, not to the message.
    const QByteArray afterForgery =
        session.feed(treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")));
    QCOMPARE(statusOf(afterForgery), quint32(0));
    QVERIFY(signatureMatches(afterForgery, key, 5));

    // A session that never signalled intent — Windows 2000 with no signing
    // policy — is served too, and its replies claim no signature.
    Smb1::Session plain(
        QHash<QString, RpcServer *>(),
        [&key](const Rpc::AuthRequest &, Ntlm::SessionKeys *keys) {
            *keys = Ntlm::SessionKeys();
            keys->sessionBaseKey = key;
            return true;
        },
        QStringLiteral("MONARCHY"), QStringLiteral("DC1"),
        QStringLiteral("monarchy.test"), shares);
    plain.feed(negotiateMessage());
    plain.feed(sessionSetupMessage(type1));
    QCOMPARE(statusOf(plain.feed(sessionSetupMessage(
                 authenticateToken(QStringLiteral("alice"), QStringLiteral("MONARCHY"))))),
             quint32(0));
    const QByteArray plainReply =
        plain.feed(treeConnectMessage(QStringLiteral("\\\\dc1\\SYSVOL")));
    QCOMPARE(statusOf(plainReply), quint32(0));
    QCOMPARE(readLe16(payloadOf(plainReply), 10) & 0x0004, quint16(0));
}

QTEST_GUILESS_MAIN(Smb1Test)
#include "test_smb1.moc"
