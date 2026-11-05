// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QFile>
#include <QTemporaryDir>

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

} // namespace

class Smb1Test : public QObject
{
    Q_OBJECT

private slots:
    void readsAPolicyFileFromSysvol();
    void opensATerminatedNameAndReportsAttributes();
    void refusesAnAnonymousTreeConnect();
    void refusesAnUnknownShare();
    void refusesTraversalOutOfTheShare();
    void refusesWrites();

private:
    QTemporaryDir m_root;
    QByteArray m_fileBytes;
    QString m_fileRelative;

    Smb1::Session *authenticatedSession();
    quint16 connectShare(Smb1::Session *session, const QString &share);
};

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

QTEST_GUILESS_MAIN(Smb1Test)
#include "test_smb1.moc"
