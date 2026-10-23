// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "Epm.h"
#include "Smb2.h"

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

} // namespace

class Smb2Test : public QObject
{
    Q_OBJECT

private slots:
    void negotiatesTheHighestOfferedDialect();
    void opensATreeAndAPipe();
    void refusesAnUnknownPipeAndUnknownShare();
    void carriesADceBindThroughThePipe();
};

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

QTEST_MAIN(Smb2Test)
#include "test_smb2.moc"
