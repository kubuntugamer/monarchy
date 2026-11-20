// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Srvsvc.h"

#include "Ndr.h"

namespace {

// Windows error codes MS-SRVS returns in place of a container.
constexpr quint32 kSuccess = 0x00000000u;
constexpr quint32 kErrorNotSupported = 0x00000032u;   // ERROR_NOT_SUPPORTED
constexpr quint32 kErrorInvalidParameter = 0x00000057u; // ERROR_INVALID_PARAMETER
constexpr quint32 kErrorInvalidLevel = 0x0000007cu;     // ERROR_INVALID_LEVEL

// The referent ids the answer allocates, in the order NDR writes them: the
// SHARE_ENUM_STRUCT and the array inside it come first, then one per deferred
// string, then the resume handle.
constexpr quint32 kContainerReferent = 0x00020000u;
constexpr quint32 kBufferReferent = 0x00020004u;
constexpr quint32 kFirstStringReferent = 0x00020008u;

void putLe32(QByteArray &out, quint32 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16)
           | (quint32(quint8(data.at(pos + 3))) << 24);
}

void alignTo(QByteArray &out, int boundary)
{
    while (out.size() % boundary != 0)
        out.append('\0');
}

// A `[string]` buffer as NDR defers it: maximum count, offset, actual count and
// the UTF-16 characters. Both counts include the terminator, and the terminator
// travels — which is what Samba's encoder produces and what MS-SRVS 2.2.2.2
// describes. An empty string is still a present pointer, so it is one
// terminator and nothing else.
void appendString(QByteArray &out, const QString &text)
{
    const QByteArray utf16 = Ndr::utf16le(text);
    const quint32 count = quint32(text.size() + 1);
    putLe32(out, count); // MaximumCount
    putLe32(out, 0);     // Offset
    putLe32(out, count); // ActualCount
    out.append(utf16);
    out.append(QByteArray(2, '\0'));
    alignTo(out, 4);
}

// The level a client asked for. NetrShareEnum and NetrShareEnumSticky take a
// [unique,string] ServerName, then the [in,out,ref] SHARE_ENUM_STRUCT, whose
// first word is the level and whose second repeats it as the union tag.
// Clients that send ServerName inline (a conformant array rather than a
// referent) shift those words, so the pair is looked for at 4-byte offsets
// instead of assumed to sit at a fixed one.
bool requestedLevel(const QByteArray &stub, quint32 *level)
{
    // The level is read whoever asked for it: a level this server cannot answer
    // is still a level, and has to be refused with ERROR_INVALID_LEVEL rather
    // than mistaken for a malformed request.
    if (stub.size() >= 12) {
        const quint32 candidate = readLe32(stub, 4);
        if (candidate == readLe32(stub, 8)) {
            *level = candidate;
            return true;
        }
    }
    for (int at = 0; at + 8 <= stub.size() && at < 64; at += 4) {
        const quint32 candidate = readLe32(stub, at);
        if (candidate <= 2 && readLe32(stub, at + 4) == candidate) {
            *level = candidate;
            return true;
        }
    }
    return false;
}

// netr_ShareEnum's reply, exactly as Samba's NDR encoder lays it out (the
// vectors this is pinned against came from samba.dcerpc.srvsvc):
//
//   level, tag, container referent
//   EntriesRead, Buffer referent, MaxCount, the entries
//   every deferrred string, in referent order
//   TotalEntries, resume-handle referent, resume-handle value, status
//
// Level 1 entries are name/type/comment; level 2 entries add the path and the
// four scalars Windows puts between the comment and it (password NULL,
// max_users unlimited, current_users zero, permissions zero).
QByteArray enumerateReply(quint32 level, const QList<Srvsvc::Share> &shares)
{
    QByteArray out;
    QByteArray deferred;
    quint32 referent = kFirstStringReferent;

    const quint32 count = quint32(shares.size());
    putLe32(out, level);
    putLe32(out, level);
    putLe32(out, kContainerReferent);
    putLe32(out, count);           // EntriesRead
    // A Windows server sends a present buffer even when it holds nothing, so
    // the pointer is never NULL and MaxCount is always on the wire.
    putLe32(out, kBufferReferent);
    putLe32(out, count);           // MaxCount

    for (const Srvsvc::Share &share : shares) {
        putLe32(out, referent);
        referent += 4;
        putLe32(out, share.type);
        putLe32(out, referent);
        referent += 4;
        if (level >= 2) {
            putLe32(out, 0);           // password: NULL
            putLe32(out, 0xffffffffu); // max_users: unlimited
            putLe32(out, 0);           // current_users
            putLe32(out, referent);
            referent += 4;
            putLe32(out, 0);           // permissions
        }
        appendString(deferred, share.name);
        appendString(deferred, share.comment);
        if (level >= 2)
            appendString(deferred, share.path);
    }

    out.append(deferred);
    putLe32(out, count);   // TotalEntries
    putLe32(out, referent); // ResumeHandle referent
    putLe32(out, 0);        // nothing left after this answer
    putLe32(out, kSuccess);
    return out;
}

QByteArray statusOnly(quint32 status)
{
    QByteArray out;
    putLe32(out, status);
    return out;
}

} // namespace

namespace Srvsvc {

Rpc::Interface interface()
{
    Rpc::Interface out;
    // 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0 on the wire: the first three
    // fields are little-endian, the last eight bytes travel as written.
    out.uuid = QByteArray::fromHex("c84f324b7016d30112785a47bf6ee188");
    out.major = 3;
    out.minor = 0;
    out.name = QStringLiteral("srvsvc");
    return out;
}

} // namespace Srvsvc

SrvsvcServer::SrvsvcServer(QObject *parent) : QObject(parent)
{
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Srvsvc::interface(),
                        [this](const Rpc::Call &call) { return handleCall(call.opnum, call.stub); });
    connect(m_rpc, &RpcServer::requestReceived, this, &SrvsvcServer::requestReceived);
}

void SrvsvcServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_rpc->setAuthenticator(std::move(authenticator));
}

bool SrvsvcServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void SrvsvcServer::close()
{
    m_rpc->close();
}

bool SrvsvcServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 SrvsvcServer::serverPort() const
{
    return m_rpc->serverPort();
}

QByteArray SrvsvcServer::handleCall(quint16 opnum, const QByteArray &stub)
{
    if (opnum != Srvsvc::OpNetrShareEnum && opnum != Srvsvc::OpNetrShareEnumSticky)
        return statusOnly(kErrorNotSupported);
    return enumerate(stub);
}

QByteArray SrvsvcServer::enumerate(const QByteArray &stub)
{
    quint32 level = 0;
    if (!requestedLevel(stub, &level))
        return statusOnly(kErrorInvalidParameter);
    // Levels 1 and 2 are what a Windows client asks for and what this server
    // can answer: 1 lists share, type and comment, 2 adds the local path.
    if (level > 2)
        return statusOnly(kErrorInvalidLevel);

    emit requestReceived(QStringLiteral("srvsvc NetrShareEnum level %1").arg(level));
    return enumerateReply(level, m_shares);
}
