// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Epm.h"

#include <QDebug>

#include "Ndr.h"

// Wire notes, all of them checked against a client rather than assumed:
//
// * The tower is not NDR. C706 appendix L: a 2-byte floor count, then each floor
//   as a 2-byte left-hand-side length, the LHS, a 2-byte right-hand-side length
//   and the RHS. Counts are little-endian; a TCP port and an IPv4 address are
//   big-endian, which is the one place the encoding is not uniform.
// * The interface and data-representation floors carry a protocol id byte
//   (0x0d) before the UUID and the major version, with the minor version in the
//   RHS. The binder floor (0x0b) carries the minor version in the LHS and the
//   transport (0x07 = TCP) and address (0x09 = IP) floors follow it.
// * `epm_entry_t.annotation` is written offset first and length second
//   (epmapper.idl names the fields __annotation_offset/__annotation_length), and
//   the length counts the terminating NUL, so an empty annotation still travels
//   as one byte.
// * The towers a lookup returns are deferred to the end of the reply, after the
//   array's fixed part; the status follows them. Both were confirmed by having
//   impacket marshal the same response and parsing the bytes back.
namespace {

constexpr quint8 kProtocolUuid = 0x0d;   // C706 appendix I: UUID floor
constexpr quint8 kProtocolNcacn = 0x0b;  // connection-oriented RPC
constexpr quint8 kProtocolTcp = 0x07;
constexpr quint8 kProtocolIp = 0x09;
constexpr quint8 kProtocolNamedPipe = 0x0f;
constexpr quint8 kProtocolNetBios = 0x11;

// 8a885d04-1ceb-11c9-9fe8-08002b104860 v2: NDR32, the transfer syntax every
// reply here is encoded in.
const QByteArray kNdr32Uuid = QByteArray::fromHex("04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60");

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

void putBe16(QByteArray &out, quint16 value)
{
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void align4(QByteArray &out)
{
    while (out.size() % 4 != 0)
        out.append('\0');
}

void appendFloor(QByteArray &tower, const QByteArray &left, const QByteArray &right)
{
    putLe16(tower, quint16(left.size()));
    tower.append(left);
    putLe16(tower, quint16(right.size()));
    tower.append(right);
}

// One uuid floor: protocol id, UUID, then the major version on the left and the
// minor on the right.
void appendUuidFloor(QByteArray &tower, const QByteArray &uuid, quint16 major, quint16 minor)
{
    QByteArray left;
    left.append(char(kProtocolUuid));
    left.append(uuid);
    putLe16(left, major);
    QByteArray right;
    putLe16(right, minor);
    appendFloor(tower, left, right);
}

void appendProtocolFloor(QByteArray &tower, quint8 protocol, quint16 minor)
{
    QByteArray left;
    left.append(char(protocol));
    QByteArray right;
    putLe16(right, minor);
    appendFloor(tower, left, right);
}

// A lookup's request. The two clients that matter disagree about two things:
// whether the entry handle is the 20-byte structure inline or a referent with
// the structure deferred, and where an inlined interface id sits. Parsing tries
// both and keeps the reading that consumes the stub exactly and yields a sane
// maximum count.
struct LookupArgs {
    quint32 inquiry = 0;
    bool objectPresent = false;
    QByteArray object; // 16 bytes
    bool interfacePresent = false;
    QByteArray uuid; // 16 bytes
    quint16 major = 0;
    quint16 minor = 0;
    quint32 versionOption = 0;
    quint32 maxEntries = 0;
    quint32 handleAttributes = 0;
    QByteArray handle; // 16 bytes
    bool inlineForm = true;
};

bool parseLookupForm(const QByteArray &stub, bool inlineForm, LookupArgs *args)
{
    Ndr::Reader reader(stub);
    quint32 objectReferent = 0;
    quint32 interfaceReferent = 0;
    quint32 handleReferent = 0;
    if (!reader.u32(&args->inquiry) || !reader.u32(&objectReferent)
        || !reader.u32(&interfaceReferent))
        return false;

    args->objectPresent = objectReferent != 0;
    args->interfacePresent = interfaceReferent != 0;

    if (inlineForm) {
        // impacket: the interface id, when present, is written at its referent's
        // position rather than deferred.
        if (args->interfacePresent
            && (!reader.bytes(16, &args->uuid) || !reader.u16(&args->major)
                || !reader.u16(&args->minor)))
            return false;
        if (!reader.u32(&args->versionOption))
            return false;
        QByteArray handle;
        if (!reader.bytes(20, &handle))
            return false;
        args->handleAttributes = quint32(quint8(handle.at(0)));
        args->handle = handle.mid(4, 16);
        if (!reader.u32(&args->maxEntries))
            return false;
        if (args->objectPresent && !reader.bytes(16, &args->object))
            return false;
    } else {
        if (!reader.u32(&args->versionOption) || !reader.u32(&handleReferent)
            || !reader.u32(&args->maxEntries))
            return false;
        // Deferred pointees, in the order their referents were met.
        if (args->objectPresent && !reader.bytes(16, &args->object))
            return false;
        if (args->interfacePresent
            && (!reader.bytes(16, &args->uuid) || !reader.u16(&args->major)
                || !reader.u16(&args->minor)))
            return false;
        if (handleReferent != 0) {
            QByteArray handle;
            if (!reader.bytes(20, &handle))
                return false;
            args->handleAttributes = quint32(quint8(handle.at(0)));
            args->handle = handle.mid(4, 16);
        } else {
            args->handle = QByteArray(16, '\0');
        }
    }

    args->inlineForm = inlineForm;
    if (!args->handle.isEmpty() && args->handle.size() != 16)
        return false;
    if (args->maxEntries == 0 || args->maxEntries > 4096)
        return false;
    if (args->inquiry > Epm::InquiryMatchByBoth)
        return false;
    if (args->versionOption > Epm::VersionUpTo)
        return false;
    return reader.remaining() >= 0 && reader.remaining() < 4;
}

bool parseLookup(const QByteArray &stub, LookupArgs *args)
{
    LookupArgs inlineAttempt;
    if (parseLookupForm(stub, true, &inlineAttempt)) {
        *args = inlineAttempt;
        return true;
    }
    LookupArgs pointerAttempt;
    if (parseLookupForm(stub, false, &pointerAttempt)) {
        *args = pointerAttempt;
        return true;
    }
    return false;
}

// The paging state a lookup handle carries: the offset of the next entry.
quint32 handleOffset(const QByteArray &handle)
{
    if (handle.size() != 16)
        return 0;
    return quint32(quint8(handle.at(0))) | (quint32(quint8(handle.at(1))) << 8)
           | (quint32(quint8(handle.at(2))) << 16) | (quint32(quint8(handle.at(3))) << 24);
}

QByteArray makeHandle(quint32 offset)
{
    QByteArray handle(16, '\0');
    handle[0] = char(offset & 0xff);
    handle[1] = char((offset >> 8) & 0xff);
    handle[2] = char((offset >> 16) & 0xff);
    handle[3] = char((offset >> 24) & 0xff);
    return handle;
}

bool versionMatches(const Epm::Entry &entry, quint32 option, quint16 major, quint16 minor)
{
    switch (option) {
    case Epm::VersionExact:
        return entry.major == major && entry.minor == minor;
    case Epm::VersionCompatible:
    case Epm::VersionMajorOnly:
        return entry.major == major;
    case Epm::VersionUpTo:
        return entry.major == major && entry.minor <= minor;
    case Epm::VersionAll:
    default:
        return true;
    }
}

// The annotation as the wire carries it: NUL-terminated, length counting the
// terminator, and always at least that one byte.
QByteArray annotationBytes(const QString &text)
{
    QByteArray bytes = text.toUtf8();
    bytes.append('\0');
    return bytes;
}

} // namespace

namespace Epm {

Rpc::Interface interface()
{
    Rpc::Interface iface;
    // e1af8308-5d1f-11c9-91a4-08002b14a0fa, the endpoint mapper, v3.0.
    iface.uuid = QByteArray::fromHex("08 83 af e1 1f 5d c9 11 91 a4 08 00 2b 14 a0 fa");
    iface.major = 3;
    iface.minor = 0;
    iface.name = QStringLiteral("EPM");
    return iface;
}

QByteArray tower(const Entry &entry, const QHostAddress &address, const QString &hostName)
{
    QByteArray out;
    putLe16(out, 5); // floors
    appendUuidFloor(out, entry.uuid, entry.major, entry.minor);
    appendUuidFloor(out, kNdr32Uuid, 2, 0);
    appendProtocolFloor(out, kProtocolNcacn, 0);

    if (entry.isPipe()) {
        // Named-pipe transport floor: the pipe's full DOS name. The host floor
        // that follows names the server without a domain, upper-cased, which is
        // what a client matches an ncacn_np tower against.
        QByteArray pipeLeft;
        pipeLeft.append(char(kProtocolNamedPipe));
        QByteArray pipeRight;
        pipeRight.append("\\pipe\\");
        pipeRight.append(entry.pipe.toUtf8());
        pipeRight.append('\0');
        appendFloor(out, pipeLeft, pipeRight);

        QByteArray hostLeft;
        hostLeft.append(char(kProtocolNetBios));
        QByteArray hostRight;
        hostRight.append(hostName.toUpper().toUtf8());
        hostRight.append('\0');
        appendFloor(out, hostLeft, hostRight);
        return out;
    }

    // Transport floor: the TCP port, big-endian (C706 appendix I).
    QByteArray left;
    left.append(char(kProtocolTcp));
    QByteArray right;
    putBe16(right, entry.port);
    appendFloor(out, left, right);

    // Address floor: the IPv4 address, big-endian. A non-IPv4 advertisement has
    // no floor encoding here, so it travels as zeroes rather than as a guess.
    QByteArray ipLeft;
    ipLeft.append(char(kProtocolIp));
    QByteArray ipRight(4, '\0');
    const quint32 ipv4 = address.toIPv4Address();
    if (ipv4 != 0) {
        ipRight[0] = char((ipv4 >> 24) & 0xff);
        ipRight[1] = char((ipv4 >> 16) & 0xff);
        ipRight[2] = char((ipv4 >> 8) & 0xff);
        ipRight[3] = char(ipv4 & 0xff);
    }
    appendFloor(out, ipLeft, ipRight);
    return out;
}

} // namespace Epm

EpmServer::EpmServer(QObject *parent)
    : QObject(parent)
    , m_rpc(new RpcServer(this))
{
    m_rpc->setInterface(Epm::interface(), [this](const Rpc::Call &call) {
        return handleCall(call.opnum, call.stub);
    });
    connect(m_rpc, &RpcServer::requestReceived, this, &EpmServer::requestReceived);
}

void EpmServer::setEntries(const QList<Epm::Entry> &entries)
{
    m_entries = entries;
}

void EpmServer::setAdvertisedAddress(const QHostAddress &address)
{
    m_address = address;
}

void EpmServer::setHostName(const QString &hostName)
{
    m_hostName = hostName;
}

bool EpmServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void EpmServer::close()
{
    m_rpc->close();
}

bool EpmServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 EpmServer::serverPort() const
{
    return m_rpc->serverPort();
}

QByteArray EpmServer::handleCall(quint16 opnum, const QByteArray &stub)
{
    switch (opnum) {
    case Epm::OpLookup:
        return lookup(stub);
    case Epm::OpMap:
        return map(stub);
    case Epm::OpLookupHandleFree: {
        // [in,out] handle: the same shape a lookup returns, cleared.
        QByteArray freed(20, '\0');
        putLe32(freed, Epm::StatusOk);
        return freed;
    }
    default:
        // InqObject names an object UUID, and Insert/Delete/MgmtDelete write the
        // mapper's table; a DC's table is the set of interfaces it serves and
        // none of them carries an object UUID, so these are refused the way C706
        // refuses an operation the mapper cannot perform rather than accepted
        // and dropped.
        return [] {
            QByteArray reply;
            putLe32(reply, Epm::StatusCantPerformOp);
            return reply;
        }();
    }
}

QByteArray EpmServer::lookup(const QByteArray &stub)
{
    LookupArgs args;
    if (!parseLookup(stub, &args)) {
        QByteArray reply;
        putLe32(reply, Epm::StatusCantPerformOp);
        return reply;
    }

    QList<Epm::Entry> matches;
    for (const Epm::Entry &entry : m_entries) {
        if (args.inquiry == Epm::InquiryMatchByInterface
            || args.inquiry == Epm::InquiryMatchByBoth) {
            if (!args.interfacePresent || entry.uuid != args.uuid)
                continue;
            if (!versionMatches(entry, args.versionOption, args.major, args.minor))
                continue;
        } else if (args.inquiry == Epm::InquiryMatchByObject) {
            // Nothing here carries an object UUID.
            continue;
        }
        matches.append(entry);
    }

    const quint32 offset = handleOffset(args.handle);
    const quint32 total = quint32(matches.size());
    if (offset >= total && total != 0) {
        // Past the end: the client is asking a handle it already exhausted.
        QByteArray reply(20, '\0');
        putLe32(reply, Epm::StatusNoMoreEntries);
        return reply;
    }

    const quint32 count = qMin(args.maxEntries, total - offset);
    const bool more = offset + count < total;

    QByteArray reply;
    // The entry handle: 20 bytes, the structure inline (C706 writes the handle
    // in place; a client sends it back on the next page request).
    if (more) {
        putLe32(reply, 1); // handle type
        reply.append(makeHandle(offset + count));
    } else {
        reply.append(QByteArray(20, '\0'));
    }
    putLe32(reply, count);          // num_ents
    putLe32(reply, args.maxEntries); // MaximumCount
    putLe32(reply, 0);               // Offset
    putLe32(reply, count);           // ActualCount

    // The array's fixed part: every entry, with each tower as a referent that is
    // filled in after the array.
    const quint32 baseReferent = 0x00020000u;
    QList<QByteArray> towers;
    for (quint32 i = 0; i < count; ++i) {
        const Epm::Entry &entry = matches.at(int(offset + i));
        towers.append(Epm::tower(entry, m_address, m_hostName));
        reply.append(QByteArray(16, '\0')); // object: no object UUID on these
        putLe32(reply, baseReferent + i);
        align4(reply);
        const QByteArray annotation = annotationBytes(entry.annotation);
        putLe32(reply, 0);                          // __annotation_offset
        putLe32(reply, quint32(annotation.size())); // __annotation_length
        reply.append(annotation);
        align4(reply);
    }

    // The deferred towers, in referent order.
    for (const QByteArray &tower : towers) {
        putLe32(reply, quint32(tower.size()));
        putLe32(reply, quint32(tower.size()));
        reply.append(tower);
        align4(reply);
    }
    putLe32(reply, Epm::StatusOk);
    return reply;
}

QByteArray EpmServer::map(const QByteArray &stub)
{
    // ept_map: [in,ptr] object, [in,ptr] map_tower, [in,out] handle,
    // [in] max_towers. The tower's first floor names the interface wanted. As
    // with a lookup, one client writes each referent's data where the referent
    // is and the other defers it behind the whole argument list, so both orders
    // are parsed and the one that consumes the request exactly is kept.
    const auto fail = [] {
        QByteArray reply;
        putLe32(reply, Epm::StatusCantPerformOp);
        return reply;
    };

    QByteArray towerBytes;
    quint32 maxTowers = 0;
    bool parsed = false;
    for (int form = 0; form < 2 && !parsed; ++form) {
        const bool inlineForm = form == 0;
        Ndr::Reader reader(stub);
        quint32 objectReferent = 0;
        quint32 towerReferent = 0;
        quint32 handleReferent = 0;
        quint32 handleAttributes = 0;
        towerBytes.clear();
        maxTowers = 0;
        if (!reader.u32(&objectReferent))
            continue;
        if (inlineForm) {
            if (objectReferent != 0 && !reader.skip(16))
                continue;
            if (!reader.u32(&towerReferent))
                continue;
            if (towerReferent != 0) {
                quint32 length = 0;
                quint32 maximum = 0;
                if (!reader.u32(&length) || !reader.u32(&maximum)
                    || !reader.bytes(int(length), &towerBytes))
                    continue;
            }
            if (!reader.u32(&handleAttributes) || !reader.skip(16) || !reader.u32(&maxTowers))
                continue;
        } else {
            if (!reader.u32(&towerReferent) || !reader.u32(&handleReferent)
                || !reader.u32(&maxTowers))
                continue;
            if (objectReferent != 0 && !reader.skip(16))
                continue;
            if (towerReferent != 0) {
                quint32 length = 0;
                quint32 maximum = 0;
                if (!reader.u32(&length) || !reader.u32(&maximum)
                    || !reader.bytes(int(length), &towerBytes))
                    continue;
            }
            if (handleReferent != 0)
                reader.skip(20);
        }
        // A tower is at least a floor count and one floor; anything shorter is
        // the other form's reading, not a real tower.
        if (towerBytes.size() < 4)
            continue;
        parsed = true;
    }
    if (!parsed)
        return fail();

    // Read the request tower's floors: floor 1 names the interface, floor 4 the
    // transport it is being asked for (0x07 tcp, 0x0f named pipe). The answer
    // must match both, or a client that asked for a pipe gets a TCP tower back
    // and reads it as a pipe.
    QByteArray wantedUuid;
    quint16 wantedMajor = 0;
    QList<quint8> protocols;
    if (towerBytes.size() >= 24) {
        const int floorCount = quint8(towerBytes.at(0)) | (quint8(towerBytes.at(1)) << 8);
        int at = 2;
        for (int i = 0; i < floorCount && at + 4 <= towerBytes.size(); ++i) {
            const int lhsLength = quint8(towerBytes.at(at)) | (quint8(towerBytes.at(at + 1)) << 8);
            if (lhsLength < 1 || at + 2 + lhsLength + 2 > towerBytes.size())
                break;
            const quint8 protocol = quint8(towerBytes.at(at + 2));
            protocols.append(protocol);
            if (i == 0 && lhsLength >= 19 && protocol == kProtocolUuid) {
                wantedUuid = towerBytes.mid(at + 3, 16);
                if (lhsLength >= 21)
                    wantedMajor = quint16(quint8(towerBytes.at(at + 3 + 16))
                                          | (quint8(towerBytes.at(at + 3 + 17)) << 8));
            }
            const int rhsLength =
                quint8(towerBytes.at(at + 2 + lhsLength))
                | (quint8(towerBytes.at(at + 2 + lhsLength + 1)) << 8);
            at += 2 + lhsLength + 2 + rhsLength;
        }
    }
    const quint8 wantedTransport = protocols.size() > 3 ? protocols.at(3) : 0;

    QList<Epm::Entry> matches;
    for (const Epm::Entry &entry : m_entries) {
        if (wantedUuid.isEmpty() || entry.uuid != wantedUuid)
            continue;
        if (wantedMajor != 0 && entry.major != wantedMajor)
            continue;
        if (wantedTransport == kProtocolNamedPipe && !entry.isPipe())
            continue;
        if (wantedTransport == kProtocolTcp && entry.isPipe())
            continue;
        matches.append(entry);
    }
    if (matches.isEmpty()) {
        // Either the tower named no interface or nothing here serves it. C706
        // reports an empty answer rather than an error, so the caller learns
        // there is no endpoint instead of retrying a call that cannot succeed.
        QByteArray empty(20, '\0');
        putLe32(empty, 0); // num_towers
        putLe32(empty, 1); // MaximumCount
        putLe32(empty, 0); // Offset
        putLe32(empty, 0); // ActualCount
        putLe32(empty, Epm::StatusNoMoreEntries);
        return empty;
    }

    const quint32 count = qMin(maxTowers == 0 ? 1u : maxTowers, quint32(matches.size()));
    QByteArray reply;
    reply.append(QByteArray(20, '\0')); // no paging: every tower fits one reply
    putLe32(reply, count);
    putLe32(reply, maxTowers == 0 ? 1u : maxTowers);
    putLe32(reply, 0);
    putLe32(reply, count);
    for (quint32 i = 0; i < count; ++i)
        putLe32(reply, 0x00020000u + i);
    for (quint32 i = 0; i < count; ++i) {
        const QByteArray tower = Epm::tower(matches.at(int(i)), m_address, m_hostName);
        putLe32(reply, quint32(tower.size()));
        putLe32(reply, quint32(tower.size()));
        reply.append(tower);
        align4(reply);
    }
    putLe32(reply, Epm::StatusOk);
    return reply;
}
