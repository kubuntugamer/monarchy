// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "DrsClient.h"

#include <QDateTime>
#include <QDeadlineTimer>
#include <QTcpSocket>
#include <QUuid>

#include "Drs.h"
#include "Ndr.h"

namespace {

// DCE/RPC PDU types (DCE 1.1 §12.6) and the fragment flag this client joins on.
constexpr quint8 PduRequest = 0;
constexpr quint8 PduResponse = 2;
constexpr quint8 PduFault = 3;
constexpr quint8 PduBind = 11;
constexpr quint8 PduBindAck = 12;
constexpr quint8 PduBindNak = 13;
constexpr quint8 PduAuth3 = 16; // MS-RPCE PTYPE_AUTH3
constexpr quint8 PduFlagLast = 0x02;

// RPC_C_AUTHN_WINNT: NTLMSSP as the RPC security provider (MS-RPCE §2.2.3).
constexpr quint8 AuthTypeNtlm = 10;

constexpr int kHeaderSize = 16;
constexpr int kResponseHeader = 24; // alloc_hint, context, cancel_count, reserved
constexpr quint16 kMaxFrag = 5840;
constexpr int kAuthTokenSize = 16; // one NTLMSSP_MESSAGE_SIGNATURE

constexpr quint32 kWerrOk = 0;
constexpr quint32 kResultAcceptance = 0;

// ATTIDs the server emits (MS-DRSR §5.12.2 prefix map). Anything outside this
// set is skipped rather than invented into an attribute name.
constexpr quint32 kAttidObjectClass = 0x00000000u;
constexpr quint32 kAttidCn = 0x00000003u;
constexpr quint32 kAttidDescription = 0x0000000Du;
constexpr quint32 kAttidMember = 0x0000001Fu;
constexpr quint32 kAttidDistinguishedName = 0x00000031u;
constexpr quint32 kAttidInstanceType = 0x00020001u;
constexpr quint32 kAttidWhenCreated = 0x00020002u;
constexpr quint32 kAttidName = 0x00090001u;
constexpr quint32 kAttidObjectGuid = 0x00090002u;
constexpr quint32 kAttidIsDeleted = 0x00090003u;
constexpr quint32 kAttidUserAccountControl = 0x00090008u;
constexpr quint32 kAttidObjectSid = 0x00090092u;
constexpr quint32 kAttidSamAccountName = 0x000900DDu;
constexpr quint32 kAttidUserPrincipalName = 0x00090290u;
constexpr quint32 kAttidWhenChanged = 0x00020003u;

quint32 negotiationFlags()
{
    return Ntlm::kNegotiateUnicode | Ntlm::kNegotiateNtlm | Ntlm::kNegotiateSign
           | Ntlm::kNegotiateSeal | Ntlm::kNegotiateAlwaysSign
           | Ntlm::kNegotiateExtendedSessionSecurity | Ntlm::kNegotiateTargetInfo
           | Ntlm::kNegotiate128 | Ntlm::kNegotiate56;
}

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
    putLe32(out, quint32(value >> 32));
}

quint16 readLe16(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(pos)) | (quint8(data.at(pos + 1)) << 8));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16)
           | (quint32(quint8(data.at(pos + 3))) << 24);
}

quint64 readLe64(const QByteArray &data, int pos)
{
    return quint64(readLe32(data, pos)) | (quint64(readLe32(data, pos + 4)) << 32);
}

void padTo4(QByteArray &out)
{
    while (out.size() % 4 != 0)
        out.append('\0');
}

void padTo8(QByteArray &out)
{
    while (out.size() % 8 != 0)
        out.append('\0');
}

// Common 16-byte header: version, type, flags, data representation, lengths.
void appendHeader(QByteArray &out, quint8 type, quint32 callId)
{
    out.append(char(5));    // rpc_vers
    out.append(char(0));    // rpc_vers_minor
    out.append(char(type)); // PTYPE
    out.append(char(0x03)); // PFC_FIRST_FRAG | PFC_LAST_FRAG
    out.append(char(0x10)); // little-endian
    out.append(char(0));
    out.append(char(0));
    out.append(char(0));
    putLe16(out, 0); // frag_length, patched below
    putLe16(out, 0); // auth_length, patched by appendAuthVerifier
    putLe32(out, callId);
}

void patchFragmentLength(QByteArray &pdu)
{
    const quint16 length = quint16(pdu.size());
    pdu[8] = char(length & 0xff);
    pdu[9] = char((length >> 8) & 0xff);
}

// sec_trailer (MS-RPCE §2.2.2.11) followed by the token. The trailer's pad
// length tells the receiver how much of the body is alignment, which is why a
// signed stub is padded before the signature is computed.
void appendAuthVerifier(QByteArray &pdu, quint8 authType, quint8 authLevel, quint8 padLength,
                        quint32 contextId, const QByteArray &token)
{
    pdu.append(char(authType));
    pdu.append(char(authLevel));
    pdu.append(char(padLength));
    pdu.append(char(0));
    putLe32(pdu, contextId);
    pdu.append(token);
    const quint16 authLength = quint16(token.size());
    pdu[10] = char(authLength & 0xff);
    pdu[11] = char((authLength >> 8) & 0xff);
    patchFragmentLength(pdu);
}

QByteArray guidBytes(const QUuid &guid)
{
    QByteArray out;
    putLe32(out, guid.data1);
    putLe16(out, guid.data2);
    putLe16(out, guid.data3);
    out.append(reinterpret_cast<const char *>(guid.data4), 8);
    return out;
}

QUuid guidFromBytes(const QByteArray &bytes)
{
    if (bytes.size() != 16)
        return QUuid();
    return QUuid(readLe32(bytes, 0), readLe16(bytes, 4), readLe16(bytes, 6),
                 quint8(bytes.at(8)), quint8(bytes.at(9)), quint8(bytes.at(10)),
                 quint8(bytes.at(11)), quint8(bytes.at(12)), quint8(bytes.at(13)),
                 quint8(bytes.at(14)), quint8(bytes.at(15)));
}

QString fromUtf16(const QByteArray &bytes)
{
    QString text = QString::fromUtf16(reinterpret_cast<const char16_t *>(bytes.constData()),
                                      bytes.size() / 2);
    while (text.endsWith(QChar(u'\0')))
        text.chop(1);
    return text;
}

QString fileTimeToIso(const QByteArray &bytes)
{
    if (bytes.size() != 8)
        return QString();
    // FILETIME counts 100 ns ticks from 1601-01-01; the epoch difference is
    // the constant Windows and Samba both use.
    const quint64 ticks = readLe64(bytes, 0);
    if (ticks == 0)
        return QString();
    const qint64 msecs = qint64(ticks / 10000u) - Q_INT64_C(11644473600000);
    return QDateTime::fromMSecsSinceEpoch(msecs, Qt::UTC).toString(Qt::ISODate);
}

// One DSNAME as the reply defers it: the conformant character count precedes
// the struct, the name characters close it (MS-RPCE §14.3.7.2).
bool walkDsName(Ndr::Reader *reader, QString *dn)
{
    quint32 count = 0;
    quint32 structLen = 0;
    quint32 sidLen = 0;
    quint32 nameLen = 0;
    if (!reader->u32(&count) || !reader->u32(&structLen) || !reader->u32(&sidLen)
        || !reader->skip(16) || !reader->skip(28) || !reader->u32(&nameLen))
        return false;
    if (count > 4096)
        return false;
    QByteArray chars;
    if (!reader->bytes(int(count) * 2, &chars))
        return false;
    reader->align(4);
    *dn = fromUtf16(chars);
    return true;
}

// A member value is a DSNAME body, not a character string: a group's member
// list carries distinguished names the same way the request's pNC does.
QString dsNameValueToDn(const QByteArray &bytes)
{
    Ndr::Reader reader(bytes);
    QString dn;
    if (!walkDsName(&reader, &dn))
        return QString();
    return dn;
}

// One REPLENTINFLIST element: its DN and the attribute values it carries.
struct ChainEntry {
    QString dn;
    QHash<quint32, QList<QByteArray>> values;
};

bool walkAttrBlock(Ndr::Reader *reader, quint32 declaredCount, ChainEntry *entry)
{
    quint32 maxCount = 0;
    if (!reader->u32(&maxCount) || maxCount != declaredCount || maxCount > 4096)
        return false;
    QVector<QPair<quint32, quint32>> attrs; // attid, value count
    for (quint32 i = 0; i < maxCount; ++i) {
        quint32 attid = 0;
        quint32 valCount = 0;
        quint32 arrayRef = 0;
        if (!reader->u32(&attid) || !reader->u32(&valCount) || !reader->u32(&arrayRef))
            return false;
        if (arrayRef == 0 || valCount > 4096)
            return false;
        attrs.append(qMakePair(attid, valCount));
    }
    for (const auto &attr : attrs) {
        quint32 count = 0;
        if (!reader->u32(&count) || count != attr.second)
            return false;
        QVector<quint32> lengths;
        for (quint32 i = 0; i < count; ++i) {
            quint32 valueLength = 0;
            quint32 valueRef = 0;
            if (!reader->u32(&valueLength) || !reader->u32(&valueRef))
                return false;
            if (valueRef == 0 || valueLength > (1u << 20))
                return false;
            lengths.append(valueLength);
        }
        for (quint32 valueLength : lengths) {
            quint32 leafCount = 0;
            if (!reader->u32(&leafCount) || leafCount != valueLength)
                return false;
            QByteArray value;
            if (!reader->bytes(int(leafCount), &value))
                return false;
            reader->align(4);
            entry->values[attr.first].append(value);
        }
    }
    return true;
}

// The chain is written deepest element first: pNextEntInf's body precedes this
// element's own DSNAME and attribute block.
bool walkChain(Ndr::Reader *reader, QList<ChainEntry> *entries, int depth = 0)
{
    if (depth > 64)
        return false;
    quint32 nextRef = 0;
    quint32 nameRef = 0;
    quint32 flags = 0;
    quint32 attrCount = 0;
    quint32 attrBlockRef = 0;
    quint32 isNcHead = 0;
    quint32 parentRef = 0;
    quint32 metaDataRef = 0;
    if (!reader->u32(&nextRef) || !reader->u32(&nameRef) || !reader->u32(&flags)
        || !reader->u32(&attrCount) || !reader->u32(&attrBlockRef)
        || !reader->u32(&isNcHead) || !reader->u32(&parentRef)
        || !reader->u32(&metaDataRef))
        return false;
    if (nameRef == 0 || (attrCount != 0 && attrBlockRef == 0))
        return false;
    if (nextRef != 0 && !walkChain(reader, entries, depth + 1))
        return false;

    ChainEntry entry;
    if (!walkDsName(reader, &entry.dn))
        return false;
    if (attrCount != 0 && !walkAttrBlock(reader, attrCount, &entry))
        return false;
    if (isNcHead == 0 && !reader->skip(16)) // the parent GUID body
        return false;
    entries->append(entry);
    return true;
}

QString attributeName(quint32 attid)
{
    switch (attid) {
    case kAttidObjectClass: return QStringLiteral("objectClass");
    case kAttidCn: return QStringLiteral("cn");
    case kAttidDescription: return QStringLiteral("description");
    case kAttidMember: return QStringLiteral("member");
    case kAttidDistinguishedName: return QStringLiteral("distinguishedName");
    case kAttidInstanceType: return QStringLiteral("instanceType");
    case kAttidWhenCreated: return QStringLiteral("whenCreated");
    case kAttidName: return QStringLiteral("name");
    case kAttidObjectGuid: return QStringLiteral("objectGUID");
    case kAttidIsDeleted: return QStringLiteral("isDeleted");
    case kAttidUserAccountControl: return QStringLiteral("userAccountControl");
    case kAttidObjectSid: return QStringLiteral("objectSid");
    case kAttidSamAccountName: return QStringLiteral("sAMAccountName");
    case kAttidUserPrincipalName: return QStringLiteral("userPrincipalName");
    case kAttidWhenChanged: return QStringLiteral("whenChanged");
    default: return QString();
    }
}

QString valueText(quint32 attid, const QByteArray &bytes)
{
    switch (attid) {
    case kAttidObjectGuid: {
        const QUuid guid = guidFromBytes(bytes);
        return guid.isNull() ? QString() : guid.toString();
    }
    case kAttidObjectSid:
        return Ndr::sidToString(bytes);
    case kAttidInstanceType:
    case kAttidUserAccountControl:
        return bytes.size() == 4 ? QString::number(readLe32(bytes, 0)) : QString();
    case kAttidIsDeleted:
        return (!bytes.isEmpty() && bytes.at(0) != '\0') ? QStringLiteral("TRUE")
                                                         : QStringLiteral("FALSE");
    case kAttidWhenCreated:
    case kAttidWhenChanged:
        return fileTimeToIso(bytes);
    default:
        return fromUtf16(bytes);
    }
}

// objectClass travels lowercase (AD serves "user" and "group"); the console
// and the rest of the store name the types "User" and "Security Group".
QString displayTypeFromClass(const QString &objectClass)
{
    const QString lowered = objectClass.toLower();
    if (lowered == QLatin1String("user"))
        return QStringLiteral("User");
    if (lowered == QLatin1String("group"))
        return QStringLiteral("Security Group");
    if (lowered == QLatin1String("computer"))
        return QStringLiteral("Computer");
    if (lowered == QLatin1String("organizationalunit"))
        return QStringLiteral("Organizational Unit");
    if (lowered == QLatin1String("container"))
        return QStringLiteral("Container");
    if (lowered == QLatin1String("domain"))
        return QStringLiteral("Domain");
    if (objectClass.isEmpty())
        return QString();
    QString capitalized = objectClass;
    capitalized[0] = capitalized.at(0).toUpper();
    return capitalized;
}

DirectoryObject toDirectoryObject(const ChainEntry &entry)
{
    DirectoryObject object;
    object.id = entry.dn;

    QString cn;
    QString name;
    QString objectClass;
    for (auto it = entry.values.constBegin(); it != entry.values.constEnd(); ++it) {
        const quint32 attid = it.key();
        const QString text = it.value().isEmpty() ? QString() : valueText(attid, it.value().first());
        if (attid == kAttidMember) {
            for (const QByteArray &value : it.value()) {
                const QString member = dsNameValueToDn(value);
                if (!member.isEmpty())
                    object.members.append(member);
            }
            continue;
        }
        const QString attribute = attributeName(attid);
        if (attribute.isEmpty() || text.isEmpty())
            continue; // an ATTID without a name is not turned into one
        object.attributes.insert(attribute, text);
        if (attid == kAttidCn)
            cn = text;
        else if (attid == kAttidName)
            name = text;
        else if (attid == kAttidObjectClass)
            objectClass = text;
        else if (attid == kAttidDescription)
            object.description = text;
    }

    object.type = displayTypeFromClass(objectClass);
    if (!cn.isEmpty())
        object.name = cn;
    else if (!name.isEmpty())
        object.name = name;
    else {
        const int eq = object.id.indexOf(QLatin1Char('='));
        const int comma = object.id.indexOf(QLatin1Char(','));
        object.name = eq >= 0 && comma > eq ? object.id.mid(eq + 1, comma - eq - 1)
                                           : object.id;
    }
    return object;
}

// The endpoint mapper (MS-RPCE §6.2): the fixed-port service a host registers
// its dynamic endpoints with. AD puts DRSUAPI on an arbitrary port, so a client
// told only "this host" asks here first instead of guessing.
const QUuid kEpmInterface =
    QUuid::fromString(QStringLiteral("{e1af8308-5d1f-11c9-91a4-08002b14a0fa}"));
const QUuid kTcpProtocol =
    QUuid::fromString(QStringLiteral("{045d888a-eb1c-c911-9fe8-08002b104860}"));

bool sendPdu(QTcpSocket *socket, const QByteArray &pdu)
{
    return socket->write(pdu) == pdu.size() && socket->waitForBytesWritten(3000);
}

bool readPdu(QTcpSocket *socket, QByteArray *buffer, QByteArray *pdu)
{
    QDeadlineTimer deadline(3000);
    auto fillTo = [&](int target) {
        while (buffer->size() < target) {
            const qint64 remaining = deadline.remainingTime();
            if (remaining <= 0)
                return false;
            if (!socket->waitForReadyRead(int(remaining))) {
                buffer->append(socket->readAll());
                return buffer->size() >= target;
            }
            buffer->append(socket->readAll());
        }
        return true;
    };
    if (!fillTo(kHeaderSize))
        return false;
    const quint16 length = readLe16(*buffer, 8);
    if (length < kHeaderSize || !fillTo(length))
        return false;
    *pdu = buffer->left(length);
    buffer->remove(0, length);
    return true;
}

bool bindAccepted(const QByteArray &pdu)
{
    if (pdu.size() < kHeaderSize + 14 || quint8(pdu.at(2)) != PduBindAck)
        return false;
    const QByteArray body = pdu.mid(kHeaderSize);
    const int secAddrLength = readLe16(body, 8);
    int pos = 10 + secAddrLength;
    pos += (4 - (pos % 4)) % 4;
    if (pos + 4 > body.size())
        return false;
    const int results = quint8(body.at(pos));
    for (int i = 0; i < results; ++i) {
        const int offset = pos + 4 + i * 24;
        if (offset + 24 > body.size())
            break;
        if (readLe16(body, offset) == kResultAcceptance)
            return true;
    }
    return false;
}

// A tower is a list of floors; a transport floor names its protocol in the
// left-hand side and carries the address in the right. The TCP address opens
// with the port in network order (MS-RPCE §6.2.1.2).
bool parseTowerPort(const QByteArray &tower, quint16 *port)
{
    int pos = 0;
    const quint16 floors = readLe16(tower, pos);
    pos += 2;
    for (int i = 0; i < floors; ++i) {
        const quint16 lhsLength = readLe16(tower, pos);
        pos += 2;
        if (pos + int(lhsLength) + 2 > tower.size())
            return false;
        const QByteArray lhs = tower.mid(pos, lhsLength);
        pos += lhsLength;
        const quint16 rhsLength = readLe16(tower, pos);
        pos += 2;
        if (pos + int(rhsLength) > tower.size())
            return false;
        if (lhsLength == 16 && guidFromBytes(lhs) == kTcpProtocol && rhsLength >= 2) {
            const quint16 found = quint16((quint8(tower.at(pos)) << 8)
                                          | quint8(tower.at(pos + 1)));
            if (found != 0) {
                *port = found;
                return true;
            }
        }
        pos += rhsLength;
    }
    return false;
}

bool lookupEndpoint(const QString &host, quint16 epmPort, const QByteArray &ifaceUuid,
                    quint16 major, quint16 minor, quint16 *port, QString *error)
{
    QTcpSocket socket;
    socket.connectToHost(host, epmPort);
    if (!socket.waitForConnected(3000)) {
        if (error)
            *error = QStringLiteral("the endpoint mapper at %1:%2 is unreachable: %3")
                         .arg(host)
                         .arg(epmPort)
                         .arg(socket.errorString());
        return false;
    }
    QByteArray buffer;
    if (!sendPdu(&socket,
                 DrsWire::bindPdu(1, guidBytes(kEpmInterface), 3, 0, QByteArray(), 0))) {
        if (error)
            *error = QStringLiteral("could not send the endpoint mapper bind");
        return false;
    }
    QByteArray pdu;
    if (!readPdu(&socket, &buffer, &pdu) || !bindAccepted(pdu)) {
        if (error)
            *error = QStringLiteral("the endpoint mapper refused the bind");
        return false;
    }

    QByteArray stub;
    putLe32(stub, 0); // inquiry_type: ept_tower
    putLe32(stub, 0); // object: null referent
    stub.append(ifaceUuid);
    putLe16(stub, major);
    putLe16(stub, minor);
    putLe32(stub, 1);                   // vers_option: major version only
    stub.append(QByteArray(20, '\0')); // ept_lookup_handle
    putLe32(stub, 4);                   // max_ents
    if (!sendPdu(&socket, DrsWire::requestPdu(2, 2, stub))) {
        if (error)
            *error = QStringLiteral("could not send the endpoint query");
        return false;
    }
    if (!readPdu(&socket, &buffer, &pdu) || quint8(pdu.at(2)) != PduResponse) {
        if (error)
            *error = QStringLiteral("the endpoint mapper did not answer the query");
        return false;
    }

    const QByteArray replyStub = pdu.mid(kResponseHeader);
    Ndr::Reader reader(replyStub);
    quint32 numEnts = 0;
    if (!reader.skip(20) || !reader.u32(&numEnts)) {
        if (error)
            *error = QStringLiteral("the endpoint reply could not be parsed");
        return false;
    }
    for (quint32 i = 0; i < numEnts && i < 32; ++i) {
        quint32 status = 0;
        quint32 towerLength = 0;
        quint32 towerOffset = 0;
        if (!reader.u32(&status) || !reader.u32(&towerLength) || !reader.u32(&towerOffset))
            break;
        QByteArray tower;
        if (!reader.bytes(int(towerLength), &tower))
            break;
        reader.align(4);
        if (status != 0)
            continue;
        if (parseTowerPort(tower, port))
            return true;
    }
    if (error)
        *error = QStringLiteral("%1 does not register DRSUAPI on a TCP port").arg(host);
    return false;
}

} // namespace

namespace DrsWire {

QByteArray bindPdu(quint32 callId, const QByteArray &abstractUuid, quint16 major,
                   quint16 minor, const QByteArray &authToken, quint8 authLevel)
{
    QByteArray pdu;
    appendHeader(pdu, PduBind, callId);
    putLe16(pdu, kMaxFrag); // max_xmit_frag
    putLe16(pdu, kMaxFrag); // max_recv_frag
    putLe32(pdu, 0);        // assoc_group: let the server assign one
    pdu.append(char(1));    // one presentation context
    pdu.append(char(0));
    putLe16(pdu, 0);
    putLe16(pdu, 0); // context id
    pdu.append(char(1)); // one transfer syntax
    pdu.append(char(0));
    pdu.append(abstractUuid);
    putLe16(pdu, major);
    putLe16(pdu, minor);
    pdu.append(Rpc::kNdrSyntaxUuid);
    putLe16(pdu, 2); // NDR32
    putLe16(pdu, 0);
    if (!authToken.isEmpty())
        appendAuthVerifier(pdu, AuthTypeNtlm, authLevel, 0, 0, authToken);
    else
        patchFragmentLength(pdu);
    return pdu;
}

QByteArray requestPdu(quint32 callId, quint16 opnum, const QByteArray &stub)
{
    QByteArray pdu;
    appendHeader(pdu, PduRequest, callId);
    putLe32(pdu, quint32(stub.size())); // alloc_hint
    putLe16(pdu, 0);                    // context id
    putLe16(pdu, opnum);
    pdu.append(stub);
    patchFragmentLength(pdu);
    return pdu;
}

QByteArray dsBindRequest()
{
    // puuidClientDsa: a GUID of this client's choosing, which the DC checks
    // against the replication topology; pextClient declares the shapes.
    QByteArray stub;
    putLe32(stub, 0x00020000u); // referent: present
    stub.append(guidBytes(QUuid::createUuid()));
    putLe32(stub, 0x00020001u); // pextClient referent
    putLe32(stub, 52);          // DRS_EXTENSIONS.cb
    putLe32(stub, 52);          // rgb conformant count
    QByteArray ext;
    putLe32(ext, 0x25100000u); // GETCHGREQ V5/V8/V10, GETCHGREPLY V6
    ext.append(QByteArray(16, '\0')); // SiteObjGuid
    putLe32(ext, 0u);                 // Pid
    putLe32(ext, 0u);                 // dwReplEpoch
    putLe32(ext, 0u);                 // dwFlagsExt
    ext.append(QByteArray(16, '\0')); // ConfigObjGuid
    putLe32(ext, 0u);                 // dwExtCaps
    stub.append(ext);
    return stub;
}

bool parseDsBindReply(const QByteArray &stub, QByteArray *handle, quint32 *werr)
{
    if (!handle || !werr || stub.size() < 88)
        return false;
    if (readLe32(stub, 0) == 0) // ppextServer: a DsBind reply always carries it
        return false;
    const quint32 cb = readLe32(stub, 4);
    if (cb > 4096)
        return false;
    const int handleOffset = 12 + int(cb);
    if (stub.size() < handleOffset + kHandleSize + 4)
        return false;
    *handle = stub.mid(handleOffset, kHandleSize);
    *werr = readLe32(stub, handleOffset + kHandleSize);
    return true;
}

QByteArray getNCChangesRequest(const QByteArray &handle, const QString &ncDn,
                               quint64 fromUsn, quint32 maxObjects)
{
    QByteArray stub = handle.left(kHandleSize);
    if (stub.size() < kHandleSize)
        stub.append(QByteArray(kHandleSize - stub.size(), '\0'));
    putLe32(stub, 8); // dwInVersion
    putLe32(stub, 8); // pmsgIn union tag: DRS_MSG_GETCHGREQ_V8
    padTo8(stub);     // the arm carries LONGLONG fields
    stub.append(QByteArray(16, '\0')); // uuidDsaObjDest
    stub.append(QByteArray(16, '\0')); // uuidInvocIdSrc
    putLe32(stub, 0x00020000u);        // pNC referent: present
    for (int i = 0; i < 3; ++i) {      // usnvecFrom
        padTo8(stub);
        putLe64(stub, i == 0 ? fromUsn : 0);
    }
    putLe32(stub, 0); // pUpToDateVecDest: none
    putLe32(stub, 0); // ulFlags
    putLe32(stub, maxObjects);
    putLe32(stub, 0); // cMaxBytes: no byte cap
    putLe32(stub, 0); // ulExtendedOp: a plain pull cycle
    padTo8(stub);
    putLe64(stub, 0); // liFsmoInfo
    putLe32(stub, 0); // pPartialAttrSet
    putLe32(stub, 0); // pPartialAttrSetEx1
    putLe32(stub, 0); // PrefixTableDest.PrefixCount
    putLe32(stub, 0); // pPrefixEntry

    const QByteArray chars = Ndr::utf16le(ncDn + QChar(u'\0'));
    putLe32(stub, quint32(chars.size() / 2)); // conformant character count
    putLe32(stub, 60 + quint32(chars.size())); // structLen
    putLe32(stub, 0);                          // SidLen
    stub.append(QByteArray(16, '\0'));         // Guid
    stub.append(QByteArray(28, '\0'));         // Sid slot
    putLe32(stub, quint32(chars.size() / 2));  // NameLen
    stub.append(chars);
    return stub;
}

bool parseGetNCChangesReply(const QByteArray &stub, QList<DirectoryObject> *objects,
                            quint64 *usnHigh, bool *moreData, quint32 *werr)
{
    if (!objects || !usnHigh || !moreData || !werr)
        return false;
    Ndr::Reader reader(stub);
    quint32 outVersion = 0;
    quint32 tag = 0;
    if (!reader.u32(&outVersion) || !reader.u32(&tag))
        return false;
    if (outVersion != 1 && outVersion != 6)
        return false;
    if (!reader.skip(32)) // uuidDsaObjSrc, uuidInvocIdSrc
        return false;
    quint32 ncRef = 0;
    if (!reader.u32(&ncRef))
        return false;
    for (int i = 0; i < 3; ++i) { // usnvecFrom echoes the request
        reader.align(8);
        quint64 echo = 0;
        if (!reader.u64(&echo))
            return false;
    }
    quint64 usnToHigh = 0;
    quint64 reserved = 0;
    quint64 usnHighProp = 0;
    if (!reader.u64(&usnToHigh) || !reader.u64(&reserved) || !reader.u64(&usnHighProp))
        return false;
    quint32 utdRef = 0;
    quint32 prefixCount = 0;
    quint32 prefixRef = 0;
    quint32 extRet = 0;
    quint32 objectCount = 0;
    quint32 numBytes = 0;
    quint32 objectsRef = 0;
    quint32 more = 0;
    if (!reader.u32(&utdRef) || !reader.u32(&prefixCount) || !reader.u32(&prefixRef)
        || !reader.u32(&extRet) || !reader.u32(&objectCount) || !reader.u32(&numBytes)
        || !reader.u32(&objectsRef) || !reader.u32(&more))
        return false;
    quint32 drsError = 0;
    if (outVersion == 6) {
        quint32 ncSizeObjects = 0;
        quint32 ncSizeValues = 0;
        quint32 valueCount = 0;
        quint32 valuesRef = 0;
        if (!reader.u32(&ncSizeObjects) || !reader.u32(&ncSizeValues)
            || !reader.u32(&valueCount) || !reader.u32(&valuesRef)
            || !reader.u32(&drsError))
            return false;
    }
    *moreData = more != 0;
    *werr = drsError;

    if (ncRef != 0) {
        QString ncDn;
        if (!walkDsName(&reader, &ncDn))
            return false;
    }

    // UPTODATE_VECTOR_V2_EXT: the head words, then one cursor per source DSA.
    if (utdRef == 0)
        return false;
    quint32 arrayCount = 0;
    quint32 vectorVersion = 0;
    quint32 headReserved = 0;
    quint32 cursorCount = 0;
    quint32 tailReserved = 0;
    if (!reader.u32(&arrayCount) || !reader.u32(&vectorVersion)
        || !reader.u32(&headReserved) || !reader.u32(&cursorCount)
        || !reader.u32(&tailReserved))
        return false;
    if (cursorCount > 1024)
        return false;
    quint64 cursorHigh = 0;
    for (quint32 i = 0; i < cursorCount; ++i) {
        if (!reader.skip(16)) // uuidSourceDsaInvocationID
            return false;
        reader.align(8);
        quint64 high = 0;
        if (!reader.u64(&high))
            return false;
        if (vectorVersion >= 2) {
            quint64 lastSync = 0;
            if (!reader.u64(&lastSync))
                return false;
        }
        if (i == 0)
            cursorHigh = high;
    }
    *usnHigh = cursorHigh != 0 ? cursorHigh : qMax(usnToHigh, usnHighProp);

    // The prefix table: the deferred conformant array opens with its own
    // max_count (the spine's count above only mirrors it), then the
    // (ndx, length, referent) triples, then the OID bytes.
    if (prefixCount > 4096)
        return false;
    quint32 tableCount = 0;
    if (!reader.u32(&tableCount) || tableCount != prefixCount)
        return false;
    QVector<quint32> lengths;
    for (quint32 i = 0; i < prefixCount; ++i) {
        quint32 ndx = 0;
        quint32 length = 0;
        quint32 elementsRef = 0;
        if (!reader.u32(&ndx) || !reader.u32(&length) || !reader.u32(&elementsRef))
            return false;
        if (length > 4096)
            return false;
        lengths.append(length);
    }
    for (quint32 length : lengths) {
        quint32 maxCount = 0;
        if (!reader.u32(&maxCount) || maxCount != length)
            return false;
        QByteArray oid;
        if (!reader.bytes(int(length), &oid))
            return false;
    }

    objects->clear();
    if (objectCount == 0)
        return true;
    if (objectsRef == 0)
        return false;
    QList<ChainEntry> entries;
    if (!walkChain(&reader, &entries))
        return false;
    for (const ChainEntry &entry : entries) {
        if (entry.dn.isEmpty())
            continue;
        objects->append(toDirectoryObject(entry));
    }
    return objects->size() == int(objectCount);
}

} // namespace DrsWire

DrsClient::DrsClient(QObject *parent) : QObject(parent) {}

DrsClient::~DrsClient()
{
    delete m_socket;
}

void DrsClient::setPeer(const QString &host, quint16 port)
{
    m_host = host;
    m_port = port;
}

void DrsClient::setTimeouts(int connectMs, int readMs)
{
    m_connectTimeoutMs = qMax(1, connectMs);
    m_readTimeoutMs = qMax(1, readMs);
}

void DrsClient::setCredentials(const QString &domain, const QString &user,
                               const QString &password)
{
    m_domain = domain;
    m_user = user;
    m_password = password;
    m_credentialsSet = !user.isEmpty() && !password.isEmpty();
}

bool DrsClient::resolvePeer(QString *error)
{
    if (m_port != 0)
        return true;
    if (m_host.isEmpty()) {
        if (error)
            *error = QStringLiteral("no peer configured");
        return false;
    }
    const Rpc::Interface interface = Drs::interface();
    quint16 port = 0;
    if (!lookupEndpoint(m_host, m_epmPort, interface.uuid, interface.major, interface.minor,
                        &port, error))
        return false;
    m_port = port;
    return true;
}

bool DrsClient::connectToPeer(QString *error)
{
    close();
    if (m_host.isEmpty()) {
        if (error)
            *error = QStringLiteral("no peer configured");
        return false;
    }
    if (m_port == 0 && !resolvePeer(error))
        return false;
    m_socket = new QTcpSocket(this);
    m_socket->connectToHost(m_host, m_port);
    if (!m_socket->waitForConnected(m_connectTimeoutMs)) {
        if (error)
            *error = QStringLiteral("connect to %1:%2 failed: %3")
                         .arg(m_host)
                         .arg(m_port)
                         .arg(m_socket->errorString());
        close();
        return false;
    }
    m_socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    m_buffer.clear();
    m_callId = 0;
    return true;
}

void DrsClient::close()
{
    if (m_socket) {
        m_socket->abort();
        delete m_socket;
        m_socket = nullptr;
    }
    m_buffer.clear();
    m_interfaceBound = false;
    m_authenticated = false;
    m_handle.clear();
    m_sendSeq = 0;
    m_recvSeq = 0;
}

bool DrsClient::isConnected() const
{
    return m_socket && m_socket->state() == QAbstractSocket::ConnectedState;
}

bool DrsClient::writePdu(const QByteArray &pdu, QString *error)
{
    if (!isConnected()) {
        if (error)
            *error = QStringLiteral("not connected");
        return false;
    }
    if (m_socket->write(pdu) != pdu.size() || !m_socket->waitForBytesWritten(m_readTimeoutMs)) {
        if (error)
            *error = QStringLiteral("write failed: %1").arg(m_socket->errorString());
        return false;
    }
    return true;
}

bool DrsClient::readMessage(quint32 callId, quint8 *type, QByteArray *body,
                            QByteArray *authToken, quint32 *faultStatus, QString *error)
{
    *faultStatus = 0;
    body->clear();
    if (authToken)
        authToken->clear();
    QDeadlineTimer deadline(m_readTimeoutMs);
    forever {
        while (m_buffer.size() < kHeaderSize) {
            if (deadline.hasExpired()) {
                if (error)
                    *error = QStringLiteral("timed out waiting for a reply");
                return false;
            }
            if (!m_socket->waitForReadyRead(int(qMax<qint64>(1, deadline.remainingTime())))) {
                if (error)
                    *error = QStringLiteral("read failed: %1").arg(m_socket->errorString());
                return false;
            }
            m_buffer.append(m_socket->readAll());
        }
        const quint16 fragLength = readLe16(m_buffer, 8);
        if (fragLength < kHeaderSize) {
            if (error)
                *error = QStringLiteral("malformed fragment length %1").arg(fragLength);
            return false;
        }
        while (m_buffer.size() < fragLength) {
            if (deadline.hasExpired()) {
                if (error)
                    *error = QStringLiteral("timed out mid-fragment");
                return false;
            }
            if (!m_socket->waitForReadyRead(int(qMax<qint64>(1, deadline.remainingTime())))) {
                if (error)
                    *error = QStringLiteral("read failed: %1").arg(m_socket->errorString());
                return false;
            }
            m_buffer.append(m_socket->readAll());
        }
        const QByteArray fragment = m_buffer.left(fragLength);
        m_buffer.remove(0, fragLength);
        if (readLe32(fragment, 12) != callId) {
            if (error)
                *error = QStringLiteral("reply for the wrong call id");
            return false;
        }
        *type = quint8(fragment.at(2));
        const quint8 flags = quint8(fragment.at(3));
        const quint16 authLength = readLe16(fragment, 10);
        const int bodyStart = (*type == PduResponse || *type == PduFault) ? kResponseHeader
                                                                         : kHeaderSize;
        const int trailerPos = authLength == 0 ? fragment.size() : fragment.size() - 8
                                                                         - int(authLength);
        if (trailerPos < bodyStart) {
            if (error)
                *error = QStringLiteral("truncated auth verifier");
            return false;
        }

        if (*type == PduFault) {
            *faultStatus = readLe32(fragment, bodyStart);
        } else if (*type == PduResponse) {
            if (authLength != 0) {
                if (!m_authenticated) {
                    if (error)
                        *error = QStringLiteral("peer signed the reply before authenticating");
                    return false;
                }
                const quint8 padLength = quint8(fragment.at(trailerPos + 2));
                QByteArray payload = fragment.mid(bodyStart, trailerPos - bodyStart);
                const QByteArray token = fragment.mid(trailerPos + 8, authLength);
                if (m_authLevel >= 6)
                    payload = m_recvSealer.apply(payload);
                // The signature covers the plaintext form: the same PDU with
                // the sealed stub put back (MS-RPCE §2.2.3.4).
                QByteArray signedData = fragment.left(fragment.size() - authLength);
                signedData.replace(bodyStart, payload.size(), payload);
                const bool signatureOk =
                    token.size() == kAuthTokenSize && readLe32(token, 0) == 1
                    && readLe32(token, 12) == m_recvSeq
                    && Ntlm::secureEquals(
                        Ntlm::mac(m_keys.serverSigningKey, m_recvSeq, signedData),
                        token.mid(4, 8));
                if (!signatureOk) {
                    if (error)
                        *error = QStringLiteral("the peer's reply signature did not verify");
                    return false;
                }
                ++m_recvSeq;
                if (int(padLength) > payload.size()) {
                    if (error)
                        *error = QStringLiteral("bad auth padding in the reply");
                    return false;
                }
                payload.truncate(payload.size() - int(padLength));
                body->append(payload);
            } else {
                body->append(fragment.mid(bodyStart, trailerPos - bodyStart));
            }
        } else if (*type == PduBindAck || *type == PduBindNak) {
            if (authLength != 0 && authToken)
                *authToken = fragment.mid(trailerPos + 8, authLength);
            body->append(fragment.mid(bodyStart, trailerPos - bodyStart));
        } else {
            if (error)
                *error = QStringLiteral("unexpected PDU type %1").arg(*type);
            return false;
        }
        if (flags & PduFlagLast)
            break;
    }
    return true;
}

bool DrsClient::bindInterface(QString *error)
{
    const Rpc::Interface interface = Drs::interface();
    const QByteArray negotiate =
        m_credentialsSet ? Ntlm::negotiateToken(negotiationFlags()) : QByteArray();
    const quint32 callId = ++m_callId;
    if (!writePdu(DrsWire::bindPdu(callId, interface.uuid, interface.major, interface.minor,
                                  negotiate, m_authLevel),
                  error))
        return false;
    quint8 type = 0;
    quint32 faultStatus = 0;
    QByteArray body;
    QByteArray token;
    if (!readMessage(callId, &type, &body, &token, &faultStatus, error))
        return false;
    if (type == PduBindNak) {
        if (error)
            *error = QStringLiteral("the peer refused the bind");
        return false;
    }
    if (type != PduBindAck) {
        if (error)
            *error = QStringLiteral("expected a bind_ack, got PDU type %1").arg(type);
        return false;
    }
    // max_xmit, max_recv, assoc_group, then the secondary address, then one
    // result per offered context.
    if (body.size() < 10) {
        if (error)
            *error = QStringLiteral("truncated bind_ack");
        return false;
    }
    const quint16 secAddrLength = readLe16(body, 8);
    int pos = 10 + int(secAddrLength);
    pos += (4 - (pos % 4)) % 4;
    if (pos + 4 > body.size()) {
        if (error)
            *error = QStringLiteral("truncated bind_ack results");
        return false;
    }
    const int resultCount = quint8(body.at(pos));
    bool accepted = false;
    quint16 reason = 0;
    for (int i = 0; i < resultCount; ++i) {
        const int offset = pos + 4 + i * 24;
        if (offset + 24 > body.size())
            break;
        if (readLe16(body, offset) == kResultAcceptance)
            accepted = true;
        else if (reason == 0)
            reason = readLe16(body, offset + 2);
    }
    if (!accepted) {
        if (error)
            *error = QStringLiteral("the peer rejected the DRSUAPI interface (reason %1)")
                         .arg(reason);
        return false;
    }
    m_interfaceBound = true;
    if (!m_credentialsSet)
        return true;

    // The bind_ack carried the CHALLENGE: answer it with an NTLMv2 response in
    // an AUTH3 PDU. A raw-NTLMSSP peer sends no reply to that, so the next call
    // is where a wrong password shows up (as an access-denied fault).
    Ntlm::Challenge challenge;
    if (token.isEmpty() || !Ntlm::parseChallenge(Ntlm::embeddedToken(token), &challenge)) {
        if (error)
            *error = QStringLiteral("the peer did not challenge the NTLMSSP bind");
        return false;
    }
    const QByteArray ntHash = Ntlm::ntowfV1(m_password);
    QByteArray ntResponse;
    QByteArray proof;
    if (!Ntlm::ntlmv2Response(ntHash, m_user, m_domain, challenge.serverChallenge,
                              challenge.targetInfo, &ntResponse, &proof)) {
        if (error)
            *error = QStringLiteral("could not build the NTLMv2 response");
        return false;
    }
    const QByteArray authenticate =
        Ntlm::authenticateToken(m_domain, m_user, negotiationFlags(), ntResponse);
    QByteArray auth3;
    appendHeader(auth3, PduAuth3, ++m_callId);
    putLe32(auth3, 0); // alloc_hint
    putLe16(auth3, 0); // p_cont_id
    auth3.append(char(0)); // cancel_count
    auth3.append(char(0)); // reserved
    appendAuthVerifier(auth3, AuthTypeNtlm, m_authLevel, 0, 0, authenticate);
    if (!writePdu(auth3, error))
        return false;

    if (!Ntlm::sessionKeys(ntHash, m_user, m_domain, proof, &m_keys, negotiationFlags())) {
        if (error)
            *error = QStringLiteral("could not derive the NTLM session keys");
        return false;
    }
    m_sendSealer.reset(m_keys.clientSealingKey);
    m_recvSealer.reset(m_keys.serverSealingKey);
    m_sendSeq = 0;
    m_recvSeq = 0;
    m_authenticated = true;
    return true;
}

bool DrsClient::callInternal(quint16 opnum, const QString &name, const QByteArray &stub,
                             QByteArray *replyStub, QString *error)
{
    if (!m_interfaceBound) {
        if (error)
            *error = QStringLiteral("the interface is not bound");
        return false;
    }
    const quint32 callId = ++m_callId;
    QByteArray pdu;
    if (m_authenticated) {
        // A signed call pads the stub, signs the plaintext PDU, and only then
        // seals it; the receiver unseals and verifies against that same form.
        const int padLength = (4 - (stub.size() % 4)) % 4;
        QByteArray padded = stub;
        padded.append(QByteArray(padLength, '\0'));
        appendHeader(pdu, PduRequest, callId);
        putLe32(pdu, quint32(stub.size())); // alloc_hint: the unpadded size
        putLe16(pdu, 0);                    // context id
        putLe16(pdu, opnum);
        const int stubStart = pdu.size();
        pdu.append(padded);
        pdu.append(char(AuthTypeNtlm));
        pdu.append(char(m_authLevel));
        pdu.append(char(padLength));
        pdu.append(char(0));
        putLe32(pdu, 0); // auth context id: none was negotiated
        // The signature covers the PDU as the peer will verify it, so both
        // header length words are stamped before signing: the fragment length
        // counts the token that is appended next.
        const quint16 signedLength = quint16(pdu.size() + kAuthTokenSize);
        pdu[8] = char(signedLength & 0xff);
        pdu[9] = char((signedLength >> 8) & 0xff);
        pdu[10] = char(kAuthTokenSize & 0xff);
        pdu[11] = char((kAuthTokenSize >> 8) & 0xff);
        const QByteArray signatureMac = Ntlm::mac(m_keys.clientSigningKey, m_sendSeq, pdu);
        QByteArray signature;
        putLe32(signature, 1);
        signature.append(signatureMac);
        putLe32(signature, m_sendSeq);
        pdu.append(signature);
        patchFragmentLength(pdu);
        if (m_authLevel >= 6)
            pdu.replace(stubStart, padded.size(), m_sendSealer.apply(padded));
        ++m_sendSeq;
    } else {
        pdu = DrsWire::requestPdu(callId, opnum, stub);
    }
    if (!writePdu(pdu, error))
        return false;
    quint8 type = 0;
    quint32 faultStatus = 0;
    if (!readMessage(callId, &type, replyStub, nullptr, &faultStatus, error))
        return false;
    if (type == PduFault) {
        if (error)
            *error = QStringLiteral("%1 was faulted by the peer (NCA status 0x%2)")
                         .arg(name)
                         .arg(faultStatus, 8, 16, QLatin1Char('0'));
        return false;
    }
    if (type != PduResponse) {
        if (error)
            *error = QStringLiteral("%1 got PDU type %2").arg(name).arg(type);
        return false;
    }
    emit callCompleted(name);
    return true;
}

bool DrsClient::call(quint16 opnum, const QByteArray &stub, QByteArray *replyStub,
                     QString *error)
{
    return callInternal(opnum, QStringLiteral("opnum %1").arg(opnum), stub, replyStub, error);
}

bool DrsClient::dsBind(QString *error)
{
    QByteArray reply;
    if (!callInternal(0, QStringLiteral("DsBind"), DrsWire::dsBindRequest(), &reply, error))
        return false;
    quint32 werr = 0;
    if (!DrsWire::parseDsBindReply(reply, &m_handle, &werr)) {
        if (error)
            *error = QStringLiteral("DsBind reply could not be parsed");
        return false;
    }
    if (werr != kWerrOk) {
        if (error)
            *error = QStringLiteral("DsBind refused (Win32 error %1)").arg(werr);
        return false;
    }
    return true;
}

bool DrsClient::dsUnbind(QString *error)
{
    QByteArray stub = m_handle;
    QByteArray reply;
    if (!callInternal(1, QStringLiteral("DsUnbind"), stub, &reply, error))
        return false;
    if (reply.size() >= DrsWire::kHandleSize + 4) {
        const quint32 werr = readLe32(reply, DrsWire::kHandleSize);
        if (werr != kWerrOk) {
            if (error)
                *error = QStringLiteral("DsUnbind refused (Win32 error %1)").arg(werr);
            return false;
        }
    }
    m_handle.clear();
    return true;
}

bool DrsClient::getNCChanges(const QString &ncDn, quint64 fromUsn,
                             QList<DirectoryObject> *objects, quint64 *usnHigh,
                             bool *moreData, QString *error)
{
    if (m_handle.isEmpty()) {
        if (error)
            *error = QStringLiteral("DsBind has not been called");
        return false;
    }
    QByteArray reply;
    if (!callInternal(3, QStringLiteral("DsGetNCChanges"),
                      DrsWire::getNCChangesRequest(m_handle, ncDn, fromUsn, 1000), &reply,
                      error))
        return false;
    quint32 werr = 0;
    if (!DrsWire::parseGetNCChangesReply(reply, objects, usnHigh, moreData, &werr)) {
        if (error)
            *error = QStringLiteral("GetNCChanges reply could not be parsed");
        return false;
    }
    if (werr != kWerrOk) {
        if (error)
            *error = QStringLiteral("GetNCChanges refused (DRS error %1)").arg(werr);
        return false;
    }
    return true;
}
