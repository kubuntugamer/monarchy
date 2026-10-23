// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Drs.h"

#include <QCryptographicHash>

#include <algorithm>

#include "Ndr.h"

namespace {

constexpr quint32 kWerrOk = 0x00000000u;
constexpr quint32 kWerrInvalidHandle = 0x000006f7u; // ERROR_INVALID_HANDLE
constexpr quint32 kWerrNotSupported = 0x00000057u; // ERROR_INVALID_PARAMETER
constexpr quint32 kExtRetNone = 0x00000000u;
constexpr quint32 kExtRetSuccess = 0x00000001u;
constexpr quint32 kExopReplObj = 0x00000006u; // EXOP_REPL_OBJ
// PrefixTableSrc.PrefixCount: 19 entries, the canonical prefix map below.
constexpr quint32 kPrefixEntryCount = 0x00000013u;
// cMaxObjects when a partner asks for no limit: the cycle is cut here instead.
constexpr quint32 kDefaultBatchCap = 1000u;

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

// An NDR GUID: the three integer fields little-endian, then Data4 as-is.
QByteArray guidBytes(const QUuid &guid)
{
    QByteArray out;
    putLe32(out, guid.data1);
    out.append(char(guid.data2 & 0xffu));
    out.append(char((guid.data2 >> 8) & 0xffu));
    out.append(char(guid.data3 & 0xffu));
    out.append(char((guid.data3 >> 8) & 0xffu));
    for (int i = 0; i < 8; ++i)
        out.append(char(guid.data4[i]));
    return out;
}

// A DRS_HANDLE is a policy_handle: 20 bytes flat on the wire (MS-LSAD's
// handle layout, what the reference IDL typedefs and what clients unpack as a
// 20-byte struct). The first 16 are this server's UUID key; the last 4 pad.
constexpr int kDrsHandleSize = 20;

QUuid guidFromBytes(const QByteArray &data)
{
    if (data.size() < 16)
        return QUuid();
    QUuid guid;
    guid.data1 = quint32(quint8(data[0])) | (quint32(quint8(data[1])) << 8)
        | (quint32(quint8(data[2])) << 16) | (quint32(quint8(data[3])) << 24);
    guid.data2 = quint16(quint8(data[4]) | (quint8(data[5]) << 8));
    guid.data3 = quint16(quint8(data[6]) | (quint8(data[7]) << 8));
    for (int i = 0; i < 8; ++i)
        guid.data4[i] = quint8(data[8 + i]);
    return guid;
}

// Stable per-DC identity, derived so it survives restarts without a write.

// A reply stub carrying just a status.
QByteArray stubReply(quint32 status)
{
    QByteArray out;
    putLe32(out, status);
    return out;
}

QUuid derivedGuid(const QString &seed)
{
    const QByteArray digest =
        QCryptographicHash::hash(seed.toUtf8(), QCryptographicHash::Md5);
    return QUuid::fromRfc4122(digest);
}

QUuid objectGuidFor(const QString &dn)
{
    return derivedGuid(QStringLiteral("monarchy-object/") + dn);
}

// The GUID an object wears on the wire: the stored objectGUID when the
// directory has one, otherwise the derived form. The DSNAME, the objectGuid
// attribute and the EXOP_REPL_OBJ target must all agree on it.
QUuid objectWireGuid(const DirectoryObject &object)
{
    const QUuid stored(object.attributes.value(QStringLiteral("objectGUID")));
    return stored.isNull() ? objectGuidFor(object.id) : stored;
}

// The whole OID in DER (ITU-T X.690), minus the last sub-identifier's bytes:
// the prefix table entry stops one arc short (MS-DRSR 5.12.2) and the ATTID
// low word supplies the final sub-identifier (OidFromAttid appends it).
QByteArray berOid(const QString &oidText)
{
    QList<quint64> arcs;
    const QStringList parts = oidText.split(QLatin1Char('.'));
    for (const QString &part : parts) {
        bool ok = false;
        const quint64 arc = part.toULongLong(&ok);
        if (!ok)
            return QByteArray();
        arcs.append(arc);
    }
    if (arcs.count() < 2)
        return QByteArray();

    QByteArray out;
    out.append(char((arcs[0] * 40 + arcs[1]) & 0x7f));
    // Everything between the root pair and the final sub-identifier.
    for (int i = 2; i < arcs.count() - 1; ++i) {
        quint64 value = arcs[i];
        QByteArray encoded;
        while (value > 0) {
            encoded.prepend(char(value & 0x7f));
            value >>= 7;
        }
        if (encoded.isEmpty())
            encoded.append('\0');
        for (int k = 0; k < encoded.size(); ++k) {
            char octet = encoded[k];
            if (k != encoded.size() - 1)
                octet |= char(0x80);
            out.append(octet);
        }
    }
    return out;
}

// Canonical attids for the served schema prefix (MS-DRSR 5.12.2 with the
// Windows prefix table indexes): attid = (ndx << 16) | lastSubId.
constexpr quint32 kAttidObjectClass = 0x00000000u;        // 2.5.4.0
constexpr quint32 kAttidCn = 0x00000003u;                 // 2.5.4.3
constexpr quint32 kAttidDescription = 0x0000000Du;        // 2.5.4.13
constexpr quint32 kAttidMember = 0x0000001Fu;             // 2.5.4.31
constexpr quint32 kAttidDistinguishedName = 0x00000031u;  // 2.5.4.49
constexpr quint32 kAttidInstanceType = 0x00020001u;       // 1.2.840.113556.1.2.1
constexpr quint32 kAttidWhenCreated = 0x00020002u;        // 1.2.840.113556.1.2.2
constexpr quint32 kAttidName = 0x00090001u;               // 1.2.840.113556.1.4.1
constexpr quint32 kAttidObjectGuid = 0x00090002u;         // 1.2.840.113556.1.4.2
constexpr quint32 kAttidUserAccountControl = 0x00090008u; // 1.2.840.113556.1.4.8
constexpr quint32 kAttidObjectSid = 0x00090092u;          // 1.2.840.113556.1.4.146
constexpr quint32 kAttidSamAccountName = 0x000900DDu;     // 1.2.840.113556.1.4.221
constexpr quint32 kAttidUserPrincipalName = 0x00090290u;  // 1.2.840.113556.1.4.656
constexpr quint32 kAttidReply = kAttidSamAccountName;     // placeholder, unused


// NDR deferral, modelled explicitly: a node marshals its spine where the
// node sits, then every referent body follows in pointer order, depth-first,
// recursively. That is the layout the peer's two-pass fromString /
// fromStringReferents walk parses; scalars align to 4, USN (LONGLONG) to 8,
// and pointer referent bodies open on a 4 boundary (MS-RPCE 14.2).
struct Node {
    struct Piece {
        int align = 4; // 4, 8 for USN, or 0 for raw payload bytes.
        QByteArray bytes;
    };
    QVector<Piece> spine;
    QVector<Node> children;
};

Node::Piece u32Piece(quint32 value)
{
    Node::Piece piece;
    putLe32(piece.bytes, value);
    return piece;
}

Node::Piece u64Piece(quint64 value)
{
    Node::Piece piece;
    putLe64(piece.bytes, value);
    piece.align = 8;
    return piece;
}

Node::Piece guidPiece(const QUuid guid)
{
    Node::Piece piece;
    piece.bytes = guidBytes(guid);
    return piece;
}

// Value buffers, SID slots, character arrays: no padding inside, the next
// aligned piece pads for itself.
Node::Piece rawPiece(QByteArray bytes)
{
    Node::Piece piece;
    piece.bytes = bytes;
    piece.align = 0;
    return piece;
}

void padTo(QByteArray &out, int offset, int boundary)
{
    while (offset % boundary != 0) {
        out.append('\0');
        ++offset;
    }
}

int flatten(const Node &node, QByteArray &out, int offset)
{
    for (const Node::Piece &piece : node.spine) {
        if (piece.align > 0) {
            padTo(out, offset, piece.align);
            offset = out.size();
        }
        out.append(piece.bytes);
        offset += piece.bytes.size();
    }
    for (const Node &child : node.children) {
        padTo(out, offset, 4); // pointer referent bodies align to 4
        offset = flatten(child, out, out.size());
    }
    return offset;
}

// Referent ids only have to be unique and non-zero.
struct Referents {
    quint32 next = 0x00020000u;
    quint32 take() { return next++; }
};

// One directory attribute on the wire: the canonical ATTID and its values.
struct AttrValue {
    quint32 attid = 0;
    QList<QByteArray> values;
};

// DSNAME (MS-DRSR 5.50) wire form: structLen, SidLen, GUID, the fixed 28-byte
// SID slot, NameLen (characters WITHOUT the terminator), then the string
// array (max_count then the UTF-16 characters WITH the terminator; peers
// slice StringName[:-1]).
Node dsNameNode(const QString &dn, const QUuid &guid, const QString &sidText)
{
    Node node;
    QByteArray sidBytes = sidText.isEmpty() ? QByteArray() : Ndr::sidFromString(sidText);
    const quint32 sidLen = quint32(sidBytes.size());
    while (sidBytes.size() < 28)
        sidBytes.append('\0');
    const QByteArray chars = Ndr::utf16le(dn + QLatin1Char('\0'));

    // The conformant StringName count precedes the struct (MS-RPCE 14.3.7.2).
    QByteArray countBytes;
    putLe32(countBytes, quint32(chars.size() / 2));
    node.spine.append(Node::Piece{4, countBytes});
    QByteArray structLenBytes;
    putLe32(structLenBytes, 4 + 4 + 16 + 28 + 4 + 4 + quint32(chars.size()));
    node.spine.append(Node::Piece{4, structLenBytes});
    QByteArray sidLenBytes;
    putLe32(sidLenBytes, sidLen);
    node.spine.append(Node::Piece{4, sidLenBytes});
    node.spine.append(guidPiece(guid));
    node.spine.append(rawPiece(sidBytes));
    QByteArray nameLenBytes;
    putLe32(nameLenBytes, quint32(dn.size()));
    node.spine.append(Node::Piece{4, nameLenBytes});
    node.spine.append(rawPiece(chars));
    return node;
}

QByteArray dsNameBytes(const QString &dn, const QUuid &guid, const QString &sidText)
{
    QByteArray out;
    flatten(dsNameNode(dn, guid, sidText), out, 0);
    return out;
}

// Attribute values served for one object, aligned to the canonical attids.
// Password material (unicodePwd, supplementalCredentials) is deliberately not
// served: this DC offers replication-level conformance, not secret export.
QList<AttrValue> attrValues(const DirectoryObject &object, const QUuid &guid)
{
    QList<AttrValue> attrs;
    const QString sidText = object.attributes.value(QStringLiteral("objectSid"));
    const auto add = [&attrs](quint32 attid, QList<QByteArray> values) {
        QList<QByteArray> present;
        for (const QByteArray &value : values) {
            if (!value.isEmpty())
                present.append(value);
        }
        if (!present.isEmpty())
            attrs.append(AttrValue{attid, present});
    };

    const QString sam = object.attributes.value(QStringLiteral("sAMAccountName"));
    add(kAttidSamAccountName, {Ndr::utf16le(sam)});
    add(kAttidObjectSid, {Ndr::sidFromString(sidText)});
    const int slash = object.id.indexOf(QLatin1Char('='));
    add(kAttidName, {Ndr::utf16le(object.id.mid(slash + 1,
                                                 object.id.indexOf(QLatin1Char(','), slash) - slash - 1))});
    add(kAttidDistinguishedName, {Ndr::utf16le(object.id)});
    if (!object.attributes.value(QStringLiteral("description")).isEmpty())
        add(kAttidDescription,
            {Ndr::utf16le(object.attributes.value(QStringLiteral("description")))});
    const QString upn = object.attributes.value(QStringLiteral("userPrincipalName"));
    if (!upn.isEmpty())
        add(kAttidUserPrincipalName, {Ndr::utf16le(upn)});
    bool uacOk = false;
    const quint32 uac =
        object.attributes.value(QStringLiteral("userAccountControl")).toUInt(&uacOk);
    if (uacOk) {
        QByteArray uacValue; // ATTRTYP 0x00090008: 4-byte little-endian integer
        putLe32(uacValue, uac);
        add(kAttidUserAccountControl, {uacValue});
    }
    if (!object.members.isEmpty()) {
        QList<QByteArray> members;
        for (const QString &memberDn : object.members)
            members.append(dsNameBytes(memberDn, objectGuidFor(memberDn), QString()));
        add(kAttidMember, members);
    }
    const QString objectClass = object.type == QStringLiteral("User")
        ? QStringLiteral("user")
        : object.type == QStringLiteral("Security Group") ? QStringLiteral("group")
                                                          : object.type.toLower();
    add(kAttidObjectClass, {Ndr::utf16le(objectClass)});
    add(kAttidCn, {Ndr::utf16le(object.name)});
    const QUuid storedGuid =
        QUuid(object.attributes.value(QStringLiteral("objectGUID")));
    add(kAttidObjectGuid, {guidBytes(storedGuid.isNull() ? guid : storedGuid)});
    add(kAttidInstanceType,
        {QByteArray::fromHex("04000000")}); // placeholder: instanceType = 4
    return attrs;
}

Node attrBlockNode(const QList<AttrValue> &attrs, Referents &refs)
{
    Node block;
    // pAttr points at a conformant ATTR array: its max_count precedes the
    // array body (the inline attrCount in the ENTINF spine already mirrors
    // it), and each ATTR is the interleaved triple
    // (attrTyp, valCount, pAVal referent) — MS-DRSR 2.4.1 ATTR/ATTRBLOCK.
    block.spine.append(u32Piece(quint32(attrs.count())));
    for (const AttrValue &attr : attrs) {
        block.spine.append(u32Piece(attr.attid)); // ATTR.attrTyp
        block.spine.append(u32Piece(quint32(attr.values.count()))); // valCount
        block.spine.append(u32Piece(refs.take())); // pAVal
    }
    for (const AttrValue &attr : attrs) {
        // ATTRVAL_ARRAY defer: max_count, then each (valLen, pVal) spine.
        Node values;
        values.spine.append(u32Piece(quint32(attr.values.count())));
        for (const QByteArray &value : attr.values) {
            values.spine.append(u32Piece(quint32(value.size())));
            values.spine.append(u32Piece(refs.take()));
        }
        for (const QByteArray &value : attr.values) {
            // PBYTE_ARRAY defer per value: max_count then the bytes.
            Node valueLeaf;
            valueLeaf.spine.append(u32Piece(quint32(value.size())));
            valueLeaf.spine.append(rawPiece(value));
            values.children.append(valueLeaf);
        }
        block.children.append(values);
    }
    return block;
}

// One chain element plus, recursively, the rest of the list. Peer walk order
// of the deferrals: the next element first, then the DSNAME, then the
// attribute array, then the parent GUID.
Node chainElement(int index, const QList<DirectoryObject> &batch,
                  const QString &baseDn, Referents &refs)
{
    const DirectoryObject object = batch.at(index);
    const QString dn = object.id;
    const QUuid guid = objectWireGuid(object);
    const QString sidText = object.attributes.value(QStringLiteral("objectSid"));
    const bool ncHead = dn.compare(baseDn, Qt::CaseInsensitive) == 0;
    const QList<AttrValue> attrs = attrValues(object, guid);

    Node element;
    // REPLENTINFLIST: pNextEntInf, ENTINF{pName, ulFlags, AttrBlock},
    // fIsNCPrefix, pParentGuid, pMetaDataExt.
    element.spine.append(u32Piece(index + 1 < batch.count() ? refs.take() : 0));
    element.spine.append(u32Piece(refs.take()));            // ENTINF.pName
    element.spine.append(u32Piece(0x00000001u));            // ENTINF_FROM_MASTER
    element.spine.append(u32Piece(quint32(attrs.count()))); // AttrBlock.attrCount
    element.spine.append(u32Piece(attrs.isEmpty() ? 0 : refs.take())); // pAttr
    element.spine.append(u32Piece(ncHead ? 1u : 0u));       // fIsNCPrefix
    element.spine.append(u32Piece(ncHead ? 0u : refs.take())); // pParentGuid
    element.spine.append(u32Piece(0u));                     // pMetaDataExt: none

    if (index + 1 < batch.count())
        element.children.append(chainElement(index + 1, batch, baseDn, refs));
    element.children.append(dsNameNode(dn, guid, sidText));
    if (!attrs.isEmpty())
        element.children.append(attrBlockNode(attrs, refs));
    if (!ncHead) {
        Node parent;
        parent.spine.append(guidPiece(objectGuidFor(dn.section(QLatin1Char(','), 1))));
        element.children.append(parent);
    }
    return element;
}

// UPTODATE_VECTOR_V2_EXT defer: version, reserved, cursor count, reserved,
// then the cursor array (max_count then the cursors). One cursor: this DC's
// invocation id and the delivered USN (V2 cursors carry the 32-byte form).
Node uptodatenessNode(const QUuid &invocationId, quint64 usn)
{
    Node vector;
    // rgCursors is conformant, so its count precedes the struct (MS-RPCE
    // 14.3.7.2); the cursors themselves follow the four head words directly.
    vector.spine.append(u32Piece(1u));  // array count (precedes the struct)
    vector.spine.append(u32Piece(2u));  // dwVersion
    vector.spine.append(u32Piece(0u));  // dwReserved1
    vector.spine.append(u32Piece(1u));  // cNumCursors
    vector.spine.append(u32Piece(0u));  // dwReserved2
    vector.spine.append(guidPiece(invocationId));
    vector.spine.append(u64Piece(usn));          // usnHighPropUpdate
    vector.spine.append(u64Piece(0u));           // timeLastSyncSuccess
    return vector;
}

// UPTODATE_VECTOR_V1_EXT: the shape a V5 request's reply carries — same head,
// cursors without timeLastSyncSuccess.
Node uptodatenessV1Node(const QUuid &invocationId, quint64 usn)
{
    Node vector;
    vector.spine.append(u32Piece(1u));  // array count (precedes the struct)
    vector.spine.append(u32Piece(1u));  // dwVersion
    vector.spine.append(u32Piece(0u));  // dwReserved1
    vector.spine.append(u32Piece(1u));  // cNumCursors
    vector.spine.append(u32Piece(0u));  // dwReserved2
    vector.spine.append(guidPiece(invocationId));
    vector.spine.append(u64Piece(usn));  // usnHighPropUpdate
    return vector;
}

// The canonical 19-entry MS-DRSR 5.12.2 prefix map. Entry id is the ATTID
// high word; the bytes are the partial binary OID of the prefix OID.
QList<QPair<quint32, QByteArray>> prefixEntries()
{
    static const struct { quint32 id; const char *prefix; } kTable[] = {
        {0x00000000u, "2.5.4"},
        {0x00000001u, "2.5.6"},
        {0x00000002u, "1.2.840.113556.1.2"},
        {0x00000003u, "1.2.840.113556.1.3"},
        {0x00000004u, "2.16.840.1.101.2.2.1"},
        {0x00000005u, "2.16.840.1.101.2.2.3"},
        {0x00000006u, "2.16.840.1.101.2.1.5"},
        {0x00000007u, "2.16.840.1.101.2.1.4"},
        {0x00000008u, "2.5.5"},
        {0x00000009u, "1.2.840.113556.1.4"},
        {0x0000000Au, "1.2.840.113556.1.5"},
        {0x00000013u, "0.9.2342.19200300.100"},
        {0x00000014u, "2.16.840.1.113730.3"},
        {0x00000015u, "0.9.2342.19200300.100.1"},
        {0x00000016u, "2.16.840.1.113730.3.1"},
        {0x00000017u, "1.2.840.113556.1.5.7000"},
        {0x00000018u, "2.5.21"},
        {0x00000019u, "2.5.18"},
        {0x0000001Au, "2.5.20"},
    };
    QList<QPair<quint32, QByteArray>> list;
    for (const auto &entry : kTable)
        list.append(qMakePair(entry.id, berOid(QString::fromLatin1(entry.prefix))));
    return list;
}

// PrefixTableSrc defer, over the canonical 19-entry MS-DRSR 5.12.2 prefix
// map built above. Entry id is the ATTID high word; the bytes are the partial
// binary OID (final sub-identifier stripped).
Node prefixTableNode(Referents &refs)
{
    const QList<QPair<quint32, QByteArray>> entries = prefixEntries();

    Node table;
    table.spine.append(u32Piece(quint32(entries.count()))); // array max_count
    // PrefixTableEntry is a struct: ndx, then OID_t {length, elements ref},
    // interleaved per entry (the inline pPrefixEntry referent id lives in the
    // reply arm's spine, not here).
    for (const auto &entry : entries) {
        table.spine.append(u32Piece(entry.first)); // PrefixTableEntry.ndx
        table.spine.append(u32Piece(quint32(entry.second.size()))); // OID_t.length
        table.spine.append(u32Piece(refs.take()));                  // elements
    }
    for (const auto &entry : entries) {
        // PBYTE_ARRAY defer per entry: max_count then the OID bytes.
        Node oid;
        oid.spine.append(u32Piece(quint32(entry.second.size())));
        oid.spine.append(rawPiece(entry.second));
        table.children.append(oid);
    }
    return table;
}

// One DSNAME out of the request arm's deferred region. StringName is a
// conformant array, so its size information precedes the whole struct
// (MS-RPCE 14.3.7.2): count, structLen, SidLen, GUID, the fixed 28-byte SID
// slot, NameLen, then the UTF-16 characters.
bool readDsName(Ndr::Reader *reader, QString *dn, QUuid *guidOut,
                QByteArray *sidOut, quint32 *sidLenOut)
{
    quint32 preCount = 0;
    quint32 structLen = 0;
    quint32 sidLen = 0;
    quint32 nameLen = 0;
    QByteArray guid;
    QByteArray sid;
    if (!reader->u32(&preCount) || !reader->u32(&structLen) || !reader->u32(&sidLen)
        || !reader->bytes(16, &guid) || !reader->bytes(28, &sid)
        || !reader->u32(&nameLen))
        return false;
    *guidOut = guidFromBytes(guid);
    *sidOut = sid.left(int(qMin(sidLen, quint32(28))));
    *sidLenOut = sidLen;
    if (preCount > 4096)
        return false;
    QByteArray chars;
    if (!reader->bytes(int(preCount) * 2, &chars))
        return false;
    reader->align(4);
    *dn = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                             int(preCount));
    if (dn->endsWith(QLatin1Char('\0')))
        dn->chop(1);
    return true;
}

// A deferred LPWSTR body: MaximumCount, Offset, ActualCount, then the UTF-16
// characters with the terminator. The count carries the terminator because
// the peers count it too: secretsdump slices the last character off pName
// before parsing the GUID out of it.
Node lpwstrNode(const QString &text)
{
    QString withTerminator = text;
    withTerminator.append(QChar(u'\0'));
    const QByteArray chars = Ndr::utf16le(withTerminator);
    const quint32 count = quint32(chars.size() / 2);
    Node node;
    node.spine.append(u32Piece(count));
    node.spine.append(u32Piece(0u)); // Offset
    node.spine.append(u32Piece(count));
    node.spine.append(rawPiece(chars));
    return node;
}

// DS_NAME_FORMAT (MS-DRSR 2.4): the offered/desired vocabulary of
// DsCrackNames, including the two SANS_DOMAIN forms impacket adds.
constexpr quint32 kDsNameFqdn = 0x00000001u;
constexpr quint32 kDsNameNt4 = 0x00000002u;
constexpr quint32 kDsNameDisplay = 0x00000003u;
constexpr quint32 kDsNameUniqueId = 0x00000006u;
constexpr quint32 kDsNameCanonical = 0x00000007u;
constexpr quint32 kDsNameUpn = 0x00000008u;
constexpr quint32 kDsNameCanonicalEx = 0x00000009u;
constexpr quint32 kDsNameSid = 0x0000000bu;
constexpr quint32 kDsNameDnsDomain = 0x0000000cu;
constexpr quint32 kDsNameNt4SansDomain = 0xfffffff9u;
constexpr quint32 kDsNameNt4SansDomainEx = 0xfffffff0u;

// drsuapi_DsNameStatus: what one cracked name reports.
constexpr quint32 kDsStatusOk = 0u;
constexpr quint32 kDsStatusResolveError = 1u;
constexpr quint32 kDsStatusNotFound = 2u;
constexpr quint32 kDsStatusNoSyntacticalMapping = 6u;

// Split a DN at its unescaped commas (RFC 4514 quoting).
QStringList splitDn(const QString &dn)
{
    QStringList rdns;
    QString current;
    bool escaped = false;
    for (const QChar c : dn) {
        if (escaped) {
            current.append(c);
            escaped = false;
        } else if (c == QLatin1Char('\\')) {
            current.append(c);
            escaped = true;
        } else if (c == QLatin1Char(',')) {
            rdns.append(current);
            current.clear();
        } else {
            current.append(c);
        }
    }
    if (!current.isEmpty())
        rdns.append(current);
    return rdns;
}

QString rdnType(const QString &rdn)
{
    const int eq = rdn.indexOf(QLatin1Char('='));
    return (eq < 0 ? rdn : rdn.left(eq)).trimmed();
}

// The value side of one RDN with its escapes resolved.
QString rdnValue(const QString &rdn)
{
    const int eq = rdn.indexOf(QLatin1Char('='));
    const QString value = eq < 0 ? rdn : rdn.mid(eq + 1);
    QString out;
    for (int i = 0; i < value.size(); ++i) {
        if (value.at(i) != QLatin1Char('\\') || i + 1 >= value.size()) {
            out.append(value.at(i));
            continue;
        }
        if (i + 2 < value.size() && value.at(i + 1).isLetterOrNumber()) {
            bool ok = false;
            const int code = value.mid(i + 1, 2).toInt(&ok, 16);
            if (ok) {
                out.append(QChar(code));
                i += 2;
                continue;
            }
        }
        out.append(value.at(i + 1));
        ++i;
    }
    return out;
}

// The trailing DC= components (the DNS domain) split from the RDNs above.
void dnDomainAndPath(const QString &dn, QString *domain, QStringList *path)
{
    const QStringList rdns = splitDn(dn);
    int i = rdns.count();
    QStringList labels;
    while (i > 0
           && rdnType(rdns.at(i - 1)).compare(QLatin1String("DC"),
                                              Qt::CaseInsensitive) == 0) {
        labels.prepend(rdnValue(rdns.at(i - 1)));
        --i;
    }
    *domain = labels.join(QLatin1Char('.'));
    *path = rdns.mid(0, i);
}

// DS_CANONICAL_NAME: the DNS domain, then each remaining RDN value upward
// (corp.example.com/Users/Administrator).
QString dnToCanonical(const QString &dn)
{
    QString domain;
    QStringList path;
    dnDomainAndPath(dn, &domain, &path);
    QStringList segments;
    for (int i = path.count() - 1; i >= 0; --i)
        segments.append(rdnValue(path.at(i)));
    if (!domain.isEmpty())
        segments.prepend(domain);
    return segments.join(QLatin1Char('/'));
}

// DS_CANONICAL_NAME_EX: the domain in DC= form, then the typed RDNs downward.
QString dnToCanonicalEx(const QString &dn)
{
    QString domain;
    QStringList path;
    dnDomainAndPath(dn, &domain, &path);
    QStringList segments;
    if (!domain.isEmpty())
        for (const QString &label : domain.split(QLatin1Char('.')))
            segments.append(QStringLiteral("DC=") + label);
    for (const QString &rdn : path)
        segments.append(rdn);
    return segments.join(QLatin1Char('/'));
}

// The inverse: domain/segment/segment back into a DN. Segment types are not
// carried by the canonical form, so bare segments bind as CN=.
QString canonicalToDn(const QString &name)
{
    const int slash = name.indexOf(QLatin1Char('/'));
    QStringList rdns;
    if (slash < 0)
        return rdns.isEmpty() ? name : rdns.join(QLatin1Char(','));
    const QStringList segments = name.mid(slash + 1).split(QLatin1Char('/'));
    for (int i = segments.count() - 1; i >= 0; --i) {
        if (segments.at(i).isEmpty())
            continue;
        rdns.append(segments.at(i).indexOf(QLatin1Char('=')) < 0
            ? QStringLiteral("CN=") + segments.at(i) : segments.at(i));
    }
    const QString head = name.left(slash);
    if (head.indexOf(QLatin1Char('=')) >= 0) {
        // The canonical-ex head is already in DC= form.
        for (const QString &rdn : splitDn(head))
            rdns.append(rdn);
    } else {
        for (const QString &label : head.split(QLatin1Char('.')))
            if (!label.isEmpty())
                rdns.append(QStringLiteral("DC=") + label);
    }
    return rdns.join(QLatin1Char(','));
}

const DirectoryObject *findObjectByDn(const QList<DirectoryObject> &objects,
                                      const QString &dn)
{
    for (const DirectoryObject &object : objects)
        if (object.id.compare(dn, Qt::CaseInsensitive) == 0)
            return &object;
    return nullptr;
}

const DirectoryObject *findObjectBySam(const QList<DirectoryObject> &objects,
                                       const QString &account)
{
    for (const DirectoryObject &object : objects)
        if (object.attributes.value(QStringLiteral("sAMAccountName"))
                .compare(account, Qt::CaseInsensitive) == 0)
            return &object;
    return nullptr;
}

const DirectoryObject *findObjectByUpn(const QList<DirectoryObject> &objects,
                                       const QString &upn)
{
    for (const DirectoryObject &object : objects)
        if (object.attributes.value(QStringLiteral("userPrincipalName"))
                .compare(upn, Qt::CaseInsensitive) == 0)
            return &object;
    return nullptr;
}

// One name through the offered \u2192 desired translation (MS-DRSR 4.1.13).
// DCSync uses it to turn an account name into the GUID its GetNCChanges pNC
// addresses, and the console to print canonical forms.
struct CrackOutcome {
    quint32 status = kDsStatusOk;
    QString domain;
    QString name;
};

CrackOutcome crackName(const QList<DirectoryObject> &objects,
                       const Samr::Config &config, const QString &dnsDomain,
                       quint32 offered, quint32 desired, quint32 flags,
                       const QString &input)
{
    const bool syntacticOnly = (flags & 0x1u) != 0;
    CrackOutcome outcome;
    outcome.domain = dnsDomain;
    outcome.name = input;
    quint32 status = kDsStatusOk;
    const DirectoryObject *object = nullptr;
    QString dn;

    // Stage one: the offered format resolves to a directory object (or to
    // the domain itself).
    if (offered == kDsNameFqdn) {
        if (input.indexOf(QLatin1Char('=')) < 0) {
            status = kDsStatusResolveError;
        } else {
            QString domain;
            QStringList path;
            dnDomainAndPath(input, &domain, &path);
            if (!domain.isEmpty())
                outcome.domain = domain;
            dn = input;
            object = findObjectByDn(objects, input);
            if (!object && !syntacticOnly)
                status = kDsStatusNotFound;
        }
    } else if (offered == kDsNameCanonical || offered == kDsNameCanonicalEx) {
        if (input.indexOf(QLatin1Char('/')) < 0) {
            status = kDsStatusResolveError;
        } else {
            dn = canonicalToDn(input);
            QString domain;
            QStringList path;
            dnDomainAndPath(dn, &domain, &path);
            if (!domain.isEmpty())
                outcome.domain = domain;
            object = findObjectByDn(objects, dn);
            if (!object && !syntacticOnly)
                status = kDsStatusNotFound;
        }
    } else if (offered == kDsNameNt4 || offered == kDsNameNt4SansDomain
               || offered == kDsNameNt4SansDomainEx) {
        QString account = input;
        if (offered == kDsNameNt4) {
            int sep = input.indexOf(QLatin1Char('\\'));
            if (sep < 0)
                sep = input.indexOf(QLatin1Char('/'));
            if (sep >= 0)
                account = input.mid(sep + 1);
        }
        if (account.isEmpty()) {
            status = kDsStatusResolveError;
        } else {
            object = findObjectBySam(objects, account);
            if (!object)
                object = findObjectByDn(objects, account);
            if (!object)
                for (const DirectoryObject &candidate : objects)
                    if (candidate.name.compare(account, Qt::CaseInsensitive) == 0) {
                        object = &candidate;
                        break;
                    }
            if (object)
                dn = object->id;
            else if (!syntacticOnly)
                status = kDsStatusNotFound;
        }
    } else if (offered == kDsNameUpn) {
        object = findObjectByUpn(objects, input);
        if (!object && input.contains(QLatin1Char('@'))) {
            const QString account = input.left(input.indexOf(QLatin1Char('@')));
            object = findObjectBySam(objects, account);
        }
        if (object)
            dn = object->id;
        else if (!syntacticOnly)
            status = kDsStatusNotFound;
    } else if (offered == kDsNameDisplay) {
        for (const DirectoryObject &candidate : objects) {
            if (candidate.attributes.value(QStringLiteral("displayName"))
                    .compare(input, Qt::CaseInsensitive) == 0
                || candidate.name.compare(input, Qt::CaseInsensitive) == 0) {
                object = &candidate;
                break;
            }
        }
        if (!object)
            object = findObjectBySam(objects, input);
        if (object)
            dn = object->id;
        else if (!syntacticOnly)
            status = kDsStatusNotFound;
    } else if (offered == kDsNameUniqueId) {
        const QUuid guid(input);
        if (guid.isNull()) {
            status = kDsStatusResolveError;
        } else {
            for (const DirectoryObject &candidate : objects)
                if (objectWireGuid(candidate) == guid) {
                    object = &candidate;
                    break;
                }
            if (object)
                dn = object->id;
            else if (!syntacticOnly)
                status = kDsStatusNotFound;
        }
    } else if (offered == kDsNameSid) {
        const QByteArray sid = Ndr::sidFromString(input);
        if (sid.isEmpty()) {
            status = kDsStatusResolveError;
        } else {
            for (const DirectoryObject &candidate : objects) {
                const QByteArray candidateSid = Ndr::sidFromString(
                    candidate.attributes.value(QStringLiteral("objectSid")));
                if (!candidateSid.isEmpty() && candidateSid == sid) {
                    object = &candidate;
                    break;
                }
            }
            if (object)
                dn = object->id;
            else if (!syntacticOnly)
                status = kDsStatusNotFound;
        }
    } else if (offered == kDsNameDnsDomain) {
        outcome.domain = input;
    } else {
        // UNKNOWN, SPN and everything outside this server's vocabulary.
        status = kDsStatusNoSyntacticalMapping;
    }

    // Stage two: render the desired format from what stage one resolved.
    const QString resolvedDn = object ? object->id : dn;
    if (object && !resolvedDn.isEmpty()) {
        QString domain;
        QStringList path;
        dnDomainAndPath(resolvedDn, &domain, &path);
        if (!domain.isEmpty())
            outcome.domain = domain;
    }
    QString account;
    if (object) {
        account = object->attributes.value(QStringLiteral("sAMAccountName"));
        if (account.isEmpty())
            account = object->name;
    }
    switch (desired) {
    case kDsNameFqdn:
        if (!resolvedDn.isEmpty())
            outcome.name = resolvedDn;
        break;
    case kDsNameCanonical:
        if (!resolvedDn.isEmpty())
            outcome.name = dnToCanonical(resolvedDn);
        break;
    case kDsNameCanonicalEx:
        if (!resolvedDn.isEmpty())
            outcome.name = dnToCanonicalEx(resolvedDn);
        break;
    case kDsNameNt4:
    case kDsNameNt4SansDomain:
    case kDsNameNt4SansDomainEx:
        if (object)
            outcome.name = desired == kDsNameNt4
                ? config.netbios + QLatin1Char('\\') + account : account;
        break;
    case kDsNameUniqueId:
        if (object)
            outcome.name = objectWireGuid(*object).toString();
        break;
    case kDsNameUpn:
        if (object) {
            const QString upn =
                object->attributes.value(QStringLiteral("userPrincipalName"));
            outcome.name = upn.isEmpty()
                ? account + QLatin1Char('@') + outcome.domain : upn;
        }
        break;
    case kDsNameDisplay:
        if (object) {
            const QString display =
                object->attributes.value(QStringLiteral("displayName"));
            outcome.name = display.isEmpty() ? object->name : display;
        }
        break;
    case kDsNameDnsDomain:
        outcome.name = outcome.domain;
        break;
    case kDsNameSid:
        if (object) {
            const QString sid =
                object->attributes.value(QStringLiteral("objectSid"));
            if (!sid.isEmpty())
                outcome.name = sid;
        }
        break;
    default:
        break; // the offered name, echoed
    }
    outcome.status = status;
    return outcome;
}

} // namespace

// The batch selection and reply arm encode for DsGetNCChanges. Targeting:
// ulExtendedOp == EXOP_REPL_OBJ addresses one object by the GUID, SID or DN
// the request's pNC carries; a plain cycle pulls the NC above usnvecFrom in
// uSNChanged order, capped at cMaxObjects with fMoreData reporting the rest.
QByteArray DrsServer::drsGetNCChanges(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    if (!m_handles.contains(guidFromBytes(handleBytes)))
        return stubReply(kWerrInvalidHandle);

    quint32 version = 0;
    quint32 tag = 0;
    if (!reader.u32(&version) || !reader.u32(&tag))
        return QByteArray();
    if (version != 5 && version != 8 && version != 10)
        return stubReply(kWerrNotSupported);

    // The union arm is a struct whose hyper fields make it 8-aligned: the
    // arm body opens on an 8 boundary after the tag (MS-RPCE 14.2.11).
    reader.align(8);
    QByteArray destDsa;
    QByteArray sourceInvocation;
    quint32 ncReferent = 0;
    if (!reader.bytes(16, &destDsa) || !reader.bytes(16, &sourceInvocation)
        || !reader.u32(&ncReferent))
        return QByteArray();

    quint64 fromUsn[3] = {0, 0, 0};
    for (int i = 0; i < 3; ++i) {
        reader.align(8); // USN (LONGLONG) fields align to 8 (MS-RPCE 14.2)
        if (!reader.u64(&fromUsn[i]))
            return QByteArray();
    }
    quint32 utdReferent = 0;
    if (!reader.u32(&utdReferent))
        return QByteArray();

    quint32 flags = 0;
    quint32 maxObjects = 0;
    quint32 maxBytes = 0;
    quint32 extendedOp = 0;
    if (tag >= 5) {
        if (!reader.u32(&flags) || !reader.u32(&maxObjects) || !reader.u32(&maxBytes)
            || !reader.u32(&extendedOp))
            return QByteArray();
        quint64 fsmo = 0;
        reader.align(8);
        if (!reader.u64(&fsmo))
            return QByteArray();
    }
    if (tag >= 8) {
        quint32 partial = 0;
        quint32 partialEx = 0;
        quint32 prefixCount = 0;
        if (!reader.u32(&partial) || !reader.u32(&partialEx)
            || !reader.u32(&prefixCount) || !reader.u32(&partial))
            return QByteArray();
    }

    // Deferred region: pNC first (the pieces beyond it are not consumed).
    QString ncDn;
    QUuid ncGuid;
    QByteArray ncSidBytes;
    quint32 ncSidLen = 0;
    bool haveNc = false;
    if (tag == 10) {
        quint32 moreFlags = 0;
        if (!reader.u32(&moreFlags))
            return QByteArray();
    }
    if (ncReferent != 0) {
        haveNc = readDsName(&reader, &ncDn, &ncGuid, &ncSidBytes, &ncSidLen);
        if (!haveNc)
            return QByteArray();
    }

    const QList<DirectoryObject> all = directory();

    // Target resolution: GUID first, then SID, then DN. An empty pNC or a
    // bare-NC DSNAME means the whole domain NC.
    const bool targeted = extendedOp == kExopReplObj
        && (!ncDn.isEmpty() || !ncGuid.isNull() || ncSidLen != 0);
    QList<QPair<quint64, DirectoryObject>> changed;
    if (targeted) {
        for (const DirectoryObject &object : all) {
            if (!ncGuid.isNull()) {
                if (objectWireGuid(object) != ncGuid)
                    continue;
            } else if (ncSidLen != 0) {
                const QByteArray objectSid =
                    Ndr::sidFromString(object.attributes.value(QLatin1String("objectSid")));
                if (objectSid.left(int(ncSidLen)) != ncSidBytes.left(int(ncSidLen)))
                    continue;
            } else if (!ncDn.isEmpty()
                       && object.id.compare(ncDn, Qt::CaseInsensitive) != 0) {
                continue;
            }
            changed.append(qMakePair(storeUsn(object), object));
        }
    } else {
        for (const DirectoryObject &object : all) {
            if (!ncDn.isEmpty() && object.id != ncDn
                && !object.id.endsWith(QLatin1Char(',') + ncDn, Qt::CaseInsensitive))
                continue;
            const quint64 usn = storeUsn(object);
            if (usn > fromUsn[0])
                changed.append(qMakePair(usn, object));
        }
        std::sort(changed.begin(), changed.end(),
                  [](const QPair<quint64, DirectoryObject> &a,
                     const QPair<quint64, DirectoryObject> &b) {
                      return a.first < b.first;
                  });
    }

    // cMaxObjects cuts the cycle; fMoreData tells the partner to come back.
    const quint32 cap = maxObjects == 0 ? kDefaultBatchCap : maxObjects;
    bool capped = false;
    if (changed.count() > int(cap)) {
        capped = true;
        while (changed.count() > int(cap))
            changed.removeLast();
    }
    const int batchCount = changed.count();
    QList<DirectoryObject> batch;
    for (const QPair<quint64, DirectoryObject> &entry : changed)
        batch.append(entry.second);
    const quint64 deliveredUsn =
        batch.isEmpty() ? fromUsn[0] : changed[batchCount - 1].first;

    // The reply arm: V6 shape for V8/V10 requests, V1 for V5, spine then
    // deferred bodies (pNC, vector, prefix table, object chain).
    const quint32 outVersion = version >= 8 ? 6u : 1u;
    const quint32 ret = targeted ? kExtRetSuccess : kExtRetNone;
    const QUuid invocation = m_invocationId.isNull()
        ? Drs::invocationId(m_config.domainSid, m_config.netbios)
        : m_invocationId;
    const QUuid sourceDsa = m_sourceDsaGuid.isNull()
        ? Drs::sourceDsaGuid(m_config.domainSid, m_config.netbios)
        : m_sourceDsaGuid;

    // The object chain is rendered first: cNumBytes reports the size of the
    // returned object data, and the chain goes out as the arm's last body.
    Referents refs;
    Node chain;
    quint32 numBytes = 0;
    if (!batch.isEmpty()) {
        chain = chainElement(0, batch, QString(baseDn()), refs);
        QByteArray chainBytes;
        flatten(chain, chainBytes, 0);
        numBytes = quint32(chainBytes.size());
    }

    Node arm;
    arm.spine.append(guidPiece(sourceDsa)); // uuidDsaObjSrc
    arm.spine.append(guidPiece(invocation)); // uuidInvocIdSrc
    arm.spine.append(u32Piece(haveNc || targeted ? refs.take() : 0)); // pNC ref
    for (int i = 0; i < 3; ++i) // usnvecFrom echoes the request
        arm.spine.append(u64Piece(fromUsn[i]));
    arm.spine.append(u64Piece(deliveredUsn)); // usnvecTo.usnHighObjUpdate
    arm.spine.append(u64Piece(0));            // usnReserved
    arm.spine.append(u64Piece(deliveredUsn)); // usnHighPropUpdate
    arm.spine.append(u32Piece(refs.take())); // pUpToDateVecSrc
    arm.spine.append(u32Piece(kPrefixEntryCount)); // PrefixTableSrc.PrefixCount
    arm.spine.append(u32Piece(refs.take())); // pPrefixEntry
    arm.spine.append(u32Piece(ret));         // ulExtendedRet
    arm.spine.append(u32Piece(quint32(batchCount)));
    arm.spine.append(u32Piece(numBytes));    // cNumBytes
    arm.spine.append(u32Piece(batch.isEmpty() ? 0 : refs.take())); // pObjects
    arm.spine.append(u32Piece(capped ? 1u : 0u));                  // fMoreData
    if (outVersion == 6) {
        arm.spine.append(u32Piece(quint32(all.count()))); // cNumNcSizeObjectsc
        arm.spine.append(u32Piece(0u));                   // cNumNcSizeValues
        arm.spine.append(u32Piece(0u));                   // cNumValues
        arm.spine.append(u32Piece(0u));                   // rgValues: none
        arm.spine.append(u32Piece(0u));                   // dwDRSError
    }

    const QString replyNcDn =
        ncDn.isEmpty() ? QString(baseDn()) : ncDn;
    if (haveNc)
        arm.children.append(dsNameNode(replyNcDn,
                                       objectGuidFor(replyNcDn),
                                       m_config.domainSid));
    arm.children.append(outVersion == 6
        ? uptodatenessNode(invocation, deliveredUsn)
        : uptodatenessV1Node(invocation, deliveredUsn));
    arm.children.append(prefixTableNode(refs));
    if (!batch.isEmpty()) {
        arm.children.append(chain);
    }

    // The response: pdwOutVersion, the DRS_MSG_GETCHGREPLY union (tag, arm),
    // then the call's trailing ErrorCode.
    QByteArray armBytes;
    flatten(arm, armBytes, 0);
    Ndr::Writer writer;
    writer.u32(outVersion); // pdwOutVersion
    writer.u32(outVersion); // pmsgOut union tag
    writer.bytes(armBytes);
    writer.u32(kWerrOk);    // ErrorCode
    return writer.take();
}

// DsBind (opnum 0): returns the handle every other call of the session
// carries, plus the extension words that shape the GetNCChanges conversation.
QByteArray DrsServer::drsBind(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    bool haveClientDsa = false;
    if (!reader.referent(&haveClientDsa))
        return QByteArray();
    if (haveClientDsa) {
        QByteArray clientDsa;
        if (!reader.bytes(16, &clientDsa))
            return QByteArray();
    }
    bool haveExt = false;
    if (!reader.referent(&haveExt))
        return QByteArray();
    if (haveExt) {
        quint32 cb = 0;
        if (!reader.u32(&cb))
            return QByteArray();
        quint32 rgbCount = 0;
        if (!reader.u32(&rgbCount))
            return QByteArray();
        if (rgbCount > 4096 || !reader.skip(int(rgbCount)))
            return QByteArray();
    }

    // DRS_EXTENSIONS_INT (MS-DRSR 5.39): the dwFlags word advertises exactly
    // the request/reply shapes this server serves, nothing else.
    QByteArray ext;
    putLe32(ext, 0x25100000u);   // GETCHGREQ V5/V8/V10, GETCHGREPLY V6
    for (int i = 0; i < 16; ++i) // SiteObjGuid
        ext.append(char(0));
    putLe32(ext, 0u);            // Pid
    putLe32(ext, 0u);            // dwReplEpoch
    putLe32(ext, 0u);            // dwFlagsExt
    for (int i = 0; i < 16; ++i) // ConfigObjGuid
        ext.append(char(0));
    putLe32(ext, 0u);            // dwExtCaps

    const QUuid handle = QUuid::createUuid();
    m_handles.insert(handle, QString());

    Ndr::Writer writer;
    writer.u32(0x00020000u);         // ppextServer referent: non-null
    writer.u32(quint32(ext.size())); // DRS_EXTENSIONS.cb
    writer.u32(quint32(ext.size())); // rgb max_count (conformant array)
    writer.bytes(ext);
    writer.bytes(guidBytes(handle)); // phDrs: 16-byte UUID + 4-byte pad
    writer.bytes(QByteArray(4, '\0'));
    writer.u32(kWerrOk);             // ErrorCode
    return writer.take();
}

// DsUnbind (opnum 1): retires the handle the stub carries.
QByteArray DrsServer::drsUnbind(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    const QUuid handle = guidFromBytes(handleBytes);
    const bool ok = m_handles.contains(handle);
    if (ok)
        m_handles.remove(handle);

    Ndr::Writer writer;
    writer.bytes(handleBytes); // phDrs echo
    writer.u32(ok ? kWerrOk : kWerrInvalidHandle);
    return writer.take();
}

// DsReplicaSync (opnum 21) and DsUpdateRefs (opnum 22): the lifecycle calls a
// replication cycle makes around GetNCChanges. Both answer from handle
// validity; the cycle itself is served by DsGetNCChanges.
QByteArray DrsServer::drsReplicaSync(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    if (!m_handles.contains(guidFromBytes(handleBytes)))
        return stubReply(kWerrInvalidHandle);
    return stubReply(kWerrOk);
}

QByteArray DrsServer::drsUpdateRefs(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    if (!m_handles.contains(guidFromBytes(handleBytes)))
        return stubReply(kWerrInvalidHandle);
    return stubReply(kWerrOk);
}

// DsGetDomainControllerInfo (opnum 16): this DC described at the requested
// info level (MS-DRSR 4.1.5). The DCSync flow reads level 2 for the DSA GUID
// it addresses GetNCChanges with.
QByteArray DrsServer::drsDomainControllerInfo(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    if (!m_handles.contains(guidFromBytes(handleBytes)))
        return stubReply(kWerrInvalidHandle);

    quint32 version = 0;
    quint32 tag = 0;
    if (!reader.u32(&version) || !reader.u32(&tag))
        return QByteArray();
    if (version != 1 || tag != 1)
        return stubReply(kWerrNotSupported);

    // V1: Domain (LPWSTR referent), then InfoLevel. The domain string body
    // is deferred past the arm; this is a single-DC directory, so the answer
    // does not depend on which domain name the caller spelled.
    quint32 domainReferent = 0;
    quint32 infoLevel = 0;
    if (!reader.u32(&domainReferent) || !reader.u32(&infoLevel))
        return QByteArray();

    const bool supported = infoLevel == 1 || infoLevel == 2 || infoLevel == 3
        || infoLevel == 0xffffffffu;
    const quint32 outVersion = supported ? infoLevel : 1u;

    Node arm;
    if (supported && infoLevel != 0xffffffffu) {
        const QString dnsDomain =
            m_dnsDomain.isEmpty() ? m_config.realm.toLower() : m_dnsDomain;
        const QString dcName = m_config.netbios;
        const QString site = QStringLiteral("Default-First-Site-Name");
        const QString configDn = QStringLiteral("CN=Configuration,") + baseDn();
        const QString siteDn =
            QStringLiteral("CN=%1,CN=Sites,%2").arg(site, configDn);
        const QString serverDn =
            QStringLiteral("CN=%1,CN=Servers,%2").arg(dcName, siteDn);
        const QString ntdsDsaDn = QStringLiteral("CN=NTDS Settings,") + serverDn;
        const QString computerDn =
            QStringLiteral("CN=%1,OU=Domain Controllers,%2").arg(dcName, baseDn());
        const QUuid dsaGuid = m_sourceDsaGuid.isNull()
            ? Drs::sourceDsaGuid(m_config.domainSid, m_config.netbios)
            : m_sourceDsaGuid;

        const QString hostName =
            dcName.toLower() + QLatin1Char('.') + dnsDomain;
        QStringList names{dcName, hostName, site};
        if (infoLevel >= 2)
            names << siteDn << computerDn << serverDn << ntdsDsaDn;
        else
            names << computerDn << serverDn;

        Referents refs;
        Node item;
        for (const QString &name : names)
            item.spine.append(u32Piece(refs.take())); // LPWSTR referents
        item.spine.append(u32Piece(1u));              // fIsPdc
        item.spine.append(u32Piece(1u));              // fDsEnabled
        if (infoLevel >= 2)
            item.spine.append(u32Piece(1u));          // fIsGc
        if (infoLevel == 3)
            item.spine.append(u32Piece(0u));          // fIsRodc
        if (infoLevel >= 2) {
            item.spine.append(guidPiece(objectGuidFor(siteDn)));
            item.spine.append(guidPiece(objectGuidFor(computerDn)));
            item.spine.append(guidPiece(objectGuidFor(serverDn)));
            // The NTDS Settings GUID is this DSA itself: the GUID a
            // partner's GetNCChanges addresses, so it agrees with the
            // uuidDsaObjSrc the replication replies stamp.
            item.spine.append(guidPiece(dsaGuid));
        }

        Node array;
        array.spine.append(u32Piece(1u)); // conformant max_count
        for (const Node::Piece &piece : item.spine)
            array.spine.append(piece);
        for (const QString &name : names)
            array.children.append(lpwstrNode(name));

        arm.spine.append(u32Piece(1u));          // cItems
        arm.spine.append(u32Piece(refs.take())); // rItems
        arm.children.append(array);
    } else {
        // The connection-info arm answers with no rows; an unknown level
        // gets the same shape with an error attached.
        arm.spine.append(u32Piece(0u)); // cItems
        arm.spine.append(u32Piece(0u)); // rItems: NULL
    }

    QByteArray armBytes;
    flatten(arm, armBytes, 0);
    Ndr::Writer writer;
    writer.u32(outVersion); // pdwOutVersion
    writer.u32(outVersion); // pmsgOut union tag
    writer.bytes(armBytes);
    writer.u32(supported ? kWerrOk : kWerrNotSupported);
    return writer.take();
}

// DsCrackNames (opnum 12): offered \u2192 desired name translation resolved in the
// same directory (MS-DRSR 4.1.13). The DCSync flow turns an account name
// into the GUID its GetNCChanges pNC addresses.
QByteArray DrsServer::drsCrackNames(const QByteArray &stub)
{
    Ndr::Reader reader(stub);
    QByteArray handleBytes;
    if (!reader.bytes(kDrsHandleSize, &handleBytes))
        return QByteArray();
    if (!m_handles.contains(guidFromBytes(handleBytes)))
        return stubReply(kWerrInvalidHandle);

    quint32 version = 0;
    quint32 tag = 0;
    if (!reader.u32(&version) || !reader.u32(&tag))
        return QByteArray();
    if (version != 1 || tag != 1)
        return stubReply(kWerrNotSupported);

    quint32 codePage = 0;
    quint32 localeId = 0;
    quint32 flags = 0;
    quint32 offered = 0;
    quint32 desired = 0;
    quint32 cNames = 0;
    quint32 namesReferent = 0;
    if (!reader.u32(&codePage) || !reader.u32(&localeId) || !reader.u32(&flags)
        || !reader.u32(&offered) || !reader.u32(&desired) || !reader.u32(&cNames)
        || !reader.u32(&namesReferent))
        return QByteArray();
    Q_UNUSED(codePage);
    Q_UNUSED(localeId);
    Q_UNUSED(cNames);

    // rpNames: a conformant array of LPWSTR referents, then the string
    // bodies in element order (the array's own max_count governs).
    QStringList names;
    if (namesReferent != 0) {
        quint32 maxCount = 0;
        if (!reader.u32(&maxCount) || maxCount > 4096)
            return QByteArray();
        QList<quint32> refs;
        for (quint32 i = 0; i < maxCount; ++i) {
            quint32 ref = 0;
            if (!reader.u32(&ref))
                return QByteArray();
            refs.append(ref);
        }
        for (quint32 ref : refs) {
            if (ref == 0) {
                names.append(QString());
                continue;
            }
            quint32 maximum = 0;
            quint32 offset = 0;
            quint32 actual = 0;
            if (!reader.u32(&maximum) || !reader.u32(&offset)
                || !reader.u32(&actual) || actual > 32768)
                return QByteArray();
            QByteArray chars;
            if (!reader.bytes(int(actual) * 2, &chars))
                return QByteArray();
            QString name = QString::fromUtf16(
                reinterpret_cast<const char16_t *>(chars.constData()), int(actual));
            while (name.endsWith(QChar(u'\0')))
                name.chop(1);
            names.append(name);
        }
    }

    const QList<DirectoryObject> objects = directory();
    const QString dnsDomain =
        m_dnsDomain.isEmpty() ? m_config.realm.toLower() : m_dnsDomain;

    Referents refs;
    Node array;
    // The rItems referent is a conformant array: its max_count precedes the
    // item structs (MS-RPCE 14.3.7.2).
    array.spine.append(u32Piece(quint32(names.count())));
    for (const QString &name : names) {
        const CrackOutcome cracked = crackName(objects, m_config, dnsDomain,
                                               offered, desired, flags, name);
        array.spine.append(u32Piece(cracked.status));
        array.spine.append(u32Piece(refs.take())); // pDomain
        array.spine.append(u32Piece(refs.take())); // pName
        array.children.append(lpwstrNode(cracked.domain));
        array.children.append(lpwstrNode(cracked.name));
    }

    Node result;
    result.spine.append(u32Piece(quint32(names.count()))); // cItems
    result.spine.append(u32Piece(names.isEmpty() ? 0 : refs.take())); // rItems
    if (!names.isEmpty())
        result.children.append(array);

    Node arm;
    arm.spine.append(u32Piece(refs.take())); // pResult
    arm.children.append(result);

    QByteArray armBytes;
    flatten(arm, armBytes, 0);
    Ndr::Writer writer;
    writer.u32(1); // pdwOutVersion
    writer.u32(1); // pmsgOut union tag
    writer.bytes(armBytes);
    writer.u32(kWerrOk);
    return writer.take();
}

namespace Drs {

Rpc::Interface interface()
{
    Rpc::Interface iface;
    // e3514235-4b06-11d1-ab04-00c04fc2dcd2, the DRSUAPI interface, 4.0 — the
    // abstract syntax the reference IDL registers (reference/specs/
    // samba-drsuapi.idl, librpc/idl/drsuapi.idl) and what impacket binds.
    iface.uuid = QByteArray::fromHex("35 42 51 e3 06 4b d1 11 ab 04 00 c0 4f c2 dc d2");
    iface.major = 4;
    iface.minor = 0;
    iface.name = QStringLiteral("DRSUAPI");
    return iface;
}

QList<QPair<quint32, QByteArray>> prefixTable()
{
    return prefixEntries();
}

QByteArray partialBinaryOid(const char *oidText)
{
    return berOid(QString::fromLatin1(oidText));
}

// Stable per-DC identity, derived from the domain SID and DC name so cursors
// and GUID checks survive a restart without a store write.
QUuid invocationId(const QString &domainSid, const QString &dcName)
{
    return derivedGuid(QStringLiteral("monarchy-invocation/") + domainSid
                       + QLatin1Char('/') + dcName);
}

QUuid sourceDsaGuid(const QString &domainSid, const QString &dcName)
{
    return derivedGuid(QStringLiteral("monarchy-dsa/") + domainSid
                       + QLatin1Char('/') + dcName);
}

} // namespace Drs

DrsServer::DrsServer(QObject *parent) : QObject(parent)
{
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Drs::interface(), [this](const Rpc::Call &call) {
        return handleCall(call.opnum, call.stub);
    });
    connect(m_rpc, &RpcServer::requestReceived, this, &DrsServer::requestReceived);
}

void DrsServer::setConfig(const Samr::Config &config)
{
    m_config = config;
    if (m_dnsDomain.isEmpty())
        m_dnsDomain = config.realm.toLower();
}

void DrsServer::setDomainNames(const QString &netbios, const QString &serverName,
                               const QString &dnsDomain)
{
    m_config.netbios = netbios;
    m_dnsDomain = dnsDomain;
    // The NTLM CHALLENGE the bind answers with is built by the RPC layer from
    // these names: without them the target info carries no MsvAvDnsComputerName
    // and clients that derive an SPN from it (impacket) abort the handshake.
    m_rpc->setDomainNames(netbios, serverName, dnsDomain);
}

void DrsServer::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = provider;
}

void DrsServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_rpc->setAuthenticator(authenticator);
}

bool DrsServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void DrsServer::close()
{
    m_rpc->close();
}

bool DrsServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 DrsServer::serverPort() const
{
    return m_rpc->serverPort();
}

QList<DirectoryObject> DrsServer::directory() const
{
    return m_provider ? m_provider() : QList<DirectoryObject>();
}

quint64 DrsServer::storeUsn(const DirectoryObject &object) const
{
    // Records do not change at runtime; serve a stable per-object uSNChanged.
    return 10000u + quint64(qHash(object.id)) % 900000u;
}

QByteArray DrsServer::handleCall(quint16 opnum, const QByteArray &stub)
{
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("DRS opnum %u stub %s", opnum, stub.toHex().constData());
    switch (opnum) {
    case 0:
        return drsBind(stub);
    case 1:
        return drsUnbind(stub);
    case 3:
        return drsGetNCChanges(stub);
    case 12:
        return drsCrackNames(stub);
    case 16:
        return drsDomainControllerInfo(stub);
    case 21:
        return drsReplicaSync(stub);
    case 22:
        return drsUpdateRefs(stub);
    default:
        // Only the calls this server implements are described; the rest are
        // refused rather than answered as if understood.
        return stubReply(kWerrNotSupported);
    }
}
