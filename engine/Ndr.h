// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NDR_H
#define NDR_H

#include <QByteArray>
#include <QString>

// NDR (DCE/RPC transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2) as the
// AD RPC interfaces marshal it (MS-RPCE §2.2.6): little-endian scalars on
// natural boundaries, 4-byte referent ids for pointers, and the pointed-to data
// deferred to the end of the enclosing structure.
namespace Ndr {

QByteArray utf16le(const QString &text);

class Writer
{
public:
    void u8(quint8 value);
    void u16(quint16 value);
    void u32(quint32 value);
    void u64(quint64 value);
    // Raw octets, no length prefix and no padding after them.
    void bytes(const QByteArray &data);
    // One referent id: 0 for NULL, otherwise a unique non-zero value.
    void referent(bool present);
    void conformantCount(quint32 count);
    // Pad to a boundary, 4 by default, 8 where the interface requires it.
    void align(int boundary = 4);

    int size() const { return m_buffer.size(); }
    QByteArray take() { return m_buffer; }
    const QByteArray &data() const { return m_buffer; }

private:
    QByteArray m_buffer;
    quint32 m_nextReferent = 0x00020000;
};

class Reader
{
public:
    Reader() = default;
    explicit Reader(const QByteArray &data) : m_data(data) {}

    bool u8(quint8 *out);
    bool u16(quint16 *out);
    bool u32(quint32 *out);
    bool u64(quint64 *out);
    bool bytes(int count, QByteArray *out);
    // Reads a referent id and reports whether it was non-NULL.
    bool referent(bool *present);
    bool conformantCount(quint32 *count);
    bool skip(int count);
    void align(int boundary = 4);

    int remaining() const { return m_data.size() - m_pos; }
    bool atEnd() const { return m_pos >= m_data.size(); }
    int position() const { return m_pos; }

private:
    bool take(int count, QByteArray *out);

    QByteArray m_data;
    int m_pos = 0;
};

// An RPC_UNICODE_STRING: Length, MaximumLength and a referent to the UTF-16
// buffer, which NDR writes as max_count followed by the characters.
void writeRpcUnicodeString(Writer &writer, const QString &text, bool present = true);
bool readRpcUnicodeString(Reader &reader, QString *text);

// SID: revision, sub-authority count, 48-bit authority, then the sub-authorities.
void writeSid(Writer &writer, const QByteArray &sid);
bool readSid(Reader &reader, QByteArray *sid);

// Builds a SID from "S-1-5-21-1-2-3-500".
QByteArray sidFromString(const QString &text);
QString sidToString(const QByteArray &sid);

} // namespace Ndr

#endif // NDR_H
