// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Ndr.h"

#include <QStringList>

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

} // namespace

namespace Ndr {

QByteArray utf16le(const QString &text)
{
    QByteArray out;
    out.reserve(text.size() * 2);
    for (const QChar c : text) {
        out.append(char(c.unicode() & 0xff));
        out.append(char((c.unicode() >> 8) & 0xff));
    }
    return out;
}

void Writer::u8(quint8 value)
{
    m_buffer.append(char(value));
}

void Writer::u16(quint16 value)
{
    align(2);
    putLe16(m_buffer, value);
}

void Writer::u32(quint32 value)
{
    align(4);
    putLe32(m_buffer, value);
}

void Writer::u64(quint64 value)
{
    align(8);
    putLe32(m_buffer, quint32(value & 0xffffffffu));
    putLe32(m_buffer, quint32((value >> 32) & 0xffffffffu));
}

void Writer::bytes(const QByteArray &data)
{
    m_buffer.append(data);
}

void Writer::referent(bool present)
{
    u32(present ? m_nextReferent++ : 0);
}

void Writer::conformantCount(quint32 count)
{
    u32(count);
}

void Writer::align(int boundary)
{
    while (m_buffer.size() % boundary != 0)
        m_buffer.append('\0');
}

bool Reader::take(int count, QByteArray *out)
{
    if (count < 0 || m_pos + count > m_data.size())
        return false;
    if (out)
        *out = m_data.mid(m_pos, count);
    m_pos += count;
    return true;
}

bool Reader::u8(quint8 *out)
{
    QByteArray value;
    if (!take(1, &value))
        return false;
    if (out)
        *out = quint8(value.at(0));
    return true;
}

bool Reader::u16(quint16 *out)
{
    align(2);
    QByteArray value;
    if (!take(2, &value))
        return false;
    if (out)
        *out = quint16(quint8(value.at(0)) | (quint8(value.at(1)) << 8));
    return true;
}

bool Reader::u32(quint32 *out)
{
    align(4);
    QByteArray value;
    if (!take(4, &value))
        return false;
    if (out)
        *out = quint32(quint8(value.at(0))) | (quint32(quint8(value.at(1))) << 8)
               | (quint32(quint8(value.at(2))) << 16) | (quint32(quint8(value.at(3))) << 24);
    return true;
}

bool Reader::u64(quint64 *out)
{
    align(8);
    quint32 low = 0;
    quint32 high = 0;
    if (!u32(&low) || !u32(&high))
        return false;
    if (out)
        *out = quint64(low) | (quint64(high) << 32);
    return true;
}

bool Reader::bytes(int count, QByteArray *out)
{
    return take(count, out);
}

bool Reader::referent(bool *present)
{
    quint32 id = 0;
    if (!u32(&id))
        return false;
    if (present)
        *present = id != 0;
    return true;
}

bool Reader::conformantCount(quint32 *count)
{
    return u32(count);
}

bool Reader::skip(int count)
{
    return take(count, nullptr);
}

void Reader::align(int boundary)
{
    while (m_pos % boundary != 0 && m_pos < m_data.size())
        ++m_pos;
}

void writeRpcUnicodeString(Writer &writer, const QString &text, bool present)
{
    writer.align(4);
    writer.referent(present);
    if (!present)
        return;
    const QByteArray utf16 = utf16le(text);
    writer.u16(quint16(utf16.size()));
    writer.u16(quint16(utf16.size() + 2)); // room for the terminator
    writer.conformantCount(quint32(utf16.size() / 2 + 1));
    writer.bytes(utf16);
    writer.u16(0); // NUL terminator
    writer.align(4);
}

bool readRpcUnicodeString(Reader &reader, QString *text)
{
    bool present = false;
    if (!reader.referent(&present))
        return false;
    if (!present) {
        if (text)
            text->clear();
        return true;
    }
    quint16 length = 0;
    quint16 maximum = 0;
    quint32 count = 0;
    if (!reader.u16(&length) || !reader.u16(&maximum) || !reader.conformantCount(&count))
        return false;
    Q_UNUSED(maximum)
    Q_UNUSED(count)
    QByteArray chars;
    if (!reader.bytes(length, &chars))
        return false;
    if (text)
        *text = QString::fromUtf16(reinterpret_cast<const char16_t *>(chars.constData()),
                                   qsizetype(chars.size() / 2));
    // The terminator and padding are only on the wire for a varying string.
    reader.skip(2);
    reader.align(4);
    return true;
}

void writeSid(Writer &writer, const QByteArray &sid)
{
    writer.align(4);
    if (sid.size() < 8) {
        // A NULL SID still occupies the header so the caller keeps its layout.
        writer.bytes(QByteArray(8, '\0'));
        return;
    }
    writer.bytes(sid.left(8));
    for (int i = 8; i + 4 <= sid.size(); i += 4)
        writer.bytes(sid.mid(i, 4));
}

bool readSid(Reader &reader, QByteArray *sid)
{
    reader.align(4);
    QByteArray header;
    if (!reader.bytes(8, &header))
        return false;
    const int count = quint8(header.at(1));
    QByteArray out = header;
    for (int i = 0; i < count; ++i) {
        QByteArray sub;
        if (!reader.bytes(4, &sub))
            return false;
        out.append(sub);
    }
    if (sid)
        *sid = out;
    return true;
}

QByteArray sidFromString(const QString &text)
{
    const QStringList parts = text.split(QLatin1Char('-'));
    if (parts.size() < 4 || parts.first() != QLatin1String("S"))
        return {};
    // S-<revision>-<authority>-<sub authority>...
    bool ok = false;
    const int revision = parts.at(1).toInt(&ok);
    if (!ok)
        return {};
    const quint64 authority = parts.at(2).toULongLong(&ok);
    if (!ok || parts.size() - 3 > 15)
        return {};

    QByteArray out;
    out.append(char(revision & 0xff));
    out.append(char((parts.size() - 3) & 0xff));
    for (int i = 5; i >= 0; --i)
        out.append(char((authority >> (8 * i)) & 0xff));
    for (int i = 3; i < parts.size(); ++i) {
        const quint32 sub = parts.at(i).toUInt(&ok);
        if (!ok)
            return {};
        putLe32(out, sub);
    }
    return out;
}

QString sidToString(const QByteArray &sid)
{
    if (sid.size() < 8)
        return {};
    const int revision = quint8(sid.at(0));
    const int count = quint8(sid.at(1));
    quint64 authority = 0;
    for (int i = 2; i < 8; ++i)
        authority = (authority << 8) | quint8(sid.at(i));
    QStringList parts;
    parts << QStringLiteral("S") << QString::number(revision) << QString::number(authority);
    for (int i = 0; i < count; ++i) {
        const int offset = 8 + i * 4;
        if (offset + 4 > sid.size())
            break;
        const quint32 sub = quint32(quint8(sid.at(offset)))
                            | (quint32(quint8(sid.at(offset + 1))) << 8)
                            | (quint32(quint8(sid.at(offset + 2))) << 16)
                            | (quint32(quint8(sid.at(offset + 3))) << 24);
        parts << QString::number(sub);
    }
    return parts.join(QLatin1Char('-'));
}

} // namespace Ndr
