// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Asn1.h"

#include <QDateTime>
#include <QStringList>
#include <QTimeZone>

namespace {

bool readLength(const QByteArray &data, int &pos, int *length)
{
    if (pos >= data.size())
        return false;
    int value = quint8(data.at(pos++));
    if (!(value & 0x80)) {
        *length = value;
        return true;
    }
    const int octets = value & 0x7f;
    if (octets == 0 || octets > 4 || pos + octets > data.size())
        return false;
    value = 0;
    for (int i = 0; i < octets; ++i)
        value = (value << 8) | quint8(data.at(pos++));
    if (value < 0)
        return false;
    *length = value;
    return true;
}

} // namespace

namespace Asn1 {

QByteArray encodeLength(int length)
{
    if (length < 0x80)
        return QByteArray(1, char(length));
    QByteArray bytes;
    int value = length;
    while (value > 0) {
        bytes.prepend(char(value & 0xff));
        value >>= 8;
    }
    QByteArray out(1, char(0x80 | bytes.size()));
    out.append(bytes);
    return out;
}

QByteArray tlv(quint8 tag, const QByteArray &content)
{
    QByteArray out(1, char(tag));
    out.append(encodeLength(content.size()));
    out.append(content);
    return out;
}

QByteArray integer(quint8 tag, qint64 value)
{
    QByteArray body;
    if (value == 0) {
        body.append('\0');
    } else if (value > 0) {
        quint64 remaining = quint64(value);
        while (remaining > 0) {
            body.prepend(char(remaining & 0xff));
            remaining >>= 8;
        }
        if (body.at(0) & 0x80)
            body.prepend('\0');
    } else {
        // Two's complement, minimal length. Kerberos only uses non-negative
        // values, but a negative one must still encode correctly.
        quint64 remaining = quint64(value);
        while (true) {
            const char octet = char(remaining & 0xff);
            body.prepend(octet);
            remaining >>= 8;
            if ((remaining == 0 && !(octet & 0x80))
                || (remaining == ~quint64(0) && (octet & 0x80)))
                break;
        }
    }
    return tlv(tag, body);
}

QByteArray bits(quint8 tag, quint32 flags)
{
    QByteArray body(1, '\0'); // no unused bits
    body.append(char((flags >> 24) & 0xff));
    body.append(char((flags >> 16) & 0xff));
    body.append(char((flags >> 8) & 0xff));
    body.append(char(flags & 0xff));
    return tlv(tag, body);
}

QByteArray octets(quint8 tag, const QByteArray &value)
{
    return tlv(tag, value);
}

QByteArray string(quint8 tag, const QString &value)
{
    return tlv(tag, value.toUtf8());
}

QByteArray generalizedTime(quint8 tag, qint64 secondsSinceEpoch)
{
    const QDateTime moment = QDateTime::fromSecsSinceEpoch(secondsSinceEpoch, QTimeZone::UTC);
    return tlv(tag, moment.toString(QStringLiteral("yyyyMMddHHmmss'Z'")).toLatin1());
}

QByteArray sequence(const QByteArray &content)
{
    return tlv(0x30, content);
}

QByteArray sequenceOf(const QList<QByteArray> &items)
{
    QByteArray body;
    for (const QByteArray &item : items)
        body.append(item);
    return tlv(0x30, body);
}

QByteArray objectIdentifier(const QString &dotted)
{
    const QStringList arcs = dotted.split(QLatin1Char('.'));
    QByteArray body;
    if (arcs.size() < 2)
        return {};
    body.append(char(arcs.at(0).toInt() * 40 + arcs.at(1).toInt()));
    for (int i = 2; i < arcs.size(); ++i) {
        quint64 value = quint64(arcs.at(i).toULongLong());
        QByteArray part;
        part.prepend(char(value & 0x7f));
        value >>= 7;
        while (value > 0) {
            part.prepend(char(0x80 | (value & 0x7f)));
            value >>= 7;
        }
        body.append(part);
    }
    return tlv(0x06, body);
}

bool parseChildren(Element *element)
{
    element->children.clear();
    int pos = 0;
    while (pos < element->value.size()) {
        Element child;
        int consumed = 0;
        if (!parse(element->value.mid(pos), &child, &consumed) || consumed <= 0)
            return false;
        element->children.append(child);
        pos += consumed;
    }
    return true;
}

bool parse(const QByteArray &data, Element *out, int *consumed)
{
    if (data.isEmpty())
        return false;
    int pos = 0;
    Element element;
    element.tag = quint8(data.at(pos++));
    int length = 0;
    if (!readLength(data, pos, &length))
        return false;
    if (length < 0 || pos + length > data.size())
        return false;
    element.value = data.mid(pos, length);
    element.valid = true;
    if (element.tag & 0x20) {
        if (!parseChildren(&element))
            return false;
    }
    if (consumed)
        *consumed = pos + length;
    *out = element;
    return true;
}

const Element *child(const Element &element, quint8 tag)
{
    for (const Element &candidate : element.children) {
        if (candidate.tag == tag)
            return &candidate;
    }
    return nullptr;
}

QList<const Element *> children(const Element &element, quint8 tag)
{
    QList<const Element *> matches;
    for (const Element &candidate : element.children) {
        if (candidate.tag == tag)
            matches.append(&candidate);
    }
    return matches;
}

qint64 toInteger(const Element &element, qint64 fallback)
{
    if (element.tag != 0x02 || element.value.isEmpty() || element.value.size() > 8)
        return fallback;
    qint64 value = (element.value.at(0) & 0x80) ? -1 : 0;
    for (const char octet : element.value)
        value = (value << 8) | quint8(octet);
    return value;
}

QString toString(const Element &element)
{
    if (element.tag == 0x1B || element.tag == 0x04 || element.tag == 0x0C)
        return QString::fromUtf8(element.value);
    return {};
}

qint64 toTime(const Element &element)
{
    // Kerberos times are always UTC; parse in UTC rather than the local zone.
    auto parse = [](const QByteArray &value, const QString &format) -> qint64 {
        QDateTime moment = QDateTime::fromString(QString::fromLatin1(value), format);
        if (!moment.isValid())
            return 0;
        moment.setTimeZone(QTimeZone::UTC);
        return moment.toSecsSinceEpoch();
    };
    if (element.tag == 0x18)
        return parse(element.value, QStringLiteral("yyyyMMddHHmmss'Z'"));
    if (element.tag == 0x17)
        return parse(element.value, QStringLiteral("yyMMddHHmmss'Z'"));
    return 0;
}

quint32 toBits(const Element &element)
{
    if (element.tag != 0x03 || element.value.size() < 2)
        return 0;
    quint32 flags = 0;
    for (int i = 1; i < element.value.size() && i < 5; ++i)
        flags = (flags << 8) | quint8(element.value.at(i));
    // Fewer than four content octets: left-align the bit string.
    const int octets = qMin(element.value.size() - 1, 4);
    return octets == 4 ? flags : (flags << (8 * (4 - octets)));
}

} // namespace Asn1
