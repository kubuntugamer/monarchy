// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ASN1_H
#define ASN1_H

#include <QByteArray>
#include <QList>
#include <QString>

// Minimal DER writer/reader for the ASN.1 subset Kerberos (RFC 4120) uses:
// explicitly tagged context fields, SEQUENCE/SEQUENCE OF, integers, bit
// strings, octet strings, GeneralString and GeneralizedTime.
namespace Asn1 {

QByteArray encodeLength(int length);

// One tag-length-value element. `tag` is a single octet because Kerberos never
// uses a multi-octet tag.
QByteArray tlv(quint8 tag, const QByteArray &content);

QByteArray integer(quint8 tag, qint64 value);
// 32-bit Kerberos flag string (TicketFlags, KDCOptions), most significant bit
// of the first octet first.
QByteArray bits(quint8 tag, quint32 flags);
QByteArray octets(quint8 tag, const QByteArray &value);
QByteArray string(quint8 tag, const QString &value);
QByteArray generalizedTime(quint8 tag, qint64 secondsSinceEpoch);
QByteArray sequence(const QByteArray &content);
QByteArray sequenceOf(const QList<QByteArray> &items);
QByteArray objectIdentifier(const QString &dotted);

struct Element {
    quint8 tag = 0;
    QByteArray value;      // content octets
    QList<Element> children; // populated for constructed tags only
    bool valid = false;
};

// Reads one element starting at the beginning of `data`. `consumed` receives
// the number of octets used. Constructed elements are parsed recursively.
bool parse(const QByteArray &data, Element *out, int *consumed = nullptr);
bool parseChildren(Element *element);

const Element *child(const Element &element, quint8 tag);
QList<const Element *> children(const Element &element, quint8 tag);

qint64 toInteger(const Element &element, qint64 fallback = 0);
QString toString(const Element &element);
qint64 toTime(const Element &element);
quint32 toBits(const Element &element);

} // namespace Asn1

#endif // ASN1_H
