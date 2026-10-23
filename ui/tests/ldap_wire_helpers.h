// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef MONARCHY_LDAP_WIRE_HELPERS_H
#define MONARCHY_LDAP_WIRE_HELPERS_H

// Minimal LDAP v3 wire helpers for the tests that speak to LdapServer over a
// real socket: enough BER to build requests, read messages and inspect the
// results and controls that come back.

#include <QtTest>

#include <QByteArray>
#include <QElapsedTimer>
#include <QIODevice>
#include <QList>
#include <QString>

namespace ldapwire {

inline QByteArray tlv(char tag, const QByteArray &content)
{
    QByteArray out;
    out.append(tag);
    const int len = content.size();
    if (len < 0x80) {
        out.append(char(len));
    } else if (len <= 0xff) {
        out.append(char(0x81));
        out.append(char(len));
    } else {
        out.append(char(0x82));
        out.append(char((len >> 8) & 0xff));
        out.append(char(len & 0xff));
    }
    out.append(content);
    return out;
}

inline QByteArray ldapInt(int value)
{
    QByteArray out;
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
    return out;
}

inline QByteArray ldapMessage(int id, char opTag, const QByteArray &opContent,
                              const QByteArray &controls = QByteArray())
{
    QByteArray body = tlv(0x02, ldapInt(id));
    body += tlv(opTag, opContent);
    body += controls; // already wrapped as controls [0]
    return tlv(0x30, body);
}

inline QByteArray startTlsRequest(int id)
{
    return ldapMessage(id, char(0x77),
                       tlv(char(0x80), QByteArray("1.3.6.1.4.1.1466.20037")));
}

inline QByteArray bindRequest(int id, const QByteArray &dn, const QByteArray &password)
{
    QByteArray inner = tlv(0x02, ldapInt(3));
    inner += tlv(0x04, dn);
    inner += tlv(char(0x80), password);
    return ldapMessage(id, char(0x60), inner);
}

// Subtree search for (objectClass=*) with no attributes requested.
inline QByteArray searchRequest(int id, const QByteArray &base,
                                const QByteArray &controls = QByteArray())
{
    QByteArray inner = tlv(0x04, base);
    inner += tlv(char(0x0a), QByteArray(1, char(2))); // scope: wholeSubtree
    inner += tlv(char(0x87), QByteArray("objectClass")); // present filter
    inner += tlv(char(0x30), QByteArray());
    return ldapMessage(id, char(0x63), inner, controls);
}

// One Control, as it appears inside the message's controls field.
inline QByteArray control(const QByteArray &oid, const QByteArray &value,
                          bool critical = false)
{
    QByteArray body = tlv(0x04, oid);
    if (critical)
        body += tlv(0x01, QByteArray(1, char(0xff)));
    body += tlv(0x04, value);
    return tlv(0x30, body);
}

inline QByteArray controlsField(const QList<QByteArray> &controls)
{
    QByteArray inner;
    for (const QByteArray &item : controls)
        inner += item;
    return tlv(0xa0, inner);
}

inline const char kPagedResultsOid[] = "1.2.840.113556.1.4.319";

// pagedResultsControl value: the DER encoding of
// SEQUENCE { size INTEGER, cookie OCTET STRING }.
inline QByteArray pagedResultsValue(int size, const QByteArray &cookie)
{
    QByteArray inner = tlv(0x02, ldapInt(size));
    inner += tlv(0x04, cookie);
    return tlv(0x30, inner);
}

inline bool nextElement(const QByteArray &data, int *pos, int *tag, QByteArray *content)
{
    if (*pos + 2 > data.size())
        return false;
    *tag = (unsigned char)data.at((*pos)++);
    int length = (unsigned char)data.at((*pos)++);
    if (length & 0x80) {
        const int count = length & 0x7f;
        if (*pos + count > data.size())
            return false;
        length = 0;
        for (int i = 0; i < count; ++i)
            length = (length << 8) | (unsigned char)data.at((*pos)++);
    }
    if (*pos + length > data.size())
        return false;
    *content = data.mid(*pos, length);
    *pos += length;
    return true;
}

// Total size of the BER element at the head of `data`, or -1 while the header is
// still incomplete.
inline int frameSize(const QByteArray &data)
{
    if (data.size() < 2)
        return -1;
    int length = (unsigned char)data.at(1);
    int header = 2;
    if (length & 0x80) {
        const int count = length & 0x7f;
        if (data.size() < 2 + count)
            return -1;
        length = 0;
        for (int i = 0; i < count; ++i)
            length = (length << 8) | (unsigned char)data.at(2 + i);
        header = 2 + count;
    }
    return header + length;
}

// Reads LDAP messages off a socket while letting the server's event loop run:
// the test thread must return to the loop for the server to accept and answer.
class Reader
{
public:
    explicit Reader(QIODevice *device) : m_device(device) {}

    QByteArray next(int timeoutMs = 5000)
    {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            const int size = frameSize(m_buffer);
            if (size > 0 && m_buffer.size() >= size) {
                const QByteArray out = m_buffer.left(size);
                m_buffer.remove(0, size);
                return out;
            }
            if (m_device->bytesAvailable() > 0)
                m_buffer += m_device->readAll();
            else
                QTest::qWait(5);
        }
        return QByteArray();
    }

    // True once no complete message is buffered and nothing arrives in `timeoutMs`.
    bool atEnd(int timeoutMs = 200)
    {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            if (m_device->bytesAvailable() > 0)
                m_buffer += m_device->readAll();
            if (!m_buffer.isEmpty())
                return false;
            QTest::qWait(5);
        }
        return true;
    }

    // Any bytes that arrived but were not a complete LDAP message.
    QByteArray leftover() { return m_buffer + m_device->readAll(); }

private:
    QIODevice *m_device;
    QByteArray m_buffer;
};

inline bool splitMessage(const QByteArray &message, int *tag, QByteArray *op,
                         QByteArray *controls)
{
    int pos = 0, outerTag = 0;
    QByteArray sequence;
    if (!nextElement(message, &pos, &outerTag, &sequence) || outerTag != 0x30)
        return false;
    int inner = 0, idTag = 0;
    QByteArray ignored;
    if (!nextElement(sequence, &inner, &idTag, &ignored) || idTag != 0x02)
        return false;
    if (!nextElement(sequence, &inner, tag, op))
        return false;
    controls->clear();
    if (inner < sequence.size())
        nextElement(sequence, &inner, &outerTag, controls);
    return true;
}

// Protocol op tag of an LDAPMessage, or -1.
inline int operationTag(const QByteArray &message)
{
    int tag = -1;
    QByteArray op, ignored;
    if (!splitMessage(message, &tag, &op, &ignored))
        return -1;
    return tag;
}

// Result code of the first protocol op in an LDAPMessage, or -1.
inline int resultCode(const QByteArray &message)
{
    int tag = -1;
    QByteArray op, ignored;
    if (!splitMessage(message, &tag, &op, &ignored))
        return -1;
    int opPos = 0, rcTag = 0;
    QByteArray rc;
    if (!nextElement(op, &opPos, &rcTag, &rc) || rcTag != 0x0a || rc.size() != 1)
        return -1;
    return (unsigned char)rc.at(0);
}

// Distinguished name carried by a SearchResultEntry, or an empty string.
inline QString entryDn(const QByteArray &message)
{
    int tag = -1;
    QByteArray op, ignored;
    if (!splitMessage(message, &tag, &op, &ignored) || tag != 0x64)
        return QString();
    int pos = 0, nameTag = 0;
    QByteArray dn;
    if (!nextElement(op, &pos, &nameTag, &dn))
        return QString();
    return QString::fromUtf8(dn);
}

// controlValue of the paged-results control in a SearchResultDone, or a null
// QByteArray when the response carries no such control.
inline QByteArray pagedResultsValueFromResponse(const QByteArray &message)
{
    int tag = -1;
    QByteArray op, controls;
    if (!splitMessage(message, &tag, &op, &controls) || controls.isEmpty())
        return QByteArray();
    int pos = 0;
    while (pos < controls.size()) {
        int elementTag = 0;
        QByteArray item;
        if (!nextElement(controls, &pos, &elementTag, &item) || elementTag != 0x30)
            return QByteArray();
        int itemPos = 0, oidTag = 0;
        QByteArray oid, value;
        if (!nextElement(item, &itemPos, &oidTag, &oid))
            return QByteArray();
        if (oid != QByteArray(kPagedResultsOid))
            continue;
        // criticality may be present; the value is the last OCTET STRING.
        while (itemPos < item.size()) {
            int t = 0;
            QByteArray part;
            if (!nextElement(item, &itemPos, &t, &part))
                break;
            if (t == 0x04)
                value = part;
        }
        return value;
    }
    return QByteArray();
}

// Cookie inside a paged-results control value, or a null QByteArray.
inline QByteArray cookieFromPagedValue(const QByteArray &value)
{
    if (value.isEmpty())
        return QByteArray();
    int pos = 0, tag = 0;
    QByteArray body;
    // Unwrap the SEQUENCE the value carries.
    if (!nextElement(value, &pos, &tag, &body) || tag != 0x30)
        return QByteArray();
    pos = 0;
    QByteArray ignored;
    if (!nextElement(body, &pos, &tag, &ignored)) // size
        return QByteArray();
    QByteArray cookie;
    if (!nextElement(body, &pos, &tag, &cookie))
        return QByteArray();
    return cookie;
}

} // namespace ldapwire

#endif // MONARCHY_LDAP_WIRE_HELPERS_H
