// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LdapClient.h"

#include <QHostAddress>

namespace {

void writeLength(QByteArray &out, int len)
{
    if (len < 0x80) {
        out.append(char(len));
        return;
    }
    QByteArray tmp;
    int v = len;
    do {
        tmp.prepend(char(v & 0xFF));
        v >>= 8;
    } while (v > 0);
    out.append(char(0x80 | tmp.size()));
    out.append(tmp);
}

void writeTLV(QByteArray &out, quint8 tag, const QByteArray &value)
{
    out.append(char(tag));
    writeLength(out, value.size());
    out.append(value);
}

void writeIntValue(QByteArray &b, qint32 v)
{
    // minimal big-endian two's complement
    if (v == 0) {
        b.append(char(0));
        return;
    }
    quint32 u = quint32(v);
    QByteArray tmp;
    bool first = true;
    while (u) {
        char c = char(u & 0xFF);
        u >>= 8;
        if (u == 0 && (c & 0x80)) {
            // would decode as negative; keep going
            tmp.prepend(c);
            if (u) continue;
            tmp.prepend(char(0));
            break;
        }
        tmp.prepend(c);
        Q_UNUSED(first)
    }
    b.append(tmp);
}

void writeInt(QByteArray &out, quint8 tag, qint32 v)
{
    QByteArray value;
    writeIntValue(value, v);
    writeTLV(out, tag, value);
}

bool readLength(const QByteArray &d, int &pos, int *len)
{
    if (pos >= d.size())
        return false;
    quint8 b = quint8(d[pos++]);
    if (!(b & 0x80)) {
        *len = b;
        return true;
    }
    int n = b & 0x7F;
    if (n == 0 || pos + n > d.size())
        return false;
    int v = 0;
    for (int i = 0; i < n; i++)
        v = (v << 8) | quint8(d[pos++]);
    *len = v;
    return true;
}

bool readTLV(const QByteArray &d, int *pos, quint8 *tag, int *len)
{
    if (*pos >= d.size())
        return false;
    *tag = quint8(d[(*pos)++]);
    return readLength(d, *pos, len);
}

QString decodeValue(const QByteArray &d, int pos, int len)
{
    return QString::fromUtf8(d.mid(pos, len));
}

// ---- RFC 4515 filter parsing, encoded per RFC 4511 §4.5.1.7 -----------

struct FilterValue {
    QList<QByteArray> parts; // split on unescaped '*'
    bool leadingWildcard = false;
    bool trailingWildcard = false;
};

bool encodeFilterString(const QString &f, int &pos, QByteArray *out);

bool isHexDigit(QChar c)
{
    return (c >= QLatin1Char('0') && c <= QLatin1Char('9'))
           || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))
           || (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
}

// Decodes \XX escapes and splits the value on unescaped '*', which is what
// separates the initial/any/final components of a substring filter.
bool decodeFilterValue(const QString &f, int &pos, FilterValue *value)
{
    QByteArray part;
    bool first = true;
    while (pos < f.size() && f.at(pos) != QLatin1Char(')')) {
        const QChar c = f.at(pos);
        if (c == QLatin1Char('\\') && pos + 2 < f.size() && isHexDigit(f.at(pos + 1))
            && isHexDigit(f.at(pos + 2))) {
            const QString hex = f.mid(pos + 1, 2);
            part.append(char(hex.toInt(nullptr, 16)));
            pos += 3;
            continue;
        }
        ++pos;
        if (c == QLatin1Char('*')) {
            value->parts.append(part);
            part.clear();
            if (first)
                value->leadingWildcard = true;
            first = false;
            continue;
        }
        part.append(QString(c).toUtf8());
        first = false;
    }
    value->parts.append(part);
    if (value->parts.size() > 1 && value->parts.last().isEmpty())
        value->trailingWildcard = true;
    if (pos >= f.size() || f.at(pos) != QLatin1Char(')'))
        return false;
    ++pos;
    return true;
}

bool encodeFilterString(const QString &f, int &pos, QByteArray *out)
{
    while (pos < f.size() && f.at(pos).isSpace())
        ++pos;
    if (pos >= f.size() || f.at(pos) != QLatin1Char('('))
        return false;
    ++pos;

    if (pos < f.size() && (f.at(pos) == QLatin1Char('&') || f.at(pos) == QLatin1Char('|'))) {
        const quint8 tag = f.at(pos) == QLatin1Char('&') ? 0xA0 : 0xA1;
        ++pos;
        QByteArray body;
        while (pos < f.size() && f.at(pos) == QLatin1Char('(')) {
            QByteArray child;
            if (!encodeFilterString(f, pos, &child))
                return false;
            body.append(child);
        }
        if (pos >= f.size() || f.at(pos) != QLatin1Char(')'))
            return false;
        ++pos;
        writeTLV(*out, tag, body);
        return true;
    }

    if (pos < f.size() && f.at(pos) == QLatin1Char('!')) {
        ++pos;
        QByteArray child;
        if (!encodeFilterString(f, pos, &child))
            return false;
        if (pos >= f.size() || f.at(pos) != QLatin1Char(')'))
            return false;
        ++pos;
        writeTLV(*out, 0xA2, child);
        return true;
    }

    const int start = pos;
    while (pos < f.size() && f.at(pos) != QLatin1Char('=') && f.at(pos) != QLatin1Char(')'))
        ++pos;
    if (pos >= f.size() || f.at(pos) != QLatin1Char('='))
        return false;
    QString attr = f.mid(start, pos - start).trimmed();
    char op = '=';
    if (!attr.isEmpty()) {
        const QChar last = attr.at(attr.size() - 1);
        if (last == QLatin1Char('>') || last == QLatin1Char('<') || last == QLatin1Char('~')) {
            op = last.toLatin1();
            attr.chop(1);
        }
    }
    if (attr.isEmpty())
        return false;
    ++pos; // '='

    FilterValue value;
    if (!decodeFilterValue(f, pos, &value))
        return false;

    const QByteArray attrBytes = attr.toUtf8();
    if (op == '>' || op == '<' || op == '~') {
        QByteArray body;
        writeTLV(body, 0x04, attrBytes);
        writeTLV(body, 0x04, value.parts.join('*'));
        writeTLV(*out, op == '>' ? 0xA5 : (op == '<' ? 0xA6 : 0xA8), body);
        return true;
    }

    // (attr=*) is a presence test; any other '*' makes it a substring filter.
    bool allEmpty = true;
    for (const QByteArray &part : value.parts)
        allEmpty = allEmpty && part.isEmpty();
    if (allEmpty) {
        writeTLV(*out, 0x87, attrBytes);
        return true;
    }
    if (value.parts.size() == 1) {
        QByteArray body;
        writeTLV(body, 0x04, attrBytes);
        writeTLV(body, 0x04, value.parts.first());
        writeTLV(*out, 0xA3, body);
        return true;
    }

    QByteArray pieces;
    for (int i = 0; i < value.parts.size(); ++i) {
        const QByteArray &part = value.parts.at(i);
        if (part.isEmpty())
            continue;
        if (i == 0)
            writeTLV(pieces, 0x80, part);      // initial
        else if (i == value.parts.size() - 1)
            writeTLV(pieces, 0x82, part);      // final
        else
            writeTLV(pieces, 0x81, part);      // any
    }
    QByteArray body;
    writeTLV(body, 0x04, attrBytes);
    writeTLV(body, 0x30, pieces);
    writeTLV(*out, 0xA4, body);
    return true;
}

} // namespace

LdapClient::~LdapClient()
{
    close();
}

bool LdapClient::open(const QString &host, quint16 port, QString *error, int timeoutMs)
{
    m_buffer.clear();
    m_nextId = 1;
    m_socket.connectToHost(host, port);
    if (!m_socket.waitForConnected(timeoutMs)) {
        if (error)
            *error = QStringLiteral("connect to %1:%2 failed: %3")
                         .arg(host).arg(port).arg(m_socket.errorString());
        return false;
    }
    return true;
}

bool LdapClient::bind(const QString &dn, const QString &password, QString *error)
{
    QByteArray inner;
    writeInt(inner, 0x02, 3); // version
    writeTLV(inner, 0x04, dn.toUtf8());
    writeTLV(inner, 0x80, password.toUtf8()); // simple auth [0]

    QByteArray msg;
    writeInt(msg, 0x02, m_nextId);
    writeTLV(msg, 0x60, inner); // BindRequest [APPLICATION 0]
    QByteArray packet;
    writeTLV(packet, 0x30, msg);
    if (!sendMessage(packet))
        return false;

    int code = -1;
    if (!waitResult(0x61, &code, 5000, error))
        return false;
    if (code != 0) {
        if (error)
            *error = QStringLiteral("bind failed with result %1").arg(code);
        return false;
    }
    return true;
}

QList<LdapClient::Entry> LdapClient::search(const QString &base, int scope, const QString &filter,
                                            const QStringList &attributes, QString *error)
{
    QList<Entry> result;

    QByteArray inner;
    writeTLV(inner, 0x04, base.toUtf8());
    writeInt(inner, 0x0A, scope);  // scope ENUM
    writeInt(inner, 0x0A, 0);      // derefAliases neverDeref
    writeInt(inner, 0x02, 0);      // sizeLimit 0
    writeInt(inner, 0x02, 0);      // timeLimit 0
    inner.append(char(0x01));
    inner.append(char(0x01));
    inner.append(char(0x00));      // typesOnly FALSE

    // RFC 4515 filter string -> BER filter (and/or/not, equality, substring,
    // presence, >= <= ~=). An unparseable filter degrades to (objectClass=*).
    const QString f = filter.trimmed();
    QByteArray filterBytes;
    int filterPos = 0;
    if (!f.isEmpty())
        encodeFilterString(f, filterPos, &filterBytes);
    if (filterBytes.isEmpty()) {
        filterBytes.append(char(0x87)); // present [7]
        const QByteArray a = QByteArray("objectClass");
        writeLength(filterBytes, a.size());
        filterBytes.append(a);
    }
    inner.append(filterBytes);

    QByteArray attrSeq;
    for (const QString &a : attributes)
        writeTLV(attrSeq, 0x04, a.toUtf8());
    writeTLV(inner, 0x30, attrSeq);

    QByteArray msg;
    writeInt(msg, 0x02, m_nextId);
    writeTLV(msg, 0x63, inner); // SearchRequest [APPLICATION 3]
    QByteArray packet;
    writeTLV(packet, 0x30, msg);
    if (!sendMessage(packet))
        return result;

    // Read entries until SearchResultDone (0x65).
    while (true) {
        QByteArray frame;
        QString readError;
        if (!readMessage(&frame, 10000, &readError)) {
            if (error)
                *error = readError;
            return result;
        }
        int pos = 0;
        quint8 tag = 0;
        int len = 0;
        if (!readTLV(frame, &pos, &tag, &len))
            break;
        // skip messageID
        quint8 t2 = 0;
        int l2 = 0;
        if (!readTLV(frame, &pos, &t2, &l2))
            break;
        pos += l2;
        quint8 opTag = 0;
        int opLen = 0;
        if (!readTLV(frame, &pos, &opTag, &opLen))
            break;
        if (opTag == 0x65) { // SearchResultDone
            break;
        }
        if (opTag != 0x64) {
            if (error)
                *error = QStringLiteral("unexpected search response tag 0x%1").arg(opTag, 0, 16);
            return result;
        }
        Entry e;
        quint8 t3 = 0;
        int l3 = 0;
        if (!readTLV(frame, &pos, &t3, &l3)) // objectName
            break;
        e.dn = decodeValue(frame, pos, l3);
        pos += l3;
        // attributes SEQUENCE
        quint8 t4 = 0;
        int l4 = 0;
        if (!readTLV(frame, &pos, &t4, &l4))
            break;
        int attrsEnd = pos + l4;
        while (pos < attrsEnd) {
            quint8 at = 0;
            int al = 0;
            if (!readTLV(frame, &pos, &at, &al))
                break;
            int attrEnd = pos + al;
            quint8 tt = 0;
            int tl = 0;
            if (!readTLV(frame, &pos, &tt, &tl))
                break;
            const QString type = decodeValue(frame, pos, tl);
            pos += tl;
            quint8 st = 0;
            int sl = 0;
            if (!readTLV(frame, &pos, &st, &sl))
                break;
            int setEnd = pos + sl;
            QStringList vals;
            while (pos < setEnd) {
                quint8 vt = 0;
                int vl = 0;
                if (!readTLV(frame, &pos, &vt, &vl))
                    break;
                vals.append(decodeValue(frame, pos, vl));
                pos += vl;
            }
            pos = attrEnd;
            if (!type.isEmpty())
                e.attrs.insert(type, vals);
        }
        result.append(e);
    }
    return result;
}

bool LdapClient::add(const QString &dn, const QMap<QString, QStringList> &attrs, QString *error)
{
    QByteArray inner;
    writeTLV(inner, 0x04, dn.toUtf8());
    QByteArray attrSeq;
    for (auto it = attrs.begin(); it != attrs.end(); ++it) {
        QByteArray vals;
        for (const QString &v : it.value())
            writeTLV(vals, 0x04, v.toUtf8());
        QByteArray set;
        writeTLV(set, 0x31, vals); // SET OF
        QByteArray attr;
        writeTLV(attr, 0x04, it.key().toUtf8());
        attr.append(set);
        writeTLV(attrSeq, 0x30, attr);
    }
    writeTLV(inner, 0x30, attrSeq);

    QByteArray msg;
    writeInt(msg, 0x02, m_nextId);
    writeTLV(msg, 0x68, inner); // AddRequest [APPLICATION 8]
    QByteArray packet;
    writeTLV(packet, 0x30, msg);
    if (!sendMessage(packet))
        return false;
    int code = -1;
    if (!waitResult(0x69, &code, 5000, error))
        return false;
    if (code != 0) {
        if (error)
            *error = QStringLiteral("add failed with result %1").arg(code);
        return false;
    }
    return true;
}

bool LdapClient::modify(const QString &dn, const QMap<QString, QStringList> &replace, QString *error)
{
    QByteArray inner;
    writeTLV(inner, 0x04, dn.toUtf8());
    QByteArray changes;
    for (auto it = replace.begin(); it != replace.end(); ++it) {
        QByteArray vals;
        for (const QString &v : it.value())
            writeTLV(vals, 0x04, v.toUtf8());
        QByteArray set;
        writeTLV(set, 0x31, vals);
        QByteArray mod;
        writeTLV(mod, 0x04, it.key().toUtf8());
        mod.append(set);
        QByteArray change;
        writeInt(change, 0x0A, 2); // replace
        writeTLV(change, 0x30, mod);
        writeTLV(changes, 0x30, change);
    }
    writeTLV(inner, 0x30, changes);

    QByteArray msg;
    writeInt(msg, 0x02, m_nextId);
    writeTLV(msg, 0x66, inner); // ModifyRequest [APPLICATION 6]
    QByteArray packet;
    writeTLV(packet, 0x30, msg);
    if (!sendMessage(packet))
        return false;
    int code = -1;
    if (!waitResult(0x67, &code, 5000, error))
        return false;
    if (code != 0) {
        if (error)
            *error = QStringLiteral("modify failed with result %1").arg(code);
        return false;
    }
    return true;
}

bool LdapClient::del(const QString &dn, QString *error)
{
    QByteArray msg;
    writeInt(msg, 0x02, m_nextId);
    writeTLV(msg, 0x4A, dn.toUtf8()); // DelRequest [APPLICATION 10]
    QByteArray packet;
    writeTLV(packet, 0x30, msg);
    if (!sendMessage(packet))
        return false;
    int code = -1;
    if (!waitResult(0x4B, &code, 5000, error))
        return false;
    if (code != 0) {
        if (error)
            *error = QStringLiteral("delete failed with result %1").arg(code);
        return false;
    }
    return true;
}

void LdapClient::close()
{
    if (m_socket.state() == QAbstractSocket::ConnectedState) {
        QByteArray msg;
        writeInt(msg, 0x02, m_nextId);
        writeTLV(msg, 0x42, QByteArray()); // UnbindRequest [APPLICATION 2]
        QByteArray packet;
        writeTLV(packet, 0x30, msg);
        m_socket.write(packet);
        m_socket.flush();
        m_socket.disconnectFromHost();
    }
    m_buffer.clear();
}

bool LdapClient::sendMessage(const QByteArray &message)
{
    if (m_socket.state() != QAbstractSocket::ConnectedState)
        return false;
    return m_socket.write(message) == message.size() && m_socket.waitForBytesWritten(5000);
}

bool LdapClient::readMessage(QByteArray *frame, int timeoutMs, QString *error)
{
    while (true) {
        // Try to extract one complete SEQUENCE from the buffer.
        if (m_buffer.size() >= 2 && quint8(m_buffer[0]) == 0x30) {
            int pos = 1;
            int len = 0;
            if (readLength(m_buffer, pos, &len)) {
                const int total = pos + len;
                if (m_buffer.size() >= total) {
                    *frame = m_buffer.left(total);
                    m_buffer.remove(0, total);
                    return true;
                }
            }
        }
        if (!m_socket.waitForReadyRead(timeoutMs)) {
            if (error) {
                *error = (m_buffer.isEmpty())
                             ? QStringLiteral("timeout waiting for LDAP response: %1")
                                   .arg(m_socket.errorString())
                             : QStringLiteral("truncated LDAP response");
            }
            return false;
        }
        m_buffer.append(m_socket.readAll());
    }
}

bool LdapClient::waitResult(quint8 expectTag, int *resultCode, int timeoutMs, QString *error)
{
    QByteArray frame;
    if (!readMessage(&frame, timeoutMs, error))
        return false;
    int pos = 0;
    quint8 tag = 0;
    int len = 0;
    if (!readTLV(frame, &pos, &tag, &len))
        return false;
    quint8 t2 = 0;
    int l2 = 0;
    if (!readTLV(frame, &pos, &t2, &l2))
        return false;
    pos += l2;
    quint8 opTag = 0;
    int opLen = 0;
    if (!readTLV(frame, &pos, &opTag, &opLen))
        return false;
    if (opTag != expectTag) {
        if (error)
            *error = QStringLiteral("unexpected response tag 0x%1 (wanted 0x%2)")
                         .arg(opTag, 0, 16).arg(expectTag, 0, 16);
        return false;
    }
    // LDAPResult: ENUM resultCode, matchedDN, diagnosticMessage
    quint8 rt = 0;
    int rl = 0;
    if (!readTLV(frame, &pos, &rt, &rl))
        return false;
    int code = 0;
    for (int i = 0; i < rl; i++)
        code = (code << 8) | quint8(frame[pos + i]);
    *resultCode = code;
    return true;
}
