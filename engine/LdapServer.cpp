// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LdapServer.h"

#include "Asn1.h"
#include "Gss.h"
#include "ObjectGuid.h"
#include "Kdc.h"
#include "LogonHours.h"
#include "PasswordAge.h"
#include "Ntlm.h"
#include "Ndr.h"

#include <QSaveFile>

#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QUdpSocket>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QSslCipher>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslError>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSet>
#include <QUuid>
#include <algorithm>
#include <functional>

// The listener hands each accepted descriptor straight to the server instead of
// letting QTcpServer wrap it in a QTcpSocket: a connection has to start as a
// QSslSocket so StartTLS can upgrade the very same socket in place, and Qt does
// not support turning a connected QTcpSocket into a TLS one.
class LdapListener : public QTcpServer
{
public:
    LdapListener(LdapServer *owner, QObject *parent)
        : QTcpServer(parent), m_owner(owner) {}

protected:
    void incomingConnection(qintptr socketDescriptor) override
    {
        m_owner->adoptDescriptor(socketDescriptor);
    }

private:
    LdapServer *m_owner;
};

namespace {

// Big-endian helpers for the SASL framing (RFC 4422), which prefixes every
// wrapped buffer with its own length.
void appendBe32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

quint32 readBe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return (quint32(quint8(data[pos])) << 24) | (quint32(quint8(data[pos + 1])) << 16)
           | (quint32(quint8(data[pos + 2])) << 8) | quint32(quint8(data[pos + 3]));
}


// ---------- BER helpers ----------

int readTag(const QByteArray &d, int &pos) {
    if (pos >= d.size()) return -1;
    return (unsigned char)d[pos++];
}

int readLength(const QByteArray &d, int &pos) {
    if (pos >= d.size()) return -1;
    unsigned char b = (unsigned char)d[pos++];
    if (b < 0x80) return b;
    int n = b & 0x7f;
    if (n == 0 || pos + n > d.size()) return -1;
    int len = 0;
    for (int i = 0; i < n; i++) len = (len << 8) | (unsigned char)d[pos++];
    return len;
}

QByteArray readTLV(const QByteArray &d, int &pos, int &tag) {
    int start = pos;
    tag = readTag(d, pos);
    if (tag < 0) return {};
    int len = readLength(d, pos);
    if (len < 0 || pos + len > d.size()) return {};
    QByteArray v = d.mid(pos, len);
    pos += len;
    return v;
}

QString readString(const QByteArray &d, int &pos) {
    int tag; QByteArray v = readTLV(d, pos, tag);
    return QString::fromUtf8(v);
}

int decodeInt(const QByteArray &v) {
    // Accumulate unsigned: a BER INTEGER is signed, but shifting a signed int
    // left is undefined once a bit reaches the sign position, and any four-byte
    // value with the top bit set (a legal sizeLimit included) does that.
    quint32 r = 0;
    for (char c : v) r = (r << 8) | (unsigned char)c;
    // sign extend
    if (!v.isEmpty() && (v[0] & 0x80)) {
        for (int i = v.size(); i < (int)sizeof(int); i++) r |= (0xFFu << (i*8));
    }
    return (int)r;
}

int readInt(const QByteArray &d, int &pos) {
    int tag; QByteArray v = readTLV(d, pos, tag);
    return decodeInt(v);
}

// Reads one INTEGER/ENUMERATED/BOOLEAN field and requires its tag, so a field
// that is absent cannot be filled in from the next element's bytes.
bool readIntField(const QByteArray &d, int &pos, int expectedTag, int *value) {
    int tag = 0;
    const int start = pos;
    const QByteArray v = readTLV(d, pos, tag);
    // A field this reader cannot represent is an error, not a guess: anything
    // wider than four bytes would wrap silently in decodeInt's quint32.
    if (tag != expectedTag || pos <= start || v.size() > 4) return false;
    *value = decodeInt(v);
    return true;
}

// ---------- BER writers ----------

void writeLength(QByteArray &out, int len) {
    if (len < 0x80) {
        out.append((char)len);
    } else {
        QByteArray tmp;
        int n = 0;
        int v = len;
        do { tmp.prepend((char)(v & 0xFF)); v >>= 8; n++; } while (v > 0);
        out.append((char)(0x80 | n));
        out.append(tmp);
    }
}

void writeTLV(QByteArray &out, int tag, const QByteArray &value) {
    out.append((char)tag);
    writeLength(out, value.size());
    out.append(value);
}

void writeInt(QByteArray &out, int tag, int v) {
    QByteArray b;
    // minimal big-endian
    int n = 1;
    int tmp = v;
    // handle sign
    if (v >= 0) {
        while (tmp > 127) { b.prepend((char)(tmp & 0xFF)); tmp >>= 8; n++; }
    } else {
        while (tmp < -128) { b.prepend((char)(tmp & 0xFF)); tmp >>= 8; n++; }
    }
    b.prepend((char)(tmp & 0xFF));
    writeTLV(out, tag, b);
}

void writeString(QByteArray &out, int tag, const QString &s) {
    writeTLV(out, tag, s.toUtf8());
}

// Filter parser: returns a predicate. We parse a subset.
// Filter ::= CHOICE { and [0] SET OF Filter, or [1], not [2], equality [3] SEQUENCE{attr,val},
//             present [7] OCTET STRING, ... }
typedef std::function<bool(const DirectoryObject &)> Pred;

// Filter ::= CHOICE { and [0] SET OF Filter, or [1] SET OF Filter, not [2] Filter,
//             equalityMatch [3] SEQUENCE{attr,val}, substrings [4], present [7] }
Pred parseFilter(const QByteArray &d, int &pos);

namespace {

// Paged results, RFC 2696.
const char kPagedResultsOid[] = "1.2.840.113556.1.4.319";
// LDAP_SERVER_PERMISSIVE_MODIFY_OID (MS-ADTS 3.1.1.3.4.1.9). Samba's join marks
// it critical when it sets servicePrincipalName, so refusing it stopped the join
// at unavailableCriticalExtension; the modify path here already ignores an added
// value that is present and a deleted one that is not, which is what the control
// asks for.
const char kPermissiveModifyOid[] = "1.2.840.113556.1.4.1413";

// Attributes AD computes rather than stores. Its own tooling filters on them:
// `(objectCategory=user)` is what ADUC, realmd and most scripts send, and
// `(sAMAccountType=805306368)` is the principal filter. A directory that answers
// only what it stores returns nothing for either, which reads to the client as
// an empty domain rather than as an attribute it will not get. The filter
// matcher and the entry builder both answer from here, and nothing is written
// to the store.
QList<QPair<QString, QString>> derivedAttributes(const DirectoryObject &o)
{
    QList<QPair<QString, QString>> out;
    if (o.id.isEmpty())
        return out;
    const QStringList classes = o.attributes.value(QStringLiteral("objectClass"))
                                    .split(QLatin1Char(';'), Qt::SkipEmptyParts);
    const auto hasClass = [&classes](const char *name) {
        for (const QString &c : classes) {
            if (c.trimmed().compare(QLatin1String(name), Qt::CaseInsensitive) == 0)
                return true;
        }
        return false;
    };

    // The schema the categories live in is in the forest's configuration NC, and
    // the forest root is the run of DC= components at the end of the object's
    // own DN.
    QString ncDn;
    const QStringList rdns = o.id.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (int i = 0; i < rdns.size(); ++i) {
        if (rdns.at(i).trimmed().startsWith(QLatin1String("DC="), Qt::CaseInsensitive)) {
            ncDn = rdns.mid(i).join(QLatin1Char(','));
            break;
        }
    }

    QString category;
    quint32 accountType = 0;
    if (hasClass("computer")) {
        category = QStringLiteral("Computer");
        accountType = 0x30000001u; // WORKSTATION_TRUST_ACCOUNT
    } else if (hasClass("group")) {
        category = QStringLiteral("Group");
        accountType = 0x10000000u; // GROUP
    } else if (hasClass("user")) {
        category = QStringLiteral("Person");
        accountType = 0x30000000u; // NORMAL_ACCOUNT
    } else if (hasClass("organizationalUnit")) {
        category = QStringLiteral("Organizational-Unit");
    } else if (hasClass("builtinDomain")) {
        category = QStringLiteral("Builtin-Domain");
    } else if (hasClass("domainDNS") || hasClass("domain")) {
        category = QStringLiteral("Domain-DNS");
    } else if (hasClass("nTDSDSA")) {
        category = QStringLiteral("NTDS-DSA");
    } else if (hasClass("container")) {
        category = QStringLiteral("Container");
    }

    if (!category.isEmpty() && !ncDn.isEmpty()) {
        out.append({QStringLiteral("objectCategory"),
                    QStringLiteral("CN=%1,CN=Schema,CN=Configuration,%2")
                        .arg(category, ncDn)});
    }
    if (accountType != 0)
        out.append({QStringLiteral("sAMAccountType"), QString::number(accountType)});
    if (accountType == 0x10000000u) {
        // A group's primary group token is its own RID, which is what a member's
        // tokenGroups names when the group is the primary one.
        const QString rid =
            o.attributes.value(QStringLiteral("objectSid")).section(QLatin1Char('-'), -1);
        bool ok = false;
        const uint token = rid.toUInt(&ok);
        if (ok)
            out.append({QStringLiteral("primaryGroupToken"), QString::number(token)});
    }
    return out;
}

QString attributeValue(const DirectoryObject &o, const QString &attr)
{
    const QString value = o.attributes.value(attr);
    if (!value.isEmpty())
        return value;
    // Objects built without an explicit cn fall back to their RDN name.
    if (attr.compare(QLatin1String("cn"), Qt::CaseInsensitive) == 0)
        return o.name;
    for (const auto &derived : derivedAttributes(o)) {
        if (derived.first.compare(attr, Qt::CaseInsensitive) == 0)
            return derived.second;
    }
    return QString();
}

bool valueEquals(const DirectoryObject &o, const QString &attr, const QString &wanted)
{
    const QString value = attributeValue(o, attr);
    if (value.compare(wanted, Qt::CaseInsensitive) == 0)
        return true;
    // Multi-valued attributes are stored as ';'-joined lists.
    for (const QString &candidate : value.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        if (candidate.trimmed().compare(wanted.trimmed(), Qt::CaseInsensitive) == 0)
            return true;
    }
    // objectCategory is a DN, and a client names the category either in full or
    // by its CN alone: `(objectCategory=person)` is what ADUC and Get-ADUser
    // send, and `(objectCategory=CN=Person,CN=Schema,...)` is the long form.
    if (attr.compare(QLatin1String("objectCategory"), Qt::CaseInsensitive) == 0) {
        QString category = value.section(QLatin1Char(','), 0, 0).trimmed();
        if (category.startsWith(QLatin1String("CN="), Qt::CaseInsensitive))
            category = category.mid(3);
        if (category.compare(wanted.trimmed(), Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QList<Pred> parseFilterList(const QByteArray &content)
{
    QList<Pred> subs;
    int cpos = 0;
    while (cpos < content.size()) {
        const int before = cpos;
        subs.append(parseFilter(content, cpos));
        if (cpos <= before)
            break;
    }
    return subs;
}

} // namespace

Pred parseFilter(const QByteArray &d, int &pos) {
    if (pos >= d.size()) return [](const DirectoryObject &){ return true; };
    const int t = readTag(d, pos);
    const int len = readLength(d, pos);
    if (len < 0 || pos + len > d.size()) {
        pos = d.size();
        return [](const DirectoryObject &){ return true; };
    }
    const QByteArray content = d.mid(pos, len);
    pos += len;

    switch (t) {
    case 0xa0: { // and
        const QList<Pred> subs = parseFilterList(content);
        return [subs](const DirectoryObject &o) {
            for (const Pred &sub : subs) {
                if (!sub(o))
                    return false;
            }
            return true;
        };
    }
    case 0xa1: { // or
        const QList<Pred> subs = parseFilterList(content);
        return [subs](const DirectoryObject &o) {
            if (subs.isEmpty())
                return false;
            for (const Pred &sub : subs) {
                if (sub(o))
                    return true;
            }
            return false;
        };
    }
    case 0xa2: { // not
        int cpos = 0;
        const Pred sub = parseFilter(content, cpos);
        return [sub](const DirectoryObject &o) { return !sub(o); };
    }
    case 0xa3: { // equalityMatch
        int cpos = 0;
        const QString attr = readString(content, cpos);
        const QString val = readString(content, cpos);
        return [attr, val](const DirectoryObject &o) { return valueEquals(o, attr, val); };
    }
    case 0xa4: { // substrings: attr, SEQUENCE of initial[0] / any[1] / final[2]
        int cpos = 0;
        const QString attr = readString(content, cpos);
        int tag = readTag(content, cpos);
        int len = readLength(content, cpos);
        Q_UNUSED(tag)
        const int end = cpos + len;
        QString initial;
        QString finalPart;
        QStringList any;
        while (cpos < end) {
            const int partTag = readTag(content, cpos);
            const int partLen = readLength(content, cpos);
            const QString part = QString::fromUtf8(content.mid(cpos, partLen));
            cpos += partLen;
            if (partTag == 0x80) initial = part;
            else if (partTag == 0x81) any.append(part);
            else if (partTag == 0x82) finalPart = part;
        }
        return [attr, initial, any, finalPart](const DirectoryObject &o) {
            const QString value = attributeValue(o, attr);
            // An empty substring sequence is a presence test.
            if (initial.isEmpty() && any.isEmpty() && finalPart.isEmpty())
                return !value.isEmpty();
            if (!initial.isEmpty() && !value.startsWith(initial, Qt::CaseInsensitive))
                return false;
            if (!finalPart.isEmpty() && !value.endsWith(finalPart, Qt::CaseInsensitive))
                return false;
            for (const QString &part : any) {
                if (!value.contains(part, Qt::CaseInsensitive))
                    return false;
            }
            return true;
        };
    }
    case 0xa5: { // extensibleMatch: rule [1], type [2], value [3], dnAttrs [4]
        int cpos = 0;
        QString rule;
        QString attr;
        QString val;
        bool dnAttributes = false;
        while (cpos < content.size()) {
            const int partTag = readTag(content, cpos);
            const int partLen = readLength(content, cpos);
            if (partLen < 0 || cpos + partLen > content.size())
                break;
            const QByteArray part = content.mid(cpos, partLen);
            cpos += partLen;
            if (partTag == 0x81)
                rule = QString::fromUtf8(part);
            else if (partTag == 0x82)
                attr = QString::fromUtf8(part);
            else if (partTag == 0x83)
                val = QString::fromUtf8(part);
            else if (partTag == 0x84)
                dnAttributes = !part.isEmpty() && part.at(0) != 0;
        }
        return [rule, attr, val, dnAttributes](const DirectoryObject &o) {
            // The two matching rules AD puts on integer attributes in its own
            // filters: a bitwise AND (1.2.840.113556.1.4.803) and a bitwise OR
            // (1.2.840.113556.1.4.804) of the stored value against the
            // assertion. ADUC's user list is why this exists:
            //   (&(objectCategory=person)(objectClass=user)
            //      (!userAccountControl:1.2.840.113556.1.4.803:=2))
            // It hides a user by setting that bit, so the negative filter is the
            // enabled list — and every extensible match used to fall through to
            // the parser's match-everything default, which made the negation
            // reject every user on the page.
            QStringList candidates = attributeValue(o, attr).split(QLatin1Char(';'),
                                                                   Qt::SkipEmptyParts);
            if (dnAttributes) {
                const QStringList rdns = o.id.split(QLatin1Char(','), Qt::SkipEmptyParts);
                for (const QString &rdn : rdns) {
                    const int eq = rdn.indexOf(QLatin1Char('='));
                    if (eq > 0 && rdn.left(eq).trimmed().compare(attr, Qt::CaseInsensitive) == 0)
                        candidates.append(rdn.mid(eq + 1));
                }
            }
            bool wantedOk = false;
            const quint32 wanted = val.trimmed().toUInt(&wantedOk);
            for (const QString &candidate : candidates) {
                if (candidate.trimmed().isEmpty())
                    continue;
                if (rule.isEmpty())
                    return valueEquals(o, attr, val);
                if (!wantedOk)
                    continue;
                bool haveOk = false;
                const quint32 have = candidate.trimmed().toUInt(&haveOk);
                if (!haveOk)
                    continue;
                if (rule == QLatin1String("1.2.840.113556.1.4.803")) {
                    if ((have & wanted) == wanted)
                        return true;
                } else if (rule == QLatin1String("1.2.840.113556.1.4.804")) {
                    if ((have & wanted) != 0)
                        return true;
                }
            }
            // A rule this store does not implement has no match to offer; it
            // must not widen the result set the way matching everything did.
            return false;
        };
    }
    case 0x87: { // present
        const QString attr = QString::fromUtf8(content);
        return [attr](const DirectoryObject &o) {
            if (attr.compare(QLatin1String("objectClass"), Qt::CaseInsensitive) == 0)
                return true;
            return !attributeValue(o, attr).isEmpty();
        };
    }
    case 0xa6:   // greaterOrEqual
    case 0xa8: { // lessOrEqual
        int cpos = 0;
        const QString attr = readString(content, cpos);
        const QString val = readString(content, cpos);
        const bool greater = (t == 0xa6);
        return [attr, val, greater](const DirectoryObject &o) {
            // Integers compare numerically, everything else as text. A range
            // filter used to fall through to match-everything, so any bound
            // returned the whole subtree and a client's "changed since" filter
            // could not be told apart from "everything".
            const QString value = attributeValue(o, attr);
            if (value.isEmpty())
                return false;
            for (const QString &candidate : value.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
                bool haveNum = false;
                bool wantNum = false;
                const qlonglong have = candidate.trimmed().toLongLong(&haveNum);
                const qlonglong want = val.trimmed().toLongLong(&wantNum);
                if (haveNum && wantNum) {
                    if (greater ? have >= want : have <= want)
                        return true;
                    continue;
                }
                const int cmp = candidate.trimmed().compare(val.trimmed(), Qt::CaseInsensitive);
                if (greater ? cmp >= 0 : cmp <= 0)
                    return true;
            }
            return false;
        };
    }
    case 0xa9: { // approxMatch: AD answers an approximation as an equality
        int cpos = 0;
        const QString attr = readString(content, cpos);
        const QString val = readString(content, cpos);
        return [attr, val](const DirectoryObject &o) { return valueEquals(o, attr, val); };
    }
    default:
        break;
    }
    // A filter type this store cannot evaluate has no matches to offer. Matching
    // everything, which is what this used to do, silently widened every such
    // query to the whole subtree — including the negation of one.
    return [](const DirectoryObject &){ return false; };
}

QString parentDn(const QString &dn) {
    int idx = dn.indexOf(',');
    if (idx < 0) return QString();
    return dn.mid(idx + 1);
}

bool isConfigurationDn(const QString &dn) {
    return dn.startsWith(QStringLiteral("CN=Configuration,"), Qt::CaseInsensitive)
        || dn.contains(QStringLiteral(",CN=Configuration,"), Qt::CaseInsensitive);
}

bool inScope(const DirectoryObject &o, const QString &base, int scope) {
    const QString b = base.trimmed();

    // Empty base is the root DSE search: only the root entry itself, or its
    // direct children (the naming contexts) for a one-level search.
    if (b.isEmpty()) {
        if (scope == 0)
            return o.id.isEmpty();
        if (scope == 1)
            return !o.id.isEmpty() && parentDn(o.id).isEmpty();
        return true;
    }

    // The root DSE is never part of a naming-context search.
    if (o.id.isEmpty())
        return false;

    // A domain naming context does not contain the Configuration partition,
    // even though both share the same DN suffix.
    if (isConfigurationDn(o.id) && !isConfigurationDn(b))
        return false;

    if (scope == 0)
        return o.id.compare(b, Qt::CaseInsensitive) == 0;
    if (scope == 1)
        return parentDn(o.id).compare(b, Qt::CaseInsensitive) == 0;

    const QString lowerBase = b.toLower();
    const QString lowerDn = o.id.toLower();
    return lowerDn == lowerBase || lowerDn.endsWith(QLatin1Char(',') + lowerBase);
}

} // namespace

LdapServer::LdapServer(QObject *parent) : QObject(parent) {
    m_server = new LdapListener(this, this);
}

LdapServer::~LdapServer() { close(); }

bool LdapServer::listen(quint16 port) {
    const bool ok = m_server->listen(QHostAddress::Any, port);
    // The locator's ping arrives on UDP at the same port number as the LDAP
    // listener; TCP and UDP bind independently, so a port already taken for UDP
    // (another CLDAP responder, say) does not cost us the directory itself.
    if (ok) listenCldap(m_server->serverPort());
    return ok;
}

bool LdapServer::listenCldap(quint16 port) {
    if (!m_cldap) {
        m_cldap = new QUdpSocket(this);
        connect(m_cldap, &QUdpSocket::readyRead, this, &LdapServer::onCldapDatagram);
    }
    if (m_cldap->state() == QAbstractSocket::BoundState) m_cldap->close();
    return m_cldap->bind(QHostAddress::Any, port);
}

void LdapServer::closeCldap() {
    if (m_cldap) m_cldap->close();
}

bool LdapServer::cldapListening() const {
    return m_cldap && m_cldap->state() == QAbstractSocket::BoundState;
}

quint16 LdapServer::cldapPort() const { return m_cldap ? m_cldap->localPort() : 0; }

void LdapServer::onCldapDatagram() {
    while (m_cldap && m_cldap->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(int(m_cldap->pendingDatagramSize()));
        QHostAddress peer;
        quint16 peerPort = 0;
        const qint64 read = m_cldap->readDatagram(datagram.data(), datagram.size(), &peer, &peerPort);
        if (read < 0) continue;
        datagram.truncate(int(read));
        const QByteArray reply = cldapResponse(datagram);
        if (!reply.isEmpty()) m_cldap->writeDatagram(reply, peer, peerPort);
    }
}

QByteArray LdapServer::cldapResponse(const QByteArray &request) const {
    // The only query a DC answers over UDP is the locator's ping: a baseObject
    // search on the root DSE whose filter asserts DnsDomain (MS-ADTS 6.3.1.4.1).
    // It is how a client satisfies itself that the machine its SRV record points
    // at really hosts this domain, and the answer carries the facts it needs to
    // carry on — the NetBIOS and DNS names, the site, the domain GUID and the
    // NtVer capabilities mask.
    Asn1::Element message;
    if (!Asn1::parse(request, &message) || message.tag != 0x30) return {};
    const Asn1::Element *idField = Asn1::child(message, 0x02);
    const Asn1::Element *search = Asn1::child(message, 0x63);
    if (!idField || !search) return {};

    const QList<const Asn1::Element *> scopeFields = Asn1::children(*search, 0x0a);
    if (!scopeFields.isEmpty() && Asn1::toInteger(*scopeFields.first()) != 0) return {};

    // Collect the filter's assertions. A ping names a domain; one that names a
    // different domain is answered with noSuchObject, the way a DC that hosts
    // only its own namespace would.
    QStringList assertions;
    QList<const Asn1::Element *> pending;
    for (const Asn1::Element &child : search->children) {
        // The filter is the context-tagged field of the search request; its
        // assertions are the leaf values beneath it.
        if ((child.tag & 0xa0) == 0xa0) pending.append(&child);
    }
    while (!pending.isEmpty()) {
        const Asn1::Element *element = pending.takeFirst();
        if (element->children.isEmpty()) {
            assertions.append(QString::fromUtf8(element->value));
            continue;
        }
        for (const Asn1::Element &child : element->children) pending.append(&child);
    }

    // A ping carries NtVer, DnsDomain, or both: Samba asks with NtVer alone
    // (and its own attribute, NetLogon), while DsGetDcName names the domain.
    // One that carries neither is a UDP LDAP search, not a locator ping, and
    // stays unanswered. A ping that names no domain is asking "are you a DC?",
    // so it is answered — refusing it looked exactly like a DC being absent,
    // which is the failure this reply exists to prevent.
    int domainIndex = -1;
    int userIndex = -1;
    bool asksAboutDomain = false;
    for (int i = 0; i < assertions.size(); ++i) {
        const QString &assertion = assertions.at(i);
        if (assertion.compare(QStringLiteral("DnsDomain"), Qt::CaseInsensitive) == 0) {
            domainIndex = i + 1;
            asksAboutDomain = true;
        } else if (assertion.compare(QStringLiteral("NtVer"), Qt::CaseInsensitive) == 0) {
            asksAboutDomain = true;
        } else if (assertion.compare(QStringLiteral("User"), Qt::CaseInsensitive) == 0) {
            userIndex = i + 1;
        }
    }
    if (!asksAboutDomain) return {};

    const int msgId = int(Asn1::toInteger(*idField));
    // A Windows locator ping names the domain as an FQDN with its root dot
    // (`corp.example.com.`); the SRV record it followed does not. They name the
    // same domain, and treating the dot as a different name made every Windows
    // 2000 logon answer noSuchObject, after which the client reports the domain
    // unavailable without ever opening the Netlogon pipe.
    const auto canonicalDomain = [](QString name) {
        while (name.endsWith(QLatin1Char('.'))) name.chop(1);
        return name;
    };
    if (domainIndex > 0 && domainIndex < assertions.size()
        && canonicalDomain(assertions.at(domainIndex))
                   .compare(canonicalDomain(m_identity.dnsDomain), Qt::CaseInsensitive)
               != 0) {
        QByteArray inner;
        writeInt(inner, 0x0a, 32); // noSuchObject
        writeString(inner, 0x04, QString());
        writeString(inner, 0x04, QString());
        QByteArray out;
        writeInt(out, 0x02, msgId);
        writeTLV(out, 0x65, inner);
        QByteArray seq;
        writeTLV(seq, 0x30, out);
        return seq;
    }

    const QString site = m_identity.siteName.isEmpty()
                             ? QStringLiteral("Default-First-Site-Name")
                             : m_identity.siteName;
    const QString host = m_identity.dcHost;
    const QString netbiosHost = host.section(QLatin1Char('.'), 0, 0).toUpper();

    // The domain's GUID, in the mixed-endian layout a GUID wears on the wire.
    QByteArray domainGuid;
    for (const DirectoryObject &object : m_objects) {
        if (object.kind != ObjectKind::Domain) continue;
        const QUuid stored(object.attributes.value(QStringLiteral("objectGUID")));
        const QUuid guid = stored.isNull() ? objectGuidFor(object.id) : stored;
        if (guid.isNull()) continue;
        const quint32 d1 = guid.data1;
        const quint16 d2 = guid.data2;
        const quint16 d3 = guid.data3;
        domainGuid.append(char(d1 & 0xff));
        domainGuid.append(char((d1 >> 8) & 0xff));
        domainGuid.append(char((d1 >> 16) & 0xff));
        domainGuid.append(char((d1 >> 24) & 0xff));
        domainGuid.append(char(d2 & 0xff));
        domainGuid.append(char((d2 >> 8) & 0xff));
        domainGuid.append(char(d3 & 0xff));
        domainGuid.append(char((d3 >> 8) & 0xff));
        for (int i = 0; i < 8; ++i) domainGuid.append(char(guid.data4[i]));
        break;
    }

    // The search names the attributes it wants back, and the entry carries those
    // and no others: an absent list means every attribute, a list means the ones
    // named. This is load-bearing rather than tidy. Samba's locator client
    // refuses any answer whose entry is not exactly one attribute called
    // netlogon (`num_attributes != 1` in libads/netlogon_ping.c), so a DC that
    // answers every ping with its whole attribute set cannot be found by
    // `net ads lookup` however good its Netlogon blob is.
    QList<QByteArray> requested;
    bool allAttributes = true;
    if (const Asn1::Element *attributeList = Asn1::child(*search, 0x30)) {
        for (const Asn1::Element &item : attributeList->children) requested.append(item.value);
        // An empty list is not "no attributes": RFC 4511 4.5.1.8 makes it mean
        // all user attributes, the same as no list at all.
        allAttributes = requested.isEmpty();
    }
    auto wants = [&requested, allAttributes](const char *name) {
        if (allAttributes) return true;
        for (const QByteArray &asked : requested) {
            if (asked == "*") return true;
            if (asked.compare(name, Qt::CaseInsensitive) == 0) return true;
        }
        return false;
    };

    auto attribute = [](const QString &type, const QByteArray &value) {
        QByteArray set;
        writeTLV(set, 0x04, value);
        QByteArray partial;
        writeString(partial, 0x04, type);
        writeTLV(partial, 0x31, set);
        QByteArray sequence;
        writeTLV(sequence, 0x30, partial);
        return sequence;
    };

    QByteArray attributes;
    if (wants("DnsDomain"))
        attributes.append(attribute(QStringLiteral("DnsDomain"), m_identity.dnsDomain.toUtf8()));
    // One namespace here: the domain is its own forest root.
    if (wants("DnsForestName"))
        attributes.append(
            attribute(QStringLiteral("DnsForestName"), m_identity.dnsDomain.toUtf8()));
    if (wants("DcSiteName"))
        attributes.append(attribute(QStringLiteral("DcSiteName"), site.toUtf8()));
    if (wants("NetbiosDomainName"))
        attributes.append(attribute(QStringLiteral("NetbiosDomainName"), m_identity.netbios.toUtf8()));
    if (wants("NetbiosComputerName"))
        attributes.append(
            attribute(QStringLiteral("NetbiosComputerName"), netbiosHost.toUtf8()));
    // DnsHostName is the name a client puts in its DC list; HostName is what a
    // Windows DC also publishes, so both are here.
    if (wants("DnsHostName"))
        attributes.append(attribute(QStringLiteral("DnsHostName"), host.toUtf8()));
    if (wants("HostName"))
        attributes.append(attribute(QStringLiteral("HostName"), host.toUtf8()));
    // NT_VERSION_5 | NT_VERSION_5EX: the capabilities mask a Windows DC
    // publishes, and the value the locator's own filter asks for.
    if (wants("NtVer"))
        attributes.append(attribute(QStringLiteral("NtVer"), QByteArray("\x06\x00\x00\x00", 4)));
    if (!domainGuid.isEmpty() && wants("DomainGuid"))
        attributes.append(attribute(QStringLiteral("DomainGuid"), domainGuid));
    if (wants("LdapService"))
        attributes.append(attribute(QStringLiteral("LdapService"), QByteArray("LDAP")));

    if (wants("NetLogon")) {
        // The locator's second answer, the binary blob `net ads lookup` and
        // Windows both parse: NETLOGON_SAM_LOGON_RESPONSE_EX as Samba's
        // librpc/idl/nbt.idl defines it, pushed with NDR_NOALIGN. Two things
        // about that encoding are easy to get wrong from the docs alone. The
        // strings are DNS label lists — a length byte per label and a closing
        // NUL — not UTF-16 and not NUL-terminated text. And the last eight
        // bytes are load-bearing: a client reads nt_version from length-8 and
        // rejects the blob unless 0xffff follows it twice, as the two legacy
        // tokens. Nothing here is declared by the LDAP attribute layer, so a
        // wrong layout is silent: the client simply says it found no DC.
        QByteArray blob;
        blob.append(char(23));
        blob.append(char(0)); // LOGON_SAM_LOGON_RESPONSE_EX
        blob.append(char(0));
        blob.append(char(0)); // sbz
        // What this server actually is: a writable AD DC that hosts LDAP, the
        // GC and the KDC, and answers the PDC query. No time service (there is
        // no NTP server here), and no 2008/2012 bits: the domain records
        // domainFunctionality 0, so a client must not be told otherwise.
        const quint32 serverType = 0x00000001 // PDC emulator
                                   | 0x00000004 // GC
                                   | 0x00000008 // LDAP
                                   | 0x00000010 // DS
                                   | 0x00000020 // KDC
                                   | 0x00000080 // closest site
                                   | 0x00000100; // writable
        for (int i = 0; i < 4; ++i) blob.append(char((serverType >> (8 * i)) & 0xff));
        blob.append(domainGuid.leftJustified(16, '\0', true));
        // NBT strings: one length-prefixed label at a time, then a NUL. An empty
        // string is that NUL alone, which is why the guard is on the whole name
        // rather than on each label.
        auto labelList = [](const QString &name) {
            QByteArray out;
            if (!name.isEmpty()) {
                for (const QByteArray &label : name.toUtf8().split('.')) {
                    out.append(char(label.size()));
                    out.append(label);
                }
            }
            out.append('\0');
            return out;
        };
        const QString user = (userIndex > 0 && userIndex < assertions.size())
                                 ? assertions.at(userIndex)
                                 : QString();
        blob.append(labelList(m_identity.dnsDomain)); // forest
        blob.append(labelList(m_identity.dnsDomain)); // dns_domain
        blob.append(labelList(host.toLower()));       // pdc_dns_name
        blob.append(labelList(m_identity.netbios));   // domain_name (pre-2000)
        blob.append(labelList(netbiosHost));          // pdc_name
        blob.append(labelList(user));                 // user_name
        blob.append(labelList(site));                 // server_site
        // One site: every client computes into it, so the client's site is this
        // DC's site and the CLOSEST bit above says so.
        blob.append(labelList(site)); // client_site
        // NT_VERSION_1 | NT_VERSION_5EX, which is what selects the EX layout in
        // a client's parser — the same choice Samba's own CLDAP server makes.
        // The IP address and closest-site fields are absent with these bits, so
        // the blob stays the same whatever mask the client asked with.
        blob.append(char(0x05));
        blob.append(char(0x00));
        blob.append(char(0x00));
        blob.append(char(0x00));
        blob.append(char(0xff));
        blob.append(char(0xff)); // lmnt_token
        blob.append(char(0xff));
        blob.append(char(0xff)); // lm20_token
        attributes.append(attribute(QStringLiteral("Netlogon"), blob));
    }

    QByteArray entry;
    writeString(entry, 0x04, QString()); // objectName: the root DSE
    QByteArray attrsSequence;
    writeTLV(attrsSequence, 0x30, attributes);
    entry.append(attrsSequence);

    QByteArray done;
    writeInt(done, 0x0a, 0); // success
    writeString(done, 0x04, QString());
    writeString(done, 0x04, QString());

    // A CLDAP answer is *two* LDAPMessages back to back — the entry, then the
    // result — each its own SEQUENCE with its own copy of the message id. Not
    // one SEQUENCE holding both: that is not an LDAPMessage at all, and a
    // client that decodes an LDAPMessage per SEQUENCE stops after the id and
    // finds no result. This server shipped the single-SEQUENCE form for a
    // while because nothing on the asking side checked; Samba's locator client
    // rejects it outright, which is what `CLDAP query failed` meant.
    auto ldapMessage = [](int id, int op, const QByteArray &body) {
        QByteArray inner;
        writeInt(inner, 0x02, id);
        writeTLV(inner, op, body);
        QByteArray message;
        writeTLV(message, 0x30, inner);
        return message;
    };
    return ldapMessage(msgId, 0x64, entry) + ldapMessage(msgId, 0x65, done);
}

void LdapServer::setIdentity(const Identity &identity) {
    m_identity = identity;
    if (!m_objects.isEmpty()) ensureRootDse();
}

bool LdapServer::listenGc(quint16 port) {
    if (!m_server || !m_server->isListening()) return false;
    if (m_gcServer && m_gcServer->isListening() && m_gcServer->serverPort() == port) return true;
    closeGc();
    // The catalog is the same store on another port, not a copy: a client that
    // searches 3268 sees what 389 sees, including writes made a moment ago.
    m_gcServer = new LdapListener(this, this);
    if (!m_gcServer->listen(QHostAddress::Any, port)) {
        delete m_gcServer;
        m_gcServer = nullptr;
        return false;
    }
    ensureRootDse();
    return true;
}

void LdapServer::closeGc() {
    if (!m_gcServer) return;
    m_gcServer->close();
    delete m_gcServer;
    m_gcServer = nullptr;
    ensureRootDse();
}

bool LdapServer::gcListening() const { return m_gcServer && m_gcServer->isListening(); }
quint16 LdapServer::gcServerPort() const { return m_gcServer ? m_gcServer->serverPort() : 0; }

void LdapServer::close() {
    for (auto *c : m_clients) {
        if (c->socket) c->socket->deleteLater();
        delete c;
    }
    m_clients.clear();
    closeCldap();
    if (m_server) m_server->close();
    if (m_gcServer) {
        m_gcServer->close();
        delete m_gcServer;
        m_gcServer = nullptr;
    }
}

bool LdapServer::isListening() const { return m_server && m_server->isListening(); }
quint16 LdapServer::serverPort() const { return m_server ? m_server->serverPort() : 0; }

void LdapServer::setObjects(const QList<DirectoryObject> &objects) {
    m_objects = objects;
    m_tombstones.clear();
    // uSNChanged has to keep moving forward across a restart. The counter lives
    // in memory, so a store that already holds USNs up to 1031 would otherwise
    // hand the next object 1001: a replication partner whose cursor is already
    // past that never sees the object at all, and two objects would share one
    // USN. Start from the store's high-water mark instead of over again.
    for (const DirectoryObject &object : m_objects) {
        bool ok = false;
        const long long usn =
            object.attributes.value(QStringLiteral("uSNChanged")).toLongLong(&ok);
        if (ok && usn > m_usn)
            m_usn = usn;
    }
    normalizeMembership();
    ensureRootDse();
}

bool LdapServer::saveToFile(const QString &path) const {
    QJsonArray arr;
    for (const DirectoryObject &o : m_objects) {
        if (o.id.isEmpty()) continue; // skip rootDSE
        QJsonObject jo;
        jo[QStringLiteral("id")] = o.id;
        jo[QStringLiteral("name")] = o.name;
        jo[QStringLiteral("type")] = o.type;
        jo[QStringLiteral("description")] = o.description;
        jo[QStringLiteral("kind")] = (int)o.kind;
        jo[QStringLiteral("container")] = o.container;
        QJsonObject attrs;
        for (auto it = o.attributes.begin(); it != o.attributes.end(); ++it)
            attrs[it.key()] = it.value();
        jo[QStringLiteral("attributes")] = attrs;
        jo[QStringLiteral("memberOf")] = QJsonArray::fromStringList(o.memberOf);
        jo[QStringLiteral("members")] = QJsonArray::fromStringList(o.members);
        arr.append(jo);
    }
    QJsonDocument doc(arr);
    // QSaveFile writes a temporary and renames it into place, so a copy of the
    // store taken while a client write lands sees either the whole old file or
    // the whole new one, never a torn one.
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    if (f.write(doc.toJson()) < 0) {
        f.cancelWriting();
        return false;
    }
    return f.commit();
}

void LdapServer::persistNow()
{
    if (m_persistHook)
        m_persistHook();
}

bool LdapServer::loadFromFile(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isArray()) return false;
    QList<DirectoryObject> objs;
    for (const QJsonValue &v : doc.array()) {
        QJsonObject jo = v.toObject();
        DirectoryObject o;
        o.id = jo[QStringLiteral("id")].toString();
        o.name = jo[QStringLiteral("name")].toString();
        o.type = jo[QStringLiteral("type")].toString();
        o.description = jo[QStringLiteral("description")].toString();
        o.kind = (ObjectKind)jo[QStringLiteral("kind")].toInt();
        o.container = jo[QStringLiteral("container")].toString();
        QJsonObject attrs = jo[QStringLiteral("attributes")].toObject();
        for (auto it = attrs.begin(); it != attrs.end(); ++it)
            o.attributes.insert(it.key(), it.value().toString());
        for (const QJsonValue &v : jo[QStringLiteral("memberOf")].toArray())
            o.memberOf.append(v.toString());
        for (const QJsonValue &v : jo[QStringLiteral("members")].toArray())
            o.members.append(v.toString());
        objs.append(o);
    }
    setObjects(objs);
    return true;
}

void LdapServer::setCredential(const QString &dn, const QByteArray &salt, const QByteArray &hash)
{
    Credential credential;
    credential.salt = salt;
    credential.hash = hash;
    m_credentials.insert(dn.toLower(), credential);
}

void LdapServer::clearCredentials()
{
    m_credentials.clear();
}

bool LdapServer::loadSecretsFromFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) return false;

    const QJsonObject secrets = doc.object();
    const QString adminDn = secrets.value(QStringLiteral("administratorDn")).toString();
    const QString salt = secrets.value(QStringLiteral("passwordSalt")).toString();
    const QString hash = secrets.value(QStringLiteral("passwordHash")).toString();
    if (adminDn.isEmpty() || salt.isEmpty() || hash.isEmpty()) return false;

    setCredential(adminDn, salt.toLatin1(), hash.toLatin1());
    return true;
}

namespace {

QByteArray saltedPasswordHash(const QByteArray &salt, const QString &password)
{
    QByteArray material = salt;
    material += password.toUtf8();
    material += salt;
    for (int i = 0; i < 1000; ++i)
        material = QCryptographicHash::hash(material, QCryptographicHash::Sha256);
    return material.toHex();
}

// AD sends unicodePwd as a quoted UTF-16LE string; the console and the wire
// client send UTF-8 under the same name. Which one arrived is decided by
// reading it both ways: UTF-16 text decoded as UTF-8 is full of NULs, so the
// form whose reading has none is the one that was written. The quotes come off
// after decoding, never before: in the UTF-16 form the first byte is 0x22 but
// the last is the top half of the closing quote, so testing the bytes finds no
// pair and both quotes stay in the password. That is how a machine account a
// join created ended up keyed one character off from the secret the machine had
// derived its own keys from, and its kinit failed on preauthentication.
QString decodePasswordValue(const QByteArray &raw, const QString &fallback)
{
    const auto unreadable = [](const QString &text) {
        return text.contains(QChar(0)) || text.contains(QChar(0xfffd));
    };
    const QString narrow = QString::fromUtf8(raw);
    QString wide;
    bool wideUsable = false;
    if (raw.size() >= 2 && raw.size() % 2 == 0) {
        wide = QString::fromUtf16(reinterpret_cast<const char16_t *>(raw.constData()),
                                  qsizetype(raw.size() / 2));
        wideUsable = !unreadable(wide);
    }
    QString text = (!unreadable(narrow) || !wideUsable) ? narrow : wide;
    if (text.size() >= 2 && text.startsWith(QLatin1Char('"')) && text.endsWith(QLatin1Char('"')))
        text = text.mid(1, text.size() - 2);
    if (text.isEmpty())
        return fallback;
    return text;
}

// The remembered passwords, as the account object carries them: the NT hashes
// of the passwords it used to have, newest first, comma separated. AD keeps the
// same information in its own credential store rather than as an attribute.
QStringList rememberedHashes(const DirectoryObject &object)
{
    return object.attributes.value(QStringLiteral("userPasswordHistory"))
        .split(QLatin1Char(','), Qt::SkipEmptyParts);
}

// Rolls the current password into the history and keeps at most `historyLength`
// entries. A policy of zero remembers nothing, as AD's does.
void rememberPassword(DirectoryObject &object, int historyLength)
{
    QStringList history = rememberedHashes(object);
    const QString previous = object.attributes.value(QStringLiteral("ntHash"));
    if (!previous.isEmpty()) {
        history.removeAll(previous);
        history.prepend(previous);
    }
    while (history.size() > historyLength)
        history.removeLast();
    if (history.isEmpty())
        object.attributes.remove(QStringLiteral("userPasswordHistory"));
    else
        object.attributes.insert(QStringLiteral("userPasswordHistory"),
                                 history.join(QLatin1Char(',')));
}

void storePasswordVerifier(DirectoryObject &object, const QString &password,
                           const QString &realm, int historyLength)
{
    rememberPassword(object, historyLength);
    QByteArray salt;
    for (int i = 0; i < 2; ++i) {
        const quint64 value = QRandomGenerator::system()->generate64();
        salt.append(QByteArray::number(value, 16).rightJustified(16, '0'));
    }
    const QByteArray hash = saltedPasswordHash(salt, password);
    object.attributes.insert(QStringLiteral("userPasswordSalt"), QString::fromLatin1(salt));
    object.attributes.insert(QStringLiteral("userPasswordHash"), QString::fromLatin1(hash));
    object.attributes.insert(QStringLiteral("passwordScheme"),
                             QStringLiteral("sha256-salted-1000+ntowfv1"));
    // The credential AD itself keeps: MD4 of the UTF-16LE password, used as the
    // NTLMv2 response key. Never returned by a search.
    object.attributes.insert(QStringLiteral("ntHash"),
                             QString::fromLatin1(Ntlm::ntowfV1(password).toHex()));
    // The AES long-term keys AD keeps next to the NT hash, derived with the
    // account's salt so a Kerberos client can get aes256/aes128 tickets.
    const QString account =
        object.attributes.value(QStringLiteral("sAMAccountName")).isEmpty()
            ? object.name
            : object.attributes.value(QStringLiteral("sAMAccountName"));
    Krb5::storePasswordKeys(object, password, realm, account);
    object.attributes.insert(QStringLiteral("pwdLastSet"),
                             QString::number(QDateTime::currentDateTimeUtc().toSecsSinceEpoch()));
    object.attributes.remove(QStringLiteral("userPassword"));
    object.attributes.remove(QStringLiteral("unicodePwd"));
}

bool isPasswordAttribute(const QString &type)
{
    return type.compare(QLatin1String("unicodepwd"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("userpassword"), Qt::CaseInsensitive) == 0;
}

bool isSecretAttribute(const QString &type)
{
    return isPasswordAttribute(type)
           || type.compare(QLatin1String("userpasswordsalt"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("userpasswordhash"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("passwordscheme"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("nthash"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("userpasswordhistory"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("aes128key"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("aes256key"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("kerberossalt"), Qt::CaseInsensitive) == 0;
}

// Derived by the server from the password; never accepted from a client.
bool isServerOnlyAttribute(const QString &type)
{
    return type.compare(QLatin1String("userpasswordsalt"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("userpasswordhash"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("passwordscheme"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("nthash"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("aes128key"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("aes256key"), Qt::CaseInsensitive) == 0
           || type.compare(QLatin1String("kerberossalt"), Qt::CaseInsensitive) == 0;
}

} // namespace

long long LdapServer::nextUsn() { return ++m_usn; }

QString rootDseNamingContext(const QList<DirectoryObject> &objects)
{
    // 1. The provisioned domain NC identifies itself as domainDNS.
    for (const DirectoryObject &o : objects) {
        if (!o.id.isEmpty()
            && o.type.compare(QStringLiteral("domainDNS"), Qt::CaseInsensitive) == 0)
            return o.id;
    }
    // 2. Otherwise use a DC=... entry, which is itself a naming context.
    QString best;
    for (const DirectoryObject &o : objects) {
        if (!o.id.startsWith(QStringLiteral("DC="), Qt::CaseInsensitive)) continue;
        if (best.isEmpty() || o.id.size() < best.size()) best = o.id;
    }
    if (!best.isEmpty()) return best;
    // 3. Last resort: take the trailing DC= components of any entry, so plain
    //    sample data still reports the domain it belongs to.
    for (const DirectoryObject &o : objects) {
        if (o.id.isEmpty()) continue;
        const QStringList parts = o.id.split(QLatin1Char(','));
        QStringList suffix;
        for (int i = parts.size() - 1; i >= 0; --i) {
            const QString part = parts.at(i).trimmed();
            if (!part.startsWith(QStringLiteral("DC="), Qt::CaseInsensitive)) break;
            suffix.prepend(part);
        }
        if (!suffix.isEmpty()) return suffix.join(QLatin1Char(','));
    }
    return {};
}

LdapServer::PasswordPolicy LdapServer::passwordPolicyFrom(const DirectoryObject &domain)
{
    PasswordPolicy policy;
    if (domain.id.isEmpty())
        return policy;
    const auto value = [&domain](const char *name) {
        return domain.attributes.value(QString::fromLatin1(name));
    };
    bool ok = false;
    const int minLength = value("minPwdLength").toInt(&ok);
    if (ok)
        policy.minLength = minLength;
    const int history = value("pwdHistoryLength").toInt(&ok);
    if (ok)
        policy.historyLength = history;
    const quint32 properties = value("pwdProperties").toUInt(&ok);
    if (ok)
        policy.properties = properties;
    // AD stores a relative time as a negative count of 100-nanosecond units, and
    // "never" as the most negative value a signed 64-bit integer can hold, which
    // is what zero days turns into through the AD tools.
    const qint64 maxAge = value("maxPwdAge").toLongLong(&ok);
    if (ok)
        policy.maxAge = maxAge;
    const qint64 minAge = value("minPwdAge").toLongLong(&ok);
    if (ok)
        policy.minAge = minAge;
    return policy;
}

LdapServer::PasswordPolicy LdapServer::passwordPolicy() const
{
    const QString dn = rootDseNamingContext(m_objects);
    for (const DirectoryObject &object : m_objects) {
        if (!dn.isEmpty() && object.id.compare(dn, Qt::CaseInsensitive) == 0)
            return passwordPolicyFrom(object);
    }
    return passwordPolicyFrom(DirectoryObject());
}

// What AD's password policy checks, in the order a user meets it: the length
// floor, the complexity rule, and the remembered passwords. Fine-grained
// password policies (a PSO on an object or group) are not modelled, so this is
// always the domain policy.
bool LdapServer::passwordMeetsPolicy(const QString &password, QString *reason) const
{
    const PasswordPolicy policy = this->passwordPolicy();
    if (password.size() < policy.minLength || password.size() > 256) {
        if (reason)
            *reason = QStringLiteral("password must be at least %1 characters")
                          .arg(policy.minLength);
        return false;
    }
    if ((policy.properties & kPasswordComplex) == 0)
        return true;
    // AD's rule: three of the four character classes, not counting the account
    // name. The unaesthetic-looking count is AD's; it is why "abCD1" passes and
    // "abcdefg" does not.
    bool upper = false, lower = false, digit = false, other = false;
    for (const QChar c : password) {
        if (c.isUpper()) upper = true;
        else if (c.isLower()) lower = true;
        else if (c.isDigit()) digit = true;
        else other = true;
    }
    const int classes = int(upper) + int(lower) + int(digit) + int(other);
    if (classes < 3) {
        if (reason)
            *reason = QStringLiteral("password must use three of the four character classes");
        return false;
    }
    return true;
}

bool LdapServer::passwordWasUsed(const DirectoryObject &object, const QString &password,
                                 QString *reason) const
{
    const int historyLength = passwordPolicy().historyLength;
    if (historyLength <= 0)
        return false;
    // The hash of the password being set, compared against the ones remembered
    // for this account — including the current password, which a change may not
    // repeat.
    const QString candidate = QString::fromLatin1(Ntlm::ntowfV1(password).toHex());
    if (object.attributes.value(QStringLiteral("ntHash")) == candidate) {
        if (reason)
            *reason = QStringLiteral("password was used before");
        return true;
    }
    if (rememberedHashes(object).contains(candidate)) {
        if (reason)
            *reason = QStringLiteral("password was used before");
        return true;
    }
    return false;
}

void LdapServer::ensureRootDse() {
    // Remove existing rootDSE (empty DN).
    for (int i = m_objects.size() - 1; i >= 0; i--) {
        if (m_objects[i].id.isEmpty()) m_objects.removeAt(i);
    }

    QString domainDn = rootDseNamingContext(m_objects);
    if (domainDn.isEmpty()) domainDn = QStringLiteral("DC=corp,DC=example,DC=com");
    const QString configDn = QStringLiteral("CN=Configuration,%1").arg(domainDn);
    const QString schemaDn = QStringLiteral("CN=Schema,%1").arg(configDn);

    DirectoryObject root;
    root.id = QString();
    root.name = QString();
    root.type = QStringLiteral("Root DSE");
    root.kind = ObjectKind::Unknown;
    root.container = QString();
    root.attributes.insert(QStringLiteral("namingContexts"), domainDn);
    root.attributes.insert(QStringLiteral("defaultNamingContext"), domainDn);
    root.attributes.insert(QStringLiteral("schemaNamingContext"), schemaDn);
    root.attributes.insert(QStringLiteral("configurationNamingContext"), configDn);
    root.attributes.insert(QStringLiteral("rootDomainNamingContext"), domainDn);
    root.attributes.insert(QStringLiteral("supportedLDAPVersion"), QStringLiteral("3"));
    root.attributes.insert(QStringLiteral("vendorName"), QStringLiteral("Monarchy"));
    root.attributes.insert(QStringLiteral("vendorVersion"), QStringLiteral("0.1"));
    root.attributes.insert(QStringLiteral("highestCommittedUSN"), QString::number(m_usn));
    root.attributes.insert(QStringLiteral("currentTime"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));

    // The DSA's own identity. A Windows client asks these questions before it
    // treats the server as a domain controller: which directory agent is this,
    // which NC does it hold, is it in sync, and what behavior level does it
    // promise. Each value below is published from what this process actually
    // does, so nothing here asserts a capability the server lacks.
    if (!m_identity.dcHost.isEmpty()) {
        const QString shortHost = m_identity.dcHost.section(QLatin1Char('.'), 0, 0).toUpper();
        const QString site = m_identity.siteName.isEmpty()
                                 ? QStringLiteral("Default-First-Site-Name")
                                 : m_identity.siteName;
        const QString serverDn = QStringLiteral("CN=%1,CN=Servers,CN=%2,CN=Sites,%3")
                                     .arg(shortHost, site, configDn);
        root.attributes.insert(QStringLiteral("dnsHostName"), m_identity.dcHost);
        root.attributes.insert(QStringLiteral("serverName"), serverDn);
        root.attributes.insert(QStringLiteral("dsServiceName"),
                               QStringLiteral("CN=NTDS Settings,%1").arg(serverDn));
        if (!m_identity.netbios.isEmpty() && !m_identity.realm.isEmpty()) {
            root.attributes.insert(
                QStringLiteral("ldapServiceName"),
                QStringLiteral("%1\\%2$@%3")
                    .arg(m_identity.netbios.toLower(),
                         shortHost.toLower().section(QLatin1Char('$'), 0, 0),
                         m_identity.realm));
        }
        root.attributes.insert(QStringLiteral("isSynchronized"), QStringLiteral("TRUE"));
        root.attributes.insert(QStringLiteral("isGlobalCatalogReady"),
                               gcListening() ? QStringLiteral("TRUE") : QStringLiteral("FALSE"));
        // Windows 2000 behavior level. Every DC in a Windows 2000 forest reports
        // 0 here, and 0 is what this server implements: no read-only DCs, no
        // DFSR, no Recycle Bin, no post-2000 schema behavior.
        root.attributes.insert(QStringLiteral("domainControllerFunctionality"), QStringLiteral("0"));
        root.attributes.insert(QStringLiteral("domainFunctionality"), QStringLiteral("0"));
        root.attributes.insert(QStringLiteral("forestFunctionality"), QStringLiteral("0"));
        root.attributes.insert(QStringLiteral("supportedCapabilities"),
                               QStringLiteral("1.2.840.113556.1.4.800"));
        // Only the control this server answers: paged results. Listing the
        // others a Windows 2000 DC lists would advertise handlers that are not
        // here, which is exactly the kind of claim this project refuses.
        root.attributes.insert(QStringLiteral("supportedControl"),
                               QStringLiteral("1.2.840.113556.1.4.319"));
        root.attributes.insert(QStringLiteral("supportedSASLMechanisms"),
                               QStringLiteral("GSSAPI; GSS-SPNEGO"));
    }
    m_objects.prepend(root);

    // Schema container (minimal) — only when the store does not have one.
    bool haveSchema = false;
    for (const DirectoryObject &o : m_objects) {
        if (o.id.compare(schemaDn, Qt::CaseInsensitive) == 0) { haveSchema = true; break; }
    }
    if (!haveSchema) {
        DirectoryObject schema;
        schema.id = schemaDn;
        schema.name = QStringLiteral("Schema");
        schema.type = QStringLiteral("dMD");
        schema.kind = ObjectKind::Unknown;
        schema.container = configDn;
        schema.attributes.insert(QStringLiteral("cn"), QStringLiteral("Schema"));
        schema.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("dMD"));
        m_objects.append(schema);
    }
}

bool LdapServer::removeObject(const QString &dn) {
    for (int i = 0; i < m_objects.size(); i++) {
        if (m_objects[i].id.compare(dn, Qt::CaseInsensitive) == 0) {
            const QString removed = m_objects[i].id;

            // AD does not erase a deleted object; it keeps a tombstone so the
            // deletion replicates. Only the identity attributes survive
            // (MS-ADTS 3.1.1.3.3), the RDN is mangled with \0ADEL:<guid> so the
            // original name is free again, and the new uSNChanged puts the
            // deletion after every live object a replication cursor has passed.
            DirectoryObject tombstone;
            tombstone.id = m_objects[i].id;
            tombstone.name = m_objects[i].name;
            tombstone.type = m_objects[i].type;
            tombstone.description = m_objects[i].description;
            tombstone.kind = m_objects[i].kind;
            for (const QString &keep : {QStringLiteral("objectGUID"),
                                        QStringLiteral("objectSid"),
                                        QStringLiteral("whenCreated")}) {
                if (m_objects[i].attributes.contains(keep))
                    tombstone.attributes.insert(keep, m_objects[i].attributes.value(keep));
            }
            QString guid = tombstone.attributes.value(QStringLiteral("objectGUID"));
            if (guid.isEmpty()) {
                // The tombstone has to carry the identity the live object had,
                // or a partner cannot tell which object was deleted: it would
                // match nothing here and leave the live copy standing. This
                // store derives an objectGUID from the DN when it holds none,
                // and that derived GUID is the identity every other path
                // publishes, so carry that one rather than inventing another.
                guid = objectGuidFor(tombstone.id).toString(QUuid::WithoutBraces);
                tombstone.attributes.insert(QStringLiteral("objectGUID"), guid);
            }
            QString bare = guid;
            bare.remove(QLatin1Char('{'));
            bare.remove(QLatin1Char('}'));
            const int comma = tombstone.id.indexOf(QLatin1Char(','));
            const QString rdn = comma < 0 ? tombstone.id : tombstone.id.left(comma);
            const QString rest = comma < 0 ? QString() : tombstone.id.mid(comma);
            if (rdn.contains(QLatin1Char('='))) {
                tombstone.id = rdn + QChar(u'\0') + QStringLiteral("ADEL:") + bare + rest;
                tombstone.name = tombstone.name + QChar(u'\0')
                    + QStringLiteral("ADEL:") + bare;
            }
            tombstone.attributes.insert(QStringLiteral("isDeleted"), QStringLiteral("TRUE"));
            tombstone.attributes.insert(QStringLiteral("whenChanged"),
                                        QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
            tombstone.attributes.insert(QStringLiteral("uSNChanged"),
                                        QString::number(nextUsn()));
            m_tombstones.append(tombstone);

            m_objects.removeAt(i);
            // A deleted object must not stay behind in any group's member list.
            for (DirectoryObject &object : m_objects) {
                object.members.erase(std::remove_if(object.members.begin(), object.members.end(),
                                                    [&removed](const QString &member) {
                                                        return member.compare(removed, Qt::CaseInsensitive) == 0;
                                                    }),
                                     object.members.end());
            }
            normalizeMembership();
            ensureRootDse();
            return true;
        }
    }
    return false;
}

int LdapServer::applyReplication(const QList<DirectoryObject> &incoming)
{
    int applied = 0;
    for (const DirectoryObject &change : incoming) {
        if (change.id.isEmpty())
            continue; // the root DSE is derived from the store, not replicated
        const bool deleted = change.attributes.value(QStringLiteral("isDeleted"))
                                 .compare(QLatin1String("TRUE"), Qt::CaseInsensitive) == 0;
        const QString changeGuid =
            change.attributes.value(QStringLiteral("objectGUID")).toLower();

        // Identity is the objectGUID. A store here derives one from the DN when
        // it holds none (ObjectGuid.h), and that is the GUID DRS exported for
        // the same object, so comparing stored attributes alone left this DC's
        // own copy of an account unmatched and appended a second object at the
        // same distinguished name — two entries for one object, which AD never
        // has. Compare the effective GUID, the one every other path publishes.
        const QUuid changeObjectGuid(changeGuid);
        const auto sameObject = [&changeObjectGuid, &change](const DirectoryObject &candidate) {
            if (candidate.id.isEmpty())
                return false;
            if (!changeObjectGuid.isNull()) {
                const QUuid stored(
                    candidate.attributes.value(QStringLiteral("objectGUID")));
                const QUuid candidateGuid = stored.isNull() ? objectGuidFor(candidate.id) : stored;
                return candidateGuid == changeObjectGuid;
            }
            return candidate.id.compare(change.id, Qt::CaseInsensitive) == 0;
        };

        int liveIndex = -1;
        for (int i = 0; i < m_objects.size(); ++i) {
            if (sameObject(m_objects[i])) {
                liveIndex = i;
                break;
            }
        }

        if (deleted) {
            if (liveIndex >= 0) {
                // The local copy becomes the tombstone, so the deletion is
                // stamped here and the object leaves every group it was in.
                if (!changeGuid.isEmpty()
                    && m_objects[liveIndex].attributes
                           .value(QStringLiteral("objectGUID")).isEmpty())
                    m_objects[liveIndex].attributes.insert(QStringLiteral("objectGUID"),
                                                           changeGuid);
                if (removeObject(m_objects[liveIndex].id))
                    ++applied;
                continue;
            }
            bool known = false;
            for (const DirectoryObject &tombstone : m_tombstones) {
                if (sameObject(tombstone)) {
                    known = true;
                    break;
                }
            }
            if (!known) {
                DirectoryObject tombstone = change;
                if (tombstone.attributes.value(QStringLiteral("whenChanged")).isEmpty())
                    tombstone.attributes.insert(QStringLiteral("whenChanged"),
                                                QDateTime::currentDateTimeUtc()
                                                    .toString(Qt::ISODate));
                tombstone.attributes.insert(QStringLiteral("uSNChanged"),
                                            QString::number(nextUsn()));
                m_tombstones.append(tombstone);
                ++applied;
            }
            continue;
        }

        // A tombstoned object stays deleted: AD will not reanimate one without
        // the recycle-bin operation, so a stale live copy is ignored.
        bool tombstoned = false;
        for (const DirectoryObject &tombstone : m_tombstones) {
            if (sameObject(tombstone)) {
                tombstoned = true;
                break;
            }
        }
        if (tombstoned)
            continue;

        if (liveIndex >= 0) {
            DirectoryObject &target = m_objects[liveIndex];
            const QString localDn = target.id;
            // A cycle carries the replicated attribute set: object class, name,
            // membership, SID and GUID. Credentials are not part of it — every
            // DC holds its own copy of the password hashes — and neither is the
            // per-DC logon state. Replacing the object with the inbound copy
            // alone therefore stripped this DC's own secrets, and an account
            // that had replicated in could no longer authenticate here at all.
            // Overlay what arrived and keep what this DC holds and a partner
            // never sends.
            for (auto it = change.attributes.constBegin(); it != change.attributes.constEnd();
                 ++it) {
                target.attributes.insert(it.key(), it.value());
            }
            target.type = change.type;
            if (change.kind != ObjectKind::Unknown)
                target.kind = change.kind;
            if (!change.container.isEmpty())
                target.container = change.container;
            // Membership is carried as the member attribute; an empty list on
            // the wire cannot be told from an attribute that was not sent, so
            // only a non-empty one replaces what this DC holds.
            if (!change.members.isEmpty())
                target.members = change.members;
            target.id = localDn; // the local DN names the object here
            target.attributes.insert(QStringLiteral("distinguishedName"), localDn);
            target.attributes.insert(QStringLiteral("uSNChanged"),
                                     QString::number(nextUsn()));
            ++applied;
        } else {
            DirectoryObject created = change;
            created.attributes.insert(QStringLiteral("uSNChanged"),
                                      QString::number(nextUsn()));
            m_objects.append(created);
            ++applied;
        }
    }
    normalizeMembership();
    ensureRootDse();
    return applied;
}

void LdapServer::normalizeMembership() {
    QSet<QString> knownDns;
    QHash<QString, QString> dnByName;
    for (const DirectoryObject &object : m_objects) {
        if (object.id.isEmpty())
            continue;
        knownDns.insert(object.id.toLower());
        if (!object.name.isEmpty() && !dnByName.contains(object.name.toLower()))
            dnByName.insert(object.name.toLower(), object.id);
    }

    // 1. Every stored member names an object by distinguished name.
    for (DirectoryObject &object : m_objects) {
        for (QString &member : object.members) {
            const QString key = member.trimmed().toLower();
            if (knownDns.contains(key))
                continue;
            const auto resolved = dnByName.constFind(key);
            if (resolved != dnByName.constEnd()) {
                member = resolved.value();
                continue;
            }
            // Unresolvable values are left alone so a dangling reference stays
            // visible rather than silently disappearing.
        }
    }

    // 2. memberOf is exactly the set of groups that list the object.
    QHash<QString, QStringList> derived;
    for (const DirectoryObject &group : m_objects) {
        if (group.kind != ObjectKind::Group || group.id.isEmpty())
            continue;
        for (const QString &member : group.members) {
            const QString key = member.toLower();
            if (knownDns.contains(key) && !derived[key].contains(group.id))
                derived[key].append(group.id);
        }
    }
    for (DirectoryObject &object : m_objects)
        object.memberOf = derived.value(object.id.toLower());
}

QString LdapServer::domainSidPrefix() const
{
    // The domain's own SID ends at the authority (S-1-5-21-a-b-c, seven
    // components); every account appends one more. Anything shorter or longer
    // is not this domain's SID and must not be used as a base.
    for (const DirectoryObject &object : m_objects) {
        const QString sid = object.attributes.value(QStringLiteral("objectSid"));
        if (sid.split(QLatin1Char('-')).size() == 7)
            return sid;
    }
    for (const DirectoryObject &object : m_objects) {
        QStringList parts = object.attributes.value(QStringLiteral("objectSid"))
                                .split(QLatin1Char('-'));
        if (parts.size() == 8) {
            parts.removeLast();
            return parts.join(QLatin1Char('-'));
        }
    }
    return QString();
}

quint32 LdapServer::nextRid() const
{
    const QString prefix = domainSidPrefix();
    quint32 highest = 999; // AD starts ordinary accounts at 1000
    if (prefix.isEmpty())
        return 1000;
    for (const DirectoryObject &object : m_objects) {
        const QString sid = object.attributes.value(QStringLiteral("objectSid"));
        const QStringList parts = sid.split(QLatin1Char('-'));
        if (parts.size() != 8)
            continue;
        if (sid.left(sid.lastIndexOf(QLatin1Char('-'))) != prefix)
            continue;
        const quint32 rid = parts.last().toUInt();
        if (rid > highest)
            highest = rid;
    }
    return highest + 1;
}

bool LdapServer::addAccount(DirectoryObject *object, QString *error)
{
    if (!object)
        return false;
    const QString account = object->attributes.value(QStringLiteral("sAMAccountName"));
    if (account.isEmpty() || object->id.isEmpty()) {
        if (error)
            *error = QStringLiteral("account name is required");
        return false;
    }
    for (const DirectoryObject &existing : m_objects) {
        if (existing.attributes.value(QStringLiteral("sAMAccountName"))
                .compare(account, Qt::CaseInsensitive) == 0) {
            if (error)
                *error = QStringLiteral("%1 already exists").arg(account);
            return false;
        }
        if (existing.id.compare(object->id, Qt::CaseInsensitive) == 0) {
            if (error)
                *error = QStringLiteral("%1 already exists").arg(object->id);
            return false;
        }
    }
    const QString prefix = domainSidPrefix();
    if (prefix.isEmpty()) {
        if (error)
            *error = QStringLiteral("no domain SID in the store");
        return false;
    }
    const quint32 rid = nextRid();
    object->attributes.insert(QStringLiteral("objectSid"),
                              QStringLiteral("%1-%2").arg(prefix).arg(rid));
    addObject(*object);
    return true;
}

bool LdapServer::setNtHash(const QString &dn, const QByteArray &ntHash, QString *error) {
    if (ntHash.size() != 16) {
        if (error)
            *error = QStringLiteral("an NT hash is 16 bytes");
        return false;
    }
    int index = -1;
    for (int i = 0; i < m_objects.size(); ++i) {
        if (m_objects[i].id.compare(dn, Qt::CaseInsensitive) == 0) {
            index = i;
            break;
        }
    }
    if (index < 0) {
        if (error)
            *error = QStringLiteral("no such account");
        return false;
    }

    DirectoryObject &object = m_objects[index];
    // The remembered-password rule applies to a hash write too: MS-SAMR 3.1.5.6.3
    // looks for the new credential in the history before it applies it.
    const QString candidate = QString::fromLatin1(ntHash.toHex());
    if (passwordPolicy().historyLength > 0
        && (object.attributes.value(QStringLiteral("ntHash")) == candidate
            || rememberedHashes(object).contains(candidate))) {
        if (error)
            *error = QStringLiteral("password was used before");
        return false;
    }
    rememberPassword(object, passwordPolicy().historyLength);
    // A hash is a credential of record, not an addition: the salted verifier
    // and the Kerberos keys the old password produced would otherwise keep
    // authenticating that password.
    for (const QString &stale : {QStringLiteral("userPasswordSalt"),
                                 QStringLiteral("userPasswordHash"),
                                 QStringLiteral("aes128Key"),
                                 QStringLiteral("aes256Key"),
                                 QStringLiteral("kerberosSalt"),
                                 QStringLiteral("userPassword"),
                                 QStringLiteral("unicodePwd")}) {
        object.attributes.remove(stale);
    }
    object.attributes.insert(QStringLiteral("ntHash"), QString::fromLatin1(ntHash.toHex()));
    object.attributes.insert(QStringLiteral("passwordScheme"), QStringLiteral("ntowfv1"));
    object.attributes.insert(QStringLiteral("pwdLastSet"),
                             QString::number(QDateTime::currentDateTimeUtc().toSecsSinceEpoch()));
    object.attributes.insert(QStringLiteral("uSNChanged"), QString::number(nextUsn()));
    object.attributes.insert(QStringLiteral("whenChanged"),
                             QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    emit requestReceived(QStringLiteral("NT hash set for %1").arg(dn));
    return true;
}

bool LdapServer::modifyObject(const QString &dn, const QMap<QString, QString> &attrs) {
    QList<ModifyChange> changes;
    for (auto it = attrs.begin(); it != attrs.end(); ++it) {
        ModifyChange change;
        change.operation = 2;
        change.type = it.key();
        change.values = isPasswordAttribute(it.key())
                            ? QStringList{it.value()}
                            : it.value().split(QStringLiteral("; "), Qt::SkipEmptyParts);
        change.rawValue = it.value().toUtf8();
        changes.append(change);
    }
    return applyModify(dn, changes) == 0;
}

int LdapServer::applyModify(const QString &dn, const QList<ModifyChange> &changes) {
    int index = -1;
    for (int i = 0; i < m_objects.size(); ++i) {
        if (m_objects[i].id.compare(dn, Qt::CaseInsensitive) == 0) {
            index = i;
            break;
        }
    }
    if (index < 0)
        return 32; // noSuchObject

    DirectoryObject &object = m_objects[index];
    for (const ModifyChange &change : changes) {
        const QString type = change.type.toLower();
        if (isPasswordAttribute(change.type)) {
            if (change.operation == 1) { // delete: no password until one is set
                object.attributes.remove(QStringLiteral("userPasswordSalt"));
                object.attributes.remove(QStringLiteral("userPasswordHash"));
                object.attributes.remove(QStringLiteral("ntHash"));
                object.attributes.remove(QStringLiteral("aes128Key"));
                object.attributes.remove(QStringLiteral("aes256Key"));
                object.attributes.insert(QStringLiteral("pwdLastSet"), QStringLiteral("0"));
                continue;
            }
            const QString password = decodePasswordValue(change.rawValue, change.values.value(0));
            QString reason;
            if (!passwordMeetsPolicy(password, &reason) || passwordWasUsed(object, password, &reason)) {
                emit requestReceived(QStringLiteral("Password rejected: %1").arg(reason));
                return 19; // constraintViolation
            }
            storePasswordVerifier(object, password,
                                  m_kdc ? m_kdc->realm().realm : QString(),
                                  passwordPolicy().historyLength);
            continue;
        }
        if (type == QLatin1String("member")) {
            QStringList values = object.members;
            for (const QString &value : change.values) {
                const QString member = value.trimmed();
                if (member.isEmpty())
                    continue;
                const bool present = std::any_of(values.begin(), values.end(),
                                                 [&member](const QString &existing) {
                                                     return existing.compare(member, Qt::CaseInsensitive) == 0;
                                                 });
                if (change.operation == 0 && !present)
                    values.append(member);
                else if (change.operation == 1)
                    values.erase(std::remove_if(values.begin(), values.end(),
                                                [&member](const QString &existing) {
                                                    return existing.compare(member, Qt::CaseInsensitive) == 0;
                                                }),
                                 values.end());
            }
            if (change.operation == 2)
                values = change.values;
            object.members = values;
            object.attributes.remove(QStringLiteral("member"));
            continue;
        }
        if (type == QLatin1String("memberof")) {
            // Derived from the groups' member lists; a client cannot set it.
            continue;
        }
        if (isServerOnlyAttribute(change.type))
            return 19; // constraintViolation: password material is server-made

        QStringList values = object.attributes.value(change.type)
                                 .split(QStringLiteral("; "), Qt::SkipEmptyParts);
        if (change.operation == 2) {
            values = change.values;
        } else if (change.operation == 0) {
            for (const QString &value : change.values) {
                if (!values.contains(value))
                    values.append(value);
            }
        } else if (change.operation == 1) {
            if (change.values.isEmpty()) {
                values.clear();
            } else {
                for (const QString &value : change.values)
                    values.removeAll(value);
            }
        }
        if (values.isEmpty())
            object.attributes.remove(change.type);
        else
            object.attributes.insert(change.type, values.join(QStringLiteral("; ")));
        if (type == QLatin1String("cn") && !values.isEmpty())
            object.name = values.first();
        if (type == QLatin1String("description") && !values.isEmpty())
            object.description = values.first();
    }

    normalizeMembership();
    object.attributes.insert(QStringLiteral("uSNChanged"), QString::number(nextUsn()));
    object.attributes.insert(QStringLiteral("whenChanged"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    ensureRootDse();
    return 0;
}

bool LdapServer::setTlsCredentials(const QByteArray &certificatePem, const QByteArray &keyPem,
                                   QString *error) {
    const QSslCertificate certificate(certificatePem, QSsl::Pem);
    if (certificate.isNull()) {
        if (error) *error = QStringLiteral("the certificate is not readable PEM");
        return false;
    }
    // An unencrypted PKCS#8 key is what the provisioner writes; RSA is tried
    // first because that is what it generates.
    QSslKey key(keyPem, QSsl::Rsa, QSsl::Pem);
    if (key.isNull())
        key = QSslKey(keyPem, QSsl::Ec, QSsl::Pem);
    if (key.isNull()) {
        if (error) *error = QStringLiteral("the private key is not readable PEM");
        return false;
    }
    m_tlsCertificate = certificate;
    m_tlsKey = key;
    m_tlsAvailable = true;
    return true;
}

bool LdapServer::loadTlsCredentials(const QString &certPath, const QString &keyPath,
                                    QString *error) {
    QFile certFile(certPath);
    if (!certFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("cannot read %1").arg(certPath);
        return false;
    }
    QFile keyFile(keyPath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("cannot read %1").arg(keyPath);
        return false;
    }
    return setTlsCredentials(certFile.readAll(), keyFile.readAll(), error);
}

void LdapServer::adoptDescriptor(qintptr descriptor) {
    auto *sock = new QSslSocket(this);
    if (!sock->setSocketDescriptor(descriptor, QAbstractSocket::ConnectedState,
                                   QIODevice::ReadWrite)) {
        delete sock;
        return;
    }
    // A dev DC has no client-certificate PKI, so the peer is not verified; the
    // certificate is what the *client* checks.
    sock->setPeerVerifyMode(QSslSocket::VerifyNone);
    if (m_tlsAvailable) {
        sock->setLocalCertificate(m_tlsCertificate);
        sock->setPrivateKey(m_tlsKey);
    }
    handleConnection(sock);
}

void LdapServer::handleConnection(QSslSocket *sock) {
    auto *st = new ClientState();
    st->socket = sock;
    m_clients.append(st);
    connect(sock, &QSslSocket::readyRead, this, &LdapServer::onReadyRead);
    connect(sock, &QSslSocket::disconnected, this, &LdapServer::onDisconnected);
    connect(sock, &QSslSocket::encrypted, this, &LdapServer::onEncrypted);
    connect(sock, &QSslSocket::sslErrors, this, &LdapServer::onSslErrors);
    emit clientConnected(sock->peerAddress().toString());
}

LdapServer::ClientState *LdapServer::stateFor(QAbstractSocket *socket) const {
    for (auto *c : m_clients)
        if (c->socket == socket)
            return c;
    return nullptr;
}

void LdapServer::resetSecurityContext(ClientState *st) {
    st->authenticatedDn.clear();
    st->ntlmChallenge.clear();
    st->saslStage = 0;
    st->gssClientDn.clear();
    st->gssSpnego = false;
    st->gssLayer = 1;
    st->gssKey.clear();
    st->gssEtype = 0;
    st->gssMaxBuf = 0;
    st->gssSendSeq = 0;
    st->gssRecvSeq = 0;
    st->gssRecvSeqSeen = false;
    st->gssBindResponse = false;
    st->ntlmLayer = 0;
    st->ntlmKeys = Ntlm::SessionKeys();
    st->ntlmSendSeq = 0;
    st->ntlmRecvSeq = 0;
    st->gssPac.clear();
    st->gssIdentity = Pac::Identity();
    st->gssHasIdentity = false;
}

void LdapServer::onEncrypted() {
    auto *sock = qobject_cast<QSslSocket *>(sender());
    if (!sock)
        return;
    ClientState *st = stateFor(sock);
    if (!st)
        return;
    st->tlsActive = true;
    st->tlsPending = false;
    emit requestReceived(QStringLiteral("StartTLS established: %1")
                             .arg(sock->sessionCipher().name()));
    // Whatever the client sent inside TLS may already be buffered.
    if (sock->bytesAvailable() > 0)
        pump(st, sock);
}

void LdapServer::onSslErrors(const QList<QSslError> &errors) {
    auto *sock = qobject_cast<QSslSocket *>(sender());
    if (!sock)
        return;
    for (const QSslError &error : errors)
        emit requestReceived(QStringLiteral("TLS: %1").arg(error.errorString()));
    // The handshake is aborted: a connection that cannot be encrypted must not
    // fall back to serving LDAP in the clear.
    sock->disconnectFromHost();
}

void LdapServer::onReadyRead() {
    auto *sock = qobject_cast<QSslSocket *>(sender());
    if (!sock) return;
    ClientState *st = stateFor(sock);
    if (!st) return;
    // While the handshake is in flight the bytes belong to TLS, not to LDAP.
    if (st->tlsPending) return;
    pump(st, sock);
}

void LdapServer::pump(ClientState *st, QSslSocket *sock) {
    if (saslLayerActive(st))
        st->raw.append(sock->readAll());
    else
        st->buffer.append(sock->readAll());

    // Process complete messages.
    while (true) {
        // With a GSS-API security layer active the wire carries length-prefixed
        // per-message tokens, so unwrap them into the LDAP byte stream first.
        // Doing this inside the loop also picks up bytes a client pipelined
        // behind the bind request that completed the negotiation.
        if (saslLayerActive(st) && !st->gssBindResponse) {
            if (!saslUnframe(st, &st->buffer)) {
                st->raw.clear();
                sock->disconnectFromHost();
                return;
            }
        }
        if (st->buffer.size() < 2) break;
        if ((unsigned char)st->buffer[0] != 0x30) { st->buffer.clear(); break; }
        int pos = 1;
        int lenBytes = 0, length = 0;
        unsigned char b = (unsigned char)st->buffer[pos++];
        lenBytes = 1;
        if (b >= 0x80) {
            int n = b & 0x7f;
            if (st->buffer.size() < 1 + n) break;
            for (int i = 0; i < n; i++) length = (length << 8) | (unsigned char)st->buffer[pos++];
            lenBytes = 1 + n;
        } else {
            length = b;
        }
        int total = 1 + lenBytes + length;
        if (st->buffer.size() < total) break;
        QByteArray msg = st->buffer.left(total);
        st->buffer.remove(0, total);
        // An UnbindRequest disconnects synchronously, which frees `st` from
        // onDisconnected(); nothing may read it after that. processMessage()
        // reports the close so the loop stops on a state that still exists.
        if (!processMessage(st, msg))
            return;
    }
}

void LdapServer::onDisconnected() {
    auto *sock = qobject_cast<QSslSocket *>(sender());
    if (!sock)
        return;
    for (int i = 0; i < m_clients.size();) {
        if (m_clients[i]->socket == sock) {
            delete m_clients[i];
            m_clients.removeAt(i);
        } else {
            ++i;
        }
    }
    sock->deleteLater();
}

// Returns false when the message closed the connection: `st` is freed by
// onDisconnected() during the call and must not be touched again.
bool LdapServer::processMessage(ClientState *st, const QByteArray &msg) {
    int pos = 0;
    int tag = readTag(msg, pos);
    if (tag != 0x30) return true;
    int len = readLength(msg, pos);
    Q_UNUSED(len)
    int msgId = readInt(msg, pos);
    int opTag = readTag(msg, pos);
    int opLen = readLength(msg, pos);
    int opStart = pos;
    QByteArray opContent = msg.mid(opStart, opLen);
    pos = opStart + opLen;
    const QList<Control> controls = parseControls(msg, pos);
    // RFC 4511 §4.1.11: a control the server does not implement must be refused
    // when the client marks it critical; optional unknown ones are ignored.
    for (const Control &control : controls) {
        if (control.criticality && control.oid != QLatin1String(kPagedResultsOid)
            && control.oid != QLatin1String(kPermissiveModifyOid)) {
            const int responseTag = opTag == 0x60 ? 0x61
                                    : opTag == 0x63 ? 0x65
                                    : opTag == 0x66 ? 0x67
                                    : opTag == 0x68 ? 0x69
                                    : opTag == 0x4a ? 0x6b
                                    : opTag == 0x6c ? 0x6d
                                    : opTag == 0x6e ? 0x6f
                                                    : 0x78;
            emit requestReceived(QStringLiteral("Control %1 refused (unavailableCriticalExtension)")
                                     .arg(control.oid));
            if (st->socket)
                st->socket->write(makeLdapResult(msgId, responseTag, 12));
            return true;
        }
    }

    // Writes over a Kerberos session are authorized from the ticket's PAC.
    const bool writeOp = opTag == 0x66 || opTag == 0x68 || opTag == 0x4a || opTag == 0x6c;
    if (writeOp && !allowsWrite(st)) {
        const int responseTag = opTag == 0x66 ? 0x67
                                : opTag == 0x68 ? 0x69
                                : opTag == 0x4a ? 0x6b
                                                : 0x6d;
        const QByteArray denied = makeLdapResult(msgId, responseTag, 50);
        emit requestReceived(QStringLiteral("Write refused: the PAC has no administrative group"));
        if (st->socket) {
            if (saslLayerActive(st))
                st->socket->write(saslFrame(st, denied));
            else
                st->socket->write(denied);
        }
        return true;
    }

    // Captured up front: a request can make the connection go away, and with it
    // this client state, so the socket must not be reached through `st` later.
    QSslSocket *socket = st->socket;
    bool startTls = false;

    QByteArray response;
    if (opTag == 0x60) { // BindRequest
        response = handleBind(st, msgId, opContent);
    } else if (opTag == 0x63) { // SearchRequest
        response = handleSearch(st, msgId, opContent, controls);
    } else if (opTag == 0x66) { // ModifyRequest
        response = handleModify(msgId, opContent);
    } else if (opTag == 0x68) { // AddRequest
        response = handleAdd(msgId, opContent);
    } else if (opTag == 0x4a) { // DelRequest
        response = handleDelete(msgId, opContent);
    } else if (opTag == 0x6c) { // ModifyDNRequest
        response = handleModifyDn(msgId, opContent);
    } else if (opTag == 0x6e) { // CompareRequest
        response = handleCompare(msgId, opContent);
    } else if (opTag == 0x77) { // ExtendedRequest
        response = handleExtended(st, msgId, opContent, &startTls);
    } else if (opTag == 0x50) { // AbandonRequest
        // no response
        response.clear();
    } else if (opTag == 0x42) { // UnbindRequest
        // The close is synchronous here: onDisconnected() deletes `st` before
        // this returns, so the caller must stop instead of re-reading it.
        socket->disconnectFromHost();
        return false;
    } else {
        response = makeLdapResult(msgId, 0x65, 2); // protocolError via search done-ish; fallback
    }
    if (!response.isEmpty() && socket) {
        // The bind response that completes the SASL negotiation is the last
        // plaintext PDU; everything after it travels through the layer.
        if (saslLayerActive(st) && !st->gssBindResponse)
            socket->write(saslFrame(st, response));
        else
            socket->write(response);
        st->gssBindResponse = false;
    }

    if (startTls && socket) {
        // The success response is already queued in plaintext; the handshake
        // follows it on the same socket. Nothing negotiated before the upgrade
        // survives it, and no plaintext may follow the response.
        resetSecurityContext(st);
        st->buffer.clear();
        st->raw.clear();
        st->tlsPending = true;
        socket->flush();
        socket->startServerEncryption();
    }
    return true;
}

QByteArray LdapServer::handleBind(ClientState *st, int msgId, const QByteArray &payload) {
    // payload: version, name, authentication
    int pos = 0;
    int version = readInt(payload, pos);
    Q_UNUSED(version)
    QString name = readString(payload, pos);
    // authentication: [0] simple, [3] SASL
    int tag = readTag(payload, pos);
    int len = readLength(payload, pos);
    QByteArray password;
    if (tag >= 0 && len >= 0 && pos + len <= payload.size())
        password = payload.mid(pos, len);

    // SASL { mechanism, credentials } is a SEQUENCE, so a client encodes it as
    // [3] *constructed* — 0xA3 — and only a loose encoder writes the primitive
    // 0x83 this server used to require. Accepting one form and not the other is
    // what made `net ads join`'s LDAP bind fail as "Invalid credentials": the
    // SASL request fell through to the simple-bind path with the mechanism name
    // as the DN.
    if (tag == 0xA3 || tag == 0x83)
        return handleSaslBind(st, msgId, password);

    emit requestReceived(QStringLiteral("Bind"));

    // A bind replaces the connection's identity even when it fails: RFC 4513
    // §5.1.1 leaves a connection anonymous after a failed or anonymous bind, so
    // a session that authenticated and then re-binds must not keep its right to
    // read. Clear before verification and record the DN only on success.
    st->authenticatedDn.clear();

    // Without any stored secret every bind succeeds (the console's sample
    // directory). Once a password exists — on the object itself or in the
    // provisioned secrets — simple binds are verified against its verifier.
    // AD takes three bind names for an account and only the first is a DN;
    // resolving the other two here leaves one form to compare below.
    const QString bindName = resolveBindName(name);
    const bool anonymous = name.isEmpty() && password.isEmpty();
    if (!anonymous) {
        QByteArray salt;
        QByteArray hash;
        QByteArray ntHashHex;
        QString logonHours;
        qint64 pwdLastSet = 0;
        bool haveVerifier = false;
        bool anyVerifier = !m_credentials.isEmpty();
        quint32 accountControl = 0;
        for (const DirectoryObject &object : m_objects) {
            const QString objectSalt =
                object.attributes.value(QStringLiteral("userPasswordSalt"));
            const QString objectHash =
                object.attributes.value(QStringLiteral("userPasswordHash"));
            const QString objectNtHash = object.attributes.value(QStringLiteral("ntHash"));
            const bool stored =
                (!objectSalt.isEmpty() && !objectHash.isEmpty()) || !objectNtHash.isEmpty();
            if (stored)
                anyVerifier = true;
            if (stored && object.id.compare(bindName, Qt::CaseInsensitive) == 0) {
                salt = objectSalt.toLatin1();
                hash = objectHash.toLatin1();
                ntHashHex = objectNtHash.toLatin1();
                accountControl =
                    object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                logonHours = object.attributes.value(QStringLiteral("logonHours"));
                pwdLastSet =
                    object.attributes.value(QStringLiteral("pwdLastSet")).toLongLong();
                haveVerifier = true;
            }
        }
        if (!haveVerifier) {
            const auto it = m_credentials.constFind(bindName.toLower());
            if (it != m_credentials.constEnd()) {
                salt = it->salt;
                hash = it->hash;
                haveVerifier = true;
            }
        }
        if (anyVerifier && !haveVerifier)
            return makeBindResponse(msgId, 49); // invalidCredentials
        if (!salt.isEmpty() && !hash.isEmpty()) {
            if (saltedPasswordHash(salt, QString::fromUtf8(password)) != hash)
                return makeBindResponse(msgId, 49);
        } else if (!ntHashHex.isEmpty()) {
            // Accounts written with only the AD credential (NT hash) still bind.
            if (Ntlm::ntowfV1(QString::fromUtf8(password)).toHex() != ntHashHex)
                return makeBindResponse(msgId, 49);
        }
        // A disabled account may not authenticate, whatever its password.
        if (haveVerifier && (accountControl & 0x2u)) // ACCOUNTDISABLE
            return makeBindResponse(msgId, 49);
        // Nor may an account outside its logonHours. Checked after the password
        // so a refused hour is indistinguishable from a wrong password.
        if (haveVerifier
            && !LogonHours::allowsHex(logonHours, QDateTime::currentDateTimeUtc()))
            return makeBindResponse(msgId, 49);
        // An expired password is refused the same way, for the same reason: the
        // client proved it knows the password, and only then learns it may not
        // log on with it. AD answers 49 here too, with the must-change data.
        if (haveVerifier
            && PasswordAge::state(pwdLastSet, accountControl, passwordPolicy().maxAge)
                   != PasswordAge::State::Valid)
            return makeBindResponse(msgId, 49);
    }
    if (!name.isEmpty())
        st->authenticatedDn = bindName;
    return makeBindResponse(msgId, 0); // success
}

QString LdapServer::resolveBindName(const QString &name) const
{
    // `CN=Administrator,CN=Users,DC=…` is already the form the verifier lookup
    // uses. `user@dns-domain` (UPN) and `DOMAIN\user` are the two names a
    // Windows client may send instead, and neither matches an entry id, so an
    // account that binds fine by DN was refused with invalidCredentials.
    if (name.contains(QLatin1Char('=')))
        return name;
    const QString lookup = name.trimmed();
    if (lookup.isEmpty())
        return name;
    const int slash = lookup.indexOf(QLatin1Char('\\'));
    const int at = lookup.indexOf(QLatin1Char('@'));
    for (const DirectoryObject &object : m_objects) {
        const QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
        if (account.isEmpty())
            continue;
        // The UPN the account carries is authoritative, so a domain with a
        // renamed UPN suffix still binds by the name it published.
        const QString upn = object.attributes.value(QStringLiteral("userPrincipalName"));
        if (!upn.isEmpty() && upn.compare(lookup, Qt::CaseInsensitive) == 0)
            return object.id;
        if (slash > 0 && slash + 1 < lookup.size()) {
            const QString domain = lookup.left(slash);
            if ((!m_identity.netbios.isEmpty()
                 && domain.compare(m_identity.netbios, Qt::CaseInsensitive) == 0)
                || (!m_identity.dnsDomain.isEmpty()
                    && domain.compare(m_identity.dnsDomain, Qt::CaseInsensitive) == 0)) {
                if (account.compare(lookup.mid(slash + 1), Qt::CaseInsensitive) == 0)
                    return object.id;
            }
        }
        if (at > 0 && at + 1 < lookup.size()) {
            const QString domain = lookup.mid(at + 1);
            if (!m_identity.dnsDomain.isEmpty()
                && domain.compare(m_identity.dnsDomain, Qt::CaseInsensitive) == 0
                && account.compare(lookup.left(at), Qt::CaseInsensitive) == 0)
                return object.id;
        }
    }
    return name;
}

QString LdapServer::ntlmDomainName() const
{
    for (const DirectoryObject &object : m_objects) {
        if (object.kind != ObjectKind::Domain)
            continue;
        const QString dc = object.attributes.value(QStringLiteral("dc"));
        if (!dc.isEmpty())
            return dc.toUpper();
        if (!object.name.isEmpty())
            return object.name.toUpper();
    }
    return QStringLiteral("MONARCHY");
}

QString LdapServer::ntlmServerName() const
{
    for (const DirectoryObject &object : m_objects) {
        if (object.attributes.value(QStringLiteral("isDomainController")).compare(
                QLatin1String("yes"), Qt::CaseInsensitive) != 0)
            continue;
        const QString host = object.attributes.value(QStringLiteral("dNSHostName"));
        if (!host.isEmpty())
            return host.section(QLatin1Char('.'), 0, 0).toUpper();
        if (!object.name.isEmpty())
            return object.name.toUpper();
    }
    return QStringLiteral("MONARCHYDC1");
}

QByteArray LdapServer::handleSaslBind(ClientState *st, int msgId, const QByteArray &payload)
{
    // SaslCredentials is implicitly tagged [3], so its contents start directly
    // with the mechanism; an explicit SEQUENCE wrapper is tolerated as well.
    int pos = 0;
    if (readTag(payload, pos) == 0x30) {
        const int len = readLength(payload, pos);
        if (len < 0 || pos + len > payload.size())
            return makeBindResponse(msgId, 2); // protocolError
    } else {
        pos = 0;
    }

    const QString mechanism = readString(payload, pos);
    const int credTag = readTag(payload, pos);
    const int credLen = readLength(payload, pos);
    QByteArray credentials;
    Q_UNUSED(credTag)
    if (credLen >= 0 && pos + credLen <= payload.size())
        credentials = payload.mid(pos, credLen);

    emit requestReceived(QStringLiteral("SASL bind: %1").arg(mechanism));

    if (mechanism.compare(QLatin1String("GSSAPI"), Qt::CaseInsensitive) == 0) {
        return handleGssapiBind(st, msgId, credentials, false);
    }

    // NTLM is what AD uses for password authentication without Kerberos, and
    // GSS-SPNEGO carries either NTLM or a Kerberos AP-REQ wrapped in ASN.1.
    if (mechanism.compare(QLatin1String("NTLM"), Qt::CaseInsensitive) != 0
        && mechanism.compare(QLatin1String("GSS-SPNEGO"), Qt::CaseInsensitive) != 0)
        return makeBindResponse(msgId, 7); // authMethodNotSupported

    const bool spnego = mechanism.compare(QLatin1String("GSS-SPNEGO"),
                                          Qt::CaseInsensitive) == 0;
    // Once a Kerberos context is in progress the follow-up tokens are the
    // security-layer exchange, not new SPNEGO negotiations.
    if (spnego && (st->saslStage != 0 || Gss::carriesKerberos(credentials))) {
        return handleGssapiBind(st, msgId, credentials, true);
    }

    st->ntlmSpnego = spnego;
    const QByteArray token = Ntlm::embeddedToken(credentials);
    const int type = Ntlm::messageType(token);

    if (type == 1) { // NEGOTIATE -> CHALLENGE
        st->ntlmChallenge = QByteArray(8, '\0');
        for (int i = 0; i < 8; ++i)
            st->ntlmChallenge[i] = char(QRandomGenerator::system()->generate() & 0xff);
        const QByteArray challenge = Ntlm::challengeToken(
            st->ntlmChallenge, ntlmDomainName(), ntlmServerName());
        // A GSS-SPNEGO negotiation takes its answers as NegTokenResp tokens: a
        // bare NTLMSSP CHALLENGE here is not a SPNEGO message at all, and
        // Samba's client stops the whole bind on it with `Invalid SPNEGO
        // request` followed by NT_STATUS_INVALID_PARAMETER. The mechanism was
        // settled by the NegTokenInit, so supportedMech is not repeated.
        const QByteArray reply = spnego
                                     ? Gss::spnegoResponse(1, QString(), challenge)
                                     : challenge;
        return makeBindResponse(msgId, 14, reply); // saslBindInProgress
    }

    if (type == 3) { // AUTHENTICATE
        if (st->ntlmChallenge.isEmpty())
            return makeBindResponse(msgId, 2);
        const QByteArray challenge = st->ntlmChallenge;
        st->ntlmChallenge.clear();

        Ntlm::Authenticate authenticate;
        if (!Ntlm::parseAuthenticate(token, &authenticate))
            return makeBindResponse(msgId, 2);

        for (const DirectoryObject &object : m_objects) {
            const QString account = object.attributes.value(QStringLiteral("sAMAccountName"));
            const bool matches = account.compare(authenticate.user, Qt::CaseInsensitive) == 0
                                 || object.name.compare(authenticate.user, Qt::CaseInsensitive) == 0;
            if (!matches || object.id.isEmpty())
                continue;

            const quint32 uac =
                object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
            if (uac & 0x2u) // ACCOUNTDISABLE
                return makeBindResponse(msgId, 49);

            const QByteArray ntHash = QByteArray::fromHex(
                object.attributes.value(QStringLiteral("ntHash")).toLatin1());
            if (ntHash.size() != 16)
                return makeBindResponse(msgId, 49);

            // NTLMv1 is answered only when the domain's policy allows it (AD's
            // LmCompatibilityLevel 0-2); the keys come with the verification.
            Ntlm::SessionKeys keys;
            if (!Ntlm::verifyResponse(ntHash, authenticate.user, authenticate.domain, challenge,
                                      authenticate.ntResponse, authenticate.lmResponse,
                                      authenticate.flags, m_lmCompatibilityLevel, &keys))
                return makeBindResponse(msgId, 49);

            if (!LogonHours::allowsHex(
                    object.attributes.value(QStringLiteral("logonHours")),
                    QDateTime::currentDateTimeUtc()))
                return makeBindResponse(msgId, 49);

            // The password proved itself; an account whose credential has aged
            // out or must be changed is still refused a session.
            if (PasswordAge::stateFor(object, m_objects) != PasswordAge::State::Valid)
                return makeBindResponse(msgId, 49);

            // MS-NLMP §3.4: the session base key comes from the proof string,
            // and the per-direction keys are derived from it. A client that
            // asked for sign or seal gets a security layer for the rest of the
            // session; sealing implies signing.
            st->ntlmKeys = keys;

            const quint32 agreed = authenticate.flags
                                   & (Ntlm::kNegotiateSign | Ntlm::kNegotiateSeal);
            if (agreed & Ntlm::kNegotiateSeal) {
                st->ntlmLayer = 0x04;
                st->ntlmSendSealer.reset(keys.serverSealingKey);
                st->ntlmRecvSealer.reset(keys.clientSealingKey);
            } else if (agreed & Ntlm::kNegotiateSign) {
                st->ntlmLayer = 0x02;
            }

            st->authenticatedDn = object.id;
            emit requestReceived(QStringLiteral("NTLM authentication: %1%2")
                                     .arg(object.id)
                                     .arg(st->ntlmLayer == 0x04
                                              ? QStringLiteral(" (sealed)")
                                              : st->ntlmLayer == 0x02
                                                    ? QStringLiteral(" (signed)")
                                                    : QString()));
            if (st->ntlmLayer != 0) {
                // The bind response that completes the negotiation is the last
                // plaintext PDU; anything the client pipelined behind it is
                // already wrapped.
                st->gssBindResponse = true;
                if (!st->buffer.isEmpty()) {
                    st->raw.prepend(st->buffer);
                    st->buffer.clear();
                }
            }
            // RFC 4178 §4.2.2: a GSS-SPNEGO exchange ends with a NegTokenResp
            // whose negState is accept-completed, even when it carries no
            // token of its own.
            if (st->ntlmSpnego) {
                st->ntlmSpnego = false;
                return makeBindResponse(msgId, 0, Gss::spnegoResponse(0, QString(), QByteArray()));
            }
            return makeBindResponse(msgId, 0);
        }
        return makeBindResponse(msgId, 49);
    }

    return makeBindResponse(msgId, 2); // protocolError
}

QByteArray LdapServer::handleGssapiBind(ClientState *st, int msgId,
                                        const QByteArray &credentials, bool spnego)
{
    if (!m_kdc)
        return makeBindResponse(msgId, 7); // no Kerberos acceptor configured

    if (st->saslStage == 0) {
        QByteArray token = credentials;
        if (spnego) {
            token = Gss::kerberosToken(credentials);
            if (token.isEmpty())
                return makeBindResponse(msgId, 49);
        }
        if (token.isEmpty())
            return makeBindResponse(msgId, 2);

        Kdc::ApResult result;
        QString error;
        if (!m_kdc->acceptApReq(token, &result, &error)) {
            emit requestReceived(QStringLiteral("Kerberos bind rejected: %1").arg(error));
            return makeBindResponse(msgId, 49); // invalidCredentials
        }
        st->saslStage = 1;
        st->gssClientDn = result.clientDn;
        st->gssSpnego = spnego;
        st->gssKey = result.contextKey;
        st->gssEtype = result.contextEtype;
        st->gssPac = result.pac;
        st->gssSendSeq = 0;
        st->gssRecvSeq = 0;
        emit requestReceived(QStringLiteral("Kerberos authentication: %1 (%2)")
                                 .arg(result.clientPrincipal, result.servicePrincipal));
        // GSS-SPNEGO carries a bare NegTokenResp; only the GSSAPI mechanism wraps
        // its token in the 0x60 InitialContextToken, and a client that offered
        // GSS-SPNEGO reads a 0x60 as a second negTokenInit — Samba answered
        // NT_STATUS_INVALID_PARAMETER for the whole bind on exactly that.
        const QByteArray reply = spnego
                                     ? Gss::spnegoResponse(0, QString(), result.replyToken)
                                     : result.replyToken;
        return makeBindResponse(msgId, 14, reply); // saslBindInProgress
    }

    // GSS-SPNEGO has no RFC 4752 step: the negotiated mechanism's own layer is
    // the SASL layer, so a client that completes with an empty token has already
    // said everything and seals the very next PDU. Samba's net ads join is such
    // a client — it answers the AP-REP with an empty GSS-SPNEGO bind and then
    // sends `05 04 02 ..` wrapped LDAP — and answering it with the RFC 4752
    // offer made it read four raw bytes as a GSS token.
    if (spnego && st->saslStage == 1 && credentials.isEmpty()) {
        st->gssLayer = 0x04; // the layer Kerberos provides: confidentiality
        st->gssMaxBuf = 0;
        return completeGssBind(st, msgId, st->gssLayer, false);
    }

    // RFC 4752 §3.1 has the client name the layer it wants; there is no server
    // offer in between. A client that sends an empty token at this point wants no
    // layer, which is what a Windows DC answers with.
    QByteArray selection = credentials;
    if (st->saslStage == 1) {
        if (selection.isEmpty())
            selection = QByteArray("\x01\x00\x00\x00", 4); // no layer
        if (selection.size() < 4)
            return makeBindResponse(msgId, 2);
        st->saslStage = 2;
    }

    if (st->saslStage == 2) {
        if (selection.size() < 4)
            return makeBindResponse(msgId, 2);

        // The client picks one layer and advertises the largest buffer it will
        // accept, then proves the choice by wrapping the authorization id with
        // the freshly negotiated context.
        const int layer = quint8(selection.at(0));
        if (layer != 0x01 && layer != 0x02 && layer != 0x04) {
            st->saslStage = 0;
            return makeBindResponse(msgId, 7); // authMethodNotSupported
        }
        st->gssLayer = layer;
        st->gssMaxBuf = (quint32(quint8(selection.at(1))) << 16)
                        | (quint32(quint8(selection.at(2))) << 8)
                        | quint32(quint8(selection.at(3)));

        if (layer != 0x01) {
            QByteArray authorizationId;
            if (selection.size() <= 4
                || !gssUnwrap(st, selection.mid(4), &authorizationId)) {
                emit requestReceived(QStringLiteral("GSSAPI layer token rejected"));
                st->saslStage = 0;
                st->gssLayer = 1;
                return makeBindResponse(msgId, 49);
            }
        }

        return completeGssBind(st, msgId, layer, layer != 0x01);
    }

    return makeBindResponse(msgId, 2);
}

bool LdapServer::allowsWrite(const ClientState *st) const
{
    if (!st->gssHasIdentity)
        return true;
    // 512 Domain Admins, 518 Schema Admins, 519 Enterprise Admins.
    return st->gssIdentity.isMemberOf(512) || st->gssIdentity.isMemberOf(518)
           || st->gssIdentity.isMemberOf(519);
}

QByteArray LdapServer::gssWrap(ClientState *st, const QByteArray &data, bool conf)
{
    if (st->gssKey.isEmpty() || st->gssEtype == 0)
        return {};

    QByteArray token;
    if (st->gssEtype == Krb5::kRc4Hmac) {
        // The legacy format carries the mechanism OID; the RFC 4121 tokens used
        // by the AES enctypes do not, because the mechanism is already fixed.
        QByteArray body;
        body.append(Gss::kLegacyWrapTokenId);
        body.append(Gss::legacyWrapToken(data, conf, st->gssSendSeq, st->gssKey));
        token = Gss::gssEnvelope(body);
    } else {
        token = Gss::cfxWrapToken(data, conf, st->gssSendSeq, st->gssEtype, st->gssKey);
    }
    ++st->gssSendSeq;
    return token;
}

bool LdapServer::gssUnwrap(ClientState *st, const QByteArray &token, QByteArray *data)
{
    QByteArray inner = token;
    if (st->gssKey.isEmpty())
        return false;
    // Both forms occur: RFC 1964 tokens carry the mechanism OID header, while
    // the CFX tokens MIT and Windows send do not.
    if (token.size() >= 2 && quint8(token[0]) == 0x60) {
        if (!Gss::stripGssEnvelope(token, &inner))
            return false;
    }
    if (inner.size() < 2)
        return false;

    quint64 seq = 0;
    bool ok = false;
    if (inner.startsWith(Gss::kLegacyWrapTokenId))
        ok = Gss::legacyUnwrapToken(inner.mid(2), data, st->gssKey, &seq);
    else if (inner.startsWith(Gss::kCfxWrapTokenId))
        ok = Gss::cfxUnwrapToken(inner, data, st->gssEtype, st->gssKey, &seq);
    if (!ok)
        return false;
    // The first token fixes the sequence base: MIT and Windows start from a
    // random number, not zero. Every later token must follow it in order.
    if (!st->gssRecvSeqSeen) {
        st->gssRecvSeq = seq;
        st->gssRecvSeqSeen = true;
    } else if (seq != st->gssRecvSeq) {
        return false;
    }
    ++st->gssRecvSeq;
    return true;
}

QByteArray LdapServer::gssFrame(ClientState *st, const QByteArray &data)
{
    const bool conf = st->gssLayer == 0x04;
    const int limit = st->gssMaxBuf > 0 ? int(qMin<quint32>(st->gssMaxBuf, 65535)) : 65535;
    QByteArray out;
    for (int offset = 0; offset < data.size();) {
        const int length = qMin(limit, data.size() - offset);
        const QByteArray token = gssWrap(st, data.mid(offset, length), conf);
        if (token.isEmpty())
            return data; // no context key: fall back to plaintext
        appendBe32(out, quint32(token.size()));
        out.append(token);
        offset += length;
    }
    return out;
}

bool LdapServer::gssUnframe(ClientState *st, QByteArray *out)
{
    while (st->raw.size() >= 4) {
        const quint32 length = readBe32(st->raw, 0);
        if (length == 0 || length > 16 * 1024 * 1024)
            return false;
        if (st->raw.size() < 4 + int(length))
            return true; // wait for the rest of the token
        const QByteArray token = st->raw.mid(4, int(length));
        st->raw.remove(0, 4 + int(length));
        QByteArray plain;
        if (!gssUnwrap(st, token, &plain))
            return false;
        out->append(plain);
    }
    return true;
}

QByteArray LdapServer::ntlmWrap(ClientState *st, const QByteArray &data, bool conf)
{
    if (st->ntlmLayer == 0)
        return {};
    const quint32 seq = st->ntlmSendSeq++;
    if (!conf)
        return Ntlm::signMessage(st->ntlmKeys.serverSigningKey, seq, data);
    return Ntlm::sealMessage(st->ntlmKeys.serverSealingKey, st->ntlmKeys.serverSigningKey,
                             &st->ntlmSendSealer, seq, data);
}

bool LdapServer::ntlmUnwrap(ClientState *st, const QByteArray &token, QByteArray *data)
{
    if (st->ntlmLayer == 0)
        return false;
    const bool sealed = st->ntlmLayer == 0x04;
    if (!Ntlm::unsealMessage(sealed ? st->ntlmKeys.clientSealingKey : QByteArray(),
                             st->ntlmKeys.clientSigningKey,
                             sealed ? &st->ntlmRecvSealer : nullptr,
                             st->ntlmRecvSeq, token, data))
        return false;
    ++st->ntlmRecvSeq;
    return true;
}

QByteArray LdapServer::saslFrame(ClientState *st, const QByteArray &data)
{
    if (st->ntlmLayer == 0)
        return gssFrame(st, data);

    // RFC 4422 §3.1: with a security layer in effect every message is sent as
    // a 4-octet length followed by the wrapped token.
    const bool conf = st->ntlmLayer == 0x04;
    QByteArray out;
    for (int offset = 0; offset < data.size();) {
        const int length = qMin(65535, data.size() - offset);
        const QByteArray token = ntlmWrap(st, data.mid(offset, length), conf);
        if (token.isEmpty())
            return data; // no session keys: fall back to plaintext
        appendBe32(out, quint32(token.size()));
        out.append(token);
        offset += length;
    }
    return out;
}

bool LdapServer::saslUnframe(ClientState *st, QByteArray *out)
{
    if (st->ntlmLayer == 0)
        return gssUnframe(st, out);

    while (st->raw.size() >= 4) {
        const quint32 length = readBe32(st->raw, 0);
        if (length == 0 || length > 16 * 1024 * 1024)
            return false;
        if (st->raw.size() < 4 + int(length))
            return true; // wait for the rest of the token
        const QByteArray token = st->raw.mid(4, int(length));
        st->raw.remove(0, 4 + int(length));
        QByteArray plain;
        if (!ntlmUnwrap(st, token, &plain))
            return false;
        out->append(plain);
    }
    return true;
}

QList<LdapServer::Control> LdapServer::parseControls(const QByteArray &message, int pos) const {
    QList<Control> controls;
    while (pos + 2 <= message.size()) {
        if ((unsigned char)message.at(pos) != 0xa0) // controls [0] constructed
            break;
        int p = pos + 1;
        int length = readLength(message, p);
        if (length < 0 || p + length > message.size())
            break;
        const int end = p + length;
        while (p < end) {
            if (readTag(message, p) != 0x30)
                break;
            int sequenceLength = readLength(message, p);
            if (sequenceLength < 0 || p + sequenceLength > end)
                break;
            const int sequenceEnd = p + sequenceLength;
            Control control;
            control.oid = readString(message, p);
            // criticality BOOLEAN DEFAULT FALSE
            if (p < sequenceEnd && (unsigned char)message.at(p) == 0x01) {
                readTag(message, p);
                const int booleanLength = readLength(message, p);
                control.criticality = booleanLength > 0 && message.at(p) != 0;
                p += qMax(0, booleanLength);
            }
            // controlValue OCTET STRING OPTIONAL
            if (p < sequenceEnd && (unsigned char)message.at(p) == 0x04) {
                readTag(message, p);
                const int valueLength = readLength(message, p);
                if (valueLength >= 0 && p + valueLength <= sequenceEnd)
                    control.value = message.mid(p, valueLength);
            }
            controls.append(control);
            p = sequenceEnd;
        }
        pos = end;
    }
    return controls;
}

QByteArray LdapServer::pagedResultsControl(int total, const QByteArray &cookie) const {
    // controlValue is the DER encoding of SEQUENCE { size INTEGER,
    // cookie OCTET STRING } (RFC 2696 §2), so the sequence tag is part of it.
    QByteArray inner;
    writeInt(inner, 0x02, total);
    writeTLV(inner, 0x04, cookie);
    QByteArray value;
    writeTLV(value, 0x30, inner);
    QByteArray control;
    writeString(control, 0x04, QString::fromLatin1(kPagedResultsOid));
    writeTLV(control, 0x04, value);
    QByteArray field;
    writeTLV(field, 0x30, control);
    return field;
}

QByteArray LdapServer::handleSearch(ClientState *st, int msgId, const QByteArray &payload,
                                    const QList<Control> &controls) {
    int pos = 0;
    int baseTag = 0;
    const QByteArray baseValue = readTLV(payload, pos, baseTag);
    int scope = 0;
    int deref = 0;
    int sizeLimit = 0;
    int timeLimit = 0;
    // RFC 4511 §4.5.1.1: baseObject, scope, derefAliases, sizeLimit, timeLimit,
    // typesOnly and filter are all required, and in that order. Reading them
    // positionally without checking tags let a request that omitted four of
    // them pass the filter's presence value to the integer reader and still
    // "recover" — the sort of accidental success /TESTING.md exists to name.
    bool fieldsOk = baseTag == 0x04
                    && readIntField(payload, pos, 0x0A, &scope)
                    && readIntField(payload, pos, 0x0A, &deref)
                    && readIntField(payload, pos, 0x02, &sizeLimit)
                    && readIntField(payload, pos, 0x02, &timeLimit);
    int typesTag = 0;
    const QByteArray typesValue = readTLV(payload, pos, typesTag);
    fieldsOk = fieldsOk && typesTag == 0x01 && typesValue.size() == 1;
    if (!fieldsOk || scope < 0 || scope > 2 || deref < 0 || deref > 3
        || (typesValue.at(0) & 0xFE) != 0)
        return makeSearchDone(msgId, 2); // protocolError

    const QString base = QString::fromUtf8(baseValue);
    Q_UNUSED(deref)
    Q_UNUSED(sizeLimit)
    Q_UNUSED(timeLimit)

    // filter: [0] and/ [1] or / [2] not / [3] equalityMatch / [4] substrings /
    // [5] greaterOrEqual / [6] lessOrEqual / [7] present / [8] approxMatch /
    // [9] extensibleMatch.
    int filterTag = 0;
    int filterStart = pos;
    readTLV(payload, filterStart, filterTag);
    const bool filterOk = (filterTag == 0x87 || (filterTag >= 0xA0 && filterTag <= 0xA9))
                          && filterStart > pos;
    if (!filterOk)
        return makeSearchDone(msgId, 2);
    Pred pred = parseFilter(payload, pos);

    // attributes SEQUENCE OF OCTET STRING
    int stag = 0;
    const QByteArray attrBytes = readTLV(payload, pos, stag);
    if (stag != 0x30)
        return makeSearchDone(msgId, 2);
    int apos = 0;
    QStringList attrs;
    while (apos < attrBytes.size()) {
        int atag = 0;
        const int before = apos;
        const QByteArray name = readTLV(attrBytes, apos, atag);
        if (atag != 0x04 || apos <= before)
            return makeSearchDone(msgId, 2);
        attrs.append(QString::fromUtf8(name));
    }
    if (pos != payload.size())
        return makeSearchDone(msgId, 2);

    emit requestReceived(QStringLiteral("Search: %1").arg(base));

    const QString searchBase = base.trimmed();

    // Anonymous sessions may read the root DSE and nothing else. A connection
    // that never bound — or whose bind was reset by StartTLS or replaced by a
    // failed re-bind — has no identity, and a non-empty base is a directory
    // read. Answer 50 insufficientAccessRights rather than an empty success, so
    // "you may not see it" is distinguishable from "it has no children".
    //
    // This check sits before the base-existence guard on purpose: an
    // unauthenticated caller that got 32 for a missing DN and 50 for an
    // existing one could use search to enumerate the directory, which is the
    // exposure this closes. The empty base is the root DSE (RFC 4512 §5.1) and
    // stays answerable, which is how a client discovers the naming context
    // before it has credentials.
    if (!searchBase.isEmpty() && st->authenticatedDn.isEmpty())
        return makeSearchDone(msgId, 50); // insufficientAccessRights

    // RFC 4511 §4.5.1: a base that names no entry is noSuchObject, not an empty
    // success. Without this, "you may not see it", "it is not there" and "it has
    // no children" are all the same answer, and a client validating a DN — a
    // referral chase, a FSMO owner, a replication target — is told yes when the
    // answer is no. Modify, modifyDN and compare already answer 32 for a missing
    // target; search was the only operation that did not.
    //
    // The empty base is the root DSE, which is synthesized rather than stored, so
    // it is never missing. The comparison is trimmed and case-insensitive
    // because that is how inScope() below matches it: a client that varies the
    // case or pads a valid DN must still find the entry.
    if (!searchBase.isEmpty()) {
        const QString lowerBase = searchBase.toLower();
        const QString childSuffix = QLatin1Char(',') + lowerBase;
        bool baseExists = false;
        for (const DirectoryObject &o : m_objects) {
            if (o.id.isEmpty())
                continue;
            const QString dn = o.id.toLower();
            // The entry itself, or an entry under it. A store can carry objects
            // beneath a naming context without materialising the context root
            // (the sample store does); inScope() already treats such a base as
            // the root of the subtree it serves, so refusing it here would turn
            // every search in that store into noSuchObject. A base with neither
            // an entry nor a descendant is genuinely absent.
            if (dn == lowerBase || dn.endsWith(childSuffix)) {
                baseExists = true;
                break;
            }
        }
        if (!baseExists)
            return makeSearchDone(msgId, 32); // noSuchObject
    }

    QList<DirectoryObject> matches;
    for (const DirectoryObject &o : m_objects) {
        if (!inScope(o, base, scope)) continue;
        if (!pred(o)) continue;
        matches.append(o);
    }

    const Control *paged = nullptr;
    for (const Control &control : controls) {
        if (control.oid == QLatin1String(kPagedResultsOid))
            paged = &control;
    }

    QByteArray out;
    if (!paged) {
        for (const DirectoryObject &o : matches)
            out.append(makeSearchEntry(msgId, o, attrs));
        out.append(makeSearchDone(msgId, 0));
        return out;
    }

    // controlValue ::= SEQUENCE { size INTEGER, cookie OCTET STRING }
    int pageSize = 0;
    QByteArray cookie;
    {
        int p = 0;
        // Skip the SEQUENCE the value is wrapped in; tolerate a client that
        // sends the two elements bare, which some do.
        int ptag = readTag(paged->value, p);
        int plen = readLength(paged->value, p);
        if (ptag != 0x30 || plen < 0)
            p = 0;
        pageSize = readInt(paged->value, p);
        if (readTag(paged->value, p) == 0x04) {
            const int cookieLength = readLength(paged->value, p);
            if (cookieLength >= 0 && p + cookieLength <= paged->value.size())
                cookie = paged->value.mid(p, cookieLength);
        }
    }
    if (pageSize < 0)
        pageSize = 0;

    if (!cookie.isEmpty()) {
        // A cookie this connection does not own is a client error, not a
        // silent restart: resuming someone else's page would repeat objects.
        if (cookie.size() != 12) {
            out.append(makeSearchDone(msgId, 53)); // unwillingToPerform
            return out;
        }
        const quint64 id = (quint64(readBe32(cookie, 0)) << 32) | readBe32(cookie, 4);
        const int offset = int(readBe32(cookie, 8));
        if (id != st->paged.id || offset != st->paged.offset
            || offset > st->paged.results.size()) {
            out.append(makeSearchDone(msgId, 53));
            return out;
        }
    } else {
        st->paged.id = m_nextPagedId++;
        st->paged.offset = 0;
        st->paged.results = matches;
        st->paged.attributes = attrs;
    }

    // RFC 2696 §3: size 0 with a cookie abandons the paged search.
    if (pageSize == 0) {
        st->paged = ClientState::PagedSearch();
        out.append(makeSearchDone(msgId, 0, pagedResultsControl(0, QByteArray())));
        return out;
    }

    const int total = st->paged.results.size();
    const int end = qMin(total, st->paged.offset + pageSize);
    for (int i = st->paged.offset; i < end; ++i)
        out.append(makeSearchEntry(msgId, st->paged.results.at(i), st->paged.attributes));

    QByteArray nextCookie;
    if (end < total) {
        appendBe32(nextCookie, quint32(st->paged.id >> 32));
        appendBe32(nextCookie, quint32(st->paged.id & 0xffffffffu));
        appendBe32(nextCookie, quint32(end));
        st->paged.offset = end;
    } else {
        // The client has the last page; it must not be able to page past it.
        st->paged = ClientState::PagedSearch();
    }
    out.append(makeSearchDone(msgId, 0, pagedResultsControl(total, nextCookie)));
    return out;
}

QByteArray LdapServer::handleModify(int msgId, const QByteArray &payload) {
    int pos = 0;
    QString dn = readString(payload, pos);
    // changes SEQUENCE OF
    int tag = readTag(payload, pos);
    int len = readLength(payload, pos);
    int end = pos + len;
    QList<ModifyChange> changes;
    while (pos < end) {
        // change: SEQUENCE { operation ENUMERATED, modification SEQUENCE { type, vals SET } }
        int ctag = readTag(payload, pos);
        int clen = readLength(payload, pos);
        int cend = pos + clen;
        ModifyChange change;
        change.operation = readInt(payload, pos); // add(0) / delete(1) / replace(2)
        int mtag = readTag(payload, pos);
        int mlen = readLength(payload, pos);
        int mend = pos + mlen;
        Q_UNUSED(mtag); Q_UNUSED(mlen)
        change.type = readString(payload, pos);
        // vals SET OF OCTET STRING: preserved as separate values so multi-valued
        // attributes such as `member` keep their entries.
        int vtag = readTag(payload, pos);
        int vlen = readLength(payload, pos);
        int vend = pos + vlen;
        Q_UNUSED(vtag); Q_UNUSED(vlen)
        while (pos < vend) {
            int t = readTag(payload, pos);
            int l = readLength(payload, pos);
            const QByteArray value = payload.mid(pos, l);
            pos += l;
            Q_UNUSED(t)
            change.values.append(QString::fromUtf8(value));
            if (change.rawValue.isNull())
                change.rawValue = value;
        }
        pos = mend;
        changes.append(change);
        pos = cend;
    }
    const int rcode = applyModify(dn, changes);
    emit requestReceived(QStringLiteral("Modify: %1").arg(dn));
    if (rcode == 0)
        persistNow();
    return makeLdapResult(msgId, 0x67, rcode);
}

QByteArray LdapServer::completeGssBind(ClientState *st, int msgId, int layer,
                                       bool wrapAuthorizationId)
{
    st->authenticatedDn = st->gssClientDn;
    st->saslStage = 0;
    st->gssClientDn.clear();
    // The verified PAC is the authority for what this session may do.
    st->gssHasIdentity = !st->gssPac.isEmpty()
                         && Pac::readIdentity(st->gssPac, &st->gssIdentity);
    st->gssPac.clear();
    if (st->authenticatedDn.isEmpty())
        return makeBindResponse(msgId, 49);

    // RFC 4752 has the server prove the layer by returning the wrapped
    // authorization id. GSS-SPNEGO has no such step: its layer is the one the
    // negotiated mechanism provides, so the bind simply succeeds and the next
    // PDU is already sealed.
    QByteArray replyCredentials;
    if (wrapAuthorizationId)
        replyCredentials = gssWrap(st, QByteArray(4, '\0'), layer == 0x04);
    st->gssBindResponse = !replyCredentials.isEmpty() || !wrapAuthorizationId;
    // Anything the client pipelined behind the bind request is already sealed,
    // so hand it to the framed decoder rather than the LDAP parser.
    if (layer != 0x01 && !st->buffer.isEmpty()) {
        st->raw.prepend(st->buffer);
        st->buffer.clear();
    }
    emit requestReceived(QStringLiteral("Kerberos bind: %1 (layer %2)")
                             .arg(st->authenticatedDn)
                             .arg(layer == 0x04 ? QStringLiteral("confidentiality")
                                  : layer == 0x02 ? QStringLiteral("integrity")
                                                  : QStringLiteral("none")));
    return makeBindResponse(msgId, 0, replyCredentials);
}

QByteArray LdapServer::handleAdd(int msgId, const QByteArray &payload) {
    int pos = 0;
    QString dn = readString(payload, pos);
    for (const DirectoryObject &existing : m_objects) {
        if (existing.id.compare(dn, Qt::CaseInsensitive) == 0)
            return makeLdapResult(msgId, 0x69, 68); // entryAlreadyExists
    }
    int tag = readTag(payload, pos);
    int len = readLength(payload, pos);
    int end = pos + len;
    Q_UNUSED(tag); Q_UNUSED(len)
    DirectoryObject obj;
    obj.id = dn;
    obj.name = dn.section(',', 0, 0).remove(0, 3);
    obj.type = QStringLiteral("Object");
    obj.kind = ObjectKind::Unknown;
    obj.container = QStringLiteral("Console Root");
    // attributes
    while (pos < end) {
        int atag = readTag(payload, pos);
        int alen = readLength(payload, pos);
        int aend = pos + alen;
        Q_UNUSED(atag); Q_UNUSED(alen)
        QString type = readString(payload, pos);
        int vtag = readTag(payload, pos);
        int vlen = readLength(payload, pos);
        int vend = pos + vlen;
        Q_UNUSED(vtag); Q_UNUSED(vlen)
        QString val;
        QByteArray rawValue;
        while (pos < vend) {
            int t = readTag(payload, pos);
            int l = readLength(payload, pos);
            QByteArray b = payload.mid(pos, l);
            pos += l;
            if (val.isEmpty()) val = QString::fromUtf8(b);
            if (rawValue.isNull()) rawValue = b;
            Q_UNUSED(t)
        }
        pos = aend;
        if (isServerOnlyAttribute(type))
            continue; // derived by the server, ignore a client's attempt
        if (isPasswordAttribute(type)) {
            // Never store the plaintext: keep a salted verifier instead.
            const QString password = decodePasswordValue(rawValue, val);
            QString reason;
            if (!passwordMeetsPolicy(password, &reason)) {
                emit requestReceived(QStringLiteral("Password rejected: %1").arg(reason));
                return makeLdapResult(msgId, 0x69, 19); // constraintViolation
            }
            storePasswordVerifier(obj, password,
                                  m_kdc ? m_kdc->realm().realm : QString(),
                                  passwordPolicy().historyLength);
            continue;
        }
        obj.attributes.insert(type, val);
        if (type.compare(QStringLiteral("cn"), Qt::CaseInsensitive) == 0) obj.name = val;
        if (type.compare(QStringLiteral("description"), Qt::CaseInsensitive) == 0) obj.description = val;
        if (type.compare(QStringLiteral("objectClass"), Qt::CaseInsensitive) == 0) {
            if (val.contains(QStringLiteral("user"), Qt::CaseInsensitive)) obj.kind = ObjectKind::User;
            else if (val.contains(QStringLiteral("group"), Qt::CaseInsensitive)) obj.kind = ObjectKind::Group;
            else if (val.contains(QStringLiteral("computer"), Qt::CaseInsensitive)) obj.kind = ObjectKind::Computer;
        }
    }
    // An entry with an account name is a security principal and needs its
    // objectSid, which is also the RID SAMR resolves names to. `addAccount`
    // allocates it from the domain SID; adding the object directly left the
    // machine account a `net ads join` creates invisible to SamrLookupNames,
    // and the join stopped on NT_STATUS_NONE_MAPPED.
    if (!obj.attributes.value(QStringLiteral("sAMAccountName")).isEmpty()
        && !domainSidPrefix().isEmpty()) {
        QString error;
        if (!addAccount(&obj, &error)) {
            emit requestReceived(QStringLiteral("Add refused: %1").arg(error));
            return makeLdapResult(msgId, 0x69, 68); // entryAlreadyExists
        }
    } else {
        addObject(obj);
    }
    emit requestReceived(QStringLiteral("Add: %1").arg(dn));
    persistNow();
    return makeLdapResult(msgId, 0x69, 0);
}

QByteArray LdapServer::handleDelete(int msgId, const QByteArray &payload) {
    // DelRequest is just an LDAPDN (OCTET STRING) as the op content.
    int pos = 0;
    QString dn;
    // payload may include tag 0x04
    if (pos < payload.size() && (unsigned char)payload[pos] == 0x04) {
        dn = readString(payload, pos);
    } else {
        dn = QString::fromUtf8(payload);
    }
    const bool removed = removeObject(dn);
    emit requestReceived(QStringLiteral("Delete: %1").arg(dn));
    if (removed)
        persistNow();
    return makeLdapResult(msgId, 0x4b, removed ? 0 : 32); // noSuchObject
}

QByteArray LdapServer::handleModifyDn(int msgId, const QByteArray &payload) {
    int pos = 0;
    QString entry = readString(payload, pos);
    QString newRdn = readString(payload, pos);
    // deleteOldRdn BOOLEAN
    int ttag = readTag(payload, pos);
    int tlen = readLength(payload, pos);
    Q_UNUSED(ttag); Q_UNUSED(tlen);
    if (tlen > 0) pos += tlen;
    // newSuperior (optional, context tag [0])
    QString newSuperior;
    if (pos < payload.size() && (unsigned char)payload[pos] == 0x80) {
        int tag = readTag(payload, pos);
        int len = readLength(payload, pos);
        Q_UNUSED(tag)
        newSuperior = QString::fromUtf8(payload.mid(pos, len));
        pos += len;
    }

    // Find entry.
    int idx = -1;
    for (int i = 0; i < m_objects.size(); i++) {
        if (m_objects[i].id.compare(entry, Qt::CaseInsensitive) == 0) { idx = i; break; }
    }
    if (idx < 0) return makeLdapResult(msgId, 0x6d, 32); // noSuchObject

    QString newDn;
    if (!newSuperior.isEmpty()) {
        newDn = newRdn + QStringLiteral(",") + newSuperior;
    } else {
        // replace RDN in existing DN
        QString oldDn = m_objects[idx].id;
        int comma = oldDn.indexOf(',');
        QString suffix = (comma >= 0) ? oldDn.mid(comma) : QString();
        newDn = newRdn + suffix;
    }

    m_objects[idx].id = newDn;
    m_objects[idx].name = newRdn.section('=', 1);
    m_objects[idx].attributes.insert(QStringLiteral("uSNChanged"), QString::number(nextUsn()));
    ensureRootDse();

    emit requestReceived(QStringLiteral("ModifyDN: %1 -> %2").arg(entry, newDn));
    persistNow();
    return makeLdapResult(msgId, 0x6d, 0);
}

QByteArray LdapServer::handleCompare(int msgId, const QByteArray &payload) {
    int pos = 0;
    QString entry = readString(payload, pos);
    // ava SEQUENCE { attributeDesc, assertionValue }
    int tag = readTag(payload, pos);
    int len = readLength(payload, pos);
    Q_UNUSED(tag); Q_UNUSED(len)
    QString attr = readString(payload, pos);
    QString val = readString(payload, pos);

    int idx = -1;
    for (int i = 0; i < m_objects.size(); i++) {
        if (m_objects[i].id.compare(entry, Qt::CaseInsensitive) == 0) { idx = i; break; }
    }
    if (idx < 0) return makeLdapResult(msgId, 0x6f, 32); // noSuchObject

    QString actual;
    if (attr.compare(QStringLiteral("cn"), Qt::CaseInsensitive) == 0) actual = m_objects[idx].name;
    else actual = m_objects[idx].attributes.value(attr);
    bool match = (actual.compare(val, Qt::CaseInsensitive) == 0);
    emit requestReceived(QStringLiteral("Compare: %1 %2").arg(entry, attr));
    return makeLdapResult(msgId, 0x6f, match ? 5 : 6); // compareTrue/False
}

QByteArray LdapServer::handleExtended(ClientState *st, int msgId, const QByteArray &payload,
                                     bool *startTls) {
    int pos = 0;
    QString reqName;
    QByteArray reqValue;
    // requestName [0] (context 0) LDAPOID, requestValue [1] (context 1) OCTET STRING
    while (pos < payload.size()) {
        int tag = (unsigned char)payload[pos];
        if (tag == 0x80) {
            int t = readTag(payload, pos);
            int len = readLength(payload, pos);
            Q_UNUSED(t)
            reqName = QString::fromUtf8(payload.mid(pos, len));
            pos += len;
        } else if (tag == 0x81) {
            int t = readTag(payload, pos);
            int len = readLength(payload, pos);
            Q_UNUSED(t)
            reqValue = payload.mid(pos, len);
            pos += len;
        } else {
            break;
        }
    }

    if (reqName == QStringLiteral("1.3.6.1.4.1.1466.20037")) {
        // StartTLS. RFC 4511 §4.14.1: it is refused with operationsError while a
        // SASL security layer is in effect or when the session is already TLS,
        // and with unavailable when the server has no certificate to offer.
        if (!m_tlsAvailable) {
            emit requestReceived(QStringLiteral("Extended: StartTLS refused (no certificate)"));
            return makeExtendedResponse(msgId, 52, QString(), QByteArray()); // unavailable
        }
        if (st && (st->tlsActive || saslLayerActive(st))) {
            emit requestReceived(QStringLiteral("Extended: StartTLS refused (already secured)"));
            return makeExtendedResponse(msgId, 1, QString(), QByteArray()); // operationsError
        }
        emit requestReceived(QStringLiteral("Extended: StartTLS"));
        if (startTls)
            *startTls = true;
        return makeExtendedResponse(msgId, 0, QString(), QByteArray());
    }
    if (reqName == QStringLiteral("1.3.6.1.4.1.4203.1.11.3")) {
        // WhoAmI (RFC 4532): the authzid this connection is bound as, which is
        // what ldapwhoami prints. The empty form was answered unconditionally,
        // so a client that had bound by DN, UPN or DOMAIN\user — and so could
        // read the directory — still could not learn what it was bound as.
        emit requestReceived(QStringLiteral("Extended: WhoAmI"));
        const QByteArray val =
            QByteArray("dn:") + (st ? st->authenticatedDn.toUtf8() : QByteArray());
        return makeExtendedResponse(msgId, 0, QStringLiteral("1.3.6.1.4.1.4203.1.11.3"), val);
    }
    // Unknown extended op
    emit requestReceived(QStringLiteral("Extended: %1 (unsupported)").arg(reqName));
    return makeExtendedResponse(msgId, 12, QString(), QByteArray()); // unavailable
}

QByteArray LdapServer::makeExtendedResponse(int msgId, int resultCode, const QString &name, const QByteArray &value) {
    QByteArray inner;
    writeInt(inner, 0x0a, resultCode);
    writeString(inner, 0x04, QString()); // matchedDN
    writeString(inner, 0x04, QString()); // diagnosticMessage
    if (!name.isEmpty()) {
        // responseName [10] (0x8a)
        QByteArray nb = name.toUtf8();
        inner.append((char)0x8a);
        writeLength(inner, nb.size());
        inner.append(nb);
    }
    if (!value.isEmpty()) {
        // responseValue [11] (0x8b)
        inner.append((char)0x8b);
        writeLength(inner, value.size());
        inner.append(value);
    }
    QByteArray op;
    writeTLV(op, 0x78, inner); // ExtendedResponse [APPLICATION 24]
    QByteArray msg;
    writeInt(msg, 0x02, msgId);
    msg.append(op);
    QByteArray seq;
    writeTLV(seq, 0x30, msg);
    return seq;
}

QByteArray LdapServer::makeLdapResult(int msgId, int opTag, int resultCode) {
    QByteArray inner;
    writeInt(inner, 0x0a, resultCode);
    writeString(inner, 0x04, QString()); // matchedDN
    writeString(inner, 0x04, QString()); // diagnosticMessage
    QByteArray op;
    writeTLV(op, opTag, inner);
    QByteArray msg;
    writeInt(msg, 0x02, msgId);
    msg.append(op);
    QByteArray seq;
    writeTLV(seq, 0x30, msg);
    return seq;
}

QByteArray LdapServer::makeBindResponse(int msgId, int resultCode, const QByteArray &saslCreds) {
    QByteArray inner;
    writeInt(inner, 0x0a, resultCode); // resultCode ENUMERATED (tag 0x0a)
    writeString(inner, 0x04, QString()); // matchedDN
    writeString(inner, 0x04, QString()); // diagnosticMessage
    if (!saslCreds.isEmpty())
        writeTLV(inner, 0x87, saslCreds); // serverSaslCreds [7] OCTET STRING
    QByteArray op;
    writeTLV(op, 0x61, inner); // BindResponse [APPLICATION 1]
    QByteArray msg;
    writeInt(msg, 0x02, msgId);
    msg.append(op);
    QByteArray seq;
    writeTLV(seq, 0x30, msg);
    return seq;
}

QByteArray LdapServer::makeSearchEntry(int msgId, const DirectoryObject &o,
                                       const QStringList &requested) {
    // RFC 4511 §4.5.1.8: the selection list is what the client asked to see. An
    // empty list is every attribute; "*" and "+" are that request spelled out;
    // "1.1" names no attribute type, so a client that sends it alone gets
    // entries carrying their DN and nothing else. Honouring none of this meant
    // a search for `cn` returned password-free but still complete entries, and
    // no client could ask for less.
    auto wanted = [&requested](const QString &type) {
        if (requested.isEmpty())
            return true;
        bool every = false;
        for (const QString &name : requested) {
            if (name.isEmpty())
                continue;
            if (name == QLatin1String("*") || name == QLatin1String("+")) {
                every = true;
                continue;
            }
            if (name.compare(type, Qt::CaseInsensitive) == 0)
                return true;
        }
        return every;
    };

    QByteArray attrs;
    // AD defines some attributes as binary: objectSid is a SID and objectGUID a
    // 16-byte GUID, never text. Sending the string form made Samba's NDR reader
    // fail on the second octet of "S-1-5-..." (45 sub-authorities) and abort the
    // join's servicePrincipalName step, so those two go out as their bytes.
    auto addRawAttr = [&attrs](const QString &type, const QByteArray &value) {
        QByteArray vals;
        writeTLV(vals, 0x04, value);
        QByteArray setVals;
        writeTLV(setVals, 0x31, vals); // SET
        QByteArray attrSeq;
        writeString(attrSeq, 0x04, type);
        attrSeq.append(setVals);
        writeTLV(attrs, 0x30, attrSeq);
    };
    auto guidBytes = [](const QString &text) {
        QString hex = text;
        hex.remove(QLatin1Char('{'));
        hex.remove(QLatin1Char('}'));
        hex.remove(QLatin1Char('-'));
        if (hex.size() != 32)
            return QByteArray();
        const QByteArray canonical = QByteArray::fromHex(hex.toLatin1());
        if (canonical.size() != 16)
            return QByteArray();
        // The first three fields are little-endian on the wire (RFC 4122 §4.1.2
        // as AD encodes it), the last eight octets stay as they are.
        QByteArray out;
        for (int i = 3; i >= 0; --i)
            out.append(canonical.at(i));
        out.append(canonical.at(5));
        out.append(canonical.at(4));
        out.append(canonical.at(7));
        out.append(canonical.at(6));
        out.append(canonical.mid(8, 8));
        return out;
    };
    auto addAttr = [&attrs](const QString &type, const QStringList &values) {
        if (type.isEmpty())
            return;
        QByteArray vals;
        for (const QString &value : values)
            writeString(vals, 0x04, value);
        QByteArray setVals;
        writeTLV(setVals, 0x31, vals); // SET
        QByteArray attrSeq;
        writeString(attrSeq, 0x04, type);
        attrSeq.append(setVals);
        writeTLV(attrs, 0x30, attrSeq);
    };

    // Everything the store knows about the object, so a client sees the same
    // data it would get from a real directory (including multi-valued attrs).
    QStringList emitted;
    for (auto it = o.attributes.constBegin(); it != o.attributes.constEnd(); ++it) {
        if (it.key().isEmpty())
            continue;
        const QString key = it.key().toLower();
        // Membership is emitted from the object's member lists, which are the
        // authoritative copy, never from a stale stored string. Password
        // material never leaves the server at all.
        if (key == QLatin1String("member") || key == QLatin1String("memberof"))
            continue;
        if (isSecretAttribute(key))
            continue;
        if (!wanted(it.key()))
            continue;
        QStringList values = it.value().split(QStringLiteral("; "), Qt::SkipEmptyParts);
        // The rootDSE is a cached object rebuilt only on a write, so the time
        // stamped into it at startup would go stale. RFC 4512 expects
        // currentTime to be the server's clock at the moment of the query, so
        // the rootDSE answers with the time now rather than when it was built.
        if (o.id.isEmpty() && key == QLatin1String("currenttime"))
            values = {QDateTime::currentDateTimeUtc().toString(Qt::ISODate)};
        if (key == QLatin1String("cn") && it.value().isEmpty())
            values = {o.name};
        if (key == QLatin1String("objectsid")) {
            const QByteArray sid = Ndr::sidFromString(it.value());
            if (!sid.isEmpty()) {
                addRawAttr(it.key(), sid);
                emitted.append(key);
                continue;
            }
        }
        if (key == QLatin1String("objectguid")) {
            const QByteArray guid = guidBytes(it.value());
            if (!guid.isEmpty()) {
                addRawAttr(it.key(), guid);
                emitted.append(key);
                continue;
            }
        }
        addAttr(it.key(), values);
        emitted.append(key);
    }
    if (!o.members.isEmpty() && wanted(QStringLiteral("member"))) {
        addAttr(QStringLiteral("member"), o.members);
        emitted.append(QStringLiteral("member"));
    }
    if (!o.memberOf.isEmpty() && wanted(QStringLiteral("memberOf"))) {
        addAttr(QStringLiteral("memberOf"), o.memberOf);
        emitted.append(QStringLiteral("memberof"));
    }
    // The attributes AD computes rather than stores, under the same selection
    // rule every stored attribute follows: asked for by name, or by "*".
    for (const auto &derived : derivedAttributes(o)) {
        const QString key = derived.first.toLower();
        if (emitted.contains(key) || !wanted(derived.first))
            continue;
        addAttr(derived.first, {derived.second});
        emitted.append(key);
    }
    if (!emitted.contains(QStringLiteral("cn")) && !o.name.isEmpty()
        && wanted(QStringLiteral("cn")))
        addAttr(QStringLiteral("cn"), {o.name});
    if (!emitted.contains(QStringLiteral("objectclass")) && wanted(QStringLiteral("objectClass")))
        addAttr(QStringLiteral("objectClass"), {QStringLiteral("top")});
    if (!emitted.contains(QStringLiteral("description")) && !o.description.isEmpty()
        && wanted(QStringLiteral("description")))
        addAttr(QStringLiteral("description"), {o.description});
    if (!emitted.contains(QStringLiteral("distinguishedname")) && !o.id.isEmpty()
        && wanted(QStringLiteral("distinguishedName")))
        addAttr(QStringLiteral("distinguishedName"), {o.id});

    QByteArray entry;
    writeString(entry, 0x04, o.id); // objectName
    writeTLV(entry, 0x30, attrs);   // attributes
    QByteArray op;
    writeTLV(op, 0x64, entry); // SearchResultEntry [APPLICATION 4]
    QByteArray msg;
    writeInt(msg, 0x02, msgId);
    msg.append(op);
    QByteArray seq;
    writeTLV(seq, 0x30, msg);
    return seq;
}

QByteArray LdapServer::makeSearchDone(int msgId, int resultCode, const QByteArray &controls) {
    QByteArray inner;
    writeInt(inner, 0x0a, resultCode);
    writeString(inner, 0x04, QString());
    writeString(inner, 0x04, QString());
    QByteArray op;
    writeTLV(op, 0x65, inner); // SearchResultDone [APPLICATION 5]
    QByteArray msg;
    writeInt(msg, 0x02, msgId);
    msg.append(op);
    if (!controls.isEmpty())
        writeTLV(msg, 0xa0, controls); // controls [0]
    QByteArray seq;
    writeTLV(seq, 0x30, msg);
    return seq;
}