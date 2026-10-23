// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LdapServer.h"

#include "Asn1.h"
#include "Gss.h"
#include "Kdc.h"
#include "Ntlm.h"

#include <QtNetwork/QTcpSocket>
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

int readInt(const QByteArray &d, int &pos) {
    int tag; QByteArray v = readTLV(d, pos, tag);
    int r = 0;
    for (char c : v) r = (r << 8) | (unsigned char)c;
    // sign extend
    if (!v.isEmpty() && (v[0] & 0x80)) {
        for (int i = v.size(); i < (int)sizeof(int); i++) r |= (0xFF << (i*8));
    }
    return r;
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

QString attributeValue(const DirectoryObject &o, const QString &attr)
{
    const QString value = o.attributes.value(attr);
    if (!value.isEmpty())
        return value;
    // Objects built without an explicit cn fall back to their RDN name.
    if (attr.compare(QLatin1String("cn"), Qt::CaseInsensitive) == 0)
        return o.name;
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
    case 0x87: { // present
        const QString attr = QString::fromUtf8(content);
        return [attr](const DirectoryObject &o) {
            if (attr.compare(QLatin1String("objectClass"), Qt::CaseInsensitive) == 0)
                return true;
            return !attributeValue(o, attr).isEmpty();
        };
    }
    default:
        break;
    }
    // Unsupported filter types match everything, as before.
    return [](const DirectoryObject &){ return true; };
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
    return m_server->listen(QHostAddress::Any, port);
}

void LdapServer::close() {
    for (auto *c : m_clients) {
        if (c->socket) c->socket->deleteLater();
        delete c;
    }
    m_clients.clear();
    if (m_server) m_server->close();
}

bool LdapServer::isListening() const { return m_server && m_server->isListening(); }
quint16 LdapServer::serverPort() const { return m_server ? m_server->serverPort() : 0; }

void LdapServer::setObjects(const QList<DirectoryObject> &objects) {
    m_objects = objects;
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
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(doc.toJson());
    f.close();
    return true;
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
// client send UTF-8. Both are accepted, and the value is never stored as text.
QString decodePasswordValue(const QByteArray &raw, const QString &fallback)
{
    QByteArray bytes = raw;
    if (bytes.size() >= 2 && bytes.startsWith('"') && bytes.endsWith('"'))
        bytes = bytes.mid(1, bytes.size() - 2);
    if (bytes.size() >= 2 && bytes.size() % 2 == 0 && bytes.contains('\0')) {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(bytes.constData()),
                                  qsizetype(bytes.size() / 2));
    }
    if (bytes.isEmpty())
        return fallback;
    return QString::fromUtf8(bytes);
}

// Baseline of the AD complexity policy: at least three of the four character
// classes, and the minimum length. Group Policy fine-grained policies are not
// modelled yet.
bool passwordMeetsPolicy(const QString &password, QString *reason)
{
    if (password.size() < LdapServer::kPasswordMinLength || password.size() > 256) {
        if (reason)
            *reason = QStringLiteral("password must be at least %1 characters")
                          .arg(LdapServer::kPasswordMinLength);
        return false;
    }
    int classes = 0;
    bool upper = false, lower = false, digit = false, other = false;
    for (const QChar c : password) {
        if (c.isUpper()) upper = true;
        else if (c.isLower()) lower = true;
        else if (c.isDigit()) digit = true;
        else other = true;
    }
    classes = int(upper) + int(lower) + int(digit) + int(other);
    if (classes < 3) {
        if (reason)
            *reason = QStringLiteral("password must use three of the four character classes");
        return false;
    }
    return true;
}

void storePasswordVerifier(DirectoryObject &object, const QString &password,
                           const QString &realm)
{
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
            nextUsn();
            ensureRootDse();
            return true;
        }
    }
    return false;
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
            if (!passwordMeetsPolicy(password, &reason)) {
                emit requestReceived(QStringLiteral("Password rejected: %1").arg(reason));
                return 19; // constraintViolation
            }
            storePasswordVerifier(object, password,
                                  m_kdc ? m_kdc->realm().realm : QString());
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
        processMessage(st, msg);
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

void LdapServer::processMessage(ClientState *st, const QByteArray &msg) {
    int pos = 0;
    int tag = readTag(msg, pos);
    if (tag != 0x30) return;
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
        if (control.criticality && control.oid != QLatin1String(kPagedResultsOid)) {
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
            return;
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
        return;
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
        socket->disconnectFromHost();
        response.clear();
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

    if (tag == 0x83) // SASL { mechanism, credentials }
        return handleSaslBind(st, msgId, password);

    emit requestReceived(QStringLiteral("Bind"));

    // Without any stored secret every bind succeeds (the console's sample
    // directory). Once a password exists — on the object itself or in the
    // provisioned secrets — simple binds are verified against its verifier.
    const bool anonymous = name.isEmpty() && password.isEmpty();
    if (!anonymous) {
        QByteArray salt;
        QByteArray hash;
        QByteArray ntHashHex;
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
            if (stored && object.id.compare(name, Qt::CaseInsensitive) == 0) {
                salt = objectSalt.toLatin1();
                hash = objectHash.toLatin1();
                ntHashHex = objectNtHash.toLatin1();
                accountControl =
                    object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
                haveVerifier = true;
            }
        }
        if (!haveVerifier) {
            const auto it = m_credentials.constFind(name.toLower());
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
    }
    return makeBindResponse(msgId, 0); // success
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

    if (mechanism.compare(QLatin1String("GSSAPI"), Qt::CaseInsensitive) == 0)
        return handleGssapiBind(st, msgId, credentials, false);

    // NTLM is what AD uses for password authentication without Kerberos, and
    // GSS-SPNEGO carries either NTLM or a Kerberos AP-REQ wrapped in ASN.1.
    if (mechanism.compare(QLatin1String("NTLM"), Qt::CaseInsensitive) != 0
        && mechanism.compare(QLatin1String("GSS-SPNEGO"), Qt::CaseInsensitive) != 0)
        return makeBindResponse(msgId, 7); // authMethodNotSupported

    const bool spnego = mechanism.compare(QLatin1String("GSS-SPNEGO"),
                                          Qt::CaseInsensitive) == 0;
    // Once a Kerberos context is in progress the follow-up tokens are the
    // security-layer exchange, not new SPNEGO negotiations.
    if (spnego && (st->saslStage != 0 || Gss::carriesKerberos(credentials)))
        return handleGssapiBind(st, msgId, credentials, true);

    const QByteArray token = Ntlm::embeddedToken(credentials);
    const int type = Ntlm::messageType(token);

    if (type == 1) { // NEGOTIATE -> CHALLENGE
        st->ntlmChallenge = QByteArray(8, '\0');
        for (int i = 0; i < 8; ++i)
            st->ntlmChallenge[i] = char(QRandomGenerator::system()->generate() & 0xff);
        const QByteArray challenge = Ntlm::challengeToken(
            st->ntlmChallenge, ntlmDomainName(), ntlmServerName());
        return makeBindResponse(msgId, 14, challenge); // saslBindInProgress
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

            if (!Ntlm::verifyNtlmv2(ntHash, authenticate.user, authenticate.domain, challenge,
                                    authenticate.ntResponse))
                return makeBindResponse(msgId, 49);

            // MS-NLMP §3.4: the session base key comes from the proof string,
            // and the per-direction keys are derived from it. A client that
            // asked for sign or seal gets a security layer for the rest of the
            // session; sealing implies signing.
            Ntlm::SessionKeys keys;
            if (!Ntlm::sessionKeys(ntHash, authenticate.user, authenticate.domain,
                                   authenticate.ntResponse.left(16), &keys, authenticate.flags))
                return makeBindResponse(msgId, 49);
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
        const QByteArray reply = spnego ? Gss::spnegoAcceptToken(result.replyToken)
                                        : result.replyToken;
        return makeBindResponse(msgId, 14, reply); // saslBindInProgress
    }

    if (st->saslStage == 1) {
        // The client has processed the AP-REP. Some clients select the security
        // layer straight away, others wait for the server's offer.
        // Offer the three RFC 4752 layers and the largest SASL buffer we send.
        if (credentials.size() < 4)
            return makeBindResponse(msgId, 14, QByteArray("\x07\x00\xff\xff", 4));
        st->saslStage = 2;
    }

    if (st->saslStage == 2) {
        if (credentials.size() < 4)
            return makeBindResponse(msgId, 2);

        // RFC 4752 §3.1: the client picks one layer and advertises the largest
        // buffer it will accept, then proves the choice by wrapping the
        // authorization id with the freshly negotiated context.
        const int layer = quint8(credentials.at(0));
        if (layer != 0x01 && layer != 0x02 && layer != 0x04) {
            st->saslStage = 0;
            return makeBindResponse(msgId, 7); // authMethodNotSupported
        }
        st->gssLayer = layer;
        st->gssMaxBuf = (quint32(quint8(credentials.at(1))) << 16)
                        | (quint32(quint8(credentials.at(2))) << 8)
                        | quint32(quint8(credentials.at(3)));

        if (layer != 0x01) {
            QByteArray authorizationId;
            if (credentials.size() <= 4
                || !gssUnwrap(st, credentials.mid(4), &authorizationId)) {
                emit requestReceived(QStringLiteral("GSSAPI layer token rejected"));
                st->saslStage = 0;
                st->gssLayer = 1;
                return makeBindResponse(msgId, 49);
            }
        }

        st->authenticatedDn = st->gssClientDn;
        st->saslStage = 0;
        st->gssClientDn.clear();
        // The verified PAC is the authority for what this session may do.
        st->gssHasIdentity = !st->gssPac.isEmpty()
                             && Pac::readIdentity(st->gssPac, &st->gssIdentity);
        st->gssPac.clear();
        if (st->authenticatedDn.isEmpty())
            return makeBindResponse(msgId, 49);

        // The same authorization id comes back wrapped, so the client knows the
        // server accepted the layer.
        QByteArray replyCredentials;
        if (layer != 0x01)
            replyCredentials = gssWrap(st, QByteArray(4, '\0'), layer == 0x04);
        st->gssBindResponse = !replyCredentials.isEmpty();
        // Anything the client pipelined behind the bind request is already
        // sealed, so hand it to the framed decoder rather than the LDAP parser.
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
    QString base = readString(payload, pos);
    int scope = readInt(payload, pos);
    int deref = readInt(payload, pos);
    Q_UNUSED(deref)
    int sizeLimit = readInt(payload, pos);
    Q_UNUSED(sizeLimit)
    int timeLimit = readInt(payload, pos);
    Q_UNUSED(timeLimit)
    // typesOnly BOOLEAN
    int ttag = readTag(payload, pos);
    int tlen = readLength(payload, pos);
    Q_UNUSED(ttag); Q_UNUSED(tlen);
    if (tlen > 0) pos += tlen;

    // filter
    Pred pred = parseFilter(payload, pos);

    // attributes SEQUENCE OF OCTET STRING
    int stag = readTag(payload, pos);
    int slen = readLength(payload, pos);
    Q_UNUSED(stag); Q_UNUSED(slen);
    int send = pos + slen;
    QStringList attrs;
    while (pos < send) {
        attrs.append(readString(payload, pos));
    }
    pos = send;

    emit requestReceived(QStringLiteral("Search: %1").arg(base));

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
            out.append(makeSearchEntry(msgId, o));
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
        out.append(makeSearchEntry(msgId, st->paged.results.at(i)));

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
    return makeLdapResult(msgId, 0x67, rcode);
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
                                  m_kdc ? m_kdc->realm().realm : QString());
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
    addObject(obj);
    emit requestReceived(QStringLiteral("Add: %1").arg(dn));
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
        // WhoAmI
        emit requestReceived(QStringLiteral("Extended: WhoAmI"));
        QByteArray val = QByteArray("dn:").append(""); // anonymous
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

QByteArray LdapServer::makeSearchEntry(int msgId, const DirectoryObject &o) {
    QByteArray attrs;
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
        QStringList values = it.value().split(QStringLiteral("; "), Qt::SkipEmptyParts);
        if (key == QLatin1String("cn") && it.value().isEmpty())
            values = {o.name};
        addAttr(it.key(), values);
        emitted.append(key);
    }
    if (!o.members.isEmpty()) {
        addAttr(QStringLiteral("member"), o.members);
        emitted.append(QStringLiteral("member"));
    }
    if (!o.memberOf.isEmpty()) {
        addAttr(QStringLiteral("memberOf"), o.memberOf);
        emitted.append(QStringLiteral("memberof"));
    }
    if (!emitted.contains(QStringLiteral("cn")) && !o.name.isEmpty())
        addAttr(QStringLiteral("cn"), {o.name});
    if (!emitted.contains(QStringLiteral("objectclass")))
        addAttr(QStringLiteral("objectClass"), {QStringLiteral("top")});
    if (!emitted.contains(QStringLiteral("description")) && !o.description.isEmpty())
        addAttr(QStringLiteral("description"), {o.description});
    if (!emitted.contains(QStringLiteral("distinguishedname")) && !o.id.isEmpty())
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