// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Kdc.h"

#include <QDateTime>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QRandomGenerator>
#include <QUdpSocket>
#include <QDebug>

#include "Asn1.h"
#include "Krb5.h"
#include "Pac.h"

namespace {

// Application tags (RFC 4120 §5.10). Kerberos uses EXPLICIT tags, so every
// application tag wraps a SEQUENCE.
constexpr quint8 kAsReqTag = 0x6A;
constexpr quint8 kAsRepTag = 0x6B;
constexpr quint8 kTgsReqTag = 0x6C;
constexpr quint8 kTgsRepTag = 0x6D;
constexpr quint8 kApReqTag = 0x6E;
constexpr quint8 kApRepTag = 0x6F;
constexpr quint8 kKrbErrorTag = 0x7E;
constexpr quint8 kEncTicketPartTag = 0x63;
constexpr quint8 kEncAsRepPartTag = 0x79;
constexpr quint8 kEncTgsRepPartTag = 0x7A;
constexpr quint8 kEncApRepPartTag = 0x7B;

// KDC error codes (RFC 4120 §7.5.9).
constexpr int kErrCPrincipalUnknown = 6;
constexpr int kErrSPrincipalUnknown = 7;
constexpr int kErrEtypeNoSupp = 14;
constexpr int kErrPadTypeNoSupp = 16;
constexpr int kErrClientRevoked = 18;
constexpr int kErrPreauthFailed = 24;
constexpr int kErrPreauthRequired = 25;
constexpr int kErrTicketExpired = 32;
constexpr int kErrClockSkew = 37;
constexpr int kErrGeneric = 60;

// Ticket flags (RFC 4120 §5.3).
constexpr quint32 kFlagForwardable = 0x20000000;
constexpr quint32 kFlagProxiable = 0x10000000;
constexpr quint32 kFlagRenewable = 0x00800000;
constexpr quint32 kFlagPreAuthent = 0x00200000;
constexpr quint32 kFlagInitial = 0x40000000;

constexpr qint64 kTicketLifetime = 10 * 3600;

// MONARCHY_KDC_TRACE=1 follows a client through the exchange on stderr, the way
// MONARCHY_RPC_TRACE does for the management endpoint.
void trace(const QString &message)
{
    if (!qEnvironmentVariableIsEmpty("MONARCHY_KDC_TRACE"))
        qWarning("KDC %s", qPrintable(message));
}

QByteArray contextTag(quint8 context, const QByteArray &der)
{
    return Asn1::tlv(quint8(0xA0 | context), der);
}

QByteArray kerberosString(quint8 context, const QString &value)
{
    return contextTag(context, Asn1::string(0x1B, value));
}

QByteArray explicitInteger(quint8 context, qint64 value)
{
    return contextTag(context, Asn1::integer(0x02, value));
}

QByteArray explicitOctets(quint8 context, const QByteArray &value)
{
    return contextTag(context, Asn1::octets(0x04, value));
}

QByteArray principalName(const QString &name)
{
    QList<QByteArray> parts;
    for (const QString &part : name.split(QLatin1Char('/')))
        parts.append(Asn1::string(0x1B, part));

    QByteArray content;
    content.append(explicitInteger(0, 1)); // name-type: NT-PRINCIPAL
    content.append(contextTag(1, Asn1::sequenceOf(parts)));
    return Asn1::sequence(content);
}

QByteArray taggedPrincipal(quint8 context, const QString &name)
{
    return contextTag(context, principalName(name));
}

QByteArray encryptionKey(const QByteArray &key, int etype)
{
    QByteArray content;
    content.append(explicitInteger(0, etype));
    content.append(explicitOctets(1, key));
    return Asn1::sequence(content);
}

QByteArray encryptedData(int etype, int kvno, const QByteArray &cipher)
{
    QByteArray content;
    content.append(explicitInteger(0, etype));
    if (kvno > 0)
        content.append(explicitInteger(1, kvno));
    content.append(explicitOctets(2, cipher));
    return Asn1::sequence(content);
}

// Ticket ::= [APPLICATION 1] SEQUENCE { ... }
QByteArray ticket(const QString &realm, const QString &sname, int etype, int kvno,
                  const QByteArray &cipher)
{
    QByteArray content;
    content.append(explicitInteger(0, 5));
    content.append(kerberosString(1, realm));
    content.append(taggedPrincipal(2, sname));
    content.append(contextTag(3, encryptedData(etype, kvno, cipher)));
    return Asn1::tlv(0x61, Asn1::sequence(content));
}

QByteArray encTicketPart(quint32 flags, const QByteArray &sessionKey, int sessionEtype,
                         const QString &crealm, const QString &cname, qint64 authtime,
                         qint64 endtime, const QByteArray &authorizationData)
{
    QByteArray content;
    content.append(contextTag(0, Asn1::bits(0x03, flags)));
    content.append(contextTag(1, encryptionKey(sessionKey, sessionEtype)));
    content.append(kerberosString(2, crealm));
    content.append(taggedPrincipal(3, cname));

    QByteArray transited;
    transited.append(explicitInteger(0, 0)); // no cross-realm hops
    transited.append(explicitOctets(1, QByteArray()));
    content.append(contextTag(4, Asn1::sequence(transited)));

    content.append(contextTag(5, Asn1::generalizedTime(0x18, authtime)));
    content.append(contextTag(6, Asn1::generalizedTime(0x18, authtime)));
    content.append(contextTag(7, Asn1::generalizedTime(0x18, endtime)));
    if (!authorizationData.isEmpty())
        content.append(contextTag(10, authorizationData));
    return Asn1::tlv(kEncTicketPartTag, Asn1::sequence(content));
}

QByteArray encKdcRepPart(quint8 application, quint32 flags, const QByteArray &sessionKey,
                         int sessionEtype, quint32 nonce, qint64 authtime, qint64 endtime,
                         const QString &srealm, const QString &sname)
{
    QByteArray content;
    content.append(contextTag(0, encryptionKey(sessionKey, sessionEtype)));
    content.append(contextTag(1, Asn1::sequence(QByteArray()))); // last-req
    content.append(explicitInteger(2, nonce));
    content.append(contextTag(4, Asn1::bits(0x03, flags)));
    content.append(contextTag(5, Asn1::generalizedTime(0x18, authtime)));
    content.append(contextTag(6, Asn1::generalizedTime(0x18, authtime)));
    content.append(contextTag(7, Asn1::generalizedTime(0x18, endtime)));
    content.append(kerberosString(9, srealm));
    content.append(taggedPrincipal(10, sname));
    return Asn1::tlv(application, Asn1::sequence(content));
}

QString decodeString(const Asn1::Element *tagged)
{
    if (!tagged)
        return {};
    Asn1::Element inner;
    int used = 0;
    if (!Asn1::parse(tagged->value, &inner, &used) || inner.tag != 0x1B)
        return {};
    return Asn1::toString(inner);
}

bool decodePrincipal(const Asn1::Element *tagged, QString *out, QString *realmOut = nullptr)
{
    if (!tagged)
        return false;
    Asn1::Element sequence;
    if (!Asn1::parse(tagged->value, &sequence) || sequence.tag != 0x30)
        return false;
    const Asn1::Element *names = Asn1::child(sequence, 0xA1);
    if (!names)
        return false;
    Asn1::Element nameSequence;
    if (!Asn1::parse(names->value, &nameSequence) || nameSequence.tag != 0x30)
        return false;
    QStringList parts;
    for (const Asn1::Element &part : nameSequence.children) {
        if (part.tag == 0x1B)
            parts.append(Asn1::toString(part));
    }
    if (parts.isEmpty())
        return false;
    if (out)
        *out = parts.join(QLatin1Char('/'));
    if (realmOut) {
        // A principal carries its own realm; TGS requests for another realm
        // use it to name the service.
        const Asn1::Element *realmTag = Asn1::child(sequence, 0xA2);
        *realmOut = realmTag ? decodeString(realmTag) : QString();
    }
    return true;
}

qint64 decodeInteger(const Asn1::Element *tagged, qint64 fallback = 0)
{
    if (!tagged)
        return fallback;
    Asn1::Element inner;
    int used = 0;
    if (!Asn1::parse(tagged->value, &inner, &used) || inner.tag != 0x02)
        return fallback;
    return Asn1::toInteger(inner, fallback);
}

QByteArray decodeOctets(const Asn1::Element *tagged)
{
    if (!tagged)
        return {};
    Asn1::Element inner;
    int used = 0;
    if (!Asn1::parse(tagged->value, &inner, &used) || inner.tag != 0x04)
        return {};
    return inner.value;
}

quint32 decodeBits(const Asn1::Element *tagged)
{
    if (!tagged)
        return 0;
    Asn1::Element inner;
    int used = 0;
    if (!Asn1::parse(tagged->value, &inner, &used) || inner.tag != 0x03)
        return 0;
    return Asn1::toBits(inner);
}

qint64 decodeTime(const Asn1::Element *tagged)
{
    if (!tagged)
        return 0;
    Asn1::Element inner;
    int used = 0;
    if (!Asn1::parse(tagged->value, &inner, &used))
        return 0;
    return Asn1::toTime(inner);
}

// PA-DATA is a SEQUENCE; the padata-value octet string carries DER.
QByteArray paData(int type, const QByteArray &value)
{
    QByteArray content;
    content.append(explicitInteger(1, type));
    content.append(explicitOctets(2, value));
    return Asn1::sequence(content);
}

QByteArray etypeInfo2Padata(const QString &salt, const QList<int> &etypes)
{
    // One entry per encryption type, each with the salt the account's keys were
    // derived with; the client tries them strongest first.
    QList<QByteArray> entries;
    for (const int etype : etypes) {
        QByteArray entry;
        entry.append(explicitInteger(0, etype));
        entry.append(kerberosString(1, salt));
        entries.append(Asn1::sequence(entry));
    }
    return paData(19, Asn1::sequenceOf(entries));
}

// GSS-API (RFC 1964) initial context token: [APPLICATION 0] { MechType,
// TOK_ID, message }. TOK_ID is 0x0100 for an AP-REQ and 0x0200 for an AP-REP.
QByteArray gssToken(const QByteArray &message, quint16 tokId)
{
    QByteArray content = Asn1::objectIdentifier(QStringLiteral("1.2.840.113554.1.2.2"));
    content.append(char((tokId >> 8) & 0xff));
    content.append(char(tokId & 0xff));
    content.append(message);
    return Asn1::tlv(0x60, content);
}

QByteArray unwrapGssToken(const QByteArray &token)
{
    if (token.isEmpty() || quint8(token.at(0)) != 0x60)
        return token;
    Asn1::Element outer;
    if (!Asn1::parse(token, &outer) || outer.tag != 0x60)
        return token;
    // Children are the mechanism OID, the two-octet TOK_ID and the message.
    for (const Asn1::Element &child : outer.children) {
        if (child.tag == kApReqTag || child.tag == kApRepTag)
            return Asn1::tlv(child.tag, child.value);
    }
    return {};
}

} // namespace

Kdc::Kdc(QObject *parent)
    : QObject(parent)
{
}

Kdc::~Kdc()
{
    close();
}

void Kdc::setRealm(const KerberosRealmConfig &config)
{
    m_config = config;
    m_config.realm = Krb5::canonicalRealm(config.realm);
    if (m_config.netbios.isEmpty())
        m_config.netbios = m_config.realm.section(QLatin1Char('.'), 0, 0);
}

void Kdc::setObjects(const QList<DirectoryObject> &objects)
{
    m_objects = objects;
    m_provider = nullptr;
}

void Kdc::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = std::move(provider);
}

QList<DirectoryObject> Kdc::directory() const
{
    if (m_provider)
        return m_provider();
    return m_objects;
}

bool Kdc::listen(quint16 port)
{
    close();
    m_tcp = new QTcpServer(this);
    if (!m_tcp->listen(QHostAddress::Any, port)) {
        close();
        return false;
    }
    m_port = m_tcp->serverPort();

    m_udp = new QUdpSocket(this);
    if (!m_udp->bind(QHostAddress::Any, m_port)) {
        close();
        return false;
    }

    connect(m_tcp, &QTcpServer::newConnection, this, &Kdc::onTcpConnection);
    connect(m_udp, &QUdpSocket::readyRead, this, &Kdc::onUdpDatagram);
    return true;
}

void Kdc::close()
{
    if (m_tcp) {
        m_tcp->close();
        m_tcp->deleteLater();
        m_tcp = nullptr;
    }
    if (m_udp) {
        m_udp->close();
        m_udp->deleteLater();
        m_udp = nullptr;
    }
    m_port = 0;
}

bool Kdc::isListening() const
{
    return m_tcp && m_tcp->isListening();
}

quint16 Kdc::serverPort() const
{
    return m_port;
}

void Kdc::onTcpConnection()
{
    while (m_tcp && m_tcp->hasPendingConnections()) {
        QTcpSocket *socket = m_tcp->nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
            QByteArray buffer = socket->property("kdcBuffer").toByteArray();
            buffer.append(socket->readAll());
            while (buffer.size() >= 4) {
                const quint32 length = (quint32(quint8(buffer.at(0))) << 24)
                                       | (quint32(quint8(buffer.at(1))) << 16)
                                       | (quint32(quint8(buffer.at(2))) << 8)
                                       | quint32(quint8(buffer.at(3)));
                if (length == 0 || buffer.size() < 4 + int(length))
                    break;
                const QByteArray message = buffer.mid(4, int(length));
                buffer.remove(0, 4 + int(length));
                const QByteArray reply = handleRequest(message);
                QByteArray framed;
                framed.append(char((reply.size() >> 24) & 0xff));
                framed.append(char((reply.size() >> 16) & 0xff));
                framed.append(char((reply.size() >> 8) & 0xff));
                framed.append(char(reply.size() & 0xff));
                framed.append(reply);
                socket->write(framed);
            }
            socket->setProperty("kdcBuffer", buffer);
        });
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    }
}

void Kdc::onUdpDatagram()
{
    while (m_udp && m_udp->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(int(m_udp->pendingDatagramSize()));
        QHostAddress sender;
        quint16 senderPort = 0;
        m_udp->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        const QByteArray reply = handleRequest(datagram);
        if (!reply.isEmpty())
            m_udp->writeDatagram(reply, sender, senderPort);
    }
}

QByteArray Kdc::handleRequest(const QByteArray &request)
{
    Asn1::Element outer;
    if (!Asn1::parse(request, &outer)) {
        emit requestReceived(QStringLiteral("Kerberos: malformed request"));
        return krbError(kErrGeneric, Krb5::canonicalRealm(m_config.realm), QString());
    }

    QString error;
    if (outer.tag == kAsReqTag) {
        KdcRequest parsed;
        if (!parseRequest(request, kAsReqTag, &parsed, &error)) {
            emit requestReceived(QStringLiteral("Kerberos AS-REQ: %1").arg(error));
            return krbError(kErrGeneric, Krb5::canonicalRealm(m_config.realm), QString());
        }
        emit requestReceived(QStringLiteral("Kerberos AS-REQ: %1").arg(parsed.cname));
        return handleAsReq(parsed);
    }
    if (outer.tag == kTgsReqTag) {
        KdcRequest parsed;
        if (!parseRequest(request, kTgsReqTag, &parsed, &error)) {
            emit requestReceived(QStringLiteral("Kerberos TGS-REQ: %1").arg(error));
            return krbError(kErrGeneric, Krb5::canonicalRealm(m_config.realm), QString());
        }
        trace(QStringLiteral("TGS-REQ %1@%2 -> %3@%4").arg(parsed.cname, parsed.realm,
                                                         parsed.sname, parsed.srealm));
        emit requestReceived(QStringLiteral("Kerberos TGS-REQ: %1").arg(parsed.sname));
        return handleTgsReq(parsed);
    }

    emit requestReceived(QStringLiteral("Kerberos: unsupported message"));
    return krbError(kErrGeneric, Krb5::canonicalRealm(m_config.realm), QString());
}

bool Kdc::parseRequest(const QByteArray &der, quint8 expectedTag, KdcRequest *out,
                       QString *error) const
{
    Asn1::Element outer;
    if (!Asn1::parse(der, &outer) || outer.tag != expectedTag) {
        if (error)
            *error = QStringLiteral("unexpected message tag");
        return false;
    }
    Asn1::Element sequence;
    if (!Asn1::parse(outer.value, &sequence) || sequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("missing KDC-REQ sequence");
        return false;
    }

    const Asn1::Element *bodyTag = Asn1::child(sequence, 0xA4);
    if (!bodyTag) {
        if (error)
            *error = QStringLiteral("missing KDC-REQ-BODY");
        return false;
    }
    Asn1::Element body;
    if (!Asn1::parse(bodyTag->value, &body) || body.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed KDC-REQ-BODY");
        return false;
    }

    out->realm = Krb5::canonicalRealm(decodeString(Asn1::child(body, 0xA2)));
    if (out->realm.isEmpty())
        out->realm = Krb5::canonicalRealm(m_config.realm);
    decodePrincipal(Asn1::child(body, 0xA1), &out->cname);
    decodePrincipal(Asn1::child(body, 0xA3), &out->sname, &out->srealm);
    out->nonce = quint32(decodeInteger(Asn1::child(body, 0xA7)));
    out->options = decodeBits(Asn1::child(body, 0xA0));

    if (const Asn1::Element *etypesTag = Asn1::child(body, 0xA8)) {
        Asn1::Element etypes;
        if (Asn1::parse(etypesTag->value, &etypes) && etypes.tag == 0x30) {
            for (const Asn1::Element &etype : etypes.children) {
                if (etype.tag == 0x02)
                    out->etypes.append(int(Asn1::toInteger(etype)));
            }
        }
    }

    if (const Asn1::Element *padataTag = Asn1::child(sequence, 0xA3)) {
        Asn1::Element padata;
        if (Asn1::parse(padataTag->value, &padata) && padata.tag == 0x30) {
            for (const Asn1::Element &entry : padata.children) {
                if (entry.tag != 0x30)
                    continue;
                const int type = int(decodeInteger(Asn1::child(entry, 0xA1)));
                const QByteArray value = decodeOctets(Asn1::child(entry, 0xA2));
                if (type == 2) { // PA-ENC-TIMESTAMP: EncryptedData
                    Asn1::Element encrypted;
                    if (Asn1::parse(value, &encrypted) && encrypted.tag == 0x30) {
                        out->encTimestamp = decodeOctets(Asn1::child(encrypted, 0xA2));
                        out->hasEncTimestamp = encrypted.tag == 0x30;
                    }
                } else if (type == 1) { // PA-TGS-REQ: AP-REQ
                    out->apReq = value;
                    out->hasApReq = !value.isEmpty();
                }
            }
        }
    }

    return true;
}

int Kdc::preferredEtype(const Krb5::Principal &principal) const
{
    for (const int etype : {Krb5::kAes256, Krb5::kAes128, Krb5::kRc4Hmac}) {
        if (principal.keyFor(etype).size() == Krb5::keySize(etype))
            return etype;
    }
    return 0;
}

QByteArray Kdc::preauthRequired(const KdcRequest &request, const QString &salt,
                                const QList<int> &etypes) const
{
    // AD advertises the mechanism it wants as an empty PA-ENC-TIMESTAMP entry;
    // clients such as MIT krb5 only answer with pre-authentication when they
    // see it alongside the salt information.
    QByteArray methodData;
    methodData.append(paData(2, QByteArray()));
    methodData.append(etypeInfo2Padata(salt, etypes));
    methodData.append(paData(3, Asn1::string(0x1B, salt)));
    const QByteArray eData = Asn1::sequence(methodData);
    return krbError(kErrPreauthRequired, Krb5::canonicalRealm(m_config.realm), request.cname,
                    eData);
}

QByteArray Kdc::krbError(int code, const QString &realm, const QString &cname,
                         const QByteArray &eData) const
{
    // KRB-ERROR keeps the field numbering MIT, Heimdal and Windows all put on
    // the wire: error-code [6], crealm [7], cname [8], srealm [9], sname [10],
    // text [11], e-data [12].
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QByteArray content;
    content.append(explicitInteger(0, 5));
    content.append(explicitInteger(1, 30));
    content.append(contextTag(4, Asn1::generalizedTime(0x18, now)));
    content.append(explicitInteger(5, 0));
    content.append(explicitInteger(6, code));
    if (!realm.isEmpty())
        content.append(kerberosString(7, realm));
    if (!cname.isEmpty())
        content.append(taggedPrincipal(8, cname));
    if (!realm.isEmpty()) {
        content.append(kerberosString(9, realm));
        content.append(taggedPrincipal(10, QStringLiteral("krbtgt/%1").arg(realm)));
    }
    content.append(kerberosString(11, QStringLiteral("Monarchy KDC error %1").arg(code)));
    if (!eData.isEmpty())
        content.append(explicitOctets(12, eData));
    return Asn1::tlv(kKrbErrorTag, Asn1::sequence(content));
}

QByteArray Kdc::handleAsReq(const KdcRequest &request)
{
    const QString realm = Krb5::canonicalRealm(m_config.realm);
    if (request.realm.compare(realm, Qt::CaseInsensitive) != 0)
        return krbError(kErrCPrincipalUnknown, realm, request.cname);

    Krb5::Principal client;
    if (!Krb5::findPrincipal(directory(),
                             request.cname + QLatin1Char('@') + request.realm, realm,
                             &client))
        return krbError(kErrCPrincipalUnknown, realm, request.cname);
    if (client.disabled)
        return krbError(kErrClientRevoked, realm, request.cname);

    const int etype = client.chooseEtype(request.etypes);
    if (!request.hasEncTimestamp)
        return preauthRequired(request, client.salt, client.etypes());
    if (etype == 0)
        return krbError(kErrEtypeNoSupp, realm, request.cname);

    QByteArray timestamp;
    if (!Krb5::decrypt(etype, 1, client.keyFor(etype), request.encTimestamp, &timestamp))
        return krbError(kErrPreauthFailed, realm, request.cname);

    Asn1::Element encrypted;
    if (!Asn1::parse(timestamp, &encrypted) || encrypted.tag != 0x30)
        return krbError(kErrPreauthFailed, realm, request.cname);
    const qint64 clientTime = decodeTime(Asn1::child(encrypted, 0xA0));
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (clientTime <= 0 || qAbs(now - clientTime) > Krb5::kClockSkewSeconds)
        return krbError(kErrPreauthFailed, realm, request.cname);

    return issueAsRep(request, client, etype, timestamp);
}

namespace {

// RFC 4120 uses key usage 3 for the AS-REP encrypted part, but RFC 4757 §7.5
// folds that into the TGS-REP usage for RC4-HMAC, so 8 is what an RC4 client
// expects and 3 is what an AES client expects.
int asRepUsage(int etype)
{
    return etype == Krb5::kRc4Hmac ? 8 : 3;
}

} // namespace

QByteArray Kdc::issueAsRep(const KdcRequest &request, const Krb5::Principal &client,
                           int etype, const QByteArray &timestamp) const
{
    Q_UNUSED(timestamp)
    const QByteArray clientKey = client.keyFor(etype);
    const QString realm = Krb5::canonicalRealm(m_config.realm);
    Krb5::Principal krbtgt;
    if (!Krb5::findPrincipal(directory(), QStringLiteral("krbtgt/%1").arg(realm), realm,
                             &krbtgt))
        return krbError(kErrSPrincipalUnknown, realm, request.cname);

    const int ticketEtype = preferredEtype(krbtgt);
    if (ticketEtype == 0)
        return krbError(kErrSPrincipalUnknown, realm, request.cname);

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 endtime = now + kTicketLifetime;
    const QByteArray sessionKey = Krb5::randomKey(etype);
    quint32 flags = kFlagInitial | kFlagPreAuthent;
    if (request.options & kFlagForwardable)
        flags |= kFlagForwardable;
    if (request.options & kFlagProxiable)
        flags |= kFlagProxiable;

    // A PAC for the client, sealed with the krbtgt key for both signatures: the
    // TGT is a ticket to krbtgt itself, so the service and KDC keys coincide.
    QByteArray authorizationData;
    Pac::Keys pacKeys;
    pacKeys.serviceKey = krbtgt.keyFor(ticketEtype);
    pacKeys.serviceEtype = ticketEtype;
    pacKeys.kdcKey = krbtgt.keyFor(ticketEtype);
    pacKeys.kdcEtype = ticketEtype;
    for (const DirectoryObject &object : directory()) {
        if (object.id.compare(client.dn, Qt::CaseInsensitive) != 0)
            continue;
        const QByteArray pac = Pac::build(object, realm, m_config.netbios,
                                          m_config.domainSid, directory(), pacKeys, now);
        if (!pac.isEmpty())
            authorizationData = Pac::authorizationData(pac);
        break;
    }

    const QString sname = QStringLiteral("krbtgt/%1").arg(realm);
    const QByteArray ticketCipher =
        Krb5::encrypt(ticketEtype, 2, krbtgt.keyFor(ticketEtype),
                      encTicketPart(flags, sessionKey, etype, realm, request.cname, now,
                                    endtime, authorizationData));
    // The reply's encrypted part is sealed with the client's long-term key, so
    // only the account that authenticated can read the session key. RC4-HMAC
    // seals it under key usage 8, not the AS-REP usage 3: RFC 4757 §7.5 folds
    // the two together, and MIT krb5 rejects 3 with "Decrypt integrity check
    // failed" (verified against libkrb5).
    const QByteArray encPart =
        Krb5::encrypt(etype, asRepUsage(etype), clientKey,
                      encKdcRepPart(kEncAsRepPartTag, flags, sessionKey, etype, request.nonce,
                                    now, endtime, realm, sname));

    QByteArray content;
    content.append(explicitInteger(0, 5));
    content.append(explicitInteger(1, 11));
    content.append(contextTag(2, Asn1::sequence(etypeInfo2Padata(client.salt, {etype}))));
    content.append(kerberosString(3, realm));
    content.append(taggedPrincipal(4, request.cname));
    content.append(
        contextTag(5, ticket(realm, sname, ticketEtype, int(krbtgt.kvno), ticketCipher)));
    content.append(contextTag(6, encryptedData(etype, 0, encPart)));
    return Asn1::tlv(kAsRepTag, Asn1::sequence(content));
}

QByteArray Kdc::handleTgsReq(const KdcRequest &request)
{
    const QString realm = Krb5::canonicalRealm(m_config.realm);
    if (!request.hasApReq)
        return krbError(kErrPadTypeNoSupp, realm, request.cname);

    Krb5::Principal krbtgt;
    const bool haveLocalKrbtgt =
        Krb5::findPrincipal(directory(), QStringLiteral("krbtgt/%1").arg(realm), realm, &krbtgt);

    Asn1::Element apReq;
    if (!Asn1::parse(request.apReq, &apReq) || apReq.tag != kApReqTag)
        return krbError(kErrGeneric, realm, request.cname);
    Asn1::Element apSequence;
    if (!Asn1::parse(apReq.value, &apSequence) || apSequence.tag != 0x30)
        return krbError(kErrGeneric, realm, request.cname);

    const Asn1::Element *ticketTag = Asn1::child(apSequence, 0xA3);
    if (!ticketTag)
        return krbError(kErrGeneric, realm, request.cname);
    const Asn1::Element *ticketElement = Asn1::child(*ticketTag, 0x61);
    if (!ticketElement)
        return krbError(kErrGeneric, realm, request.cname);

    OpenedTicket tgt;
    QString error;
    const QByteArray ticketDer = Asn1::tlv(0x61, ticketElement->value);
    bool opened = haveLocalKrbtgt && openTicket(ticketDer, krbtgt, &tgt, &error);
    if (!opened) {
        // A TGT issued by a trusted realm is sealed with the trust key, not
        // with ours. Only an inbound trust (bit 1) accepts one.
        const QString ticketRealm = Krb5::canonicalRealm(tgt.realm);
        if (!ticketRealm.isEmpty() && ticketRealm != realm) {
            const Krb5::Principal trust = trustPrincipal(ticketRealm);
            const bool inbound = (trustDirection(ticketRealm) & 1u) != 0;
            if (trust.isValid() && inbound) {
                opened = openTicket(ticketDer, trust, &tgt, &error);
                if (opened)
                    emit requestReceived(QStringLiteral("Cross-realm TGT from %1")
                                             .arg(ticketRealm));
            }
        }
    }
    if (!opened) {
        trace(QStringLiteral("TGS-REQ rejected (TGT): %1").arg(error));
        emit requestReceived(QStringLiteral("Kerberos TGS-REQ rejected: %1").arg(error));
        return krbError(kErrGeneric, realm, request.cname);
    }
    if (tgt.endtime <= QDateTime::currentSecsSinceEpoch())
        return krbError(kErrTicketExpired, realm, tgt.client);

    QByteArray subkey;
    int subkeyEtype = 0;
    if (!verifyAuthenticator(request.apReq, tgt, 7, nullptr, &error, &subkey, &subkeyEtype)) {
        emit requestReceived(QStringLiteral("Kerberos TGS-REQ rejected: %1").arg(error));
        return krbError(kErrGeneric, realm, tgt.client);
    }

    return issueTgsRep(request, tgt, subkey, subkeyEtype);
}

QByteArray Kdc::issueTgsRep(const KdcRequest &request, const OpenedTicket &tgt,
                           const QByteArray &subkey, int subkeyEtype) const
{
    const QString realm = Krb5::canonicalRealm(m_config.realm);
    Krb5::Principal service;
    const bool localService =
        Krb5::findPrincipal(directory(), request.sname + QLatin1Char('@') + realm, realm,
                            &service);
    if (!localService) {
        // RFC 4120 §3.3.3.3: when the service lives in another realm, hand back
        // a ticket for that realm's krbtgt instead — a referral — and the client
        // takes it to the peer KDC.
        QString target = Krb5::canonicalRealm(request.srealm);
        if (request.sname.startsWith(QLatin1String("krbtgt/"), Qt::CaseInsensitive))
            target = Krb5::canonicalRealm(request.sname.mid(7));
        if (!target.isEmpty() && target != realm) {
            const Krb5::Principal trust = trustPrincipal(target);
            if (trust.isValid() && (trustDirection(target) & 2u)) // outbound
                return issueReferral(request, tgt, trust, target, subkey, subkeyEtype);
        }
        trace(QStringLiteral("service %1@%2 is not in the directory").arg(request.sname,
                                                                       realm));
        return krbError(kErrSPrincipalUnknown, realm, tgt.client);
    }

    // The service ticket is sealed with the service account's strongest key;
    // the reply itself travels under the TGT's session key type, and the new
    // session key uses whatever both sides asked for there.
    const int serviceEtype = preferredEtype(service);
    if (serviceEtype == 0)
        return krbError(kErrSPrincipalUnknown, realm, tgt.client);
    const int sessionEtype = tgt.sessionEtype;
    if (!request.etypes.isEmpty() && !request.etypes.contains(sessionEtype))
        return krbError(kErrEtypeNoSupp, realm, tgt.client);

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 endtime = qMin(tgt.endtime, now + kTicketLifetime);
    const QByteArray sessionKey = Krb5::randomKey(sessionEtype);
    const quint32 flags =
        tgt.flags & (kFlagForwardable | kFlagProxiable | kFlagRenewable);

    // Carry the TGT's PAC into the service ticket, re-signed for this service
    // (the KDC signature still comes from krbtgt).
    QByteArray authorizationData;
    const QByteArray tgtPac = Pac::extract(tgt.authorizationData);
    Krb5::Principal krbtgt;
    if (!tgtPac.isEmpty()
        && Krb5::findPrincipal(directory(), QStringLiteral("krbtgt/%1").arg(realm), realm,
                               &krbtgt)) {
        const int kdcEtype = preferredEtype(krbtgt);
        Pac::Keys pacKeys;
        pacKeys.serviceKey = service.keyFor(serviceEtype);
        pacKeys.serviceEtype = serviceEtype;
        pacKeys.kdcKey = krbtgt.keyFor(kdcEtype);
        pacKeys.kdcEtype = kdcEtype;
        const QByteArray pac = Pac::resign(tgtPac, pacKeys);
        if (!pac.isEmpty())
            authorizationData = Pac::authorizationData(pac);
    }

    // A ticket for a client that came across a trust keeps the client's own
    // realm; a local client's realm is ours.
    const QString crealm = tgt.crealm.isEmpty() ? realm : tgt.crealm;
    const QByteArray ticketCipher =
        Krb5::encrypt(serviceEtype, 2, service.keyFor(serviceEtype),
                      encTicketPart(flags, sessionKey, sessionEtype, crealm, tgt.client, now,
                                    endtime, authorizationData));
    // RFC 4120 §7.5.1: a TGS reply is sealed under the request's subkey with
    // usage 9 when the client supplied one, otherwise under the TGT session key
    // with usage 8. MIT clients propose a subkey, so honour it.
    const bool haveSubkey = subkeyEtype != 0 && subkey.size() == Krb5::keySize(subkeyEtype);
    const QByteArray replyKey = haveSubkey ? subkey : tgt.sessionKey;
    const int replyEtype = haveSubkey ? subkeyEtype : sessionEtype;
    const QByteArray encPart =
        Krb5::encrypt(replyEtype, haveSubkey ? 9 : 8, replyKey,
                      encKdcRepPart(kEncTgsRepPartTag, flags, sessionKey, sessionEtype,
                                    request.nonce, now, endtime, realm, request.sname));

    QByteArray content;
    content.append(explicitInteger(0, 5));
    content.append(explicitInteger(1, 13));
    content.append(kerberosString(3, crealm));
    content.append(taggedPrincipal(4, tgt.client));
    content.append(contextTag(5, ticket(realm, request.sname, serviceEtype, int(service.kvno),
                                        ticketCipher)));
    content.append(contextTag(6, encryptedData(replyEtype, 0, encPart)));
    return Asn1::tlv(kTgsRepTag, Asn1::sequence(content));
}

Krb5::Principal Kdc::trustPrincipal(const QString &peerRealm) const
{
    Krb5::Principal principal;
    if (!Krb5::findTrustPrincipal(directory(), peerRealm,
                                  Krb5::canonicalRealm(m_config.realm), &principal))
        return {};
    return principal;
}

quint32 Kdc::trustDirection(const QString &peerRealm) const
{
    const QString peer = Krb5::canonicalRealm(peerRealm);
    for (const DirectoryObject &object : directory()) {
        const QString partner = Krb5::canonicalRealm(
            object.attributes.value(QStringLiteral("trustPartner")));
        if (!partner.isEmpty() && partner == peer)
            return object.attributes.value(QStringLiteral("trustDirection")).toUInt();
    }
    return 0;
}

QByteArray Kdc::issueReferral(const KdcRequest &request, const OpenedTicket &tgt,
                             const Krb5::Principal &trust, const QString &peerRealm,
                             const QByteArray &subkey, int subkeyEtype) const
{
    const QString realm = Krb5::canonicalRealm(m_config.realm);
    const int trustEtype = preferredEtype(trust);
    if (trustEtype == 0)
        return krbError(kErrSPrincipalUnknown, realm, tgt.client);

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 endtime = qMin(tgt.endtime, now + kTicketLifetime);
    const QByteArray sessionKey = Krb5::randomKey(tgt.sessionEtype);
    const quint32 flags =
        tgt.flags & (kFlagForwardable | kFlagProxiable | kFlagRenewable);

    // MS-PAC §4.1.4: a PAC crossing a trust boundary is signed by the KDC for
    // that boundary, so the peer's krbtgt signature is replaced by the trust key.
    QByteArray authorizationData;
    const QByteArray tgtPac = Pac::extract(tgt.authorizationData);
    if (!tgtPac.isEmpty()) {
        Pac::Keys pacKeys;
        pacKeys.serviceKey = trust.keyFor(trustEtype);
        pacKeys.serviceEtype = trustEtype;
        pacKeys.kdcKey = trust.keyFor(trustEtype);
        pacKeys.kdcEtype = trustEtype;
        const QByteArray pac = Pac::resign(tgtPac, pacKeys);
        if (!pac.isEmpty())
            authorizationData = Pac::authorizationData(pac);
    }

    const QString sname = QStringLiteral("krbtgt/%1").arg(peerRealm);
    const QByteArray ticketCipher =
        Krb5::encrypt(trustEtype, 2, trust.keyFor(trustEtype),
                      encTicketPart(flags, sessionKey, tgt.sessionEtype, realm, tgt.client,
                                    now, endtime, authorizationData));

    const bool haveSubkey = subkeyEtype != 0 && subkey.size() == Krb5::keySize(subkeyEtype);
    const QByteArray replyKey = haveSubkey ? subkey : tgt.sessionKey;
    const int replyEtype = haveSubkey ? subkeyEtype : tgt.sessionEtype;
    // srealm is the realm of the server principal, which for krbtgt/PEER@OURS is
    // ours — the peer realm travels in the second name component, not here.
    const QByteArray encPart =
        Krb5::encrypt(replyEtype, haveSubkey ? 9 : 8, replyKey,
                      encKdcRepPart(kEncTgsRepPartTag, flags, sessionKey, tgt.sessionEtype,
                                    request.nonce, now, endtime, realm, sname));

    QByteArray content;
    content.append(explicitInteger(0, 5));
    content.append(explicitInteger(1, 13));
    content.append(kerberosString(3, realm));
    content.append(taggedPrincipal(4, tgt.client));
    content.append(contextTag(5, ticket(realm, sname, trustEtype, int(trust.kvno),
                                        ticketCipher)));
    content.append(contextTag(6, encryptedData(replyEtype, 0, encPart)));
    return Asn1::tlv(kTgsRepTag, Asn1::sequence(content));
}

bool Kdc::openTicket(const QByteArray &ticketDer, const Krb5::Principal &principal,
                     OpenedTicket *out, QString *error) const
{
    Asn1::Element ticketElement;
    if (!Asn1::parse(ticketDer, &ticketElement) || ticketElement.tag != 0x61) {
        if (error)
            *error = QStringLiteral("malformed ticket");
        return false;
    }
    Asn1::Element ticketSequence;
    if (!Asn1::parse(ticketElement.value, &ticketSequence) || ticketSequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed ticket sequence");
        return false;
    }
    out->realm = decodeString(Asn1::child(ticketSequence, 0xA1));
    decodePrincipal(Asn1::child(ticketSequence, 0xA2), &out->service);

    const Asn1::Element *encTag = Asn1::child(ticketSequence, 0xA3);
    if (!encTag) {
        if (error)
            *error = QStringLiteral("ticket has no encrypted part");
        return false;
    }
    Asn1::Element encrypted;
    if (!Asn1::parse(encTag->value, &encrypted) || encrypted.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed ticket enc-part");
        return false;
    }
    const QByteArray cipher = decodeOctets(Asn1::child(encrypted, 0xA2));
    const int etype = int(decodeInteger(Asn1::child(encrypted, 0xA0), 0));
    out->ticketEtype = etype;
    const QByteArray key = principal.keyFor(etype);
    if (key.isEmpty()) {
        if (error)
            *error = QStringLiteral("no key for ticket encryption type %1").arg(etype);
        return false;
    }

    QByteArray plaintext;
    if (!Krb5::decrypt(etype, 2, key, cipher, &plaintext)) {
        if (error)
            *error = QStringLiteral("ticket integrity check failed");
        return false;
    }
    Asn1::Element part;
    if (!Asn1::parse(plaintext, &part) || part.tag != kEncTicketPartTag) {
        if (error)
            *error = QStringLiteral("malformed EncTicketPart");
        return false;
    }
    Asn1::Element fields;
    if (!Asn1::parse(part.value, &fields) || fields.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed EncTicketPart fields");
        return false;
    }

    out->flags = decodeBits(Asn1::child(fields, 0xA0));
    out->crealm = decodeString(Asn1::child(fields, 0xA2));
    if (const Asn1::Element *keyTag = Asn1::child(fields, 0xA1)) {
        Asn1::Element keySeq;
        if (!Asn1::parse(keyTag->value, &keySeq) || keySeq.tag != 0x30) {
            if (error)
                *error = QStringLiteral("malformed ticket key");
            return false;
        }
        out->sessionEtype = int(decodeInteger(Asn1::child(keySeq, 0xA0), 0));
        out->sessionKey = decodeOctets(Asn1::child(keySeq, 0xA1));
    }
    if (out->sessionKey.isEmpty()
        || out->sessionKey.size() != Krb5::keySize(out->sessionEtype)) {
        if (error)
            *error = QStringLiteral("ticket has no usable session key");
        return false;
    }
    decodePrincipal(Asn1::child(fields, 0xA3), &out->client);
    out->authtime = decodeTime(Asn1::child(fields, 0xA5));
    out->endtime = decodeTime(Asn1::child(fields, 0xA7));
    if (const Asn1::Element *authData = Asn1::child(fields, 0xAA))
        out->authorizationData = authData->value;
    return true;
}

bool Kdc::readAuthenticator(const QByteArray &apReqDer, const OpenedTicket &ticket, int usage,
                            AuthenticatorFields *out, QString *error)
{
    Asn1::Element apReq;
    if (!Asn1::parse(apReqDer, &apReq) || apReq.tag != kApReqTag) {
        if (error)
            *error = QStringLiteral("not an AP-REQ");
        return false;
    }
    Asn1::Element apSequence;
    if (!Asn1::parse(apReq.value, &apSequence) || apSequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed AP-REQ");
        return false;
    }
    const Asn1::Element *authenticatorTag = Asn1::child(apSequence, 0xA4);
    if (!authenticatorTag) {
        if (error)
            *error = QStringLiteral("AP-REQ has no authenticator");
        return false;
    }
    Asn1::Element encrypted;
    if (!Asn1::parse(authenticatorTag->value, &encrypted) || encrypted.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed AP-REQ authenticator");
        return false;
    }
    const QByteArray cipher = decodeOctets(Asn1::child(encrypted, 0xA2));

    QByteArray plaintext;
    if (!Krb5::decrypt(ticket.sessionEtype, usage, ticket.sessionKey, cipher, &plaintext)) {
        if (error)
            *error = QStringLiteral("authenticator integrity check failed");
        return false;
    }
    Asn1::Element authenticator;
    if (!Asn1::parse(plaintext, &authenticator) || authenticator.tag != 0x62) {
        if (error)
            *error = QStringLiteral("malformed Authenticator");
        return false;
    }
    Asn1::Element fields;
    if (!Asn1::parse(authenticator.value, &fields) || fields.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed Authenticator fields");
        return false;
    }

    const QString realm = decodeString(Asn1::child(fields, 0xA1));
    QString client;
    decodePrincipal(Asn1::child(fields, 0xA2), &client);
    // The authenticator names the client's realm, which is the ticket's crealm;
    // the ticket's own realm is the service's and differs across a trust.
    const QString clientRealm = ticket.crealm.isEmpty() ? ticket.realm : ticket.crealm;
    if (client.compare(ticket.client, Qt::CaseInsensitive) != 0
        || realm.compare(clientRealm, Qt::CaseInsensitive) != 0) {
        if (error)
            *error = QStringLiteral("authenticator does not match the ticket");
        return false;
    }

    const qint64 clientTime = decodeTime(Asn1::child(fields, 0xA5));
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (clientTime <= 0 || qAbs(now - clientTime) > Krb5::kClockSkewSeconds) {
        if (error)
            *error = QStringLiteral("authenticator timestamp outside the clock skew");
        return false;
    }

    AuthenticatorFields result;
    result.ctime = clientTime;
    result.usec = quint32(decodeInteger(Asn1::child(fields, 0xA4)));
    // A client may propose a subkey; the AP-REP is then sealed with it and
    // carries it back, which is what GSSAPI mutual authentication expects.
    if (const Asn1::Element *subkeyTag = Asn1::child(fields, 0xA6)) {
        Asn1::Element subkeySequence;
        if (Asn1::parse(subkeyTag->value, &subkeySequence)
            && subkeySequence.tag == 0x30) {
            result.subkeyEtype = int(decodeInteger(Asn1::child(subkeySequence, 0xA0), 0));
            result.subkey = decodeOctets(Asn1::child(subkeySequence, 0xA1));
        }
    }
    // Where the initiator starts its own per-message tokens (RFC 4121 §3.1).
    // A client that does not send one starts from zero.
    result.seq = quint32(decodeInteger(Asn1::child(fields, 0xA7), 0));

    const QString replayKey = QStringLiteral("%1|%2|%3")
                                  .arg(client.toLower())
                                  .arg(clientTime)
                                  .arg(result.usec);
    for (auto it = m_replay.begin(); it != m_replay.end();) {
        if (it.value() + Krb5::kClockSkewSeconds < now)
            it = m_replay.erase(it);
        else
            ++it;
    }
    if (m_replay.contains(replayKey)) {
        if (error)
            *error = QStringLiteral("replayed authenticator");
        return false;
    }
    m_replay.insert(replayKey, now);

    if (out)
        *out = result;
    return true;
}

bool Kdc::verifyAuthenticator(const QByteArray &apReqDer, const OpenedTicket &ticket,
                             int usage, QByteArray *replyToken, QString *error,
                             QByteArray *subkeyOut, int *subkeyEtypeOut)
{
    AuthenticatorFields fields;
    if (!readAuthenticator(apReqDer, ticket, usage, &fields, error))
        return false;

    if (subkeyOut)
        *subkeyOut = fields.subkey;
    if (subkeyEtypeOut)
        *subkeyEtypeOut = fields.subkeyEtype;

    if (!replyToken)
        return true;

    const bool usableSubkey =
        fields.subkeyEtype != 0 && fields.subkey.size() == Krb5::keySize(fields.subkeyEtype);
    const QByteArray replyKey = usableSubkey ? fields.subkey : ticket.sessionKey;
    const int replyEtype = usableSubkey ? fields.subkeyEtype : ticket.sessionEtype;
    QByteArray content;
    content.append(contextTag(0, Asn1::generalizedTime(0x18, fields.ctime)));
    content.append(explicitInteger(1, fields.usec));
    if (usableSubkey)
        content.append(contextTag(2, encryptionKey(fields.subkey, replyEtype)));
    const QByteArray encPart =
        Krb5::encrypt(replyEtype, 12, replyKey,
                      Asn1::tlv(kEncApRepPartTag, Asn1::sequence(content)));

    QByteArray apRep;
    apRep.append(explicitInteger(0, 5));
    apRep.append(explicitInteger(1, 15));
    apRep.append(contextTag(2, encryptedData(replyEtype, 0, encPart)));
    *replyToken = gssToken(Asn1::tlv(kApRepTag, Asn1::sequence(apRep)), 0x0200);
    return true;
}

bool Kdc::openApReq(const QByteArray &apReqDer, OpenedTicket *ticket, Krb5::Principal *service,
                    QString *serviceName, QString *error)
{
    Asn1::Element apReq;
    if (!Asn1::parse(apReqDer, &apReq) || apReq.tag != kApReqTag) {
        if (error)
            *error = QStringLiteral("token is not an AP-REQ");
        return false;
    }
    Asn1::Element apSequence;
    if (!Asn1::parse(apReq.value, &apSequence) || apSequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed AP-REQ");
        return false;
    }
    const Asn1::Element *ticketTag = Asn1::child(apSequence, 0xA3);
    const Asn1::Element *ticketElement =
        ticketTag ? Asn1::child(*ticketTag, 0x61) : nullptr;
    if (!ticketElement) {
        if (error)
            *error = QStringLiteral("AP-REQ carries no ticket");
        return false;
    }

    const QByteArray ticketDer = Asn1::tlv(0x61, ticketElement->value);

    // Which service was requested? The ticket names it, and the directory holds
    // the key, so no static keytab has to be kept anywhere.
    Asn1::Element ticketOuter;
    Asn1::Element ticketSequence;
    if (!Asn1::parse(ticketDer, &ticketOuter)
        || !Asn1::parse(ticketOuter.value, &ticketSequence)
        || ticketSequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed ticket");
        return false;
    }
    const QString realm = decodeString(Asn1::child(ticketSequence, 0xA1));
    QString name;
    decodePrincipal(Asn1::child(ticketSequence, 0xA2), &name);

    Krb5::Principal found;
    if (!Krb5::findPrincipal(directory(), name + QLatin1Char('@') + realm, realm, &found)) {
        if (error)
            *error = QStringLiteral("service principal %1 is not in the directory").arg(name);
        return false;
    }

    if (!openTicket(ticketDer, found, ticket, error))
        return false;
    if (ticket->endtime <= QDateTime::currentSecsSinceEpoch()) {
        if (error)
            *error = QStringLiteral("service ticket has expired");
        return false;
    }
    if (service)
        *service = found;
    if (serviceName)
        *serviceName = name;
    return true;
}

bool Kdc::verifyServicePac(const OpenedTicket &ticket, const Krb5::Principal &service,
                           QByteArray *pacOut, QString *error)
{
    const QByteArray pac = Pac::extract(ticket.authorizationData);
    if (pac.isEmpty())
        return true;

    // MS-PAC: a service must verify both signatures before trusting the PAC.
    const QString realm = ticket.realm;
    Krb5::Principal krbtgt;
    const bool haveKrbtgt =
        Krb5::findPrincipal(directory(), QStringLiteral("krbtgt/%1").arg(realm), realm,
                            &krbtgt);
    bool verified = false;
    for (const int kdcEtype : {Krb5::kAes256, Krb5::kAes128, Krb5::kRc4Hmac}) {
        Pac::Keys keys;
        keys.serviceKey = service.keyFor(ticket.ticketEtype);
        keys.serviceEtype = ticket.ticketEtype;
        keys.kdcKey = haveKrbtgt ? krbtgt.keyFor(kdcEtype) : QByteArray();
        keys.kdcEtype = kdcEtype;
        if (keys.kdcKey.isEmpty())
            continue;
        if (Pac::verify(pac, keys)) {
            verified = true;
            break;
        }
    }
    if (!verified) {
        if (error)
            *error = QStringLiteral("PAC signature check failed");
        return false;
    }
    if (pacOut)
        *pacOut = pac;
    emit requestReceived(QStringLiteral("Kerberos PAC verified: %1 bytes").arg(pac.size()));
    return true;
}

bool Kdc::acceptApReq(const QByteArray &token, ApResult *out, QString *error)
{
    const QByteArray apReqDer = unwrapGssToken(token);
    if (apReqDer.isEmpty()) {
        if (error)
            *error = QStringLiteral("token is not a GSS-API Kerberos AP-REQ");
        return false;
    }

    OpenedTicket ticket;
    Krb5::Principal service;
    QString serviceName;
    if (!openApReq(apReqDer, &ticket, &service, &serviceName, error))
        return false;

    QByteArray reply;
    QByteArray subkey;
    int subkeyEtype = 0;
    if (!verifyAuthenticator(apReqDer, ticket, 11, &reply, error, &subkey, &subkeyEtype))
        return false;

    QByteArray pac;
    if (!verifyServicePac(ticket, service, &pac, error))
        return false;

    if (out) {
        out->clientPrincipal = ticket.client;
        out->servicePrincipal = serviceName;
        out->sessionKey = ticket.sessionKey;
        // What the authenticated context seals with: the initiator's subkey
        // when it proposed one (GSS-API always does), else the session key.
        const bool usableSubkey =
            subkeyEtype != 0 && subkey.size() == Krb5::keySize(subkeyEtype);
        out->contextKey = usableSubkey ? subkey : ticket.sessionKey;
        out->contextEtype = usableSubkey ? subkeyEtype : ticket.sessionEtype;
        out->replyToken = reply;
        out->pac = pac;

        Krb5::Principal client;
        if (Krb5::findPrincipal(directory(),
                                ticket.client + QLatin1Char('@') + ticket.realm,
                                ticket.realm, &client))
            out->clientDn = client.dn;
    }
    return true;
}

bool Kdc::acceptDceApReq(const QByteArray &token, ApResult *out, QString *error)
{
    const QByteArray apReqDer = unwrapGssToken(token);
    if (apReqDer.isEmpty()) {
        if (error)
            *error = QStringLiteral("token is not a GSS-API Kerberos AP-REQ");
        return false;
    }

    OpenedTicket ticket;
    Krb5::Principal service;
    QString serviceName;
    if (!openApReq(apReqDer, &ticket, &service, &serviceName, error))
        return false;

    AuthenticatorFields fields;
    if (!readAuthenticator(apReqDer, ticket, 11, &fields, error))
        return false;

    // RFC 4121 §7.1: a DCE/RPC context seals with an acceptor subkey that the
    // acceptor generates and hands back in the AP-REP; the initiator's own
    // subkey only protects the AP-REP itself.
    QByteArray acceptorSubkey = Krb5::randomKey(ticket.sessionEtype);
    if (acceptorSubkey.isEmpty()) {
        if (error)
            *error = QStringLiteral("no key for enctype %1").arg(ticket.sessionEtype);
        return false;
    }
    const quint32 sendSeq = quint32(QRandomGenerator::system()->generate());

    const bool usableSubkey =
        fields.subkeyEtype != 0 && fields.subkey.size() == Krb5::keySize(fields.subkeyEtype);
    const QByteArray replyKey = usableSubkey ? fields.subkey : ticket.sessionKey;
    const int replyEtype = usableSubkey ? fields.subkeyEtype : ticket.sessionEtype;

    QByteArray content;
    content.append(contextTag(0, Asn1::generalizedTime(0x18, fields.ctime)));
    content.append(explicitInteger(1, fields.usec));
    content.append(contextTag(2, encryptionKey(acceptorSubkey, ticket.sessionEtype)));
    content.append(explicitInteger(3, sendSeq));
    const QByteArray encPart =
        Krb5::encrypt(replyEtype, 12, replyKey,
                      Asn1::tlv(kEncApRepPartTag, Asn1::sequence(content)));

    QByteArray apRep;
    apRep.append(explicitInteger(0, 5));
    apRep.append(explicitInteger(1, 15));
    apRep.append(contextTag(2, encryptedData(replyEtype, 0, encPart)));
    // A bare AP-REP: DCE/RPC supplies the framing, so no GSS-API token header.
    const QByteArray reply = Asn1::tlv(kApRepTag, Asn1::sequence(apRep));

    QByteArray pac;
    if (!verifyServicePac(ticket, service, &pac, error))
        return false;

    if (out) {
        out->clientPrincipal = ticket.client;
        out->servicePrincipal = serviceName;
        out->sessionKey = ticket.sessionKey;
        out->contextKey = acceptorSubkey;
        out->contextEtype = ticket.sessionEtype;
        out->replyToken = reply;
        out->recvSeq = fields.seq;
        out->sendSeq = sendSeq;
        out->pac = pac;

        Krb5::Principal client;
        if (Krb5::findPrincipal(directory(),
                                ticket.client + QLatin1Char('@') + ticket.realm,
                                ticket.realm, &client))
            out->clientDn = client.dn;
    }
    return true;
}

bool Kdc::finishDceApReq(const QByteArray &token, const QByteArray &contextKey, int etype,
                         quint32 expectedSeq, QString *error)
{
    return finishDceApReq(token, contextKey, etype, QByteArray(), 0, expectedSeq, error);
}

bool Kdc::finishDceApReq(const QByteArray &token, const QByteArray &contextKey, int etype,
                         const QByteArray &ticketKey, int ticketEtype, quint32 expectedSeq,
                         QString *error)
{
    QByteArray apRepDer = unwrapGssToken(token);
    if (apRepDer.isEmpty())
        apRepDer = token;
    Asn1::Element apRep;
    if (!Asn1::parse(apRepDer, &apRep) || apRep.tag != kApRepTag) {
        if (error)
            *error = QStringLiteral("not the closing AP-REP");
        return false;
    }
    Asn1::Element sequence;
    if (!Asn1::parse(apRep.value, &sequence) || sequence.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed AP-REP");
        return false;
    }
    const Asn1::Element *encryptedTag = Asn1::child(sequence, 0xA2);
    Asn1::Element encrypted;
    if (!encryptedTag
        || !Asn1::parse(encryptedTag->value, &encrypted) || encrypted.tag != 0x30) {
        if (error)
            *error = QStringLiteral("AP-REP has no encrypted part");
        return false;
    }
    const QByteArray sealed = decodeOctets(Asn1::child(encrypted, 0xA2));
    QByteArray plaintext;
    bool opened = !contextKey.isEmpty() && Krb5::decrypt(etype, 12, contextKey, sealed, &plaintext);
    if (!opened && !ticketKey.isEmpty())
        opened = Krb5::decrypt(ticketEtype, 12, ticketKey, sealed, &plaintext);
    if (!opened) {
        if (error)
            *error = QStringLiteral("AP-REP integrity check failed");
        return false;
    }
    Asn1::Element part;
    Asn1::Element fields;
    if (!Asn1::parse(plaintext, &part) || part.tag != kEncApRepPartTag
        || !Asn1::parse(part.value, &fields) || fields.tag != 0x30) {
        if (error)
            *error = QStringLiteral("malformed EncAPRepPart");
        return false;
    }
    if (Asn1::child(fields, 0xA2)) {
        if (error)
            *error = QStringLiteral("the closing AP-REP carries a subkey");
        return false;
    }
    const quint32 seq = quint32(decodeInteger(Asn1::child(fields, 0xA3), 0));
    if (seq != expectedSeq) {
        if (error)
            *error = QStringLiteral("AP-REP sequence number mismatch");
        return false;
    }
    return true;
}
