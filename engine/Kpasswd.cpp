// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Kpasswd.h"

#include "Asn1.h"
#include "Kdc.h"
#include "Krb5.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>

namespace {

// RFC 3244 §2: all 16-bit fields are big-endian.
quint16 read16(const char *bytes)
{
    return quint16((quint8(bytes[0]) << 8) | quint8(bytes[1]));
}

void append16(QByteArray &out, quint16 value)
{
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

void append32(QByteArray &out, quint32 value)
{
    out.append(char((value >> 24) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char(value & 0xff));
}

// EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL,
//                              cipher [2] OCTET STRING }
QByteArray encryptedData(int etype, const QByteArray &cipher)
{
    QByteArray content;
    content.append(Asn1::tlv(0xA0, Asn1::integer(0x02, etype)));
    content.append(Asn1::tlv(0xA2, Asn1::octets(0x04, cipher)));
    return Asn1::sequence(content);
}

bool readEncryptedData(const Asn1::Element &element, int *etype, QByteArray *cipher)
{
    const Asn1::Element *etypeField = Asn1::child(element, 0xA0);
    const Asn1::Element *cipherField = Asn1::child(element, 0xA2);
    if (!etypeField || !cipherField)
        return false;
    Asn1::Element etypeValue;
    Asn1::Element cipherValue;
    if (!Asn1::parse(etypeField->value, &etypeValue) || etypeValue.tag != 0x02)
        return false;
    if (!Asn1::parse(cipherField->value, &cipherValue) || cipherValue.tag != 0x04)
        return false;
    *etype = int(Asn1::toInteger(etypeValue));
    *cipher = cipherValue.value;
    return true;
}

// An explicitly tagged OCTET STRING, which is how Kerberos carries both the
// KRB-PRIV user-data and the [0] newpasswd field.
bool readTaggedOctets(const Asn1::Element &element, quint8 tag, QByteArray *out)
{
    const Asn1::Element *field = Asn1::child(element, tag);
    if (!field)
        return false;
    Asn1::Element value;
    if (!Asn1::parse(field->value, &value) || value.tag != 0x04)
        return false;
    *out = value.value;
    return true;
}

// kpasswd result codes (RFC 3244 §2).
constexpr quint16 kSuccess = 0;
constexpr quint16 kMalformed = 1;
constexpr quint16 kHardError = 2;
constexpr quint16 kAuthError = 3;
constexpr quint16 kSoftError = 4;
constexpr quint16 kAccessDenied = 5;
constexpr quint16 kBadVersion = 6;

// Key usages from RFC 4120 §7.5.1: the AP-REP enc-part and the KRB-PRIV
// enc-part have their own.
constexpr int kApRepUsage = 12;
constexpr int kKrbPrivUsage = 13;

} // namespace

KpasswdServer::KpasswdServer(QObject *parent)
    : QObject(parent)
{
}

KpasswdServer::~KpasswdServer()
{
    close();
}

void KpasswdServer::setKdc(Kdc *kdc)
{
    m_kdc = kdc;
}

void KpasswdServer::setObjectProvider(std::function<QList<DirectoryObject>()> provider)
{
    m_provider = std::move(provider);
}

void KpasswdServer::setPasswordWriter(
    std::function<bool(const QString &, const QString &, QString *)> writer)
{
    m_writer = std::move(writer);
}

bool KpasswdServer::listen(quint16 port)
{
    close();
    m_tcp = new QTcpServer(this);
    connect(m_tcp, &QTcpServer::newConnection, this, &KpasswdServer::onTcpConnection);
    if (!m_tcp->listen(QHostAddress::Any, port)) {
        delete m_tcp;
        m_tcp = nullptr;
        return false;
    }
    m_port = m_tcp->serverPort();

    m_udp = new QUdpSocket(this);
    connect(m_udp, &QUdpSocket::readyRead, this, &KpasswdServer::onUdpDatagram);
    if (!m_udp->bind(QHostAddress::Any, m_port)) {
        close();
        return false;
    }
    return true;
}

void KpasswdServer::close()
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

bool KpasswdServer::isListening() const
{
    return m_tcp && m_tcp->isListening();
}

quint16 KpasswdServer::serverPort() const
{
    return m_port;
}

void KpasswdServer::onTcpConnection()
{
    while (QTcpSocket *socket = m_tcp->nextPendingConnection()) {
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);

        // RFC 3244 §2: over TCP the message is preceded by a four-octet length
        // in network byte order. The message itself starts with its own
        // two-octet length, so the two are not the same field.
        QByteArray buffer;
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < 5000 && socket->state() == QAbstractSocket::ConnectedState) {
            buffer += socket->readAll();
            if (buffer.size() >= 4) {
                const quint32 length = (quint32(quint8(buffer.at(0))) << 24)
                                       | (quint32(quint8(buffer.at(1))) << 16)
                                       | (quint32(quint8(buffer.at(2))) << 8)
                                       | quint32(quint8(buffer.at(3)));
                if (length > 0 && length < (1 << 20)
                    && quint32(buffer.size()) >= 4 + length) {
                    const QByteArray reply = handleRequest(buffer.mid(4, int(length)));
                    QByteArray framed;
                    append32(framed, quint32(reply.size()));
                    framed.append(reply);
                    socket->write(framed);
                    socket->flush();
                    break;
                }
            }
            if (!socket->waitForReadyRead(50) && socket->bytesAvailable() == 0
                && socket->state() != QAbstractSocket::ConnectedState) {
                break;
            }
        }
        socket->disconnectFromHost();
    }
}

void KpasswdServer::onUdpDatagram()
{
    while (m_udp->hasPendingDatagrams()) {
        QByteArray datagram(int(m_udp->pendingDatagramSize()), Qt::Uninitialized);
        QHostAddress sender;
        quint16 senderPort = 0;
        const qint64 read =
            m_udp->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        if (read <= 0)
            continue;
        datagram.resize(int(read));
        const QByteArray reply = handleRequest(datagram);
        if (!reply.isEmpty())
            m_udp->writeDatagram(reply, sender, senderPort);
    }
}

QByteArray KpasswdServer::errorReply(const QByteArray &realm, quint16 code,
                                     const QString &message)
{
    // RFC 3244 §2: errors are an unframed KRB-ERROR whose e-data carries the
    // result code and a UTF-8 string. There is no AP-REP when the request could
    // not be authenticated at all.
    QByteArray data;
    append16(data, code);
    data.append(message.toUtf8());

    QByteArray content;
    content.append(Asn1::tlv(0xA0, Asn1::integer(0x02, 5)));  // pvno
    content.append(Asn1::tlv(0xA1, Asn1::integer(0x02, 30))); // KRB-ERROR
    content.append(Asn1::tlv(0xA4, Asn1::generalizedTime(0x18, QDateTime::currentSecsSinceEpoch())));
    content.append(Asn1::tlv(0xA5, Asn1::integer(0x02, 0)));  // susec
    content.append(Asn1::tlv(0xA6, Asn1::integer(0x02, 60))); // KRB_ERR_GENERIC
    if (!realm.isEmpty())
        content.append(Asn1::tlv(0xA9, Asn1::string(0x1B, realm)));
    content.append(Asn1::tlv(0xAC, Asn1::octets(0x04, data))); // e-data
    return Asn1::tlv(0x7E, Asn1::sequence(content));
}

QByteArray KpasswdServer::resultPriv(const QByteArray &key, int etype, quint32 seq, quint16 code,
                                     const QString &message) const
{
    QByteArray data;
    append16(data, code);
    data.append(message.toUtf8());

    // EncKrbPrivPart ::= SEQUENCE { user-data [0] OCTET STRING OPTIONAL,
    //   timestamp [1] ..., usec [2] ..., seq-number [3] ... }
    QByteArray part;
    part.append(Asn1::tlv(0xA0, Asn1::octets(0x04, data)));
    if (seq != 0)
        part.append(Asn1::tlv(0xA3, Asn1::integer(0x02, seq)));
    // RFC 4120 §5.9.3 makes s-address mandatory, unlike the other optional
    // fields: a decoder that follows the ASN.1 rejects the part without it.
    QByteArray hostAddress;
    hostAddress.append(Asn1::tlv(0xA0, Asn1::integer(0x02, 2)));             // IPv4
    hostAddress.append(Asn1::tlv(0xA1, Asn1::octets(0x04,
                                                    QByteArray::fromHex("7f000001"))));
    part.append(Asn1::tlv(0xA4, Asn1::sequence(hostAddress)));

    // EncKrbPrivPart is [APPLICATION 28], not a bare SEQUENCE.
    const QByteArray plainPart = Asn1::tlv(0x7C, Asn1::sequence(part));
    const QByteArray sealed = Krb5::encrypt(etype, kKrbPrivUsage, key, plainPart);
    QByteArray content;
    content.append(Asn1::tlv(0xA0, Asn1::integer(0x02, 5)));  // pvno
    content.append(Asn1::tlv(0xA1, Asn1::integer(0x02, 21))); // KRB-PRIV
    content.append(Asn1::tlv(0xA3, encryptedData(etype, sealed)));
    return Asn1::tlv(0x75, Asn1::sequence(content));
}

QByteArray KpasswdServer::frame(const QByteArray &apRep, const QByteArray &priv)
{
    QByteArray out;
    append16(out, quint16(6 + apRep.size() + priv.size()));
    append16(out, 0x0001); // the reply uses the original protocol's version
    append16(out, quint16(apRep.size()));
    out.append(apRep);
    out.append(priv);
    return out;
}

QByteArray KpasswdServer::handleRequest(const QByteArray &request)
{
    const QString realm = m_kdc ? m_kdc->realm().realm : QString();
    const auto fail = [&](quint16 code, const QString &text) {
        emit requestReceived(tr("kpasswd refused a request: %1").arg(text));
        return errorReply(realm.toUtf8(), code, text);
    };

    if (request.size() < 6)
        return fail(kMalformed, QStringLiteral("the request is shorter than its header"));
    if (read16(request.constData()) != quint16(request.size()))
        return fail(kMalformed, QStringLiteral("the length field does not match the message"));
    const quint16 version = read16(request.constData() + 2);
    if (version != 0x0001 && version != 0xff80) {
        return fail(kBadVersion,
                    QStringLiteral("protocol version 0x%1 is not served").arg(version, 4, 16));
    }
    const quint16 apReqLength = read16(request.constData() + 4);
    if (apReqLength == 0)
        return fail(kMalformed, QStringLiteral("the request carries no AP-REQ"));
    if (6 + int(apReqLength) > request.size())
        return fail(kMalformed, QStringLiteral("the AP-REQ length runs past the message"));

    const QByteArray apReq = request.mid(6, apReqLength);
    const QByteArray privDer = request.mid(6 + apReqLength);
    if (!m_kdc)
        return fail(kHardError, QStringLiteral("no Kerberos realm is served"));

    Kdc::ApResult result;
    QString error;
    if (!m_kdc->acceptApReq(apReq, &result, &error))
        return fail(kAuthError, error);

    // The ticket has to be for this service: a ticket for some other SPN would
    // otherwise let any service's client change passwords.
    const QString service = result.servicePrincipal.section(QLatin1Char('@'), 0, 0);
    if (service.compare(QLatin1String("kadmin/changepw"), Qt::CaseInsensitive) != 0) {
        return fail(kAuthError, QStringLiteral("the ticket names %1, not kadmin/changepw")
                                    .arg(result.servicePrincipal));
    }
    if (result.contextKey.isEmpty() || result.contextEtype == 0)
        return fail(kAuthError, QStringLiteral("the AP-REQ carried no session key"));

    Asn1::Element priv;
    Asn1::Element privSequence;
    if (!Asn1::parse(privDer, &priv) || priv.tag != 0x75
        || !Asn1::parse(priv.value, &privSequence) || privSequence.tag != 0x30) {
        return fail(kMalformed, QStringLiteral("the KRB-PRIV message is malformed"));
    }
    const Asn1::Element *encrypted = Asn1::child(privSequence, 0xA3);
    Asn1::Element encryptedElement;
    int encryptedEtype = 0;
    QByteArray cipher;
    if (!encrypted || !Asn1::parse(encrypted->value, &encryptedElement)
        || encryptedElement.tag != 0x30
        || !readEncryptedData(encryptedElement, &encryptedEtype, &cipher)) {
        return fail(kMalformed, QStringLiteral("the KRB-PRIV enc-part is malformed"));
    }

    // RFC 3244 §2: the user-data is sealed under the subsession key from the
    // authenticator, not under the service ticket's session key.
    QByteArray plain;
    if (!Krb5::decrypt(encryptedEtype, kKrbPrivUsage, result.contextKey, cipher, &plain))
        return fail(kAuthError, QStringLiteral("the KRB-PRIV does not open"));

    Asn1::Element part;
    Asn1::Element partSequence;
    if (!Asn1::parse(plain, &part) || part.tag != 0x7C
        || !Asn1::parse(part.value, &partSequence) || partSequence.tag != 0x30) {
        return fail(kMalformed, QStringLiteral("the KRB-PRIV plaintext is malformed"));
    }
    QByteArray userData;
    if (!readTaggedOctets(partSequence, 0xA0, &userData))
        return fail(kMalformed, QStringLiteral("the KRB-PRIV carries no password"));

    QByteArray newPassword;
    QString targetName;
    QString targetRealm;
    bool targetNamed = false;
    if (version == 0xff80) {
        // ChangePasswdData ::= SEQUENCE { newpasswd [0] OCTET STRING,
        //   targname [1] PrincipalName OPTIONAL, targrealm [2] Realm OPTIONAL }
        Asn1::Element data;
        if (!Asn1::parse(userData, &data) || data.tag != 0x30)
            return fail(kMalformed, QStringLiteral("ChangePasswdData is malformed"));
        if (!readTaggedOctets(data, 0xA0, &newPassword))
            return fail(kMalformed, QStringLiteral("ChangePasswdData names no password"));
        if (const Asn1::Element *nameField = Asn1::child(data, 0xA1)) {
            Asn1::Element principalName;
            if (!Asn1::parse(nameField->value, &principalName)
                || principalName.tag != 0x30) {
                return fail(kMalformed, QStringLiteral("targname is malformed"));
            }
            QStringList parts;
            if (const Asn1::Element *strings = Asn1::child(principalName, 0xA1)) {
                Asn1::Element sequenceOf;
                if (Asn1::parse(strings->value, &sequenceOf)) {
                    for (const Asn1::Element &item : sequenceOf.children) {
                        if (item.tag == 0x1B)
                            parts.append(QString::fromUtf8(item.value));
                    }
                }
            }
            targetName = parts.join(QLatin1Char('/'));
            targetNamed = !targetName.isEmpty();
        }
        const Asn1::Element *realmField = Asn1::child(data, 0xA2);
        if (realmField) {
            Asn1::Element realmValue;
            if (Asn1::parse(realmField->value, &realmValue) && realmValue.tag == 0x1B)
                targetRealm = QString::fromUtf8(realmValue.value);
        }
    } else {
        // Protocol version 1: the user-data is the password itself.
        newPassword = userData;
    }

    const Outcome outcome =
        changePassword(result.clientDn, result.clientPrincipal, newPassword, targetName,
                       targetRealm, targetNamed);

    // The AP-REP echoes the authenticator's time and sequence number, so the
    // client can verify it and knows which sequence number the reply's
    // KRB-PRIV will carry. RFC 4120 §5.5.2 seals the AP-REP under the ticket's
    // session key; only the KRB-PRIV moves to the subsession key.
    const int repEtype = result.sessionEtype != 0 ? result.sessionEtype : result.contextEtype;
    QByteArray repPart;
    repPart.append(Asn1::tlv(0xA0, Asn1::generalizedTime(0x18, result.ctime)));
    repPart.append(Asn1::tlv(0xA1, Asn1::integer(0x02, result.cusec)));
    repPart.append(Asn1::tlv(0xA3, Asn1::integer(0x02, result.clientSeq)));
    const QByteArray repSealed =
        Krb5::encrypt(repEtype, kApRepUsage, result.sessionKey,
                      Asn1::tlv(0x7B, Asn1::sequence(repPart)));
    QByteArray apRepContent;
    apRepContent.append(Asn1::tlv(0xA0, Asn1::integer(0x02, 5)));  // pvno
    apRepContent.append(Asn1::tlv(0xA1, Asn1::integer(0x02, 15))); // AP-REP
    apRepContent.append(Asn1::tlv(0xA2, encryptedData(repEtype, repSealed)));
    const QByteArray apRep = Asn1::tlv(0x6F, Asn1::sequence(apRepContent));

    const QByteArray replyPriv = resultPriv(result.contextKey, result.contextEtype,
                                            result.clientSeq, outcome.code, outcome.message);
    if (outcome.code == kSuccess) {
        emit requestReceived(
            tr("kpasswd changed the password of %1").arg(result.clientPrincipal));
    }
    return frame(apRep, replyPriv);
}

bool KpasswdServer::isAdministrator(const QString &clientDn) const
{
    if (!m_provider)
        return false;
    for (const DirectoryObject &object : m_provider()) {
        if (object.id.compare(clientDn, Qt::CaseInsensitive) != 0)
            continue;
        if (object.attributes.value(QStringLiteral("sAMAccountName"))
                .compare(QLatin1String("Administrator"), Qt::CaseInsensitive)
            == 0)
            return true;
        for (const QString &group : object.memberOf) {
            if (group.compare(QLatin1String("Domain Admins"), Qt::CaseInsensitive) == 0)
                return true;
        }
    }
    return false;
}

KpasswdServer::Outcome KpasswdServer::changePassword(const QString &clientDn,
                                                     const QString &clientPrincipal,
                                                     const QByteArray &newPassword,
                                                     const QString &targetName,
                                                     const QString &targetRealm, bool targetNamed)
{
    if (newPassword.isEmpty())
        return {kSoftError, QStringLiteral("the new password is empty")};
    if (!targetRealm.isEmpty() && m_kdc
        && Krb5::canonicalRealm(targetRealm) != m_kdc->realm().realm) {
        return {kAccessDenied, QStringLiteral("the realm %1 is not served here").arg(targetRealm)};
    }

    QString targetDn;
    if (targetNamed) {
        if (!m_provider)
            return {kHardError, QStringLiteral("the directory is not available")};
        QStringList spns;
        for (const DirectoryObject &object : m_provider()) {
            if (!targetName.contains(QLatin1Char('/'))) {
                if (object.attributes.value(QStringLiteral("sAMAccountName"))
                        .compare(targetName, Qt::CaseInsensitive)
                    == 0) {
                    targetDn = object.id;
                    break;
                }
            } else {
                for (const QString &spn : Krb5::servicePrincipalNames(object)) {
                    if (spn.compare(targetName, Qt::CaseInsensitive) == 0) {
                        targetDn = object.id;
                        break;
                    }
                }
                if (!targetDn.isEmpty())
                    break;
            }
        }
        if (targetDn.isEmpty())
            return {kAuthError, QStringLiteral("there is no account named %1").arg(targetName)};
        if (targetDn.compare(clientDn, Qt::CaseInsensitive) != 0 && !isAdministrator(clientDn)) {
            return {kAccessDenied,
                    QStringLiteral("%1 may not set another account's password")
                        .arg(clientPrincipal)};
        }
    } else {
        if (clientDn.isEmpty())
            return {kAuthError, QStringLiteral("the client principal has no account")};
        targetDn = clientDn;
    }

    QString error;
    if (!m_writer || !m_writer(targetDn, QString::fromUtf8(newPassword), &error)) {
        return {kSoftError,
                error.isEmpty() ? QStringLiteral("the password was refused") : error};
    }
    return {kSuccess, QString()};
}
