// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QDateTime>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QSemaphore>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QThread>

#include "Asn1.h"
#include "Gss.h"
#include "Kdc.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ntlm.h"
#include "Pac.h"
#include "Provisioner.h"

#ifdef MONARCHY_WITH_KRB5
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#include <cstring>
#endif

namespace {

// ---------- LDAP wire helpers ----------

void putLen(QByteArray &out, int len)
{
    if (len < 0x80) {
        out.append(char(len));
        return;
    }
    QByteArray tmp;
    int value = len;
    while (value > 0) {
        tmp.prepend(char(value & 0xff));
        value >>= 8;
    }
    out.append(char(0x80 | tmp.size()));
    out.append(tmp);
}

void putTLV(QByteArray &out, quint8 tag, const QByteArray &value)
{
    out.append(char(tag));
    putLen(out, value.size());
    out.append(value);
}

void putInt(QByteArray &out, quint8 tag, int value)
{
    QByteArray body;
    if (value == 0) {
        body.append('\0');
    } else {
        int v = value;
        while (v > 0) {
            body.prepend(char(v & 0xff));
            v >>= 8;
        }
        if (body.at(0) & 0x80)
            body.prepend('\0');
    }
    putTLV(out, tag, body);
}

bool takeTLV(const QByteArray &data, int &pos, quint8 *tag, QByteArray *value)
{
    if (pos >= data.size())
        return false;
    *tag = quint8(data.at(pos++));
    if (pos >= data.size())
        return false;
    int len = quint8(data.at(pos++));
    if (len & 0x80) {
        const int bytes = len & 0x7f;
        if (bytes == 0 || pos + bytes > data.size())
            return false;
        len = 0;
        for (int i = 0; i < bytes; ++i)
            len = (len << 8) | quint8(data.at(pos++));
    }
    if (len < 0 || pos + len > data.size())
        return false;
    *value = data.mid(pos, len);
    pos += len;
    return true;
}

QByteArray saslBindRequest(int msgId, const QByteArray &token, const QByteArray &mechanism)
{
    QByteArray sasl;
    putTLV(sasl, 0x04, mechanism);
    putTLV(sasl, 0x04, token);

    QByteArray inner;
    putInt(inner, 0x02, 3);
    putTLV(inner, 0x04, QByteArray());
    putTLV(inner, 0x83, sasl);

    QByteArray msg;
    putInt(msg, 0x02, msgId);
    putTLV(msg, 0x60, inner);
    QByteArray packet;
    putTLV(packet, 0x30, msg);
    return packet;
}

struct BindReply {
    int resultCode = -1;
    QByteArray saslCreds;
    bool parsed = false;
};

BindReply exchange(QTcpSocket &socket, const QByteArray &request, int timeoutMs = 4000)
{
    BindReply reply;
    socket.write(request);
    socket.flush();

    QByteArray buffer;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        buffer += socket.readAll();
        int pos = 0;
        quint8 tag = 0;
        QByteArray body;
        if (!takeTLV(buffer, pos, &tag, &body)) {
            if (!socket.waitForReadyRead(20))
                continue;
            continue;
        }
        if (tag != 0x30)
            continue;
        int inner = 0;
        quint8 itag = 0;
        QByteArray ignored;
        QByteArray op;
        if (!takeTLV(body, inner, &itag, &ignored))
            continue;
        if (!takeTLV(body, inner, &itag, &op))
            continue;
        if (itag != 0x61)
            continue;
        int opos = 0;
        quint8 ftag = 0;
        QByteArray code;
        if (!takeTLV(op, opos, &ftag, &code))
            continue;
        reply.resultCode = code.isEmpty() ? 0 : quint8(code.at(0));
        while (opos < op.size()) {
            quint8 partTag = 0;
            QByteArray part;
            if (!takeTLV(op, opos, &partTag, &part))
                break;
            if (partTag == 0x87)
                reply.saslCreds = part;
        }
        reply.parsed = true;
        return reply;
    }
    return reply;
}

// ---------- AS-REQ builder (unconditional protocol test) ----------

QByteArray principalDer(const QString &name)
{
    QList<QByteArray> parts;
    for (const QString &part : name.split(QLatin1Char('/')))
        parts.append(Asn1::string(0x1B, part));
    QByteArray content;
    content.append(Asn1::tlv(0xA0, Asn1::integer(0x02, 1)));
    content.append(Asn1::tlv(0xA1, Asn1::sequenceOf(parts)));
    return Asn1::sequence(content);
}

QByteArray asReq(const QString &realm, const QString &user)
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QByteArray body;
    body.append(Asn1::tlv(0xA0, Asn1::bits(0x03, 0x40000000))); // forwardable
    body.append(Asn1::tlv(0xA1, principalDer(user)));
    body.append(Asn1::tlv(0xA2, Asn1::string(0x1B, realm)));
    body.append(Asn1::tlv(0xA3, principalDer(QStringLiteral("krbtgt/") + realm)));
    body.append(Asn1::tlv(0xA5, Asn1::generalizedTime(0x18, now + 3600)));
    body.append(Asn1::tlv(0xA7, Asn1::integer(0x02, 42)));
    body.append(Asn1::tlv(0xA8, Asn1::sequence(Asn1::integer(0x02, Krb5::kRc4Hmac))));

    QByteArray request;
    request.append(Asn1::tlv(0xA1, Asn1::integer(0x02, 5)));
    request.append(Asn1::tlv(0xA2, Asn1::integer(0x02, 10))); // AS-REQ
    request.append(Asn1::tlv(0xA4, Asn1::sequence(body)));
    return Asn1::tlv(0x6A, Asn1::sequence(request));
}

// One request/reply over the KDC's TCP transport (length-prefixed).
QByteArray kdcExchange(quint16 port, const QByteArray &request)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, port);
    if (!socket.waitForConnected(3000))
        return {};
    QByteArray framed;
    framed.append(char((request.size() >> 24) & 0xff));
    framed.append(char((request.size() >> 16) & 0xff));
    framed.append(char((request.size() >> 8) & 0xff));
    framed.append(char(request.size() & 0xff));
    framed.append(request);
    socket.write(framed);
    socket.flush();

    QByteArray buffer;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 4000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        buffer += socket.readAll();
        if (buffer.size() >= 4) {
            const int length = (int(quint8(buffer.at(0))) << 24)
                               | (int(quint8(buffer.at(1))) << 16)
                               | (int(quint8(buffer.at(2))) << 8)
                               | int(quint8(buffer.at(3)));
            if (buffer.size() >= 4 + length)
                return buffer.mid(4, length);
        }
        if (!socket.waitForReadyRead(20))
            continue;
    }
    return {};
}

int krbErrorCode(const QByteArray &reply)
{
    Asn1::Element outer;
    if (!Asn1::parse(reply, &outer) || outer.tag != 0x7E)
        return -1;
    Asn1::Element sequence;
    if (!Asn1::parse(outer.value, &sequence) || sequence.tag != 0x30)
        return -1;
    const Asn1::Element *code = Asn1::child(sequence, 0xA6);
    if (!code)
        return -1;
    Asn1::Element inner;
    if (!Asn1::parse(code->value, &inner) || inner.tag != 0x02)
        return -1;
    return int(Asn1::toInteger(inner));
}

// ---------- SPNEGO wrapping ----------

QByteArray spnegoInitToken(const QByteArray &gssToken)
{
    QByteArray mechTypes = Asn1::sequenceOf(
        {Asn1::objectIdentifier(QStringLiteral("1.2.840.113554.1.2.2"))});
    QByteArray init;
    init.append(Asn1::tlv(0xA0, mechTypes));                    // mechTypes
    init.append(Asn1::tlv(0xA2, Asn1::octets(0x04, gssToken))); // mechToken

    QByteArray content = Asn1::objectIdentifier(QStringLiteral("1.3.6.1.5.5.2"));
    content.append(Asn1::tlv(0xA0, Asn1::sequence(init)));
    return Asn1::tlv(0x60, content);
}

// Pulls responseToken out of a NegTokenResp for the next GSSAPI step.
QByteArray spnegoResponseToken(const QByteArray &token)
{
    Asn1::Element outer;
    if (!Asn1::parse(token, &outer))
        return {};
    for (const Asn1::Element &child : outer.children) {
        if (child.tag != 0xA1) // negTokenResp
            continue;
        Asn1::Element response;
        if (!Asn1::parse(child.value, &response) || response.tag != 0x30)
            continue;
        const Asn1::Element *responseToken = Asn1::child(response, 0xA2);
        if (!responseToken)
            continue;
        Asn1::Element octets;
        int used = 0;
        if (Asn1::parse(responseToken->value, &octets, &used) && octets.tag == 0x04)
            return octets.value;
    }
    return {};
}

// ---------- Provisioned realm fixture ----------

// The KDC serves UDP and TCP, which needs a running event loop. A test that
// calls the blocking MIT krb5 client in the main thread therefore hosts the
// KDC in its own thread; the console hosts it in the application loop.
class KdcService : public QThread
{
public:
    KerberosRealmConfig config;
    QList<DirectoryObject> objects;
    quint16 port = 0;
    QSemaphore ready;

    ~KdcService() override
    {
        quit();
        wait(5000);
    }

protected:
    void run() override
    {
        Kdc kdc;
        kdc.setRealm(config);
        kdc.setObjects(objects);
        port = kdc.listen(0) ? kdc.serverPort() : 0;
        ready.release();
        exec();
    }
};

struct Fixture {
    QTemporaryDir dir;
    ProvisionResult provisioned;
    // Enctypes published to the MIT client (and therefore used for its tickets).
    QStringList enctypes{QStringLiteral("rc4-hmac")};
    LdapServer *server = nullptr;
    Kdc *kdc = nullptr;
    KdcService *service = nullptr;
    QString confPath;
    QString ccache;

    ~Fixture()
    {
        delete service;
        delete server;
        delete kdc;
    }

    // Provisioning and serving are separate so a test can change the directory
    // (for example disable an account) before the KDC reads it.
    bool provision()
    {
        if (!dir.isValid())
            return false;
        ProvisionConfig config;
        config.realm = QStringLiteral("CORP.EXAMPLE.COM");
        config.netbiosDomain = QStringLiteral("CORP");
        config.adminPassword = QStringLiteral("Str0ng-Pass!");
        config.targetDir = dir.path();
        provisioned = provisionDomain(config);
        if (!provisioned.ok)
            return false;

        server = new LdapServer;
        return server->loadFromFile(provisioned.storePath);
    }

    bool startServices()
    {
        if (!server)
            return false;

        KerberosRealmConfig realm;
        realm.realm = QStringLiteral("CORP.EXAMPLE.COM");
        realm.netbios = QStringLiteral("CORP");
        realm.domainSid = provisioned.domainSid;
        realm.dcHost = provisioned.dcHost;

        // Acceptor in this thread: verifies service tickets for LDAP binds.
        kdc = new Kdc;
        kdc->setRealm(realm);
        kdc->setObjectProvider([this]() { return server->objects(); });
        server->setKdc(kdc);
        if (!server->listen(0))
            return false;

        // KDC service in its own thread: answers kinit/TGS requests.
        service = new KdcService;
        service->config = realm;
        service->objects = server->objects();
        service->start();
        service->ready.acquire();
        if (service->port == 0)
            return false;

        confPath = dir.path() + QStringLiteral("/krb5-test.conf");
        QFile conf(confPath);
        if (!conf.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return false;
        const QString list = enctypes.join(QLatin1Char(' '));
        const QString contents =
            QStringLiteral("[libdefaults]\n"
                           "    default_realm = CORP.EXAMPLE.COM\n"
                           "    dns_lookup_kdc = false\n"
                           "    dns_lookup_realm = false\n"
                           "    allow_weak_crypto = true\n"
                           "    default_tkt_enctypes = %1\n"
                           "    default_tgs_enctypes = %1\n"
                           "    permitted_enctypes = %1\n"
                           "\n"
                           "[realms]\n"
                           "    CORP.EXAMPLE.COM = {\n"
                           "        kdc = 127.0.0.1:%2\n"
                           "    }\n"
                           "\n"
                           "[domain_realm]\n"
                           "    .corp.example.com = CORP.EXAMPLE.COM\n"
                           "    corp.example.com = CORP.EXAMPLE.COM\n")
                .arg(list)
                .arg(service->port);
        conf.write(contents.toUtf8());
        conf.close();

        ccache = dir.path() + QStringLiteral("/ccache");
        qputenv("KRB5_CONFIG", confPath.toUtf8());
        qputenv("KRB5CCNAME", QStringLiteral("FILE:").append(ccache).toUtf8());
        return true;
    }

    bool start()
    {
        return provision() && startServices();
    }
};

#ifdef MONARCHY_WITH_KRB5

QString krb5Error(krb5_context context, krb5_error_code code)
{
    const char *message = krb5_get_error_message(context, code);
    const QString text = QString::fromUtf8(message);
    krb5_free_error_message(context, message);
    return text;
}

bool kinitUser(const QString &principal, const QString &password, QString *error)
{
    krb5_context context = nullptr;
    if (krb5_init_context(&context) != 0) {
        if (error)
            *error = QStringLiteral("krb5_init_context failed");
        return false;
    }
    bool ok = false;
    krb5_principal name = nullptr;
    krb5_creds creds;
    memset(&creds, 0, sizeof(creds));
    krb5_ccache ccache = nullptr;

    krb5_error_code code = krb5_parse_name(context, principal.toUtf8().constData(), &name);
    if (code != 0) {
        if (error)
            *error = krb5Error(context, code);
    } else {
        code = krb5_get_init_creds_password(context, &creds, name,
                                            password.toUtf8().constData(), nullptr, nullptr, 0,
                                            nullptr, nullptr);
        if (code != 0) {
            if (error)
                *error = krb5Error(context, code);
        } else if (krb5_cc_default(context, &ccache) == 0
                   && krb5_cc_initialize(context, ccache, name) == 0
                   && krb5_cc_store_cred(context, ccache, &creds) == 0) {
            ok = true;
        } else if (error) {
            *error = QStringLiteral("cannot store the credential cache");
        }
    }

    if (ccache)
        krb5_cc_close(context, ccache);
    krb5_free_principal(context, name);
    krb5_free_cred_contents(context, &creds);
    krb5_free_context(context);
    return ok;
}

struct GssClient {
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_name_t target = GSS_C_NO_NAME;
    gss_cred_id_t credential = GSS_C_NO_CREDENTIAL;
    OM_uint32 flags = 0;

    ~GssClient()
    {
        OM_uint32 minor = 0;
        if (context != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
        if (target != GSS_C_NO_NAME)
            gss_release_name(&minor, &target);
        if (credential != GSS_C_NO_CREDENTIAL)
            gss_release_cred(&minor, &credential);
    }
};

QString gssError(OM_uint32 major, OM_uint32 minor)
{
    OM_uint32 ignored = 0;
    gss_buffer_desc text = GSS_C_EMPTY_BUFFER;
    gss_display_status(&ignored, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &ignored, &text);
    QString message = QString::fromUtf8(static_cast<const char *>(text.value),
                                        qsizetype(text.length));
    gss_release_buffer(&ignored, &text);
    gss_display_status(&ignored, minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &ignored, &text);
    if (text.length > 0)
        message += QStringLiteral(" / ")
                   + QString::fromUtf8(static_cast<const char *>(text.value),
                                       qsizetype(text.length));
    gss_release_buffer(&ignored, &text);
    return message;
}

bool gssStart(GssClient *client, const QString &servicePrincipal, QByteArray *token,
              QString *error)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    const QByteArray spn = servicePrincipal.toUtf8();
    gss_buffer_desc nameBuffer;
    nameBuffer.value = const_cast<char *>(spn.constData());
    nameBuffer.length = size_t(spn.size());
    major = gss_import_name(&minor, &nameBuffer, GSS_KRB5_NT_PRINCIPAL_NAME, &client->target);
    if (major != GSS_S_COMPLETE) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_INITIATE,
                             &client->credential, nullptr, nullptr);
    if (major != GSS_S_COMPLETE) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    const OM_uint32 requested =
        GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_REPLAY_FLAG;
    major = gss_init_sec_context(&minor, client->credential, &client->context, client->target,
                                 GSS_C_NO_OID, requested, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, nullptr, &output, &client->flags, nullptr);
    if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    if (token) {
        *token = QByteArray(static_cast<const char *>(output.value), int(output.length));
        gss_release_buffer(&minor, &output);
    }
    return true;
}

bool gssStep(GssClient *client, const QByteArray &input, QByteArray *output, QString *error)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc in;
    in.value = const_cast<char *>(input.constData());
    in.length = size_t(input.size());
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
    const OM_uint32 requested =
        GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_REPLAY_FLAG;
    major = gss_init_sec_context(&minor, client->credential, &client->context, client->target,
                                 GSS_C_NO_OID, requested, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                 &in, nullptr, &out, &client->flags, nullptr);
    if (output)
        *output = QByteArray(static_cast<const char *>(out.value), int(out.length));
    gss_release_buffer(&minor, &out);
    if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    return true;
}

bool gssWrapClient(GssClient *client, const QByteArray &data, int confidentiality,
                   QByteArray *token, int *confState, QString *error)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc in;
    in.value = const_cast<char *>(data.constData());
    in.length = size_t(data.size());
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
    int state = 0;
    major = gss_wrap(&minor, client->context, confidentiality, GSS_C_QOP_DEFAULT, &in, &state, &out);
    if (major != GSS_S_COMPLETE) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    *token = QByteArray(static_cast<const char *>(out.value), int(out.length));
    gss_release_buffer(&minor, &out);
    if (confState)
        *confState = state;
    return true;
}

bool gssUnwrapClient(GssClient *client, const QByteArray &token, QByteArray *data,
                     int *confState, QString *error)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc in;
    in.value = const_cast<char *>(token.constData());
    in.length = size_t(token.size());
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
    int state = 0;
    gss_qop_t qop = 0;
    major = gss_unwrap(&minor, client->context, &in, &out, &state, &qop);
    if (major != GSS_S_COMPLETE) {
        if (error)
            *error = gssError(major, minor);
        return false;
    }
    *data = QByteArray(static_cast<const char *>(out.value), int(out.length));
    gss_release_buffer(&minor, &out);
    if (confState)
        *confState = state;
    return true;
}

// ---------- Wrapped LDAP session (RFC 4752 security layer) ----------

QByteArray searchRequest(int msgId, const QString &base)
{
    QByteArray inner;
    putTLV(inner, 0x04, base.toUtf8());
    putInt(inner, 0x0A, 2);                    // scope: wholeSubtree
    putInt(inner, 0x0A, 0);                    // derefAliases: never
    putInt(inner, 0x02, 0);                    // sizeLimit
    putInt(inner, 0x02, 0);                    // timeLimit
    putTLV(inner, 0x01, QByteArray(1, '\0'));  // typesOnly FALSE
    putTLV(inner, 0x87, QByteArrayLiteral("objectClass")); // present filter
    putTLV(inner, 0x30, QByteArray());         // attributes: all

    QByteArray message;
    putInt(message, 0x02, msgId);
    putTLV(message, 0x63, inner);
    QByteArray packet;
    putTLV(packet, 0x30, message);
    return packet;
}

QByteArray modifyRequest(int msgId, const QString &dn, const QString &attribute,
                         const QString &value)
{
    QByteArray values;
    putTLV(values, 0x04, value.toUtf8());
    QByteArray modification;
    putTLV(modification, 0x04, attribute.toUtf8());
    putTLV(modification, 0x31, values); // vals: SET OF

    QByteArray change;
    putInt(change, 0x0A, 2); // replace
    putTLV(change, 0x30, modification);

    QByteArray inner;
    putTLV(inner, 0x04, dn.toUtf8());
    putTLV(inner, 0x30, change); // changes: SEQUENCE OF

    QByteArray message;
    putInt(message, 0x02, msgId);
    putTLV(message, 0x66, inner);
    QByteArray packet;
    putTLV(packet, 0x30, message);
    return packet;
}

// Reads one LDAPMessage and returns its resultCode, or -1.
int readResultCode(QTcpSocket &socket, int timeoutMs = 4000)
{
    QElapsedTimer timer;
    timer.start();
    QByteArray buffer;
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        buffer += socket.readAll();
        int pos = 0;
        quint8 tag = 0;
        QByteArray body;
        if (takeTLV(buffer, pos, &tag, &body) && tag == 0x30) {
            int inner = 0;
            QByteArray ignored;
            QByteArray operation;
            quint8 innerTag = 0;
            if (takeTLV(body, inner, &innerTag, &ignored)
                && takeTLV(body, inner, &innerTag, &operation)) {
                int opPos = 0;
                quint8 fieldTag = 0;
                QByteArray code;
                if (takeTLV(operation, opPos, &fieldTag, &code))
                    return code.isEmpty() ? 0 : quint8(code.at(0));
            }
        }
        socket.waitForReadyRead(20);
    }
    return -1;
}

// kinit + GSSAPI bind, leaving the socket authenticated without a layer.
bool gssBindAs(Fixture &fixture, const QString &user, const QString &password,
               QTcpSocket *socket, QString *error)
{
    if (!kinitUser(user, password, error))
        return false;

    GssClient client;
    QByteArray token;
    if (!gssStart(&client, QStringLiteral("ldap/%1@CORP.EXAMPLE.COM")
                               .arg(fixture.provisioned.dcHost),
                  &token, error))
        return false;
    socket->connectToHost(QHostAddress::LocalHost, fixture.server->serverPort());
    if (!socket->waitForConnected(3000)) {
        if (error)
            *error = QStringLiteral("cannot connect to the directory");
        return false;
    }

    const BindReply challenge = exchange(*socket, saslBindRequest(1, token, "GSSAPI"));
    if (!challenge.parsed || challenge.resultCode != 14) {
        if (error)
            *error = QStringLiteral("the AP-REQ was not accepted");
        return false;
    }
    QByteArray continuation;
    if (!gssStep(&client, challenge.saslCreds, &continuation, error))
        return false;

    const BindReply offer = exchange(*socket, saslBindRequest(2, QByteArray(), "GSSAPI"));
    if (!offer.parsed || offer.resultCode != 14) {
        if (error)
            *error = QStringLiteral("no security-layer offer");
        return false;
    }
    const BindReply done = exchange(*socket, saslBindRequest(3, QByteArray("\x01\x00\x00\x00", 4),
                                                            "GSSAPI"));
    if (!done.parsed || done.resultCode != 0) {
        if (error)
            *error = QStringLiteral("the Kerberos bind failed (rc %1)").arg(done.resultCode);
        return false;
    }
    return true;
}

// One length-prefixed SASL buffer from the socket.
QByteArray readSaslFrame(QTcpSocket &socket, int timeoutMs = 4000)
{
    QElapsedTimer timer;
    timer.start();
    QByteArray raw;
    while (timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        raw += socket.readAll();
        if (raw.size() >= 4) {
            const quint32 length = (quint32(quint8(raw.at(0))) << 24)
                                   | (quint32(quint8(raw.at(1))) << 16)
                                   | (quint32(quint8(raw.at(2))) << 8)
                                   | quint32(quint8(raw.at(3)));
            if (raw.size() >= 4 + int(length))
                return raw.mid(4, int(length));
        }
        socket.waitForReadyRead(20);
    }
    return {};
}

QByteArray saslFrame(const QByteArray &token)
{
    QByteArray frame;
    frame.append(char((token.size() >> 24) & 0xff));
    frame.append(char((token.size() >> 16) & 0xff));
    frame.append(char((token.size() >> 8) & 0xff));
    frame.append(char(token.size() & 0xff));
    frame.append(token);
    return frame;
}

// Establishes a GSSAPI context against the directory and then drives LDAP over
// the confidentiality layer, so both the negotiation and the per-message tokens
// are exercised by real MIT GSSAPI code.
bool runWrappedLdapSession(Fixture &fixture, QString *error)
{
    if (!kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                   QStringLiteral("Str0ng-Pass!"), error))
        return false;

    GssClient client;
    QByteArray token;
    if (!gssStart(&client, QStringLiteral("ldap/%1@CORP.EXAMPLE.COM")
                               .arg(fixture.provisioned.dcHost),
                  &token, error))
        return false;
    if (!(client.flags & GSS_C_CONF_FLAG)) {
        if (error)
            *error = QStringLiteral("the context did not negotiate confidentiality");
        return false;
    }

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, fixture.server->serverPort());
    if (!socket.waitForConnected(3000)) {
        if (error)
            *error = QStringLiteral("cannot connect to the directory");
        return false;
    }

    const BindReply challenge = exchange(socket, saslBindRequest(1, token, "GSSAPI"));
    if (!challenge.parsed || challenge.resultCode != 14) {
        if (error)
            *error = QStringLiteral("the AP-REQ was not accepted (rc %1)").arg(challenge.resultCode);
        return false;
    }
    QByteArray continuation;
    if (!gssStep(&client, challenge.saslCreds, &continuation, error))
        return false;

    const BindReply offer = exchange(socket, saslBindRequest(2, QByteArray(), "GSSAPI"));
    if (!offer.parsed || offer.resultCode != 14 || offer.saslCreds.size() != 4
        || quint8(offer.saslCreds.at(0)) != 0x07) {
        if (error)
            *error = QStringLiteral("the server did not offer the security layers");
        return false;
    }

    QByteArray wrappedId;
    if (!gssWrapClient(&client, QByteArray(4, '\0'), 1, &wrappedId, nullptr, error))
        return false;
    QByteArray selection;
    selection.append(char(0x04)); // confidentiality
    selection.append("\x00\xff\xff", 3);
    selection.append(wrappedId);

    const BindReply done = exchange(socket, saslBindRequest(3, selection, "GSSAPI"));
    if (!done.parsed || done.resultCode != 0) {
        if (error)
            *error = QStringLiteral("the layer selection was refused (rc %1)")
                         .arg(done.resultCode);
        return false;
    }
    QByteArray serverId;
    int confState = 0;
    if (done.saslCreds.isEmpty()
        || !gssUnwrapClient(&client, done.saslCreds, &serverId, &confState, error))
        return false;
    if (!confState || serverId.size() != 4) {
        if (error)
            *error = QStringLiteral("the server's authorization id was not wrapped");
        return false;
    }

    // Everything from here on is sealed with the negotiated context.
    QByteArray sealedRequest;
    if (!gssWrapClient(&client, searchRequest(4, fixture.provisioned.baseDn), 1,
                       &sealedRequest, nullptr, error))
        return false;
    socket.write(saslFrame(sealedRequest));
    socket.flush();

    const QByteArray replyToken = readSaslFrame(socket);
    if (replyToken.isEmpty()) {
        if (error)
            *error = QStringLiteral("no wrapped search response");
        return false;
    }
    QByteArray plain;
    if (!gssUnwrapClient(&client, replyToken, &plain, &confState, error))
        return false;
    if (!confState || !plain.contains(fixture.provisioned.baseDn.toUtf8())) {
        if (error)
            *error = QStringLiteral("the wrapped search returned unexpected data");
        return false;
    }
    return true;
}

// The trust account a two-realm test needs: the shared key, plus the attributes
// the KDC reads to decide the direction of the trust and which realm it is with.
void addTrust(LdapServer &server, const QString &localRealm, const QString &peerRealm,
              const QString &peerNetbios, const QString &password)
{
    DirectoryObject trust;
    trust.id = QStringLiteral("CN=krbtgt_%1,CN=System,%2")
                   .arg(peerNetbios, realmToBaseDn(localRealm));
    trust.name = QStringLiteral("krbtgt_") + peerNetbios;
    trust.type = QStringLiteral("Trusted Domain");
    trust.kind = ObjectKind::Container;
    trust.container = QStringLiteral("Console Root");
    trust.attributes.insert(QStringLiteral("sAMAccountName"),
                            QStringLiteral("krbtgt_%1$").arg(peerNetbios));
    trust.attributes.insert(QStringLiteral("trustPartner"), peerRealm);
    trust.attributes.insert(QStringLiteral("trustDirection"), QStringLiteral("3")); // both
    trust.attributes.insert(QStringLiteral("trustType"), QStringLiteral("2"));
    trust.attributes.insert(QStringLiteral("trustAttributes"), QStringLiteral("64"));
    trust.attributes.insert(QStringLiteral("servicePrincipalName"),
                            QStringLiteral("krbtgt/") + peerRealm);
    trust.attributes.insert(QStringLiteral("msDS-KeyVersionNumber"), QStringLiteral("1"));
    Krb5::storeTrustKeys(trust, password, localRealm, peerRealm);
    server.addObject(trust);
}

#endif // MONARCHY_WITH_KRB5

} // namespace

class KerberosTest : public QObject
{
    Q_OBJECT

private slots:
    void rc4HmacRoundTrip();
    void knownStringToKey();
    void asReqRequiresPreauth();
    void unknownAccountIsRejected();
    void aesEtypesRoundTrip();
    void aesStringToKeyVectors();
    void dceRpcFraming();
    void pacIsSignedAndVerifiable();
#ifdef MONARCHY_WITH_KRB5
    void pacVerifiesWithMitKrb5();
    void kerberosBindOverLdap();
    void spnegoKerberosBind();
    void wrappedLdapSessionRc4();
    void wrappedLdapSessionAes();
    void pacAuthorizesWrites();
    void rejectsWrongPassword();
    void rejectsDisabledAccount();
    void rejectsUnknownService();
    void crossRealmTrust();
#endif
};

void KerberosTest::rc4HmacRoundTrip()
{
    const QByteArray key = QByteArray::fromHex("ac8e657f83df82beea5d43bdaf7800cc");
    const QByteArray plaintext = QByteArrayLiteral("Monarchy Kerberos ticket payload");

    for (const int usage : {1, 2, 8, 11, 12}) {
        const QByteArray cipher = Krb5::encrypt(usage, key, plaintext);
        QCOMPARE(cipher.size(), plaintext.size() + 24);
        QByteArray recovered;
        QVERIFY(Krb5::decrypt(usage, key, cipher, &recovered));
        QCOMPARE(recovered, plaintext);

        // The usage is part of the key derivation: a different one must fail.
        QByteArray ignored;
        QVERIFY(!Krb5::decrypt(usage + 1, key, cipher, &ignored));

        // A flipped ciphertext octet must fail the HMAC check.
        QByteArray tampered = cipher;
        tampered[tampered.size() - 1] = char(tampered.at(tampered.size() - 1) ^ 0x01);
        QVERIFY(!Krb5::decrypt(usage, key, tampered, &ignored));
    }

    // Two encryptions of the same plaintext differ (random confounder) but both
    // decrypt, and the checksum primitive is deterministic.
    QVERIFY(Krb5::encrypt(2, key, plaintext) != Krb5::encrypt(2, key, plaintext));
    QCOMPARE(Krb5::checksum(15, key, plaintext), Krb5::checksum(15, key, plaintext));
}

void KerberosTest::knownStringToKey()
{
    // RFC 4757 §2: String2Key("foo").
    QCOMPARE(Ntlm::ntowfV1(QStringLiteral("foo")).toHex(),
             QByteArray("ac8e657f83df82beea5d43bdaf7800cc"));
}

void KerberosTest::asReqRequiresPreauth()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    const QByteArray reply =
        kdcExchange(fixture.service->port,
                    asReq(QStringLiteral("CORP.EXAMPLE.COM"), QStringLiteral("Administrator")));
    QVERIFY(!reply.isEmpty());
    QCOMPARE(krbErrorCode(reply), 25); // KDC_ERR_PREAUTH_REQUIRED

    // The error carries METHOD-DATA with an ETYPE-INFO2 entry for RC4-HMAC.
    Asn1::Element outer;
    QVERIFY(Asn1::parse(reply, &outer));
    Asn1::Element sequence;
    QVERIFY(Asn1::parse(outer.value, &sequence));
    const Asn1::Element *eData = Asn1::child(sequence, 0xAC);
    QVERIFY(eData);
    Asn1::Element octets;
    QVERIFY(Asn1::parse(eData->value, &octets) && octets.tag == 0x04);
    QVERIFY(octets.value.size() > 16);
    // PA-ETYPE-INFO2 (19) and PA-PW-SALT (3) are both advertised.
    QVERIFY(octets.value.contains(QByteArray::fromHex("a103020113")));
    QVERIFY(octets.value.contains(QByteArray::fromHex("a103020103")));
}

void KerberosTest::unknownAccountIsRejected()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    const QByteArray reply =
        kdcExchange(fixture.service->port,
                    asReq(QStringLiteral("CORP.EXAMPLE.COM"), QStringLiteral("nosuchuser")));
    QVERIFY(!reply.isEmpty());
    QCOMPARE(krbErrorCode(reply), 6); // KDC_ERR_C_PRINCIPAL_UNKNOWN
}

#ifdef MONARCHY_WITH_KRB5

void KerberosTest::kerberosBindOverLdap()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    QString error;
    QVERIFY2(kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                       QStringLiteral("Str0ng-Pass!"), &error),
             qPrintable(error));

    GssClient client;
    QByteArray token;
    QVERIFY2(gssStart(&client, QStringLiteral("ldap/%1@CORP.EXAMPLE.COM")
                                    .arg(fixture.provisioned.dcHost),
                      &token, &error),
             qPrintable(error));
    QVERIFY(!token.isEmpty());

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, fixture.server->serverPort());
    QVERIFY(socket.waitForConnected(3000));

    const BindReply challenge = exchange(socket, saslBindRequest(1, token, "GSSAPI"));
    QVERIFY(challenge.parsed);
    QCOMPARE(challenge.resultCode, 14); // saslBindInProgress
    QVERIFY(!challenge.saslCreds.isEmpty());

    // The AP-REP must complete mutual authentication in the real GSSAPI stack.
    QByteArray continuation;
    QVERIFY2(gssStep(&client, challenge.saslCreds, &continuation, &error), qPrintable(error));
    QVERIFY(client.flags & GSS_C_MUTUAL_FLAG);

    const BindReply offer = exchange(socket, saslBindRequest(2, QByteArray(), "GSSAPI"));
    QVERIFY(offer.parsed);
    QCOMPARE(offer.resultCode, 14);
    QCOMPARE(offer.saslCreds.size(), 4);

    const BindReply done = exchange(socket, saslBindRequest(3, QByteArray("\x01\x00\x00\x00", 4),
                                                           "GSSAPI"));
    QVERIFY(done.parsed);
    QCOMPARE(done.resultCode, 0);
}

void KerberosTest::spnegoKerberosBind()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    QString error;
    QVERIFY2(kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                       QStringLiteral("Str0ng-Pass!"), &error),
             qPrintable(error));

    GssClient client;
    QByteArray token;
    QVERIFY2(gssStart(&client, QStringLiteral("ldap/%1@CORP.EXAMPLE.COM")
                                    .arg(fixture.provisioned.dcHost),
                      &token, &error),
             qPrintable(error));

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, fixture.server->serverPort());
    QVERIFY(socket.waitForConnected(3000));

    const BindReply challenge =
        exchange(socket, saslBindRequest(1, spnegoInitToken(token), "GSS-SPNEGO"));
    QVERIFY(challenge.parsed);
    QCOMPARE(challenge.resultCode, 14);

    // The NegTokenResp carries the GSSAPI AP-REP the krb5 mech expects.
    const QByteArray apRep = spnegoResponseToken(challenge.saslCreds);
    QVERIFY(!apRep.isEmpty());
    QByteArray continuation;
    QVERIFY2(gssStep(&client, apRep, &continuation, &error), qPrintable(error));
    QVERIFY(client.flags & GSS_C_MUTUAL_FLAG);

    const BindReply offer = exchange(socket, saslBindRequest(2, QByteArray(), "GSS-SPNEGO"));
    QCOMPARE(offer.resultCode, 14);
    const BindReply done =
        exchange(socket, saslBindRequest(3, QByteArray("\x01\x00\x00\x00", 4), "GSS-SPNEGO"));
    QVERIFY(done.parsed);
    QCOMPARE(done.resultCode, 0);
}

void KerberosTest::wrappedLdapSessionRc4()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    QString error;
    QVERIFY2(runWrappedLdapSession(fixture, &error), qPrintable(error));
}

void KerberosTest::wrappedLdapSessionAes()
{
    Fixture fixture;
    fixture.enctypes = {QStringLiteral("aes256-cts-hmac-sha1-96")};
    QVERIFY(fixture.start());

    QString error;
    QVERIFY2(runWrappedLdapSession(fixture, &error), qPrintable(error));
}

void KerberosTest::pacAuthorizesWrites()
{
    Fixture fixture;
    QVERIFY(fixture.provision());

    // A plain domain user: same password machinery as provisioning, but the
    // PAC only carries Domain Users.
    DirectoryObject jane;
    jane.id = QStringLiteral("CN=Jane Smith,CN=Users,%1").arg(fixture.provisioned.baseDn);
    jane.name = QStringLiteral("Jane Smith");
    jane.type = QStringLiteral("User");
    jane.container = QStringLiteral("Users");
    jane.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("jsmith"));
    jane.attributes.insert(QStringLiteral("objectSid"),
                           fixture.provisioned.domainSid + QStringLiteral("-1105"));
    jane.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    fixture.server->addObject(jane);

    const QString password = QStringLiteral("Str0ng-Pass!");
    LdapServer::ModifyChange setPassword;
    setPassword.operation = 2;
    setPassword.type = QStringLiteral("unicodePwd");
    setPassword.values = QStringList{password};
    setPassword.rawValue = password.toUtf8();
    QCOMPARE(fixture.server->applyModify(jane.id, {setPassword}), 0);

    QVERIFY(fixture.startServices());

    QString error;
    // The standard user can authenticate, but the PAC has no admin group, so
    // the directory refuses to let the session write.
    QTcpSocket janeSocket;
    QVERIFY2(gssBindAs(fixture, QStringLiteral("jsmith@CORP.EXAMPLE.COM"), password,
                       &janeSocket, &error),
             qPrintable(error));
    janeSocket.write(modifyRequest(10, jane.id, QStringLiteral("description"),
                                  QStringLiteral("written by jsmith")));
    janeSocket.flush();
    QCOMPARE(readResultCode(janeSocket), 50); // insufficientAccessRights

    // Domain Admins comes through the PAC, so the same request is allowed.
    QTcpSocket adminSocket;
    QVERIFY2(gssBindAs(fixture, QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                       QStringLiteral("Str0ng-Pass!"), &adminSocket, &error),
             qPrintable(error));
    adminSocket.write(modifyRequest(11, jane.id, QStringLiteral("description"),
                                   QStringLiteral("written by the admin")));
    adminSocket.flush();
    QCOMPARE(readResultCode(adminSocket), 0);
}

void KerberosTest::rejectsWrongPassword()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    QString error;
    QVERIFY(!kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                       QStringLiteral("Wrong-Pass!"), &error));
    QVERIFY(!error.isEmpty());
}

void KerberosTest::rejectsDisabledAccount()
{
    Fixture fixture;
    QVERIFY(fixture.provision());

    const QString adminDn = QStringLiteral("CN=Administrator,CN=Users,%1")
                                .arg(fixture.provisioned.baseDn);
    LdapServer::ModifyChange disable;
    disable.operation = 2;
    disable.type = QStringLiteral("userAccountControl");
    disable.values = QStringList{QStringLiteral("514")};
    QCOMPARE(fixture.server->applyModify(adminDn, {disable}), 0);
    QVERIFY(fixture.startServices());

    QString error;
    QVERIFY(!kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                       QStringLiteral("Str0ng-Pass!"), &error));
}

void KerberosTest::rejectsUnknownService()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    QString error;
    QVERIFY(kinitUser(QStringLiteral("Administrator@CORP.EXAMPLE.COM"),
                      QStringLiteral("Str0ng-Pass!"), &error));

    GssClient client;
    QByteArray token;
    QVERIFY(!gssStart(&client, QStringLiteral("vault/%1@CORP.EXAMPLE.COM")
                                   .arg(fixture.provisioned.dcHost),
                      &token, &error));
    QVERIFY(!error.isEmpty());
}

void KerberosTest::crossRealmTrust()
{
    QTemporaryDir dirA;
    QTemporaryDir dirB;
    QVERIFY(dirA.isValid() && dirB.isValid());

    ProvisionConfig configA;
    configA.realm = QStringLiteral("ALPHA.EXAMPLE.COM");
    configA.netbiosDomain = QStringLiteral("ALPHA");
    configA.adminPassword = QStringLiteral("Str0ng-Pass!");
    configA.targetDir = dirA.path();
    const ProvisionResult alpha = provisionDomain(configA);
    QVERIFY2(alpha.ok, qPrintable(alpha.error));

    ProvisionConfig configB;
    configB.realm = QStringLiteral("BETA.EXAMPLE.COM");
    configB.netbiosDomain = QStringLiteral("BETA");
    configB.adminPassword = QStringLiteral("Str0ng-Pass!");
    configB.targetDir = dirB.path();
    const ProvisionResult beta = provisionDomain(configB);
    QVERIFY2(beta.ok, qPrintable(beta.error));

    LdapServer serverA;
    LdapServer serverB;
    QVERIFY(serverA.loadFromFile(alpha.storePath));
    QVERIFY(serverB.loadFromFile(beta.storePath));

    // One shared secret, applied to both directories: that is the trust.
    const QString trustSecret = QStringLiteral("Trust-Pass!2000");
    addTrust(serverA, QStringLiteral("ALPHA.EXAMPLE.COM"), QStringLiteral("BETA.EXAMPLE.COM"),
             QStringLiteral("BETA"), trustSecret);
    addTrust(serverB, QStringLiteral("BETA.EXAMPLE.COM"), QStringLiteral("ALPHA.EXAMPLE.COM"),
             QStringLiteral("ALPHA"), trustSecret);

    KerberosRealmConfig realmA;
    realmA.realm = QStringLiteral("ALPHA.EXAMPLE.COM");
    realmA.netbios = QStringLiteral("ALPHA");
    realmA.domainSid = alpha.domainSid;
    realmA.dcHost = alpha.dcHost;

    KerberosRealmConfig realmB;
    realmB.realm = QStringLiteral("BETA.EXAMPLE.COM");
    realmB.netbios = QStringLiteral("BETA");
    realmB.domainSid = beta.domainSid;
    realmB.dcHost = beta.dcHost;

    // BETA serves LDAP and accepts the AP-REQs its own KDC issues.
    Kdc kdcB;
    kdcB.setRealm(realmB);
    kdcB.setObjectProvider([&serverB]() { return serverB.objects(); });
    QVERIFY(serverB.listen(0));
    serverB.setKdc(&kdcB);

    KdcService serviceA;
    serviceA.config = realmA;
    serviceA.objects = serverA.objects();
    serviceA.start();
    serviceA.ready.acquire();
    KdcService serviceB;
    serviceB.config = realmB;
    serviceB.objects = serverB.objects();
    serviceB.start();
    serviceB.ready.acquire();
    QVERIFY(serviceA.port != 0 && serviceB.port != 0);

    // One client configuration naming both KDCs, so MIT itself walks the trust.
    const QString confPath = dirA.path() + QStringLiteral("/krb5-cross.conf");
    QFile conf(confPath);
    QVERIFY(conf.open(QIODevice::WriteOnly | QIODevice::Truncate));
    conf.write(QStringLiteral("[libdefaults]\n"
                              "    default_realm = ALPHA.EXAMPLE.COM\n"
                              "    dns_lookup_kdc = false\n"
                              "    dns_lookup_realm = false\n"
                              "    allow_weak_crypto = true\n"
                              "    default_tkt_enctypes = rc4-hmac\n"
                              "    default_tgs_enctypes = rc4-hmac\n"
                              "    permitted_enctypes = rc4-hmac\n"
                              "\n"
                              "[realms]\n"
                              "    ALPHA.EXAMPLE.COM = {\n"
                              "        kdc = 127.0.0.1:%1\n"
                              "    }\n"
                              "    BETA.EXAMPLE.COM = {\n"
                              "        kdc = 127.0.0.1:%2\n"
                              "    }\n"
                              "\n"
                              "[capaths]\n"
                              "    ALPHA.EXAMPLE.COM = {\n"
                              "        BETA.EXAMPLE.COM = .\n"
                              "    }\n"
                              "    BETA.EXAMPLE.COM = {\n"
                              "        ALPHA.EXAMPLE.COM = .\n"
                              "    }\n")
                   .arg(serviceA.port)
                   .arg(serviceB.port)
                   .toUtf8());
    conf.close();

    const QByteArray previousConfig = qgetenv("KRB5_CONFIG");
    const QByteArray previousCache = qgetenv("KRB5CCNAME");
    qputenv("KRB5_CONFIG", confPath.toUtf8());
    qputenv("KRB5CCNAME", QByteArrayLiteral("FILE:") + dirA.path().toUtf8()
                              + QByteArrayLiteral("/ccache"));

    QString error;
    const bool kinit = kinitUser(QStringLiteral("Administrator@ALPHA.EXAMPLE.COM"),
                                 QStringLiteral("Str0ng-Pass!"), &error);
    QVERIFY2(kinit, qPrintable(error));

    // A service in BETA, held by a client whose realm is ALPHA: MIT asks ALPHA
    // for a referral, then BETA for the ticket.
    GssClient client;
    QByteArray token;
    const bool started = gssStart(
        &client, QStringLiteral("ldap/%1@BETA.EXAMPLE.COM").arg(beta.dcHost), &token, &error);

    if (previousConfig.isEmpty())
        qunsetenv("KRB5_CONFIG");
    else
        qputenv("KRB5_CONFIG", previousConfig);
    if (previousCache.isEmpty())
        qunsetenv("KRB5CCNAME");
    else
        qputenv("KRB5CCNAME", previousCache);

    QVERIFY2(started, qPrintable(error));
    QVERIFY(!token.isEmpty());

    // BETA verifies the cross-realm AP-REQ against its own service key and the
    // trust key's TGT, and answers with the mutual-auth token.
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, serverB.serverPort());
    QVERIFY(socket.waitForConnected(3000));
    const BindReply bind = exchange(socket, saslBindRequest(1, token, "GSSAPI"));
    QVERIFY(bind.parsed);
    QCOMPARE(bind.resultCode, 14); // saslBindInProgress: AP-REQ accepted
}

void KerberosTest::pacVerifiesWithMitKrb5()
{
    // Build the PAC with key blocks MIT itself made, so the test proves the
    // bytes and signatures against an independent implementation.
    krb5_context context = nullptr;
    QVERIFY(krb5_init_context(&context) == 0);
    krb5_keyblock serverKey;
    memset(&serverKey, 0, sizeof serverKey);
    krb5_keyblock kdcKey;
    memset(&kdcKey, 0, sizeof kdcKey);
    QVERIFY(krb5_c_make_random_key(context, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &serverKey) == 0);
    QVERIFY(krb5_c_make_random_key(context, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &kdcKey) == 0);

    Pac::Keys keys;
    keys.serviceKey =
        QByteArray(reinterpret_cast<const char *>(serverKey.contents), int(serverKey.length));
    keys.serviceEtype = Krb5::kAes256;
    keys.kdcKey =
        QByteArray(reinterpret_cast<const char *>(kdcKey.contents), int(kdcKey.length));
    keys.kdcEtype = Krb5::kAes256;

    DirectoryObject client;
    client.id = QStringLiteral("CN=Administrator,CN=Users,DC=corp,DC=example,DC=com");
    client.name = QStringLiteral("Administrator");
    client.type = QStringLiteral("User");
    client.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("Administrator"));
    client.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-500"));
    client.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));

    const qint64 authtime = QDateTime::currentSecsSinceEpoch();
    const QByteArray pac = Pac::build(client, QStringLiteral("CORP.EXAMPLE.COM"),
                                      QStringLiteral("CORP"), QStringLiteral("S-1-5-21-1-2-3"),
                                      {client}, keys, authtime);
    QVERIFY(!pac.isEmpty());

    krb5_pac parsed = nullptr;
    QVERIFY(krb5_pac_parse(context, pac.constData(), size_t(pac.size()), &parsed) == 0);
    krb5_principal principal = nullptr;
    QVERIFY(krb5_parse_name(context, "Administrator@CORP.EXAMPLE.COM", &principal) == 0);

    // The directory's own PAC carries the UPN/DNS buffer, and MIT can read it
    // back independently of the server's encoder.
    krb5_data upnDns;
    QVERIFY(krb5_pac_get_buffer(context, parsed, KRB5_PAC_UPN_DNS_INFO, &upnDns) == 0);
    QVERIFY(upnDns.length > 16);
    const quint32 upnLength = quint32(quint8(upnDns.data[0]))
                              | (quint32(quint8(upnDns.data[1])) << 8)
                              | (quint32(quint8(upnDns.data[2])) << 16)
                              | (quint32(quint8(upnDns.data[3])) << 24);
    const quint32 upnOffset = quint32(quint8(upnDns.data[4]))
                              | (quint32(quint8(upnDns.data[5])) << 8)
                              | (quint32(quint8(upnDns.data[6])) << 16)
                              | (quint32(quint8(upnDns.data[7])) << 24);
    QCOMPARE(upnLength, quint32(60)); // 30 UTF-16 code units
    QCOMPARE(upnOffset, quint32(16));
    QCOMPARE(QString::fromUtf16(reinterpret_cast<const char16_t *>(upnDns.data + upnOffset),
                                qsizetype(upnLength / 2)),
             QStringLiteral("Administrator@CORP.EXAMPLE.COM"));
    // krb5_free_data() frees the struct as well; this one lives on the stack.
    krb5_free_data_contents(context, &upnDns);

    const krb5_error_code rc =
        krb5_pac_verify(context, parsed, krb5_timestamp(authtime), principal, &serverKey, &kdcKey);
    const QString message = QString::fromUtf8(krb5_get_error_message(context, rc));
    krb5_free_principal(context, principal);
    krb5_pac_free(context, parsed);
    krb5_free_keyblock_contents(context, &serverKey);
    krb5_free_keyblock_contents(context, &kdcKey);
    krb5_free_context(context);
    QVERIFY2(rc == 0, qPrintable(QStringLiteral("krb5_pac_verify: %1 (%2)")
                                    .arg(rc)
                                    .arg(message)));
}

#endif // MONARCHY_WITH_KRB5

namespace {

// The initiator's half of a DCE/RPC token, which is what a request carries. A
// server only ever sends the acceptor half, so the test plays the client here:
// the ciphertext is one stream (confounder, data, header copy, checksum) with
// the header copy and checksum rotated in front of it (RFC 4121 §4.2.5, §7.1,
// the form Windows, Samba and impacket send).
void initiatorDceToken(const QByteArray &stub, quint64 seq, int etype, const QByteArray &key,
                       QByteArray *verifier, QByteArray *payload)
{
    QByteArray header;
    header.append(Gss::kCfxWrapTokenId);
    header.append(char(0x02 | 0x04)); // sealed, acceptor subkey, sent by the initiator
    header.append(char(0xff));
    header.append(QByteArray(2, '\0')); // EC: the stub is already aligned
    header.append(char(0));
    header.append(char(28)); // RRC
    for (int shift = 56; shift >= 0; shift -= 8)
        header.append(char((seq >> shift) & 0xff));

    QByteArray copy = header;
    copy[6] = char(0);
    copy[7] = char(0);

    const int kInitiatorSealUsage = 24;
    const QByteArray sealed = Krb5::encrypt(etype, kInitiatorSealUsage, key, stub + copy);
    const QByteArray rotated = sealed.right(28) + sealed.left(sealed.size() - 28);
    *verifier = header + rotated.left(28 + 16);
    *payload = rotated.mid(28 + 16);
}

} // namespace

void KerberosTest::dceRpcFraming()
{
    for (const int etype : {Krb5::kAes128, Krb5::kAes256}) {
        const QByteArray key = Krb5::randomKey(etype);
        QByteArray stub = QByteArrayLiteral("SAMR stub, padded to two blocks");
        stub.append(QByteArray(16 - (stub.size() % 16), '\0'));

        // What this side sends: the header, the encrypted copy of it, the
        // checksum and the confounder in the verifier, the ciphertext of the
        // data in the stub.
        const Gss::DceMessage sealed = Gss::dceSeal(stub, 7, etype, key);
        QVERIFY(!sealed.payload.isEmpty());
        QCOMPARE(sealed.payload.size(), stub.size());          // the stub keeps its size
        QCOMPARE(sealed.verifier.size(), 16 + 16 + 12 + 16);   // header, copy, checksum, confounder
        QCOMPARE(sealed.verifier.left(2), Gss::kCfxWrapTokenId);
        QCOMPARE(int(quint8(sealed.verifier.at(2))), 0x07);    // acceptor, sealed, subkey
        QCOMPARE(int(quint8(sealed.verifier.at(4))), 0);       // EC: the stub is already aligned
        // RRC: the encrypted header copy and the checksum rotate to the front.
        QCOMPARE((int(quint8(sealed.verifier.at(6))) << 8) | quint8(sealed.verifier.at(7)), 28);

        // What a client sends, and this side accepts.
        QByteArray verifier;
        QByteArray payload;
        initiatorDceToken(stub, 11, etype, key, &verifier, &payload);
        QByteArray plain;
        quint64 seq = 0;
        QVERIFY(Gss::dceUnseal(verifier, payload, etype, key, &plain, &seq));
        QCOMPARE(plain, stub);
        QCOMPARE(seq, quint64(11));

        // A tampered stub is not the ciphertext the checksum covers, and a
        // token sealed under another key does not open.
        QByteArray broken = payload;
        broken[0] = char(broken.at(0) ^ 0x01);
        QVERIFY(!Gss::dceUnseal(verifier, broken, etype, key, &plain, &seq));
        QVERIFY(!Gss::dceUnseal(verifier, payload, etype, Krb5::randomKey(etype), &plain, &seq));
        // A token this side produced is an acceptor token: it is never accepted
        // back, because requests carry the initiator's half.
        QVERIFY(!Gss::dceUnseal(sealed.verifier, sealed.payload, etype, key, &plain, &seq));

        // Integrity: a MIC covers the stub and nothing else.
        const QByteArray mic = Gss::dceMic(stub, 13, etype, key);
        QCOMPARE(mic.size(), 16 + 12);
        QVERIFY(!Gss::checkDceMic(mic, stub, etype, key, nullptr)); // also an acceptor token

        QByteArray clientMic;
        clientMic.append(Gss::kCfxMicTokenId);
        clientMic.append(char(0x04)); // acceptor subkey, sent by the initiator
        clientMic.append(char(0xff));
        clientMic.append(QByteArray(4, char(0xff))); // EC and RRC carry no meaning
        for (int shift = 56; shift >= 0; shift -= 8)
            clientMic.append(char((quint64(13) >> shift) & 0xff));
        const int kInitiatorSignUsage = 25;
        clientMic.append(Krb5::checksum(etype, kInitiatorSignUsage, key, stub + clientMic));
        quint64 micSeq = 0;
        QVERIFY(Gss::checkDceMic(clientMic, stub, etype, key, &micSeq));
        QCOMPARE(micSeq, quint64(13));
        QVERIFY(!Gss::checkDceMic(clientMic, stub + 'x', etype, key, &micSeq));
    }

    // RC4 has no CFX token, so the DCE framing declines it rather than
    // producing something a client cannot verify.
    QByteArray stub(16, '\0');
    QVERIFY(Gss::dceSeal(stub, 0, Krb5::kRc4Hmac, QByteArray(16, '\0')).verifier.isEmpty());

    // The SPNEGO reply wrapper round-trips, which is how a Kerberos AP-REP and
    // the closing token reach an RPC client.
    const QByteArray mechToken = QByteArrayLiteral("an AP-REP");
    const QByteArray response =
        Gss::spnegoResponse(0, QStringLiteral("1.2.840.113554.1.2.2"), mechToken);
    QCOMPARE(Gss::spnegoNegotiatedToken(response), mechToken);
    QCOMPARE(Gss::spnegoNegotiatedToken(Gss::gssEnvelope(response)), mechToken);
}

void KerberosTest::aesEtypesRoundTrip()
{
    for (const int etype : {Krb5::kAes128, Krb5::kAes256}) {
        const QByteArray key = Krb5::randomKey(etype);
        QCOMPARE(key.size(), Krb5::keySize(etype));
        for (const int usage : {1, 2, 3, 8, 11, 12}) {
            const QByteArray plaintext = QByteArrayLiteral("Monarchy AES ticket payload");
            const QByteArray cipher = Krb5::encrypt(etype, usage, key, plaintext);
            QCOMPARE(cipher.size(), plaintext.size() + 16 + 12);
            QByteArray recovered;
            QVERIFY(Krb5::decrypt(etype, usage, key, cipher, &recovered));
            QCOMPARE(recovered, plaintext);

            QByteArray ignored;
            QVERIFY(!Krb5::decrypt(etype, usage + 1, key, cipher, &ignored));
            QByteArray damaged = cipher;
            damaged[0] = char(damaged.at(0) ^ 0x01);
            QVERIFY(!Krb5::decrypt(etype, usage, key, damaged, &ignored));
        }
        const QByteArray data = QByteArrayLiteral("pac bytes");
        QCOMPARE(Krb5::checksum(etype, 17, key, data).size(), 12);
        QCOMPARE(Krb5::checksum(etype, 17, key, data),
                 Krb5::checksum(etype, 17, key, data));
    }
    // The AES key cannot be used as an RC4 key and vice versa.
    QVERIFY(Krb5::decrypt(Krb5::kRc4Hmac, 3, Krb5::randomKey(Krb5::kAes256),
                          Krb5::encrypt(Krb5::kAes256, 3, Krb5::randomKey(Krb5::kAes256),
                                        QByteArrayLiteral("x")),
                          nullptr)
            == false);
}

void KerberosTest::aesStringToKeyVectors()
{
    // RFC 3962 appendix B.
    struct Vector {
        int iterations;
        const char *salt;
        const char *aes128;
        const char *aes256;
    };
    const QList<Vector> vectors = {
        {1, "ATHENA.MIT.EDUraeburn", "42263c6e89f4fc28b8df68ee09799f15",
         "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
        {2, "ATHENA.MIT.EDUraeburn", "c651bf29e2300ac27fa469d693bdda13",
         "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
        {1200, "ATHENA.MIT.EDUraeburn", "4c01cd46d632d01e6dbe230a01ed642a",
         "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"}};

    for (const Vector &vector : vectors) {
        const QString salt = QString::fromLatin1(vector.salt);
        QCOMPARE(Krb5::stringToKey(Krb5::kAes128, QStringLiteral("password"), salt,
                                   vector.iterations)
                     .toHex(),
                 QByteArray(vector.aes128));
        QCOMPARE(Krb5::stringToKey(Krb5::kAes256, QStringLiteral("password"), salt,
                                   vector.iterations)
                     .toHex(),
                 QByteArray(vector.aes256));
    }
}

void KerberosTest::pacIsSignedAndVerifiable()
{
    DirectoryObject client;
    client.id = QStringLiteral("CN=Administrator,CN=Users,DC=corp,DC=example,DC=com");
    client.name = QStringLiteral("Administrator");
    client.type = QStringLiteral("User");
    client.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("Administrator"));
    client.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-500"));
    client.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));
    client.attributes.insert(QStringLiteral("pwdLastSet"),
                             QString::number(QDateTime::currentSecsSinceEpoch()));

    DirectoryObject admins;
    admins.id = QStringLiteral("CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com");
    admins.name = QStringLiteral("Domain Admins");
    admins.type = QStringLiteral("Group");
    admins.attributes.insert(QStringLiteral("objectSid"), QStringLiteral("S-1-5-21-1-2-3-512"));
    admins.members = {client.id};

    Pac::Keys keys;
    keys.serviceKey = Krb5::randomKey(Krb5::kAes256);
    keys.serviceEtype = Krb5::kAes256;
    keys.kdcKey = Krb5::randomKey(Krb5::kAes256);
    keys.kdcEtype = Krb5::kAes256;

    const QByteArray pac = Pac::build(client, QStringLiteral("CORP.EXAMPLE.COM"),
                                      QStringLiteral("CORP"), QStringLiteral("S-1-5-21-1-2-3"),
                                      {client, admins}, keys);
    QVERIFY(!pac.isEmpty());
    QVERIFY(Pac::verify(pac, keys));

    QByteArray tampered = pac;
    tampered[tampered.size() - 30] = char(tampered.at(tampered.size() - 30) ^ 0x01);
    QVERIFY(!Pac::verify(tampered, keys));

    Pac::Keys wrong = keys;
    wrong.serviceKey = Krb5::randomKey(Krb5::kAes256);
    QVERIFY(!Pac::verify(pac, wrong));

    const QByteArray wrapped = Pac::authorizationData(pac);
    QCOMPARE(Pac::extract(wrapped), pac);

    const QByteArray resigned = Pac::resign(pac, wrong);
    QVERIFY(!resigned.isEmpty());
    QVERIFY(Pac::verify(resigned, wrong));
}

QTEST_GUILESS_MAIN(KerberosTest)
#include "test_kerberos.moc"
