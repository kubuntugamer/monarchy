// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Rpc.h"

#include "Asn1.h"
#include "Gss.h"

#include <QStringList>

#include <QHostAddress>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QDebug>

#include <memory>

namespace {

// PDU types (DCE 1.1 §12.6.3.1).
enum : quint8 {
    PduRequest = 0,
    PduResponse = 2,
    PduFault = 3,
    PduBind = 11,
    PduBindAck = 12,
    PduBindNak = 13,
    PduAlterContext = 14,
    PduAlterContextResp = 15,
    PduAuth3 = 16
};

// Rejection reasons in a bind_ack result (DCE 1.1 §12.6.3.3).
enum : quint16 {
    ResultAcceptance = 0,
    ResultProviderRejection = 2,
    ReasonNotSupported = 1,
    ReasonTransferSyntaxesNotSupported = 2
};

enum : quint32 {
    FaultAccessDenied = 0x00000005u,
    FaultOpRangeError = 0x1c010002u,
    FaultProtoError = 0x1c010009u
};

// RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE and RPC_C_AUTHN_GSS_KERBEROS:
// the security providers AD endpoints see. Windows and Samba negotiate with
// SPNEGO even when the only mechanism on offer is NTLMSSP, so both have to be
// understood; a Kerberos bind arrives either as auth_type 16 (a bare AP-REQ)
// or as auth_type 9 with the Kerberos mechanism inside.
enum : quint8 {
    AuthTypeSpnego = 9,
    AuthTypeNtlm = 10,
    AuthTypeKerberos = 16
};

constexpr quint16 kMaxFrag = 4280;

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

quint16 readLe16(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(pos)) | (quint8(data.at(pos + 1)) << 8));
}

quint32 readLe32(const QByteArray &data, int pos)
{
    if (pos < 0 || pos + 4 > data.size())
        return 0;
    return quint32(quint8(data.at(pos))) | (quint32(quint8(data.at(pos + 1))) << 8)
           | (quint32(quint8(data.at(pos + 2))) << 16) | (quint32(quint8(data.at(pos + 3))) << 24);
}

// Whether a token is a Kerberos message with `tag` (an AP-REQ is 0x6E, an
// AP-REP 0x6F), bare or inside the GSS-API envelope a SPNEGO client may add.
// A SPNEGO NegTokenInit that lists Kerberos among several mechanisms but sends
// an NTLMSSP token has to fall through to the NTLMSSP path instead.
bool isKerberosMessage(const QByteArray &token, quint8 tag)
{
    QByteArray current = token;
    if (!current.isEmpty() && quint8(current.at(0)) == 0x60) {
        QByteArray inner;
        if (!Gss::stripGssEnvelope(current, &inner))
            return false;
        current = inner;
    }
    // The GSS-API framing in front of the message names it: 0x0100 for an
    // AP-REQ, 0x0200 for an AP-REP (RFC 4121 §4.1).
    if (current.size() >= 3
        && ((quint8(current.at(0)) == 0x01 && quint8(current.at(1)) == 0x00)
            || (quint8(current.at(0)) == 0x02 && quint8(current.at(1)) == 0x00)))
        current = current.mid(2);
    return !current.isEmpty() && quint8(current.at(0)) == tag;
}

void padTo4(QByteArray &out)
{
    while (out.size() % 4 != 0)
        out.append('\0');
}

// Common header: version, type, flags, data representation, lengths, call id.
void appendHeader(QByteArray &out, quint8 type, quint32 callId, quint16 authLength)
{
    out.append(char(5));    // rpc_vers
    out.append(char(0));    // rpc_vers_minor
    out.append(char(type)); // PTYPE
    out.append(char(0x03)); // PFC_FIRST_FRAG | PFC_LAST_FRAG
    out.append(char(0x10)); // little-endian integers and characters
    out.append(char(0));
    out.append(char(0));
    out.append(char(0));
    putLe16(out, 0); // frag_length, patched below
    putLe16(out, authLength);
    putLe32(out, callId);
}

void patchFragLength(QByteArray &pdu)
{
    const quint16 length = quint16(pdu.size());
    pdu[8] = char(length & 0xff);
    pdu[9] = char((length >> 8) & 0xff);
}

quint16 transferSyntaxVersion(const QByteArray &data, int pos)
{
    return readLe16(data, pos);
}

// A GSS-SPNEGO NegTokenResp (RFC 4178 §4.2.2) carrying an NTLMSSP message.
// Answering a NegTokenInit with this is what lets a Windows or Samba client
// continue the exchange; a bare NTLMSSP token would not be understood.
QByteArray spnegoResponse(const QByteArray &ntlmsspToken, quint8 negState)
{
    QByteArray fields;
    // negState: 0 accept-completed, 1 accept-incomplete (challenge sent).
    fields.append(Asn1::tlv(0xA0, Asn1::tlv(0x0A, QByteArray(1, char(negState)))));
    // supportedMech: one mechanism, NTLMSSP (1.3.6.1.4.1.311.2.2.10).
    fields.append(Asn1::tlv(0xA1, Asn1::objectIdentifier(
                                     QStringLiteral("1.3.6.1.4.1.311.2.2.10"))));
    if (!ntlmsspToken.isEmpty())
        fields.append(Asn1::tlv(0xA2, Asn1::octets(0x04, ntlmsspToken)));
    return Asn1::tlv(0xA1, Asn1::sequence(fields));
}

} // namespace

namespace Rpc {

const QByteArray kNdrSyntaxUuid =
    QByteArray::fromHex("04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60");
const QByteArray kNdrsSyntaxUuid =
    QByteArray::fromHex("33 05 71 71 ba be 37 84 84 09 9d 89 2b 89 6c 66");

} // namespace Rpc

RpcServer::RpcServer(QObject *parent) : QObject(parent) {}

RpcServer::~RpcServer()
{
    close();
}

void RpcServer::setInterface(const Rpc::Interface &interface, Rpc::Handler handler)
{
    m_interface = interface;
    m_handler = std::move(handler);
}

void RpcServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_authenticator = std::move(authenticator);
}

void RpcServer::setKerberosAcceptor(Rpc::KerberosAcceptor acceptor, Rpc::KerberosFinisher finisher)
{
    m_kerberosAcceptor = std::move(acceptor);
    m_kerberosFinisher = std::move(finisher);
}

void RpcServer::setDomainNames(const QString &domain, const QString &serverName,
                               const QString &dnsDomain)
{
    m_domain = domain;
    m_serverName = serverName;
    m_dnsDomain = dnsDomain;
}

RpcServer::Verifier RpcServer::splitVerifier(const QByteArray &pdu)
{
    Verifier verifier;
    verifier.bodyEnd = pdu.size();
    const quint16 authLength = readLe16(pdu, 10);
    if (authLength == 0 || pdu.size() < 24 + int(authLength))
        return verifier;
    const int trailerPos = pdu.size() - 8 - int(authLength);
    verifier.present = true;
    verifier.type = quint8(pdu.at(trailerPos));
    verifier.level = quint8(pdu.at(trailerPos + 1));
    verifier.padLength = quint8(pdu.at(trailerPos + 2));
    verifier.contextId = readLe32(pdu, trailerPos + 4);
    verifier.token = pdu.mid(trailerPos + 8, authLength);
    verifier.bodyEnd = qMax(0, trailerPos - int(verifier.padLength));
    return verifier;
}

void RpcServer::appendVerifier(QByteArray &pdu, const Client::Security &security, quint8 padLength,
                               const QByteArray &token)
{
    pdu.append(char(security.type));
    pdu.append(char(security.level));
    pdu.append(char(padLength));
    pdu.append(char(0));
    putLe32(pdu, security.contextId);
    pdu.append(token);
    patchFragLength(pdu);
}

bool RpcServer::listen(quint16 port, const QHostAddress &address)
{
    if (!m_server) {
        m_server = new QTcpServer(this);
        connect(m_server, &QTcpServer::newConnection, this, &RpcServer::onNewConnection);
    }
    if (!m_server->listen(address, port))
        return false;
    return true;
}

void RpcServer::Client::write(const QByteArray &data)
{
    if (sink) {
        sink(data);
        return;
    }
    if (socket)
        socket->write(data);
}

struct RpcServer::ChannelState {
    Client *client = nullptr;
    QByteArray out;
};

RpcServer::Channel::Channel() = default;

RpcServer::Channel::~Channel()
{
    if (m_state && m_state->client) {
        delete m_state->client;
        m_state->client = nullptr;
    }
}

QByteArray RpcServer::Channel::feed(const QByteArray &pdu)
{
    if (!m_state || !m_state->client || !m_server)
        return QByteArray();
    ChannelState *state = m_state.get();
    Client *client = state->client;
    state->out.clear();
    client->sink = [state](const QByteArray &data) { state->out.append(data); };
    m_server->handlePdu(client, pdu);
    client->sink = nullptr;
    QByteArray out = state->out;
    state->out.clear();
    return out;
}

QString RpcServer::Channel::user() const
{
    if (!m_state || !m_state->client)
        return QString();
    return m_state->client->security.user;
}

bool RpcServer::Channel::bound() const
{
    return m_state && m_state->client && m_state->client->assocGroup != 0;
}

void RpcServer::Channel::setTransportIdentity(const QString &user)
{
    if (!m_state || !m_state->client || user.isEmpty())
        return;
    Client *client = m_state->client;
    client->security.active = true;
    client->security.transportOnly = true;
    client->security.user = user;
    // Level 1 (connect) is what a transport that authenticates the connection
    // rather than each PDU reports; nothing is signed on this pipe.
    client->security.level = 1;
}

RpcServer::Channel *RpcServer::newChannel(const QString &peer)
{
    auto *channel = new Channel;
    channel->m_server = this;
    channel->m_state = std::make_unique<ChannelState>();
    channel->m_state->client = new Client;
    channel->m_state->client->peer = peer;
    return channel;
}

void RpcServer::close()
{
    for (Client *client : m_clients) {
        if (client->socket) {
            client->socket->disconnect(this);
            client->socket->abort();
            client->socket->deleteLater();
        }
        delete client;
    }
    m_clients.clear();
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
}

bool RpcServer::isListening() const
{
    return m_server && m_server->isListening();
}

quint16 RpcServer::serverPort() const
{
    return m_server ? m_server->serverPort() : 0;
}

void RpcServer::onNewConnection()
{
    while (m_server && m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();
        auto *client = new Client;
        client->socket = socket;
        client->peer = socket->peerAddress().toString();
        m_clients.append(client);
        connect(socket, &QTcpSocket::readyRead, this, &RpcServer::onReadyRead);
        connect(socket, &QTcpSocket::disconnected, this, &RpcServer::onDisconnected);
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC accepted peer=%s", client->peer.toUtf8().constData());
    }
}

void RpcServer::onReadyRead()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("RPC readyRead socket=%p", reinterpret_cast<void *>(socket));
    if (!socket)
        return;
    Client *client = nullptr;
    for (Client *candidate : m_clients) {
        if (candidate->socket == socket) {
            client = candidate;
            break;
        }
    }
    if (!client)
        return;

    client->buffer.append(socket->readAll());
    while (client->buffer.size() >= 16) {
        const quint16 fragLength = readLe16(client->buffer, 8);
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC read buffer=%lld frag=%u",
                     static_cast<long long>(client->buffer.size()),
                     static_cast<unsigned>(fragLength));
        if (fragLength < 16) {
            client->buffer.clear();
            socket->disconnectFromHost();
            return;
        }
        if (client->buffer.size() < fragLength)
            return; // wait for the rest of the fragment
        const QByteArray pdu = client->buffer.left(fragLength);
        client->buffer.remove(0, fragLength);
        handlePdu(client, pdu);
    }
}

void RpcServer::onDisconnected()
{
    auto *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    for (int i = 0; i < m_clients.size(); ++i) {
        if (m_clients[i]->socket == socket) {
            delete m_clients[i];
            m_clients.removeAt(i);
            break;
        }
    }
    socket->deleteLater();
}

void RpcServer::handlePdu(Client *client, const QByteArray &pdu)
{
    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
        qWarning("RPC pdu type=%u size=%d pdu=%s", quint8(pdu.at(2)), int(pdu.size()),
                 pdu.toHex().constData());
    const quint8 type = quint8(pdu.at(2));
    const quint32 callId = readLe32(pdu, 12);

    switch (type) {
    case PduBind:
    case PduAlterContext: {
        const bool alter = type == PduAlterContext;
        const QByteArray reply = handleBind(client, pdu, alter);
        if (client->canWrite() && !reply.isEmpty())
            client->write(reply);
        break;
    }
    case PduRequest: {
        if (!m_handler) {
            if (client->canWrite())
                client->write(faultPdu(callId, FaultProtoError));
            return;
        }
        const Verifier verifier = splitVerifier(pdu);
        const quint8 flags = quint8(pdu.at(3));
        int pos = 16;
        pos += 4;                                  // alloc_hint
        const quint16 contextId = readLe16(pdu, pos);
        pos += 2;
        const quint16 opnum = readLe16(pdu, pos);
        pos += 2;
        // PFC_FIRST_FRAG is 0x01, not an object-UUID marker, and the AD
        // management interfaces are context-bound, so no object UUID follows.
        Q_UNUSED(flags)
        // The signature is the last `token.size()` bytes; the sec_trailer sits
        // immediately in front of it, and the stub ends where the trailer starts.
        const int signatureOffset = verifier.present ? pdu.size() - verifier.token.size()
                                                     : pdu.size();
        const int sealedEnd = verifier.present ? signatureOffset - 8 : pdu.size();
        if (pos > sealedEnd) {
            if (client->canWrite())
                client->write(faultPdu(callId, FaultProtoError));
            return;
        }
        QByteArray stub = pdu.mid(pos, sealedEnd - pos);

        // With a security provider configured, nothing is served before a bind
        // has authenticated: an unauthenticated call is refused, not honoured.
        if ((m_authenticator || m_kerberosAcceptor) && !client->security.active) {
            if (client->canWrite())
                client->write(faultPdu(callId, FaultAccessDenied));
            return;
        }

        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC request auth active=%d level=%d verifier=%d token=%d stub=%d",
                     int(client->security.active), int(client->security.level),
                     int(verifier.present), int(verifier.token.size()), int(stub.size()));

        // An authenticated session must carry a verifier on every call: the
        // signature covers the PDU with its own field excluded (MS-RPCE §2.2.3.4,
        // with the NTLMSSP rules of MS-NLMP §3.4.5.2).
        if (client->security.active && !client->security.transportOnly) {
            if (!verifier.present && client->security.kerberos) {
                // A Kerberos context at connect level authenticates the bind
                // only; above that every call carries a token.
                if (client->security.level >= 2) {
                    if (client->canWrite())
                        client->write(faultPdu(callId, FaultProtoError));
                    return;
                }
            } else if (!verifier.present) {
                if (client->canWrite())
                    client->write(faultPdu(callId, FaultProtoError));
                return;
            }
            if (client->security.kerberos) {
                if (!verifyKerberosRequest(client, verifier, &stub)) {
                    emit requestReceived(
                        QStringLiteral("%1 refused: bad Kerberos token").arg(m_interface.name));
                    return;
                }
                stub.truncate(stub.size() - int(verifier.padLength));
            } else {
                // The signature covers the PDU as it was before sealing: the
                // sender signs the plaintext stub and only then ciphers it.
                // Unseal once, rebuild that form, and verify against it
                // (MS-RPCE §2.2.3.4).
                QByteArray plainStub = client->security.privacy
                                           ? client->security.recvSealer.apply(stub)
                                           : stub;
                QByteArray signedData = pdu.left(signatureOffset);
                if (client->security.privacy)
                    signedData.replace(pos, plainStub.size(), plainStub);
                const QByteArray expected = Ntlm::mac(client->security.keys.clientSigningKey,
                                                      client->security.recvSeq, signedData);
                const bool signatureOk =
                    verifier.token.size() == 16 && readLe32(verifier.token, 0) == 1
                    && readLe32(verifier.token, 12) == client->security.recvSeq
                    && Ntlm::secureEquals(expected, verifier.token.mid(4, 8));
                if (!signatureOk) {
                    if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
                        qWarning("RPC signature mismatch seq=%u expected=%s token=%s pdu=%s",
                                 client->security.recvSeq, expected.toHex().constData(),
                                 verifier.token.toHex().constData(), pdu.toHex().constData());
                    emit requestReceived(
                        QStringLiteral("%1 refused: bad signature").arg(m_interface.name));
                    return;
                }
                stub = plainStub;
                stub.truncate(stub.size() - int(verifier.padLength));
                ++client->security.recvSeq;
            }
        }

        Rpc::Call call;
        call.peer = client->peer;
        call.user = client->security.kerberos ? client->security.gss.user
                                              : client->security.user;
        call.contextId = contextId;
        call.opnum = opnum;
        call.stub = stub;
        // The interfaces that cipher their own payload (SAMR's password
        // buffers) key it off the session key: NTLM's exported key, or for
        // Kerberos the service ticket's session key (RFC 4120 §7.5.1).
        call.sessionKey = client->security.kerberos
                              ? client->security.gss.ticketKey
                              : client->security.keys.sessionBaseKey;
        emit requestReceived(QStringLiteral("%1 call %2 (opnum %3)")
                                 .arg(m_interface.name)
                                 .arg(callId)
                                 .arg(opnum));

        const QByteArray replyStub = m_handler(call);
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC reply opnum %u stub %s", opnum, replyStub.toHex().constData());
        if (!client->canWrite())
            return;

        // A reply carries a verifier when the call did. A Kerberos context at
        // connect level has none: the bind was the whole authentication.
        const bool signedReply = client->security.active && verifier.present;
        const bool kerberosReply = signedReply && client->security.kerberos;
        const bool tokenReply = kerberosReply ? client->security.level >= 2 : signedReply;

        // A Kerberos reply is sealed or signed with a GSS token of its own: the
        // stub pads to a whole block and the token replaces the NTLM signature.
        QByteArray payload = replyStub;
        int pad = 0;
        QByteArray kerberosToken;
        if (kerberosReply && tokenReply) {
            pad = (16 - (payload.size() % 16)) % 16;
            payload.append(QByteArray(pad, '\0'));
            if (client->security.privacy) {
                const Gss::DceMessage sealed =
                    Gss::dceSeal(payload, client->security.gss.sendSeq,
                                 client->security.gss.etype, client->security.gss.key);
                if (sealed.payload.size() != payload.size()) {
                    if (client->canWrite())
                        client->write(faultPdu(callId, FaultProtoError));
                    return;
                }
                payload = sealed.payload;
                kerberosToken = sealed.verifier;
            } else {
                kerberosToken = Gss::dceMic(payload, client->security.gss.sendSeq,
                                            client->security.gss.etype, client->security.gss.key);
            }
            if (kerberosToken.isEmpty()) {
                if (client->canWrite())
                    client->write(faultPdu(callId, FaultProtoError));
                return;
            }
            ++client->security.gss.sendSeq;
        } else if (tokenReply) {
            pad = (4 - (replyStub.size() % 4)) % 4;
            payload.append(QByteArray(pad, '\0'));
        }

        QByteArray response;
        appendHeader(response, PduResponse, callId,
                     quint16(kerberosReply ? kerberosToken.size()
                                           : (tokenReply ? 16 : 0)));
        putLe32(response, quint32(replyStub.size())); // alloc_hint
        putLe16(response, contextId);
        response.append(char(0)); // cancel_count
        response.append(char(0)); // reserved
        const int payloadStart = response.size();
        response.append(payload);
        if (kerberosReply) {
            appendVerifier(response, client->security, quint8(pad), kerberosToken);
        } else if (tokenReply) {
            appendVerifier(response, client->security, quint8(pad), QByteArray(16, '\0'));
            const int signatureOffset = response.size() - 16;
            QByteArray signature;
            putLe32(signature, 1);
            signature.append(Ntlm::mac(client->security.keys.serverSigningKey,
                                       client->security.sendSeq, response.left(signatureOffset)));
            putLe32(signature, client->security.sendSeq);
            response.replace(signatureOffset, 16, signature);
            // Sign the plaintext, then cipher it in place: the receiver
            // unseals first and verifies the same bytes we signed.
            if (client->security.privacy)
                response.replace(payloadStart, payload.size(),
                                 client->security.sendSealer.apply(payload));
            ++client->security.sendSeq;
        } else {
            patchFragLength(response);
        }
        client->write(response);
        break;
    }
    case PduAuth3:
        handleAuth3(client, pdu);
        break;
    default:
        break;
    }
}

void RpcServer::handleAuth3(Client *client, const QByteArray &pdu)
{
    const Verifier verifier = splitVerifier(pdu);
    if (!verifier.present)
        return;

    // A Kerberos client whose GSS state machine wanted a reply to its bind
    // sends the closing AP-REP as an AUTH3 instead of an alter_context.
    if (client->security.kerberos) {
        const QByteArray inner = Gss::spnegoNegotiatedToken(verifier.token);
        const QByteArray closing = inner.isEmpty() ? verifier.token : inner;
        if (isKerberosMessage(closing, 0x6F))
            finishKerberos(client, closing);
        return;
    }

    if (!m_authenticator || client->security.challenge.isEmpty())
        return;
    // The client answers inside the wrapper it used: SPNEGO keeps the NTLMSSP
    // AUTHENTICATE in a NegTokenResp, a raw NTLMSSP client sends it directly.
    const QByteArray token = verifier.type == AuthTypeSpnego
                                 ? Ntlm::embeddedToken(verifier.token)
                                 : verifier.token;
    if (Ntlm::messageType(token) != 3)
        return;

    if (!verifyAuthenticate(client, token, verifier.level))
        return;

    // A SPNEGO client is not finished when its AUTHENTICATE is accepted: its
    // GSS state machine still waits for the accept-completed NegTokenResp,
    // which an AUTH3 reply carries. Raw NTLMSSP needs no answer.
    if (verifier.type == AuthTypeSpnego && client->canWrite()) {
        const QByteArray accept = spnegoResponse(QByteArray(), 0);
        QByteArray reply;
        appendHeader(reply, PduAuth3, readLe32(pdu, 12), quint16(accept.size()));
        putLe32(reply, 0); // alloc_hint
        putLe16(reply, 0); // p_cont_id
        reply.append(char(0)); // cancel_count
        reply.append(char(0)); // reserved
        appendVerifier(reply, client->security, 0, accept);
        client->write(reply);
    }
}

QByteArray RpcServer::handleBind(Client *client, const QByteArray &pdu, bool alterContext)
{
    const quint32 callId = readLe32(pdu, 12);
    const quint16 maxXmit = readLe16(pdu, 16);
    const quint16 maxRecv = readLe16(pdu, 18);
    const quint32 assocGroup = readLe32(pdu, 20);
    const int count = quint8(pdu.at(24));
    const Verifier verifier = splitVerifier(pdu);

    // One result per presentation context, in the order they were offered.
    // Windows and Samba bind NDR32 and NDR64 in the same PDU and expect an
    // answer for each, so a single result is a protocol error to them; this
    // server speaks NDR32 only, which is the context it accepts.
    struct ContextResult {
        bool accepted = false;
        quint16 reason = ReasonNotSupported;
    };
    QList<ContextResult> results;
    int pos = 28;
    bool accepted = false;
    quint16 contextId = 0;
    for (int i = 0; i < count && pos + 24 <= verifier.bodyEnd; ++i) {
        const quint16 id = readLe16(pdu, pos);
        const int syntaxCount = quint8(pdu.at(pos + 2));
        pos += 4;
        const QByteArray abstractUuid = pdu.mid(pos, 16);
        const quint16 major = readLe16(pdu, pos + 16);
        const quint16 minor = readLe16(pdu, pos + 18);
        pos += 20;

        bool ndr32 = false;
        for (int s = 0; s < syntaxCount && pos + 20 <= pdu.size(); ++s) {
            if (pdu.mid(pos, 16) == Rpc::kNdrSyntaxUuid
                && transferSyntaxVersion(pdu, pos + 16) == 2)
                ndr32 = true;
            pos += 20;
        }
        // The AD management interfaces are published as 1.0, and clients that
        // predate that (and Samba's own tools) still bind them as 0.0; a DC
        // accepts both for SAMR/LSAD.
        const bool versionOk = (major == m_interface.major && minor == m_interface.minor)
                               || (major <= 1 && minor == 0);
        ContextResult result;
        if (abstractUuid != m_interface.uuid || !versionOk) {
            result.reason = ReasonNotSupported; // abstract syntax not supported
        } else if (!ndr32) {
            // NDR64 alone: the interface is known, the transfer syntax is not.
            result.reason = ReasonTransferSyntaxesNotSupported;
        } else {
            result.accepted = true;
            if (!accepted)
                contextId = id;
            accepted = true;
        }
        results.append(result);
    }

    const auto appendResults = [&results](QByteArray &reply) {
        reply.append(char(results.size()));
        reply.append(char(0));
        putLe16(reply, 0);
        for (const ContextResult &result : results) {
            putLe16(reply, result.accepted ? ResultAcceptance : ResultProviderRejection);
            putLe16(reply, result.accepted ? 0 : result.reason);
            reply.append(Rpc::kNdrSyntaxUuid);
            putLe16(reply, 2);
            putLe16(reply, 0);
        }
        padTo4(reply);
    };

    if (!alterContext) {
        if (accepted) {
            client->assocGroup = assocGroup != 0 ? assocGroup : 0x00000001u;
            emit requestReceived(QStringLiteral("%1 bind accepted (context %2)")
                                     .arg(m_interface.name)
                                     .arg(contextId));
        } else {
            emit requestReceived(QStringLiteral("%1 bind rejected").arg(m_interface.name));
        }
    }

    // NTLMSSP: the client's NEGOTIATE travels in the auth verifier and the
    // answer carries the CHALLENGE; the AUTHENTICATE that follows may arrive in
    // an AUTH3 PDU or in an alter_context, and both are answered in place. With
    // SPNEGO the NTLMSSP message sits inside an ASN.1 wrapper, and so does the
    // answer. Windows and Samba negotiate that way, raw-NTLMSSP clients do not.
    QByteArray authToken;

    // Kerberos: the AP-REQ travels in the bind (auth_type 16, or 9 with the
    // Kerberos mechanism inside) and the AP-REP goes back in the ack. A client
    // that already holds a context sends its closing AP-REP in an
    // alter_context, which completes mutual authentication.
    if (verifier.present && verifier.level != 0 && !client->security.active)
        authToken = acceptKerberosBind(client, verifier);
    else if (verifier.present && client->security.kerberos
             && client->security.awaitingFinal) {
        const QByteArray inner = Gss::spnegoNegotiatedToken(verifier.token);
        const QByteArray closing = inner.isEmpty() ? verifier.token : inner;
        if (isKerberosMessage(closing, 0x6F)
            && finishKerberos(client, closing) && verifier.type == AuthTypeSpnego)
            authToken = Gss::spnegoResponse(0, QStringLiteral("1.2.840.113554.1.2.2"),
                                            QByteArray());
    }

    const bool spnego = !authToken.isEmpty()
                        || (verifier.present && verifier.type == AuthTypeSpnego);
    const QByteArray presented =
        verifier.token.isEmpty()
            ? verifier.token
            : (spnego ? Ntlm::embeddedToken(verifier.token) : verifier.token);
    if (authToken.isEmpty() && !client->security.kerberos && verifier.present
        && verifier.level != 0 && m_authenticator && !presented.isEmpty()
        && (verifier.type == AuthTypeNtlm || spnego)) {
        client->security.type = verifier.type;
        client->security.contextId = verifier.contextId;
        const int messageType = Ntlm::messageType(presented);
        if (messageType == 1) {
            QByteArray challenge(8, '\0');
            for (int i = 0; i < 8; ++i)
                challenge[i] = char(QRandomGenerator::system()->generate() & 0xff);
            client->security.level = verifier.level;
            client->security.challenge = challenge;
            authToken = Ntlm::challengeToken(challenge, m_domain, m_serverName, m_dnsDomain);
            if (spnego)
                authToken = spnegoResponse(authToken, 1); // accept-incomplete
        } else if (messageType == 3 && verifyAuthenticate(client, presented, verifier.level)) {
            if (spnego)
                authToken = spnegoResponse(QByteArray(), 0); // accept-completed
        }
    }

    QByteArray reply;
    appendHeader(reply, alterContext ? PduAlterContextResp : PduBindAck, callId,
                 quint16(authToken.size()));
    putLe16(reply, qMin(maxXmit, kMaxFrag));
    putLe16(reply, qMin(maxRecv, kMaxFrag));
    putLe32(reply, alterContext ? assocGroup : client->assocGroup);
    reply.append(char(0)); // sec_addr_len: no secondary address for TCP
    padTo4(reply);
    appendResults(reply);
    if (!authToken.isEmpty())
        appendVerifier(reply, client->security, 0, authToken);
    else
        patchFragLength(reply);
    return reply;
}

QByteArray RpcServer::acceptKerberosBind(Client *client, const Verifier &verifier)
{
    if (!m_kerberosAcceptor || !verifier.present || verifier.level == 0)
        return {};

    // auth_type 16 carries the AP-REQ directly; auth_type 9 wraps it in a
    // SPNEGO NegTokenInit, and the answer has to go back the same way.
    bool spnego = false;
    QByteArray apReq;
    if (verifier.type == AuthTypeKerberos) {
        apReq = verifier.token;
    } else if (verifier.type == AuthTypeSpnego && Gss::carriesKerberos(verifier.token)) {
        apReq = Gss::kerberosToken(verifier.token);
        spnego = true;
    }
    if (!isKerberosMessage(apReq, 0x6E)) // not an AP-REQ: let the NTLMSSP path try
        return {};

    Rpc::KerberosContext context;
    QString error;
    if (!m_kerberosAcceptor(apReq, &context, &error)) {
        // A rejected bind does not authenticate the connection: the calls that
        // follow are refused, never served unauthenticated.
        client->security.rejected = true;
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC Kerberos bind refused: %s", qPrintable(error));
        emit requestReceived(QStringLiteral("%1 Kerberos bind refused: %2")
                                 .arg(m_interface.name, error));
        return {};
    }

    client->security.type = verifier.type;
    client->security.level = verifier.level;
    client->security.contextId = verifier.contextId;
    client->security.kerberos = true;
    client->security.active = true;
    client->security.privacy = verifier.level >= 6;
    client->security.user = context.user;
    client->security.gss = context;
    client->security.awaitingFinal = true;
    emit requestReceived(QStringLiteral("%1 authenticated as %2 (Kerberos, level %3)")
                             .arg(m_interface.name, context.user)
                             .arg(verifier.level));

    if (!spnego)
        return context.replyToken;
    return Gss::spnegoResponse(1, QStringLiteral("1.2.840.113554.1.2.2"), context.replyToken);
}

bool RpcServer::finishKerberos(Client *client, const QByteArray &token)
{
    if (!m_kerberosFinisher || !client->security.kerberos || !client->security.awaitingFinal)
        return false;

    QString error;
    if (!m_kerberosFinisher(token, client->security.gss, &error)) {
        if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
            qWarning("RPC Kerberos closing token refused: %s", qPrintable(error));
        // The context is only established once mutual authentication completes,
        // so a bad AP-REP costs the whole session.
        client->security.rejected = true;
        client->security.active = false;
        emit requestReceived(QStringLiteral("%1 Kerberos mutual authentication failed: %2")
                                 .arg(m_interface.name, error));
        return false;
    }
    client->security.awaitingFinal = false;
    emit requestReceived(QStringLiteral("%1 Kerberos context established for %2")
                             .arg(m_interface.name, client->security.user));
    return true;
}

bool RpcServer::verifyKerberosRequest(Client *client, const Verifier &verifier,
                                      QByteArray *stub)
{
    Client::Security &security = client->security;
    if (security.level < 2)
        return true; // the bind authenticated the connection; no per-PDU token

    if (!verifier.present || verifier.token.isEmpty())
        return false;

    quint64 seq = 0;
    if (security.privacy) {
        QByteArray sealed;
        if (!Gss::dceUnseal(verifier.token, *stub, security.gss.etype, security.gss.key, &sealed,
                            &seq)) {
            if (!qEnvironmentVariableIsEmpty("MONARCHY_RPC_TRACE"))
                qWarning("RPC Kerberos unseal failed: token=%s payload=%s",
                         verifier.token.toHex().constData(), stub->toHex().constData());
            return false;
        }
        if (seq != security.gss.recvSeq)
            return false;
        *stub = sealed;
    } else {
        if (!Gss::checkDceMic(verifier.token, *stub, security.gss.etype, security.gss.key, &seq))
            return false;
        if (seq != security.gss.recvSeq)
            return false;
    }
    ++security.gss.recvSeq;
    return true;
}

bool RpcServer::verifyAuthenticate(Client *client, const QByteArray &ntlmsspToken, quint8 level)
{
    Ntlm::Authenticate authenticate;
    if (!Ntlm::parseAuthenticate(ntlmsspToken, &authenticate))
        return false;

    Rpc::AuthRequest request;
    request.user = authenticate.user;
    request.domain = authenticate.domain;
    request.challenge = client->security.challenge;
    request.ntResponse = authenticate.ntResponse;
    request.flags = authenticate.flags;

    Ntlm::SessionKeys keys;
    if (!m_authenticator(request, &keys)) {
        // A failed AUTHENTICATE ends the session: serving the calls that follow
        // would be an authentication downgrade.
        client->security.rejected = true;
        client->security.challenge.clear();
        emit requestReceived(QStringLiteral("%1 authentication failed for %2")
                                 .arg(m_interface.name, authenticate.user));
        if (client->canWrite())
            client->socket->disconnectFromHost();
        return false;
    }

    client->security.keys = keys;
    client->security.user = authenticate.user;
    client->security.level = qMax(client->security.level, level);
    client->security.privacy = client->security.level >= 6;
    client->security.active = true;
    if (client->security.privacy) {
        client->security.recvSealer.reset(keys.clientSealingKey);
        client->security.sendSealer.reset(keys.serverSealingKey);
    }
    client->security.challenge.clear();
    emit requestReceived(QStringLiteral("%1 authenticated as %2 (level %3)")
                             .arg(m_interface.name, authenticate.user)
                             .arg(client->security.level));
    return true;
}

QByteArray RpcServer::faultPdu(quint32 callId, quint32 status)
{
    QByteArray fault;
    appendHeader(fault, PduFault, callId, 0);
    putLe32(fault, 0); // alloc_hint
    putLe16(fault, 0); // p_cont_id
    fault.append(char(0)); // cancel_count
    fault.append(char(0)); // reserved
    putLe32(fault, status);
    putLe32(fault, 0); // reserved
    patchFragLength(fault);
    return fault;
}
