// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Smb1.h"

#include "Gss.h"
#include "Ntlm.h"
#include "SmbPaths.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>

namespace {

const QString kNtlmMech = QStringLiteral("1.3.6.1.4.1.311.2.2.10");
const QString kKrb5Mech = QStringLiteral("1.2.840.113554.1.2.2");

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void putLe32(QByteArray &out, quint32 value)
{
    putLe16(out, quint16(value & 0xffff));
    putLe16(out, quint16((value >> 16) & 0xffff));
}

quint16 readLe16(const QByteArray &data, int at)
{
    if (at < 0 || at + 2 > data.size())
        return 0;
    return quint16(quint8(data.at(at))) | quint16(quint16(quint8(data.at(at + 1))) << 8);
}

quint32 readLe32(const QByteArray &data, int at)
{
    return quint32(readLe16(data, at)) | (quint32(readLe16(data, at + 2)) << 16);
}

QByteArray toUtf16Bytes(const QString &text)
{
    return QByteArray(reinterpret_cast<const char *>(text.utf16()), text.size() * 2);
}

QString fromUtf16(const QByteArray &bytes)
{
    return QString::fromUtf16(reinterpret_cast<const char16_t *>(bytes.constData()),
                              bytes.size() / 2);
}

quint64 fileTimeNow()
{
    // 100ns intervals since 1601-01-01.
    const qint64 unixMs = QDateTime::currentMSecsSinceEpoch();
    return quint64(unixMs + 11644473600000LL) * 10000ULL;
}

quint64 fileTime(const QDateTime &time)
{
    if (!time.isValid())
        return 0;
    return quint64(time.toMSecsSinceEpoch() + 11644473600000LL) * 10000ULL;
}

QByteArray nbtFrame(const QByteArray &message)
{
    QByteArray framed;
    framed.append(char(0));
    framed.append(char((message.size() >> 16) & 0xff));
    framed.append(char((message.size() >> 8) & 0xff));
    framed.append(char(message.size() & 0xff));
    framed.append(message);
    return framed;
}

// The fields of an NTLMSSP AUTHENTICATE the RPC authenticator verifies,
// read at the offsets MS-NLMP 2.2.1.3 defines.
// MS-NLMP 2.2.1.3 without credentials: no user and no NT response.
bool isNullSession(const QByteArray &token)
{
    const QByteArray ntlm = Ntlm::embeddedToken(token);
    if (Ntlm::messageType(ntlm) != 3 || ntlm.size() < 64)
        return false;
    const int lmLength = readLe16(ntlm, 12);
    return readLe16(ntlm, 20) == 0 && readLe16(ntlm, 36) == 0 && lmLength <= 1;
}

bool parseAuthenticate(const QByteArray &token, Rpc::AuthRequest *request,
                       QByteArray *encryptedSessionKey)
{
    const QByteArray ntlm = Ntlm::embeddedToken(token);
    if (Ntlm::messageType(ntlm) != 3)
        return false;
    const auto field = [&ntlm](int at) {
        const int length = readLe16(ntlm, at);
        const int offset = int(readLe32(ntlm, at + 4));
        if (length <= 0 || offset < 0 || offset + length > ntlm.size())
            return QByteArray();
        return ntlm.mid(offset, length);
    };
    request->ntResponse = field(20);
    request->lmResponse = field(12);
    request->domain = fromUtf16(field(28));
    request->user = fromUtf16(field(36));
    if (encryptedSessionKey)
        *encryptedSessionKey = field(40);
    request->flags = readLe32(ntlm, 60);
    return !request->user.isEmpty() && !request->ntResponse.isEmpty();
}

struct Header {
    quint8 command = 0;
    quint16 flags2 = 0;
    quint16 tid = 0;
    quint16 uid = 0;
    quint16 mid = 0;
    QByteArray words;
    QByteArray data;
    bool unicode = false;
    bool valid = false;
};

Header parseHeader(const QByteArray &message)
{
    Header header;
    if (message.size() < 35 || message.left(4) != QByteArray("\377SMB", 4))
        return header;
    header.valid = true;
    header.command = quint8(message.at(4));
    header.flags2 = readLe16(message, 10);
    header.tid = readLe16(message, 24);
    header.uid = readLe16(message, 28);
    header.mid = readLe16(message, 30);
    header.unicode = (header.flags2 & 0x8000) != 0;
    const int wordCount = quint8(message.at(32));
    const int dataAt = 35 + wordCount * 2;
    header.words = message.mid(33, wordCount * 2);
    if (message.size() >= dataAt)
        header.data = message.mid(dataAt, readLe16(message, dataAt - 2));
    return header;
}

} // namespace

namespace Smb1 {

Session::Session(QHash<QString, RpcServer *> pipes, Rpc::Authenticator authenticator,
                 QString domain, QString serverName, QString dnsDomain,
                 QHash<QString, QString> shares, int lmCompatibilityLevel)
    : m_pipes(std::move(pipes))
    , m_shares(std::move(shares))
    , m_authenticator(std::move(authenticator))
    , m_domain(std::move(domain))
    , m_serverName(std::move(serverName))
    , m_dnsDomain(std::move(dnsDomain))
    , m_lmCompatibilityLevel(lmCompatibilityLevel)
{
}

bool Session::isSmb1(const QByteArray &message)
{
    return message.size() >= 35 && message.left(4) == QByteArray("\377SMB", 4);
}

QString Session::refusalReason(const Rpc::AuthRequest &request) const
{
    // NTLMv2 is never refused by the level, so a refusal of one is about the
    // credential. A v1 answer is refused by the level only when it reaches 5,
    // and below that the level cannot be why the logon failed.
    if (!Ntlm::isNtlmv1Response(request.ntResponse))
        return QStringLiteral("ntlmv2 answer, which the level never refuses");
    if (!Ntlm::acceptsNtlmv1(m_lmCompatibilityLevel))
        return QStringLiteral("policy: lmCompatibilityLevel %1 refuses an NTLMv1 answer")
            .arg(m_lmCompatibilityLevel);
    return QStringLiteral("credential: lmCompatibilityLevel %1 accepts an NTLMv1 answer")
        .arg(m_lmCompatibilityLevel);
}

QString Session::stringAt(const QByteArray &data, int at) const
{
    if (at < 0 || at >= data.size())
        return QString();
    if (m_unicode) {
        QByteArray bytes;
        for (int i = at; i + 1 < data.size(); i += 2) {
            if (data.at(i) == '\0' && data.at(i + 1) == '\0')
                break;
            bytes.append(data.at(i));
            bytes.append(data.at(i + 1));
        }
        return fromUtf16(bytes);
    }
    QByteArray bytes;
    for (int i = at; i < data.size() && data.at(i) != '\0'; ++i)
        bytes.append(data.at(i));
    return QString::fromLatin1(bytes);
}

Session::SessionState *Session::sessionState(quint16 uid)
{
    const auto at = m_sessions.find(uid);
    return at == m_sessions.end() ? nullptr : &at.value();
}

const Session::SessionState *Session::sessionState(quint16 uid) const
{
    const auto at = m_sessions.constFind(uid);
    return at == m_sessions.constEnd() ? nullptr : &at.value();
}

QByteArray Session::reply(const QByteArray &request, quint32 status, const QByteArray &words,
                          const QByteArray &data, int uid, int tid, bool sign)
{
    QByteArray out;
    out.append("\377SMB", 4);
    out.append(char(readLe16(request, 4))); // command, echoed
    putLe32(out, status);
    const quint8 flags = quint8(readLe16(request, 6) & 0x18) | 0x80;
    out.append(char(flags));
    // FLAGS2 is echoed so Unicode, long names and NT status stay on. The
    // signature bit is set only on a reply that actually carries one: before a
    // session key exists there is nothing to sign with, and a client that did
    // not sign its own requests must not be answered with a signature it will
    // not check.
    // The key, the identity and the counter belong to the session the request
    // names, not to the connection: a Windows 2000 member signs its machine
    // channel and its user session with two different keys over one socket.
    // A reply that opens a session names it with the UID argument, so the
    // session whose key and number this answer spends is that one: the request
    // carried no session of its own (UID 0), and looking only at the request
    // found none and numbered nothing.
    const quint16 replyUid = uid >= 0 ? quint16(uid) : readLe16(request, 28);
    SessionState *session = sessionState(replyUid);
    const bool signedReply = sign && m_signingActive && session
                             && session->authenticated && !session->key.isEmpty();
    putLe16(out, quint16((readLe16(request, 10) & ~0x0004) | (signedReply ? 0x0004 : 0)));
    putLe16(out, 0);  // PID high
    out.append(QByteArray(8, '\0')); // signature, filled in below
    putLe16(out, 0);  // reserved
    putLe16(out, tid >= 0 ? quint16(tid) : readLe16(request, 24)); // TID
    putLe16(out, readLe16(request, 26)); // PID
    putLe16(out, replyUid); // UID
    putLe16(out, readLe16(request, 30)); // MID
    out.append(char(words.size() / 2));
    out.append(words);
    putLe16(out, quint16(data.size()));
    out.append(data);

    // SMB1 signing (MS-CIFS 3.2.4.1): the signature field holds a sequence
    // number, one counter per direction, and the MAC is MD5(session key ||
    // message with that number in the field), first eight bytes. The header is
    // final before the hash: a UID or TID written in afterwards would break the
    // signature the client is about to verify.
    if (signedReply) {
        QByteArray sequence;
        putLe32(sequence, session->signingSeq++);
        sequence.append(QByteArray(4, '\0'));
        out.replace(14, 8, sequence);
        QByteArray macInput = session->key;
        macInput.append(out);
        const QByteArray digest = QCryptographicHash::hash(macInput, QCryptographicHash::Md5);
        out.replace(14, 8, digest.left(8));
    } else if (session && session->authenticated && !session->key.isEmpty()) {
        // A message without a MAC still occupies its number. The session setup
        // answer hands out the key and is deliberately sent unsigned, but the
        // setup exchange is numbered all the same — the request took the number
        // before it and this answer takes the next one — so the client's first
        // post-setup message is 2. Skipping this bump left the two sides one
        // apart, and a Windows 2000 member's tree connect was refused for a
        // signature computed over the number this side had not reached
        // (Samba's server lands in the same place: smb1_signing_activate sets
        // its counter to 2).
        ++session->signingSeq;
    }
    return nbtFrame(out);
}

QByteArray Session::unsupportedReply(const QByteArray &message)
{
    // A command this server does not implement still has to be answered. An
    // empty reply leaves the client waiting for its own timeout, which reads as
    // a broken transport instead of an unimplemented command.
    return reply(message, kStatusNotSupported, QByteArray(2, '\0'), QByteArray());
}

bool Session::signatureValid(const QByteArray &message, quint32 sequence,
                             const QByteArray &key) const
{
    if (key.isEmpty() || !(readLe16(message, 10) & 0x0004))
        return true;
    // The client's own counter is not trusted; the number this side expects is
    // put in the field and the MAC is recomputed, so a replayed or reordered
    // message fails here as surely as a forged one (MS-CIFS 3.2.4.1).
    QByteArray zeroed = message;
    QByteArray expected;
    putLe32(expected, sequence);
    expected.append(QByteArray(4, '\0'));
    zeroed.replace(14, 8, expected);
    QByteArray macInput = key;
    macInput.append(zeroed);
    const QByteArray digest = QCryptographicHash::hash(macInput, QCryptographicHash::Md5);
    return digest.left(8) == message.mid(14, 8);
}

QByteArray Session::feed(const QByteArray &message)
{
    const Header header = parseHeader(message);
    if (!header.valid)
        return QByteArray();
    m_unicode = header.unicode;
    if (m_notifier)
        m_notifier(QStringLiteral("SMB1 cmd %1").arg(header.command));

    // A signed request is checked before it is dispatched, and refused when the
    // signature does not cover the message received. Until this existed the bit
    // was read and ignored: a signing client's requests were accepted whatever
    // they carried, so the flag promised integrity the endpoint did not give.
    if (header.flags2 & 0x0004)
        m_signingActive = true;
    // Only a request a session can be checked against is verified. A session
    // setup that names no session — every one that opens a new one — carries no
    // signature and has no key yet, so demanding one refused the very request
    // Windows 2000 opens its user session with after the machine's channel.
    SessionState *requestSession = sessionState(header.uid);
    if (requestSession && !requestSession->key.isEmpty() && (header.flags2 & 0x0004)) {
        if (!signatureValid(message, requestSession->signingSeq, requestSession->key)) {
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 cmd %1 refused: bad signature")
                               .arg(header.command));
            return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());
        }
        ++requestSession->signingSeq;
    }

    switch (header.command) {
    case CmdNegotiate:
        return negotiate(message);
    case CmdSessionSetupAndX:
        return sessionSetup(message);
    case CmdTreeConnectAndX:
        return treeConnect(message);
    case CmdTreeDisconnect:
        return treeDisconnect(message);
    case CmdLogoffAndX:
        return logoff(message);
    case CmdEcho:
        return echo(message);
    case CmdQueryDisk:
        return queryDisk(message);
    case CmdNtCreateAndX:
        return ntCreate(message);
    case CmdClose:
        return closeFile(message);
    case CmdReadAndX:
        return readAndX(message);
    case CmdWriteAndX:
        return writeAndX(message);
    case CmdTrans:
        return transact(message);
    case CmdTrans2:
        return trans2(message);
    default:
        if (!qEnvironmentVariableIsEmpty("MONARCHY_SMB1_TRACE"))
            qWarning("SMB1 unhandled cmd %u wc=%d words=%s", header.command,
                     int(header.words.size() / 2), header.words.toHex().constData());
        return unsupportedReply(message);
    }
}

QByteArray Session::negotiate(const QByteArray &message)
{
    const Header header = parseHeader(message);
    QList<QByteArray> dialects;
    int at = 0;
    while (at < header.data.size()) {
        // Each dialect is a buffer with a leading 0x02 type byte.
        if (quint8(header.data.at(at)) != 0x02) {
            ++at;
            continue;
        }
        int end = at + 1;
        while (end < header.data.size() && header.data.at(end) != '\0')
            ++end;
        dialects.append(header.data.mid(at + 1, end - at - 1).toUpper());
        at = end + 1;
    }

    int index = -1;
    for (int i = 0; i < dialects.size(); ++i) {
        if (dialects.at(i) == "NT LM 0.12") {
            index = i;
            break;
        }
    }
    if (index < 0) {
        QByteArray words;
        putLe16(words, 0xffff);
        return reply(message, 0, words, QByteArray());
    }

    QByteArray words;
    putLe16(words, quint16(index));       // DialectIndex
    // SECURITY_MODE_SIGNING_ENABLED: signing is offered, not demanded, so a
    // client with no signing policy (Windows 2000 by default) is served
    // unsigned and a client that signs is held to it.
    words.append(char(0x03 | 0x04));      // user, encrypted passwords, signing enabled
    putLe16(words, 50);                   // MaxMpxCount
    putLe16(words, 1);                    // MaxNumberVcs
    putLe32(words, 4356);                 // MaxBufferSize
    putLe32(words, 65536);                // MaxRawSize
    putLe32(words, 0);                    // SessionKey
    putLe32(words, 0x80000000u | 0x00000004u | 0x00000008u | 0x00000010u | 0x00000040u);
    const quint64 now = fileTimeNow();
    putLe32(words, quint32(now & 0xffffffffu));
    putLe32(words, quint32(now >> 32));
    putLe16(words, 0);                    // ServerTimeZone
    words.append(char(0));                // ChallengeLength (extended security)

    QByteArray data(16, '\0');            // ServerGuid
    for (int i = 0; i < 16; ++i)
        data[i] = char(QRandomGenerator::system()->generate() & 0xff);
    if (m_notifier)
        m_notifier(QStringLiteral("SMB1 negotiate NT LM 0.12"));
    return reply(message, kStatusSuccess, words, data);
}

QByteArray Session::sessionSetup(const QByteArray &message)
{
    const Header header = parseHeader(message);
    // A request that names a session this connection does not have opens a new
    // one and is given a UID of its own. Two sessions on one connection is not
    // an edge case: it is every Windows member's logon, where the machine's
    // Kerberos channel and the user's NTLM session share a socket.
    quint16 sessionUid = header.uid;
    if (!sessionState(sessionUid)) {
        do {
            sessionUid = quint16(QRandomGenerator::system()->generate() | 1);
        } while (sessionState(sessionUid));
        m_sessions.insert(sessionUid, SessionState());
    }
    SessionState &session = *sessionState(sessionUid);
    //    Extended security: AndX (4), MaxBuffer (2), MaxMpx (2), Vc (2),
    // SessionKey (4), SecurityBlobLength (2), Reserved (4), Capabilities (4).
    const quint16 blobLength = readLe16(header.words, 14);
    QByteArray token = header.data.left(blobLength);

    // Before extended security existed the client put its LM and NT responses
    // in the request itself, followed by the account and domain names as OEM
    // strings, and answered no challenge beyond the one the negotiate reply
    // carried (MS-CIFS 2.2.4.52.2). A Windows 2000 machine's Netlogon path and
    // Samba's non-SPNEGO client both send this form, and reading it as an
    // extended request with an empty blob turned every one of them into
    // LOGON_FAILURE — the login never reached the pipe it came for.
    // A GSS token is a SPNEGO message: 0x60 is an initial context token, 0xa1
    // and 0xa2 the [1] and [2] choices of a NegTokenResp. Recognising only the
    // first of those made Samba's own type-3 reply look like a legacy request.
    const quint8 firstByte = token.isEmpty() ? 0 : quint8(token.at(0));
    const bool gssToken = firstByte == 0x60 || firstByte == 0xa1 || firstByte == 0xa2;
    const bool legacyForm = !token.startsWith("NTLMSSP") && !gssToken
                            && header.words.size() >= 24
                            && (readLe16(header.words, 14) != 0
                                || readLe16(header.words, 16) != 0);
    if (legacyForm) {
        const int lmLength = readLe16(header.words, 14);
        const int ntLength = readLe16(header.words, 16);
        // The names follow the responses as terminated strings in the
        // connection's string encoding — Samba sends them as UTF-16 here even
        // though the form itself predates extended security, so reading a byte
        // at a time would stop at the 'A' of "Administrator".
        const auto oemString = [this, &header](int at, int *next) {
            QString text;
            int i = at;
            if (m_unicode) {
                while (i + 1 < header.data.size()
                       && !(header.data.at(i) == '\0' && header.data.at(i + 1) == '\0')) {
                    const quint16 unit = quint16(quint8(header.data.at(i)))
                                         | quint16(quint16(quint8(header.data.at(i + 1))) << 8);
                    text.append(QChar(unit));
                    i += 2;
                }
                if (next)
                    *next = i + 2;
                return text;
            }
            while (i < header.data.size() && header.data.at(i) != '\0') {
                text.append(QChar(quint8(header.data.at(i))));
                ++i;
            }
            if (next)
                *next = i + 1;
            return text;
        };
        Rpc::AuthRequest request;
        // The negotiate reply carried no challenge of its own (ChallengeLength
        // zero), so these responses were computed over eight zero bytes.
        request.challenge = QByteArray(8, '\0');
        request.lmResponse = header.data.mid(0, lmLength);
        request.ntResponse = header.data.mid(lmLength, ntLength);
        int namesAt = lmLength + ntLength;
        if (namesAt < header.data.size() && header.data.at(namesAt) == '\0')
            ++namesAt; // the optional pad byte between the responses and the names
        request.user = oemString(namesAt, &namesAt);
        request.domain = oemString(namesAt, nullptr);
        // No NTLM flags are exchanged in this form, so there is no 128-bit or
        // key-exchange negotiation: the client signs with the session base key
        // MS-NLMP derives for the response it sent. That one value covers both
        // versions — HMAC_MD5(ResponseKeyNT, NTProofStr) for NTLMv2 and
        // MD4(NTOWFv1) for NTLMv1. Signing with MD4 of the NT one-way function
        // instead (the NTLMv2 `userSessionKey`) is one hash too many: Samba's
        // client logged on in this form and then refused the reply
        // `smb1_signing_good: BAD SIG: seq 1`, while an unsigned session over it
        // worked, which is what made this look like the client's problem.
        request.flags = 0;

        Ntlm::SessionKeys keys;
        quint32 legacyStatus = kStatusLogonFailure;
        if (!request.user.isEmpty() && m_authenticator
            && m_authenticator(request, &keys)) {
            session.authenticated = true;
            // The MAC key is not the session key on its own: Samba's client
            // forms it as the user session key followed by the NTLM response it
            // sent (libcli/smb/smb_signing.c, smb1_signing_activate), and with
            // the 16-byte key alone every reply to a signing client in this
            // form was refused `smb1_signing_good: BAD SIG: seq 1`. Keyed this
            // way the client's own expected MAC reproduces byte for byte.
            session.key = keys.sessionBaseKey + request.ntResponse;
            session.user = request.domain.isEmpty()
                               ? request.user
                               : request.domain + QLatin1Char('\\') + request.user;
            legacyStatus = kStatusSuccess;
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 logon %1").arg(session.user));
        }
        QByteArray words;
        words.append(char(0xff)); // AndXCommand: none
        words.append(char(0));    // AndXReserved
        putLe16(words, 0);        // AndXOffset
        putLe16(words, 0);        // Action
        QByteArray data;
        for (const QString &name : {QStringLiteral("Windows NT"), QStringLiteral("Monarchy")}) {
            data.append(name.toLatin1());
            data.append('\0');
        }
        if (m_notifier) {
            m_notifier(QStringLiteral("SMB1 session setup (pre-extended security) user=%1 lm=%2 nt=%3")
                           .arg(request.user.isEmpty() ? QStringLiteral("<none>") : request.user)
                           .arg(request.lmResponse.size())
                           .arg(request.ntResponse.size()));
        }
        return reply(message, legacyStatus, words, data, sessionUid, -1, false);
    }

    const int type = Ntlm::messageType(Ntlm::embeddedToken(token));
    // A client that sent a raw NTLMSSP token gets a raw one back. Windows 2000
    // speaks extended security without SPNEGO here and drops the session when
    // the server answers with a NegTokenResp it never asked for; Samba's client
    // sends the GSS wrapper, so both forms have to be answered in kind.
    const bool spnegoWrapped = !token.startsWith("NTLMSSP");
    QByteArray replyToken;
    quint32 status = kStatusSuccess;
    quint16 action = 0;

    if (type == 1) {
        session.challenge = QByteArray(8, '\0');
        for (int i = 0; i < 8; ++i)
            session.challenge[i] = char(QRandomGenerator::system()->generate() & 0xff);
        const QByteArray challenge = Ntlm::challengeToken(session.challenge, m_domain,
                                                          m_serverName, m_dnsDomain);
        replyToken = spnegoWrapped ? Gss::spnegoResponse(1, kNtlmMech, challenge) : challenge;
        status = kStatusMoreProcessingRequired;
    } else if (type == 3 && isNullSession(token)) {
        // A Windows 2000 member opens its machine channel with a null session
        // first: a Type 3 that names no user and carries no response. Refusing
        // that aborts the whole logon (LOGON_FAILURE, logoff) before the machine
        // account is ever authenticated, so it is answered as the anonymous
        // session it is. The session stays unauthenticated for the disk shares.
        session.user.clear();
        session.authenticated = false;
        replyToken = spnegoWrapped ? Gss::spnegoResponse(0, kNtlmMech, QByteArray())
                                   : QByteArray();
        status = kStatusSuccess;
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 null session"));
    } else if (type == 3) {
        Rpc::AuthRequest request;
        request.challenge = session.challenge;
        QByteArray encryptedSessionKey;
        Ntlm::SessionKeys keys;
        if (parseAuthenticate(token, &request, &encryptedSessionKey) && m_authenticator
            && m_authenticator(request, &keys)) {
            session.authenticated = true;
            // SMB1 signs with the NTLM session key (MS-CIFS 3.2.4.1), which is
            // the exported key when the client negotiated key exchange.
            constexpr quint32 kKeyExchange = 0x40000000u;
            if ((request.flags & kKeyExchange) && !encryptedSessionKey.isEmpty()) {
                Ntlm::Sealer rc4(keys.sessionBaseKey);
                session.key = rc4.apply(encryptedSessionKey);
            } else {
                session.key = keys.sessionBaseKey;
            }
            session.user = request.domain.isEmpty()
                               ? request.user
                               : request.domain + QLatin1Char('\\') + request.user;
            replyToken = spnegoWrapped ? Gss::spnegoResponse(0, kNtlmMech, QByteArray())
                                       : QByteArray();
            action = 0;
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 logon %1").arg(session.user));
        } else {
            replyToken = spnegoWrapped ? Gss::spnegoResponse(2, kNtlmMech, QByteArray())
                                       : QByteArray();
            status = kStatusLogonFailure;
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 logon refused %1 (nt %2 bytes, flags 0x%3, %4)")
                               .arg(request.user.isEmpty() ? QStringLiteral("?")
                                                           : request.user)
                               .arg(request.ntResponse.size())
                               .arg(request.flags, 8, 16, QLatin1Char('0'))
                               .arg(refusalReason(request)));
        }
    } else if (m_kerberosAcceptor && !Gss::kerberosToken(token).isEmpty()) {
        // SPNEGO lets the acceptor choose any mechanism the initiator listed, and
        // a Windows 2000 member offers Kerberos first on its machine channel. It
        // holds a ticket for this server, so the AP-REQ is accepted and answered
        // with the AP-REP; there is nothing left to ask for.
        Rpc::KerberosContext context;
        QString error;
        const QByteArray apReq = Gss::kerberosToken(token);
        if (!apReq.isEmpty() && m_kerberosAcceptor(apReq, &context, &error)) {
            session.authenticated = true;
            session.user = context.user;
            // The session key of a Kerberos session is the GSS context key, and
            // SMB1 signs with it exactly as it signs with NTLM's session key:
            // MD5(key || message). Windows 2000 signs a Kerberos session from
            // its first message on — answering unsigned made the client drop
            // the connection right after the IPC$ tree connect, which is where
            // the domain join dies with "the specified network name is no
            // longer available".
            //
            // The whole key, not its first 16 bytes: SMB2's session key is the
            // SSPI form, which GSS_KRB5_INQ_SSPI_SESSION_KEY truncates to 16, and
            // that is what Smb2.cpp uses. SMB1 has no such truncation — Samba's
            // smb1_signing_set_key() takes the GSS key at its full length, as
            // smbd's own SMB1 signing does — so an AES-256 ticket signed every
            // message with 32 bytes here and 16 there. Measured: a Kerberos
            // SMB1 session was refused NT_STATUS_ACCESS_DENIED with "smb1_signing_good:
            // BAD SIG: seq 1" under the default aes256 session key, and worked
            // once GSS_TKT/SKEY_TGS were forced to rc4-hmac, whose session key is
            // 16 bytes and so hid the truncation.
            session.key = context.key;
            replyToken = Gss::spnegoResponse(0, QString(), context.replyToken);
            status = kStatusSuccess;
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 logon %1 (kerberos)").arg(session.user));
        } else {
            replyToken = Gss::spnegoResponse(2, kKrb5Mech, QByteArray());
            status = kStatusLogonFailure;
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 kerberos refused: %1")
                               .arg(apReq.isEmpty() ? QStringLiteral("no AP-REQ token") : error));
        }
    } else if (spnegoWrapped && Gss::carriesKerberos(token)) {
        // An offer that names Kerberos but carries no AP-REQ: either no acceptor
        // is installed or the client holds no ticket for this server. SPNEGO
        // lets the acceptor pick any listed mechanism, and a Windows 2000 member
        // lists NTLMSSP last: select it and let the exchange go on rather than
        // dropping the session with LOGON_FAILURE.
        replyToken = Gss::spnegoResponse(1, kNtlmMech, QByteArray());
        status = kStatusMoreProcessingRequired;
    } else {
        status = kStatusLogonFailure;
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 session setup refused: no NTLMSSP message "
                                       "(blob %1 bytes, %2 words)")
                           .arg(blobLength)
                           .arg(header.words.size() / 2));
    }

    QByteArray words;
    words.append(char(0xff)); // AndXCommand: none
    words.append(char(0));    // AndXReserved
    putLe16(words, 0);        // AndXOffset
    putLe16(words, action);   // Action
    putLe16(words, quint16(replyToken.size())); // SecurityBlobLength

    // CAP_EXTENDED_SECURITY was negotiated in the negotiate reply, so the
    // security blob is the answer. MS-CIFS 2.2.4.6.3 still puts NativeOS and
    // NativeLanMan after it — both NUL-terminated, and UTF-16 when the request
    // was Unicode — and a client that parses the response by that definition
    // reads the blob's trailing bytes as the first string and fails to find its
    // terminator: impacket's SMB1 client sent a non-Unicode session setup, took
    // our bare blob for a NativeOS/NativeLanMan pair and stopped at
    // LOGON_FAILURE without ever sending its Type 3 message. The legacy form's
    // trailing strings are the ones a Windows 2000 member reads as malformed;
    // these are the extended form's own fields.
    QByteArray data = replyToken;
    // Pad only when the blob ends mid-character. Padding an even-length blob
    // put NativeOS one byte off, so the client read UTF-16 from an odd offset:
    // every unit came out byte-swapped and the terminator it was looking for
    // arrived as part of a character. Measured on our own answer to a raw
    // NTLMSSP session setup, where the empty blob got a leading 0x00 and the
    // strings after it decoded as U+4D00 rather than "Monarchy".
    if (data.size() % 2 != 0)
        data.append(char(0));
    const auto nativeString = [&header](const QString &text) {
        QByteArray out;
        if (header.unicode) {
            for (const QChar c : text) {
                out.append(char(c.unicode() & 0xff));
                out.append(char((c.unicode() >> 8) & 0xff));
            }
            out.append(QByteArray(2, '\0'));
        } else {
            out = text.toLatin1();
            out.append(char(0));
        }
        return out;
    };
    data.append(nativeString(QStringLiteral("Monarchy"))); // NativeOS
    data.append(nativeString(QStringLiteral("Monarchy"))); // NativeLanMan

    if (m_notifier)
        m_notifier(QStringLiteral("SMB1 session setup type %1").arg(type));
    // The UID is assigned here and has to be in the header the signature covers.
    // The signature itself is not on this reply: it is the message that gives
    // the session its key, and Samba's server answers it before it turns
    // signing on for the session. Measured: a Windows 2000 member's session
    // setup was answered signed and the guest hung up without a tree connect,
    // where the same exchange answered unsigned is what every other client here
    // accepts.
    return reply(message, status, words, data, sessionUid, -1, false);
}

QByteArray Session::treeConnect(const QByteArray &message)
{
    const Header header = parseHeader(message);
    // AndX (4), Flags (2), PasswordLength (2); data: password, path, service.
    const quint16 passwordLength = readLe16(header.words, 6);
    const QString path = stringAt(header.data, passwordLength);
    const int slash = path.lastIndexOf(QLatin1Char('\\'));
    const QString share = slash >= 0 ? path.mid(slash + 1) : path;
    // The disk shares a member reads its policy from, and the pipe share every
    // DCE/RPC call rides on. Anything else is not shared by this server.
    const bool isIpc = share.compare(QStringLiteral("IPC$"), Qt::CaseInsensitive) == 0;
    const QString shareRoot = m_shares.value(share.toLower());
    if (!isIpc && shareRoot.isEmpty()) {
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 tree connect %1 refused").arg(share));
        return reply(message, kStatusBadNetworkName, QByteArray(), QByteArray());
    }
    // A disk share, unlike IPC$, is only for an authenticated session: the
    // domain's policy files are not anonymous-readable on Windows either.
    const SessionState *session = sessionState(header.uid);
    if (!isIpc && !(session && session->authenticated)) {
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 tree connect %1 refused (anonymous)").arg(share));
        return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());
    }

    const quint16 tid = ++m_nextTree;
    m_trees.insert(tid, share);
    m_treeSession.insert(tid, header.uid);
    if (m_notifier)
        m_notifier(QStringLiteral("SMB1 tree connect %1").arg(share));

    QByteArray words;
    words.append(char(0xff)); // AndXCommand
    words.append(char(0));
    putLe16(words, 0);
    putLe16(words, 0x0001); // OptionalSupport: SMB_SUPPORT_SEARCH_BITS
    // MS-CIFS 2.2.4.55.2: an NT client gets the seven-word form, which adds the
    // two maximal access masks. Measured against a Windows 2000 DC: it answers
    // 0x1ff for both, for IPC$ as well as for a disk share.
    putLe32(words, 0x000001ffu); // MaximalShareAccessRights
    putLe32(words, 0x000001ffu); // GuestMaximalShareAccessRights

    // Service: "IPC" for the pipe share, "A:" for a disk share.
    QByteArray data = isIpc ? QByteArray("IPC", 3) : QByteArray("A:", 2);
    data.append(char(0));
    data.append(char(0)); // pad so the Unicode name starts on an even offset
    // The native file system string is empty for IPC$: the Windows 2000 DC
    // answers that way (seven-byte body), and naming a disk file system on a
    // pipe share makes a 2000 client read the tree as a malformed reply — it
    // closes the connection right after the tree connect, before the first
    // NT Create AndX for \lsarpc that the join needs.
    if (isIpc) {
        data.append(QByteArray(2, '\0'));
    } else {
        data.append(toUtf16Bytes(QStringLiteral("NTFS")));
        data.append(QByteArray(2, '\0'));
    }
    // The TID is assigned here and has to be in the header the signature covers.
    return reply(message, kStatusSuccess, words, data, -1, tid);
}

QByteArray Session::treeDisconnect(const QByteArray &message)
{
    const quint16 tid = parseHeader(message).tid;
    m_trees.remove(tid);
    m_treeSession.remove(tid);
    return reply(message, kStatusSuccess, QByteArray(), QByteArray());
}

QByteArray Session::logoff(const QByteArray &message)
{
    const Header header = parseHeader(message);
    // The answer is built while the session still exists, because a signing
    // session verifies it; only then is the session and everything it opened
    // dropped. The other session on this connection keeps its trees and keys.
    const QByteArray answer = reply(message, kStatusSuccess, QByteArray(), QByteArray());
    QList<quint16> owned;
    for (auto it = m_treeSession.cbegin(); it != m_treeSession.cend(); ++it) {
        if (it.value() == header.uid)
            owned.append(it.key());
    }
    for (const quint16 tid : owned) {
        m_trees.remove(tid);
        m_treeSession.remove(tid);
        for (auto it = m_files.begin(); it != m_files.end();) {
            if (it.value().tid == tid) {
                delete it.value().channel;
                it = m_files.erase(it);
            } else {
                ++it;
            }
        }
    }
    m_sessions.remove(header.uid);
    return answer;
}

QByteArray Session::echo(const QByteArray &message)
{
    const Header header = parseHeader(message);
    QByteArray words;
    putLe16(words, readLe16(header.words, 0)); // SequenceNumber
    const int count = header.words.isEmpty() ? 0 : readLe16(header.words, 0);
    QByteArray data;
    for (int i = 0; i < count; ++i)
        data.append(header.data);
    return reply(message, kStatusSuccess, words, data);
}

QByteArray Session::ntCreate(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const quint16 nameLength = readLe16(header.words, 5);
    QString name;
    if (header.unicode) {
        const int at = header.data.size() > 0 ? 1 : 0;
        name = fromUtf16(header.data.mid(at, int(nameLength)));
    } else {
        name = QString::fromLatin1(header.data.left(int(nameLength)));
    }
    // Clients pad the name to an even length, and some include the UTF-16
    // terminator in NameLength, so drop any trailing NULs before using it.
    while (name.endsWith(QChar(0)))
        name.chop(1);
    while (name.startsWith(QLatin1Char('\\')))
        name.remove(0, 1);
    if (name.startsWith(QStringLiteral("pipe\\"), Qt::CaseInsensitive))
        name.remove(0, 5);

    // A name opened inside a disk share is a file or directory under that
    // share's root, resolved case-insensitively and never allowed to climb
    // out of it. Writes are not accepted: SYSVOL and NETLOGON are read-only
    // here, as they are until a GPO editor exists to write them.
    //
    // A refusal below carries no parameter block. An NT_CREATE_ANDX error is
    // read as one only when WordCount is zero; replying with the success
    // layout's 34 zero words instead made Samba's client report
    // NT_STATUS_INVALID_NETWORK_RESPONSE for every failure, so the status this
    // function chose never reached the client.
    const QString shareName = m_trees.value(header.tid);
    const QString shareRoot = m_shares.value(shareName.toLower());
    const SessionState *session = sessionState(header.uid);
    if (!shareRoot.isEmpty()) {
        if (!(session && session->authenticated))
            return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());
        // Every disk share here is read-only, so an access that could change it
        // is refused before the name is resolved: a client creating a new name
        // on SYSVOL gets access denied, not "not found", which is what a
        // Windows read-only share answers and what the SMB2 path already does.
        // MS-CIFS 2.2.4.7 puts DesiredAccess at word 15 and CreateDisposition
        // at word 35 of the NT_CREATE_ANDX request.
        constexpr quint32 kWriteAccess = 0x00000002u  // FILE_WRITE_DATA / FILE_ADD_FILE
                                         | 0x00000004u // FILE_APPEND_DATA / ADD_SUBDIRECTORY
                                         | 0x00000010u // FILE_WRITE_EA
                                         | 0x00000100u // FILE_WRITE_ATTRIBUTES
                                         | 0x00010000u // DELETE
                                         | 0x00040000u // WRITE_DAC
                                         | 0x00080000u; // WRITE_OWNER
        const quint32 desiredAccess = readLe32(header.words, 15);
        const quint32 createDisposition = readLe32(header.words, 35);
        if ((desiredAccess & kWriteAccess) || createDisposition == 2 /* FILE_CREATE */
            || createDisposition == 5 /* FILE_OVERWRITE_IF */) {
            if (m_notifier)
                m_notifier(QStringLiteral("SMB1 create \\\\%1\\%2 refused: share is read-only")
                               .arg(shareName, name));
            return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());
        }
        QString relative;
        QString resolved;
        if (SmbPaths::safeRelativeName(name, &relative))
            resolved = SmbPaths::resolveCaseInsensitive(shareRoot, relative);
        const QFileInfo info(resolved);
        if (resolved.isEmpty() || !info.exists())
            return reply(message, kStatusObjectNameNotFound, QByteArray(), QByteArray());

        OpenFile file;
        file.kind = info.isDir() ? OpenFile::Kind::DiskDirectory : OpenFile::Kind::DiskFile;
        file.name = name;
        file.path = resolved;
        file.size = info.isDir() ? 0 : info.size();
        const quint16 fileId = ++m_nextFid;
        m_files.insert(fileId, file);
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 open \\\\%1\\%2").arg(shareName, relative));

        const quint64 created = fileTime(info.birthTime().isValid() ? info.birthTime()
                                                                    : info.lastModified());
        const quint64 accessed = fileTime(info.lastRead());
        const quint64 written = fileTime(info.lastModified());
        QByteArray words;
        words.append(char(0xff)); // AndXCommand
        words.append(char(0));
        putLe16(words, 0);
        words.append(char(0)); // OplockLevel
        putLe16(words, fileId);
        putLe32(words, 1);      // CreateAction: FILE_OPENED
        putLe32(words, quint32(created & 0xffffffffu));
        putLe32(words, quint32(created >> 32));
        putLe32(words, quint32(accessed & 0xffffffffu));
        putLe32(words, quint32(accessed >> 32));
        putLe32(words, quint32(written & 0xffffffffu));
        putLe32(words, quint32(written >> 32));
        putLe32(words, quint32(written & 0xffffffffu));
        putLe32(words, quint32(written >> 32));
        putLe32(words, info.isDir() ? 0x10u : 0x80u); // FileAttributes
        putLe32(words, quint32(file.size));           // AllocationSize
        putLe32(words, 0);
        putLe32(words, quint32(file.size));           // EndOfFile
        putLe32(words, 0);
        putLe16(words, 0);                            // FileType: disk
        putLe16(words, 0);                            // DeviceState
        words.append(char(info.isDir() ? 1 : 0));     // Directory
        return reply(message, kStatusSuccess, words, QByteArray());
    }

    RpcServer *endpoint = m_pipes.value(name.toLower());
    if (!m_trees.contains(header.tid) || !endpoint) {
        if (m_notifier)
            m_notifier(QStringLiteral("SMB1 create \\\\pipe\\\\%1 refused").arg(name));
        return reply(message, kStatusObjectNameNotFound, QByteArray(), QByteArray());
    }

    const quint16 fid = ++m_nextFid;
    OpenFile file;
    file.name = name;
    file.tid = header.tid;
    file.channel = endpoint->newChannel(QStringLiteral("smb1:%1").arg(name));
    if (session && session->authenticated && file.channel) {
        file.channel->setTransportIdentity(session->user);
        file.channel->setTransportSessionKey(session->key);
    }
    m_files.insert(fid, file);
    if (m_notifier)
        m_notifier(QStringLiteral("SMB1 open \\\\pipe\\\\%1").arg(name));

    QByteArray words;
    words.append(char(0xff));
    words.append(char(0));
    putLe16(words, 0);
    words.append(char(0)); // OplockLevel
    putLe16(words, fid);
    putLe32(words, 1);     // CreateAction: FILE_OPENED
    putLe32(words, 0);     // CreateTime
    putLe32(words, 0);
    putLe32(words, 0);     // LastAccessTime
    putLe32(words, 0);
    putLe32(words, 0);     // LastWriteTime
    putLe32(words, 0);
    putLe32(words, 0);     // ChangeTime
    putLe32(words, 0);
    putLe32(words, 0x80);  // FileAttributes
    putLe32(words, 0);     // AllocationSize
    putLe32(words, 0);
    putLe32(words, 0);     // EndOfFile
    putLe32(words, 0);
    putLe16(words, 2);     // FileType: pipe
    putLe16(words, 0);     // DeviceState
    words.append(char(0)); // Directory
    return reply(message, kStatusSuccess, words, QByteArray());
}

void Session::feedPipe(OpenFile *file, const QByteArray &data)
{
    if (!file->channel) {
        file->pending.append(QByteArray());
        return;
    }
    QByteArray remaining = data;
    while (remaining.size() >= 16) {
        const quint16 fragLength = readLe16(remaining, 8);
        if (fragLength < 16 || remaining.size() < fragLength)
            break;
        const QByteArray pdu = remaining.left(fragLength);
        remaining.remove(0, fragLength);
        file->pending.append(file->channel->feed(pdu));
    }
    if (!remaining.isEmpty())
        file->pending.append(file->channel->feed(remaining));
    if (!qEnvironmentVariableIsEmpty("MONARCHY_SMB1_TRACE"))
        qWarning("SMB1 pipe %s fed %d bytes, pending %d", qPrintable(file->name),
                 int(data.size()), int(file->pending.size()));
}

QByteArray Session::readAndX(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const quint16 fid = readLe16(header.words, 4);
    const quint16 maxCount = readLe16(header.words, 10);
    auto it = m_files.find(fid);
    if (it == m_files.end())
        return reply(message, kStatusInvalidHandle, QByteArray(24, '\0'), QByteArray());

    QByteArray data;
    if (it->kind == OpenFile::Kind::DiskFile) {
        const quint32 offset = readLe32(header.words, 6);
        QFile file(it->path);
        if (!file.open(QIODevice::ReadOnly))
            return reply(message, kStatusAccessDenied, QByteArray(24, '\0'), QByteArray());
        file.seek(qint64(offset));
        data = file.read(maxCount);
    } else {
        data = it->pending;
        it->pending.clear();
    }
    if (data.size() > int(maxCount))
        data.truncate(maxCount);

    QByteArray words;
    words.append(char(0xff));
    words.append(char(0));
    putLe16(words, 0);
    putLe16(words, 0);                    // Remaining
    putLe16(words, 0);                    // DataMode
    putLe16(words, 0);                    // Reserved
    putLe16(words, quint16(data.size())); // DataCount
    putLe16(words, 60);                   // DataOffset from the SMB header
    putLe32(words, 0);                    // DataCount_Hi
    words.append(QByteArray(6, '\0'));

    QByteArray out(1, '\0'); // pad so the payload starts at offset 60
    out.append(data);
    return reply(message, kStatusSuccess, words, out);
}

QByteArray Session::writeAndX(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const quint16 fid = readLe16(header.words, 4);
    // AndX (4), FID (2), Offset (4), Reserved (4), WriteMode (2), Remaining (2),
    // DataLength_Hi (2), DataLength (2), DataOffset (2), HighOffset (4).
    const quint16 dataLength = readLe16(header.words, 20);
    quint16 dataOffset = readLe16(header.words, 22);
    if (dataOffset == 0)
        dataOffset = 32 + 1 + quint16(header.words.size()) + 2;

    if (!qEnvironmentVariableIsEmpty("MONARCHY_SMB1_TRACE"))
        qWarning("SMB1 write fid=%u words=%s off=%u len=%u msg=%d", fid,
                 header.words.toHex().constData(), dataOffset, dataLength, int(message.size()));
    auto it = m_files.find(fid);
    if (it == m_files.end())
        return reply(message, kStatusInvalidHandle, QByteArray(12, '\0'), QByteArray());
    if (it->kind != OpenFile::Kind::Pipe) {
        // SYSVOL and NETLOGON are delivered read-only.
        return reply(message, kStatusAccessDenied, QByteArray(6, '\0'), QByteArray());
    }
    QByteArray data;
    if (dataOffset < message.size())
        data = message.mid(dataOffset, dataLength);
    feedPipe(&it.value(), data);

    QByteArray words;
    words.append(char(0xff));
    words.append(char(0));
    putLe16(words, 0);
    putLe16(words, quint16(dataLength)); // Count
    putLe16(words, 0);                   // Available
    putLe32(words, 0);                   // Reserved
    return reply(message, kStatusSuccess, words, QByteArray());
}

QByteArray Session::closeFile(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const quint16 fid = readLe16(header.words, 0);
    auto it = m_files.find(fid);
    if (it == m_files.end())
        return reply(message, kStatusInvalidHandle, QByteArray(), QByteArray());
    delete it->channel;
    m_files.erase(it);
    return reply(message, kStatusSuccess, QByteArray(), QByteArray());
}

QByteArray Session::transact(const QByteArray &message)
{
    const Header header = parseHeader(message);
    // WordCount 14 + SetupCount. Setup[0] is the subcommand, Setup[1] the pipe
    // file id.
    const quint8 setupCount = header.words.isEmpty() ? 0 : quint8(header.words.at(26));
    const quint16 parameterCount = readLe16(header.words, 18);
    const quint16 parameterOffset = readLe16(header.words, 20);
    if (setupCount < 2)
        return reply(message, kStatusNotSupported, QByteArray(20, '\0'), QByteArray());
    const quint16 subcommand = readLe16(header.words, 28);
    const quint16 fid = readLe16(header.words, 30);
    auto it = m_files.find(fid);

    // TRANS_SET_NMPIPE_STATE (0x0001). A Windows 2000 client sets it on a pipe
    // it has already opened, before it binds DCE/RPC on that handle: the
    // transaction names `\PIPE\` with an empty pipe name and puts the handle in
    // Setup[1], which is the same dispatch Samba's `handle_trans` does. The
    // state asks the transport for message- or byte-mode delivery; every pipe
    // here is a headless channel to an RPC endpoint that frames itself, so the
    // state cannot change what a caller gets back and the answer is success with
    // nothing to read back.
    if (subcommand == 0x0001) {
        if (it == m_files.end() || it->kind != OpenFile::Kind::Pipe)
            return reply(message, kStatusInvalidHandle, QByteArray(20, '\0'), QByteArray());
        if (parameterCount < 2)
            return reply(message, kStatusInvalidParameter, QByteArray(20, '\0'),
                         QByteArray());
        return transactionReply(message, QByteArray(), false);
    }
    if (subcommand != 0x0026)
        return reply(message, kStatusNotSupported, QByteArray(20, '\0'), QByteArray());
    if (it == m_files.end())
        return reply(message, kStatusInvalidHandle, QByteArray(20, '\0'), QByteArray());

    // TRANS_TRANSACT_NMPIPE (0x0026) writes a PDU to the pipe and reads the
    // answer back. MS-CIFS puts that input in Trans_Data and Samba's
    // `api_dcerpc_cmd` reads it there, which is what Windows 2000 does; other
    // clients put it in Trans_Parameters, which is where this server used to
    // look and what an SMB1 bind from impacket sends. Both are fed, parameters
    // first because that is the order they appear in the message, and the answer
    // goes back in the field the PDU came in so each client reads it where it
    // expects.
    const quint16 dataCount = readLe16(header.words, 22);
    const quint16 dataOffset = readLe16(header.words, 24);
    QByteArray parameters;
    if (parameterOffset < message.size())
        parameters = message.mid(parameterOffset, int(parameterCount));
    QByteArray data;
    if (dataOffset < message.size())
        data = message.mid(dataOffset, int(dataCount));
    feedPipe(&it.value(), parameters + data);
    QByteArray out = it->pending;
    it->pending.clear();
    return transactionReply(message, out, dataCount > 0);
}

QByteArray Session::transactionReply(const QByteArray &message, const QByteArray &out,
                                     bool inData)
{
    const quint16 size = quint16(out.size());
    QByteArray words;
    putLe16(words, inData ? 0 : size);   // TotalParameterCount
    putLe16(words, inData ? size : 0);   // TotalDataCount
    putLe16(words, 0);                   // Reserved1
    putLe16(words, inData ? 0 : size);   // ParameterCount
    putLe16(words, 56);                  // ParameterOffset
    putLe16(words, 0);                   // ParameterDisplacement
    putLe16(words, inData ? size : 0);   // DataCount
    putLe16(words, 56);                  // DataOffset: the pad byte is at 55
    putLe16(words, 0);                   // DataDisplacement
    words.append(char(0));               // SetupCount
    words.append(char(0));               // Reserved2

    // A subcommand that answers with nothing (SET_NMPIPE_STATE) sends no byte
    // block at all, as Samba's `send_trans_reply` does; the offsets stay 56, the
    // position the pad byte occupies when there is a parameter block.
    QByteArray data;
    if (!out.isEmpty()) {
        data = QByteArray(1, '\0'); // pad so the pipe reply starts at offset 56
        data.append(out);
        if (data.size() % 2)
            data.append(char(0));
    }
    return reply(message, kStatusSuccess, words, data);
}

// TRANS2. A client that already has a file open still asks for its attributes
// through SMB_COM_TRANSACTION2 before reading it, so QUERY_PATH_INFORMATION has
// to answer or the transfer stalls on a reply that never comes.
QByteArray Session::trans2(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const quint8 setupCount = header.words.isEmpty() ? 0 : quint8(header.words.at(26));
    if (setupCount < 1 || header.words.size() < 30)
        return reply(message, kStatusNotSupported, QByteArray(), QByteArray());
    const quint16 subcommand = readLe16(header.words, 28);
    const quint16 parameterCount = readLe16(header.words, 18);
    const quint16 parameterOffset = readLe16(header.words, 20);
    QByteArray parameters;
    if (parameterOffset < message.size())
        parameters = message.mid(parameterOffset, int(parameterCount));

    const QString shareName = m_trees.value(header.tid);
    const QString shareRoot = m_shares.value(shareName.toLower());
    if (shareRoot.isEmpty())
        return reply(message, kStatusBadNetworkName, QByteArray(), QByteArray());
    const SessionState *session = sessionState(header.uid);
    if (!(session && session->authenticated))
        return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());

    if (subcommand == 0x0001 || subcommand == 0x0002 || subcommand == 0x0004)
        return find(message, subcommand, parameters, shareRoot);

    // QUERY_PATH_INFORMATION names the file; QUERY_FILE_INFORMATION names the
    // handle the client already has, which is what a 2000 client asks for
    // before reading a file it just created.
    quint16 level = 0;
    QString resolved;
    if (subcommand == 0x0007) {
        const quint16 fid = readLe16(parameters, 0);
        level = readLe16(parameters, 2);
        auto it = m_files.find(fid);
        if (it == m_files.end() || it->kind == OpenFile::Kind::Pipe)
            return reply(message, kStatusInvalidHandle, QByteArray(), QByteArray());
        resolved = it->path;
    } else if (subcommand == 0x0005) {
        level = readLe16(parameters, 0);
        QString name;
        if (m_unicode) {
            QByteArray bytes;
            for (int i = 6; i + 1 < parameters.size(); i += 2) {
                if (parameters.at(i) == '\0' && parameters.at(i + 1) == '\0')
                    break;
                bytes.append(parameters.at(i));
                bytes.append(parameters.at(i + 1));
            }
            name = fromUtf16(bytes);
        } else {
            const int nul = parameters.indexOf('\0', 6);
            name = QString::fromLatin1(parameters.mid(6, nul < 0 ? -1 : nul - 6));
        }
        while (name.startsWith(QLatin1Char('\\')))
            name.remove(0, 1);
        QString relative;
        if (SmbPaths::safeRelativeName(name, &relative))
            resolved = SmbPaths::resolveCaseInsensitive(shareRoot, relative);
    } else {
        return reply(message, kStatusNotSupported, QByteArray(), QByteArray());
    }

    const QFileInfo info(resolved);
    if (resolved.isEmpty() || !info.exists())
        return reply(message, kStatusObjectNameNotFound, QByteArray(), QByteArray());

    const quint64 created = fileTime(info.birthTime().isValid() ? info.birthTime()
                                                                : info.lastModified());
    const quint64 accessed = fileTime(info.lastRead());
    const quint64 written = fileTime(info.lastModified());
    const quint32 attributes = info.isDir() ? 0x10u : 0x80u;
    QByteArray infoBytes;
    if (level == 0x0101 || level == 0x0107) { // SMB_QUERY_FILE_BASIC_INFO
        putLe32(infoBytes, quint32(created & 0xffffffffu));
        putLe32(infoBytes, quint32(created >> 32));
        putLe32(infoBytes, quint32(accessed & 0xffffffffu));
        putLe32(infoBytes, quint32(accessed >> 32));
        putLe32(infoBytes, quint32(written & 0xffffffffu));
        putLe32(infoBytes, quint32(written >> 32));
        putLe32(infoBytes, quint32(written & 0xffffffffu));
        putLe32(infoBytes, quint32(written >> 32));
        putLe32(infoBytes, attributes);
        putLe32(infoBytes, 0);
    }
    if (level == 0x0102 || level == 0x0107) { // SMB_QUERY_FILE_STANDARD_INFO
        putLe32(infoBytes, quint32(info.size()));
        putLe32(infoBytes, 0);
        putLe32(infoBytes, quint32(info.size()));
        putLe32(infoBytes, 0);
        putLe32(infoBytes, 1);     // NumberOfLinks
        infoBytes.append(char(0)); // DeletePending
        infoBytes.append(char(info.isDir() ? 1 : 0));
    }
    if (level == 0x0107) { // the rest of SMB_QUERY_FILE_ALL_INFO
        putLe32(infoBytes, 0); // Internal: IndexNumber
        putLe32(infoBytes, 0);
        putLe32(infoBytes, 0); // Ea: EaSize
        putLe32(infoBytes, 0); // Access: AccessMask
        putLe32(infoBytes, 0); // Position: CurrentByteOffset
        putLe32(infoBytes, 0);
        putLe32(infoBytes, 0); // Mode
        putLe32(infoBytes, 0); // Alignment
        QByteArray nameBytes;
        const QString base = info.fileName();
        for (QChar ch : base) {
            const char16_t unit = ch.unicode();
            nameBytes.append(char(unit & 0xff));
            nameBytes.append(char((unit >> 8) & 0xff));
        }
        putLe32(infoBytes, quint32(nameBytes.size()));
        infoBytes.append(nameBytes);
        if (infoBytes.size() % 2)
            infoBytes.append(char(0));
    }
    if (level != 0x0101 && level != 0x0102 && level != 0x0107)
        return reply(message, kStatusNotSupported, QByteArray(), QByteArray());

    QByteArray params;
    putLe16(params, 0); // EAErrorOffset
    QByteArray words;
    putLe16(words, quint16(params.size()));      // TotalParameterCount
    putLe16(words, quint16(infoBytes.size()));   // TotalDataCount
    putLe16(words, 0);                           // Reserved
    putLe16(words, quint16(params.size()));      // ParameterCount
    putLe16(words, 56);                          // ParameterOffset
    putLe16(words, 0);                           // ParameterDisplacement
    putLe16(words, quint16(infoBytes.size()));   // DataCount
    putLe16(words, quint16(56 + params.size())); // DataOffset
    putLe16(words, 0);                           // DataDisplacement
    words.append(char(0));                       // SetupCount
    words.append(char(0));                       // Reserved2
    QByteArray data(1, '\0'); // pad so parameters start at offset 56
    data.append(params);
    data.append(infoBytes);
    return reply(message, kStatusSuccess, words, data);
}

// SMB_COM_QUERY_INFORMATION_DISK: word parameters only, no data. The numbers
// are a well-formed answer for a share rather than a measurement of the host
// filesystem — a 4096-byte block size and a generous unit count, which is what
// a client needs to print its free-space line and continue.
QByteArray Session::queryDisk(const QByteArray &message)
{
    const Header header = parseHeader(message);
    const QString shareName = m_trees.value(header.tid);
    if (m_shares.value(shareName.toLower()).isEmpty())
        return reply(message, kStatusBadNetworkName, QByteArray(), QByteArray());
    const SessionState *session = sessionState(header.uid);
    if (!(session && session->authenticated))
        return reply(message, kStatusAccessDenied, QByteArray(), QByteArray());

    constexpr quint32 kBlockSize = 4096;
    constexpr quint32 kTotalUnits = 0xffff;
    QByteArray words;
    putLe16(words, quint16(kTotalUnits));      // TotalUnits
    putLe16(words, 1);                         // BlocksPerUnit
    putLe16(words, quint16(kBlockSize));       // BlockSize
    putLe16(words, quint16(kTotalUnits / 2));  // FreeUnits
    return reply(message, kStatusSuccess, words, QByteArray());
}

// FIND_FIRST2 / FIND_NEXT2 / FIND_CLOSE2. A client that can authenticate,
// connect to a share and open a file by exact name still cannot browse without
// these, and browsing is the first thing a 2000 workstation does: smbclient
// pinned to NT1 asked for FIND_FIRST2 on `\*` and stopped at NOT_SUPPORTED,
// which is the gap G8 records. MS-CIFS 2.2.6.3 (request), 2.2.6.4 and 2.2.6.6
// (response).
QByteArray Session::find(const QByteArray &message, quint16 subcommand,
                         const QByteArray &parameters, const QString &shareRoot)
{
    // One record of a listing. Every layout starts with NextEntryOffset, so a
    // reply is a chain whose last link carries zero; NAMES_INFO is the one
    // layout without timestamps or sizes, and the others differ only in what
    // follows FileAttributes.
    auto record = [](quint16 level, const QFileInfo &info) -> QByteArray {
        const quint64 created = fileTime(info.birthTime().isValid() ? info.birthTime()
                                                                    : info.lastModified());
        const quint64 accessed = fileTime(info.lastRead());
        const quint64 written = fileTime(info.lastModified());
        const quint32 attributes = info.isDir() ? 0x10u : 0x80u;
        const quint64 size = info.isDir() ? 0 : quint64(info.size());
        const QByteArray name = toUtf16Bytes(info.fileName());

        QByteArray out;
        putLe32(out, 0); // NextEntryOffset, patched once the chain is complete
        if (level == 0x0103) { // SMB_FIND_FILE_NAMES_INFO
            putLe32(out, 0); // FileIndex
            putLe32(out, quint32(name.size()));
            out.append(name);
            return out;
        }
        putLe32(out, 0); // FileIndex
        for (quint64 stamp : {created, accessed, written, written}) { // four times
            putLe32(out, quint32(stamp & 0xffffffffu));
            putLe32(out, quint32(stamp >> 32));
        }
        putLe32(out, quint32(size & 0xffffffffu)); // EndOfFile
        putLe32(out, quint32(size >> 32));
        putLe32(out, quint32(size & 0xffffffffu)); // AllocationSize
        putLe32(out, quint32(size >> 32));
        putLe32(out, attributes);
        putLe32(out, quint32(name.size()));
        if (level == 0x0101) { // SMB_FIND_FILE_DIRECTORY_INFO: name at offset 64
        } else if (level == 0x0102) { // SMB_FIND_FILE_FULL_DIRECTORY_INFO
            putLe32(out, 0); // EaSize
        } else if (level == 0x0104) { // SMB_FIND_FILE_BOTH_DIRECTORY_INFO
            putLe32(out, 0);           // EaSize
            out.append(char(0));       // ShortNameLength
            out.append(char(0));       // Reserved
            out.append(QByteArray(24, '\0')); // ShortName, unused
        } else {
            return QByteArray();
        }
        out.append(name);
        return out;
    };

    if (subcommand == 0x0004) { // FIND_CLOSE2
        m_searches.remove(readLe16(parameters, 0));
        QByteArray words;
        putLe16(words, 0); // SearchCount
        return reply(message, kStatusSuccess, words, QByteArray());
    }

    quint16 sid = 0;
    quint16 requested = 0;
    quint16 level = 0;
    Search *search = nullptr;
    bool closeAtEnd = false;

    if (subcommand == 0x0001) { // FIND_FIRST2
        sid = m_nextSearchId++;
        if (m_nextSearchId < 0x200)
            m_nextSearchId = 0x200;
        requested = readLe16(parameters, 2);
        closeAtEnd = (readLe16(parameters, 4) & 0x0001) != 0;
        level = readLe16(parameters, 6);
        const QString pattern = stringAt(parameters, 12);

        // The pattern names a directory and a wildcard within it. A bare name
        // with no wildcard is still a pattern over the share root, which is how
        // a client asks for one directory's contents by full path.
        QString relative;
        if (!SmbPaths::safeRelativeName(pattern, &relative))
            return reply(message, kStatusObjectNameNotFound, QByteArray(), QByteArray());
        QString directory;
        QString namePattern = QStringLiteral("*");
        const int slash = relative.lastIndexOf(QLatin1Char('/'));
        if (slash >= 0) {
            directory = relative.left(slash);
            namePattern = relative.mid(slash + 1);
        } else {
            namePattern = relative;
        }
        // A path that names a directory lists what is inside it: `ls subdir`
        // sends the directory with no wildcard, and matching that name alone
        // would answer with the directory itself instead of its contents.
        const bool wildcard = namePattern.contains(QLatin1Char('*'))
                              || namePattern.contains(QLatin1Char('?'));
        if (!wildcard && !relative.isEmpty()) {
            const QString candidate = SmbPaths::resolveCaseInsensitive(shareRoot, relative);
            if (!candidate.isEmpty() && QFileInfo(candidate).isDir()) {
                directory = relative;
                namePattern = QStringLiteral("*");
            }
        }
        if (namePattern.isEmpty())
            namePattern = QStringLiteral("*");

        const QString directoryPath = SmbPaths::resolveCaseInsensitive(shareRoot, directory);
        if (directoryPath.isEmpty() || !QFileInfo(directoryPath).isDir())
            return reply(message, kStatusObjectNameNotFound, QByteArray(), QByteArray());

        QString expression = QRegularExpression::escape(namePattern);
        expression.replace(QStringLiteral("\\*"), QStringLiteral(".*"));
        expression.replace(QStringLiteral("\\?"), QStringLiteral("."));
        const QRegularExpression wanted(QRegularExpression::anchoredPattern(expression),
                                        QRegularExpression::CaseInsensitiveOption);

        Search fresh;
        const QFileInfoList entries = QDir(directoryPath).entryInfoList(
            QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot, QDir::Name);
        for (const QFileInfo &entry : entries) {
            if (wanted.match(entry.fileName()).hasMatch())
                fresh.paths.append(entry.absoluteFilePath());
        }
        // A pattern that matches nothing is answered with an error, not with an
        // empty success: a client parses the first record out of the data block
        // and reports NO_MEMORY when there is none. Windows answers the same
        // way for SMB1.
        if (fresh.paths.isEmpty())
            return reply(message, kStatusNoSuchFile, QByteArray(), QByteArray());
        search = &m_searches.insert(sid, fresh).value();
    } else { // FIND_NEXT2
        sid = readLe16(parameters, 0);
        requested = readLe16(parameters, 2);
        level = readLe16(parameters, 4);
        const auto it = m_searches.find(sid);
        if (it == m_searches.end())
            return reply(message, kStatusInvalidHandle, QByteArray(), QByteArray());
        search = &it.value();
    }

    QByteArray records;
    int previousStart = -1;
    quint16 emitted = 0;
    if (requested == 0)
        requested = 1;
    while (search->index < search->paths.size() && emitted < requested
           && records.size() < 0x8000) {
        const QByteArray entry = record(level, QFileInfo(search->paths.at(search->index)));
        if (entry.isEmpty())
            return reply(message, kStatusNotSupported, QByteArray(), QByteArray());
        if (previousStart >= 0) {
            // The previous record names the distance to this one, in a field
            // whose width is already fixed at the front of that record.
            const quint32 delta = quint32(records.size() - previousStart);
            records[previousStart + 0] = char(delta & 0xff);
            records[previousStart + 1] = char((delta >> 8) & 0xff);
            records[previousStart + 2] = char((delta >> 16) & 0xff);
            records[previousStart + 3] = char((delta >> 24) & 0xff);
        }
        previousStart = records.size();
        records.append(entry);
        ++search->index;
        ++emitted;
    }

    const bool endOfSearch = search->index >= search->paths.size();
    if (endOfSearch && closeAtEnd)
        m_searches.remove(sid);

    QByteArray params;
    if (subcommand == 0x0001)
        putLe16(params, sid);
    putLe16(params, emitted);          // SearchCount
    putLe16(params, endOfSearch ? 1 : 0); // EndOfSearch
    putLe16(params, 0);                // EaErrorOffset
    putLe16(params, 0);                // LastNameOffset

    QByteArray words;
    putLe16(words, quint16(params.size()));    // TotalParameterCount
    putLe16(words, quint16(records.size()));   // TotalDataCount
    putLe16(words, 0);                         // Reserved
    putLe16(words, quint16(params.size()));    // ParameterCount
    putLe16(words, 56);                        // ParameterOffset
    putLe16(words, 0);                         // ParameterDisplacement
    putLe16(words, quint16(records.size()));   // DataCount
    // An empty listing still has to name a place its data would start. Samba's
    // client validates the offset against the byte count even when DataCount is
    // zero and answers NO_MEMORY when 56 + parameters runs past the message.
    putLe16(words, records.isEmpty() ? 0 : quint16(56 + params.size())); // DataOffset
    putLe16(words, 0);                         // DataDisplacement
    words.append(char(0));                     // SetupCount
    words.append(char(0));                     // Reserved2
    QByteArray data(1, '\0'); // pad so parameters start at offset 56
    data.append(params);
    data.append(records);
    return reply(message, kStatusSuccess, words, data);
}

} // namespace Smb1
