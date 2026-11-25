// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SMB1_H
#define SMB1_H

#include <QByteArray>
#include <QHash>
#include <QString>

#include <functional>

#include "Rpc.h"

// SMB1 (MS-CIFS), the only dialect Windows 2000 speaks. A Windows 2000
// workstation cannot negotiate SMB2 at all, so this is the transport a domain
// join uses: negotiate, session setup carrying NTLMSSP inside SPNEGO, tree
// connect to IPC$, and named-pipe traffic that feeds the same DCE/RPC endpoints
// the TCP listeners serve. Newer clients keep using SMB2; the two share the
// pipe map and the authenticator.
namespace Smb1 {

enum Command : quint8 {
    CmdClose = 0x04,
    CmdEcho = 0x2b,
    CmdReadAndX = 0x2e,
    CmdWriteAndX = 0x2f,
    CmdTrans = 0x25,
    CmdTrans2 = 0x32,
    CmdTreeDisconnect = 0x71,
    CmdNegotiate = 0x72,
    CmdSessionSetupAndX = 0x73,
    CmdLogoffAndX = 0x74,
    CmdTreeConnectAndX = 0x75,
    CmdNtCreateAndX = 0xa2,
    // SMB_COM_QUERY_INFORMATION_DISK. smbclient asks it after a listing to
    // print the free-space line; a client that gets no answer waits for one.
    CmdQueryDisk = 0x80
};

constexpr quint32 kStatusSuccess = 0x00000000u;
constexpr quint32 kStatusMoreProcessingRequired = 0xc0000016u;
constexpr quint32 kStatusLogonFailure = 0xc000006du;
constexpr quint32 kStatusAccessDenied = 0xc0000022u;
constexpr quint32 kStatusBadNetworkName = 0xc00000ccu;
constexpr quint32 kStatusObjectNameNotFound = 0xc0000034u;
constexpr quint32 kStatusNotSupported = 0xc00000bbu;
constexpr quint32 kStatusInvalidHandle = 0xc0000008u;
// A pipe state request that carries no state value: Samba's api_SNPHS refuses
// the same shape with INVALID_PARAMETER.
constexpr quint32 kStatusInvalidParameter = 0xc000000du;
// A FIND_FIRST2 whose pattern matches nothing is an error in SMB1, not an
// empty success: clients parse the reply as a first record and answer NO_MEMORY
// when the data block is empty.
constexpr quint32 kStatusNoSuchFile = 0xc000000fu;

// One SMB1 connection's state. feed() takes one deframed SMB message and
// returns zero or one NetBIOS-framed replies.
class Session
{
public:
    // `shares` maps a share name (lowercased) to the directory behind it. The
    // pipe map and the disk shares are separate namespaces on one session: a
    // 2000 client opens \\dc\SYSVOL and \\dc\pipe\samr over the same
    // connection, exactly as it does on Windows.
    // The policy level is carried so a refusal can say which rule refused: an
    // answer the domain's LmCompatibilityLevel does not allow and an answer that
    // does not match the stored hash produce the same LOGON_FAILURE on the wire,
    // and a log line that cannot tell them apart sends an administrator to the
    // wrong place.
    Session(QHash<QString, RpcServer *> pipes, Rpc::Authenticator authenticator,
            QString domain, QString serverName, QString dnsDomain,
            QHash<QString, QString> shares = QHash<QString, QString>(),
            int lmCompatibilityLevel = Ntlm::kDefaultLmCompatibilityLevel);

    // A 2000 member authenticates to the pipe share with Kerberos: it holds a
    // ticket for the server and offers an AP-REQ in SPNEGO, and only falls back
    // to NTLMSSP when the server declines. Declining is what made its machine
    // channel fail, so the AP-REQ is accepted here exactly as SMB2 accepts it.
    void setKerberosAcceptor(Rpc::KerberosAcceptor acceptor)
    {
        m_kerberosAcceptor = std::move(acceptor);
    }

    static bool isSmb1(const QByteArray &message);

    QByteArray feed(const QByteArray &message);

    void setNotifier(std::function<void(const QString &)> notifier)
    {
        m_notifier = std::move(notifier);
    }

private:
    struct OpenFile {
        enum class Kind { Pipe, DiskFile, DiskDirectory };
        Kind kind = Kind::Pipe;
        QString name;
        QString path;   // resolved absolute path, for a disk object
        quint16 tid = 0;
        qint64 size = 0;
        RpcServer::Channel *channel = nullptr;
        QByteArray pending;
    };

    QByteArray negotiate(const QByteArray &message);
    QByteArray sessionSetup(const QByteArray &message);
    QByteArray treeConnect(const QByteArray &message);
    QByteArray treeDisconnect(const QByteArray &message);
    QByteArray logoff(const QByteArray &message);
    QByteArray echo(const QByteArray &message);
    QByteArray queryDisk(const QByteArray &message);
    QByteArray ntCreate(const QByteArray &message);
    QByteArray closeFile(const QByteArray &message);
    QByteArray readAndX(const QByteArray &message);
    QByteArray writeAndX(const QByteArray &message);
    QByteArray transact(const QByteArray &message);
    // The SMB_COM_TRANSACTION response block, shared by every subcommand that
    // answers with parameters and no data.
    QByteArray transactionReply(const QByteArray &message, const QByteArray &out,
                               bool inData);
    QByteArray trans2(const QByteArray &message);
    // FIND_FIRST2 / FIND_NEXT2 / FIND_CLOSE2, the TRANS2 half a directory
    // listing needs. MS-CIFS 2.2.6.3.
    QByteArray find(const QByteArray &message, quint16 subcommand,
                    const QByteArray &parameters, const QString &shareRoot);
    // QUERY_FS_INFORMATION: the volume, size, device and attribute records a
    // redirector reads about the share before it will enumerate it.
    QByteArray fileSystemInfo(const QByteArray &message, const QByteArray &parameters,
                              const QString &shareName);
    QByteArray unsupportedReply(const QByteArray &message);
    // Which rule refused a logon: the domain's LmCompatibilityLevel refusing an
    // NTLMv1 answer is a configuration fact, while the same status from a level
    // that accepts that shape is a credential or account fact.
    QString refusalReason(const Rpc::AuthRequest &request) const;
    // MS-CIFS 3.2.4.1: the signature field carries a sequence number per
    // direction, so a request is checked against the number expected next.
    bool signatureValid(const QByteArray &message, quint32 sequence,
                        const QByteArray &key) const;

    // uid and tid override the echoed ones; session setup assigns the UID and
    // tree connect the TID, and both have to be in the header before a signed
    // reply is hashed or the client rejects the signature it is given.
    // `sign` exists for the reply that gives the session its key: the client
    // has not armed signing for that session yet, and a signature there is a
    // MAC in a field the client reads as a sequence number. Samba's server
    // builds its session-setup answer before it turns signing on, which is
    // what a Windows 2000 client is written against.
    QByteArray reply(const QByteArray &request, quint32 status, const QByteArray &words,
                     const QByteArray &data, int uid = -1, int tid = -1,
                     bool sign = true);
    QString stringAt(const QByteArray &data, int at) const;
    // Splits `data` on DCE/RPC frag_length and feeds each PDU to the channel.
    void feedPipe(OpenFile *file, const QByteArray &data);

    QHash<QString, RpcServer *> m_pipes;
    QHash<QString, QString> m_shares;
    Rpc::Authenticator m_authenticator;
    int m_lmCompatibilityLevel = Ntlm::kDefaultLmCompatibilityLevel;
    Rpc::KerberosAcceptor m_kerberosAcceptor;
    QString m_domain;
    QString m_serverName;
    QString m_dnsDomain;

    // One connection carries more than one session, and a Windows 2000 member's
    // logon always does: a Kerberos channel for the machine's computer account,
    // then a second session for the user over the same TCP connection. Each has
    // its own key, identity and signing counter, and each needs its own UID —
    // one set of members handed the user's session the machine's UID and then
    // refused the request that opened it as a bad signature, because the key on
    // the connection belonged to the other session.
    struct SessionState {
        bool authenticated = false;
        QString user;
        QByteArray challenge;
        QByteArray key;
        // One counter for both directions: MS-CIFS numbers each message in one
        // sequence, so the reply to a request carries the number after it. The
        // setup exchange takes the first two numbers, the request one before
        // this session existed and the answer one this side still spends even
        // when it carries no MAC, which leaves a freshly set-up session at 2 —
        // where Samba's server puts its own counter (smb1_signing_activate) and
        // where a Windows 2000 member signed its first tree connect.
        quint32 signingSeq = 1;
    };
    SessionState *sessionState(quint16 uid);
    const SessionState *sessionState(quint16 uid) const;
    QHash<quint16, SessionState> m_sessions;
    mutable quint32 m_sendSeq = 1;
    // Set when a request arrives saying it is signed. A client announces
    // that before it has a key to sign with, so the flag is intent: replies
    // are signed only for a session that asked for it.
    mutable bool m_signingActive = false;
    bool m_unicode = false;

    // A directory search an SMB1 client is walking. The matches are resolved on
    // FIND_FIRST2 and kept, so FIND_NEXT2 returns the same set even if the
    // directory changes between calls — which is what the resume key promises.
    struct Search {
        QStringList paths;
        int index = 0;
    };

    quint16 m_nextSearchId = 0x200;
    QHash<quint16, Search> m_searches;

    quint16 m_nextTree = 0x100;
    quint16 m_nextFid = 0x4000;
    QHash<quint16, QString> m_trees;
    // Which session connected each tree, so a logoff closes that session's
    // handles and leaves the other session on the connection alone.
    QHash<quint16, quint16> m_treeSession;
    QHash<quint16, OpenFile> m_files;

    std::function<void(const QString &)> m_notifier;
};

} // namespace Smb1

#endif // SMB1_H
