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
    Session(QHash<QString, RpcServer *> pipes, Rpc::Authenticator authenticator,
            QString domain, QString serverName, QString dnsDomain,
            QHash<QString, QString> shares = QHash<QString, QString>());

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
    QByteArray trans2(const QByteArray &message);
    // FIND_FIRST2 / FIND_NEXT2 / FIND_CLOSE2, the TRANS2 half a directory
    // listing needs. MS-CIFS 2.2.6.3.
    QByteArray find(const QByteArray &message, quint16 subcommand,
                    const QByteArray &parameters, const QString &shareRoot);
    QByteArray unsupported(quint8 command);
    bool signatureValid(const QByteArray &message) const;

    QByteArray reply(const QByteArray &request, quint32 status, const QByteArray &words,
                     const QByteArray &data) const;
    QString stringAt(const QByteArray &data, int at) const;
    // Splits `data` on DCE/RPC frag_length and feeds each PDU to the channel.
    void feedPipe(OpenFile *file, const QByteArray &data);

    QHash<QString, RpcServer *> m_pipes;
    QHash<QString, QString> m_shares;
    Rpc::Authenticator m_authenticator;
    QString m_domain;
    QString m_serverName;
    QString m_dnsDomain;

    QByteArray m_challenge;
    QByteArray m_sessionKey;
    mutable quint32 m_sendSeq = 1;
    bool m_authenticated = false;
    QString m_user;
    bool m_unicode = false;
    quint16 m_uid = 0;

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
    QHash<quint16, OpenFile> m_files;

    std::function<void(const QString &)> m_notifier;
};

} // namespace Smb1

#endif // SMB1_H
