// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRSCLIENT_H
#define DRSCLIENT_H

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>

#include "Ntlm.h"
#include "resultsmodel.h"

class QTcpSocket;

// The outbound half of DRSUAPI: what a DC runs to pull a cycle from a partner
// (MS-DRSR §3.1.4 step 1). The decoder is kept separate from the socket so the
// marshalling can be checked against a reply the server built without any
// network at all.
namespace DrsWire {

// The DRS_HANDLE a DsBind reply carries: a 16-byte GUID plus a 4-byte pad.
constexpr int kHandleSize = 20;

// One DCE/RPC bind for the DRSUAPI interface, offering NDR32 only.
QByteArray bindPdu(quint32 callId, const QByteArray &abstractUuid, quint16 major,
                   quint16 minor);

// One DCE/RPC request PDU for `opnum` with this stub.
QByteArray requestPdu(quint32 callId, quint16 opnum, const QByteArray &stub);

// DsBind (opnum 0) request stub: a client DSA GUID and an extensions word that
// declares the GetNCChanges shapes this client understands.
QByteArray dsBindRequest();

// Pulls the handle and the call's ErrorCode out of a DsBind reply.
bool parseDsBindReply(const QByteArray &stub, QByteArray *handle, quint32 *werr);

// DsGetNCChanges (opnum 3) request: a V8 request filtered by USN, asking for
// the whole naming context under `ncDn`. Only the object half of a cycle is
// requested (no extended operation), which is what a pull replication uses.
QByteArray getNCChangesRequest(const QByteArray &handle, const QString &ncDn,
                               quint64 fromUsn, quint32 maxObjects);

// Decodes a V6 GetNCChanges reply into the objects it carries, reports the
// cursor the reply advances (the USN to ask from next time) and whether the
// server still holds changes this cycle did not fit.
bool parseGetNCChangesReply(const QByteArray &stub, QList<DirectoryObject> *objects,
                            quint64 *usnHigh, bool *moreData, quint32 *werr);

} // namespace DrsWire

class DrsClient : public QObject
{
    Q_OBJECT

public:
    explicit DrsClient(QObject *parent = nullptr);
    ~DrsClient() override;

    // ncacn_ip_tcp to a DRS endpoint. A DC publishes DRS on a dynamic port
    // discovered through EPM; this client takes the port it is given.
    void setPeer(const QString &host, quint16 port);
    void setTimeouts(int connectMs, int readMs);

    // The security provider. With credentials the bind carries an NTLMSSP
    // NEGOTIATE, the answer carries the CHALLENGE and an AUTH3 completes it;
    // every call is then signed, and sealed at level 6. Without credentials the
    // client binds unauthenticated, which a peer that enforces authentication
    // faults rather than serving.
    void setCredentials(const QString &domain, const QString &user, const QString &password);
    // 1 connect, 2 integrity, 6 privacy (MS-RPCE §2.2.3.5). Default 6.
    void setAuthLevel(quint8 level) { m_authLevel = level; }
    bool isAuthenticated() const { return m_authenticated; }

    bool connectToPeer(QString *error = nullptr);
    void close();
    bool isConnected() const;

    // The DCE bind of the interface, separate from DsBind: the transport
    // handshake has to succeed before any call can be made.
    bool bindInterface(QString *error = nullptr);

    // DsBind (0), which every other call's handle comes from, and DsUnbind (1).
    bool dsBind(QString *error = nullptr);
    bool dsUnbind(QString *error = nullptr);

    // One pull cycle. The caller applies the objects with
    // LdapServer::applyReplication and asks again while `moreData` is true.
    bool getNCChanges(const QString &ncDn, quint64 fromUsn,
                      QList<DirectoryObject> *objects, quint64 *usnHigh,
                      bool *moreData, QString *error = nullptr);

    // Any other opnum, for the calls this class does not model yet.
    bool call(quint16 opnum, const QByteArray &stub, QByteArray *replyStub,
              QString *error = nullptr);

    QByteArray handle() const { return m_handle; }
    bool interfaceBound() const { return m_interfaceBound; }

signals:
    // One line per call, for the same tracing the server side emits.
    void callCompleted(const QString &operation);

private:
    bool writePdu(const QByteArray &pdu, QString *error);
    // Reads one whole message, joining fragments until PFC_LAST_FRAG.
    // Reads one whole message, joining fragments until PFC_LAST_FRAG. A signed
    // reply is verified and unsealed here; a bind_ack's token comes back in
    // `authToken`.
    bool readMessage(quint32 callId, quint8 *type, QByteArray *body, QByteArray *authToken,
                     quint32 *faultStatus, QString *error);
    bool callInternal(quint16 opnum, const QString &name, const QByteArray &stub,
                      QByteArray *replyStub, QString *error);

    QTcpSocket *m_socket = nullptr;
    QString m_host;
    quint16 m_port = 0;
    int m_connectTimeoutMs = 5000;
    int m_readTimeoutMs = 30000;
    quint32 m_callId = 0;
    QByteArray m_handle;
    QByteArray m_buffer;
    bool m_interfaceBound = false;

    // NTLMSSP session state: the keys the per-PDU signatures use and the two
    // directions' sequence numbers, which start at zero on each side.
    QString m_domain;
    QString m_user;
    QString m_password;
    bool m_credentialsSet = false;
    bool m_authenticated = false;
    quint8 m_authLevel = 6;
    Ntlm::SessionKeys m_keys;
    Ntlm::Sealer m_sendSealer;
    Ntlm::Sealer m_recvSealer;
    quint32 m_sendSeq = 0;
    quint32 m_recvSeq = 0;
};

#endif // DRSCLIENT_H
