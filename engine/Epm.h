// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef EPM_H
#define EPM_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>

#include "Rpc.h"

class RpcServer;

// The endpoint mapper (ncacn_epm, port 135): the service a client asks when it
// knows an interface's UUID and a protocol but not its port. MS-RPCE leaves it
// to DCE 1.1 RPC chapter 6, whose interface is `e1af8308-5d1f-11c9-91a4-
// 08002b14a0fa` v3.0; the towers that answer it are encoded by C706 appendix L,
// not by NDR (`reference/specs/samba-epmapper.idl`, `impacket-epm.py`).
namespace Epm {

// Opnum table from C706 chapter 6 (the same numbering in Samba's epmapper.idl).
enum Opnum : quint16 {
    OpInsert = 0,
    OpDelete = 1,
    OpLookup = 2,
    OpMap = 3,
    OpLookupHandleFree = 4,
    OpInqObject = 5,
    OpMgmtDelete = 6,
    OpMapAuth = 7
};

// EPMAPPER_STATUS_* (epmapper.idl).
enum Status : quint32 {
    StatusOk = 0x00000000u,
    StatusCantPerformOp = 0x000006d8u,
    StatusNoMemory = 0x16c9a012u,
    StatusNoMoreEntries = 0x16c9a0d6u
};

// Inquiry types and version options (C706 6.2.2; ept_lookup_handle_t carries
// the paging state between calls).
enum InquiryType : quint32 {
    InquiryAllElements = 0,
    InquiryMatchByInterface = 1,
    InquiryMatchByObject = 2,
    InquiryMatchByBoth = 3
};

enum VersionOption : quint32 {
    VersionAll = 0,
    VersionCompatible = 1,
    VersionExact = 2,
    VersionMajorOnly = 3,
    VersionUpTo = 4
};

// One registered endpoint: an interface version served on a TCP port. The
// annotation is the human-readable name a lookup returns beside the tower, the
// same way a Windows DC annotates its own entries.
struct Entry {
    QByteArray uuid; // 16 bytes, wire order
    quint16 major = 0;
    quint16 minor = 0;
    quint16 port = 0;    // ncacn_ip_tcp endpoint
    QString pipe;         // named pipe, when the entry is an ncacn_np endpoint
    QString annotation;

    bool isPipe() const { return !pipe.isEmpty(); }
};

Rpc::Interface interface();

// The C706 appendix L tower for this entry: five floors. For a TCP endpoint they
// are interface, data representation, ncacn, tcp, ip — lengths little-endian,
// the port and the address big-endian. For a named pipe the last two are the
// pipe name (0x0f) and the host name (0x11), which is the tower a client asking
// for `ncacn_np` matches.
QByteArray tower(const Entry &entry, const QHostAddress &address,
                 const QString &hostName = QString());

} // namespace Epm

// A single-interface RPC endpoint that answers lookups with the entries the
// console registers: every other interface served on this DC, so a client can
// discover a port instead of being told one.
class EpmServer : public QObject
{
    Q_OBJECT

public:
    explicit EpmServer(QObject *parent = nullptr);

    // The interfaces to advertise. Ports are whatever the endpoints actually
    // bound, so a lookup answer is always a port that accepts a connection.
    void setEntries(const QList<Epm::Entry> &entries);
    QList<Epm::Entry> entries() const { return m_entries; }
    // The address put in the fifth floor. Loopback when the endpoints are
    // loopback, so a client that trusts the answer connects somewhere real.
    void setAdvertisedAddress(const QHostAddress &address);
    // The name a named-pipe tower carries in its host floor.
    void setHostName(const QString &hostName);

    bool listen(quint16 port = 135, const QHostAddress &address = QHostAddress::LocalHost);
    void close();
    bool isListening() const;
    quint16 serverPort() const;
    RpcServer *rpc() const { return m_rpc; }

    // One NDR request in, one response out, for the endpoint and the tests.
    QByteArray handleCall(quint16 opnum, const QByteArray &stub);

signals:
    void requestReceived(const QString &operation);

private:
    QByteArray lookup(const QByteArray &stub);
    QByteArray map(const QByteArray &stub);

    RpcServer *m_rpc = nullptr;
    QList<Epm::Entry> m_entries;
    QHostAddress m_address = QHostAddress::LocalHost;
    QString m_hostName;
};

#endif // EPM_H
