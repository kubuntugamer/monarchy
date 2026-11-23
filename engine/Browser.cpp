// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Browser.h"

namespace {

QByteArray statusOnly(quint32 status)
{
    QByteArray out;
    out.append(char(status & 0xff));
    out.append(char((status >> 8) & 0xff));
    out.append(char((status >> 16) & 0xff));
    out.append(char((status >> 24) & 0xff));
    return out;
}

void putLe32(QByteArray *out, quint32 value)
{
    out->append(char(value & 0xff));
    out->append(char((value >> 8) & 0xff));
    out->append(char((value >> 16) & 0xff));
    out->append(char((value >> 24) & 0xff));
}

} // namespace

namespace Browser {

Rpc::Interface interface()
{
    Rpc::Interface out;
    // 6bffd098-a112-3610-9833-012892020162 v0.0 on the wire: the first three
    // fields little-endian, the last eight bytes as written.
    out.uuid = QByteArray::fromHex("98d0ff6b12a110369833012892020162");
    out.major = 0;
    out.minor = 0;
    out.name = QStringLiteral("browser");
    return out;
}

} // namespace Browser

BrowserServer::BrowserServer(QObject *parent) : QObject(parent)
{
    m_rpc = new RpcServer(this);
    m_rpc->setInterface(Browser::interface(),
                        [this](const Rpc::Call &call) { return handleCall(call.opnum, call.stub); });
    connect(m_rpc, &RpcServer::requestReceived, this, &BrowserServer::requestReceived);
}

void BrowserServer::setAuthenticator(Rpc::Authenticator authenticator)
{
    m_rpc->setAuthenticator(std::move(authenticator));
}

bool BrowserServer::listen(quint16 port, const QHostAddress &address)
{
    return m_rpc->listen(port, address);
}

void BrowserServer::close()
{
    m_rpc->close();
}

bool BrowserServer::isListening() const
{
    return m_rpc->isListening();
}

quint16 BrowserServer::serverPort() const
{
    return m_rpc->serverPort();
}

QByteArray BrowserServer::handleCall(quint16 opnum, const QByteArray &stub)
{
    Q_UNUSED(stub)
    if (opnum == Browser::OpQueryOtherDomains) {
        // The reply body the IDL declares, carrying the answer instead of a
        // refusal: the [in,out] SERVER_ENUM at level 100 whose container is
        // empty (no other domains in this forest), the [out] TotalEntries of
        // zero, and NERR_Success. NDR writes the unique pointer referents before
        // the values they point at, and the container is deferred before
        // TotalEntries' value because it was reached first.
        QByteArray out;
        putLe32(&out, 0x00020000u); // InfoStruct: present
        putLe32(&out, 100);         // Level = 100 (SERVER_INFO_100)
        putLe32(&out, 0x00020004u); // Level100: present, the container follows
        putLe32(&out, 0x00020008u); // TotalEntries: present, the count follows
        putLe32(&out, 0);           // container EntriesRead: no other domains
        putLe32(&out, 0);           // container Buffer: NULL
        putLe32(&out, 0);           // TotalEntries
        putLe32(&out, Browser::kErrorSuccess);
        emit requestReceived(
            QStringLiteral("browser QueryOtherDomains: no other domains"));
        return out;
    }
    // Any other opnum is refused by status: a client that gets
    // ERROR_NOT_SUPPORTED has other ways to enumerate and takes one, while an
    // invented SERVER_INFO container would be a layout no Windows client ever
    // sent this server. The pipe itself is what makes the difference — opening
    // it is how a 2000 member starts the enumeration at all, and refusing the
    // open with STATUS_OBJECT_NAME_NOT_FOUND is what stopped its logon.
    emit requestReceived(QStringLiteral("browser opnum %1 refused").arg(opnum));
    return statusOnly(Browser::kErrorNotSupported);
}
