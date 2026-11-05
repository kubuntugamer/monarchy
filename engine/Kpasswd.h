// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef KPASSWD_H
#define KPASSWD_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>

#include <functional>

#include "resultsmodel.h"

class Kdc;
class QTcpServer;
class QUdpSocket;

// Kerberos change password (RFC 3244), the service an AD client reaches on
// port 464 — which is what the zone's `_kpasswd` locator records point at.
//
// The protocol is one request/reply pair over TCP or UDP: the AP-REQ proves
// who is asking and hands back a subsession key, and a KRB-PRIV sealed under
// that key carries the new password. Two request forms are accepted, because
// clients send both: version 0x0001 with the password in the clear inside the
// KRB-PRIV (the original change-password protocol MIT's krb5_change_password
// uses), and version 0xff80 with a ChangePasswdData structure that can also
// name another account to set (krb5_set_password).
//
// The password is written through the caller's writer, so it lands where every
// other credential write lands: the NT hash, the Kerberos keys and the
// simple-bind verifier all move together, and the new password works for
// Kerberos, NTLM and LDAP at once.
class KpasswdServer : public QObject
{
    Q_OBJECT
public:
    explicit KpasswdServer(QObject *parent = nullptr);
    ~KpasswdServer() override;

    // The KDC that verifies the AP-REQ; it holds the realm and the keys.
    void setKdc(Kdc *kdc);
    // The directory the target account is resolved in (same store as LDAP).
    void setObjectProvider(std::function<QList<DirectoryObject>()> provider);
    // (dn, newPassword) -> whether the store accepted it, with a reason.
    void setPasswordWriter(
        std::function<bool(const QString &dn, const QString &password, QString *error)> writer);

    bool listen(quint16 port = 464);
    void close();
    bool isListening() const;
    quint16 serverPort() const;

    // One RFC 3244 request message in, one reply out. Both transports use it.
    QByteArray handleRequest(const QByteArray &request);

signals:
    void requestReceived(const QString &summary);

private slots:
    void onTcpConnection();
    void onUdpDatagram();

private:
    struct Request {
        quint16 version = 0;
        QByteArray apReq;
        QByteArray krbPriv;
    };
    bool parseRequest(const QByteArray &message, Request *out) const;
    struct Outcome {
        quint16 code = 0;      // KRB5_KPASSWD_* result code
        QString message;       // shown to the user by the client
    };
    Outcome changePassword(const QString &clientDn, const QString &clientPrincipal,
                           const QByteArray &newPassword, const QString &targetName,
                           const QString &targetRealm, bool targetNamed);
    QByteArray resultPriv(const QByteArray &key, int etype, quint32 seq, quint16 code,
                          const QString &message) const;
    static QByteArray errorReply(const QByteArray &realm, quint16 code, const QString &message);
    static QByteArray unwrapApRep(const QByteArray &gssToken);
    static QByteArray frame(const QByteArray &apRep, const QByteArray &priv);
    bool isAdministrator(const QString &clientDn) const;

    Kdc *m_kdc = nullptr;
    std::function<QList<DirectoryObject>()> m_provider;
    std::function<bool(const QString &, const QString &, QString *)> m_writer;
    QTcpServer *m_tcp = nullptr;
    QUdpSocket *m_udp = nullptr;
    quint16 m_port = 0;
};

#endif // KPASSWD_H
