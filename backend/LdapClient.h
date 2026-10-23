// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef LDAPCLIENT_H
#define LDAPCLIENT_H

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QTcpSocket>

// Real LDAP v3 (RFC 4511) wire client. Speaks BER over TCP to any LDAP server,
// including Monarchy's own DC. Synchronous/blocking: create one per worker thread
// or per operation; never share across threads.
class LdapClient
{
public:
    struct Entry {
        QString dn;
        QMap<QString, QStringList> attrs;
    };

    LdapClient() = default;
    ~LdapClient();

    LdapClient(const LdapClient &) = delete;
    LdapClient &operator=(const LdapClient &) = delete;

    bool open(const QString &host, quint16 port, QString *error, int timeoutMs = 5000);
    bool bind(const QString &dn, const QString &password, QString *error);
    QList<Entry> search(const QString &base, int scope, const QString &filter,
                        const QStringList &attributes, QString *error);
    bool add(const QString &dn, const QMap<QString, QStringList> &attrs, QString *error);
    bool modify(const QString &dn, const QMap<QString, QStringList> &replace, QString *error);
    bool del(const QString &dn, QString *error);
    void close(); // unbind + disconnect

    bool isOpen() const { return m_socket.state() == QAbstractSocket::ConnectedState; }

private:
    bool sendMessage(const QByteArray &message);
    bool readMessage(QByteArray *frame, int timeoutMs, QString *error);
    bool waitResult(quint8 expectTag, int *resultCode, int timeoutMs, QString *error);

    QTcpSocket m_socket;
    QByteArray m_buffer;
    int m_nextId = 1;
};

#endif // LDAPCLIENT_H
