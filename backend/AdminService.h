// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ADMINSERVICE_H
#define ADMINSERVICE_H

#include "DirectoryService.h"

#include <QObject>
#include <QFuture>
#include <QString>

// High-level administration operations on top of DirectoryService.
class AdminService : public QObject
{
    Q_OBJECT
public:
    explicit AdminService(DirectoryService *directory, QObject *parent = nullptr);

    QFuture<bool> createUser(const QString &name, const QString &containerDn, const QString &password);
    QFuture<bool> createGroup(const QString &name, const QString &containerDn);
    QFuture<bool> createComputer(const QString &name, const QString &containerDn);
    QFuture<bool> createOu(const QString &name, const QString &parentDn);
    QFuture<bool> resetPassword(const QString &userDn, const QString &newPassword, bool mustChange);
    // Membership is a multi-valued `member` attribute on the group, so both
    // operations read the current list, change one entry and write it back.
    QFuture<bool> addMember(const QString &groupDn, const QString &memberDn);
    QFuture<bool> removeMember(const QString &groupDn, const QString &memberDn);
    QFuture<bool> addUserToGroup(const QString &userDn, const QString &groupDn);
    QFuture<bool> removeUserFromGroup(const QString &userDn, const QString &groupDn);

signals:
    void error(const QString &message);

private:
    DirectoryService *m_directory = nullptr;
};

#endif // ADMINSERVICE_H