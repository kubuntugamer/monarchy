// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PROPERTYSHEET_H
#define PROPERTYSHEET_H

#include "resultsmodel.h"

#include <QDialog>

class QCheckBox;
class QDateEdit;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTabWidget;
class QTableWidget;

// Classic tabbed MMC property sheet for a single directory object.
class PropertySheet : public QDialog
{
    Q_OBJECT

public:
    explicit PropertySheet(const DirectoryObject &object, QWidget *parent = nullptr);

    DirectoryObject object() const { return m_object; }

    // The objects that may be added to a group (or to this object's groups).
    // Set before exec(); the Add button stays disabled while the list is empty.
    void setMembershipCandidates(const QList<DirectoryObject> &candidates);

public slots:
    void accept() override;

private:
    void addGeneralTab(QTabWidget *tabs);
    void addMembershipTab(QTabWidget *tabs, bool groupMembers);
    void addMembershipItem(const QString &value);
    void chooseMembershipTargets();
    void removeSelectedMembership();
    void updateMembershipLabel();
    void syncMembership();
    QString membershipLabel(const QString &value) const;
    bool hasMembershipValue(const QString &value) const;
    void addAttributesTab(QTabWidget *tabs);
    void addProfileTab(QTabWidget *tabs);
    void addAccountTab(QTabWidget *tabs);
    void addEnvironmentTab(QTabWidget *tabs);
    void addSessionsTab(QTabWidget *tabs);
    void addRemoteControlTab(QTabWidget *tabs);
    void addTerminalServicesTab(QTabWidget *tabs);
    void addComPlusTab(QTabWidget *tabs);
    void refreshAttributesTable();
    void applyChanges();

    QString attribute(const QString &key) const { return m_object.attributes.value(key); }

    DirectoryObject m_object;
    QLabel *m_headerName = nullptr;
    QLabel *m_headerDescription = nullptr;
    QLineEdit *m_firstName = nullptr;
    QLineEdit *m_lastName = nullptr;
    QLineEdit *m_displayName = nullptr;
    QLineEdit *m_description = nullptr;
    QLineEdit *m_office = nullptr;
    QLineEdit *m_telephone = nullptr;
    QLineEdit *m_email = nullptr;
    QLineEdit *m_webPage = nullptr;
    QLineEdit *m_profilePath = nullptr;
    QLineEdit *m_homeDrive = nullptr;
    QLineEdit *m_homeDirectory = nullptr;
    QLineEdit *m_logonScript = nullptr;
    QCheckBox *m_mustChangePassword = nullptr;
    QCheckBox *m_cannotChangePassword = nullptr;
    QCheckBox *m_passwordNeverExpires = nullptr;
    QCheckBox *m_accountDisabled = nullptr;
    QCheckBox *m_accountLockedOut = nullptr;
    QDateEdit *m_accountExpires = nullptr;
    QTableWidget *m_attributesTable = nullptr;
    QListWidget *m_membershipList = nullptr;
    QLabel *m_membershipLabel = nullptr;
    QPushButton *m_addMemberButton = nullptr;
    bool m_membershipIsMembers = false;
    QList<DirectoryObject> m_candidates;
};

#endif // PROPERTYSHEET_H
