// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "propertysheet.h"

#include "objecticons.h"

#include <QCheckBox>
#include <QDateEdit>
#include <QDialogButtonBox>
#include <QComboBox>
#include <QGroupBox>
#include <QRadioButton>
#include <QSpinBox>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

QLineEdit *readOnlyLineEdit(const QString &text, QWidget *parent)
{
    auto *edit = new QLineEdit(text, parent);
    edit->setReadOnly(true);
    edit->setCursorPosition(0);
    return edit;
}

QLabel *readOnlyLabel(const QString &text, QWidget *parent)
{
    auto *label = new QLabel(text, parent);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return label;
}

} // namespace

PropertySheet::PropertySheet(const DirectoryObject &object, QWidget *parent)
    : QDialog(parent)
    , m_object(object)
{
    setWindowTitle(tr("%1 Properties").arg(m_object.name));
    setWindowIcon(objectIcon(m_object.kind));
    setModal(true);
    resize(540, 500);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    // Header: object icon, name, type, description.
    auto *header = new QHBoxLayout;
    header->setSpacing(10);

    auto *iconLabel = new QLabel(this);
    iconLabel->setPixmap(objectIcon(m_object.kind).pixmap(32, 32));
    iconLabel->setFixedSize(36, 36);
    iconLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    header->addWidget(iconLabel);

    auto *headerText = new QVBoxLayout;
    headerText->setSpacing(1);

    m_headerName = new QLabel(m_object.name, this);
    QFont nameFont = m_headerName->font();
    nameFont.setBold(true);
    nameFont.setPointSize(nameFont.pointSize() + 1);
    m_headerName->setFont(nameFont);
    headerText->addWidget(m_headerName);

    m_headerDescription = new QLabel(m_object.description, this);
    m_headerDescription->setWordWrap(true);
    m_headerDescription->setStyleSheet(QStringLiteral("color: #4a4a4a;"));
    headerText->addWidget(m_headerDescription);

    auto *typeLabel = new QLabel(tr("%1  ·  %2").arg(m_object.type, m_object.container), this);
    typeLabel->setStyleSheet(QStringLiteral("color: #5a5a5a;"));
    headerText->addWidget(typeLabel);

    header->addLayout(headerText, 1);
    layout->addLayout(header);

    auto *rule = new QFrame(this);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Sunken);
    layout->addWidget(rule);

    auto *tabs = new QTabWidget(this);
    addGeneralTab(tabs);
    addMembershipTab(tabs, m_object.kind == ObjectKind::Group);
    addAttributesTab(tabs);
    if (m_object.kind == ObjectKind::User) {
        addProfileTab(tabs);
        addAccountTab(tabs);
        addEnvironmentTab(tabs);
        addSessionsTab(tabs);
        addRemoteControlTab(tabs);
        addTerminalServicesTab(tabs);
        addComPlusTab(tabs);
    }
    layout->addWidget(tabs, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok
                                             | QDialogButtonBox::Cancel
                                             | QDialogButtonBox::Apply
                                             | QDialogButtonBox::Help,
                                         this);
    connect(buttons, &QDialogButtonBox::accepted, this, &PropertySheet::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons->button(QDialogButtonBox::Apply), &QPushButton::clicked,
            this, &PropertySheet::applyChanges);
    if (auto *helpButton = buttons->button(QDialogButtonBox::Help)) {
        connect(helpButton, &QPushButton::clicked, this, [this] {
            QMessageBox::information(this, tr("Property Sheet Help"),
                tr("Edit the fields on the General tab, then click OK or Apply. "
                   "Use Add/Remove on the membership tab to change group membership; "
                   "the Attribute Editor is a read-only view."));
        });
    }
    layout->addWidget(buttons);
}

void PropertySheet::addGeneralTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *form = new QFormLayout(page);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(8);
    form->setVerticalSpacing(6);

    if (m_object.kind == ObjectKind::User) {
        m_firstName = new QLineEdit(attribute(QStringLiteral("givenName")), page);
        m_firstName->setObjectName(QStringLiteral("firstNameEdit"));
        form->addRow(tr("&First name:"), m_firstName);

        m_lastName = new QLineEdit(attribute(QStringLiteral("sn")), page);
        m_lastName->setObjectName(QStringLiteral("lastNameEdit"));
        form->addRow(tr("&Last name:"), m_lastName);
    }

    m_displayName = new QLineEdit(m_object.name, page);
    m_displayName->setObjectName(QStringLiteral("displayNameEdit"));
    form->addRow(tr("&Display name:"), m_displayName);

    m_description = new QLineEdit(m_object.description, page);
    m_description->setObjectName(QStringLiteral("descriptionEdit"));
    form->addRow(tr("&Description:"), m_description);

    if (m_object.kind == ObjectKind::User) {
        m_office = new QLineEdit(attribute(QStringLiteral("physicalDeliveryOfficeName")), page);
        m_office->setObjectName(QStringLiteral("officeEdit"));
        form->addRow(tr("&Office:"), m_office);

        m_telephone = new QLineEdit(attribute(QStringLiteral("telephoneNumber")), page);
        m_telephone->setObjectName(QStringLiteral("telephoneEdit"));
        form->addRow(tr("Telep&hone:"), m_telephone);

        m_email = new QLineEdit(attribute(QStringLiteral("mail")), page);
        m_email->setObjectName(QStringLiteral("emailEdit"));
        form->addRow(tr("E-&mail:"), m_email);

        m_webPage = new QLineEdit(attribute(QStringLiteral("wWWHomePage")), page);
        m_webPage->setObjectName(QStringLiteral("webPageEdit"));
        form->addRow(tr("&Web page:"), m_webPage);

        form->addRow(tr("User logon name:"), readOnlyLabel(attribute(QStringLiteral("sAMAccountName")), page));
        form->addRow(tr("Account options:"), readOnlyLabel(attribute(QStringLiteral("userAccountControl")), page));
    } else if (m_object.kind == ObjectKind::Group) {
        form->addRow(tr("Group scope:"), readOnlyLabel(attribute(QStringLiteral("groupScope")), page));
        form->addRow(tr("Group type:"), readOnlyLabel(attribute(QStringLiteral("groupType")), page));
    } else if (m_object.kind == ObjectKind::Computer) {
        form->addRow(tr("Computer name:"), readOnlyLabel(attribute(QStringLiteral("dNSHostName")), page));
        form->addRow(tr("Operating system:"), readOnlyLabel(attribute(QStringLiteral("operatingSystem")), page));
    }

    form->addRow(tr("Type:"), readOnlyLabel(m_object.type, page));

    auto *dn = readOnlyLineEdit(m_object.id, page);
    dn->setObjectName(QStringLiteral("distinguishedNameEdit"));
    dn->setToolTip(m_object.id);
    form->addRow(tr("Distinguished name:"), dn);

    form->addRow(tr("Container:"), readOnlyLabel(m_object.container, page));

    tabs->addTab(page, tr("General"));
}

void PropertySheet::addMembershipTab(QTabWidget *tabs, bool groupMembers)
{
    m_membershipIsMembers = groupMembers;
    const QString title = groupMembers ? tr("Members") : tr("Member Of");

    auto *page = new QWidget(tabs);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    m_membershipLabel = new QLabel(page);
    layout->addWidget(m_membershipLabel);

    m_membershipList = new QListWidget(page);
    m_membershipList->setObjectName(QStringLiteral("membershipList"));
    m_membershipList->setAlternatingRowColors(true);
    m_membershipList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(m_membershipList, 1);

    for (const QString &value : groupMembers ? m_object.members : m_object.memberOf)
        addMembershipItem(value);

    auto *buttons = new QHBoxLayout;
    m_addMemberButton = new QPushButton(tr("&Add..."), page);
    m_addMemberButton->setObjectName(QStringLiteral("addMemberButton"));
    m_addMemberButton->setEnabled(!m_candidates.isEmpty());
    auto *removeButton = new QPushButton(tr("&Remove"), page);
    removeButton->setObjectName(QStringLiteral("removeMemberButton"));
    connect(m_addMemberButton, &QPushButton::clicked, this, &PropertySheet::chooseMembershipTargets);
    connect(removeButton, &QPushButton::clicked, this, &PropertySheet::removeSelectedMembership);
    buttons->addWidget(m_addMemberButton);
    buttons->addWidget(removeButton);
    buttons->addStretch(1);
    layout->addLayout(buttons);

    updateMembershipLabel();
    tabs->addTab(page, title);
}

void PropertySheet::setMembershipCandidates(const QList<DirectoryObject> &candidates)
{
    m_candidates = candidates;
    if (m_addMemberButton)
        m_addMemberButton->setEnabled(!m_candidates.isEmpty());
    if (m_membershipList) {
        // Labels are resolved against the candidates, so refresh them now.
        const QStringList values = m_membershipIsMembers ? m_object.members : m_object.memberOf;
        m_membershipList->clear();
        for (const QString &value : values)
            addMembershipItem(value);
        updateMembershipLabel();
    }
}

QString PropertySheet::membershipLabel(const QString &value) const
{
    for (const DirectoryObject &object : m_candidates) {
        if (object.id.compare(value, Qt::CaseInsensitive) == 0)
            return object.name;
    }
    if (value.contains(QLatin1Char('=')))
        return value.section(QLatin1Char(','), 0, 0).section(QLatin1Char('='), 1);
    return value;
}

bool PropertySheet::hasMembershipValue(const QString &value) const
{
    if (!m_membershipList)
        return false;
    for (int row = 0; row < m_membershipList->count(); ++row) {
        if (m_membershipList->item(row)->data(Qt::UserRole).toString()
                .compare(value, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

void PropertySheet::addMembershipItem(const QString &value)
{
    if (!m_membershipList || value.isEmpty() || hasMembershipValue(value))
        return;
    auto *item = new QListWidgetItem(membershipLabel(value), m_membershipList);
    item->setData(Qt::UserRole, value);
    item->setToolTip(value);
}

void PropertySheet::chooseMembershipTargets()
{
    QStringList labels;
    QStringList values;
    for (const DirectoryObject &object : m_candidates) {
        if (object.id.isEmpty()
            || object.id.compare(m_object.id, Qt::CaseInsensitive) == 0
            || hasMembershipValue(object.id))
            continue;
        // A group's Members tab takes users, computers and other groups; a
        // Member Of tab only takes groups.
        if (!m_membershipIsMembers && object.kind != ObjectKind::Group)
            continue;
        labels.append(object.name);
        values.append(object.id);
    }

    if (labels.isEmpty()) {
        QMessageBox::information(this, tr("Select Objects"),
                                 tr("There is no object left to add."));
        return;
    }

    bool accepted = false;
    const QString chosen = QInputDialog::getItem(
        this, tr("Select Objects"),
        m_membershipIsMembers ? tr("Add to this group:") : tr("Add this object to the group:"),
        labels, 0, false, &accepted);
    if (!accepted)
        return;
    const int index = labels.indexOf(chosen);
    if (index < 0)
        return;
    addMembershipItem(values.at(index));
    updateMembershipLabel();
}

void PropertySheet::removeSelectedMembership()
{
    if (!m_membershipList)
        return;
    const QList<QListWidgetItem *> selected = m_membershipList->selectedItems();
    for (QListWidgetItem *item : selected)
        delete item;
    updateMembershipLabel();
}

void PropertySheet::updateMembershipLabel()
{
    if (!m_membershipLabel || !m_membershipList)
        return;
    const QString title = m_membershipIsMembers ? tr("Members") : tr("Member Of");
    if (m_membershipList->count() == 0) {
        m_membershipLabel->setText(m_membershipIsMembers
                                       ? tr("This group has no members.")
                                       : tr("This object is not a member of any groups."));
        return;
    }
    m_membershipLabel->setText(tr("%1 (%2):").arg(title).arg(m_membershipList->count()));
}

void PropertySheet::syncMembership()
{
    if (!m_membershipList)
        return;
    QStringList values;
    for (int row = 0; row < m_membershipList->count(); ++row)
        values.append(m_membershipList->item(row)->data(Qt::UserRole).toString());
    if (m_membershipIsMembers)
        m_object.members = values;
    else
        m_object.memberOf = values;
}

void PropertySheet::addAttributesTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    auto *note = new QLabel(tr("Read-only view of the attributes held by this console."), page);
    note->setStyleSheet(QStringLiteral("color: #5a5a5a;"));
    layout->addWidget(note);

    m_attributesTable = new QTableWidget(0, 2, page);
    m_attributesTable->setHorizontalHeaderLabels({tr("Attribute"), tr("Value")});
    m_attributesTable->verticalHeader()->setVisible(false);
    m_attributesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_attributesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_attributesTable->setAlternatingRowColors(true);
    m_attributesTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_attributesTable, 1);

    refreshAttributesTable();
    tabs->addTab(page, tr("Attribute Editor"));
}

void PropertySheet::refreshAttributesTable()
{
    if (!m_attributesTable)
        return;

    QMap<QString, QString> attributes = m_object.attributes;
    attributes.insert(QStringLiteral("distinguishedName"), m_object.id);
    attributes.insert(QStringLiteral("name"), m_object.name);
    attributes.insert(QStringLiteral("description"), m_object.description);
    if (m_object.kind == ObjectKind::Group)
        attributes.insert(QStringLiteral("member"), m_object.members.join(QStringLiteral("; ")));
    else
        attributes.insert(QStringLiteral("memberOf"), m_object.memberOf.join(QStringLiteral("; ")));

    m_attributesTable->clearContents();
    m_attributesTable->setRowCount(attributes.size());

    int row = 0;
    for (auto it = attributes.cbegin(); it != attributes.cend(); ++it, ++row) {
        m_attributesTable->setItem(row, 0, new QTableWidgetItem(it.key()));
        m_attributesTable->setItem(row, 1, new QTableWidgetItem(it.value()));
    }
    m_attributesTable->resizeColumnToContents(0);
}

void PropertySheet::addProfileTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *form = new QFormLayout(page);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(8);
    form->setVerticalSpacing(6);

    m_profilePath = new QLineEdit(attribute(QStringLiteral("profilePath")), page);
    m_profilePath->setObjectName(QStringLiteral("profilePathEdit"));
    form->addRow(tr("Profile path:"), m_profilePath);

    m_logonScript = new QLineEdit(attribute(QStringLiteral("scriptPath")), page);
    m_logonScript->setObjectName(QStringLiteral("logonScriptEdit"));
    form->addRow(tr("Logon script:"), m_logonScript);

    m_homeDrive = new QLineEdit(attribute(QStringLiteral("homeDrive")), page);
    m_homeDrive->setObjectName(QStringLiteral("homeDriveEdit"));
    form->addRow(tr("Home drive:"), m_homeDrive);

    m_homeDirectory = new QLineEdit(attribute(QStringLiteral("homeDirectory")), page);
    m_homeDirectory->setObjectName(QStringLiteral("homeDirectoryEdit"));
    form->addRow(tr("Home directory:"), m_homeDirectory);

    auto *note = new QLabel(tr("These settings are stored on the object and applied at logon."), page);
    note->setStyleSheet(QStringLiteral("color: #5a5a5a;"));
    form->addRow(QString(), note);

    tabs->addTab(page, tr("Profile"));
}

void PropertySheet::addAccountTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    auto *optionsGroup = new QGroupBox(tr("Account options"), page);
    auto *optionsLayout = new QVBoxLayout(optionsGroup);
    m_mustChangePassword = new QCheckBox(tr("User must change password at next logon"), optionsGroup);
    m_cannotChangePassword = new QCheckBox(tr("User cannot change password"), optionsGroup);
    m_passwordNeverExpires = new QCheckBox(tr("Password never expires"), optionsGroup);
    m_accountDisabled = new QCheckBox(tr("Account is disabled"), optionsGroup);
    m_accountDisabled->setObjectName(QStringLiteral("accountDisabledCheck"));
    m_passwordNeverExpires->setObjectName(QStringLiteral("passwordNeverExpiresCheck"));
    m_accountLockedOut = new QCheckBox(tr("Account is locked out"), optionsGroup);
    optionsLayout->addWidget(m_mustChangePassword);
    optionsLayout->addWidget(m_cannotChangePassword);
    optionsLayout->addWidget(m_passwordNeverExpires);
    optionsLayout->addWidget(m_accountDisabled);
    optionsLayout->addWidget(m_accountLockedOut);
    layout->addWidget(optionsGroup);

    auto *expiresGroup = new QGroupBox(tr("Account expires"), page);
    auto *expiresLayout = new QFormLayout(expiresGroup);
    m_accountExpires = new QDateEdit(page);
    m_accountExpires->setCalendarPopup(true);
    m_accountExpires->setDisplayFormat(QStringLiteral("yyyy-MM-dd"));
    m_accountExpires->setSpecialValueText(tr("Never"));
    expiresLayout->addRow(tr("Expires on:"), m_accountExpires);
    layout->addWidget(expiresGroup);

    layout->addStretch(1);

    // Initialize from attributes.
    // The Account tab reflects the real userAccountControl flags (MS-ADTS 2.2.16).
    const quint32 uac = attribute(QStringLiteral("userAccountControl")).toUInt();
    m_accountDisabled->setChecked((uac & 0x0002u) != 0);        // ACCOUNTDISABLE
    m_passwordNeverExpires->setChecked((uac & 0x10000u) != 0);  // DONT_EXPIRE_PASSWORD

    tabs->addTab(page, tr("Account"));
}

void PropertySheet::addEnvironmentTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *form = new QFormLayout(page);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(8);
    form->setVerticalSpacing(6);

    auto *startupProgram = new QLineEdit(attribute(QStringLiteral("startupProgram")), page);
    startupProgram->setObjectName(QStringLiteral("startupProgramEdit"));
    form->addRow(tr("Startup program:"), startupProgram);

    auto *startupDir = new QLineEdit(attribute(QStringLiteral("startupDirectory")), page);
    startupDir->setObjectName(QStringLiteral("startupDirectoryEdit"));
    form->addRow(tr("Start in:"), startupDir);

    auto *clientDevices = new QCheckBox(tr("Connect client drives at logon"), page);
    clientDevices->setObjectName(QStringLiteral("clientDevicesCheck"));
    form->addRow(QString(), clientDevices);

    auto *clientPrinters = new QCheckBox(tr("Connect client printers at logon"), page);
    clientPrinters->setObjectName(QStringLiteral("clientPrintersCheck"));
    form->addRow(QString(), clientPrinters);

    auto *defaultPrinter = new QCheckBox(tr("Default to main client printer"), page);
    defaultPrinter->setObjectName(QStringLiteral("defaultPrinterCheck"));
    form->addRow(QString(), defaultPrinter);

    tabs->addTab(page, tr("Environment"));
}

void PropertySheet::addSessionsTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *form = new QFormLayout(page);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(8);
    form->setVerticalSpacing(6);

    auto *endDisconnected = new QSpinBox(page);
    endDisconnected->setRange(0, 9999);
    endDisconnected->setSuffix(tr(" minutes"));
    endDisconnected->setObjectName(QStringLiteral("endDisconnectedSpin"));
    form->addRow(tr("End a disconnected session:"), endDisconnected);

    auto *activeLimit = new QSpinBox(page);
    activeLimit->setRange(0, 9999);
    activeLimit->setSuffix(tr(" minutes"));
    activeLimit->setObjectName(QStringLiteral("activeLimitSpin"));
    form->addRow(tr("Active session limit:"), activeLimit);

    auto *idleLimit = new QSpinBox(page);
    idleLimit->setRange(0, 9999);
    idleLimit->setSuffix(tr(" minutes"));
    idleLimit->setObjectName(QStringLiteral("idleLimitSpin"));
    form->addRow(tr("Idle session limit:"), idleLimit);

    auto *whenLimitReached = new QComboBox(page);
    whenLimitReached->addItems({tr("Disconnect from session"), tr("End session")});
    whenLimitReached->setObjectName(QStringLiteral("whenLimitReachedCombo"));
    form->addRow(tr("When a session limit is reached or connection is broken:"), whenLimitReached);

    auto *allowReconnect = new QComboBox(page);
    allowReconnect->addItems({tr("From any client"), tr("From originating client only")});
    allowReconnect->setObjectName(QStringLiteral("allowReconnectCombo"));
    form->addRow(tr("Allow reconnection:"), allowReconnect);

    tabs->addTab(page, tr("Sessions"));
}

void PropertySheet::addRemoteControlTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    auto *enable = new QCheckBox(tr("Enable remote control"), page);
    enable->setObjectName(QStringLiteral("enableRemoteControlCheck"));
    layout->addWidget(enable);

    auto *levelGroup = new QGroupBox(tr("Level of control"), page);
    auto *levelLayout = new QVBoxLayout(levelGroup);
    auto *viewOnly = new QRadioButton(tr("View the user's session"), levelGroup);
    auto *interact = new QRadioButton(tr("Interact with the session"), levelGroup);
    viewOnly->setObjectName(QStringLiteral("viewOnlyRadio"));
    interact->setObjectName(QStringLiteral("interactRadio"));
    interact->setChecked(true);
    levelLayout->addWidget(viewOnly);
    levelLayout->addWidget(interact);
    layout->addWidget(levelGroup);

    auto *requirePermission = new QCheckBox(tr("Require user's permission"), page);
    requirePermission->setObjectName(QStringLiteral("requirePermissionCheck"));
    requirePermission->setChecked(true);
    layout->addWidget(requirePermission);

    layout->addStretch(1);

    tabs->addTab(page, tr("Remote Control"));
}

void PropertySheet::addTerminalServicesTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *form = new QFormLayout(page);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(8);
    form->setVerticalSpacing(6);

    auto *profilePath = new QLineEdit(attribute(QStringLiteral("tsProfilePath")), page);
    profilePath->setObjectName(QStringLiteral("tsProfilePathEdit"));
    form->addRow(tr("Terminal Services profile path:"), profilePath);

    auto *homeDir = new QLineEdit(attribute(QStringLiteral("tsHomeDirectory")), page);
    homeDir->setObjectName(QStringLiteral("tsHomeDirectoryEdit"));
    form->addRow(tr("Terminal Services home directory:"), homeDir);

    auto *homeDrive = new QLineEdit(attribute(QStringLiteral("tsHomeDrive")), page);
    homeDrive->setObjectName(QStringLiteral("tsHomeDriveEdit"));
    form->addRow(tr("Terminal Services home drive:"), homeDrive);

    auto *denyLogon = new QCheckBox(tr("Deny this user permissions to log on to Terminal Server"), page);
    denyLogon->setObjectName(QStringLiteral("denyLogonCheck"));
    form->addRow(QString(), denyLogon);

    tabs->addTab(page, tr("Terminal Services Profile"));
}

void PropertySheet::addComPlusTab(QTabWidget *tabs)
{
    auto *page = new QWidget(tabs);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    auto *note = new QLabel(tr("COM+ partition settings for this user."), page);
    note->setStyleSheet(QStringLiteral("color: #5a5a5a;"));
    layout->addWidget(note);

    auto *partition = new QComboBox(page);
    partition->setObjectName(QStringLiteral("comPlusPartitionCombo"));
    partition->addItems({tr("(Default)"), tr("System Application"), tr("COM+ Utilities")});
    auto *form = new QFormLayout();
    form->addRow(tr("Partition:"), partition);
    layout->addLayout(form);

    layout->addStretch(1);

    tabs->addTab(page, tr("COM+"));
}

void PropertySheet::applyChanges()
{
    syncMembership();

    if (m_displayName)
        m_object.name = m_displayName->text().trimmed();
    if (m_description)
        m_object.description = m_description->text().trimmed();

    if (m_firstName)
        m_object.attributes.insert(QStringLiteral("givenName"), m_firstName->text().trimmed());
    if (m_lastName)
        m_object.attributes.insert(QStringLiteral("sn"), m_lastName->text().trimmed());
    if (m_office)
        m_object.attributes.insert(QStringLiteral("physicalDeliveryOfficeName"), m_office->text().trimmed());
    if (m_telephone)
        m_object.attributes.insert(QStringLiteral("telephoneNumber"), m_telephone->text().trimmed());
    if (m_email)
        m_object.attributes.insert(QStringLiteral("mail"), m_email->text().trimmed());
    if (m_webPage)
        m_object.attributes.insert(QStringLiteral("wWWHomePage"), m_webPage->text().trimmed());
    if (m_profilePath)
        m_object.attributes.insert(QStringLiteral("profilePath"), m_profilePath->text().trimmed());
    if (m_logonScript)
        m_object.attributes.insert(QStringLiteral("scriptPath"), m_logonScript->text().trimmed());
    if (m_homeDrive)
        m_object.attributes.insert(QStringLiteral("homeDrive"), m_homeDrive->text().trimmed());
    if (m_homeDirectory)
        m_object.attributes.insert(QStringLiteral("homeDirectory"), m_homeDirectory->text().trimmed());
    if (m_mustChangePassword)
        m_object.attributes.insert(QStringLiteral("mustChangePassword"),
                                   m_mustChangePassword->isChecked() ? QStringLiteral("yes") : QStringLiteral("no"));
    if (m_cannotChangePassword)
        m_object.attributes.insert(QStringLiteral("cannotChangePassword"),
                                   m_cannotChangePassword->isChecked() ? QStringLiteral("yes") : QStringLiteral("no"));
    if (m_passwordNeverExpires || m_accountDisabled) {
        // Only the two flags this sheet owns are rewritten; the directory keeps
        // every other bit of userAccountControl as it was.
        quint32 uac = m_object.attributes.value(QStringLiteral("userAccountControl")).toUInt();
        if (m_accountDisabled) {
            if (m_accountDisabled->isChecked())
                uac |= 0x0002u;
            else
                uac &= ~0x0002u;
        }
        if (m_passwordNeverExpires) {
            if (m_passwordNeverExpires->isChecked())
                uac |= 0x10000u;
            else
                uac &= ~0x10000u;
        }
        m_object.attributes.insert(QStringLiteral("userAccountControl"), QString::number(uac));
    }
    if (m_accountLockedOut)
        m_object.attributes.insert(QStringLiteral("accountLockedOut"),
                                   m_accountLockedOut->isChecked() ? QStringLiteral("yes") : QStringLiteral("no"));
    if (m_accountExpires)
        m_object.attributes.insert(QStringLiteral("accountExpires"),
                                   m_accountExpires->date().toString(Qt::ISODate));

    m_object.attributes.insert(QStringLiteral("displayName"), m_object.name);
    m_object.attributes.insert(QStringLiteral("description"), m_object.description);

    if (m_headerName)
        m_headerName->setText(m_object.name);
    if (m_headerDescription)
        m_headerDescription->setText(m_object.description);

    refreshAttributesTable();
}

void PropertySheet::accept()
{
    if (m_displayName && m_displayName->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Properties"),
                             tr("The display name cannot be empty."));
        m_displayName->setFocus();
        return;
    }

    applyChanges();
    QDialog::accept();
}
