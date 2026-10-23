// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QApplication>
#include <QBuffer>
#include <QCheckBox>
#include <QFuture>
#include <QInputDialog>
#include <QLineEdit>
#include <QListView>
#include <QListWidget>
#include <QPushButton>
#include <QTimer>

#include "ConnectionService.h"
#include "DirectoryService.h"
#include "LdapServer.h"
#include "SampleData.h"
#include "consoleview.h"
#include "propertysheet.h"
#include "resultsmodel.h"

class ConsoleViewTest : public QObject
{
    Q_OBJECT

private slots:
    void filtersByContainer();
    void navigatesHistory();
    void switchesViewMode();
    void exportsVisibleRows();
    void propertySheetAppliesEdits();
    void propertySheetEditsMembership();
    void propertySheetAddsMember();
    void addsObjectThroughDirectory();
    void accountTabWritesUserAccountControl();
    void loadsLiveDirectory();
};

void ConsoleViewTest::filtersByContainer()
{
    ConsoleView view;

    QCOMPARE(view.resultsModel()->objectCount(), 12);

    view.navigateTo(QStringLiteral("Users"));
    QCOMPARE(view.resultsModel()->objectCount(), 4);
    QCOMPARE(view.resultsModel()->objectAt(0).type, QStringLiteral("User"));

    view.navigateTo(QStringLiteral("Groups"));
    QCOMPARE(view.resultsModel()->objectCount(), 4);
    QCOMPARE(view.resultsModel()->objectAt(0).type, QStringLiteral("Security Group"));

    view.navigateTo(QStringLiteral("Computers"));
    QCOMPARE(view.resultsModel()->objectCount(), 4);

    view.navigateTo(QStringLiteral("Domain Controllers"));
    QCOMPARE(view.resultsModel()->objectCount(), 1);
    QCOMPARE(view.resultsModel()->objectAt(0).name, QStringLiteral("DC01"));

    view.navigateTo(QStringLiteral("Console Root"));
    QCOMPARE(view.resultsModel()->objectCount(), 12);
}

void ConsoleViewTest::navigatesHistory()
{
    ConsoleView view;
    QCOMPARE(view.currentContainer(), QStringLiteral("Console Root"));
    QVERIFY(!view.canGoBack());
    QVERIFY(!view.canGoForward());
    QVERIFY(!view.canGoUp());

    view.navigateTo(QStringLiteral("Users"));
    QVERIFY(view.canGoBack());
    QVERIFY(view.canGoUp());

    view.navigateTo(QStringLiteral("Groups"));
    QVERIFY(view.canGoBack());
    QVERIFY(!view.canGoForward());

    view.goBack();
    QCOMPARE(view.currentContainer(), QStringLiteral("Users"));
    QVERIFY(view.canGoForward());

    view.goForward();
    QCOMPARE(view.currentContainer(), QStringLiteral("Groups"));

    view.goUp();
    QCOMPARE(view.currentContainer(), QStringLiteral("Console Root"));
    QVERIFY(!view.canGoUp());
}

void ConsoleViewTest::switchesViewMode()
{
    ConsoleView view;
    view.resize(800, 600);
    view.show();

    auto *iconView = view.findChild<QListView *>(QStringLiteral("iconView"));
    QVERIFY(iconView);

    view.setViewMode(ConsoleView::LargeIcons);
    QCOMPARE(view.viewMode(), ConsoleView::LargeIcons);
    QCOMPARE(iconView->iconSize(), QSize(32, 32));

    view.setViewMode(ConsoleView::SmallIcons);
    QCOMPARE(view.viewMode(), ConsoleView::SmallIcons);
    QCOMPARE(iconView->iconSize(), QSize(16, 16));

    view.setViewMode(ConsoleView::List);
    QCOMPARE(view.viewMode(), ConsoleView::List);

    view.setViewMode(ConsoleView::Details);
    QCOMPARE(view.viewMode(), ConsoleView::Details);
}

void ConsoleViewTest::exportsVisibleRows()
{
    ConsoleView view;
    view.navigateTo(QStringLiteral("Users"));

    QBuffer buffer;
    QVERIFY(buffer.open(QIODevice::WriteOnly));
    QVERIFY(view.exportResults(&buffer));
    buffer.close();

    const QString csv = QString::fromUtf8(buffer.data());
    QVERIFY(csv.startsWith(QStringLiteral("Name,Type,Description\n")));
    QCOMPARE(csv.count(QLatin1Char('\n')), 5);
    QVERIFY(csv.contains(QStringLiteral("\"Administrator\",\"User\"")));
}

void ConsoleViewTest::propertySheetAppliesEdits()
{
    DirectoryObject object;
    object.id = QStringLiteral("CN=Test User,CN=Users,DC=corp,DC=example,DC=com");
    object.name = QStringLiteral("Test User");
    object.type = QStringLiteral("User");
    object.description = QStringLiteral("Original description");
    object.kind = ObjectKind::User;
    object.container = QStringLiteral("Users");
    object.attributes.insert(QStringLiteral("givenName"), QStringLiteral("Test"));

    PropertySheet sheet(object);

    auto *displayName = sheet.findChild<QLineEdit *>(QStringLiteral("displayNameEdit"));
    auto *description = sheet.findChild<QLineEdit *>(QStringLiteral("descriptionEdit"));
    auto *firstName = sheet.findChild<QLineEdit *>(QStringLiteral("firstNameEdit"));
    QVERIFY(displayName);
    QVERIFY(description);
    QVERIFY(firstName);

    displayName->setText(QStringLiteral("Renamed User"));
    description->setText(QStringLiteral("Updated description"));
    firstName->setText(QStringLiteral("Renamed"));

    sheet.accept();

    QCOMPARE(sheet.object().name, QStringLiteral("Renamed User"));
    QCOMPARE(sheet.object().description, QStringLiteral("Updated description"));
    QCOMPARE(sheet.object().attributes.value(QStringLiteral("givenName")),
             QStringLiteral("Renamed"));
    QCOMPARE(sheet.object().attributes.value(QStringLiteral("displayName")),
             QStringLiteral("Renamed User"));
}

void ConsoleViewTest::propertySheetEditsMembership()
{
    const QString usersDn = QStringLiteral("CN=Users,DC=corp,DC=example,DC=com");
    const QString groupDn = QStringLiteral("CN=Audit Team,") + usersDn;
    const QString aliceDn = QStringLiteral("CN=Alice Chen,") + usersDn;
    const QString bobDn = QStringLiteral("CN=Bob Martinez,") + usersDn;

    DirectoryObject group;
    group.id = groupDn;
    group.name = QStringLiteral("Audit Team");
    group.type = QStringLiteral("Security Group");
    group.kind = ObjectKind::Group;
    group.container = QStringLiteral("Groups");
    group.members = {aliceDn, bobDn};

    QList<DirectoryObject> candidates = sampleObjects();
    PropertySheet sheet(group);
    sheet.setMembershipCandidates(candidates);

    auto *list = sheet.findChild<QListWidget *>(QStringLiteral("membershipList"));
    auto *remove = sheet.findChild<QPushButton *>(QStringLiteral("removeMemberButton"));
    auto *add = sheet.findChild<QPushButton *>(QStringLiteral("addMemberButton"));
    QVERIFY(list);
    QVERIFY(remove);
    QVERIFY(add);
    QCOMPARE(list->count(), 2);
    QVERIFY(add->isEnabled());

    // Members are shown by name while the sheet keeps distinguished names.
    QCOMPARE(list->item(0)->text(), QStringLiteral("Alice Chen"));
    QCOMPARE(list->item(0)->data(Qt::UserRole).toString(), aliceDn);

    list->setCurrentRow(0);
    remove->click();
    QCOMPARE(list->count(), 1);

    sheet.accept();
    QCOMPARE(sheet.object().members, QStringList{bobDn});

    // A user's Member Of tab edits the same pair from the other side.
    const DirectoryObject *alice = nullptr;
    for (const DirectoryObject &candidate : candidates) {
        if (candidate.id == aliceDn)
            alice = &candidate;
    }
    QVERIFY(alice);

    DirectoryObject user = *alice;
    user.memberOf = {QStringLiteral("CN=Domain Admins,") + usersDn};
    PropertySheet userSheet(user);
    userSheet.setMembershipCandidates(candidates);

    auto *userList = userSheet.findChild<QListWidget *>(QStringLiteral("membershipList"));
    QVERIFY(userList);
    QCOMPARE(userList->count(), 1);
    QCOMPARE(userList->item(0)->text(), QStringLiteral("Domain Admins"));

    userSheet.accept();
    QCOMPARE(userSheet.object().memberOf,
             QStringList{QStringLiteral("CN=Domain Admins,") + usersDn});
}

void ConsoleViewTest::propertySheetAddsMember()
{
    const QString usersDn = QStringLiteral("CN=Users,DC=corp,DC=example,DC=com");
    const QString bobDn = QStringLiteral("CN=Bob Martinez,") + usersDn;

    DirectoryObject group;
    group.id = QStringLiteral("CN=Audit Team,") + usersDn;
    group.name = QStringLiteral("Audit Team");
    group.type = QStringLiteral("Security Group");
    group.kind = ObjectKind::Group;
    group.container = QStringLiteral("Groups");
    group.members = {QStringLiteral("CN=Alice Chen,") + usersDn};

    PropertySheet sheet(group);
    sheet.setMembershipCandidates(sampleObjects());

    auto *list = sheet.findChild<QListWidget *>(QStringLiteral("membershipList"));
    auto *add = sheet.findChild<QPushButton *>(QStringLiteral("addMemberButton"));
    QVERIFY(list);
    QVERIFY(add);
    QCOMPARE(list->count(), 1);

    // Add... opens a modal selection dialog; choose Bob from inside the loop.
    QTimer::singleShot(0, []() {
        auto *dialog = qobject_cast<QInputDialog *>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        dialog->setTextValue(QStringLiteral("Bob Martinez"));
        dialog->accept();
    });
    add->click();

    QCOMPARE(list->count(), 2);
    QCOMPARE(list->item(1)->data(Qt::UserRole).toString(), bobDn);

    sheet.accept();
    QCOMPARE(sheet.object().members.size(), 2);
    QVERIFY(sheet.object().members.contains(bobDn));
}

void ConsoleViewTest::addsObjectThroughDirectory()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    DirectoryService directory(&connection);
    ConsoleView view;
    view.setConnectionService(&connection);
    view.setDirectoryService(&directory);

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());
    view.refresh();
    QTRY_COMPARE_WITH_TIMEOUT(view.resultsModel()->objectCount(), 12, 5000);

    DirectoryObject user;
    user.kind = ObjectKind::User;
    user.name = QStringLiteral("Grace Hopper");
    user.type = QStringLiteral("User");
    user.description = QStringLiteral("Created from the console");
    user.container = QStringLiteral("Users");
    user.id = QStringLiteral("CN=Grace Hopper,CN=Users,DC=corp,DC=example,DC=com");
    user.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    user.attributes.insert(QStringLiteral("cn"), user.name);
    user.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("gracehopper"));
    user.attributes.insert(QStringLiteral("unicodePwd"), QStringLiteral("C0bol-R0cks!"));
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));

    view.addObject(user);
    QTRY_COMPARE_WITH_TIMEOUT(view.resultsModel()->objectCount(), 13, 5000);

    // A create the directory refuses (password fails policy) leaves the pane
    // untouched instead of showing an object the server rejected.
    DirectoryObject weak = user;
    weak.name = QStringLiteral("Weak Password");
    weak.id = QStringLiteral("CN=Weak Password,CN=Users,DC=corp,DC=example,DC=com");
    weak.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("weak"));
    weak.attributes.insert(QStringLiteral("unicodePwd"), QStringLiteral("abc"));
    view.addObject(weak);
    QTest::qWait(500);
    QCOMPARE(view.resultsModel()->objectCount(), 13);
}

void ConsoleViewTest::accountTabWritesUserAccountControl()
{
    DirectoryObject user;
    user.id = QStringLiteral("CN=Test User,CN=Users,DC=corp,DC=example,DC=com");
    user.name = QStringLiteral("Test User");
    user.type = QStringLiteral("User");
    user.kind = ObjectKind::User;
    user.container = QStringLiteral("Users");
    user.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));

    PropertySheet sheet(user);
    auto *disabled = sheet.findChild<QCheckBox *>(QStringLiteral("accountDisabledCheck"));
    auto *neverExpires = sheet.findChild<QCheckBox *>(QStringLiteral("passwordNeverExpiresCheck"));
    QVERIFY(disabled);
    QVERIFY(neverExpires);
    QVERIFY(!disabled->isChecked());
    QVERIFY(!neverExpires->isChecked());

    // Disable the account: NORMAL_ACCOUNT (0x200) + ACCOUNTDISABLE (0x2).
    disabled->setChecked(true);
    sheet.accept();
    QCOMPARE(sheet.object().attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("514"));

    // Re-open: the flag round-trips, and adding DONT_EXPIRE_PASSWORD keeps it.
    DirectoryObject reopened = sheet.object();
    PropertySheet again(reopened);
    auto *againDisabled = again.findChild<QCheckBox *>(QStringLiteral("accountDisabledCheck"));
    auto *againNever = again.findChild<QCheckBox *>(QStringLiteral("passwordNeverExpiresCheck"));
    QVERIFY(againDisabled->isChecked());
    againNever->setChecked(true);
    again.accept();
    QCOMPARE(again.object().attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("66050"));

    againDisabled->setChecked(false);
    again.accept();
    QCOMPARE(again.object().attributes.value(QStringLiteral("userAccountControl")),
             QStringLiteral("66048"));
}

void ConsoleViewTest::loadsLiveDirectory()
{
    LdapServer server;
    QVERIFY(server.listen(0));

    QList<DirectoryObject> seed = sampleObjects();
    DirectoryObject marker;
    marker.id = QStringLiteral("CN=Live Marker,CN=Users,DC=corp,DC=example,DC=com");
    marker.name = QStringLiteral("Live Marker");
    marker.kind = ObjectKind::User;
    marker.container = QStringLiteral("Users");
    marker.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    marker.attributes.insert(QStringLiteral("cn"), QStringLiteral("Live Marker"));
    marker.attributes.insert(QStringLiteral("sAMAccountName"), QStringLiteral("livemarker"));
    seed.append(marker);
    server.setObjects(seed);

    ConnectionService connection;
    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    DirectoryService directory(&connection);
    ConsoleView view;
    view.setConnectionService(&connection);
    view.setDirectoryService(&directory);

    // The console opens with 12 sample objects; the live directory has 13.
    QCOMPARE(view.resultsModel()->objectCount(), 12);

    auto connectFuture = connection.connect(profile);
    QTRY_VERIFY_WITH_TIMEOUT(connectFuture.isFinished(), 5000);
    QVERIFY(connectFuture.result());

    QTRY_COMPARE_WITH_TIMEOUT(view.resultsModel()->objectCount(), 13, 5000);

    bool foundMarker = false;
    for (int row = 0; row < view.resultsModel()->objectCount(); ++row) {
        if (view.resultsModel()->objectAt(row).name == QStringLiteral("Live Marker")) {
            foundMarker = true;
            QCOMPARE(view.resultsModel()->objectAt(row).container, QStringLiteral("Users"));
            break;
        }
    }
    QVERIFY(foundMarker);

    view.navigateTo(QStringLiteral("Groups"));
    QCOMPARE(view.resultsModel()->objectCount(), 4);
    view.navigateTo(QStringLiteral("Users"));
    QCOMPARE(view.resultsModel()->objectCount(), 5);
    view.navigateTo(QStringLiteral("Domain Controllers"));
    QCOMPARE(view.resultsModel()->objectCount(), 1);
}

QTEST_MAIN(ConsoleViewTest)
#include "test_consoleview.moc"
