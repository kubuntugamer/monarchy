// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QApplication>
#include <QDialog>
#include <QLineEdit>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>

#include "ConnectionService.h"
#include "LdapServer.h"
#include "SampleData.h"
#include "consoleview.h"
#include "mainwindow.h"
#include "resultsmodel.h"

namespace {

const char kAdministratorDn[] = "CN=Administrator,CN=Users,DC=corp,DC=example,DC=com";
const char kAdministratorPassword[] = "Str0ng-Pass!";

// The sample store ships no credential, so a bind to any DN succeeds until one
// account has a verifier — after that, every bind is checked against the stored
// verifiers. Give the account this harness signs in as a real one.
bool giveAdministratorAVerifier(LdapServer &server)
{
    LdapServer::ModifyChange change;
    change.operation = 2; // replace
    change.type = QStringLiteral("unicodePwd");
    change.values = QStringList{QString::fromLatin1(kAdministratorPassword)};
    change.rawValue = kAdministratorPassword;
    return server.applyModify(QString::fromLatin1(kAdministratorDn), {change}) == 0;
}

} // namespace

// The console window itself, driven through the profile-taking constructor: an
// anonymous session is refused the directory, the credential prompt appears,
// and accepting it loads the objects. This is the end-to-end half that
// monarchy-backend-tests cannot cover — the signal and the reconnect path are
// tested there, the dialog only exists here.
class MainWindowTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void promptsForCredentialsAndThenLoadsTheDirectory();

private:
    QTemporaryDir m_settingsDir;
};

void MainWindowTest::initTestCase()
{
    // Keep the console from reading or writing the developer's own settings:
    // this suite is about the window, not the machine it runs on.
    QVERIFY(m_settingsDir.isValid());
    QCoreApplication::setOrganizationName(QStringLiteral("MonarchyTests"));
    QCoreApplication::setApplicationName(QStringLiteral("MainWindowTest"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_settingsDir.path());

    QSettings settings;
    settings.setValue(QStringLiteral("options/autoRefresh"), false);
    settings.setValue(QStringLiteral("connection/tls"), false);
    settings.setValue(QStringLiteral("connection/kerberos"), false);
    settings.sync();
}

void MainWindowTest::promptsForCredentialsAndThenLoadsTheDirectory()
{
    LdapServer server;
    QVERIFY(server.listen(0));
    server.setObjects(sampleObjects());
    QVERIFY(giveAdministratorAVerifier(server));

    ConnectionProfile profile;
    profile.server = QStringLiteral("127.0.0.1");
    profile.port = server.serverPort();
    profile.baseDn = QStringLiteral("DC=corp,DC=example,DC=com");

    MainWindow window(profile);
    auto *view = window.findChild<ConsoleView *>();
    QVERIFY(view);

    // The prompt is modal, so the timer that drives it must already be running
    // when the read is refused; it fires inside the dialog's nested event loop.
    QTimer prompter;
    prompter.setInterval(10);
    bool prompted = false;
    QString prefilledDn;
    connect(&prompter, &QTimer::timeout, this, [&] {
        auto *dialog = window.findChild<QDialog *>(QStringLiteral("credentialPrompt"));
        if (!dialog || !dialog->isVisible())
            return;
        auto *dnEdit = dialog->findChild<QLineEdit *>(QStringLiteral("credentialBindDn"));
        auto *passwordEdit =
            dialog->findChild<QLineEdit *>(QStringLiteral("credentialPassword"));
        if (!dnEdit || !passwordEdit)
            return;
        prompted = true;
        prefilledDn = dnEdit->text();
        passwordEdit->setText(QString::fromLatin1(kAdministratorPassword));
        dialog->accept();
    });
    prompter.start();

    QTRY_VERIFY_WITH_TIMEOUT(prompted, 10000);
    prompter.stop();

    // The refused anonymous session is offered the account that can read it.
    QCOMPARE(prefilledDn, QString::fromLatin1(kAdministratorDn));

    // Accepting reconnects with the credential; the console then shows exactly
    // what the bound session may read.
    QTRY_COMPARE_WITH_TIMEOUT(view->resultsModel()->objectCount(), 12, 10000);
    QCOMPARE(QSettings().value(QStringLiteral("connection/bindDn")).toString(),
             QString::fromLatin1(kAdministratorDn));
}

QTEST_MAIN(MainWindowTest)
#include "test_mainwindow.moc"
