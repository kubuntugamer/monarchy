// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QLabel;

class QAction;
class QActionGroup;
class QCloseEvent;
class QMenuBar;
class QPrinter;
class QStatusBar;
class QTimer;
class QToolBar;
class ConsoleView;
class AdminService;
class ConnectionService;
class DirectoryService;
class DnsServer;
class SamrServer;
class LsadServer;
class NetlogonServer;
class EpmServer;
class DrsServer;
class Smb2Server;
class Kdc;
class LdapServer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onNewWindow();
    void onExportList();
    void onProperties();
    void onDelete();
    void onRefresh();
    void onFind();
    void onNewUser();
    void onNewGroup();
    void onNewComputer();
    void onNewOu();
    void onResetPassword();
    void onOpenConsole();
    void onSaveConsole();
    void onSaveConsoleAs();
    void onPrint();
    void onPrintPreview();
    void onPageSetup();
    void onCloseWindow();
    void onOptions();
    void onCustomize();
    void applyAutoRefreshSettings();
    void onConnectToDirectory();
    void onDisconnect();
    void onToggleFullScreen();
    void onInvertSelection();
    void onCascadeWindows();
    void onTileHorizontal();
    void onTileVertical();
    void onAbout();
    void onHelpTopics();
    void onViewLargeIcons();
    void onViewSmallIcons();
    void onViewList();
    void onViewDetails();
    void updateHistoryActions(bool canGoBack, bool canGoForward, bool canGoUp);

private:
    void createActions();
    void createMenus();
    void createToolbar();
    void createStatusBar();
    void createCentralWidget();
    // Naming context of the directory the console is connected to.
    QString namingContext() const;
    void loadSettings();
    void saveSettings();
    void saveConsoleTo(const QString &fileName);
    void printResults(QPrinter *printer);
    void updateRecentFilesMenu();
    void addToRecentFiles(const QString &fileName);

    ConsoleView *m_consoleView = nullptr;
    ConnectionService *m_connectionService = nullptr;
    DirectoryService *m_directoryService = nullptr;
    AdminService *m_adminService = nullptr;
    LdapServer *m_ldapServer = nullptr;
    DnsServer *m_dnsServer = nullptr;
    Kdc *m_kdc = nullptr;
    SamrServer *m_samrServer = nullptr;
    LsadServer *m_lsadServer = nullptr;
    NetlogonServer *m_netlogonServer = nullptr;
    DrsServer *m_drsServer = nullptr;
    EpmServer *m_epmServer = nullptr;
    Smb2Server *m_smbServer = nullptr;
    // Store and zone locations resolved from dc.conf at start-up.
    QString m_storePath;
    QString m_zonePath;
    QString m_consoleFilePath;
    QPrinter *m_printer = nullptr;
    QTimer *m_refreshTimer = nullptr;
    QToolBar *m_toolbar = nullptr;
    QStatusBar *m_statusBar = nullptr;
    QLabel *m_statusCountLabel = nullptr;
    QMenuBar *m_menuBar = nullptr;
    QMenu *m_recentFilesMenu = nullptr;
    QActionGroup *m_viewGroup = nullptr;

    QAction *m_actBack = nullptr;
    QAction *m_actForward = nullptr;
    QAction *m_actUp = nullptr;
    QAction *m_actNew = nullptr;
    QAction *m_actNewWindow = nullptr;
    QAction *m_actExport = nullptr;
    QAction *m_actDelete = nullptr;
    QAction *m_actProperties = nullptr;
    QAction *m_actRefresh = nullptr;
    QAction *m_actFind = nullptr;
    QAction *m_actHelp = nullptr;
    QAction *m_actViewLargeIcons = nullptr;
    QAction *m_actViewSmallIcons = nullptr;
    QAction *m_actViewList = nullptr;
    QAction *m_actViewDetails = nullptr;
    QAction *m_actStatusBar = nullptr;
    QAction *m_actConsoleTree = nullptr;
    QAction *m_actStandardMenus = nullptr;
    QAction *m_actAdvancedMenus = nullptr;
};

#endif // MAINWINDOW_H
