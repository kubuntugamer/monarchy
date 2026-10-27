// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "mainwindow.h"

#include "consoleview.h"
#include "objecticons.h"

#include <QAbstractItemView>

#include "../backend/ConnectionService.h"
#include "../backend/AdminService.h"
#include "../backend/DirectoryService.h"

#include "../backend/SampleData.h"
#include <QAction>
#include <QClipboard>
#include <QActionGroup>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QDir>
#include <QFileDialog>
#include <QIcon>
#include <QItemSelectionModel>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QKeySequence>
#include <QMenu>
#include <QMenuBar>
#include <QPrinter>
#include <QPrintDialog>
#include <QPrintPreviewDialog>
#include <QFileInfo>
#include <QScreen>
#include <QStandardPaths>
#include <QSpinBox>
#include <QTextDocument>
#include <QMessageBox>
#include <QSaveFile>
#include <QSettings>
#include <QStatusBar>
#include <QStyle>
#include <QTimer>
#include <QTableView>
#include <QToolBar>
#include <QListView>
#include <QTreeView>
#include <QToolButton>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Monarchy Management Console"));
    setWindowIcon(objectIcon(ObjectKind::Domain));
    setMinimumSize(800, 600);

    createActions();
    createMenus();
    createToolbar();
    createStatusBar();
    createCentralWidget();
    loadSettings();
    applyAutoRefreshSettings();

    // Re-emit the initial console state now that the signals are connected.
    m_consoleView->navigateTo(m_consoleView->currentContainer());
}

MainWindow::~MainWindow() = default;

void MainWindow::createActions()
{
    QStyle *s = style();

    m_actBack = new QAction(s->standardIcon(QStyle::SP_ArrowBack), tr("&Back"), this);
    m_actBack->setShortcut(QKeySequence(QStringLiteral("Alt+Left")));
    m_actBack->setStatusTip(tr("Go back to the previous console view"));
    m_actBack->setEnabled(false);
    connect(m_actBack, &QAction::triggered, this, [this] {
        if (m_consoleView)
            m_consoleView->goBack();
    });

    m_actForward = new QAction(s->standardIcon(QStyle::SP_ArrowForward), tr("&Forward"), this);
    m_actForward->setShortcut(QKeySequence(QStringLiteral("Alt+Right")));
    m_actForward->setStatusTip(tr("Go forward to the next console view"));
    m_actForward->setEnabled(false);
    connect(m_actForward, &QAction::triggered, this, [this] {
        if (m_consoleView)
            m_consoleView->goForward();
    });

    m_actUp = new QAction(s->standardIcon(QStyle::SP_ArrowUp), tr("&Up"), this);
    m_actUp->setShortcut(QKeySequence(QStringLiteral("Alt+Up")));
    m_actUp->setStatusTip(tr("Go up one level in the console tree"));
    m_actUp->setEnabled(false);
    connect(m_actUp, &QAction::triggered, this, [this] {
        if (m_consoleView)
            m_consoleView->goUp();
    });

    m_actNew = new QAction(s->standardIcon(QStyle::SP_FileIcon), tr("&New"), this);
    m_actNew->setShortcut(QKeySequence::New);
    m_actNew->setStatusTip(tr("Open a new console window"));
    connect(m_actNew, &QAction::triggered, this, &MainWindow::onNewWindow);

    m_actNewWindow = new QAction(tr("New &Window"), this);
    m_actNewWindow->setShortcut(QKeySequence(QStringLiteral("Ctrl+M")));
    connect(m_actNewWindow, &QAction::triggered, this, &MainWindow::onNewWindow);

    m_actExport = new QAction(s->standardIcon(QStyle::SP_DialogSaveButton),
                              tr("&Export List..."), this);
    m_actExport->setStatusTip(tr("Export the current results list as CSV"));
    connect(m_actExport, &QAction::triggered, this, &MainWindow::onExportList);

    m_actDelete = new QAction(s->standardIcon(QStyle::SP_TrashIcon), tr("&Delete"), this);
    m_actDelete->setShortcut(QKeySequence::Delete);
    m_actDelete->setStatusTip(tr("Delete the selected object from this console"));
    m_actDelete->setEnabled(false);
    connect(m_actDelete, &QAction::triggered, this, &MainWindow::onDelete);

    m_actProperties = new QAction(s->standardIcon(QStyle::SP_FileDialogInfoView),
                                  tr("&Properties"), this);
    m_actProperties->setShortcut(QKeySequence(QStringLiteral("Alt+Return")));
    m_actProperties->setStatusTip(tr("Open the property sheet for the selected object"));
    m_actProperties->setEnabled(false);
    connect(m_actProperties, &QAction::triggered, this, &MainWindow::onProperties);

    m_actRefresh = new QAction(s->standardIcon(QStyle::SP_BrowserReload),
                               tr("&Refresh"), this);
    m_actRefresh->setShortcut(QKeySequence::Refresh);
    m_actRefresh->setStatusTip(tr("Refresh the current console view"));
    connect(m_actRefresh, &QAction::triggered, this, &MainWindow::onRefresh);

    m_actFind = new QAction(s->standardIcon(QStyle::SP_FileDialogContentsView),
                            tr("&Find..."), this);
    m_actFind->setShortcut(QKeySequence::Find);
    m_actFind->setStatusTip(tr("Filter the results pane by name, type or description"));
    connect(m_actFind, &QAction::triggered, this, &MainWindow::onFind);

    m_actHelp = new QAction(s->standardIcon(QStyle::SP_MessageBoxQuestion),
                            tr("&Help Topics"), this);
    m_actHelp->setShortcut(QKeySequence::HelpContents);
    connect(m_actHelp, &QAction::triggered, this, &MainWindow::onHelpTopics);

    m_actViewLargeIcons = new QAction(tr("Large &Icons"), this);
    m_actViewLargeIcons->setShortcut(QKeySequence(QStringLiteral("Ctrl+1")));
    m_actViewSmallIcons = new QAction(tr("Small I&cons"), this);
    m_actViewSmallIcons->setShortcut(QKeySequence(QStringLiteral("Ctrl+2")));
    m_actViewList = new QAction(tr("&List"), this);
    m_actViewList->setShortcut(QKeySequence(QStringLiteral("Ctrl+3")));
    m_actViewDetails = new QAction(tr("&Details"), this);
    m_actViewDetails->setShortcut(QKeySequence(QStringLiteral("Ctrl+4")));

    m_viewGroup = new QActionGroup(this);
    m_viewGroup->setExclusive(true);
    for (QAction *action : {m_actViewLargeIcons, m_actViewSmallIcons,
                            m_actViewList, m_actViewDetails}) {
        action->setCheckable(true);
        m_viewGroup->addAction(action);
    }
    m_actViewDetails->setChecked(true);

    connect(m_actViewLargeIcons, &QAction::triggered, this, &MainWindow::onViewLargeIcons);
    connect(m_actViewSmallIcons, &QAction::triggered, this, &MainWindow::onViewSmallIcons);
    connect(m_actViewList, &QAction::triggered, this, &MainWindow::onViewList);
    connect(m_actViewDetails, &QAction::triggered, this, &MainWindow::onViewDetails);

    m_actStatusBar = new QAction(tr("Status &Bar"), this);
    m_actStatusBar->setCheckable(true);
    m_actStatusBar->setChecked(true);
    connect(m_actStatusBar, &QAction::toggled, this, [this](bool visible) {
        statusBar()->setVisible(visible);
    });

    m_actConsoleTree = new QAction(tr("Console &Tree"), this);
    m_actConsoleTree->setCheckable(true);
    m_actConsoleTree->setChecked(true);
    connect(m_actConsoleTree, &QAction::toggled, this, [this](bool visible) {
        if (m_consoleView)
            m_consoleView->setTreeVisible(visible);
    });
}

void MainWindow::createMenus()
{
    m_menuBar = menuBar();

    QMenu *fileMenu = m_menuBar->addMenu(tr("&File"));
    fileMenu->addAction(m_actNew);

    auto *openAction = new QAction(tr("&Open..."), this);
    openAction->setShortcut(QKeySequence::Open);
    openAction->setStatusTip(tr("Open a console state file"));
    connect(openAction, &QAction::triggered, this, &MainWindow::onOpenConsole);
    fileMenu->addAction(openAction);

    auto *saveAction = new QAction(tr("&Save"), this);
    saveAction->setShortcut(QKeySequence::Save);
    saveAction->setStatusTip(tr("Save the current console state"));
    connect(saveAction, &QAction::triggered, this, &MainWindow::onSaveConsole);
    fileMenu->addAction(saveAction);

    auto *saveAsAction = new QAction(tr("Save &As..."), this);
    saveAsAction->setStatusTip(tr("Save the current console state to a new file"));
    connect(saveAsAction, &QAction::triggered, this, &MainWindow::onSaveConsoleAs);
    fileMenu->addAction(saveAsAction);

    m_recentFilesMenu = fileMenu->addMenu(tr("Recent &Files"));
    updateRecentFilesMenu();

    fileMenu->addSeparator();

    auto *connectAction = new QAction(tr("Connect to &Directory..."), this);
    connect(connectAction, &QAction::triggered, this, &MainWindow::onConnectToDirectory);
    fileMenu->addAction(connectAction);

    auto *disconnectAction = new QAction(tr("&Disconnect"), this);
    connect(disconnectAction, &QAction::triggered, this, &MainWindow::onDisconnect);
    fileMenu->addAction(disconnectAction);

    fileMenu->addSeparator();
    auto *optionsAction = new QAction(tr("O&ptions..."), this);
    connect(optionsAction, &QAction::triggered, this, &MainWindow::onOptions);
    fileMenu->addAction(optionsAction);

    fileMenu->addSeparator();

    auto *printAction = new QAction(tr("&Print..."), this);
    printAction->setShortcut(QKeySequence::Print);
    connect(printAction, &QAction::triggered, this, &MainWindow::onPrint);
    fileMenu->addAction(printAction);

    auto *previewAction = new QAction(tr("Print Pre&view..."), this);
    connect(previewAction, &QAction::triggered, this, &MainWindow::onPrintPreview);
    fileMenu->addAction(previewAction);

    auto *pageSetupAction = new QAction(tr("Page Set&up..."), this);
    connect(pageSetupAction, &QAction::triggered, this, &MainWindow::onPageSetup);
    fileMenu->addAction(pageSetupAction);

    fileMenu->addSeparator();

    auto *closeAction = new QAction(tr("&Close"), this);
    closeAction->setShortcut(QKeySequence::Close);
    connect(closeAction, &QAction::triggered, this, &MainWindow::onCloseWindow);
    fileMenu->addAction(closeAction);

    fileMenu->addSeparator();
    auto *exitAction = new QAction(tr("E&xit"), this);
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    fileMenu->addAction(exitAction);

    QMenu *editMenu = m_menuBar->addMenu(tr("&Edit"));
    auto *copyAction = new QAction(tr("&Copy"), this);
    copyAction->setShortcut(QKeySequence::Copy);
    connect(copyAction, &QAction::triggered, this, [this] {
        if (!m_consoleView)
            return;
        QStringList names;
        for (const QModelIndex &idx : m_consoleView->selectedNameIndexes())
            names.append(idx.data().toString());
        QApplication::clipboard()->setText(names.join(QLatin1Char('\n')));
        statusBar()->showMessage(tr("Copied %n item(s).", nullptr, names.size()), 3000);
    });
    editMenu->addAction(copyAction);

    auto *selectAllAction = new QAction(tr("Select &All"), this);
    selectAllAction->setShortcut(QKeySequence::SelectAll);
    connect(selectAllAction, &QAction::triggered, this, [this] {
        if (!m_consoleView)
            return;
        QAbstractItemView *view = m_consoleView->currentResultsView();
        if (view)
            view->selectAll();
    });
    editMenu->addAction(selectAllAction);

    auto *invertAction = new QAction(tr("&Invert Selection"), this);
    connect(invertAction, &QAction::triggered, this, &MainWindow::onInvertSelection);
    editMenu->addAction(invertAction);

    auto *renameAction = new QAction(tr("Re&name"), this);
    renameAction->setShortcut(QKeySequence(Qt::Key_F2));
    connect(renameAction, &QAction::triggered, this, &MainWindow::onProperties);
    editMenu->addAction(renameAction);

    editMenu->addSeparator();
    auto *deleteEditAction = new QAction(tr("&Delete"), this);
    deleteEditAction->setShortcut(QKeySequence::Delete);
    connect(deleteEditAction, &QAction::triggered, this, &MainWindow::onDelete);
    editMenu->addAction(deleteEditAction);

    editMenu->addSeparator();
    auto *findAction = new QAction(tr("&Find..."), this);
    findAction->setShortcut(QKeySequence::Find);
    connect(findAction, &QAction::triggered, this, &MainWindow::onFind);
    editMenu->addAction(findAction);

    QMenu *actionMenu = m_menuBar->addMenu(tr("&Action"));
    actionMenu->addAction(m_actNewWindow);

    auto *taskpadAction = new QAction(tr("New &Taskpad View"), this);
    taskpadAction->setEnabled(false);
    taskpadAction->setStatusTip(tr("Taskpad views are not implemented yet."));
    actionMenu->addAction(taskpadAction);

    actionMenu->addSeparator();

    auto *newMenu = actionMenu->addMenu(tr("&New"));
    auto *newUserAction = new QAction(tr("&User"), this);
    connect(newUserAction, &QAction::triggered, this, &MainWindow::onNewUser);
    newMenu->addAction(newUserAction);

    auto *newGroupAction = new QAction(tr("&Group"), this);
    connect(newGroupAction, &QAction::triggered, this, &MainWindow::onNewGroup);
    newMenu->addAction(newGroupAction);

    auto *newComputerAction = new QAction(tr("&Computer"), this);
    connect(newComputerAction, &QAction::triggered, this, &MainWindow::onNewComputer);
    newMenu->addAction(newComputerAction);

    auto *newOuAction = new QAction(tr("&Organizational Unit"), this);
    connect(newOuAction, &QAction::triggered, this, &MainWindow::onNewOu);
    newMenu->addAction(newOuAction);

    actionMenu->addSeparator();

    auto *duplicateAction = new QAction(tr("D&uplicate"), this);
    duplicateAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+D")));
    connect(duplicateAction, &QAction::triggered, this, [this] {
        if (!m_consoleView || !m_consoleView->hasSingleSelection())
            return;
        DirectoryObject obj = m_consoleView->currentObject();
        obj.name += tr(" (copy)");
        obj.id += tr("-copy");
        m_consoleView->addObject(obj);
        statusBar()->showMessage(tr("Duplicated %1.").arg(obj.name), 4000);
    });
    actionMenu->addAction(duplicateAction);

    auto *resetPasswordAction = new QAction(tr("Reset &Password..."), this);
    connect(resetPasswordAction, &QAction::triggered, this, &MainWindow::onResetPassword);
    actionMenu->addAction(resetPasswordAction);

    actionMenu->addSeparator();
    actionMenu->addAction(m_actExport);
    actionMenu->addSeparator();
    actionMenu->addAction(m_actProperties);
    actionMenu->addAction(m_actDelete);
    actionMenu->addSeparator();
    actionMenu->addAction(m_actRefresh);
    actionMenu->addAction(m_actFind);

    QMenu *viewMenu = m_menuBar->addMenu(tr("&View"));
    viewMenu->addAction(m_actViewLargeIcons);
    viewMenu->addAction(m_actViewSmallIcons);
    viewMenu->addAction(m_actViewList);
    viewMenu->addAction(m_actViewDetails);
    viewMenu->addSeparator();
    viewMenu->addAction(m_actStatusBar);
    viewMenu->addAction(m_actConsoleTree);

    auto *gridAction = new QAction(tr("Show &Grid"), this);
    gridAction->setCheckable(true);
    gridAction->setChecked(true);
    connect(gridAction, &QAction::toggled, this, [this](bool visible) {
        if (m_consoleView) {
            QTableView *tv = m_consoleView->findChild<QTableView *>(QStringLiteral("detailsView"));
            if (tv)
                tv->setShowGrid(visible);
        }
    });
    viewMenu->addAction(gridAction);
    viewMenu->addSeparator();

    m_actStandardMenus = new QAction(tr("Standard &Menus"), this);
    m_actStandardMenus->setCheckable(true);
    m_actStandardMenus->setChecked(true);
    connect(m_actStandardMenus, &QAction::toggled, this, [this](bool visible) {
        // Toggle the core menus' visibility.
        for (QAction *a : m_menuBar->actions()) {
            const QString t = a->text();
            if (t.contains(tr("File")) || t.contains(tr("Edit")) ||
                t.contains(tr("View")) || t.contains(tr("Action"))) {
                a->setVisible(visible);
            }
        }
    });
    viewMenu->addAction(m_actStandardMenus);

    m_actAdvancedMenus = new QAction(tr("Advanced M&enus"), this);
    m_actAdvancedMenus->setCheckable(true);
    m_actAdvancedMenus->setChecked(true);
    connect(m_actAdvancedMenus, &QAction::toggled, this, [this](bool visible) {
        for (QAction *a : m_menuBar->actions()) {
            const QString t = a->text();
            if (t.contains(tr("Favorites")) || t.contains(tr("Window")) ||
                t.contains(tr("Help"))) {
                a->setVisible(visible);
            }
        }
    });
    viewMenu->addAction(m_actAdvancedMenus);
    viewMenu->addSeparator();

    auto *fullScreenAction = new QAction(tr("Full &Screen"), this);
    fullScreenAction->setShortcut(QKeySequence(Qt::Key_F11));
    connect(fullScreenAction, &QAction::triggered, this, &MainWindow::onToggleFullScreen);
    viewMenu->addAction(fullScreenAction);
    viewMenu->addSeparator();
    auto *expandAllAction = new QAction(tr("E&xpand All"), this);
    connect(expandAllAction, &QAction::triggered, this, [this] {
        if (m_consoleView && m_consoleView->findChild<QTreeView *>(QStringLiteral("consoleTree")))
            m_consoleView->findChild<QTreeView *>(QStringLiteral("consoleTree"))->expandAll();
    });
    viewMenu->addAction(expandAllAction);

    auto *collapseAllAction = new QAction(tr("C&ollapse All"), this);
    connect(collapseAllAction, &QAction::triggered, this, [this] {
        if (m_consoleView && m_consoleView->findChild<QTreeView *>(QStringLiteral("consoleTree")))
            m_consoleView->findChild<QTreeView *>(QStringLiteral("consoleTree"))->collapseAll();
    });
    viewMenu->addAction(collapseAllAction);

    viewMenu->addSeparator();
    auto *customizeAction = new QAction(tr("&Customize..."), this);
    connect(customizeAction, &QAction::triggered, this, &MainWindow::onCustomize);
    viewMenu->addAction(customizeAction);

    QMenu *favoritesMenu = m_menuBar->addMenu(tr("F&avorites"));
    auto *addFavorite = new QAction(tr("Add to &Favorites"), this);
    connect(addFavorite, &QAction::triggered, this, [this] {
        if (!m_consoleView)
            return;
        const QString container = m_consoleView->currentContainer();
        QSettings settings;
        QStringList favorites = settings.value(QStringLiteral("favorites/list")).toStringList();
        if (!favorites.contains(container))
            favorites.append(container);
        settings.setValue(QStringLiteral("favorites/list"), favorites);
        statusBar()->showMessage(tr("Added \"%1\" to Favorites.").arg(container), 4000);
    });
    favoritesMenu->addAction(addFavorite);

    auto *organizeFavorites = new QAction(tr("&Organize Favorites..."), this);
    connect(organizeFavorites, &QAction::triggered, this, [this] {
        QSettings settings;
        QStringList favorites = settings.value(QStringLiteral("favorites/list")).toStringList();
        if (favorites.isEmpty()) {
            QMessageBox::information(this, tr("Organize Favorites"),
                                     tr("No favorites have been added yet."));
            return;
        }

        bool ok = false;
        const QString choice = QInputDialog::getItem(
            this, tr("Organize Favorites"), tr("Select a favorite to remove:"),
            favorites, 0, false, &ok);
        if (!ok || choice.isEmpty())
            return;

        favorites.removeAll(choice);
        settings.setValue(QStringLiteral("favorites/list"), favorites);
        statusBar()->showMessage(tr("Removed \"%1\" from Favorites.").arg(choice), 4000);
    });
    favoritesMenu->addAction(organizeFavorites);

    QMenu *windowMenu = m_menuBar->addMenu(tr("&Window"));
    auto *cascadeAction = new QAction(tr("&Cascade"), this);
    connect(cascadeAction, &QAction::triggered, this, &MainWindow::onCascadeWindows);
    windowMenu->addAction(cascadeAction);

    auto *tileHAction = new QAction(tr("Tile &Horizontally"), this);
    connect(tileHAction, &QAction::triggered, this, &MainWindow::onTileHorizontal);
    windowMenu->addAction(tileHAction);

    auto *tileVAction = new QAction(tr("Tile &Vertically"), this);
    connect(tileVAction, &QAction::triggered, this, &MainWindow::onTileVertical);
    windowMenu->addAction(tileVAction);

    auto *arrangeAction = new QAction(tr("&Arrange Icons"), this);
    connect(arrangeAction, &QAction::triggered, this, [this] {
        if (!m_consoleView)
            return;
        QListView *iconView = m_consoleView->findChild<QListView *>(QStringLiteral("iconView"));
        if (iconView)
            iconView->doItemsLayout();
        statusBar()->showMessage(tr("Icons arranged."), 3000);
    });
    windowMenu->addAction(arrangeAction);

    QMenu *helpMenu = m_menuBar->addMenu(tr("&Help"));
    helpMenu->addAction(m_actHelp);
    helpMenu->addSeparator();
    auto *aboutQtAction = new QAction(tr("About &Qt"), this);
    connect(aboutQtAction, &QAction::triggered, this, [this] {
        QMessageBox::aboutQt(this, tr("About Qt"));
    });
    helpMenu->addAction(aboutQtAction);
    helpMenu->addSeparator();
    auto *aboutAction = new QAction(tr("&About Monarchy Management Console"), this);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::onAbout);
    helpMenu->addAction(aboutAction);
}

void MainWindow::createToolbar()
{
    m_toolbar = addToolBar(tr("Standard"));
    m_toolbar->setObjectName(QStringLiteral("standardToolBar"));
    m_toolbar->setMovable(false);
    m_toolbar->setFloatable(false);
    m_toolbar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    m_toolbar->setIconSize(QSize(16, 16));

    m_toolbar->addAction(m_actBack);
    m_toolbar->addAction(m_actForward);
    m_toolbar->addAction(m_actUp);
    m_toolbar->addSeparator();
    m_toolbar->addAction(m_actNew);
    m_toolbar->addAction(m_actDelete);
    m_toolbar->addAction(m_actProperties);
    m_toolbar->addSeparator();

    auto *viewButton = new QToolButton(m_toolbar);
    viewButton->setObjectName(QStringLiteral("viewButton"));
    viewButton->setIcon(style()->standardIcon(QStyle::SP_FileDialogListView));
    viewButton->setToolTip(tr("View"));
    viewButton->setPopupMode(QToolButton::InstantPopup);
    viewButton->setAutoRaise(true);
    auto *viewMenu = new QMenu(viewButton);
    viewMenu->addAction(m_actViewLargeIcons);
    viewMenu->addAction(m_actViewSmallIcons);
    viewMenu->addAction(m_actViewList);
    viewMenu->addAction(m_actViewDetails);
    viewButton->setMenu(viewMenu);
    m_toolbar->addWidget(viewButton);

    m_toolbar->addSeparator();
    m_toolbar->addAction(m_actRefresh);
    m_toolbar->addAction(m_actFind);
    m_toolbar->addAction(m_actExport);
    m_toolbar->addSeparator();
    m_toolbar->addAction(m_actHelp);
}

void MainWindow::createStatusBar()
{
    m_statusBar = statusBar();
    m_statusBar->showMessage(tr("Ready"));

    m_statusCountLabel = new QLabel(tr("0 objects"), this);
    m_statusCountLabel->setObjectName(QStringLiteral("statusCountLabel"));
    m_statusCountLabel->setMinimumWidth(120);
    m_statusBar->addPermanentWidget(m_statusCountLabel);
}

void MainWindow::createCentralWidget()
{
    m_consoleView = new ConsoleView(this);
    setCentralWidget(m_consoleView);

    // Backend services: the console is purely a client, like dsa.msc on a
    // Windows DC — it never hosts the domain controller, not even when the
    // very machine runs `monarchy-dcd` next to it.
    m_connectionService = new ConnectionService(this);
    m_directoryService = new DirectoryService(m_connectionService, this);
    m_adminService = new AdminService(m_directoryService, this);
    m_consoleView->setConnectionService(m_connectionService);
    m_consoleView->setDirectoryService(m_directoryService);
    m_consoleView->setAdminService(m_adminService);

    // Auto-connect using the saved profile (talks real LDAP to the local DC).
    ConnectionProfile profile;
    profile.server = QSettings().value(QStringLiteral("connection/server"), QStringLiteral("localhost")).toString();
    profile.port = QSettings().value(QStringLiteral("connection/port"), 1389).toInt();
    profile.baseDn = QSettings().value(QStringLiteral("connection/baseDn"),
                                       QStringLiteral("DC=corp,DC=example,DC=com")).toString();
    profile.bindDn = QSettings().value(QStringLiteral("connection/bindDn"), QString()).toString();
    profile.useKerberos = QSettings().value(QStringLiteral("connection/kerberos"), false).toBool();
    profile.useTls = QSettings().value(QStringLiteral("connection/tls"), false).toBool();
    m_connectionService->connect(profile);

    connect(m_connectionService, &ConnectionService::error, this, [this](const QString &message) {
        statusBar()->showMessage(tr("Connection failed: %1").arg(message), 8000);
    });
    connect(m_directoryService, &DirectoryService::error, this, [this](const QString &message) {
        statusBar()->showMessage(tr("Directory error: %1").arg(message), 8000);
    });
    connect(m_adminService, &AdminService::error, this, [this](const QString &message) {
        statusBar()->showMessage(tr("Administration error: %1").arg(message), 8000);
    });

    connect(m_consoleView, &ConsoleView::statusMessage,
            this, [this](const QString &message) {
                statusBar()->showMessage(message);
            });
    connect(m_consoleView, &ConsoleView::containerChanged,
            this, [this](const QString &container) {
                setWindowTitle(tr("Monarchy Management Console - %1").arg(container));
            });
    connect(m_consoleView, &ConsoleView::selectionStateChanged,
            this, [this](bool hasSelection, bool singleSelection) {
                Q_UNUSED(hasSelection)
                m_actProperties->setEnabled(singleSelection);
                m_actDelete->setEnabled(singleSelection);
            });
    connect(m_consoleView, &ConsoleView::historyChanged,
            this, &MainWindow::updateHistoryActions);
    connect(m_consoleView->resultsModel(), &ResultsModel::modelReset,
            this, [this] {
                if (m_statusCountLabel && m_consoleView)
                    m_statusCountLabel->setText(
                        tr("%1 object(s)").arg(m_consoleView->resultsModel()->objectCount()));
            });
}

void MainWindow::loadSettings()
{
    QSettings settings;

    const QByteArray geometry = settings.value(QStringLiteral("main/geometry")).toByteArray();
    if (!geometry.isEmpty())
        restoreGeometry(geometry);

    const bool statusBarVisible = settings.value(QStringLiteral("main/statusBar"), true).toBool();
    m_actStatusBar->setChecked(statusBarVisible);
    statusBar()->setVisible(statusBarVisible);

    const bool treeVisible = settings.value(QStringLiteral("main/consoleTree"), true).toBool();
    m_actConsoleTree->setChecked(treeVisible);
    m_consoleView->setTreeVisible(treeVisible);

    const QString mode = settings.value(QStringLiteral("main/viewMode"),
                                        QStringLiteral("details")).toString();
    if (mode == QLatin1String("large")) {
        m_consoleView->setViewMode(ConsoleView::LargeIcons);
        m_actViewLargeIcons->setChecked(true);
    } else if (mode == QLatin1String("small")) {
        m_consoleView->setViewMode(ConsoleView::SmallIcons);
        m_actViewSmallIcons->setChecked(true);
    } else if (mode == QLatin1String("list")) {
        m_consoleView->setViewMode(ConsoleView::List);
        m_actViewList->setChecked(true);
    } else {
        m_consoleView->setViewMode(ConsoleView::Details);
        m_actViewDetails->setChecked(true);
    }
}

void MainWindow::saveSettings()
{
    QSettings settings;
    settings.setValue(QStringLiteral("main/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("main/statusBar"), m_actStatusBar->isChecked());
    settings.setValue(QStringLiteral("main/consoleTree"), m_actConsoleTree->isChecked());

    QString mode = QStringLiteral("details");
    switch (m_consoleView->viewMode()) {
    case ConsoleView::LargeIcons:
        mode = QStringLiteral("large");
        break;
    case ConsoleView::SmallIcons:
        mode = QStringLiteral("small");
        break;
    case ConsoleView::List:
        mode = QStringLiteral("list");
        break;
    case ConsoleView::Details:
        break;
    }
    settings.setValue(QStringLiteral("main/viewMode"), mode);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // The console never owns the DC: persistence is the service's job (the
    // daemon's shutdown path flushes the store), exactly as LSASS persists
    // the NTDS store on a Windows DC whether or not dsa.msc is open.
    saveSettings();
    QMainWindow::closeEvent(event);
}

void MainWindow::onNewWindow()
{
    auto *window = new MainWindow;
    window->setAttribute(Qt::WA_DeleteOnClose);
    window->move(x() + 24, y() + 24);
    window->show();
}

void MainWindow::onExportList()
{
    if (!m_consoleView)
        return;

    const QString fileName = QFileDialog::getSaveFileName(
        this, tr("Export List"),
        QDir::homePath() + QStringLiteral("/console-list.csv"),
        tr("CSV files (*.csv);;All files (*)"));
    if (fileName.isEmpty())
        return;

    QSaveFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export List"),
                             tr("Could not create the file:\n%1").arg(file.errorString()));
        return;
    }

    const int count = m_consoleView->resultsModel()->objectCount();
    if (!m_consoleView->exportResults(&file) || !file.commit()) {
        QMessageBox::warning(this, tr("Export List"),
                             tr("Could not write the file:\n%1").arg(file.errorString()));
        return;
    }

    statusBar()->showMessage(tr("Exported %n object(s) to %1", nullptr, count)
                                 .arg(QDir::toNativeSeparators(fileName)),
                             5000);
}

void MainWindow::onProperties()
{
    if (m_consoleView)
        m_consoleView->showPropertiesForSelection();
}

void MainWindow::onDelete()
{
    if (!m_consoleView || !m_consoleView->hasSingleSelection())
        return;

    const DirectoryObject object = m_consoleView->currentObject();
    const auto answer = QMessageBox::question(
        this, tr("Delete"),
        tr("Delete \"%1\"?\n\n"
           "The object is removed from the directory and cannot be recovered.")
            .arg(object.name),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer == QMessageBox::Yes)
        m_consoleView->deleteCurrentObject();
}

void MainWindow::onRefresh()
{
    if (m_consoleView)
        m_consoleView->refresh();
}

void MainWindow::onFind()
{
    if (!m_consoleView)
        return;

    bool ok = false;
    const QString text = QInputDialog::getText(
        this, tr("Find"), tr("Filter results by name, type or description:"),
        QLineEdit::Normal, m_consoleView->filterText(), &ok);
    if (!ok)
        return;

    m_consoleView->setFilterText(text.trimmed());
    statusBar()->showMessage(
        text.trimmed().isEmpty()
            ? tr("Filter cleared.")
            : tr("Filter applied: \"%1\"").arg(text.trimmed()),
        4000);
}

void MainWindow::onOpenConsole()
{
    const QString fileName = QFileDialog::getOpenFileName(
        this, tr("Open Console"), QString(),
        tr("Console state files (*.ini *.msc);;All files (*)"));
    if (fileName.isEmpty())
        return;

    QSettings settings(fileName, QSettings::IniFormat);
    const QString container = settings.value(QStringLiteral("console/container"),
                                             QStringLiteral("Console Root")).toString();
    const QString mode = settings.value(QStringLiteral("console/viewMode"),
                                        QStringLiteral("details")).toString();
    const QString filter = settings.value(QStringLiteral("console/filter")).toString();

    if (m_consoleView) {
        m_consoleView->navigateTo(container);
        if (mode == QLatin1String("large"))
            m_consoleView->setViewMode(ConsoleView::LargeIcons);
        else if (mode == QLatin1String("small"))
            m_consoleView->setViewMode(ConsoleView::SmallIcons);
        else if (mode == QLatin1String("list"))
            m_consoleView->setViewMode(ConsoleView::List);
        else
            m_consoleView->setViewMode(ConsoleView::Details);
        m_consoleView->setFilterText(filter);
    }

    m_consoleFilePath = fileName;
    addToRecentFiles(fileName);
    statusBar()->showMessage(tr("Opened %1").arg(QDir::toNativeSeparators(fileName)), 4000);
}

void MainWindow::onSaveConsole()
{
    if (m_consoleFilePath.isEmpty()) {
        onSaveConsoleAs();
        return;
    }
    saveConsoleTo(m_consoleFilePath);
}

void MainWindow::onSaveConsoleAs()
{
    const QString fileName = QFileDialog::getSaveFileName(
        this, tr("Save Console As"), QDir::homePath() + QStringLiteral("/console.ini"),
        tr("Console state files (*.ini *.msc);;All files (*)"));
    if (fileName.isEmpty())
        return;

    m_consoleFilePath = fileName;
    saveConsoleTo(fileName);
}

void MainWindow::saveConsoleTo(const QString &fileName)
{
    // Helper implemented inline below via QSettings.
    QSettings settings(fileName, QSettings::IniFormat);
    settings.setValue(QStringLiteral("console/container"),
                      m_consoleView ? m_consoleView->currentContainer()
                                    : QStringLiteral("Console Root"));

    QString mode = QStringLiteral("details");
    if (m_consoleView) {
        switch (m_consoleView->viewMode()) {
        case ConsoleView::LargeIcons: mode = QStringLiteral("large"); break;
        case ConsoleView::SmallIcons: mode = QStringLiteral("small"); break;
        case ConsoleView::List: mode = QStringLiteral("list"); break;
        case ConsoleView::Details: break;
        }
    }
    settings.setValue(QStringLiteral("console/viewMode"), mode);
    settings.setValue(QStringLiteral("console/filter"),
                      m_consoleView ? m_consoleView->filterText() : QString());
    settings.sync();

    addToRecentFiles(fileName);
    statusBar()->showMessage(tr("Saved %1").arg(QDir::toNativeSeparators(fileName)), 4000);
}

void MainWindow::onCascadeWindows()
{
    const QWidgetList windows = QApplication::topLevelWidgets();
    QList<QMainWindow *> mainWindows;
    for (QWidget *w : windows) {
        if (auto *mw = qobject_cast<QMainWindow *>(w))
            mainWindows.append(mw);
    }
    if (mainWindows.isEmpty())
        return;

    int x = 0, y = 0;
    for (QMainWindow *w : mainWindows) {
        w->move(x, y);
        w->raise();
        x += 24;
        y += 24;
    }
}

void MainWindow::onTileHorizontal()
{
    const QWidgetList windows = QApplication::topLevelWidgets();
    QList<QMainWindow *> mainWindows;
    for (QWidget *w : windows) {
        if (auto *mw = qobject_cast<QMainWindow *>(w))
            mainWindows.append(mw);
    }
    if (mainWindows.isEmpty())
        return;

    const QRect screen = QApplication::primaryScreen()->availableGeometry();
    const int h = screen.height() / mainWindows.size();
    int y = screen.top();
    for (QMainWindow *w : mainWindows) {
        w->setGeometry(screen.left(), y, screen.width(), h);
        y += h;
    }
}

void MainWindow::onTileVertical()
{
    const QWidgetList windows = QApplication::topLevelWidgets();
    QList<QMainWindow *> mainWindows;
    for (QWidget *w : windows) {
        if (auto *mw = qobject_cast<QMainWindow *>(w))
            mainWindows.append(mw);
    }
    if (mainWindows.isEmpty())
        return;

    const QRect screen = QApplication::primaryScreen()->availableGeometry();
    const int w = screen.width() / mainWindows.size();
    int x = screen.left();
    for (QMainWindow *mw : mainWindows) {
        mw->setGeometry(x, screen.top(), w, screen.height());
        x += w;
    }
}

QString MainWindow::namingContext() const
{
    if (m_connectionService) {
        const QString base = m_connectionService->baseDn();
        if (!base.isEmpty())
            return base;
    }
    return QStringLiteral("DC=corp,DC=example,DC=com");
}

QString MainWindow::connectedDnsZone() const
{
    // The console is a pure client: it derives the DNS zone from the
    // connected domain's naming base the way AD admin tools do against a
    // remote DC — never from a locally hosted engine.
    //   "DC=corp,DC=example,DC=com" -> "corp.example.com"
    QString zone;
    const QString nc = namingContext();
    int at = nc.indexOf(QLatin1String("DC="));
    while (at != -1) {
        const int end = nc.indexOf(QLatin1Char(','), at + 3);
        if (!zone.isEmpty())
            zone += QLatin1Char('.');
        zone += nc.mid(at + 3, (end == -1 ? nc.size() : end) - at - 3);
        at = (end == -1) ? -1 : nc.indexOf(QLatin1String("DC="), end + 1);
    }
    return zone.isEmpty() ? QStringLiteral("corp.example.com") : zone;
}

void MainWindow::onNewUser()
{
    if (!m_consoleView)
        return;

    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New User"),
                                               tr("Full name:"), QLineEdit::Normal, QString(), &ok);
    if (!ok || name.trimmed().isEmpty())
        return;

    const QString password = QInputDialog::getText(this, tr("New User"),
                                                   tr("Password for %1:").arg(name.trimmed()),
                                                   QLineEdit::Password, QString(), &ok);
    if (!ok || password.isEmpty())
        return;

    DirectoryObject object;
    object.kind = ObjectKind::User;
    object.name = name.trimmed();
    object.type = QStringLiteral("User");
    object.description = tr("Newly created user");
    object.container = QStringLiteral("Users");
    object.id = QStringLiteral("CN=%1,CN=Users,%2").arg(object.name, namingContext());
    const QString account = object.name.toLower().remove(QLatin1Char(' '));
    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("user"));
    object.attributes.insert(QStringLiteral("cn"), object.name);
    object.attributes.insert(QStringLiteral("displayName"), object.name);
    object.attributes.insert(QStringLiteral("sAMAccountName"), account);
    object.attributes.insert(QStringLiteral("userPrincipalName"),
                             account + QLatin1Char('@') + connectedDnsZone());
    // The directory derives a salted verifier from this and never stores it.
    object.attributes.insert(QStringLiteral("unicodePwd"), password);
    object.attributes.insert(QStringLiteral("userAccountControl"), QStringLiteral("512"));

    m_consoleView->addObject(object);
    statusBar()->showMessage(tr("Creating user %1...").arg(object.name), 4000);
}

void MainWindow::onNewGroup()
{
    if (!m_consoleView)
        return;

    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New Group"),
                                               tr("Group name:"), QLineEdit::Normal, QString(), &ok);
    if (!ok || name.trimmed().isEmpty())
        return;

    DirectoryObject object;
    object.kind = ObjectKind::Group;
    object.name = name.trimmed();
    object.type = QStringLiteral("Security Group");
    object.description = tr("Newly created group");
    object.container = QStringLiteral("Groups");
    object.id = QStringLiteral("CN=%1,CN=Users,%2").arg(object.name, namingContext());
    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("group"));
    object.attributes.insert(QStringLiteral("cn"), object.name);
    object.attributes.insert(QStringLiteral("sAMAccountName"), object.name.toLower().remove(QLatin1Char(' ')));
    object.attributes.insert(QStringLiteral("groupType"), QStringLiteral("Security"));

    m_consoleView->addObject(object);
    statusBar()->showMessage(tr("Created group %1.").arg(object.name), 4000);
}

void MainWindow::onNewComputer()
{
    if (!m_consoleView)
        return;

    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New Computer"),
                                               tr("Computer name:"), QLineEdit::Normal, QString(), &ok);
    if (!ok || name.trimmed().isEmpty())
        return;

    DirectoryObject object;
    object.kind = ObjectKind::Computer;
    object.name = name.trimmed().toUpper();
    object.type = QStringLiteral("Computer");
    object.description = tr("Newly created computer");
    object.container = QStringLiteral("Computers");
    object.id = QStringLiteral("CN=%1,CN=Computers,%2").arg(object.name, namingContext());
    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("computer"));
    object.attributes.insert(QStringLiteral("cn"), object.name);
    object.attributes.insert(QStringLiteral("sAMAccountName"), object.name.toLower() + QLatin1Char('$'));
    const QString zone = connectedDnsZone();
    object.attributes.insert(QStringLiteral("dNSHostName"),
                             object.name.toLower() + QLatin1Char('.') + zone);

    m_consoleView->addObject(object);
    statusBar()->showMessage(tr("Created computer %1.").arg(object.name), 4000);
}

void MainWindow::onOptions()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Options"));
    dialog.setModal(true);
    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout;

    QCheckBox *treeCheck = new QCheckBox(tr("Console tree"), &dialog);
    treeCheck->setChecked(m_actConsoleTree->isChecked());
    form->addRow(tr("Show:"), treeCheck);

    QCheckBox *statusCheck = new QCheckBox(tr("Status bar"), &dialog);
    statusCheck->setChecked(m_actStatusBar->isChecked());
    form->addRow(QString(), statusCheck);

    QCheckBox *autoRefreshCheck = new QCheckBox(tr("Auto-refresh"), &dialog);
    autoRefreshCheck->setChecked(QSettings().value(QStringLiteral("options/autoRefresh"), false).toBool());
    form->addRow(QString(), autoRefreshCheck);

    QSpinBox *autoRefreshInterval = new QSpinBox(&dialog);
    autoRefreshInterval->setRange(5, 3600);
    autoRefreshInterval->setSuffix(tr(" sec"));
    autoRefreshInterval->setValue(QSettings().value(QStringLiteral("options/autoRefreshInterval"), 60).toInt());
    form->addRow(tr("Interval:"), autoRefreshInterval);

    QComboBox *viewCombo = new QComboBox(&dialog);
    viewCombo->addItems({tr("Details"), tr("Large Icons"), tr("Small Icons"), tr("List")});
    if (m_consoleView) {
        switch (m_consoleView->viewMode()) {
        case ConsoleView::LargeIcons: viewCombo->setCurrentIndex(1); break;
        case ConsoleView::SmallIcons: viewCombo->setCurrentIndex(2); break;
        case ConsoleView::List: viewCombo->setCurrentIndex(3); break;
        case ConsoleView::Details: default: viewCombo->setCurrentIndex(0); break;
        }
    }
    form->addRow(tr("Default view:"), viewCombo);

    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted)
        return;

    m_actConsoleTree->setChecked(treeCheck->isChecked());
    m_actStatusBar->setChecked(statusCheck->isChecked());

    QSettings settings;
    settings.setValue(QStringLiteral("options/autoRefresh"), autoRefreshCheck->isChecked());
    settings.setValue(QStringLiteral("options/autoRefreshInterval"), autoRefreshInterval->value());
    applyAutoRefreshSettings();

    if (m_consoleView) {
        switch (viewCombo->currentIndex()) {
        case 1: m_consoleView->setViewMode(ConsoleView::LargeIcons); break;
        case 2: m_consoleView->setViewMode(ConsoleView::SmallIcons); break;
        case 3: m_consoleView->setViewMode(ConsoleView::List); break;
        default: m_consoleView->setViewMode(ConsoleView::Details); break;
        }
    }
    saveSettings();
}

void MainWindow::onCustomize()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Customize"));
    dialog.setModal(true);
    auto *layout = new QVBoxLayout(&dialog);

    auto *label = new QLabel(tr("Toggle toolbar buttons and menu items. (Basic customization)"), &dialog);
    layout->addWidget(label);

    QCheckBox *toolbarCheck = new QCheckBox(tr("Show standard toolbar"), &dialog);
    toolbarCheck->setChecked(m_toolbar && m_toolbar->isVisible());
    layout->addWidget(toolbarCheck);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted)
        return;

    if (m_toolbar)
        m_toolbar->setVisible(toolbarCheck->isChecked());
}

void MainWindow::onPrint()
{
    if (!m_consoleView)
        return;

    if (!m_printer)
        m_printer = new QPrinter(QPrinter::HighResolution);

    QPrintDialog dialog(m_printer, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    printResults(m_printer);
}

void MainWindow::onPrintPreview()
{
    if (!m_consoleView)
        return;

    if (!m_printer)
        m_printer = new QPrinter(QPrinter::HighResolution);

    QPrintPreviewDialog preview(m_printer, this);
    connect(&preview, &QPrintPreviewDialog::paintRequested,
            this, [this](QPrinter *p) { printResults(p); });
    preview.exec();
}

void MainWindow::onPageSetup()
{
    if (!m_printer)
        m_printer = new QPrinter(QPrinter::HighResolution);

    // Qt 6 has no QPageSetupDialog; use QPrintDialog's page setup via printer properties.
    QPrintDialog dialog(m_printer, this);
    dialog.setWindowTitle(tr("Page Setup"));
    dialog.exec();
}

void MainWindow::onCloseWindow()
{
    close();
}

void MainWindow::printResults(QPrinter *printer)
{
    if (!printer || !m_consoleView)
        return;

    ResultsModel *model = m_consoleView->resultsModel();
    QString html = QStringLiteral("<h2>%1</h2>")
                       .arg(m_consoleView->currentContainer().toHtmlEscaped());
    html += QStringLiteral("<table border='1' cellspacing='0' cellpadding='4'>");
    html += QStringLiteral("<tr><th>Name</th><th>Type</th><th>Description</th></tr>");

    for (int row = 0; row < model->objectCount(); ++row) {
        const DirectoryObject obj = model->objectAt(row);
        html += QStringLiteral("<tr><td>%1</td><td>%2</td><td>%3</td></tr>")
                    .arg(obj.name.toHtmlEscaped(), obj.type.toHtmlEscaped(),
                         obj.description.toHtmlEscaped());
    }
    html += QStringLiteral("</table>");

    QTextDocument document;
    document.setHtml(html);
    document.print(printer);
}

void MainWindow::updateRecentFilesMenu()
{
    if (!m_recentFilesMenu)
        return;

    m_recentFilesMenu->clear();
    QSettings settings;
    const QStringList files = settings.value(QStringLiteral("recentFiles/list")).toStringList();

    if (files.isEmpty()) {
        auto *noneAction = m_recentFilesMenu->addAction(tr("(none)"));
        noneAction->setEnabled(false);
        return;
    }

    for (const QString &file : files) {
        QAction *action = m_recentFilesMenu->addAction(QDir::toNativeSeparators(file));
        connect(action, &QAction::triggered, this, [this, file] {
            // Re-open via onOpenConsole path by setting and invoking.
            m_consoleFilePath = file;
            // Trigger load manually.
            QSettings s(file, QSettings::IniFormat);
            const QString container = s.value(QStringLiteral("console/container"),
                                             QStringLiteral("Console Root")).toString();
            const QString mode = s.value(QStringLiteral("console/viewMode"),
                                        QStringLiteral("details")).toString();
            const QString filter = s.value(QStringLiteral("console/filter")).toString();
            if (m_consoleView) {
                m_consoleView->navigateTo(container);
                if (mode == QLatin1String("large"))
                    m_consoleView->setViewMode(ConsoleView::LargeIcons);
                else if (mode == QLatin1String("small"))
                    m_consoleView->setViewMode(ConsoleView::SmallIcons);
                else if (mode == QLatin1String("list"))
                    m_consoleView->setViewMode(ConsoleView::List);
                else
                    m_consoleView->setViewMode(ConsoleView::Details);
                m_consoleView->setFilterText(filter);
            }
            statusBar()->showMessage(tr("Opened %1").arg(QDir::toNativeSeparators(file)), 4000);
        });
    }

    m_recentFilesMenu->addSeparator();
    auto *clearAction = m_recentFilesMenu->addAction(tr("Clear Recent Files"));
    connect(clearAction, &QAction::triggered, this, [this] {
        QSettings settings;
        settings.remove(QStringLiteral("recentFiles/list"));
        updateRecentFilesMenu();
    });
}

void MainWindow::addToRecentFiles(const QString &fileName)
{
    QSettings settings;
    QStringList files = settings.value(QStringLiteral("recentFiles/list")).toStringList();
    files.removeAll(fileName);
    files.prepend(fileName);
    while (files.size() > 8)
        files.removeLast();
    settings.setValue(QStringLiteral("recentFiles/list"), files);
    updateRecentFilesMenu();
}

void MainWindow::onNewOu()
{
    if (!m_consoleView)
        return;

    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New Organizational Unit"),
                                               tr("OU name:"), QLineEdit::Normal, QString(), &ok);
    if (!ok || name.trimmed().isEmpty())
        return;

    DirectoryObject object;
    object.kind = ObjectKind::Ou;
    object.name = name.trimmed();
    object.type = QStringLiteral("Organizational Unit");
    object.description = tr("Newly created OU");
    object.container = QStringLiteral("Console Root");
    object.id = QStringLiteral("OU=%1,%2").arg(object.name, namingContext());
    object.attributes.insert(QStringLiteral("objectClass"), QStringLiteral("organizationalUnit"));
    object.attributes.insert(QStringLiteral("ou"), object.name);

    m_consoleView->addObject(object);
    statusBar()->showMessage(tr("Created OU %1.").arg(object.name), 4000);
}

void MainWindow::onConnectToDirectory()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Connect to Directory"));
    dialog.setModal(true);
    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout;

    QLineEdit *serverEdit = new QLineEdit(&dialog);
    serverEdit->setText(QSettings().value(QStringLiteral("connection/server"), QStringLiteral("localhost")).toString());
    form->addRow(tr("Server:"), serverEdit);

    QSpinBox *portSpin = new QSpinBox(&dialog);
    portSpin->setRange(1, 65535);
    portSpin->setValue(QSettings().value(QStringLiteral("connection/port"), 1389).toInt());
    form->addRow(tr("Port:"), portSpin);

    QLineEdit *baseDnEdit = new QLineEdit(&dialog);
    baseDnEdit->setText(QSettings().value(QStringLiteral("connection/baseDn"), QStringLiteral("DC=corp,DC=example,DC=com")).toString());
    form->addRow(tr("Base DN:"), baseDnEdit);

    QLineEdit *bindDnEdit = new QLineEdit(&dialog);
    bindDnEdit->setText(QSettings().value(QStringLiteral("connection/bindDn"), QString()).toString());
    form->addRow(tr("Bind DN:"), bindDnEdit);

    QLineEdit *passwordEdit = new QLineEdit(&dialog);
    passwordEdit->setEchoMode(QLineEdit::Password);
    form->addRow(tr("Password:"), passwordEdit);

    QCheckBox *kerberosCheck = new QCheckBox(tr("Use Kerberos (GSSAPI)"), &dialog);
    kerberosCheck->setChecked(QSettings().value(QStringLiteral("connection/kerberos"), false).toBool());
    form->addRow(QString(), kerberosCheck);

    QCheckBox *tlsCheck = new QCheckBox(tr("Use TLS (LDAPS)"), &dialog);
    tlsCheck->setChecked(QSettings().value(QStringLiteral("connection/tls"), false).toBool());
    form->addRow(QString(), tlsCheck);

    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted)
        return;

    QSettings settings;
    settings.setValue(QStringLiteral("connection/server"), serverEdit->text());
    settings.setValue(QStringLiteral("connection/port"), portSpin->value());
    settings.setValue(QStringLiteral("connection/baseDn"), baseDnEdit->text());
    settings.setValue(QStringLiteral("connection/bindDn"), bindDnEdit->text());
    settings.setValue(QStringLiteral("connection/kerberos"), kerberosCheck->isChecked());
    settings.setValue(QStringLiteral("connection/tls"), tlsCheck->isChecked());

    if (!m_connectionService)
        return;

    ConnectionProfile profile;
    profile.server = serverEdit->text().trimmed();
    profile.port = portSpin->value();
    profile.baseDn = baseDnEdit->text().trimmed();
    profile.bindDn = bindDnEdit->text().trimmed();
    profile.password = passwordEdit->text();
    profile.useKerberos = kerberosCheck->isChecked();
    profile.useTls = tlsCheck->isChecked();

    m_connectionService->disconnect();
    m_connectionService->connect(profile);
    statusBar()->showMessage(tr("Connecting to %1:%2...")
                                 .arg(profile.server).arg(profile.port),
                             4000);
}

void MainWindow::onDisconnect()
{
    if (m_connectionService)
        m_connectionService->disconnect();
    statusBar()->showMessage(tr("Disconnected. Showing the offline sample directory."), 5000);
}

void MainWindow::onInvertSelection()
{
    if (!m_consoleView)
        return;
    QAbstractItemView *view = m_consoleView->currentResultsView();
    if (!view || !view->selectionModel())
        return;

    QItemSelectionModel *sel = view->selectionModel();
    const int rows = m_consoleView->resultsModel()->rowCount();
    for (int r = 0; r < rows; ++r) {
        const QModelIndex idx = m_consoleView->resultsModel()->index(r, 0);
        if (sel->isSelected(idx))
            sel->select(idx, QItemSelectionModel::Deselect);
        else
            sel->select(idx, QItemSelectionModel::Select | QItemSelectionModel::Rows);
    }
    m_consoleView->updateSelectionState();
}

void MainWindow::applyAutoRefreshSettings()
{
    const bool enabled = QSettings().value(QStringLiteral("options/autoRefresh"), false).toBool();
    const int intervalSec = QSettings().value(QStringLiteral("options/autoRefreshInterval"), 60).toInt();

    if (!m_refreshTimer) {
        m_refreshTimer = new QTimer(this);
        connect(m_refreshTimer, &QTimer::timeout, this, [this] {
            if (m_consoleView)
                m_consoleView->refresh();
        });
    }

    if (enabled) {
        m_refreshTimer->setInterval(intervalSec * 1000);
        m_refreshTimer->start();
    } else {
        m_refreshTimer->stop();
    }
}

void MainWindow::onToggleFullScreen()
{
    if (isFullScreen())
        showNormal();
    else
        showFullScreen();
}

void MainWindow::onResetPassword()
{
    if (!m_consoleView || !m_consoleView->hasSingleSelection() || !m_adminService)
        return;

    const DirectoryObject obj = m_consoleView->currentObject();
    if (obj.kind != ObjectKind::User) {
        QMessageBox::information(this, tr("Reset Password"),
                                 tr("Password reset is only available for users."));
        return;
    }

    bool ok = false;
    const QString password = QInputDialog::getText(this, tr("Reset Password"),
                                                   tr("New password for %1:").arg(obj.name),
                                                   QLineEdit::Password, QString(), &ok);
    if (!ok || password.isEmpty())
        return;

    m_adminService->resetPassword(obj.id, password, true);
    statusBar()->showMessage(tr("Password reset for %1.").arg(obj.name), 4000);
}

void MainWindow::onAbout()
{
    QMessageBox::about(
        this, tr("About Monarchy Management Console"),
        tr("<h3>Monarchy Management Console %1</h3>"
           "<p>Classic Microsoft Management Console-style host for the Monarchy directory service.</p>"
           "<p>This console is an independently authored Qt 6 application. "
           "It reproduces the MMC layout and behaviour using its own code and artwork.</p>"
           "<p>This build hosts a local Monarchy directory service (LDAP 1389, DNS 1053) "
           "and can also connect to a remote directory over LDAP. LDAPS and "
           "Kerberos/GSSAPI require the OpenLDAP build option.</p>")
            .arg(QApplication::applicationVersion()));
}

void MainWindow::onHelpTopics()
{
    QMessageBox::information(
        this, tr("Monarchy Management Console Help"),
        tr("<p>Use the console tree on the left to choose what the results pane shows. "
           "Back, Forward and Up navigate the console history.</p>"
           "<p>Select an object and choose <b>Properties</b> (or double-click it) to open "
           "its property sheet. <b>Export List</b> writes the visible objects to CSV.</p>"
           "<p>Console state is remembered between sessions with QSettings.</p>"));
}

void MainWindow::onViewLargeIcons()
{
    if (m_consoleView)
        m_consoleView->setViewMode(ConsoleView::LargeIcons);
}

void MainWindow::onViewSmallIcons()
{
    if (m_consoleView)
        m_consoleView->setViewMode(ConsoleView::SmallIcons);
}

void MainWindow::onViewList()
{
    if (m_consoleView)
        m_consoleView->setViewMode(ConsoleView::List);
}

void MainWindow::onViewDetails()
{
    if (m_consoleView)
        m_consoleView->setViewMode(ConsoleView::Details);
}

void MainWindow::updateHistoryActions(bool canGoBack, bool canGoForward, bool canGoUp)
{
    m_actBack->setEnabled(canGoBack);
    m_actForward->setEnabled(canGoForward);
    m_actUp->setEnabled(canGoUp);
}
