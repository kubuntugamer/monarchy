// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef CONSOLEVIEW_H
#define CONSOLEVIEW_H

#include "resultsmodel.h"

#include "AdminService.h"
#include "DirectoryService.h"
#include "ConnectionService.h"

#include <QWidget>

class QAbstractItemView;
class QIODevice;
class QListView;
class QSplitter;
class QStackedWidget;
class QStandardItemModel;
class QTableView;
class QTreeView;

// Tree + results pane splitter, the central surface of the MMC console.
class ConsoleView : public QWidget
{
    Q_OBJECT

public:
    enum ViewMode {
        LargeIcons,
        SmallIcons,
        List,
        Details
    };

    explicit ConsoleView(QWidget *parent = nullptr);
    ~ConsoleView() override;

    void setViewMode(ViewMode mode);
    ViewMode viewMode() const { return m_viewMode; }

    void navigateTo(const QString &containerKey);
    void goBack();
    void goForward();
    void goUp();
    bool canGoBack() const;
    bool canGoForward() const;
    bool canGoUp() const;

    void setTreeVisible(bool visible);
    bool isTreeVisible() const;

    bool hasSelection() const;
    bool hasSingleSelection() const;
    DirectoryObject currentObject() const;
    void updateSelectionState();

    void showPropertiesForSelection();
    void deleteCurrentObject();
    void refresh();
    bool exportResults(QIODevice *device) const;

    void setDirectoryService(DirectoryService *service);
    void setConnectionService(ConnectionService *service);
    void setAdminService(AdminService *service);
    void loadFromBackend();

    void addObject(const DirectoryObject &object);

    void setFilterText(const QString &text);
    QString filterText() const;

    QString currentContainer() const { return m_resultsModel->container(); }
    ResultsModel *resultsModel() const { return m_resultsModel; }
    QAbstractItemView *currentResultsView() const;
    QList<QModelIndex> selectedNameIndexes() const;

signals:
    void statusMessage(const QString &message);
    void containerChanged(const QString &containerName);
    void selectionStateChanged(bool hasSelection, bool singleSelection);
    void historyChanged(bool canGoBack, bool canGoForward, bool canGoUp);

private:
    void createTreePane();
    void createResultsPane();
    void populateSampleData();
    void applyViewMode(ViewMode mode);

    void onTreeSelectionChanged();
    void onResultsActivated(const QModelIndex &index);

    void showContainer(const QString &containerKey, bool recordHistory);
    void applyContainer(const QString &containerKey);
    void recordHistory(const QString &containerKey);
    void emitHistoryState();
    void updateStatus();

    QModelIndex findTreeIndex(const QString &containerKey) const;
    QStringList selectedObjectIds() const;
    void restoreSelection(const QStringList &ids);

    QSplitter *m_splitter = nullptr;
    QTreeView *m_consoleTree = nullptr;
    QStandardItemModel *m_treeModel = nullptr;
    QStackedWidget *m_resultsStack = nullptr;
    QTableView *m_detailsView = nullptr;
    QListView *m_iconView = nullptr;
    ResultsModel *m_resultsModel = nullptr;
    DirectoryService *m_directoryService = nullptr;
    ConnectionService *m_connectionService = nullptr;
    AdminService *m_adminService = nullptr;
    ViewMode m_viewMode = Details;

    QStringList m_history;
    int m_historyIndex = -1;
    bool m_navigating = false;
};

#endif // CONSOLEVIEW_H
