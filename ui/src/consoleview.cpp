// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "consoleview.h"

#include "propertysheet.h"
#include "../backend/SampleData.h"

#include <QAbstractItemView>
#include <QDialog>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QMenu>
#include <QIODevice>
#include <QItemSelectionModel>
#include <QListView>
#include <QSet>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStringConverter>
#include <QTableView>
#include <QTextStream>
#include <QTreeView>
#include <QVBoxLayout>


ConsoleView::ConsoleView(QWidget *parent)
    : QWidget(parent)
{
    m_splitter = new QSplitter(Qt::Horizontal, this);
    m_splitter->setChildrenCollapsible(false);

    createTreePane();
    createResultsPane();

    m_splitter->addWidget(m_consoleTree);
    m_splitter->addWidget(m_resultsStack);
    m_splitter->setStretchFactor(0, 0);
    m_splitter->setStretchFactor(1, 1);
    m_splitter->setSizes({240, 660});

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_splitter);

    populateSampleData();
    applyViewMode(Details);
    navigateTo(QStringLiteral("Console Root"));
}

ConsoleView::~ConsoleView() = default;

void ConsoleView::createTreePane()
{
    m_treeModel = new QStandardItemModel(this);

    auto *root = new QStandardItem(objectIcon(ObjectKind::Domain), tr("Console Root"));
    root->setEditable(false);
    root->setData(QStringLiteral("Console Root"), Qt::UserRole);
    root->setToolTip(tr("Root of the console tree"));
    m_treeModel->appendRow(root);

    auto addContainer = [root](const QString &name, const QString &key) {
        auto *item = new QStandardItem(objectIcon(ObjectKind::Container), name);
        item->setEditable(false);
        item->setData(key, Qt::UserRole);
        item->setToolTip(name);
        root->appendRow(item);
    };

    addContainer(tr("Users"), QStringLiteral("Users"));
    addContainer(tr("Groups"), QStringLiteral("Groups"));
    addContainer(tr("Computers"), QStringLiteral("Computers"));
    addContainer(tr("Domain Controllers"), QStringLiteral("Domain Controllers"));

    m_consoleTree = new QTreeView(this);
    m_consoleTree->setObjectName(QStringLiteral("consoleTree"));
    m_consoleTree->setModel(m_treeModel);
    m_consoleTree->setHeaderHidden(true);
    m_consoleTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_consoleTree->setAnimated(true);
    m_consoleTree->setIndentation(16);
    m_consoleTree->setUniformRowHeights(true);
    m_consoleTree->setMinimumWidth(160);
    m_consoleTree->expandAll();

    connect(m_consoleTree->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &ConsoleView::onTreeSelectionChanged);

    m_consoleTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_consoleTree, &QWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        const QModelIndex index = m_consoleTree->indexAt(pos);
        if (index.isValid())
            m_consoleTree->setCurrentIndex(index);

        QMenu menu;
        QAction *propertiesAction = menu.addAction(tr("Properties"));
        propertiesAction->setEnabled(hasSingleSelection());
        QAction *refreshAction = menu.addAction(tr("Refresh"));
        menu.addSeparator();
        QAction *chosen = menu.exec(m_consoleTree->viewport()->mapToGlobal(pos));
        if (chosen == propertiesAction)
            showPropertiesForSelection();
        else if (chosen == refreshAction)
            refresh();
    });
}

void ConsoleView::createResultsPane()
{
    m_resultsModel = new ResultsModel(this);
    m_resultsStack = new QStackedWidget(this);

    m_detailsView = new QTableView(m_resultsStack);
    m_detailsView->setObjectName(QStringLiteral("detailsView"));
    m_detailsView->setModel(m_resultsModel);
    m_detailsView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_detailsView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_detailsView->setAlternatingRowColors(true);
    m_detailsView->setShowGrid(true);
    m_detailsView->setWordWrap(false);
    m_detailsView->verticalHeader()->setVisible(false);
    m_detailsView->horizontalHeader()->setStretchLastSection(true);
    m_detailsView->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_detailsView->horizontalHeader(), &QWidget::customContextMenuRequested,
            this, [this](const QPoint &pos) {
                QMenu menu;
                for (int col = 0; col < ResultsModel::ColumnCount; ++col) {
                    QAction *action = menu.addAction(m_resultsModel->headerData(col, Qt::Horizontal).toString());
                    action->setCheckable(true);
                    action->setChecked(!m_detailsView->isColumnHidden(col));
                    connect(action, &QAction::toggled, this, [this, col](bool visible) {
                        m_detailsView->setColumnHidden(col, !visible);
                    });
                }
                menu.exec(m_detailsView->horizontalHeader()->mapToGlobal(pos));
            });
    m_detailsView->horizontalHeader()->setSectionResizeMode(ResultsModel::NameColumn,
                                                           QHeaderView::Interactive);
    m_detailsView->setColumnWidth(ResultsModel::NameColumn, 220);
    m_detailsView->setColumnWidth(ResultsModel::TypeColumn, 150);
    m_detailsView->setSortingEnabled(true);
    m_detailsView->sortByColumn(ResultsModel::NameColumn, Qt::AscendingOrder);

    m_iconView = new QListView(m_resultsStack);
    m_iconView->setObjectName(QStringLiteral("iconView"));
    m_iconView->setModel(m_resultsModel);
    m_iconView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_iconView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_iconView->setWordWrap(true);
    m_iconView->setTextElideMode(Qt::ElideRight);
    m_iconView->setSpacing(4);

    m_resultsStack->addWidget(m_detailsView);
    m_resultsStack->addWidget(m_iconView);
    m_resultsStack->setCurrentWidget(m_detailsView);

    connect(m_detailsView, &QTableView::activated,
            this, &ConsoleView::onResultsActivated);
    connect(m_iconView, &QListView::activated,
            this, &ConsoleView::onResultsActivated);
    connect(m_detailsView->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &ConsoleView::updateSelectionState);
    connect(m_iconView->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &ConsoleView::updateSelectionState);

    auto showResultsContextMenu = [this](QAbstractItemView *view, const QPoint &pos) {
        const QModelIndex index = view->indexAt(pos);
        if (index.isValid())
            view->setCurrentIndex(index);

        QMenu menu;
        QAction *propertiesAction = menu.addAction(tr("Properties"));
        propertiesAction->setEnabled(hasSingleSelection());
        QAction *deleteAction = menu.addAction(tr("Delete"));
        deleteAction->setEnabled(hasSingleSelection());
        menu.addSeparator();
        QAction *exportAction = menu.addAction(tr("Export List..."));
        QAction *refreshAction = menu.addAction(tr("Refresh"));

        QAction *chosen = menu.exec(view->viewport()->mapToGlobal(pos));
        if (chosen == propertiesAction)
            showPropertiesForSelection();
        else if (chosen == deleteAction)
            deleteCurrentObject();
        else if (chosen == refreshAction)
            refresh();
        else if (chosen == exportAction) {
            // Export via a temp file prompt is handled by main window; here just emit status.
            emit statusMessage(tr("Use File menu to export the list."));
        }
    };

    m_detailsView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_detailsView, &QWidget::customContextMenuRequested, this,
            [showResultsContextMenu, this](const QPoint &pos) {
                showResultsContextMenu(m_detailsView, pos);
            });

    m_iconView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_iconView, &QWidget::customContextMenuRequested, this,
            [showResultsContextMenu, this](const QPoint &pos) {
                showResultsContextMenu(m_iconView, pos);
            });
}

void ConsoleView::populateSampleData()
{
    m_resultsModel->setObjects(sampleObjects());
}

void ConsoleView::setViewMode(ViewMode mode)
{
    if (m_viewMode == mode) {
        applyViewMode(mode);
        return;
    }

    const QStringList selected = selectedObjectIds();
    m_viewMode = mode;
    applyViewMode(mode);
    restoreSelection(selected);
}

void ConsoleView::applyViewMode(ViewMode mode)
{
    switch (mode) {
    case Details:
        m_resultsStack->setCurrentWidget(m_detailsView);
        break;
    case LargeIcons:
        m_iconView->setViewMode(QListView::IconMode);
        m_iconView->setFlow(QListView::LeftToRight);
        m_iconView->setWrapping(true);
        m_iconView->setResizeMode(QListView::Adjust);
        m_iconView->setIconSize(QSize(32, 32));
        m_iconView->setGridSize(QSize(104, 78));
        m_iconView->setUniformItemSizes(true);
        m_iconView->setWordWrap(true);
        m_iconView->setSpacing(6);
        m_resultsStack->setCurrentWidget(m_iconView);
        break;
    case SmallIcons:
        m_iconView->setViewMode(QListView::ListMode);
        m_iconView->setFlow(QListView::LeftToRight);
        m_iconView->setWrapping(true);
        m_iconView->setResizeMode(QListView::Adjust);
        m_iconView->setIconSize(QSize(16, 16));
        m_iconView->setGridSize(QSize(160, 22));
        m_iconView->setUniformItemSizes(true);
        m_iconView->setWordWrap(false);
        m_iconView->setSpacing(2);
        m_resultsStack->setCurrentWidget(m_iconView);
        break;
    case List:
        m_iconView->setViewMode(QListView::ListMode);
        m_iconView->setFlow(QListView::TopToBottom);
        m_iconView->setWrapping(false);
        m_iconView->setIconSize(QSize(16, 16));
        m_iconView->setGridSize(QSize());
        m_iconView->setUniformItemSizes(false);
        m_iconView->setWordWrap(false);
        m_iconView->setSpacing(2);
        m_resultsStack->setCurrentWidget(m_iconView);
        break;
    }

    updateSelectionState();
}

void ConsoleView::navigateTo(const QString &containerKey)
{
    showContainer(containerKey, true);
}

void ConsoleView::showContainer(const QString &containerKey, bool record)
{
    const QModelIndex index = findTreeIndex(containerKey);
    if (!index.isValid())
        return;

    if (m_consoleTree->currentIndex() != index) {
        m_navigating = true;
        m_consoleTree->setCurrentIndex(index);
        m_navigating = false;
    }
    m_consoleTree->scrollTo(index);

    applyContainer(containerKey);
    if (record)
        recordHistory(containerKey);
    else
        emitHistoryState();
}

void ConsoleView::applyContainer(const QString &containerKey)
{
    m_resultsModel->setContainer(containerKey);
    emit containerChanged(containerKey);
    updateStatus();
    updateSelectionState();
}

void ConsoleView::onTreeSelectionChanged()
{
    if (m_navigating)
        return;

    const QModelIndex index = m_consoleTree->currentIndex();
    const QString key = index.data(Qt::UserRole).toString();
    if (key.isEmpty())
        return;

    applyContainer(key);
    recordHistory(key);
}

void ConsoleView::recordHistory(const QString &containerKey)
{
    if (m_historyIndex >= 0 && m_historyIndex < m_history.size()
        && m_history.at(m_historyIndex) == containerKey) {
        emitHistoryState();
        return;
    }

    while (m_history.size() > m_historyIndex + 1)
        m_history.removeLast();

    m_history.append(containerKey);
    m_historyIndex = m_history.size() - 1;
    emitHistoryState();
}

void ConsoleView::emitHistoryState()
{
    emit historyChanged(canGoBack(), canGoForward(), canGoUp());
}

bool ConsoleView::canGoBack() const
{
    return m_historyIndex > 0;
}

bool ConsoleView::canGoForward() const
{
    return m_historyIndex >= 0 && m_historyIndex + 1 < m_history.size();
}

bool ConsoleView::canGoUp() const
{
    return m_resultsModel && m_resultsModel->container() != QLatin1String("Console Root");
}

void ConsoleView::goBack()
{
    if (!canGoBack())
        return;

    --m_historyIndex;
    showContainer(m_history.at(m_historyIndex), false);
}

void ConsoleView::goForward()
{
    if (!canGoForward())
        return;

    ++m_historyIndex;
    showContainer(m_history.at(m_historyIndex), false);
}

void ConsoleView::goUp()
{
    if (canGoUp())
        navigateTo(QStringLiteral("Console Root"));
}

QModelIndex ConsoleView::findTreeIndex(const QString &containerKey) const
{
    for (int row = 0; row < m_treeModel->rowCount(); ++row) {
        const QModelIndex top = m_treeModel->index(row, 0);
        if (top.data(Qt::UserRole).toString() == containerKey)
            return top;

        for (int child = 0; child < m_treeModel->rowCount(top); ++child) {
            const QModelIndex index = m_treeModel->index(child, 0, top);
            if (index.data(Qt::UserRole).toString() == containerKey)
                return index;
        }
    }
    return {};
}

void ConsoleView::setTreeVisible(bool visible)
{
    m_consoleTree->setVisible(visible);
}

bool ConsoleView::isTreeVisible() const
{
    return m_consoleTree->isVisible();
}

QAbstractItemView *ConsoleView::currentResultsView() const
{
    return qobject_cast<QAbstractItemView *>(m_resultsStack->currentWidget());
}

QList<QModelIndex> ConsoleView::selectedNameIndexes() const
{
    QList<QModelIndex> result;
    QAbstractItemView *view = currentResultsView();
    if (!view || !view->selectionModel())
        return result;

    QSet<int> seenRows;
    const QModelIndexList selected = view->selectionModel()->selectedIndexes();
    for (const QModelIndex &index : selected) {
        if (index.column() != ResultsModel::NameColumn || seenRows.contains(index.row()))
            continue;
        seenRows.insert(index.row());
        result.append(index);
    }
    return result;
}

QStringList ConsoleView::selectedObjectIds() const
{
    QStringList ids;
    for (const QModelIndex &index : selectedNameIndexes())
        ids.append(index.data(Qt::UserRole).toString());
    return ids;
}

void ConsoleView::restoreSelection(const QStringList &ids)
{
    if (ids.isEmpty())
        return;

    QAbstractItemView *view = currentResultsView();
    if (!view || !view->selectionModel())
        return;

    view->selectionModel()->clearSelection();

    QItemSelection selection;
    QModelIndex first;
    for (int row = 0; row < m_resultsModel->rowCount(); ++row) {
        const QModelIndex index = m_resultsModel->index(row, ResultsModel::NameColumn);
        if (!ids.contains(index.data(Qt::UserRole).toString()))
            continue;

        selection.select(index, index);
        if (!first.isValid())
            first = index;
    }

    if (!first.isValid())
        return;

    view->selectionModel()->select(selection,
                                   QItemSelectionModel::Select | QItemSelectionModel::Rows);
    view->setCurrentIndex(first);
    updateSelectionState();
}

bool ConsoleView::hasSelection() const
{
    return !selectedNameIndexes().isEmpty();
}

bool ConsoleView::hasSingleSelection() const
{
    return selectedNameIndexes().size() == 1;
}

DirectoryObject ConsoleView::currentObject() const
{
    QAbstractItemView *view = currentResultsView();
    if (!view || !view->selectionModel())
        return {};

    QModelIndex current = view->currentIndex();
    if (!current.isValid() || !view->selectionModel()->isSelected(current)) {
        const QList<QModelIndex> selected = selectedNameIndexes();
        if (selected.isEmpty())
            return {};
        current = selected.first();
    }

    return m_resultsModel->objectAt(current.row());
}

void ConsoleView::updateSelectionState()
{
    const int count = selectedNameIndexes().size();
    emit selectionStateChanged(count > 0, count == 1);
}

void ConsoleView::showPropertiesForSelection()
{
    if (!hasSingleSelection())
        return;

    const DirectoryObject original = currentObject();
    PropertySheet sheet(original, window());
    // Members are chosen from the objects this console knows about, so the
    // sheet can show names and hand back distinguished names.
    sheet.setMembershipCandidates(m_resultsModel->objects());
    if (sheet.exec() != QDialog::Accepted)
        return;

    const DirectoryObject updated = sheet.object();
    m_resultsModel->updateObject(updated);
    if (m_directoryService) {
        // Send only what actually changed; the property sheet holds a complete
        // snapshot of the object, and a blind replace would also touch
        // server-maintained attributes.
        QMap<QString, QString> changed;
        for (auto it = updated.attributes.constBegin(); it != updated.attributes.constEnd(); ++it) {
            if (original.attributes.value(it.key()) != it.value())
                changed.insert(it.key(), it.value());
        }
        if (updated.name != original.name)
            changed.insert(QStringLiteral("displayName"), updated.name);
        if (updated.description != original.description)
            changed.insert(QStringLiteral("description"), updated.description);
        if (!changed.isEmpty())
            m_directoryService->modifyObject(updated.id, changed);
    }
    // Membership is a linked pair of attributes: writing a group's `member`
    // list makes the server derive each member's `memberOf`.
    bool membershipChanged = false;
    if (m_adminService) {
        const bool isGroup = updated.kind == ObjectKind::Group;
        const QStringList before = isGroup ? original.members : original.memberOf;
        const QStringList after = isGroup ? updated.members : updated.memberOf;
        membershipChanged = before != after;
        for (const QString &dn : after) {
            if (before.contains(dn, Qt::CaseInsensitive))
                continue;
            if (isGroup)
                m_adminService->addMember(updated.id, dn);
            else
                m_adminService->addMember(dn, updated.id);
        }
        for (const QString &dn : before) {
            if (after.contains(dn, Qt::CaseInsensitive))
                continue;
            if (isGroup)
                m_adminService->removeMember(updated.id, dn);
            else
                m_adminService->removeMember(dn, updated.id);
        }
    }

    // Membership edits change the *other* objects too (a member gains or loses
    // this group in its memberOf), so reload from the directory afterwards.
    if (membershipChanged && m_directoryService)
        loadFromBackend();

    restoreSelection({updated.id});
    emit statusMessage(tr("Updated %1.").arg(updated.name));
}

void ConsoleView::deleteCurrentObject()
{
    if (!hasSingleSelection())
        return;

    const DirectoryObject object = currentObject();
    if (m_directoryService) {
        // Only drop the row once the directory confirms the delete, so the pane
        // never shows an object that is still on the server.
        QFuture<bool> future = m_directoryService->removeObject(object.id);
        auto *watcher = new QFutureWatcher<bool>(this);
        connect(watcher, &QFutureWatcher<bool>::finished, this,
                [this, watcher, object]() {
                    const bool removed = watcher->result();
                    watcher->deleteLater();
                    if (removed) {
                        m_resultsModel->removeObject(object.id);
                        updateStatus();
                        updateSelectionState();
                        emit statusMessage(tr("%1 deleted.").arg(object.name));
                    } else {
                        emit statusMessage(tr("Could not delete %1.").arg(object.name));
                    }
                });
        watcher->setFuture(future);
        return;
    }
    m_resultsModel->removeObject(object.id);
    updateStatus();
    updateSelectionState();
    emit statusMessage(tr("%1 deleted from this console.").arg(object.name));
}

void ConsoleView::addObject(const DirectoryObject &object)
{
    if (m_directoryService) {
        // A rejected create (for example a password that fails policy) must not
        // appear in the results pane, so wait for the server and re-query.
        QFuture<bool> future = m_directoryService->addObject(object);
        auto *watcher = new QFutureWatcher<bool>(this);
        connect(watcher, &QFutureWatcher<bool>::finished, this,
                [this, watcher, object]() {
                    const bool created = watcher->result();
                    watcher->deleteLater();
                    if (created) {
                        loadFromBackend();
                        restoreSelection({object.id});
                        emit statusMessage(tr("Created %1.").arg(object.name));
                    } else {
                        emit statusMessage(tr("Could not create %1.").arg(object.name));
                    }
                });
        watcher->setFuture(future);
        return;
    }
    m_resultsModel->addObject(object);
    updateStatus();
    updateSelectionState();
}

void ConsoleView::refresh()
{
    // Requery the connected directory; fall back to seed data when standalone.
    if (m_directoryService) {
        loadFromBackend();
        return;
    }
    m_resultsModel->setObjects(sampleObjects());
    updateSelectionState();
    updateStatus();
    emit statusMessage(tr("%1: %n object(s) refreshed.", nullptr,
                          m_resultsModel->objectCount())
                           .arg(m_resultsModel->container()));
}

void ConsoleView::setDirectoryService(DirectoryService *service)
{
    m_directoryService = service;
}

void ConsoleView::setAdminService(AdminService *service)
{
    m_adminService = service;
}

void ConsoleView::setConnectionService(ConnectionService *service)
{
    m_connectionService = service;
    if (service) {
        connect(service, &ConnectionService::connectedChanged, this, [this](bool connected) {
            if (connected)
                loadFromBackend();
            else
                populateSampleData();
        });
    }
}

void ConsoleView::loadFromBackend()
{
    if (!m_directoryService)
        return;

    auto *watcher = new QFutureWatcher<QList<DirectoryObject>>(this);
    connect(watcher, &QFutureWatcher<QList<DirectoryObject>>::finished, this, [this, watcher]() {
        const QList<DirectoryObject> objects = watcher->result();
        // An empty result is valid for an empty container; only keep the
        // seed data when the search could not reach a directory at all.
        if (!objects.isEmpty() || (m_connectionService && m_connectionService->isConnected()))
            m_resultsModel->setObjects(objects);
        updateStatus();
        updateSelectionState();
        watcher->deleteLater();
    });
    // Empty base lets DirectoryService use the connected profile's base DN.
    watcher->setFuture(m_directoryService->search(QString(),
                                                 QStringLiteral("(objectClass=*)"),
                                                 QStringList(), 1000));
}

void ConsoleView::setFilterText(const QString &text)
{
    m_resultsModel->setFilterText(text);
    updateStatus();
    updateSelectionState();
}

QString ConsoleView::filterText() const
{
    return m_resultsModel->filterText();
}

void ConsoleView::updateStatus()
{
    const int count = m_resultsModel->objectCount();
    emit statusMessage(tr("%1: %n object(s)", nullptr, count)
                           .arg(m_resultsModel->container()));
}

void ConsoleView::onResultsActivated(const QModelIndex &index)
{
    Q_UNUSED(index)
    if (hasSingleSelection())
        showPropertiesForSelection();
}

bool ConsoleView::exportResults(QIODevice *device) const
{
    if (!device || !device->isOpen())
        return false;

    QTextStream stream(device);
    stream.setEncoding(QStringConverter::Utf8);

    auto quote = [](QString value) {
        value.replace(QLatin1Char('"'), QLatin1String("\"\""));
        value.replace(QLatin1Char('\n'), QLatin1Char(' '));
        value.replace(QLatin1Char('\r'), QLatin1Char(' '));
        return QStringLiteral("\"") + value + QStringLiteral("\"");
    };

    stream << QStringLiteral("Name,Type,Description\n");
    for (int row = 0; row < m_resultsModel->objectCount(); ++row) {
        const DirectoryObject object = m_resultsModel->objectAt(row);
        stream << quote(object.name) << ','
               << quote(object.type) << ','
               << quote(object.description) << '\n';
    }
    stream.flush();

    return stream.status() == QTextStream::Ok;
}
