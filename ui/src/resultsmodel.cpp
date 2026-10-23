// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "resultsmodel.h"

#include <algorithm>

ResultsModel::ResultsModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int ResultsModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_visibleRows.size();
}

int ResultsModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ResultsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_visibleRows.size())
        return {};

    const DirectoryObject &object = m_objects.at(m_visibleRows.at(index.row()));

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case NameColumn:
            return object.name;
        case TypeColumn:
            return object.type;
        case DescriptionColumn:
            return object.description;
        default:
            return {};
        }
    case Qt::DecorationRole:
        if (index.column() == NameColumn)
            return objectIcon(object.kind);
        return {};
    case Qt::ToolTipRole:
        if (object.description.isEmpty())
            return object.id;
        return object.description + QLatin1Char('\n') + object.id;
    case Qt::UserRole:
        return object.id;
    default:
        return {};
    }
}

QVariant ResultsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};

    switch (section) {
    case NameColumn:
        return tr("Name");
    case TypeColumn:
        return tr("Type");
    case DescriptionColumn:
        return tr("Description");
    default:
        return {};
    }
}

void ResultsModel::sort(int column, Qt::SortOrder order)
{
    if (column < 0 || column >= ColumnCount)
        return;

    m_sortColumn = column;
    m_sortOrder = order;
    beginResetModel();
    rebuildVisibleRows();
    endResetModel();
}

void ResultsModel::setObjects(const QList<DirectoryObject> &objects)
{
    beginResetModel();
    m_objects = objects;
    rebuildVisibleRows();
    endResetModel();
}

void ResultsModel::addObject(const DirectoryObject &object)
{
    beginResetModel();
    m_objects.append(object);
    rebuildVisibleRows();
    endResetModel();
}

void ResultsModel::setContainer(const QString &container)
{
    if (m_container == container)
        return;

    beginResetModel();
    m_container = container;
    rebuildVisibleRows();
    endResetModel();
}

void ResultsModel::setFilterText(const QString &text)
{
    if (m_filterText == text)
        return;

    beginResetModel();
    m_filterText = text;
    rebuildVisibleRows();
    endResetModel();
}

void ResultsModel::updateObject(const DirectoryObject &object)
{
    for (int i = 0; i < m_objects.size(); ++i) {
        if (m_objects.at(i).id != object.id)
            continue;

        beginResetModel();
        m_objects[i] = object;
        rebuildVisibleRows();
        endResetModel();
        return;
    }
}

void ResultsModel::removeObject(const QString &id)
{
    for (int i = 0; i < m_objects.size(); ++i) {
        if (m_objects.at(i).id != id)
            continue;

        beginResetModel();
        m_objects.removeAt(i);
        rebuildVisibleRows();
        endResetModel();
        return;
    }
}

DirectoryObject ResultsModel::objectAt(int row) const
{
    if (row < 0 || row >= m_visibleRows.size())
        return {};
    return m_objects.value(m_visibleRows.at(row));
}

bool ResultsModel::isVisible(const DirectoryObject &object) const
{
    if (!m_container.isEmpty() && m_container != QLatin1String("Console Root")) {
        if (m_container == QLatin1String("Domain Controllers")) {
            if (object.attributes.value(QStringLiteral("isDomainController")) != QLatin1String("yes"))
                return false;
        } else if (object.container.compare(m_container, Qt::CaseInsensitive) != 0) {
            return false;
        }
    }

    if (!m_filterText.isEmpty()) {
        const QString needle = m_filterText.toLower();
        if (!object.name.toLower().contains(needle)
            && !object.type.toLower().contains(needle)
            && !object.description.toLower().contains(needle)) {
            return false;
        }
    }

    return true;
}

void ResultsModel::rebuildVisibleRows()
{
    m_visibleRows.clear();
    for (int i = 0; i < m_objects.size(); ++i) {
        if (isVisible(m_objects.at(i)))
            m_visibleRows.append(i);
    }

    std::stable_sort(m_visibleRows.begin(), m_visibleRows.end(), [this](int a, int b) {
        const QString left = valueAt(a, m_sortColumn);
        const QString right = valueAt(b, m_sortColumn);
        int result = QString::compare(left, right, Qt::CaseInsensitive);
        if (result == 0)
            result = QString::compare(m_objects.at(a).name, m_objects.at(b).name, Qt::CaseInsensitive);
        return m_sortOrder == Qt::AscendingOrder ? result < 0 : result > 0;
    });
}

QString ResultsModel::valueAt(int sourceRow, int column) const
{
    const DirectoryObject &object = m_objects.at(sourceRow);
    switch (column) {
    case NameColumn:
        return object.name;
    case TypeColumn:
        return object.type;
    case DescriptionColumn:
        return object.description;
    default:
        return {};
    }
}
