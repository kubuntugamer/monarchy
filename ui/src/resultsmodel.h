// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef RESULTSMODEL_H
#define RESULTSMODEL_H

#include "objecticons.h"

#include <QAbstractTableModel>
#include <QList>
#include <QMap>
#include <QMetaType>
#include <QStringList>

// One directory object as displayed by the results pane.
struct DirectoryObject {
    QString id;          // Distinguished name, used as the stable identity.
    QString name;        // Display name.
    QString type;        // "User", "Security Group", "Computer", ...
    QString description;
    ObjectKind kind = ObjectKind::Unknown;
    QString container;   // Console-tree container this object belongs to.
    QMap<QString, QString> attributes;
    QStringList memberOf;
    QStringList members;
};

Q_DECLARE_METATYPE(DirectoryObject)

// Table model shared by all results-pane views (details, icons, list).
class ResultsModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        NameColumn = 0,
        TypeColumn,
        DescriptionColumn,
        ColumnCount
    };

    explicit ResultsModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    void setObjects(const QList<DirectoryObject> &objects);
    void addObject(const DirectoryObject &object);
    void setContainer(const QString &container);
    QString container() const { return m_container; }

    void setFilterText(const QString &text);
    QString filterText() const { return m_filterText; }

    void updateObject(const DirectoryObject &object);
    void removeObject(const QString &id);

    int objectCount() const { return m_visibleRows.size(); }
    DirectoryObject objectAt(int row) const;
    QList<DirectoryObject> objects() const { return m_objects; }

private:
    bool isVisible(const DirectoryObject &object) const;
    void rebuildVisibleRows();
    QString valueAt(int sourceRow, int column) const;

    QList<DirectoryObject> m_objects;
    QList<int> m_visibleRows;
    QString m_container = QStringLiteral("Console Root");
    QString m_filterText;
    int m_sortColumn = NameColumn;
    Qt::SortOrder m_sortOrder = Qt::AscendingOrder;
};

#endif // RESULTSMODEL_H
