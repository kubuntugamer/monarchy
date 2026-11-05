// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SMBPATHS_H
#define SMBPATHS_H

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

// Path handling shared by the SMB1 and SMB2 servers: both resolve names the
// same way inside a share, so a file reached over CIFS and over SMB2 is the
// same file with the same traversal rules.
namespace SmbPaths {

// A share path as the client sent it. `..` and absolute components are refused
// outright rather than normalised, so a name can never climb out of the share
// root.
inline bool safeRelativeName(const QString &raw, QString *relative)
{
    QString name = raw;
    while (name.startsWith(QLatin1Char('\\')) || name.startsWith(QLatin1Char('/')))
        name.remove(0, 1);
    while (name.endsWith(QLatin1Char('\\')) || name.endsWith(QLatin1Char('/')))
        name.chop(1);
    QStringList parts;
    for (const QString &part : name.split(QRegularExpression(QStringLiteral("[\\\\/]")),
                                         Qt::SkipEmptyParts)) {
        if (part == QLatin1String("."))
            continue;
        if (part == QLatin1String(".."))
            return false;
        parts.append(part);
    }
    *relative = parts.join(QLatin1Char('/'));
    return true;
}

// SMB paths are case-insensitive and the filesystem holding the share is not,
// so each component is matched case-insensitively when the exact name is not
// there. This is what makes `SYSTEM32` and `system32` the same directory on a
// DC whose SYSVOL lives on ext4.
inline QString resolveCaseInsensitive(const QString &root, const QString &relative)
{
    if (relative.isEmpty())
        return root;
    QString current = root;
    for (const QString &part : relative.split(QLatin1Char('/'), Qt::SkipEmptyParts)) {
        const QString exact = current + QLatin1Char('/') + part;
        if (QFileInfo::exists(exact)) {
            current = exact;
            continue;
        }
        if (!QFileInfo(current).isDir())
            return QString();
        const QStringList entries = QDir(current).entryList(QDir::AllEntries | QDir::NoDotAndDotDot,
                                                            QDir::NoSort);
        QString match;
        for (const QString &entry : entries) {
            if (entry.compare(part, Qt::CaseInsensitive) == 0) {
                match = entry;
                break;
            }
        }
        if (match.isEmpty())
            return QString();
        current += QLatin1Char('/') + match;
    }
    return current;
}

} // namespace SmbPaths

#endif // SMBPATHS_H
