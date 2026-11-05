// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "WorkstationRestriction.h"

#include <QStringList>

namespace WorkstationRestriction {

bool allows(const QString &list, const QString &workstation)
{
    if (list.trimmed().isEmpty())
        return true;
    const QString name = workstation.trimmed();
    // A restricted account logging on from a workstation the caller did not
    // name cannot be shown to be on the list, so it is refused rather than
    // waved through.
    if (name.isEmpty())
        return false;
    for (const QString &entry : list.split(QLatin1Char(','))) {
        const QString candidate = entry.trimmed();
        if (candidate.isEmpty())
            continue;
        if (candidate.compare(name, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

} // namespace WorkstationRestriction
