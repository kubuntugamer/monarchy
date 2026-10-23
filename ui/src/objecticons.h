// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef OBJECTICONS_H
#define OBJECTICONS_H

#include <QIcon>

// Object kinds shown by the console tree and results pane.
enum class ObjectKind {
    User,
    Group,
    Computer,
    Ou,
    Domain,
    Container,
    Unknown
};

// Returns an independently drawn, MMC-style icon for the given object kind.
// The artwork is generated at runtime, so no third-party icon assets are
// required and the same icon is available at every size.
QIcon objectIcon(ObjectKind kind);

#endif // OBJECTICONS_H
