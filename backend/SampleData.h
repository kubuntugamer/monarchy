// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SAMPLEDATA_H
#define SAMPLEDATA_H

#include "resultsmodel.h"

#include <QList>

// Sample directory objects used by the UI when no live backend is connected
// and by tests. Mirrors the classic ADUC demo data.
QList<DirectoryObject> sampleObjects();

#endif // SAMPLEDATA_H