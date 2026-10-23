# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

project(Monarchy VERSION 0.1.0 LANGUAGES CXX)

option(MONARCHY_WITH_LDAP "Build with the system OpenLDAP client backend" OFF)
option(MONARCHY_WITH_SAMBA "Reserved for a future Samba-backed engine" OFF)

include(CTest)

add_subdirectory(ui)
