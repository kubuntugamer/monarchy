#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Provision a Monarchy domain from Monarchy's own source tree.
#
# Nothing is installed: the provisioner is built from this repository and
# writes a self-contained domain store that Monarchy's LDAP engine serves.
#
# Usage:
#   scripts/provision-monarchy.sh [options] [target-dir]
#
# Options are passed straight through to monarchy-provision (--realm, --domain,
# --adminpass, --force, --help). Run `scripts/provision-monarchy.sh --help` for
# the full list.
#
# Environment:
#   MONARCHY_PROVISION_BIN  Path to an already-built monarchy-provision binary.
#   MONARCHY_BUILD_DIR      Build directory to search. Default: ./build
#   MONARCHY_DC_DIR         Target directory.
#                         Default: ${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy
#                         (the directory the admin console reads).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${MONARCHY_BUILD_DIR:-$ROOT/build}"
TARGETDIR="${MONARCHY_DC_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy}"
DEFAULT_PASS="P@ssw0rd123!"

die() {
    printf 'provision-monarchy: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/provision-monarchy.sh [options] [target-dir]

Provisions a Monarchy domain using Monarchy's own provisioner (no Samba).

Options (forwarded to monarchy-provision):
  --realm <realm>        Kerberos realm        (default: MONARCHY.EXAMPLE.COM)
  --domain <name>        NetBIOS domain        (default: first realm label)
  --adminpass <password> Administrator password
  --force                Overwrite an existing domain store
  -h, --help             Show this help

Environment:
  MONARCHY_PROVISION_BIN   Path to a built monarchy-provision binary
  MONARCHY_BUILD_DIR       Build directory to search (default: ./build)
  MONARCHY_DC_DIR          Target directory
                         (default: ${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy)
  MONARCHY_ADMINPASS       Administrator password (default: development-only value)
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

find_provisioner() {
    if [[ -n "${MONARCHY_PROVISION_BIN:-}" ]]; then
        [[ -x "$MONARCHY_PROVISION_BIN" ]] \
            || die "MONARCHY_PROVISION_BIN=$MONARCHY_PROVISION_BIN is not executable"
        printf '%s\n' "$MONARCHY_PROVISION_BIN"
        return
    fi
    # CMake puts it at the top level or under the ui/ subdirectory, depending
    # on how the project is organised.
    local candidate
    for candidate in "$BUILD_DIR/monarchy-provision" "$BUILD_DIR/ui/monarchy-provision"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    if [[ -d "$BUILD_DIR" ]]; then
        candidate="$(find "$BUILD_DIR" -maxdepth 3 -type f -name monarchy-provision -perm -u+x -print -quit 2>/dev/null || true)"
        if [[ -n "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    fi
    local on_path
    on_path="$(command -v monarchy-provision || true)"
    if [[ -n "$on_path" ]]; then
        printf '%s\n' "$on_path"
        return
    fi
    return 1
}

if ! PROVISIONER="$(find_provisioner)"; then
    die "monarchy-provision not found; build it first:
  cmake -S \"$ROOT\" -B \"$BUILD_DIR\"
  cmake --build \"$BUILD_DIR\" --target monarchy-provision"
fi

# Fill in the defaults the CLI would otherwise require, scanning properly so
# option *values* are never mistaken for a positional target directory.
args=("$@")
have_pass=false
have_target=false
have_positional=false
skip_next=false
for arg in "${args[@]}"; do
    if $skip_next; then
        skip_next=false
        continue
    fi
    case "$arg" in
        --adminpass) have_pass=true; skip_next=true ;;
        --adminpass=*) have_pass=true ;;
        --realm|--domain) skip_next=true ;;
        --targetdir) have_target=true; skip_next=true ;;
        --targetdir=*) have_target=true ;;
        -*) ;;
        *) have_positional=true ;;
    esac
done

if [[ "$have_pass" == false ]]; then
    args+=("--adminpass=${MONARCHY_ADMINPASS:-$DEFAULT_PASS}")
fi
if [[ "$have_target" == false && "$have_positional" == false ]]; then
    args+=("$TARGETDIR")
fi

exec "$PROVISIONER" "${args[@]}"
