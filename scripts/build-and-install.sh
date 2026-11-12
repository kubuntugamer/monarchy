#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and install Monarchy from this source tree, then (when run as root)
# provision and start the domain controller service.
#
#   sudo scripts/build-and-install.sh
#
# This is the short path for a tree that is already here: configure, build,
# test, install into PREFIX, and optionally create the first domain and start
# monarchy-dcd. The full promotion wizard with DNS/resolver setup lives in
# scripts/install-monarchy.sh — use that when you want the guided walkthrough
# or need port 53 freed from systemd-resolved.
#
# Defaults are chosen for a real DC:
#   PREFIX   /usr/local
#   DCDIR    /var/lib/monarchy/Monarchy
#   REALM    MONARCHY.EXAMPLE.COM
#   ADMINPASS prompted for interactively
#
# Run as a normal user and it installs under ~/.local with development ports
# and no systemd changes:
#
#   scripts/build-and-install.sh
#   ~/.local/bin/monarchy-ui
#
# Unattended example (root):
#
#   sudo scripts/build-and-install.sh --realm CORP.EXAMPLE.COM \
#       --adminpass 'Choose-A-Password!'
#
# Re-running is safe: an already-provisioned domain is left alone unless
# --force is given, and the service is restarted with whatever dc.conf says.

set -euo pipefail

ORIGINAL_ARGS=$#
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT}/build"
PREFIX=""
DCDIR=""
REALM="MONARCHY.EXAMPLE.COM"
ADMINPASS=""
JOBS=""
WITH_LDAP=0
RUN_TESTS=1
RUN_BUILD=1
PROVISION=1
FORCE=0
# Tri-state, resolved after the arguments are parsed: empty means the flag was
# not given, 0 means the caller asked for a binaries-only install, 1 means the
# caller asked for the service. Initialising it to 0 here used to make the root
# default unreachable, so a root run without --service installed into
# $HOME/.local and left the system service on its old binary.
SERVICE=
USER_MODE=0
SERVICE_USER="monarchy-dc"
REALM_GIVEN=0

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'build-and-install: %s\n' "$*" >&2; }
die()  { printf 'build-and-install: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: scripts/build-and-install.sh [options]

Builds Monarchy, runs its tests, installs it, and (when run as root)
provisions and starts the domain controller service. The guided promotion
wizard with DNS/resolver setup is scripts/install-monarchy.sh.

Build
  --build-dir DIR   Build tree (default: ./build)
  --jobs N          Parallel build jobs (default: all CPUs)
  --with-ldap       Build with the system OpenLDAP client backend
  --skip-build      Use an existing build tree instead of building
  --skip-tests      Do not run ctest

Install
  --prefix DIR      Install prefix (default: /usr/local as root,
                    ~/.local otherwise)
  --service         Install and start the monarchy-dcd systemd unit
                    (default when run as root)
  --no-service      Install binaries only; do not touch systemd. Under root
                    this is now distinguishable from the default, and the
                    summary says the service was left alone
  --user            Rootless install: ~/.local, development ports,
                    no systemd (default for a non-root run)

Domain
  --realm REALM       Kerberos realm (default: MONARCHY.EXAMPLE.COM)
  --adminpass PASS    Administrator password (prompted for when omitted;
                      required for unattended runs)
  --dcdir DIR         Domain store directory (default: /var/lib/monarchy/
                      Monarchy as root, the user data directory otherwise)
  --dc-ip ADDRESS     Address published in the domain DNS zone
  --dc-host HOST      Domain controller hostname or FQDN
  --dev-ports         Provision unprivileged ports (default for --user)
  --native-ports      Provision the AD port set (default for the service)
  --no-provision      Install without creating a domain
  --force             Re-provision an existing domain store

  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)       PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*)     PREFIX="${1#*=}"; shift ;;
        --build-dir)    BUILD_DIR="${2:?--build-dir needs a directory}"; shift 2 ;;
        --build-dir=*)  BUILD_DIR="${1#*=}"; shift ;;
        --jobs|-j)      JOBS="${2:?--jobs needs a number}"; shift 2 ;;
        --with-ldap)    WITH_LDAP=1; shift ;;
        --skip-build)   RUN_BUILD=0; shift ;;
        --skip-tests)   RUN_TESTS=0; shift ;;
        --service)      SERVICE=1; shift ;;
        --no-service)   SERVICE=0; shift ;;
        --user)         SERVICE=0; USER_MODE=1; PREFIX="${PREFIX:-$HOME/.local}"; shift ;;
        --realm)        REALM="${2:?--realm needs a value}"; REALM_GIVEN=1; shift 2 ;;
        --realm=*)      REALM="${1#*=}"; REALM_GIVEN=1; shift ;;
        --adminpass)    ADMINPASS="${2:?--adminpass needs a value}"; shift 2 ;;
        --adminpass=*)  ADMINPASS="${1#*=}"; shift ;;
        --dcdir)        DCDIR="${2:?--dcdir needs a directory}"; shift 2 ;;
        --dcdir=*)      DCDIR="${1#*=}"; shift ;;
        --dc-ip)        DC_IP="${2:?--dc-ip needs an address}"; shift 2 ;;
        --dc-ip=*)      DC_IP="${1#*=}"; shift ;;
        --dc-host)      DC_HOST="${2:?--dc-host needs a hostname}"; shift 2 ;;
        --dc-host=*)    DC_HOST="${1#*=}"; shift ;;
        --dev-ports)    DEV_PORTS=1; shift ;;
        --native-ports) DEV_PORTS=0; shift ;;
        --no-provision) PROVISION=0; shift ;;
        --force)        FORCE=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown option: $1 (see --help)" ;;
    esac
done

if [[ -z "$SERVICE" ]]; then
    if [[ $EUID -eq 0 && $USER_MODE -eq 0 ]]; then
        SERVICE=1
    else
        SERVICE=0
    fi
fi

if [[ $SERVICE -eq 1 ]]; then
    [[ $EUID -eq 0 ]] || die "a system service install needs root; rerun with sudo or use --user"
    PREFIX="${PREFIX:-/usr/local}"
    DCDIR="${DCDIR:-/var/lib/monarchy/Monarchy}"
    DEV_PORTS="${DEV_PORTS:-0}"
else
    PREFIX="${PREFIX:-$HOME/.local}"
    if [[ $USER_MODE -eq 0 && $EUID -eq 0 ]]; then
        DCDIR="${DCDIR:-/var/lib/monarchy/Monarchy}"
    else
        DCDIR="${DCDIR:-${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy}"
    fi
    DEV_PORTS="${DEV_PORTS:-1}"
fi

PREFIX="$(realpath -m "$PREFIX")"
DCDIR="$(realpath -m "$DCDIR")"

if [[ -z "$JOBS" ]]; then
    JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
fi

# --- dependencies -----------------------------------------------------------

check_dependencies() {
    local missing=0
    for tool in cmake; do
        command -v "$tool" >/dev/null 2>&1 || missing=1
    done
    if ! command -v c++ >/dev/null 2>&1 \
        && ! command -v g++ >/dev/null 2>&1 \
        && ! command -v clang++ >/dev/null 2>&1; then
        missing=1
    fi
    if [[ $missing -eq 1 ]]; then
        cat >&2 <<EOF

Monarchy needs CMake 3.16+, a C++17 compiler and Qt 6.5+. Install them with:

  sudo apt-get install build-essential cmake qt6-base-dev openssl

and then re-run this script.
EOF
        die "build dependencies are missing"
    fi

    local version
    version="$(cmake --version | head -n1 | awk '{print $3}')"
    if ! printf '3.16\n%s\n' "$version" | sort -V -C; then
        die "CMake 3.16 or newer is required (found $version)"
    fi
}

# --- build ------------------------------------------------------------------

configure_and_build() {
    if [[ $RUN_BUILD -eq 0 ]]; then
        [[ -f "$BUILD_DIR/CMakeCache.txt" ]] \
            || die "--skip-build given but $BUILD_DIR is not a configured build tree"
        log "Using existing build tree $BUILD_DIR"
        return
    fi

    log "Configuring in $BUILD_DIR"
    local args=(-S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release)
    args+=("-DCMAKE_INSTALL_PREFIX=$PREFIX")
    [[ $WITH_LDAP -eq 1 ]] && args+=(-DMONARCHY_WITH_LDAP=ON)
    if ! cmake "${args[@]}"; then
        cat >&2 <<EOF

CMake configuration failed. Install the dependencies and re-run:

  sudo apt-get install build-essential cmake qt6-base-dev openssl

with --with-ldap if you want the system OpenLDAP client backend.
EOF
        die "CMake configuration failed"
    fi

    log "Building with $JOBS jobs"
    cmake --build "$BUILD_DIR" --target monarchy-ui monarchy-dcd monarchy-provision --parallel "$JOBS"
}

run_tests() {
    [[ $RUN_TESTS -eq 1 ]] || { log "Skipping tests"; return 0; }
    log "Running the test suite"
    ctest --test-dir "$BUILD_DIR" --output-on-failure
}

# --- install ----------------------------------------------------------------

install_binaries() {
    log "Installing into $PREFIX"
    cmake --install "$BUILD_DIR" --prefix "$PREFIX"
}

install_service_unit() {
    getent group "$SERVICE_USER" >/dev/null 2>&1 \
        || groupadd --system "$SERVICE_USER"
    getent passwd "$SERVICE_USER" >/dev/null 2>&1 \
        || useradd --system --gid "$SERVICE_USER" \
                   --home-dir /var/lib/monarchy --shell /usr/sbin/nologin \
                   "$SERVICE_USER"

    mkdir -p "$DCDIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$DCDIR"
    chmod 0750 "$DCDIR"

    local protect_home=true
    if [[ "$PREFIX" == /home/* || "$DCDIR" == /home/* ]]; then
        protect_home=false
    fi
    sed -e "s|/usr/local/bin/monarchy-dcd|$PREFIX/bin/monarchy-dcd|" \
        -e "s|--dcdir /var/lib/monarchy/Monarchy|--dcdir $DCDIR|" \
        -e "s|-/var/lib/monarchy/Monarchy|-$DCDIR|" \
        -e "s|ProtectHome=true|ProtectHome=$protect_home|" \
        "$ROOT/packaging/monarchy-dcd.service" \
        > /etc/systemd/system/monarchy-dcd.service
    chmod 0644 /etc/systemd/system/monarchy-dcd.service

    systemctl daemon-reload
    log "Installed /etc/systemd/system/monarchy-dcd.service"
}

# --- provisioning -----------------------------------------------------------

prompt_admin_password() {
    [[ -n "$ADMINPASS" ]] && return 0
    local first="" second=""
    while :; do
        printf 'Administrator password: ' >&2
        IFS= read -r -s first || die "input ended during setup"
        printf '\n' >&2
        if [[ -z "$first" ]]; then
            warn "a password is required; enter one or pass --adminpass"
            continue
        fi
        printf 'Confirm Administrator password: ' >&2
        IFS= read -r -s second || die "input ended during setup"
        printf '\n' >&2
        if [[ "$first" == "$second" ]]; then
            ADMINPASS="$first"
            return 0
        fi
        warn "passwords do not match; try again"
    done
}

provision_domain() {
    [[ $PROVISION -eq 1 ]] || { log "Skipping domain provisioning"; return 0; }

    if [[ -f "$DCDIR/dc.conf" && $FORCE -eq 0 ]]; then
        log "Domain already provisioned in $DCDIR (use --force to replace it)"
        return
    fi

    if [[ -z "$ADMINPASS" ]]; then
        if [[ -t 0 ]]; then
            prompt_admin_password
        else
            die "an Administrator password is required; pass --adminpass or run interactively"
        fi
    fi

    local provisioner="$PREFIX/bin/monarchy-provision"
    [[ -x "$provisioner" ]] || die "$provisioner was not installed"

    local args=(--realm "$REALM" --adminpass "$ADMINPASS" --targetdir "$DCDIR")
    [[ -n "${DC_IP:-}" ]] && args+=(--dc-ip "$DC_IP")
    [[ -n "${DC_HOST:-}" ]] && args+=(--dc-host "$DC_HOST")
    [[ ${DEV_PORTS:-0} -eq 1 ]] && args+=(--dev-ports)
    [[ $FORCE -eq 1 ]] && args+=(--force)

    log "Provisioning $REALM in $DCDIR"
    if [[ $SERVICE -eq 1 ]]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "$SERVICE_USER" -- "$provisioner" "${args[@]}"
        else
            su -s /bin/sh -c "$(printf '%q ' "$provisioner" "${args[@]}")" "$SERVICE_USER"
        fi
    else
        "$provisioner" "${args[@]}"
    fi
}

start_service() {
    [[ $SERVICE -eq 1 ]] || return 0
    if [[ ! -f "$DCDIR/dc.conf" ]]; then
        warn "no domain in $DCDIR; monarchy-dcd is installed but not started"
        warn "provision it, then: sudo systemctl enable --now monarchy-dcd"
        return
    fi
    log "Enabling and starting monarchy-dcd"
    systemctl enable monarchy-dcd.service
    systemctl restart monarchy-dcd.service
    sleep 1
    if systemctl is-active --quiet monarchy-dcd.service; then
        log "monarchy-dcd is running"
    else
        warn "monarchy-dcd did not stay running; inspect: journalctl -u monarchy-dcd -n 50"
    fi
}

# --- main -------------------------------------------------------------------

check_dependencies
configure_and_build
run_tests
install_binaries
[[ $SERVICE -eq 1 ]] && install_service_unit
provision_domain
start_service

cat <<EOF

Monarchy is installed.

  Prefix:  $PREFIX
  Domain:  $DCDIR
  Console: $PREFIX/bin/monarchy-ui
EOF

if [[ $SERVICE -eq 1 ]]; then
    cat <<EOF
  Service: systemctl status monarchy-dcd
           journalctl -u monarchy-dcd
  Log in:  Administrator@$REALM
  KRB5:    $DCDIR/krb5.conf
  Health:  sudo $ROOT/scripts/check-dc-health.sh "$DCDIR"
           (needs root: $SERVICE_USER owns the store)
EOF
else
    cat <<EOF
  Service: not installed (--no-service)
  Run:     $PREFIX/bin/monarchy-ui
  Daemon:  $PREFIX/bin/monarchy-dcd --dcdir "$DCDIR"
EOF
    # A root run that skips the service still installs binaries and prints
    # success, so say which binary is actually answering rather than leaving a
    # passing run to be read as "the daemon was upgraded".
    if [[ -f /etc/systemd/system/monarchy-dcd.service ]]; then
        warn "systemd was not touched: monarchy-dcd.service keeps its own ExecStart binary"
        warn "restart it separately if you meant to upgrade the running daemon"
    fi
fi
