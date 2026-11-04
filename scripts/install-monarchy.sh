#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build and install Monarchy in one step.
#
#   sudo scripts/install-monarchy.sh
#
# As root this builds and tests everything, installs the binaries under
# /usr/local, installs the monarchy-dcd systemd unit, provisions a domain
# under /var/lib/monarchy/Monarchy and starts the service. Run as a normal
# user instead and it installs under ~/.local and provisions a development
# domain on the unprivileged ports, without touching systemd:
#
#   scripts/install-monarchy.sh
#   ~/.local/bin/monarchy-ui
#
# Re-running is safe: an already-provisioned domain is left alone unless
# --force is given, and the service is restarted with whatever dc.conf says.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build"
PREFIX=""
DCDIR=""
REALM="MONARCHY.EXAMPLE.COM"
DOMAIN=""
ADMINPASS=""
DC_IP=""
JOBS=""
WITH_LDAP=0
RUN_TESTS=1
RUN_BUILD=1
PROVISION=1
DEV_PORTS=""
FORCE=0
INSTALL_DEPS=0
FIX_DNS53=0
SERVICE=""
USER_MODE=0
SERVICE_USER="monarchy-dc"
GENERATED_PASS=0

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'install-monarchy: %s\n' "$*" >&2; }
die()  { printf 'install-monarchy: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: scripts/install-monarchy.sh [options]

Builds Monarchy, runs its tests, installs it, and (when run as root)
provisions and starts the domain controller service.

Install location
  --prefix DIR        Install prefix (default: /usr/local as root,
                      ~/.local otherwise)
  --build-dir DIR     Build tree (default: ./build)
  --jobs N            Parallel build jobs (default: all CPUs)
  --with-ldap         Build with the system OpenLDAP client backend
  --install-deps      Install build dependencies with the system package
                      manager before configuring
  --skip-build        Use an existing build tree instead of building
  --skip-tests        Do not run ctest

Install mode
  --service           Install and start the monarchy-dcd systemd unit
                      (default when run as root)
  --no-service        Install binaries only; do not touch systemd
  --user              Rootless install: ~/.local, development ports,
                      no systemd (default for a non-root run)

Domain
  --realm REALM       Kerberos realm (default: MONARCHY.EXAMPLE.COM)
  --domain NAME       NetBIOS domain name (default: first realm label)
  --adminpass PASS    Administrator password (default: generated and
                      printed at the end)
  --dcdir DIR         Domain store directory (default: /var/lib/monarchy/
                      Monarchy as root, the user data directory otherwise)
  --dc-ip ADDRESS     Address published in the domain DNS zone
  --dev-ports         Provision unprivileged ports (default for --user)
  --native-ports      Provision the AD port set (default for the service)
  --fix-dns53         Disable systemd-resolved's port 53 stub listener
                      without asking (interactive runs are prompted)
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
        --install-deps) INSTALL_DEPS=1; shift ;;
        --skip-build)   RUN_BUILD=0; shift ;;
        --skip-tests)   RUN_TESTS=0; shift ;;
        --service)      SERVICE=1; shift ;;
        --no-service)   SERVICE=0; shift ;;
        --user)         SERVICE=0; USER_MODE=1; PREFIX="${PREFIX:-$HOME/.local}"; shift ;;
        --realm)        REALM="${2:?--realm needs a value}"; shift 2 ;;
        --realm=*)      REALM="${1#*=}"; shift ;;
        --domain)       DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
        --domain=*)     DOMAIN="${1#*=}"; shift ;;
        --adminpass)    ADMINPASS="${2:?--adminpass needs a value}"; shift 2 ;;
        --adminpass=*)  ADMINPASS="${1#*=}"; shift ;;
        --dcdir)        DCDIR="${2:?--dcdir needs a directory}"; shift 2 ;;
        --dcdir=*)      DCDIR="${1#*=}"; shift ;;
        --dc-ip)        DC_IP="${2:?--dc-ip needs an address}"; shift 2 ;;
        --dc-ip=*)      DC_IP="${1#*=}"; shift ;;
        --dev-ports)    DEV_PORTS=1; shift ;;
        --native-ports) DEV_PORTS=0; shift ;;
        --fix-dns53)    FIX_DNS53=1; shift ;;
        --no-provision) PROVISION=0; shift ;;
        --force)        FORCE=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown option: $1 (see --help)" ;;
    esac
done

if [[ $EUID -eq 0 && -z "$SERVICE" ]]; then
    SERVICE=1
elif [[ -z "$SERVICE" ]]; then
    SERVICE=0
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

# Absolute paths keep the systemd unit correct when the caller used a
# relative --prefix or --dcdir.
PREFIX="$(realpath -m "$PREFIX")"
DCDIR="$(realpath -m "$DCDIR")"

if [[ -z "$JOBS" ]]; then
    JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
fi

# --- dependencies -----------------------------------------------------------

package_hint() {
    cat >&2 <<EOF

Monarchy needs CMake 3.16+, a C++17 compiler and Qt 6.5+ (Widgets, Core, Gui,
PrintSupport, Concurrent, Network and Test). Install them with:

$(detect_packages_hint)
EOF
}

detect_packages_hint() {
    if command -v apt-get >/dev/null 2>&1; then
        printf '  sudo apt-get install build-essential cmake qt6-base-dev openssl\n'
        printf '  (optional LDAP backend: libldap2-dev libsasl2-dev)\n'
    elif command -v dnf >/dev/null 2>&1; then
        printf '  sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl\n'
        printf '  (optional LDAP backend: openldap-devel)\n'
    elif command -v pacman >/dev/null 2>&1; then
        printf '  sudo pacman -S cmake gcc qt6-base openssl\n'
        printf '  (optional LDAP backend: libldap)\n'
    elif command -v zypper >/dev/null 2>&1; then
        printf '  sudo zypper install cmake gcc-c++ qt6-base-devel openssl\n'
        printf '  (optional LDAP backend: openldap2-devel)\n'
    else
        printf '  Use your distribution'"'"'s package manager for cmake, a C++17\n'
        printf '  compiler and Qt 6.5+ development packages.\n'
    fi
}

as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        command -v sudo >/dev/null 2>&1 || die "sudo is required to install packages"
        sudo "$@"
    fi
}

install_dependencies() {
    log "Installing build dependencies"
    if command -v apt-get >/dev/null 2>&1; then
        local pkgs=(build-essential cmake qt6-base-dev openssl)
        [[ $WITH_LDAP -eq 1 ]] && pkgs+=(libldap2-dev libsasl2-dev)
        as_root apt-get update
        as_root apt-get install -y "${pkgs[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        local pkgs=(cmake gcc-c++ qt6-qtbase-devel openssl)
        [[ $WITH_LDAP -eq 1 ]] && pkgs+=(openldap-devel)
        as_root dnf install -y "${pkgs[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        local pkgs=(cmake gcc qt6-base openssl)
        [[ $WITH_LDAP -eq 1 ]] && pkgs+=(libldap)
        as_root pacman -S --needed --noconfirm "${pkgs[@]}"
    elif command -v zypper >/dev/null 2>&1; then
        local pkgs=(cmake gcc-c++ qt6-base-devel openssl)
        [[ $WITH_LDAP -eq 1 ]] && pkgs+=(openldap2-devel)
        as_root zypper install -y "${pkgs[@]}"
    else
        die "no supported package manager found; install CMake, a C++17 compiler and Qt 6.5+ manually"
    fi
}

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
        package_hint
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
        package_hint
        die "CMake configuration failed"
    fi

    log "Building with $JOBS jobs"
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
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

    # Own the domain store itself, never an arbitrary parent such as /srv.
    mkdir -p "$DCDIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$DCDIR"
    chmod 0750 "$DCDIR"

    # The unit in packaging/ assumes the default prefix and state directory;
    # rewrite those paths so --prefix and --dcdir still work. A store or
    # prefix under /home also has to lift ProtectHome, which would otherwise
    # hide the very files the service is meant to read.
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

# --- port 53 ----------------------------------------------------------------

port53_holders() {
    { ss -lunpH 'sport = :53' 2>/dev/null || true
      ss -ltnpH 'sport = :53' 2>/dev/null || true
    } | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u
}

port53_in_use() {
    ss -lunH 'sport = :53' 2>/dev/null | grep -q . && return 0
    ss -ltnH 'sport = :53' 2>/dev/null | grep -q . && return 0
    return 1
}

configure_resolved_stub_listener() {
    local dropin_dir=/etc/systemd/resolved.conf.d
    local dropin="$dropin_dir/10-monarchy.conf"

    log "Disabling the systemd-resolved DNS stub listener"
    install -d -m 0755 "$dropin_dir"
    cat > "$dropin" <<'EOF'
# Installed by scripts/install-monarchy.sh: the Monarchy domain controller
# serves DNS on port 53, so systemd-resolved must not hold the stub listener.
[Resolve]
DNSStubListener=no
EOF
    chmod 0644 "$dropin"

    # The stub file only names 127.0.0.53. Make the DC the host's resolver:
    # it answers the domain authoritatively and forwards/caches everything
    # else. The previous upstreams stay as fallback for the window before the
    # DC starts, and the DC itself forwards to them. A resolv.conf managed by
    # something other than systemd-resolved is left alone.
    if [[ -L /etc/resolv.conf ]]; then
        local target
        target="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
        if [[ "$target" == */stub-resolv.conf ]]; then
            local search_line="" options_line=""
            search_line="$(grep -E '^(search|domain)[[:space:]]' "$target" 2>/dev/null | head -n1 || true)"
            options_line="$(grep -E '^options[[:space:]]' "$target" 2>/dev/null | head -n1 || true)"
            [[ "$search_line" == "search ." ]] && search_line=""

            rm -f /etc/resolv.conf
            {
                echo "# Managed by Monarchy's installer: the domain controller is"
                echo "# the local caching/forwarding resolver."
                [[ -n "$search_line" ]] && echo "$search_line"
                [[ -n "$options_line" ]] && echo "$options_line"
                echo "nameserver 127.0.0.1"
                local added=0
                if [[ -r /run/systemd/resolve/resolv.conf ]]; then
                    while read -r key value _; do
                        [[ "$key" == "nameserver" && -n "$value" ]] || continue
                        [[ "$value" == 127.* || "$value" == "::1" ]] && continue
                        echo "nameserver $value"
                        added=$((added + 1))
                        [[ $added -ge 2 ]] && break
                    done < /run/systemd/resolve/resolv.conf
                fi
            } > /etc/resolv.conf
            chmod 0644 /etc/resolv.conf
            log "Pointed /etc/resolv.conf at the DC (with upstream fallbacks)"
        fi
    fi

    if ! systemctl restart systemd-resolved; then
        warn "could not restart systemd-resolved; port 53 may still be taken"
        return 1
    fi
    log "systemd-resolved no longer listens on port 53"
}

check_dns_port_conflict() {
    [[ $SERVICE -eq 1 && $DEV_PORTS -eq 0 ]] || return 0
    if ! command -v ss >/dev/null 2>&1; then
        warn "cannot check port 53 (ss not found); the DC's DNS endpoint may not bind"
        return 0
    fi
    port53_in_use || return 0

    local holders
    holders="$(port53_holders)"
    # A previous run of our own service holding 53 is not a conflict.
    if [[ -n "$holders" ]] && ! grep -qvx 'monarchy-dcd' <<<"$holders"; then
        return 0
    fi
    if ! systemctl is-active --quiet systemd-resolved; then
        warn "port 53 is already in use${holders:+ (${holders//$'\n'/, })}; Monarchy's DNS endpoint will not bind"
        return 0
    fi
    if [[ -n "$holders" ]] && ! grep -qx 'systemd-resolve' <<<"$holders"; then
        warn "port 53 is held by ${holders//$'\n'/, }, not systemd-resolved; leaving it alone"
        return 0
    fi

    if [[ $FIX_DNS53 -eq 0 ]]; then
        if [[ -t 0 ]]; then
            printf 'Port 53 is used by systemd-resolved. Disable its stub listener so Monarchy can serve DNS? [y/N] '
            local reply=""
            read -r reply || true
            if [[ ! $reply =~ ^[Yy]([Ee][Ss])?$ ]]; then
                warn "leaving systemd-resolved untouched; Monarchy's DNS endpoint will not bind"
                return 0
            fi
        else
            warn "port 53 is used by systemd-resolved; Monarchy's DNS endpoint will not bind"
            warn "re-run with --fix-dns53, or set DNSStubListener=no in /etc/systemd/resolved.conf.d/"
            return 0
        fi
    fi

    configure_resolved_stub_listener || true
}

generate_password() {
    local raw
    if command -v openssl >/dev/null 2>&1; then
        raw="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9')"
    else
        raw="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
    fi
    printf 'Aa1!%s' "${raw:0:20}"
}

provision_domain() {
    [[ $PROVISION -eq 1 ]] || { log "Skipping domain provisioning"; return 0; }

    if [[ -f "$DCDIR/dc.conf" && $FORCE -eq 0 ]]; then
        log "Domain already provisioned in $DCDIR (use --force to replace it)"
        return
    fi

    if [[ -z "$ADMINPASS" ]]; then
        ADMINPASS="$(generate_password)"
        GENERATED_PASS=1
    fi

    local provisioner="$PREFIX/bin/monarchy-provision"
    [[ -x "$provisioner" ]] || die "$provisioner was not installed"

    local args=(--realm "$REALM" --adminpass "$ADMINPASS" --targetdir "$DCDIR")
    [[ -n "$DOMAIN" ]] && args+=(--domain "$DOMAIN")
    [[ -n "$DC_IP" ]] && args+=(--dc-ip "$DC_IP")
    [[ $DEV_PORTS -eq 1 ]] && args+=(--dev-ports)
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
        warn "provision it, then: systemctl enable --now monarchy-dcd"
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

if [[ $INSTALL_DEPS -eq 1 ]]; then
    install_dependencies
fi

check_dependencies
configure_and_build
run_tests
install_binaries
[[ $SERVICE -eq 1 ]] && install_service_unit
check_dns_port_conflict
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

EOF
else
    cat <<EOF
  Run:     $PREFIX/bin/monarchy-ui
  Daemon:  $PREFIX/bin/monarchy-dcd --dcdir "$DCDIR"

EOF
fi

if [[ $GENERATED_PASS -eq 1 ]]; then
    cat <<EOF
Administrator password (generated once, save it now):

  $ADMINPASS

EOF
fi
