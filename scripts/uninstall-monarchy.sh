#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Remove a Monarchy install created by scripts/install-monarchy.sh.
#
#   sudo scripts/uninstall-monarchy.sh
#
# As root this stops and removes the monarchy-dcd unit, the installed binaries,
# the service account and (after confirmation) the domain store. If the
# installer reconfigured systemd-resolved for port 53, that change is reverted
# and the original stub symlink is restored. A rootless --user install only
# removes the binaries and the domain store.
#
# Use --keep-domain, --keep-user or --keep-resolver to leave individual pieces
# in place. --yes is required when stdin is not a terminal.

set -euo pipefail

PREFIX=""
DCDIR=""
USER_MODE=0
KEEP_DOMAIN=0
KEEP_USER=0
KEEP_RESOLVER=0
ASSUME_YES=0
FORCE=0
SERVICE_USER="monarchy-dc"
DOMAIN_REMOVED=0
RESOLVER_REVERTED=0
ACCOUNT_REMOVED=0

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'uninstall-monarchy: %s\n' "$*" >&2; }
die()  { printf 'uninstall-monarchy: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: scripts/uninstall-monarchy.sh [options]

Removes a Monarchy install. Interactive runs ask before deleting anything.

  --prefix DIR      Install prefix (default: /usr/local as root,
                    ~/.local with --user)
  --dcdir DIR       Domain store (default: /var/lib/monarchy/Monarchy as root,
                    the user data directory with --user)
  --user            Rootless install: no systemd unit, resolver or service
                    account is touched
  --keep-domain     Leave the provisioned domain store in place
  --keep-user       Leave the monarchy-dc system account in place
  --keep-resolver   Leave systemd-resolved and /etc/resolv.conf as they are
  --yes             Do not ask for confirmation (required when not a terminal)
  --force           Delete a --dcdir that does not look like a Monarchy store

  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)         PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*)       PREFIX="${1#*=}"; shift ;;
        --dcdir)          DCDIR="${2:?--dcdir needs a directory}"; shift 2 ;;
        --dcdir=*)        DCDIR="${1#*=}"; shift ;;
        --user)           USER_MODE=1; shift ;;
        --keep-domain)    KEEP_DOMAIN=1; shift ;;
        --keep-user)      KEEP_USER=1; shift ;;
        --keep-resolver)  KEEP_RESOLVER=1; shift ;;
        --yes|-y)         ASSUME_YES=1; shift ;;
        --force)          FORCE=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown option: $1 (see --help)" ;;
    esac
done

if [[ $USER_MODE -eq 1 ]]; then
    PREFIX="${PREFIX:-$HOME/.local}"
    DCDIR="${DCDIR:-${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy}"
else
    [[ $EUID -eq 0 ]] || die "removing a system install needs root; rerun with sudo or use --user"
    PREFIX="${PREFIX:-/usr/local}"
    DCDIR="${DCDIR:-/var/lib/monarchy/Monarchy}"
fi
PREFIX="$(realpath -m "$PREFIX")"
DCDIR="$(realpath -m "$DCDIR")"

if [[ $KEEP_DOMAIN -eq 0 && -d "$DCDIR" ]]; then
    if [[ ! -f "$DCDIR/dc.conf" && ! -f "$DCDIR/private/directory.json" && $FORCE -eq 0 ]]; then
        warn "$DCDIR does not look like a Monarchy domain store; keeping it"
        warn "pass --keep-domain to silence this, or --force to delete it"
        KEEP_DOMAIN=1
    fi
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    [[ -t 0 ]] || die "refusing to remove anything without --yes when stdin is not a terminal"
    cat <<EOF
This will remove:
  binaries:  $PREFIX/bin/monarchy-{ui,dcd,provision}
EOF
    [[ $USER_MODE -eq 0 ]] && cat <<EOF
  service:   monarchy-dcd (stopped, disabled and deleted)
  account:   $SERVICE_USER (unless --keep-user)
EOF
    [[ $KEEP_DOMAIN -eq 0 ]] && printf '  domain:    %s\n' "$DCDIR"
    [[ $KEEP_RESOLVER -eq 0 && $USER_MODE -eq 0 ]] \
        && printf '  resolver:  systemd-resolved stub listener and /etc/resolv.conf\n'
    printf 'Proceed? [y/N] '
    reply=""
    read -r reply || true
    [[ $reply =~ ^[Yy]([Ee][Ss])?$ ]] || die "cancelled"
fi

# --- service -----------------------------------------------------------------

if [[ $USER_MODE -eq 0 ]]; then
    if [[ -f /etc/systemd/system/monarchy-dcd.service ]]; then
        log "Stopping and disabling monarchy-dcd"
        systemctl disable --now monarchy-dcd.service || warn "could not stop monarchy-dcd"
    fi
    rm -f /etc/systemd/system/monarchy-dcd.service
    rm -f /etc/systemd/system/multi-user.target.wants/monarchy-dcd.service
    systemctl daemon-reload || warn "systemctl daemon-reload failed"
fi

# --- resolver ----------------------------------------------------------------

revert_resolver() {
    [[ $USER_MODE -eq 0 && $KEEP_RESOLVER -eq 0 ]] || return 0
    local dropin=/etc/systemd/resolved.conf.d/10-monarchy.conf
    local managed=0
    [[ -f /etc/resolv.conf ]] \
        && grep -q "Managed by Monarchy's installer" /etc/resolv.conf 2>/dev/null \
        && managed=1
    if [[ ! -f "$dropin" && $managed -eq 0 ]]; then
        return 0
    fi

    log "Restoring the system resolver"
    rm -f "$dropin"
    if [[ $managed -eq 1 ]]; then
        rm -f /etc/resolv.conf
        if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
            ln -sfn ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        else
            warn "systemd-resolved is not enabled; /etc/resolv.conf was not replaced"
        fi
    fi
    if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
        systemctl restart systemd-resolved || warn "could not restart systemd-resolved"
    fi
    RESOLVER_REVERTED=1
}

revert_resolver

# --- binaries ----------------------------------------------------------------

log "Removing installed binaries"
for binary in monarchy-ui monarchy-dcd monarchy-provision; do
    rm -f "$PREFIX/bin/$binary"
done
rmdir "$PREFIX/bin" 2>/dev/null || true

# --- domain store ------------------------------------------------------------

if [[ $KEEP_DOMAIN -eq 0 && -d "$DCDIR" ]]; then
    log "Removing the domain store at $DCDIR"
    rm -rf "$DCDIR"
    DOMAIN_REMOVED=1
fi

# systemd's StateDirectory leaves its runtime cache behind even after the
# store is gone. Remove that and the default directory when nothing else is in
# it; an arbitrary --dcdir parent is never touched.
if [[ $USER_MODE -eq 0 && $KEEP_DOMAIN -eq 0 && -d /var/lib/monarchy ]]; then
    rm -rf /var/lib/monarchy/.cache
    rmdir /var/lib/monarchy 2>/dev/null || true
fi

# --- service account ---------------------------------------------------------

if [[ $USER_MODE -eq 0 && $KEEP_USER -eq 0 ]]; then
    if getent passwd "$SERVICE_USER" >/dev/null; then
        if command -v pgrep >/dev/null 2>&1 && pgrep -u "$SERVICE_USER" >/dev/null 2>&1; then
            warn "$SERVICE_USER still has running processes; keeping the account"
        else
            log "Removing the $SERVICE_USER service account"
            userdel "$SERVICE_USER" 2>/dev/null || warn "could not remove $SERVICE_USER"
            getent group "$SERVICE_USER" >/dev/null && groupdel "$SERVICE_USER" 2>/dev/null || true
            ACCOUNT_REMOVED=1
        fi
    fi
fi

cat <<EOF

Monarchy is uninstalled.

  Binaries:  removed from $PREFIX/bin
EOF
[[ $DOMAIN_REMOVED -eq 1 ]] && printf '  Domain:    %s removed\n' "$DCDIR"
[[ $RESOLVER_REVERTED -eq 1 ]] && printf '  Resolver:  restored to systemd-resolved\n'
[[ $ACCOUNT_REMOVED -eq 1 ]] && printf '  Account:   %s removed\n' "$SERVICE_USER"
exit 0
