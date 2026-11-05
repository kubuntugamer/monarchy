#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Install an already-built Monarchy as a boot-started system service.
#
#   scripts/install-dc-services.sh [dcdir]
#
# Default dcdir: /var/lib/monarchy/Monarchy — the state systemd's
# StateDirectory= creates and owns for the service. Everything lives under
# that directory: the provisioned store, dc.conf, DNS zone, sysvol, keys.
#
# The unit is enabled at boot. If the domain is not provisioned yet the script
# leaves it stopped rather than starting a service that has nothing to serve:
#   sudo -u monarchy-dc /usr/local/bin/monarchy-provision \
#        /var/lib/monarchy/Monarchy --realm MONARCHY.EXAMPLE.COM --adminpass '…'
#   sudo systemctl restart monarchy-dcd
#
# For a full build-install-provision-start run, use scripts/install-monarchy.sh
# instead.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCDIR="$(realpath -m "${1:-/var/lib/monarchy/Monarchy}")"
PREFIX="/usr/local"
SERVICE_USER="monarchy-dc"
SERVICE_GROUP="$SERVICE_USER"

# Locate the freshly built binaries the way CMake lays them out.
find_bin() {
    local name="$1" candidate
    for candidate in "$ROOT/build/$name" "$ROOT/build/ui/$name"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    candidate="$(find "$ROOT/build" -maxdepth 3 -type f -name "$name" -perm -u+x -print -quit 2>/dev/null || true)"
    [[ -n "$candidate" ]] || { printf 'install-dc-services: %s not built\n' "$name" >&2; exit 1; }
    printf '%s\n' "$candidate"
}

DCD_BIN="$(find_bin monarchy-dcd)"
PROVISION_BIN="$(find_bin monarchy-provision)"

# The service runs unprivileged except for binding the privileged ports.
getent group "$SERVICE_GROUP" >/dev/null \
    || groupadd --system "$SERVICE_GROUP"
getent passwd "$SERVICE_USER" >/dev/null \
    || useradd --system --gid "$SERVICE_GROUP" --home-dir /var/lib/monarchy \
               --shell /usr/sbin/nologin "$SERVICE_USER"

install -m 0755 "$DCD_BIN" "$PREFIX/bin/monarchy-dcd"
install -m 0755 "$PROVISION_BIN" "$PREFIX/bin/monarchy-provision"

# The store's home: systemd's StateDirectory= already creates
# /var/lib/monarchy at start, but provisioning happens before the first
# start, so create it here with the service's ownership. Own only the store
# itself, never an arbitrary parent such as /srv.
mkdir -p "$DCDIR"
chown "$SERVICE_USER:$SERVICE_GROUP" "$DCDIR"
chmod 0750 "$DCDIR"

# The unit assumes the default paths; rewrite them when dcdir differs.
# A store under /home also needs ProtectHome lifted.
protect_home=true
[[ "$DCDIR" == /home/* ]] && protect_home=false
sed -e "s|--dcdir /var/lib/monarchy/Monarchy|--dcdir $DCDIR|" \
    -e "s|-/var/lib/monarchy/Monarchy|-$DCDIR|" \
    -e "s|ProtectHome=true|ProtectHome=$protect_home|" \
    "$ROOT/packaging/monarchy-dcd.service" \
    > /etc/systemd/system/monarchy-dcd.service
chmod 0644 /etc/systemd/system/monarchy-dcd.service

systemctl daemon-reload
systemctl enable monarchy-dcd.service

HEALTH=""
if [[ -f "$DCDIR/dc.conf" ]]; then
    systemctl restart monarchy-dcd.service
    STATE="running"
    if command -v ss >/dev/null 2>&1; then
        dns53="$(ss -lunpH 'sport = :53' 2>/dev/null || true)"
        if [[ -n "$dns53" ]] && ! grep -q 'monarchy-dcd' <<<"$dns53"; then
            printf 'install-dc-services: port 53 is held by another resolver; if it is\n' >&2
            printf '  systemd-resolved, run scripts/install-monarchy.sh --fix-dns53\n' >&2
        fi
    fi
    # A restart that leaves a locator record pointing at a dead port is a
    # failure, not a warning: the check reports it and this script exits with
    # its status after printing the summary.
    if "$ROOT/scripts/check-dc-health.sh" "$DCDIR"; then
        HEALTH="all advertised endpoints answer"
    else
        HEALTH="FAILED — see the mismatches above"
    fi
else
    STATE="waiting for a provisioned domain"
fi

cat <<EOF

Monarchy's domain controller is installed and enabled at boot.

  Unit:      systemctl status monarchy-dcd
  State:     $STATE
  Store:     $DCDIR
  Health:    ${HEALTH:-not checked (no provisioned domain)}
  Provision: sudo -u $SERVICE_USER $PREFIX/bin/monarchy-provision \\
                 $DCDIR --realm MONARCHY.EXAMPLE.COM --adminpass '…' [--force]
  Provisioning defaults to the native DC ports (53/389/88/464/135/445). Only for a
  rootless dev machine add --dev-ports. After re-provisioning (dc.conf changes):
             sudo systemctl restart monarchy-dcd
EOF

if [[ "$HEALTH" == FAILED* ]]; then
    exit 1
fi
