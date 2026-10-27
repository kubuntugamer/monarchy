#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Install Monarchy's domain controller as boot-started system services.
#
#   scripts/install-dc-services.sh [dcdir]
#
# Default dcdir: /var/lib/monarchy/Monarchy — the state systemd's
# StateDirectory= creates and owns for the service. Everything lives under
# that directory: the provisioned store, dc.conf, DNS zone, sysvol, keys.
#
# After installing, provision the domain once:
#   sudo -u monarchy-dc /usr/local/bin/monarchy-provision \
#        /var/lib/monarchy/Monarchy --realm MONARCHY.EXAMPLE.COM --adminpass '…'
# and restart the unit (`systemctl restart monarchy-dcd`). The daemon then
# serves whatever dc.conf lists at boot, exactly like a Windows DC's
# services start.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCDIR="${1:-/var/lib/monarchy/Monarchy}"
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
getent passwd "$SERVICE_USER" >/dev/null \
    || useradd --system --home-dir /var/lib/monarchy --shell /usr/sbin/nologin \
               "$SERVICE_USER"

install -m 0755 "$DCD_BIN" /usr/local/bin/monarchy-dcd
install -m 0755 "$PROVISION_BIN" /usr/local/bin/monarchy-provision
install -m 0644 "$ROOT/packaging/monarchy-dcd.service" /etc/systemd/system/monarchy-dcd.service

# The store's home: systemd's StateDirectory= already creates
# /var/lib/monarchy at start, but provisioning happens before the first
# start, so create it here with the service's ownership.
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$(dirname "$DCDIR")"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DCDIR"

systemctl daemon-reload
systemctl enable --now monarchy-dcd.service

cat <<EOF

Monarchy's domain controller is installed and enabled at boot.

  Unit:      systemctl status monarchy-dcd
  State:     $DCDIR
  Provision: sudo -u $SERVICE_USER /usr/local/bin/monarchy-provision \\
                 $DCDIR --realm MONARCHY.EXAMPLE.COM --adminpass '…' [--force]
  Provisioning defaults to the native DC ports (53/389/88/135/445). Only for a
  rootless dev machine add --dev-ports. After re-provisioning (dc.conf changes):
             sudo systemctl restart monarchy-dcd
EOF
