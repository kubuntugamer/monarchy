#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Configure, build and test the tree: the check a change has to pass.
#
# Usage: scripts/ci.sh [--build-dir DIR] [--jobs N] [--with-ldap] [--conformance]
#
# The default build directory is removed first, so a stale CMake cache cannot
# hide a missing dependency or a source file that was never added to a target.
# A directory you name yourself is reused as-is, and the script says so.
#
# QT_QPA_PLATFORM=offscreen is exported because several suites link
# QApplication (the console, TLS, LDAP, DRSUAPI and EPM cases); without it they
# fail on a host with no display instead of testing anything.
#
# --conformance goes further than the suites: it provisions a throwaway domain
# under a temporary directory, starts monarchy-dcd on the unprivileged dev port
# set, and drives the running DC with scripts/drs-conformance.py and the
# impacket half of scripts/lsad-conformance.py. Those checks marshal every call
# with impacket's own NDR, so they fail where a reply only this tree's encoder
# understands would pass. They need impacket for python3 and are therefore
# opt-in rather than automatic.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${root}/build-ci
jobs=$(nproc 2>/dev/null || echo 2)
with_ldap=0
conformance=0

# The throwaway domain the conformance stage creates. Its password exists only
# for the lifetime of the temporary directory.
conformance_realm=CI.EXAMPLE.ORG
conformance_domain=CI
conformance_dns=ci.example.org
conformance_base_dn=DC=ci,DC=example,DC=org
conformance_password='Ci-Repl!cate-2026'

usage()
{
    sed -n '5,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

run_conformance()
{
    if ! python3 -c 'import impacket' >/dev/null 2>&1; then
        printf 'ci.sh: --conformance needs impacket for the python3 on PATH\n' >&2
        return 1
    fi

    local work
    work=$(mktemp -d -t monarchy-ci-XXXXXX)
    local dc_dir=$work/domain
    local log=$work/dcd.log
    mkdir -p "$dc_dir"

    # Netlogon (1037) and DRSUAPI (1038) are the same number in every port set,
    # so a host already running a Monarchy DC holds them and the throwaway
    # instance silently loses those binds while a probe still sees the other
    # DC answering. Ask the kernel for two free ports instead; the sockets are
    # closed before the daemon starts, which is the window this accepts.
    local netlogon_port drs_port
    read -r netlogon_port drs_port < <(python3 - <<'PY'
import socket

held = []
ports = []
for _ in range(2):
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    held.append(probe)
    ports.append(probe.getsockname()[1])
print(*ports)
PY
)

    printf '== provision a throwaway domain (netlogon %s, drsuapi %s)\n' \
        "$netlogon_port" "$drs_port"
    if ! "$build_dir/ui/monarchy-provision" \
        --realm "$conformance_realm" --domain "$conformance_domain" \
        --adminpass "$conformance_password" --targetdir "$dc_dir" --dev-ports \
        --netlogon-port "$netlogon_port" --drs-port "$drs_port" \
        >"$work/provision.log" 2>&1; then
        cat "$work/provision.log" >&2
        rm -rf -- "$work"
        return 1
    fi

    printf '== start the daemon on the dev ports\n'
    "$build_dir/ui/monarchy-dcd" --dcdir "$dc_dir" >"$log" 2>&1 &
    local daemon=$!
    local cleaned=0
    cleanup()
    {
        # The trap can fire after this function has returned, when the local is
        # gone, so it is read through a default. Without that, set -u turns
        # teardown into an error and leaves the daemon running.
        (( ${cleaned:-0} )) && return 0
        cleaned=1
        if kill -0 "$daemon" 2>/dev/null; then
            kill -TERM "$daemon" 2>/dev/null || true
            wait "$daemon" 2>/dev/null || true
        fi
    }
    trap cleanup EXIT

    # The port answering is the readiness signal; a fixed sleep would either
    # race a slow machine or waste time on a fast one.
    if ! python3 - "$drs_port" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.time() + 30
while time.time() < deadline:
    with socket.socket() as probe:
        probe.settimeout(0.5)
        if probe.connect_ex(('127.0.0.1', port)) == 0:
            sys.exit(0)
    time.sleep(0.2)
sys.exit('the daemon did not answer on 127.0.0.1:%d within 30s' % port)
PY
    then
        tail -n 40 "$log" >&2 || true
        cleanup
        trap - EXIT
        rm -rf -- "$work"
        return 1
    fi

    # The probe above proves a port answers, not that it is this DC: a stale
    # process on 1038 satisfied it once while the new daemon reported that its
    # own listener had failed. The daemon's own line is the real readiness.
    if ! grep -q 'DRSR served on' "$log"; then
        printf 'ci.sh: the daemon did not report a DRSUAPI listener\n' >&2
        tail -n 40 "$log" >&2 || true
        cleanup
        trap - EXIT
        rm -rf -- "$work"
        return 1
    fi

    local status=0
    printf '== DRSR conformance (impacket NDR)\n'
    python3 "$root/scripts/drs-conformance.py" --host 127.0.0.1 --port "$drs_port" \
        --basedn "$conformance_base_dn" --dnsdomain "$conformance_dns" \
        --netbios "$conformance_domain" --user Administrator \
        --password "$conformance_password" || status=1

    # The LSAD script checks each call against the domain SID the provisioned
    # tree recorded, and its Samba half needs pidl's bindings, which a CI image
    # does not carry; the impacket half still runs against MS-LSAD itself.
    local domain_sid
    domain_sid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("domainSid", ""))' \
        "$dc_dir/private/secrets.json" 2>/dev/null || true)
    if [[ -n "$domain_sid" ]]; then
        printf '== LSAD conformance (impacket half)\n'
        python3 "$root/scripts/lsad-conformance.py" --host 127.0.0.1 --port 1036 \
            --user Administrator --password "$conformance_password" \
            --domain "$conformance_domain" --domain-sid "$domain_sid" --skip-samba \
            || status=1
    else
        printf 'ci.sh: no domainSid in the provisioned secrets; LSAD conformance cannot run\n' >&2
        status=1
    fi

    if ((status != 0)); then
        printf '== daemon log (last 40 lines)\n' >&2
        tail -n 40 "$log" >&2 || true
    fi

    cleanup
    trap - EXIT
    rm -rf -- "$work"
    return "$status"
}

while (($#)); do
    case "$1" in
        --build-dir)
            build_dir=${2:?--build-dir needs a path}
            shift 2
            ;;
        --jobs)
            jobs=${2:?--jobs needs a count}
            shift 2
            ;;
        --with-ldap)
            with_ldap=1
            shift
            ;;
        --conformance)
            conformance=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'ci.sh: unknown argument %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

export QT_QPA_PLATFORM=offscreen

if [[ "$build_dir" == "${root}/build-ci" ]]; then
    rm -rf -- "$build_dir"
else
    printf 'ci.sh: reusing %s\n' "$build_dir"
fi

configure_args=(-S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release)
if ((with_ldap)); then
    configure_args+=(-DMONARCHY_WITH_LDAP=ON)
fi

printf '== configure\n'
cmake "${configure_args[@]}"

printf '== build (%s jobs)\n' "$jobs"
cmake --build "$build_dir" --parallel "$jobs"

printf '== test\n'
ctest --test-dir "$build_dir" --output-on-failure

if ((conformance)); then
    run_conformance
fi

printf '== every check passed\n'
