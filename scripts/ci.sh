#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Configure, build and test the tree: the check a change has to pass.
#
# Usage: scripts/ci.sh [--build-dir DIR] [--jobs N] [--with-ldap] [--sanitize] [--conformance]
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
# set, and drives the running DC with scripts/ldap-conformance.py (the LDAP
# listener, driven by OpenLDAP's ldapsearch so neither the BER encoder nor the
# DN parser is this tree's), scripts/drs-conformance.py, the impacket
# half of scripts/lsad-conformance.py, scripts/samr-conformance.py (the account
# lifecycle), scripts/netlogon-conformance.py (the locator and the secure
# channel a logon rides on, with a machine account it creates over SAMR) and
# scripts/smb-conformance.py (the SMB2 transport those pipes ride on, driven at
# a pinned dialect by smbclient, rpcclient and impacket). Those checks marshal
# with impacket's own NDR or with Samba's or OpenLDAP's, so they fail where a
# reply only this tree's encoder understands would pass. They need impacket for
# python3, the smbclient package and the ldap-utils package, and are therefore
# opt-in rather than automatic.
#
# --sanitize configures a Debug build with AddressSanitizer and
# UndefinedBehaviorSanitizer and runs every suite. UBSan is set to halt rather
# than recover: by default it prints a runtime error and still exits 0, so a
# job built on it would report a shift of a negative number as a pass. Leak
# detection is off because the suites deliberately leave Qt objects alive at
# exit; that is the only check this mode weakens.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${root}/build-ci
jobs=$(nproc 2>/dev/null || echo 2)
with_ldap=0
sanitize=0
conformance=0

# The throwaway domain the conformance stage creates. Its password exists only
# for the lifetime of the temporary directory.
conformance_realm=CI.EXAMPLE.ORG
conformance_domain=CI
conformance_dns=ci.example.org
conformance_base_dn=DC=ci,DC=example,DC=org
conformance_password='Ci-Repl!cate-2026'

usage()
{        sed -n '5,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

run_conformance()
{
    if ! python3 -c 'import impacket' >/dev/null 2>&1; then
        printf 'ci.sh: --conformance needs impacket for the python3 on PATH\n' >&2
        return 1
    fi
    # The SMB driver runs against real clients rather than impacket's own SMB
    # stack for the file half, so both binaries have to exist before the
    # daemon is provisioned and started.
    if ! command -v smbclient >/dev/null 2>&1 || ! command -v rpcclient >/dev/null 2>&1; then
        printf 'ci.sh: --conformance needs smbclient and rpcclient (the smbclient package)\n' >&2
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
    # DC answering. Ask the kernel for free ports instead; the sockets are
    # closed before the daemon starts, which is the window this accepts. SMB is
    # the same problem with a different cause: 445 needs root, and the SMB
    # stage has to reach the shares and the pipes, so the throwaway instance
    # moves that port too. The endpoint mapper is the other port below 1024,
    # and the health check below reads it from dc.conf, so it moves for the
    # same reason instead of being left to fail as an unprivileged bind.
    local netlogon_port drs_port smb_port epm_port
    read -r netlogon_port drs_port smb_port epm_port < <(python3 - <<'PY'
import socket

held = []
ports = []
for _ in range(4):
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

    # The runner's own non-loopback address, which stands in for the second
    # host the endpoint mapper stage needs. A UDP connect sends nothing; it only
    # asks the kernel which address a packet would leave from. A machine with no
    # route leaves this empty and that stage skips the remote half.
    local lan_ip
    lan_ip=$(python3 - 2>/dev/null <<'PY' || true
import socket

probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    probe.connect(('192.0.2.1', 9))
    print(probe.getsockname()[0])
except OSError:
    pass
PY
)

    # The daemon reads these from dc.conf when it starts, so the move has to
    # happen after provisioning and before that. Without it the SMB listener
    # fails with "port 445 needs root" and the SMB stage has nothing to reach,
    # and the endpoint mapper does the same on 135. dcIp is the address the DC
    # publishes for itself, which the endpoint mapper's towers name: leaving it
    # at the provisioner's loopback default would make that stage test the very
    # answer it exists to rule out.
    sed -i -e "s/^smbPort=.*/smbPort=$smb_port/" \
        -e "s/^epmPort=.*/epmPort=$epm_port/" "$dc_dir/dc.conf"
    if [[ -n "${lan_ip:-}" ]]; then
        sed -i "s/^dcIp=.*/dcIp=$lan_ip/" "$dc_dir/dc.conf"
        # The endpoint mapper stage asks from that address, so the throwaway
        # instance serves there: rpcAddress is the operator's opt-in to taking
        # the RPC endpoints off loopback, and this stage is the workload for it.
        if grep -q '^rpcAddress=' "$dc_dir/dc.conf"; then
            sed -i "s/^rpcAddress=.*/rpcAddress=0.0.0.0/" "$dc_dir/dc.conf"
        else
            printf 'rpcAddress=0.0.0.0\n' >>"$dc_dir/dc.conf"
        fi
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
    if ! grep -q 'SMB2 served on' "$log"; then
        printf 'ci.sh: the daemon did not report an SMB2 listener\n' >&2
        tail -n 40 "$log" >&2 || true
        cleanup
        trap - EXIT
        rm -rf -- "$work"
        return 1
    fi

    # The greps above prove the listeners started; this proves a client that
    # reads dc.conf and follows the zone's SRV records reaches them. It runs
    # here, after those greps, because it cannot tell whose listener answered:
    # on one box a daemon that had failed four listeners reported all passing
    # because an installed DC held the ports. The greps are what make the
    # absence of this daemon's own line a failure before the check runs.
    printf '== health check (dc.conf ports and advertised locators)\n'
    "$root/scripts/check-dc-health.sh" "$dc_dir" || {
        printf 'ci.sh: the provisioned DC does not answer where it says it does\n' >&2
        cleanup
        trap - EXIT
        rm -rf -- "$work"
        return 1
    }

    local status=0

    # Every other driver marshals with impacket or a Samba binary; this one is
    # the only place an LDAP client that is not this tree talks to the LISTENER,
    # and libldap brings its own BER length encoder and DN parser, so a reply
    # only our encoder accepts fails here. The port comes from dc.conf because
    # --dev-ports moves the privileged ones.
    local ldap_port
    ldap_port=$(sed -n 's/^ldapPort=//p' "$dc_dir/dc.conf" | head -1)
    : "${ldap_port:=389}"
    printf '== LDAP conformance (OpenLDAP ldapsearch)\n'
    python3 "$root/scripts/ldap-conformance.py" --host 127.0.0.1 --port "$ldap_port" \
        --base-dn "$conformance_base_dn" --user Administrator \
        --password "$conformance_password" --dns-domain "$conformance_dns" || status=1

    # MIT's own client against the KDC. The ticket flags a reply carries are
    # what a client acts on — forwardable for delegation, initial for whether it
    # may renew — and no suite in this tree decodes them the way a client does.
    local kdc_port
    kdc_port=$(sed -n 's/^kdcPort=//p' "$dc_dir/dc.conf" | head -1)
    : "${kdc_port:=88}"
    printf '== Kerberos conformance (MIT kinit/klist/kvno)\n'
    if ! command -v kinit >/dev/null 2>&1 || ! command -v kvno >/dev/null 2>&1; then
        # No client means nothing was tested, not that something broke: this is
        # reported as a skip, the way the health script treats a missing dig, so
        # a box without krb5-user does not show a red run no change could cause.
        # CI installs it, so the stage always runs there.
        printf 'ci.sh: skipped - kinit/kvno are not on PATH (install krb5-user)\n' >&2
    else
        python3 "$root/scripts/kerberos-conformance.py" --kdc 127.0.0.1 --kdc-port "$kdc_port" \
            --realm "$conformance_realm" --user Administrator \
            --password "$conformance_password" \
            --dc-host "$(printf '%s' "$conformance_domain" | tr '[:upper:]' '[:lower:]')dc1.$conformance_dns" \
            || status=1
    fi

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

    # SAMR and netlogon, marshalled by impacket's own NDR. The netlogon driver
    # creates the machine account it authenticates with through SAMR, so it
    # needs that endpoint's port as well; the port comes from the provisioned
    # configuration because --dev-ports keeps it at 1035.
    local samr_port
    samr_port=$(sed -n 's/^samrPort=//p' "$dc_dir/dc.conf" | head -1)
    : "${samr_port:=1035}"
    printf '== SAMR conformance (impacket NDR)\n'
    python3 "$root/scripts/samr-conformance.py" --host 127.0.0.1 --port "$samr_port" \
        --user Administrator --password "$conformance_password" \
        --domain "$conformance_domain" || status=1

    printf '== Netlogon conformance (impacket NDR)\n'
    python3 "$root/scripts/netlogon-conformance.py" --host 127.0.0.1 \
        --port "$netlogon_port" --samr-port "$samr_port" \
        --user Administrator --password "$conformance_password" \
        --domain "$conformance_domain" || status=1

    # The endpoint mapper: the service a client asks when it knows an interface
    # but not the port, so it has to answer where a *remote* client looks. The
    # mapper and the endpoints it named once bound loopback only while the tower
    # named loopback too, and a probe on this host could see neither. Questions
    # go over the LAN address for exactly that reason.
    if [[ -n "${lan_ip:-}" ]]; then
        printf '== EPM conformance (impacket, over %s)\n' "$lan_ip"
        python3 "$root/scripts/epm-conformance.py" --host "$lan_ip" \
            --epm-port "$epm_port" --advertised "$lan_ip" \
            --user Administrator --password "$conformance_password" \
            --domain "$conformance_domain" || status=1
    else
        printf '== EPM conformance (impacket)\n'
        python3 "$root/scripts/epm-conformance.py" --host 127.0.0.1 \
            --epm-port "$epm_port" --advertised 127.0.0.1 \
            --user Administrator --password "$conformance_password" \
            --domain "$conformance_domain" || status=1
        printf 'ci.sh: skipped the remote half - this host has no non-loopback address\n' >&2
    fi

    # The share root is the parent of the domain directory the daemon serves,
    # which is what the SYSVOL share is mapped to; the driver writes its fixture
    # there so the bytes it reads back over SMB have something to match.
    printf '== SMB2 conformance (smbclient, rpcclient, impacket pipes)\n'
    python3 "$root/scripts/smb-conformance.py" --host 127.0.0.1 --port "$smb_port" \
        --user Administrator --password "$conformance_password" \
        --domain "$conformance_domain" --dns-domain "$conformance_dns" \
        --sysvol-root "$dc_dir/sysvol" || status=1

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
        --sanitize)
            sanitize=1
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
if ((sanitize)); then
    # Debug because the optimiser is what turns a report into a wrong answer
    # the tests cannot see, and -O0 keeps the reported line honest.
    sanitize_flags='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1'
    configure_args+=(
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_C_FLAGS="$sanitize_flags"
        -DCMAKE_CXX_FLAGS="$sanitize_flags"
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
    )
fi

printf '== configure\n'
cmake "${configure_args[@]}"

printf '== build (%s jobs)\n' "$jobs"
cmake --build "$build_dir" --parallel "$jobs"

# Every suite binds port 0, so they do not compete for a fixed port; the
# conformance stage below is the exception and stays serial.
printf '== test (%s jobs)\n' "$jobs"
if ((sanitize)); then
    # halt_on_error is the difference between a sanitizer job and a decoration.
    export ASAN_OPTIONS="detect_leaks=0"
    export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
fi
ctest --test-dir "$build_dir" --parallel "$jobs" --output-on-failure

if ((conformance)); then
    run_conformance
fi

printf '== every check passed\n'
