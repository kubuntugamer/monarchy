#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Verify that every endpoint this DC advertises is actually answering.
#
#   scripts/check-dc-health.sh [dcdir]
#
# Reads the dc.conf under dcdir (default /var/lib/monarchy/Monarchy) and checks
# two things:
#
#   1. every port named there accepts a TCP connection, and
#   2. every SRV locator record the served zone publishes points at a port that
#      accepts a TCP connection — a client that follows the record must not be
#      sent to a port nothing is listening on.
#
# Each check is printed with its result. Every mismatch is a FAIL line and the
# script exits non-zero, so an install or restart that leaves a locator record
# pointing at a dead port is visible instead of discovered later by a client.
# A zone this DC is not authoritative for, or a host without dig, is reported
# as skipped rather than failed.

set -euo pipefail

DCDIR="$(realpath -m "${1:-${MONARCHY_DCDIR:-/var/lib/monarchy/Monarchy}}")"
CONF="$DCDIR/dc.conf"
FAILURES=0
CHECKS=0

conf_value() { # key [default]
    local key="$1" default="${2-}" value
    value="$(awk -v k="$key" '
        { line = $0; sub(/#.*/, "", line); split(line, parts, "=");
          if (tolower(parts[1]) == tolower(k)) {
              sub(/^[^=]*=/, "", line);
              gsub(/^[ \t]+|[ \t]+$/, "", line); gsub(/"/, "", line);
              print line; exit } }' "$CONF")"
    printf '%s' "${value:-$default}"
}

tcp_open() { # host port
    timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# Either address counts as answering here. That is deliberate for the ports a
# client resolves, and it is not enough for the RPC ones: those are checked
# again below from this host's own non-loopback address, because binding
# loopback only looks identical from here.
reachable() { # port
    tcp_open "$DC_IP" "$1" && return 0
    tcp_open 127.0.0.1 "$1" && return 0
    return 1
}

# The address a client on another host would use, taken from the route the
# kernel would pick. Empty when this host has no route at all.
host_address() {
    local address=""
    if command -v ip >/dev/null 2>&1; then
        address="$(ip -4 route get 192.0.2.1 2>/dev/null |
            awk '{ for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1) }' | head -1)"
    fi
    if [[ -z "$address" ]] && command -v hostname >/dev/null 2>&1; then
        address="$(hostname -I 2>/dev/null | awk '{ print $1 }')"
    fi
    printf '%s' "$address"
}

ok() { printf '  %-32s %s\n' "$1" "ok"; }
fail() { printf '  %-32s FAIL: %s\n' "$1" "$2"; FAILURES=$((FAILURES + 1)); }
skip() { printf '  %-32s skipped: %s\n' "$1" "$2"; }

if [[ ! -f "$CONF" ]]; then
    printf 'check-dc-health: no provisioned domain under %s\n' "$DCDIR" >&2
    exit 78
fi

DNS_DOMAIN="$(conf_value dnsDomain)"
DC_HOST="$(conf_value dcHost)"
DC_IP="$(conf_value dcIp 127.0.0.1)"
DNS_PORT="$(conf_value dnsPort 53)"
SITE="$(conf_value siteName Default-First-Site-Name)"
SITE_LOWER="$(printf '%s' "$SITE" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$DNS_DOMAIN" || -z "$DC_HOST" ]]; then
    printf 'check-dc-health: %s names no dnsDomain/dcHost\n' "$CONF" >&2
    exit 78
fi

printf 'Monarchy DC health check: %s\n' "$DCDIR"
printf 'Domain %s, DC %s (%s)\n\n' "$DNS_DOMAIN" "$DC_HOST" "$DC_IP"

# --- 1. the endpoints dc.conf tells this process to serve -------------------
printf 'Endpoints named in dc.conf:\n'
declare -A declared=(
    [ldapPort]="$(conf_value ldapPort 1389)"
    [gcPort]="$(conf_value gcPort 3268)"
    [kdcPort]="$(conf_value kdcPort 8888)"
    [kpasswdPort]="$(conf_value kpasswdPort 464)"
    [dnsPort]="$DNS_PORT"
    [smbPort]="$(conf_value smbPort 445)"
    [epmPort]="$(conf_value epmPort 135)"
    [samrPort]="$(conf_value samrPort 1035)"
    [lsadPort]="$(conf_value lsadPort 1036)"
    [netlogonPort]="$(conf_value netlogonPort 1037)"
    [drsPort]="$(conf_value drsPort 1038)"
)
for key in ldapPort gcPort kdcPort kpasswdPort dnsPort smbPort epmPort samrPort lsadPort netlogonPort drsPort; do
    port="${declared[$key]}"
    CHECKS=$((CHECKS + 1))
    if reachable "$port"; then
        ok "$key $port"
    else
        fail "$key $port" "nothing is listening"
    fi
done

# The RPC endpoints — the endpoint mapper a client asks first, and the dynamic
# ports it names — are on loopback unless dc.conf sets rpcAddress, which STATUS.md
# keeps that way until per-account RPC authorization exists. A loopback set is
# therefore not a failure: it is a DC no other machine can join, and the skip says
# so. When rpcAddress does take them off loopback, ask for them from this host's
# own routable address, because a bind that silently stayed on loopback passes
# every check above.
printf '\nRPC endpoints as another host reaches them:\n'
HOST_ADDRESS="$(host_address)"
RPC_ADDRESS="$(conf_value rpcAddress '')"
case "$RPC_ADDRESS" in
    ""|127.*|::1|localhost) LOOPBACK_ONLY=1 ;;
    *) LOOPBACK_ONLY=0 ;;
esac
if (( LOOPBACK_ONLY )); then
    skip "RPC endpoints off-host" \
        "rpcAddress is loopback (STATUS.md 4); a domain join from another host cannot reach them"
elif [[ -z "$HOST_ADDRESS" ]]; then
    skip "RPC endpoints off-host" "this host has no non-loopback address"
else
    for key in epmPort samrPort lsadPort netlogonPort drsPort; do
        port="${declared[$key]}"
        CHECKS=$((CHECKS + 1))
        if tcp_open "$HOST_ADDRESS" "$port"; then
            ok "$key $port at $HOST_ADDRESS"
        else
            fail "$key $port at $HOST_ADDRESS" \
                "not reachable off this host; a domain join cannot reach it"
        fi
    done
fi

# --- 2. what the zone tells clients to connect to ---------------------------
printf '\nAdvertised SRV locators:\n'
if ! command -v dig >/dev/null 2>&1; then
    skip "SRV locators" "dig is not installed"
else
    # Every owner name loadAdZone() publishes, asked the way a client asks.
    locators=(
        "_ldap._tcp.$DNS_DOMAIN"
        "_ldap._tcp.dc._msdcs.$DNS_DOMAIN"
        "_ldap._tcp.$SITE_LOWER._sites.$DNS_DOMAIN"
        "_ldap._tcp.$SITE_LOWER._sites.dc._msdcs.$DNS_DOMAIN"
        "_ldap._tcp.gc._msdcs.$DNS_DOMAIN"
        "_ldap._tcp.$SITE_LOWER._sites.gc._msdcs.$DNS_DOMAIN"
        "_ldap._tcp.pdc._msdcs.$DNS_DOMAIN"
        "_gc._tcp.$DNS_DOMAIN"
        "_gc._tcp.$SITE_LOWER._sites.$DNS_DOMAIN"
        "_kerberos._tcp.$DNS_DOMAIN"
        "_kerberos._tcp.dc._msdcs.$DNS_DOMAIN"
        "_kerberos._tcp.$SITE_LOWER._sites.$DNS_DOMAIN"
        "_kpasswd._tcp.$DNS_DOMAIN"
    )

    declare -A port_reported=()
    resolved=0
    zone_error=""
    for owner in "${locators[@]}"; do
        # dig writes its diagnostics ("communications error …", "no servers
        # could be reached") to stdout even with +short, so the exit status
        # decides whether the answer lines mean anything; otherwise those
        # words would be parsed as the priority/weight/port/target fields.
        dig_status=0
        records="$(dig @"$DC_IP" -p "$DNS_PORT" +short +time=2 +tries=1 SRV "$owner" 2>/dev/null)" || dig_status=$?
        if [[ "$dig_status" -ne 0 ]]; then
            zone_error="dig exited $dig_status"
            break
        fi
        [[ -n "$records" ]] || continue
        # priority weight port target
        while read -r _priority _weight port target; do
            [[ "${_priority:-}" =~ ^[0-9]+$ && "${_weight:-}" =~ ^[0-9]+$ &&
               "${port:-}" =~ ^[0-9]+$ && -n "${target:-}" ]] || continue
            resolved=$((resolved + 1))
            CHECKS=$((CHECKS + 1))
            if reachable "$port"; then
                if [[ "${port_reported[$port]:-}" == "" ]]; then
                    ok "$owner -> $port"
                    port_reported[$port]=1
                else
                    ok "$owner -> $port (already checked)"
                fi
            else
                fail "$owner -> $port" "advertised to $target, nothing is listening"
            fi
        done <<<"$records"
    done

    if [[ -n "$zone_error" ]]; then
        CHECKS=$((CHECKS + 1))
        fail "SRV locators" "the zone at $DC_IP:$DNS_PORT did not answer ($zone_error), so no locator could be checked"
    elif [[ "$resolved" -eq 0 ]]; then
        skip "SRV locators" "the zone at $DC_IP:$DNS_PORT holds none for $DNS_DOMAIN"
    fi

    # A negative answer is a claim a client caches, and the two negatives are
    # not the same one: a name outside the zone is NXDOMAIN, an existing name
    # without the type asked for is an empty NOERROR. Both have to carry the
    # zone's SOA in AUTHORITY or a resolver cannot cache the absence.
    absent="no-such-name-$RANDOM.$DNS_DOMAIN"
    negative_status=0
    answer="$(dig @"$DC_IP" -p "$DNS_PORT" +time=2 +tries=1 A "$absent" 2>/dev/null)" \
        || negative_status=$?
    CHECKS=$((CHECKS + 1))
    if [[ "$negative_status" -ne 0 ]]; then
        fail "NXDOMAIN" "dig exited $negative_status asking for $absent"
    elif ! grep -q 'status: NXDOMAIN' <<<"$answer"; then
        fail "NXDOMAIN" "$absent did not answer NXDOMAIN"
    elif ! grep -q 'AUTHORITY: 1' <<<"$answer"; then
        fail "NXDOMAIN" "$absent answered NXDOMAIN without the zone's SOA"
    elif ! grep -q 'flags: qr aa' <<<"$answer"; then
        fail "NXDOMAIN" "$absent answered without AA, so a resolver will not keep it"
    else
        ok "NXDOMAIN + SOA"
    fi

    # The zone apex exists, so a type it does not carry is NODATA, not NXDOMAIN.
    nodata_status=0
    answer="$(dig @"$DC_IP" -p "$DNS_PORT" +time=2 +tries=1 TXT "$DNS_DOMAIN" 2>/dev/null)" \
        || nodata_status=$?
    CHECKS=$((CHECKS + 1))
    if [[ "$nodata_status" -ne 0 ]]; then
        fail "NODATA" "dig exited $nodata_status asking for a TXT at the apex"
    elif ! grep -q 'status: NOERROR' <<<"$answer"; then
        fail "NODATA" "the zone apex did not answer NOERROR for a type it lacks"
    elif ! grep -q 'AUTHORITY: 1' <<<"$answer"; then
        fail "NODATA" "the empty answer carried no SOA, so nothing can be cached"
    else
        ok "NODATA + SOA"
    fi
fi

# --- summary ---------------------------------------------------------------
printf '\n'
if [[ "$FAILURES" -eq 0 ]]; then
    printf '%d checks, all passing.\n' "$CHECKS"
    exit 0
fi
printf '%d checks, %d failing. A client that follows this DC'"'"'s own records\n' "$CHECKS" "$FAILURES"
printf 'would be sent somewhere nothing answers.\n'
exit 1
