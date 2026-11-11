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

# The endpoints this daemon serves are reached at dcIp, except the RPC
# interfaces, which bind loopback only. Either address counts as answering.
reachable() { # port
    tcp_open "$DC_IP" "$1" && return 0
    tcp_open 127.0.0.1 "$1" && return 0
    return 1
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
