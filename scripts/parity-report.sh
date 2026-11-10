#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Print the working-copy state two boxes must agree on, in a form that diffs.
#
#   scripts/parity-report.sh [--build-dir DIR] [--dcdir DIR]
#
# Two boxes are in parity when this output matches line for line. Run it before
# claiming work and after landing it, and paste it into the thread: a HEAD that
# differs between boxes is the one thing the suites cannot report, because both
# boxes pass on their own tree.
#
# --dcdir adds the ports the installed DC declares and the health check's
# verdict, which is how a box discovers that it is serving a domain the other
# box does not have. Without it the report touches no running process.
#
# Exit status: 0 in parity, 1 the tree has drifted from origin/main or carries
# tracked changes, 2 bad usage. Untracked files are listed but are not
# divergence -- a scratch patch beside the tree cannot change what a commit does.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=$root/build
dcdir=

usage() { sed -n '5,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while (($#)); do
    case "$1" in
        --build-dir) build_dir=${2:?--build-dir needs a path}; shift 2 ;;
        --dcdir) dcdir=${2:?--dcdir needs a path}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'parity-report: unknown argument %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

cd "$root"
status=0

# --- the commit both boxes have to be on -------------------------------------
head=$(git rev-parse HEAD 2>/dev/null || echo none)
origin=$(git rev-parse --verify --quiet origin/main 2>/dev/null || echo missing)
printf 'head: %s\n' "$head"
printf 'origin/main: %s\n' "$origin"
printf 'branch: %s\n' "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo none)"
printf 'subject: %s\n' "$(git log -1 --format=%s 2>/dev/null || echo none)"
if [[ "$origin" != missing ]]; then
    ahead=$(git rev-list --count 'origin/main..HEAD' 2>/dev/null || echo 0)
    behind=$(git rev-list --count 'HEAD..origin/main' 2>/dev/null || echo 0)
    printf 'ahead: %s\n' "$ahead"
    printf 'behind: %s\n' "$behind"
    if ((ahead != 0 || behind != 0)); then
        status=1
    fi
fi

# --- tracked changes: the only divergence a commit cannot explain ------------
tracked=$(git status --porcelain --untracked-files=no)
if [[ -n "$tracked" ]]; then
    printf 'tracked-changes: %s\n' "$(printf '%s\n' "$tracked" | wc -l)"
    printf '%s\n' "$tracked" | sed 's/^/  /'
    status=1
else
    printf 'tracked-changes: 0\n'
fi

untracked=$(git status --porcelain --untracked-files=normal | awk '$1 == "??" {print}')
count=0
if [[ -n "$untracked" ]]; then
    count=$(printf '%s\n' "$untracked" | wc -l)
fi
printf 'untracked: %s\n' "$count"
if [[ -n "$untracked" ]]; then
    printf '%s\n' "$untracked" | sed 's/^/  /'
fi
printf 'stashes: %s\n' "$(git stash list | wc -l)"

# --- the build: the suites both boxes can run --------------------------------
printf '\n'
if [[ -f "$build_dir/CTestTestfile.cmake" ]]; then
    printf 'build-dir: %s\n' "$build_dir"
    mapfile -t suites < <(ctest --test-dir "$build_dir" -N 2>/dev/null \
        | sed -n 's/^ *Test *#[0-9]*: *//p' | sort)
    printf 'suites: %s\n' "${#suites[@]}"
    printf '%s\n' "${suites[@]}" | sed 's/^/  /'
else
    printf 'build-dir: %s (not configured)\n' "$build_dir"
    status=1
fi
for binary in monarchy-dcd monarchy-provision monarchy-ldap-tests; do
    if [[ -x "$build_dir/ui/$binary" ]]; then
        printf 'binary %s: present\n' "$binary"
    else
        printf 'binary %s: absent\n' "$binary"
        status=1
    fi
done

# --- optional: the installed domain, when a box is asked about one -----------
if [[ -n "$dcdir" ]]; then
    printf '\ndcdir: %s\n' "$dcdir"
    if [[ -f "$dcdir/dc.conf" ]]; then
        printf 'ports:\n'
        awk -F= 'tolower($1) ~ /port$/ {
                     gsub(/^[ \t]+|[ \t]+$/, "", $2)
                     printf "  %s=%s\n", $1, $2
                 }' "$dcdir/dc.conf" | sort -u
    else
        printf 'ports: no dc.conf\n'
        status=1
    fi
    # The health check is the only thing that asks whether a declared port is
    # actually bound, so its verdict is the part of this report a fresh install
    # can disagree about while every suite still passes.
    health=$(scripts/check-dc-health.sh "$dcdir" 2>&1 | tail -1) || status=1
    printf 'health: %s\n' "${health:-no output}"
fi

printf '\nparity: %s\n' "$([[ "$status" -eq 0 ]] && echo ok || echo diverged)"
exit "$status"
