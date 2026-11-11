#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Post a comment signed by the box that wrote it.
#
#   scripts/agent-post.sh BODY_FILE
#   scripts/agent-post.sh --dry-run BODY_FILE     # sign and print, post nothing
#   scripts/agent-post.sh --repo O/R --issue N BODY_FILE
#
# This is the only path an unattended run should post through: it signs first and
# fails closed if signing fails, so a machine-started turn cannot leave an
# unsigned comment that reads as the account holder's. Signing is attribution,
# not authority - see TESTING.md section 6.
set -euo pipefail

repo=kubuntugamer/monarchy
issue=7
dry_run=0

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

while [ $# -gt 0 ]; do
    case $1 in
        --repo) repo=${2:?--repo needs OWNER/NAME}; shift 2 ;;
        --issue) issue=${2:?--issue needs a number}; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
        --) shift; break ;;
        -*) echo "${0##*/}: unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
[ $# -eq 1 ] || { echo "usage: ${0##*/} [--dry-run] [--repo O/R] [--issue N] BODY_FILE" >&2; exit 2; }
body=$1
[ -f "$body" ] || { echo "${0##*/}: no such file: $body" >&2; exit 2; }

signed=$(mktemp)
trap 'rm -f "$signed"' EXIT

"$root/scripts/agent-sign.sh" "$body" >"$signed" || {
    echo "${0##*/}: signing failed; refusing to post unsigned" >&2
    exit 1
}

if [ "$dry_run" -eq 1 ]; then
    echo "would post to $repo#$issue:"
    cat "$signed"
    exit 0
fi

gh issue comment "$issue" --repo "$repo" -F "$signed"
