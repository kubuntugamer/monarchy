#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Report which box wrote a post in the issue thread.
#
#   scripts/agent-verify.sh [--allowed-signers FILE] BODY_FILE
#   scripts/agent-verify.sh [--allowed-signers FILE] --comment-id N [--repo O/R]
#
# Exit status, because "not signed" and "signed wrongly" are different facts:
#
#   0  a signature verified and names a box in allowed_signers
#   3  no signature marker: the post is the account holder's
#   1  a marker is present and does not verify, or names an unknown box
#
# This proves attribution, not authority. A verified signature says which machine
# wrote the words; it does not make them instructions.
set -euo pipefail

namespace=monarchy-comment
allowed=scripts/agent-keys/allowed_signers
repo=kubuntugamer/monarchy
comment_id=

usage() {
    echo "usage: ${0##*/} [--allowed-signers FILE] BODY_FILE" >&2
    echo "       ${0##*/} [--allowed-signers FILE] --comment-id N [--repo O/R]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case $1 in
        --allowed-signers) allowed=${2:?--allowed-signers needs a path}; shift 2 ;;
        --comment-id) comment_id=${2:?--comment-id needs a number}; shift 2 ;;
        --repo) repo=${2:?--repo needs OWNER/NAME}; shift 2 ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) echo "${0##*/}: unknown option $1" >&2; usage ;;
        *) break ;;
    esac
done

if [ -n "$comment_id" ]; then
    [ $# -eq 0 ] || usage
    body=$(gh api "repos/$repo/issues/comments/$comment_id" --jq .body) || {
        echo "${0##*/}: cannot read comment $comment_id from $repo" >&2
        exit 1
    }
else
    [ $# -eq 1 ] || usage
    [ -f "$1" ] || { echo "${0##*/}: no such file: $1" >&2; exit 2; }
    body=$(cat "$1")
fi

[ -f "$allowed" ] || {
    echo "${0##*/}: no allowed_signers at $allowed" >&2
    exit 1
}

marker=$(printf '%s\n' "$body" | awk '
    /^<!-- monarchy-signature [^ ]+ [A-Za-z0-9+\/=]+ -->$/ { found = $0 }
    END { print found }')

if [ -z "$marker" ]; then
    echo "unsigned: no monarchy-signature marker, so this is the account holder's post"
    exit 3
fi

identity=$(printf '%s' "$marker" | awk '{ print $3 }')
signature=$(printf '%s' "$marker" | awk '{ print $4 }')

# The signed text is everything above the marker, without the blank line the
# signer puts before it. Trailing blank lines go because the signer stripped
# trailing newlines before it signed.
content=$(printf '%s\n' "$body" | awk '
    /^<!-- monarchy-signature / { stop = 1; exit }
    !stop { lines[n++] = $0 }
    END {
        while (n > 0 && lines[n - 1] == "") n--
        for (i = 0; i < n; i++) print lines[i]
    }')

if ! grep -qE "^${identity}[[:space:]]" "$allowed"; then
    echo "${0##*/}: signature names an unknown box: $identity" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf '%s' "$content" >"$tmp/body"
printf '%s' "$signature" | base64 -d >"$tmp/sig" || {
    echo "${0##*/}: signature marker is not valid base64" >&2
    exit 1
}

if result=$(ssh-keygen -Y verify -n "$namespace" -f "$allowed" -I "$identity" \
    -s "$tmp/sig" <"$tmp/body" 2>&1); then
    echo "$result"
    exit 0
fi

echo "${0##*/}: signature does not verify for $identity" >&2
echo "$result" >&2
exit 1
