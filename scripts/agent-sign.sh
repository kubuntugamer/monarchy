#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Mark an agent comment body with the box that wrote it.
#
#   scripts/agent-sign.sh [--key KEY] [--identity NAME] BODY_FILE
#
# Prints the body unchanged, then one HTML comment carrying an SSH signature:
#
#   <!-- monarchy-signature box-b AAAAB3Nza... -->
#
# A signature names a box; it grants no authority. That is deliberate: #7 settled
# that no signature is authority, so this marker says which machine wrote the
# text and nothing about whether the text may be obeyed. A key that conferred
# authority would be a credential worth stealing; this one is only worth its
# honesty.
#
# The private half stays on the box and the public half is committed in
# scripts/agent-keys/allowed_signers. Both boxes post under one GitHub account, so
# this marker is the only thing that separates them in the thread; a post with no
# marker is the account holder's, which is why the human never signs.
set -euo pipefail

namespace=monarchy-comment
key=${MONARCHY_AGENT_KEY:-$HOME/.ssh/monarchy-agent-$(hostname -s)}
identity=

usage() {
    echo "usage: ${0##*/} [--key KEY] [--identity NAME] BODY_FILE" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case $1 in
        --key) key=${2:?--key needs a path}; shift 2 ;;
        --identity) identity=${2:?--identity needs a name}; shift 2 ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) echo "${0##*/}: unknown option $1" >&2; usage ;;
        *) break ;;
    esac
done
[ $# -eq 1 ] || usage
body=$1

[ -f "$body" ] || { echo "${0##*/}: no such file: $body" >&2; exit 2; }
[ -f "$key" ] || {
    echo "${0##*/}: no signing key at $key; see TESTING.md section 6" >&2
    exit 2
}

# The key's own comment names the box, so the identity cannot drift from the key
# it is written beside.
if [ -z "$identity" ]; then
    identity=$(awk 'NF >= 3 { print $3; exit }' "$key.pub" 2>/dev/null || true)
fi
[ -n "$identity" ] || {
    echo "${0##*/}: cannot read an identity from $key.pub; pass --identity" >&2
    exit 2
}

# GitHub hands a reader the body without its trailing newlines, so those are not
# part of anything verifiable; sign the text as it reads back.
content=$(cat "$body")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf '%s' "$content" >"$tmp/body"
ssh-keygen -Y sign -n "$namespace" -f "$key" "$tmp/body" >/dev/null 2>&1 || {
    echo "${0##*/}: ssh-keygen could not sign with $key" >&2
    exit 1
}

printf '%s\n\n<!-- monarchy-signature %s %s -->\n' \
    "$content" "$identity" "$(base64 -w0 <"$tmp/body.sig")"
