#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Poll a GitHub repository's issue tracker and report what changed since the
# last run: new issues, edits and state changes. Pull requests are skipped,
# because they share the issues endpoint but are not issues.
#
#   scripts/poll-issues.sh [--repo OWNER/NAME] [--state-dir DIR]
#
# The repository is public, so no credential is required.
#
# The last answer's ETag is replayed with If-None-Match, so an unchanged
# tracker costs one 304 and prints nothing; a changed issue costs one more
# request, for its comments.
#
# Authentication: a GH_TOKEN or GITHUB_TOKEN in the environment wins, so a
# headless unit can be given a scoped token with neither `gh` nor an unlocked
# keyring on its path. Otherwise the token is borrowed from `gh` when it is
# installed and logged in: gh already holds the credential (on a desktop, in the
# login keyring, reached over the session bus), so this asks it rather than
# asking for one. That is 5000 requests an hour instead of the 60 an
# unauthenticated address gets, which a 2-minute timer on two hosts sharing one
# address exhausts before a comment is ever fetched. A host with no token, no
# `gh`, or no reachable session bus silently polls unauthenticated rather than
# failing; a token that is present but rejected is an error, not a downgrade.
# The token is handed to curl in a config file, never on its command line, so it
# does not appear in `ps`.
#
# What it reports goes to stdout, to `feed.log` under the state directory, and
# to a desktop notification when a session bus is available. The state
# directory also holds `seen.json`, the issue numbers already reported, so a
# restart does not re-announce old issues.
#
# A CHANGED issue also prints the comments it gained since the previous poll,
# with their authors, so a reply reads as a reply instead of "something changed".

set -euo pipefail

REPO="kubuntugamer/monarchy"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/monarchy-issues"

usage() {
    # The header: everything after the shebang, up to the first code line.
    sed -n '2,/^[^#]/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)      REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
        --repo=*)    REPO="${1#*=}"; shift ;;
        --state-dir) STATE_DIR="${2:?--state-dir needs a directory}"; shift 2 ;;
        --state-dir=*) STATE_DIR="${1#*=}"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           printf 'poll-issues: unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

mkdir -p "$STATE_DIR"
SEEN="$STATE_DIR/seen.json"
LOG="$STATE_DIR/feed.log"
ETAG="$STATE_DIR/etag"

[[ -s "$SEEN" ]] || printf '{}\n' > "$SEEN"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The environment's token first, so a unit does not depend on a session bus;
# then `gh`'s. Neither being present is not an error: the public API still
# answers 60 times an hour.
#
# `gh` is looked for on PATH and then where a user install puts it, because a
# system unit gets a fixed PATH that leaves out ~/.local/bin - so the poller
# authenticates without the unit being edited, which needs root.
gh_bin="$(command -v gh 2>/dev/null || true)"
if [[ -z "$gh_bin" && -x "${HOME:-}/.local/bin/gh" ]]; then
    gh_bin="$HOME/.local/bin/gh"
fi

curl_auth=()
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "$token" && -n "$gh_bin" ]]; then
    token="$("$gh_bin" auth token 2>/dev/null || true)"
fi
if [[ -n "$token" ]]; then
    (umask 077 && printf 'header = "Authorization: Bearer %s"\n' "$token" > "$tmp/auth")
    curl_auth=(--config "$tmp/auth")
fi
unset token

# A conditional request keeps an idle tracker down to a 304 with no body. It
# is only safe once a baseline exists: with an empty seen.json a 304 would
# leave the baseline unbuilt, and every later change would go unreported.
extra=()
if [[ -s "$ETAG" && "$(jq 'length' "$SEEN")" -gt 0 ]]; then
    extra=(-H "If-None-Match: $(cat "$ETAG")")
fi

code="$(curl -sS -o "$tmp/body.json" -D "$tmp/headers" -w '%{http_code}' \
    ${curl_auth[@]+"${curl_auth[@]}"} \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    ${extra[@]+"${extra[@]}"} \
    "https://api.github.com/repos/$REPO/issues?state=all&sort=updated&direction=desc&per_page=100" \
    2>"$tmp/curl.err" || echo 000)"

case "$code" in
    304) exit 0 ;;
    200) ;;
    000) printf 'poll-issues: cannot reach api.github.com: %s\n' \
             "$(tr -d '\n' < "$tmp/curl.err")" >&2; exit 1 ;;
    *)   printf 'poll-issues: the API answered %s for %s\n' "$code" "$REPO" >&2
         exit 1 ;;
esac

awk 'tolower($1) == "etag:" { gsub(/\r/, ""); print $2; exit }' \
    "$tmp/headers" > "$ETAG" || true

jq -c '.[] | select(.pull_request == null)
        | {number, title, state, updated_at, url: .html_url,
           author: (if .user then .user.login else "ghost" end)}' \
    "$tmp/body.json" > "$tmp/issues.jsonl"

# The first run only records a baseline; announcing every existing issue once
# would be noise, not news.
if [[ "$(jq 'length' "$SEEN")" -eq 0 ]]; then
    baseline="$(jq -s 'length' "$tmp/issues.jsonl")"
    jq -s 'reduce .[] as $i ({}; .[$i.number|tostring] =
                               {state: $i.state, updated_at: $i.updated_at})' \
        "$tmp/issues.jsonl" > "$tmp/seen.json"
    mv "$tmp/seen.json" "$SEEN"
    printf 'seeded %s issue(s) from %s; only later changes are reported\n' \
        "$baseline" "$REPO"
    exit 0
fi

# NEW      a number that was never seen
# CHANGED  a seen number whose updated_at moved
# STATE    a seen number whose state flipped (open <-> closed), which GitHub
#          usually folds into the edit above but not always
report="$(jq -r -s --slurpfile seen "$SEEN" '
    .[] as $i
    | ($seen[0][($i.number|tostring)]) as $old
    | if $old == null then "NEW\t\($i.number)\t\($i.title)\t\($i.author)\t\($i.url)"
      elif $old.state != $i.state then "STATE\t\($i.number)\t\($old.state)->\($i.state)\t\($i.title)\t\($i.url)"
      elif $old.updated_at != $i.updated_at then "CHANGED\t\($i.number)\t\($i.title)\t\($i.url)\t\($old.updated_at)"
      else empty end' "$tmp/issues.jsonl")"

jq -s 'reduce .[] as $i ({}; .[$i.number|tostring] =
                           {state: $i.state, updated_at: $i.updated_at})' \
    "$tmp/issues.jsonl" > "$tmp/seen.json"
mv "$tmp/seen.json" "$SEEN"

[[ -n "$report" ]] || exit 0

# The comments a changed issue gained since the previous poll, one line each.
# `since` is that issue's previous updated_at: GitHub has already counted every
# comment older than it, so only new or edited ones come back. A failure here
# is not a reason to lose the change report, so it is silent.
comments_since() {
    local number="$1" since="$2" body
    body="$(curl -sS ${curl_auth[@]+"${curl_auth[@]}"} \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/repos/$REPO/issues/$number/comments?per_page=100&since=$since" \
        2>/dev/null)" || return 0
    jq -r '.[] | "  " + (if .user then .user.login else "ghost" end)
                  + " @ " + .created_at + ": "
                  + (.body | gsub("\\s+"; " ") | .[0:240])' <<< "$body" 2>/dev/null || true
}

while IFS=$'\t' read -r kind number a b c; do
    case "$kind" in
        NEW)     printf '%s NEW     #%s %s — %s (%s)\n' "$(date -Is)" "$number" "$a" "$c" "$b" ;;
        CHANGED) printf '%s CHANGED #%s %s (%s)\n'      "$(date -Is)" "$number" "$a" "$b"
                 comments_since "$number" "$c" ;;
        STATE)   printf '%s STATE   #%s %s %s (%s)\n'   "$(date -Is)" "$number" "$a" "$b" "$c" ;;
    esac
done <<< "$report" | tee -a "$LOG"

if command -v notify-send >/dev/null 2>&1 && [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    notify-send --app-name=Monarchy "Issues changed in $REPO" \
        "$(printf '%s\n' "$report" | head -5 | cut -f1,2,3)" || true
fi
