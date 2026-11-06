#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Configure, build and test the tree: the check a change has to pass.
#
# Usage: scripts/ci.sh [--build-dir DIR] [--jobs N] [--with-ldap]
#
# The default build directory is removed first, so a stale CMake cache cannot
# hide a missing dependency or a source file that was never added to a target.
# A directory you name yourself is reused as-is, and the script says so.
#
# QT_QPA_PLATFORM=offscreen is exported because several suites link
# QApplication (the console, TLS, LDAP, DRSUAPI and EPM cases); without it they
# fail on a host with no display instead of testing anything.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${root}/build-ci
jobs=$(nproc 2>/dev/null || echo 2)
with_ldap=0

usage()
{
    sed -n '5,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

printf '== every suite passed\n'
