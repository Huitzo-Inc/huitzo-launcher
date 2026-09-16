#!/bin/sh
# Copyright (c) 2026 Huitzo Inc. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

# The #B4 invariant, stated once and asserted by every installer e2e case.
#
# B4 was: the launcher, unable to find a wheel, fell back to PyPI, where the
# name `huitzo` resolves to an unrelated 0.2.0 placeholder ("MOVED - Huitzo CLI
# is now distributed via the native launcher"). Users ended up with a package
# that was not the CLI and a launcher that reported success.
#
# T2 deleted that fallback and T14 then moved the trigger: an interpreter the
# feed publishes no wheel for is no longer built on and refused, it provisions a
# managed CPython instead. So the guard cannot live on one job any more. It
# lives here, in two halves that between them cover every terminal state a run
# can reach:
#
#   installed <file>  a run that SUCCEEDED really installed the feed's wheel:
#                     the version is not 0.2.0, the manifest provenance says
#                     `github_release` with an ABI-keyed wheel (T8/M9), and the
#                     distribution in the venv agrees with the running CLI.
#   absent            a run that FAILED installed nothing at all: no manifest,
#                     and no huitzo distribution anywhere under $HUITZO_HOME.
#
# Usage:
#   HUITZO_HOME=... assert_install_outcome.sh installed <huitzo --version output>
#   HUITZO_HOME=... assert_install_outcome.sh absent
#
# Exit codes: 0 invariant holds, 1 it does not, 2 usage error.
set -eu

home="${HUITZO_HOME:?HUITZO_HOME must be set - never assert against a real home}"
PIP_LOG="${TMPDIR:-/tmp}/assert-install-outcome-pip.log"

# Anything shaped like an installed huitzo distribution, anywhere under the
# managed home. Deliberately broader than "the managed venv": a fallback that
# installed somewhere else would still be the bug.
huitzo_distributions() {
    find "$home" -path "*site-packages*" -name "huitzo*" 2>/dev/null || true
    find "$home" -name "huitzo-*.dist-info" 2>/dev/null || true
}

case "${1:-}" in
installed)
    out="${2:-}"
    [ -n "$out" ] || { echo "usage: $0 installed <version-output-file>" >&2; exit 2; }
    [ -f "$out" ] || { echo "::error::$out does not exist"; exit 1; }

    version=$(sed -n 's/^huitzo-cli \([0-9][^[:space:]]*\).*/\1/p' "$out" | head -1)
    if [ -z "$version" ]; then
        echo "::error::no 'huitzo-cli <version>' line in $out - the CLI never ran"
        cat "$out"
        exit 1
    fi
    if [ "$version" = "0.2.0" ]; then
        echo "::error::the CLI reports 0.2.0 - the PyPI placeholder is back (#B4)"
        exit 1
    fi

    manifest="$home/manifest.json"
    [ -f "$manifest" ] || { echo "::error::a successful install wrote no manifest at $manifest"; exit 1; }
    # T8/M9: provenance is derived from the wheel that was actually installed,
    # so "github_release" here is a fact about this install, not a default.
    if ! grep -q '"install_source": "github_release"' "$manifest"; then
        echo "::error::install_source is not github_release - this did not come from the release feed"
        cat "$manifest"
        exit 1
    fi
    if ! grep -qE '"wheel_platform": "[a-z0-9_-]+-cp3[0-9]+"' "$manifest"; then
        echo "::error::wheel_platform does not name an ABI-keyed feed wheel"
        cat "$manifest"
        exit 1
    fi
    if ! grep -q "\"huitzo_version\": \"$version\"" "$manifest"; then
        echo "::error::the manifest disagrees with the CLI that just ran ($version)"
        cat "$manifest"
        exit 1
    fi

    # ... and the distribution sitting in the venv is that same thing, rather
    # than something that merely happens to print a version.
    if ! "$home/venv/bin/python" -m pip show huitzo > "$PIP_LOG" 2>&1; then
        echo "::error::pip show huitzo found nothing in the managed venv"
        cat "$PIP_LOG"
        exit 1
    fi
    if ! grep -q "^Version: $version$" "$PIP_LOG"; then
        echo "::error::pip reports a different version than the CLI ($version)"
        cat "$PIP_LOG"
        exit 1
    fi
    if grep -qi "MOVED" "$PIP_LOG"; then
        echo "::error::the installed distribution is the 'MOVED' PyPI placeholder (#B4)"
        cat "$PIP_LOG"
        exit 1
    fi
    echo "confirmed: huitzo $version, installed from a github_release wheel, not the 0.2.0 stub"
    ;;
absent)
    if [ -e "$home/manifest.json" ]; then
        echo "::error::a run that failed still wrote a manifest"
        cat "$home/manifest.json"
        exit 1
    fi
    found=$(huitzo_distributions)
    if [ -n "$found" ]; then
        echo "::error::a huitzo distribution exists after a failed run - the stub is back (#B4)"
        echo "$found"
        exit 1
    fi
    echo "confirmed: no manifest and no huitzo distribution anywhere under $home"
    ;;
*)
    echo "usage: $0 installed <version-output-file> | absent" >&2
    exit 2
    ;;
esac
