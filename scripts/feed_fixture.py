#!/usr/bin/env python3
# Copyright (c) 2026 Huitzo Inc. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

"""
Module: scripts.feed_fixture
Description: Derives the installer e2e's feed premises from the live release
    feed, so a case states which wheels the feed must (not) carry and fails
    with that sentence when the feed moves, instead of with a stray `grep`.
    Stdlib only: it runs on the Python 3.11 of the T14 container.

Why this exists (#72): the T14 case assumed the live feed publishes no cp311
wheel. The feed shipped one, the installer correctly reused the system 3.11,
and the case failed on `grep "Skipping Python 3.11"` - a symptom that said
nothing about the real cause. The case now builds its own feed from the live
one with the interpreter's wheel removed, so the premise is constructed rather
than hoped for, and the live feed is only asked for what it must still have.

Usage:
    feed_fixture.py require ABI
        Exit 0 when the newest cli-v* release carries `linux-<arch>-ABI`.
    feed_fixture.py fixture DIR ABI BASE_URL
        Write DIR/releases and DIR/cli-release.json: the newest cli-v*
        manifest minus every `*-ABI` wheel, served from BASE_URL. Print the
        live release's download-dir URL, for HUITZO_RELEASE_DOWNLOAD_URL.

Exit codes: 0 premise holds, 1 it does not or the feed is unreadable, 2 usage.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import urllib.request

RELEASES = "https://api.github.com/repos/Huitzo-Inc/huitzo-launcher/releases"


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "huitzo-feed-fixture"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def latest_manifest() -> tuple[str, dict]:
    """(tag, cli-release.json) of the newest cli-v* release, by version."""
    releases = json.loads(get(RELEASES))
    cli = []
    for r in releases:
        m = re.fullmatch(r"cli-v(\d+)\.(\d+)\.(\d+)", r.get("tag_name", ""))
        if m and not r.get("draft"):
            cli.append((tuple(map(int, m.groups())), r))
    if not cli:
        fail("the live feed lists no cli-v* release")
    _, release = max(cli, key=lambda c: c[0])
    asset = next((a for a in release["assets"] if a["name"] == "cli-release.json"), None)
    if asset is None:
        fail(f"{release['tag_name']} has no cli-release.json asset")
    return release["tag_name"], json.loads(get(asset["browser_download_url"]))


def fail(msg: str) -> None:
    print(f"::error::premise no longer holds: {msg}")
    sys.exit(1)


def platform_prefix() -> str:
    arch = platform.machine()
    return f"linux-{'aarch64' if arch in ('aarch64', 'arm64') else arch}"


def main(argv: list[str]) -> None:
    prefix = platform_prefix()
    if len(argv) == 3 and argv[1] == "require":
        abi = argv[2]
        tag, manifest = latest_manifest()
        key = f"{prefix}-{abi}"
        if key not in manifest["wheels"]:
            fail(
                f"{tag} publishes no {key} wheel (it carries "
                f"{sorted(k for k in manifest['wheels'] if k.startswith(prefix))}); "
                "this case needs a system Python of that ABI to be installable"
            )
        print(f"confirmed: {tag} publishes {key}")
    elif len(argv) == 5 and argv[1] == "fixture":
        out, abi, base = argv[2:]
        tag, manifest = latest_manifest()
        manifest["wheels"] = {
            k: v for k, v in manifest["wheels"].items() if not k.endswith(f"-{abi}")
        }
        if not any(k.startswith(f"{prefix}-") for k in manifest["wheels"]):
            fail(f"{tag} carries no {prefix} wheel other than {abi}; nothing to provision")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "cli-release.json"), "w") as f:
            json.dump(manifest, f)
        listing = [
            {
                "tag_name": tag,
                "draft": False,
                "prerelease": True,
                "created_at": "2026-09-01T00:00:00Z",
                "assets": [
                    {
                        "name": "cli-release.json",
                        "browser_download_url": f"{base}/cli-release.json",
                    }
                ],
            }
        ]
        with open(os.path.join(out, "releases"), "w") as f:
            json.dump(listing, f)
        kept = sorted(k for k in manifest["wheels"] if k.startswith(prefix))
        print(f"fixture from {tag}: dropped *-{abi}, {prefix} keeps {kept}", file=sys.stderr)
        print(f"https://github.com/Huitzo-Inc/huitzo-launcher/releases/download/{tag}")
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
