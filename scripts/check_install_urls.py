#!/usr/bin/env python3
# Copyright (c) 2026 Huitzo Inc. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

"""
Module: scripts.check_install_urls
Description: Fetches every install URL this repository ships to a user and
    fails when one does not serve an installer. Stdlib only, so it runs
    identically on a laptop and on a GitHub-hosted runner.

Why this exists (#B1): `https://huitzo.ai/install.sh` was documented as the
one-command bootstrap for months. It answered 200 — with the Hub single-page
app. `curl … | sh` therefore piped HTML into a shell. Nothing in CI fetched a
documented URL, so nothing noticed. A status check alone would not have
noticed either: the failure mode is a 200 with the wrong content type.

What counts as a failure:
    - a non-2xx status                      (the URL is simply broken)
    - an HTML content type                  (a web page, not a script)
    - a body that does not look like a shell/PowerShell installer

What is tolerated, with a warning:
    - 403/429 from a raw.githubusercontent.com / github.com host. Those are
      rate limits on a shared runner IP, not a claim about the URL. A wrong
      content type is never tolerated.

Usage:
    check_install_urls.py                 # scan the default file set
    check_install_urls.py --list          # print the URLs and exit
    check_install_urls.py FILE [FILE ...] # scan specific files

Exit codes: 0 clean, 1 findings remain, 2 usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every file that can put an install URL in front of a human: the two docs a
# user reads, and the prober line the launcher prints when `huitzo` is missing.
DEFAULT_SOURCES = (
    "README.md",
    "docs/SUPPORT_MATRIX.md",
    "src/prober.rs",
)

# An install URL is one whose path ends in the installer we publish. Other URLs
# in these files (the releases page, an example proxy) are deliberately out of
# scope: a releases page IS html.
INSTALL_URL = re.compile(r"https?://[^\s\"'`)<>\\]*install\.(?:sh|ps1)")

TIMEOUT_SECONDS = 30

# Positive evidence that the body is the installer and not a page that happens
# to be served as text. install.sh opens with a shebang; install.ps1 has no
# shebang, so key off content it must contain.
SHELL_MARKERS = ("#!/bin/sh", "#!/usr/bin/env sh", "#!/bin/bash")
PS1_MARKERS = ("$ErrorActionPreference", "Write-Host", "param(")

RATE_LIMIT_HOSTS = ("raw.githubusercontent.com", "github.com", "api.github.com")


def collect_urls(paths: list[Path]) -> dict[str, list[str]]:
    """Map each install URL to the `file:line` occurrences that ship it."""
    found: dict[str, list[str]] = {}
    for path in paths:
        if not path.is_file():
            print(f"error: no such file: {path}", file=sys.stderr)
            raise SystemExit(2)
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in INSTALL_URL.finditer(line):
                rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
                found.setdefault(match.group(0), []).append(f"{rel}:{lineno}")
    return found


def looks_like_installer(url: str, body: str) -> bool:
    markers = PS1_MARKERS if url.endswith(".ps1") else SHELL_MARKERS
    return any(marker in body for marker in markers)


def check(url: str, where: list[str]) -> tuple[bool, str]:
    """Fetch `url`. Returns (ok, message); ok=True also covers a tolerated skip."""
    origins = ", ".join(where)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "huitzo-launcher-url-contract-check"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            content_type = (response.headers.get("Content-Type") or "").lower()
            body = response.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        host = urllib.parse.urlparse(url).hostname or ""
        if e.code in (403, 429) and host in RATE_LIMIT_HOSTS:
            return True, f"SKIP {url}\n      HTTP {e.code} from {host} — rate limit, not a verdict on the URL"
        return False, f"FAIL {url}\n      HTTP {e.code} {e.reason}\n      shipped at: {origins}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return False, f"FAIL {url}\n      could not be fetched: {e}\n      shipped at: {origins}"

    if not 200 <= status < 300:
        return False, f"FAIL {url}\n      HTTP {status}\n      shipped at: {origins}"

    # The huitzo.ai failure exactly: 200, and an SPA.
    if "html" in content_type:
        return False, (
            f"FAIL {url}\n"
            f"      HTTP {status} but Content-Type is '{content_type}' — this URL serves a\n"
            f"      web page, and `curl … | sh` would pipe HTML into a shell (#B1).\n"
            f"      shipped at: {origins}"
        )

    if not looks_like_installer(url, body):
        return False, (
            f"FAIL {url}\n"
            f"      HTTP {status}, Content-Type '{content_type}', but the body does not look\n"
            f"      like the installer it claims to be.\n"
            f"      shipped at: {origins}"
        )

    return True, f"ok   {url}  [{status}, {content_type or 'no content-type'}]  ({origins})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", help="files to scan (default: the shipped doc set)")
    parser.add_argument("--list", action="store_true", help="print the URLs found and exit")
    args = parser.parse_args()

    paths = (
        [Path(f).resolve() for f in args.files]
        if args.files
        else [REPO_ROOT / name for name in DEFAULT_SOURCES]
    )

    urls = collect_urls(paths)
    if not urls:
        # The docs always ship at least one install URL. Finding none means the
        # scan is pointed at the wrong files, which must not read as "clean".
        print("error: no install URLs found — the scan found nothing to check", file=sys.stderr)
        for path in paths:
            print(f"  scanned: {path}", file=sys.stderr)
        return 2

    if args.list:
        for url, where in sorted(urls.items()):
            print(f"{url}  ({', '.join(where)})")
        return 0

    print(f"Checking {len(urls)} install URL(s) from {len(paths)} file(s):")
    failures = 0
    for url, where in sorted(urls.items()):
        ok, message = check(url, where)
        print(f"  {message}")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"{failures} install URL(s) do not serve an installer.")
        return 1
    print("All install URLs serve an installer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
