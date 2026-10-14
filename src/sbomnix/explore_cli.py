#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Andrzej Piotrowski
#
# SPDX-License-Identifier: Apache-2.0

"""CLI wrapper: run sbomnix and auto-export to SBOM Explorer."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from common.log import LOG, set_log_verbosity


def main():
    """Entry point for sbomnix-explore CLI."""
    parser = argparse.ArgumentParser(
        description="Run sbomnix and export output to SBOM Explorer format"
    )
    parser.add_argument("NIXREF", help="Nix store path or flakeref")
    parser.add_argument("PRODUCT_ID", help="Explorer product ID")
    parser.add_argument("VARIANT", nargs="?", default="nix", help="Variant label")
    parser.add_argument("NAME", nargs="?", help="Display name")
    parser.add_argument(
        "--explorer-dir",
        default="",
        help="Explorer root dir (auto-detected if omitted)",
    )
    parser.add_argument("--buildtime", action="store_true", help="Build-time deps")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()
    set_log_verbosity(args.verbose)

    explorer_dir = args.explorer_dir or _find_explorer_dir()
    if not explorer_dir:
        LOG.fatal("Could not find SBOM Explorer (docs/ or site/). Set --explorer-dir.")
        sys.exit(1)
    explorer_dir = Path(explorer_dir).resolve()
    LOG.info("Explorer directory: %s", explorer_dir)

    cmd = [
        sys.executable,
        "-m",
        "sbomnix",
        args.NIXREF,
        "--cdx",
        "sbom.cdx.json",
        "--csv",
        "",  # disable csv
        "--spdx",
        "",  # disable spdx
        "--explorer-dir",
        str(explorer_dir),
        "--explorer-id",
        args.PRODUCT_ID,
        "--explorer-variant",
        args.VARIANT,
    ]
    if args.NAME:
        cmd.extend(["--explorer-name", args.NAME])
    if args.buildtime:
        cmd.append("--buildtime")

    LOG.info("Running: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)
    LOG.info("Done. Product '%s' added to Explorer at %s", args.PRODUCT_ID, explorer_dir)


def _find_explorer_dir():
    """Search for Explorer root directory."""
    search = ["./docs", "./site", "../docs", "../site"]
    for rel in search:
        p = Path(rel)
        if (p / "data" / "manifest.json").exists():
            return str(p.resolve())
    return None


if __name__ == "__main__":
    main()
