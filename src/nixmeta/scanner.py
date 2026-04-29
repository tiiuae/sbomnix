#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

"""Summarize nixpkgs meta-attributes"""

import pathlib
import subprocess
from tempfile import NamedTemporaryFile

import pandas as pd

from common.df import df_from_csv_file, df_to_csv_file
from common.log import LOG, LOG_SPAM
from common.proc import exec_cmd, nix_cmd
from nixmeta.flake_metadata import get_flake_metadata, nixref_to_nixpkgs_path
from nixmeta.metadata_json import parse_json_metadata

###############################################################################


def _run_nix_env_metadata(cmd, stdout):
    """Run nix-env metadata scan while keeping successful eval warnings quiet."""
    ret = subprocess.run(
        cmd,
        encoding="utf-8",
        check=True,
        stdout=stdout,
        stderr=subprocess.PIPE,
    )
    if ret.stderr:
        LOG.debug("nix-env metadata stderr:\n%s", ret.stderr.strip())


class NixMetaScanner:
    """Scan nixpkgs meta-info"""

    def __init__(self):
        self.df_meta = None

    def scan(self, nixref):
        """
        Scan nixpkgs meta-info using nixpkgs version pinned in nixref;
        nixref can be a nix store path, flakeref or dynamical attribute set.
        """
        nixpkgs_path = nixref_to_nixpkgs_path(
            nixref,
            get_flake_metadata_fn=lambda flakeref: get_flake_metadata(
                flakeref,
                exec_cmd_fn=exec_cmd,
                nix_cmd_fn=nix_cmd,
                log=LOG,
            ),
            log=LOG,
            log_spam=LOG_SPAM,
        )
        if not nixpkgs_path:
            # try format which is understood by nix-env:
            #   https://ianthehenry.com/posts/how-to-learn-nix/chipping-away-at-flakes/
            # ownpkgs-nix-env.nix:
            #   { ... }:
            #     (builtins.getFlake "/tmp/ownpkgs-special-unstable").
            #     outputs.packages.${builtins.currentSystem}
            # and execute
            #   NIX_PATH="nixpkgs=/tmp/ownpkgs-special-unstable/ownpkgs-nix-env.nix"
            #   sbomnix /nix/store/outputpath-for-ownpkgs-special-unstable-flake-output
            nixpkgs_path = pathlib.Path(nixref)
        self.scan_path(nixpkgs_path)

    def scan_path(self, nixpkgs_path):
        """Scan nixpkgs meta-info using an already resolved nixpkgs path."""
        nixpkgs_path = pathlib.Path(nixpkgs_path)
        if not nixpkgs_path.exists():
            LOG.warning("Nixpkgs not in nix store: %s", nixpkgs_path.as_posix())
            return
        LOG.debug("nixpkgs: %s", nixpkgs_path)
        self._read_nixpkgs_meta(nixpkgs_path)

    def scan_expression(self, expression, *, impure=False):
        """Scan nixpkgs meta-info using an expression returning a package set."""
        prefix = "nixmeta_expr_"
        suffix = ".nix"
        with NamedTemporaryFile(
            mode="w",
            delete=True,
            encoding="utf-8",
            prefix=prefix,
            suffix=suffix,
        ) as f:
            f.write(expression)
            f.flush()
            self._read_nixpkgs_meta(
                pathlib.Path(f.name),
                enable_flakes=True,
                impure=impure,
            )

    def to_csv(self, csv_path, append=False):
        """Export meta-info to a csv file"""
        csv_path = pathlib.Path(csv_path)
        if append and csv_path.exists():
            df = df_from_csv_file(csv_path)
            self.df_meta = pd.concat([self.df_meta, df], ignore_index=True)
            self._drop_duplicates()
        if self.df_meta is None or self.df_meta.empty:
            LOG.info("Nothing to output")
            return
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        df_to_csv_file(self.df_meta, csv_path.absolute().as_posix())

    def to_df(self):
        """Return meta-info as dataframe"""
        return self.df_meta

    def _read_nixpkgs_meta(
        self,
        nixpkgs_path,
        *,
        enable_flakes=False,
        impure=False,
    ):
        prefix = "nixmeta_"
        suffix = ".json"
        with NamedTemporaryFile(delete=True, prefix=prefix, suffix=suffix) as f:
            LOG.info("Reading nixpkgs metadata from '%s'", nixpkgs_path.as_posix())
            cmd = [
                "nix-env",
                "-qa",
                "--meta",
                "--json",
                "-f",
                f"{nixpkgs_path.as_posix()}",
            ]
            if enable_flakes:
                cmd.extend(["--option", "experimental-features", "nix-command flakes"])
            if impure:
                cmd.append("--impure")
            cmd.extend(["--arg", "config", "{allowAliases=false;}"])
            _run_nix_env_metadata(cmd, stdout=f)
            LOG.debug("Generated meta.json: %s", f.name)
            LOG.info("Parsing nixpkgs metadata")
            self.df_meta = parse_json_metadata(f.name, log=LOG)
            self._drop_duplicates()

    def _drop_duplicates(self):
        if self.df_meta is None or self.df_meta.empty:
            return
        self.df_meta = self.df_meta.astype(str)
        self.df_meta.fillna("", inplace=True)
        uids = [
            "name",
            "version",
            "meta_license_short",
            "meta_license_spdxid",
            "meta_homepage",
        ]
        self.df_meta.sort_values(by=uids, inplace=True)
        self.df_meta.drop_duplicates(subset=uids, keep="last", inplace=True)


###############################################################################
