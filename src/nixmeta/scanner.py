#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

"""Summarize nixpkgs meta-attributes"""

import pathlib
from tempfile import NamedTemporaryFile

import pandas as pd

from common.df import df_from_csv_file, df_to_csv_file
from common.log import LOG
from common.proc import exec_cmd, nix_cmd
from nixmeta.metadata_json import parse_json_metadata

###############################################################################


class NixMetaScanner:
    """Scan nixpkgs meta-info"""

    def __init__(self):
        self.df_meta = None
        self._had_failures = False

    @property
    def had_failures(self):
        """True if at least one batch eval failed during the last scan_store_names call."""
        return self._had_failures

    def scan_store_names(self, names, *, impure=False, batch_size=2000, pkgs_expr=None):
        """Look up nixpkgs metadata for the given list of store-path names."""
        self._had_failures = False
        if not names or pkgs_expr is None:
            return
        meta_nix = pathlib.Path(__file__).parent / "meta.nix"
        frames = []
        saw_success = False
        for i in range(0, len(names), batch_size):
            batch = names[i : i + batch_size]
            # Store-path names are alphanumeric + [-_.+?=], safe to embed without escaping.
            names_nix = " ".join(f'"{n}"' for n in batch)
            pkgs_arg = f" pkgs = {pkgs_expr};"
            apply_expr = f"f: f {{ names = [{names_nix}];{pkgs_arg} }}"
            cmd = nix_cmd(
                "eval",
                "--json",
                "--file",
                str(meta_nix),
                "--apply",
                apply_expr,
                impure=impure,
            )
            ret = exec_cmd(
                cmd, raise_on_error=False, return_error=True, log_error=False
            )
            if ret is None or ret.returncode != 0:
                self._had_failures = True
                LOG.warning(
                    "meta.nix eval failed for batch of %d names (offset %d); "
                    "metadata for those packages will be missing",
                    len(batch),
                    i,
                )
                continue
            saw_success = True
            prefix, suffix = "nixmeta_names_", ".json"
            with NamedTemporaryFile(
                mode="w",
                delete=True,
                encoding="utf-8",
                prefix=prefix,
                suffix=suffix,
            ) as f:
                f.write(ret.stdout)
                f.flush()
                df = parse_json_metadata(f.name, log=LOG)
                if df is not None and not df.empty:
                    frames.append(df)
        if frames:
            LOG.info("Parsing nixpkgs metadata from meta.nix output")
            self.df_meta = pd.concat(frames, ignore_index=True)
            self._drop_duplicates()
        elif saw_success:
            # Distinguish a successful lookup with zero matches from an eval failure.
            self.df_meta = pd.DataFrame()

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
