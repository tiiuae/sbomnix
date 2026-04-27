# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared dataframe helpers."""

import csv
import logging
import urllib.error

import pandas as pd
from tabulate import tabulate

from common.errors import CsvLoadError
from common.log import LOG


def df_to_csv_file(df, name, loglevel=logging.INFO):
    """Write dataframe to csv file."""
    df.to_csv(
        path_or_buf=name, quoting=csv.QUOTE_ALL, sep=",", index=False, encoding="utf-8"
    )
    LOG.log(loglevel, "Wrote: %s", name)


def df_from_csv_file(name, exit_on_error=True):
    """Read csv file into dataframe."""
    LOG.debug("Reading: %s", name)
    try:
        df = pd.read_csv(name, keep_default_na=False, dtype=str)
        df.reset_index(drop=True, inplace=True)
        return df
    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        urllib.error.HTTPError,
        urllib.error.URLError,
    ) as error:
        if exit_on_error:
            raise CsvLoadError(name, error) from error
        LOG.debug("Error reading csv file '%s':\n%s", name, error)
        return None


def df_regex_filter(df, column, regex):
    """Return rows where column `column` values match the given regex."""
    LOG.debug("column:'%s', regex:'%s'", column, regex)
    return df[df[column].str.contains(regex, regex=True, na=False)]


def df_log(df, loglevel, tablefmt="presto"):
    """Log dataframe with given loglevel and tablefmt."""
    if LOG.level <= loglevel:
        if df is None or df.empty:
            return
        df = df.fillna("")
        table = tabulate(
            df, headers="keys", tablefmt=tablefmt, stralign="left", showindex=False
        )
        LOG.log(loglevel, "\n%s\n", table)
