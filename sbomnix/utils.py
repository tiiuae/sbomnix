# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

""" sbomnix utils """

import re
import sys
import csv
import logging
import subprocess
from importlib.metadata import version, PackageNotFoundError
from tabulate import tabulate
from colorlog import ColoredFormatter, default_log_colors
import pandas as pd

###############################################################################

LOGGER_NAME = "sbomnix-logger"
LOG_SPAM = logging.DEBUG - 1

###############################################################################


def df_to_csv_file(df, name):
    """Write dataframe to csv file"""
    df.to_csv(
        path_or_buf=name, quoting=csv.QUOTE_ALL, sep=",", index=False, encoding="utf-8"
    )
    logging.getLogger(LOGGER_NAME).info("Wrote: %s", name)


def df_from_csv_file(name):
    """Read csv file into dataframe"""
    logging.getLogger(LOGGER_NAME).debug("Reading: %s", name)
    try:
        df = pd.read_csv(name, keep_default_na=False, dtype=str)
        df.reset_index(drop=True, inplace=True)
        return df
    except pd.errors.ParserError:
        logging.getLogger(LOGGER_NAME).fatal("Not a csv file: '%s'", name)
        sys.exit(1)


def df_regex_filter(df, column, regex):
    """Return rows where column 'column' values match the given regex"""
    logging.getLogger(LOGGER_NAME).debug("column:'%s', regex:'%s'", column, regex)
    return df[df[column].str.contains(regex, regex=True, na=False)]


def df_log(df, loglevel, tablefmt="presto"):
    """Log dataframe with given loglevel and tablefmt"""
    if logging.getLogger(LOGGER_NAME).level <= loglevel:
        if df.empty:
            return
        df = df.fillna("")
        table = tabulate(
            df, headers="keys", tablefmt=tablefmt, stralign="left", showindex=False
        )
        logging.getLogger(LOGGER_NAME).log(loglevel, "\n%s\n", table)


def setup_logging(verbosity=1):
    """Setup logging with specified verbosity"""
    project_logger = logging.getLogger(LOGGER_NAME)

    if verbosity == 0:
        level = logging.NOTSET
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    else:
        level = LOG_SPAM

    if level <= logging.DEBUG:
        logformat = (
            "%(log_color)s%(levelname)-8s%(reset)s "
            "%(filename)s:%(funcName)s():%(lineno)d "
            "%(message)s"
        )
    else:
        logformat = "%(log_color)s%(levelname)-8s%(reset)s %(message)s"

    default_log_colors["INFO"] = "fg_bold_white"
    default_log_colors["DEBUG"] = "fg_bold_white"
    default_log_colors["SPAM"] = "fg_bold_white"
    formatter = ColoredFormatter(logformat, log_colors=default_log_colors)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logging.addLevelName(LOG_SPAM, "SPAM")
    project_logger.addHandler(stream)
    project_logger.setLevel(level)


def exec_cmd(cmd, raise_on_error=True, return_error=False):
    """Run shell command cmd"""
    command_str = " ".join(cmd)
    logging.getLogger(LOGGER_NAME).debug("Running: %s", command_str)
    try:
        ret = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
        return ret.stdout
    except subprocess.CalledProcessError as error:
        logging.getLogger(LOGGER_NAME).debug(
            "Error running shell command:\n cmd:   '%s'\n stdout: %s\n stderr: %s",
            command_str,
            error.stdout,
            error.stderr,
        )
        if raise_on_error:
            raise error
        if return_error:
            return error
        return None


def regex_match(regex, string):
    """Return True if regex matches string"""
    if not regex or not string:
        return False
    return re.match(regex, string) is not None


def get_version(package="sbomnix"):
    """Return package version string"""
    versionstr = ""
    try:
        versionstr = version(package)
    except PackageNotFoundError:
        versionstr = "0.0.0"
    return versionstr


################################################################################
