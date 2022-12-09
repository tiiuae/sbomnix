""" sbomnix utils """

# pylint: disable=invalid-name

import csv
import logging
import subprocess

from colorlog import ColoredFormatter, default_log_colors

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


def exec_cmd(cmd):
    """Run shell command cmd"""
    command_str = " ".join(cmd)
    logging.getLogger(LOGGER_NAME).debug("Running: %s", command_str)
    ret = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
    return ret.stdout


################################################################################
