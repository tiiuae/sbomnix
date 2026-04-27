# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared logging configuration and logger access."""

import logging
import os

from colorlog import ColoredFormatter, default_log_colors

LOG_VERBOSE = 15
LOG_SPAM = logging.DEBUG - 1
LOG_TRACE = LOG_SPAM
LOG_LEVELS = [logging.INFO, LOG_VERBOSE, logging.DEBUG, LOG_SPAM]


class SbomnixLogger(logging.getLoggerClass()):
    """Project logger with sbomnix-specific verbose levels."""

    def verbose(self, msg, *args, **kwargs):
        """Log at the project VERBOSE level."""
        if self.isEnabledFor(LOG_VERBOSE):
            kwargs.setdefault("stacklevel", 2)
            self._log(LOG_VERBOSE, msg, args, **kwargs)

    def spam(self, msg, *args, **kwargs):
        """Log at the project SPAM level."""
        if self.isEnabledFor(LOG_SPAM):
            kwargs.setdefault("stacklevel", 2)
            self._log(LOG_SPAM, msg, args, **kwargs)

    def trace(self, msg, *args, **kwargs):
        """Log at the project TRACE level alias."""
        if self.isEnabledFor(LOG_TRACE):
            kwargs.setdefault("stacklevel", 2)
            self._log(LOG_TRACE, msg, args, **kwargs)


__all__ = [
    "LOG",
    "LOG_SPAM",
    "LOG_TRACE",
    "LOG_VERBOSE",
    "is_debug_enabled",
    "set_log_verbosity",
]


logging.addLevelName(LOG_VERBOSE, "VERBOSE")
logging.addLevelName(LOG_SPAM, "SPAM")
logging.setLoggerClass(SbomnixLogger)

LOG = logging.getLogger(os.path.abspath(__file__))


def set_log_verbosity(verbosity=0):
    """Set logging verbosity."""
    verbosity = min(len(LOG_LEVELS) - 1, max(verbosity, 0))
    _init_logging(verbosity)


def _init_logging(verbosity=0):
    """Initialize logging."""
    level = LOG_LEVELS[verbosity]
    if level <= logging.DEBUG:
        logformat = (
            "%(log_color)s%(levelname)-8s%(reset)s "
            "%(filename)s:%(funcName)s():%(lineno)d "
            "%(message)s"
        )
    else:
        logformat = "%(log_color)s%(levelname)-8s%(reset)s %(message)s"
    log_colors = {
        **default_log_colors,
        "INFO": "fg_bold_white",
        "VERBOSE": "fg_bold_cyan",
        "DEBUG": "fg_bold_white",
        "SPAM": "fg_bold_white",
    }
    if LOG.handlers:
        stream = LOG.handlers[0]
    else:
        stream = logging.StreamHandler()
    formatter = ColoredFormatter(
        logformat,
        log_colors=log_colors,
        stream=getattr(stream, "stream", None),
    )
    stream.setFormatter(formatter)
    if not LOG.handlers:
        LOG.addHandler(stream)
    LOG.setLevel(level)


def is_debug_enabled():
    """Return True when project logging is enabled for DEBUG details."""
    return LOG.isEnabledFor(logging.DEBUG)


set_log_verbosity(0)
