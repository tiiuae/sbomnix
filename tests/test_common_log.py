#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Focused tests for shared logging levels."""

import logging

import pytest

from common.log import LOG, LOG_SPAM, LOG_TRACE, LOG_VERBOSE, set_log_verbosity


@pytest.mark.parametrize(
    ("verbosity", "level"),
    [
        (0, logging.INFO),
        (1, LOG_VERBOSE),
        (2, logging.DEBUG),
        (3, LOG_SPAM),
        (99, LOG_SPAM),
        (-1, logging.INFO),
    ],
)
def test_set_log_verbosity_maps_cli_levels_to_logging_levels(verbosity, level):
    try:
        set_log_verbosity(verbosity)
        assert LOG.level == level
    finally:
        set_log_verbosity(0)


def test_custom_log_level_names_are_registered():
    assert logging.getLevelName(LOG_VERBOSE) == "VERBOSE"
    assert logging.getLevelName(LOG_SPAM) == "SPAM"
    assert LOG_TRACE == LOG_SPAM


def test_verbose_level_is_between_info_and_debug():
    try:
        set_log_verbosity(1)
        assert LOG.isEnabledFor(logging.INFO)
        assert LOG.isEnabledFor(LOG_VERBOSE)
        assert not LOG.isEnabledFor(logging.DEBUG)
    finally:
        set_log_verbosity(0)
