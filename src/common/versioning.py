# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared version parsing and comparison helpers."""

import re

import packaging.version

from common.log import LOG, LOG_SPAM


def number_distance(n1, n2):
    """
    Return float value between [0.0,1.0] indicating the distance
    between two non-negative numbers.
    Returns 1.0 if the two numbers are equal.
    Returns 0.0 if either argument is not a non-negative number.
    """
    if (
        not isinstance(n1, (float, int))
        or not isinstance(n2, (float, int))
        or n1 < 0
        or n2 < 0
    ):
        return 0.0
    min_n = min(n1, n2)
    max_n = max(n1, n2)
    if max_n == 0:
        return 1.0
    if min_n == 0:
        min_n += 1
        max_n += 1
    return min_n / max_n


def version_distance(v1, v2):
    """
    Return float value between [0.0,1.0] indicating the closeness
    of the given two version number strings.
    """
    v1 = str(v1)
    v2 = str(v2)
    v1_clean = re.sub(r"[^0-9.]+", "", v1)
    v2_clean = re.sub(r"[^0-9.]+", "", v2)
    re_vsplit = re.compile(r".*?(?P<ver_beg>[0-9][0-9]*)(?P<ver_end>.*)$")
    match = re.match(re_vsplit, v1_clean)
    if not match:
        LOG.debug("Unexpected v1 version '%s'", v1)
        return 0.0
    v1_major = match.group("ver_beg")
    v1_minor = match.group("ver_end").replace(".", "")
    v1_float = float(v1_major + "." + v1_minor)
    match = re.match(re_vsplit, v2_clean)
    if not match:
        LOG.debug("Unexpected v2 version '%s'", v2)
        return 0.0
    v2_major = match.group("ver_beg")
    v2_minor = match.group("ver_end").replace(".", "")
    v2_float = float(v2_major + "." + v2_minor)
    return number_distance(v1_float, v2_float)


def parse_version(ver_str):
    """
    Return comparable version object from the given version string.
    Returns None if the version string can not be converted to version object.
    """
    ver_str = str(ver_str)
    if not ver_str:
        return None
    re_ver = re.compile(r".*?(?P<ver_beg>[0-9][0-9.]*)(?P<ver_end>.*)$")
    match = re_ver.match(ver_str)
    if not match:
        LOG.debug("Unable to parse version '%s'", ver_str)
        return None
    ver_beg = match.group("ver_beg").rstrip(".")
    ver_end = match.group("ver_end")
    ver_end = re.sub(r"[^0-9.]+", "", ver_end).lstrip(".")
    if ver_end:
        ver_end = f"+{ver_end}"
    else:
        ver_end = ""
    ver_end = ver_end.rstrip(".")
    ver = f"{ver_beg}{ver_end}"
    ver = re.sub(r"\.+", ".", ver)
    LOG.log(LOG_SPAM, "%s --> %s", ver_str, ver)
    if not ver:
        LOG.debug("Invalid version '%s'", ver_str)
        return None
    return packaging.version.parse(ver)
