# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for validating SPDX license identifiers."""

from functools import lru_cache

from license_expression import ExpressionError, get_spdx_licensing


@lru_cache(maxsize=1)
def _spdx_licensing():
    return get_spdx_licensing()


def canonicalize_spdx_license_id(identifier):
    """Return a canonical SPDX identifier for a single license key."""
    if not identifier:
        return None
    try:
        parsed = _spdx_licensing().parse(str(identifier), validate=True)
    except ExpressionError:
        return None
    return getattr(parsed, "key", None)
