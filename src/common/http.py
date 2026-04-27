# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=abstract-method

"""Shared HTTP session primitives."""

from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """
    Session class with caching and rate-limiting.
    https://requests-cache.readthedocs.io/en/stable/user_guide/compatibility.html
    """
