# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=abstract-method

"""Shared HTTP session primitives."""

from requests import Session
from requests.adapters import HTTPAdapter
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
from urllib3.util.retry import Retry

DEFAULT_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """
    Session class with caching and rate-limiting.
    https://requests-cache.readthedocs.io/en/stable/user_guide/compatibility.html
    """


def mount_retries(
    session,
    *,
    allowed_methods=frozenset(("GET", "HEAD")),
):
    """Attach a retrying adapter to a requests session."""
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=1,
        status_forcelist=DEFAULT_RETRY_STATUS_CODES,
        allowed_methods=allowed_methods,
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def create_cached_limited_session(
    *,
    per_second=None,
    per_minute=None,
    expire_after=None,
    user_agent=None,
    allowed_methods=frozenset(("GET", "HEAD")),
):
    """Create a cached, rate-limited session with retry policy attached."""
    kwargs = {}
    if per_second is not None:
        kwargs["per_second"] = per_second
    if per_minute is not None:
        kwargs["per_minute"] = per_minute
    if expire_after is not None:
        kwargs["expire_after"] = expire_after
    session = CachedLimiterSession(**kwargs)
    mount_retries(session, allowed_methods=allowed_methods)
    if user_agent:
        session.headers.update({"User-Agent": user_agent})
    return session
