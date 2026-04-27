# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared HTTP helpers for repology.org clients."""

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from common.http import CachedLimiterSession

REPOLOGY_CACHE_SECONDS = 6 * 60 * 60
REPOLOGY_REQUEST_TIMEOUT = 60
REPOLOGY_USER_AGENT = "repology_cli/0 (https://github.com/tiiuae/sbomnix/)"


def create_repology_session():
    """Return a cached, rate-limited, retrying HTTP session."""
    session = CachedLimiterSession(
        per_second=1,
        expire_after=REPOLOGY_CACHE_SECONDS,
    )
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(("GET", "HEAD")),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": REPOLOGY_USER_AGENT})
    return session


DEFAULT_REPOLOGY_SESSION = create_repology_session()
