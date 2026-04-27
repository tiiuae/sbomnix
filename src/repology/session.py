# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared HTTP helpers for repology.org clients."""

from common.http import create_cached_limited_session

REPOLOGY_CACHE_SECONDS = 6 * 60 * 60
REPOLOGY_REQUEST_TIMEOUT = 60
REPOLOGY_USER_AGENT = "repology_cli/0 (https://github.com/tiiuae/sbomnix/)"


def create_repology_session():
    """Return a cached, rate-limited, retrying HTTP session."""
    return create_cached_limited_session(
        per_second=1,
        expire_after=REPOLOGY_CACHE_SECONDS,
        user_agent=REPOLOGY_USER_AGENT,
    )


DEFAULT_REPOLOGY_SESSION = create_repology_session()
