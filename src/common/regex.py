# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Small regex helpers kept for compatibility with older call sites."""

import re


def regex_match(regex, string):
    """Return true if ``regex`` matches ``string``."""
    if not regex or not string:
        return False
    return re.match(regex, string) is not None
