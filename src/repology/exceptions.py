# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=unnecessary-pass

"""Repology exceptions"""


class RepologyError(Exception):
    """Base class for exceptions raised in the repology modules"""

    pass


class RepologyNoMatchingPackages(RepologyError):
    """Raised when no matching repology packages found"""

    pass


class RepologyUnexpectedResponse(RepologyError):
    """Raised when repology sends unexpected response"""

    pass
