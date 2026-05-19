# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for recognizing file artifacts in Nix build closures."""

import re

_PATCH_OR_DIFF_RE = r"[.](?:patch|diff)(?:[.][a-zA-Z0-9]+)?"
_SOURCE_ARCHIVE_RE = (
    r"[.]tar(?:[.][a-zA-Z0-9]+)?|"
    r"[.](?:tgz|tbz2?|txz|zip|whl|gem|cabal|crate)"
)
_CONFIG_OR_DATA_RE = (
    r"[.](?:"
    r"conf|cfg|ini|json|toml|ya?ml|lock|sum|mod|list|rules|preset|"
    r"desktop|service|socket|target|timer|mount|path|slice|network|"
    r"link|netdev|nmconnection|pam|pc|xml|crt|pem|cer|der|dat|"
    r"asc|sig|txt|md|rst"
    r")"
)
_FONT_OR_MEDIA_RE = (
    r"[.](?:"
    r"bdf|pcf|otf|ttf|ttc|woff2?|pfa|pfb|"
    r"mp3|mp4|mov|mkv|mxf|wav|ogg|amv|dmg|png|svg|gif|jpe?g|webp"
    r")"
    r"(?:[.](?:gz|xz|bz2|zst))?"
)
_SOURCE_FILE_RE = (
    r"[.](?:"
    r"sh|bash|fish|py|pl|pm|lua|cgi|c|cc|cpp|h|hpp|java|js|ts|"
    r"go|rs|hs|m4|in|cmake|mk|proto|css|scss|html"
    r")"
)
_GENERATED_CARGO_ARTIFACT_RE = re.compile(
    r"^cargo-(?:src|package)-.+-[0-9].*$",
    re.IGNORECASE,
)
_NON_PACKAGE_ARTIFACT_NAME_RE = re.compile(
    rf".*(?:{_PATCH_OR_DIFF_RE}|{_SOURCE_ARCHIVE_RE}|"
    rf"{_CONFIG_OR_DATA_RE}|{_FONT_OR_MEDIA_RE}|{_SOURCE_FILE_RE})(?:[?].*)?$",
    re.IGNORECASE,
)


def is_non_package_artifact_name(name):
    """Return True when a store-path name looks like a file, not a package."""
    if not isinstance(name, str) or not name:
        return False
    return (
        "?" in name
        or _GENERATED_CARGO_ARTIFACT_RE.match(name) is not None
        or _NON_PACKAGE_ARTIFACT_NAME_RE.match(name) is not None
    )
