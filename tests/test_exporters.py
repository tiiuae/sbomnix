# SPDX-FileCopyrightText: 2026 Dmitry Sergeev
# SPDX-License-Identifier: Apache-2.0

"""Tests for SBOM document exporters."""

import re
from types import SimpleNamespace

import pandas as pd
import pytest

from sbomnix.exporters import build_spdx_document


def test_spdx_created_is_utc_without_offset_or_fraction():
    sbomdb = SimpleNamespace(
        uuid="00000000-0000-0000-0000-000000000000",
        sbom_type="runtime_only",
        df_sbomdb=pd.DataFrame(),
    )

    created = build_spdx_document(sbomdb)["creationInfo"]["created"]

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created)


def test_spdx_document_describes_the_target_package():
    target = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-2.12"
    dep = "/nix/store/2ccccccccccccccccccccccccccccccc-glibc-2.40"
    sbomdb = SimpleNamespace(
        uuid="00000000-0000-0000-0000-000000000000",
        sbom_type="runtime_only",
        df_sbomdb=pd.DataFrame(
            {
                "store_path": [dep, target],
                "pname": ["glibc", "hello"],
                "version": ["2.40", "2.12"],
                "urls": ["", ""],
                "cpe": ["", ""],
                "purl": ["", ""],
            }
        ),
        uid="store_path",
        target_component_ref=target,
        lookup_dependencies=lambda drv, uid: [dep] if drv.store_path == target else [],
    )

    relationships = build_spdx_document(sbomdb)["relationships"]

    describes = [r for r in relationships if r["relationshipType"] == "DESCRIBES"]
    assert describes == [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": (
                "SPDXRef-nix-store-1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-2.12"
            ),
        }
    ]
    assert relationships[0] == describes[0]


_HELLO_MIRROR = "mirror://gnu/hello/hello-2.12.tar.gz"
_HELLO_HTTPS = "https://ftpmirror.gnu.org/hello/hello-2.12.tar.gz"


@pytest.mark.parametrize(
    ("urls", "download_location"),
    [
        ("", "NOASSERTION"),
        (_HELLO_MIRROR, "NOASSERTION"),
        (f"{_HELLO_MIRROR} {_HELLO_HTTPS}", _HELLO_HTTPS),
        (
            f"http://example.test/hello-2.12.tar.gz {_HELLO_HTTPS}",
            "http://example.test/hello-2.12.tar.gz",
        ),
        (
            "ftp://example.test/hello-2.12.tar.gz",
            "ftp://example.test/hello-2.12.tar.gz",
        ),
    ],
    ids=["none", "mirror-only", "mirror-first", "several", "ftp"],
)
def test_spdx_download_location_is_the_first_http_or_ftp_url(urls, download_location):
    # nixpkgs fetchurl often lists only mirror:// URLs, which SPDX does not accept
    target = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-2.12"
    sbomdb = SimpleNamespace(
        uuid="00000000-0000-0000-0000-000000000000",
        sbom_type="runtime_only",
        df_sbomdb=pd.DataFrame(
            {
                "store_path": [target],
                "pname": ["hello"],
                "version": ["2.12"],
                "urls": [urls],
                "cpe": [""],
                "purl": [""],
            }
        ),
        uid="store_path",
        target_component_ref=target,
        lookup_dependencies=lambda drv, uid: [],
    )

    (package,) = build_spdx_document(sbomdb)["packages"]

    assert package["downloadLocation"] == download_location
