# SPDX-FileCopyrightText: 2026 Dmitry Sergeev
# SPDX-License-Identifier: Apache-2.0

"""Tests for SBOM document exporters."""

import re
from types import SimpleNamespace

import pandas as pd

from sbomnix.exporters import build_spdx_document


def test_spdx_created_is_utc_without_offset_or_fraction():
    sbomdb = SimpleNamespace(
        uuid="00000000-0000-0000-0000-000000000000",
        sbom_type="runtime_only",
        df_sbomdb=pd.DataFrame(),
    )

    created = build_spdx_document(sbomdb)["creationInfo"]["created"]

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created)
