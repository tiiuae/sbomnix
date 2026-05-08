#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for build-closure artifact classification."""

from sbomnix import meta as sbomnix_meta
from sbomnix.artifacts import is_non_package_artifact_name


def test_non_package_artifact_detection_covers_file_artifacts():
    artifact_names = [
        "0001-fix-build.patch?id=625e19c19972e69e034c0870a31b375833d1ab5d",
        "Python-3.14.2.tar.xz",
        "fc-00-nixos-cache.conf",
        "dart-sass-1.99.0-package-config.json",
        "polkit-1.pam",
        "unifont-17.0.04.bdf.gz",
        "Dvorak_Symphony_9_1.mp3",
        "MovText_capability_tester.mp4",
        "ghaf.iso",
    ]

    assert all(is_non_package_artifact_name(name) for name in artifact_names)


def test_non_package_artifact_detection_keeps_package_names():
    package_names = [
        "hello-2.12.3",
        "python3.13-gyp-unstable-2024-02-07",
        "kmod-debian-aliases.conf-30+20230601-2",
        "nixos-system-ghaf-host-26.05.20260418.b12141e",
    ]

    assert not any(is_non_package_artifact_name(name) for name in package_names)


def test_meta_scan_filters_non_package_artifacts():
    names = [
        "hello-2.12.3",
        "fc-00-nixos-cache.conf",
        "protoc-gen-dart-25.0.0-package-config.json",
        "polkit-1.pam",
        "unifont-17.0.04.otf",
        "Dvorak_Symphony_9_1.mp3",
        "kmod-debian-aliases.conf-30+20230601-2",
    ]

    assert sbomnix_meta._filter_store_names_for_meta_scan(names) == [
        "hello-2.12.3",
        "kmod-debian-aliases.conf-30+20230601-2",
    ]
