#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for shared nix target resolution helpers."""

import pytest

from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from sbomnix import cli_utils as sbomnix_cli_utils


def test_resolve_nix_target_preserves_flakeref_on_success(monkeypatch):
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        lambda *_args, **_kwargs: "/nix/store/resolved",
    )

    resolved = sbomnix_cli_utils.resolve_nix_target(".#hello", buildtime=False)

    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/resolved",
        flakeref=".#hello",
        original_ref=".#hello",
    )


def test_resolve_nix_target_normalizes_plain_nixos_configuration(monkeypatch):
    calls = []

    def fake_resolve(flakeref, **_kwargs):
        calls.append(flakeref)
        return "/nix/store/resolved"

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        fake_resolve,
    )

    resolved = sbomnix_cli_utils.resolve_nix_target(
        "/flake#nixosConfigurations.host",
        buildtime=False,
    )

    assert calls == ['/flake#nixosConfigurations."host".config.system.build.toplevel']
    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/resolved",
        flakeref='/flake#nixosConfigurations."host".config.system.build.toplevel',
        original_ref="/flake#nixosConfigurations.host",
    )


def test_resolve_nix_target_normalizes_quoted_nixos_configuration(monkeypatch):
    calls = []

    def fake_resolve(flakeref, **_kwargs):
        calls.append(flakeref)
        return "/nix/store/resolved"

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        fake_resolve,
    )

    resolved = sbomnix_cli_utils.resolve_nix_target(
        '/flake#nixosConfigurations."host.example.com"',
        buildtime=False,
    )

    assert calls == [
        '/flake#nixosConfigurations."host.example.com".config.system.build.toplevel'
    ]
    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/resolved",
        flakeref=(
            '/flake#nixosConfigurations."host.example.com".config.system.build.toplevel'
        ),
        original_ref='/flake#nixosConfigurations."host.example.com"',
    )


@pytest.mark.parametrize(
    "nixref",
    [
        "/flake#nixosConfigurations.",
        '/flake#nixosConfigurations."unterminated',
        '/flake#nixosConfigurations."trailing\\',
    ],
)
def test_resolve_nix_target_leaves_malformed_nixos_configuration_refs(
    nixref,
    monkeypatch,
):
    calls = []

    def fake_resolve(flakeref, **_kwargs):
        calls.append(flakeref)
        return "/nix/store/resolved"

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        fake_resolve,
    )

    resolved = sbomnix_cli_utils.resolve_nix_target(nixref, buildtime=False)

    assert calls == [nixref]
    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/resolved",
        flakeref=nixref,
        original_ref=nixref,
    )


def test_resolve_nix_target_propagates_flakeref_realisation_failure_without_store_fallback(
    monkeypatch,
):
    artifact_checks = []

    def raise_realisation_error(*_args, **_kwargs):
        raise FlakeRefRealisationError(".#broken", "build failed")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        raise_realisation_error,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    with pytest.raises(FlakeRefRealisationError) as excinfo:
        sbomnix_cli_utils.resolve_nix_target(".#broken", buildtime=False)

    assert (
        str(excinfo.value) == "Failed force-realising flakeref '.#broken': build failed"
    )
    assert not artifact_checks


def test_resolve_nix_target_propagates_flakeref_eval_failure_without_store_fallback(
    monkeypatch,
):
    artifact_checks = []

    def raise_resolution_error(*_args, **_kwargs):
        raise FlakeRefResolutionError(".#broken", "attribute missing")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        raise_resolution_error,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    with pytest.raises(FlakeRefResolutionError) as excinfo:
        sbomnix_cli_utils.resolve_nix_target(".#broken", buildtime=False)

    assert (
        str(excinfo.value) == "Failed evaluating flakeref '.#broken': attribute missing"
    )
    assert not artifact_checks


def test_resolve_nix_target_falls_back_to_store_path_validation(monkeypatch):
    artifact_checks = []

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    resolved = sbomnix_cli_utils.resolve_nix_target("/nix/store/not-a-flake")

    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/not-a-flake",
        flakeref=None,
        original_ref="/nix/store/not-a-flake",
    )
    assert artifact_checks == [("/nix/store/not-a-flake", True)]
