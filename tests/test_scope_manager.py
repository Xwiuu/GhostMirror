"""Tests for the scope manager."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.core.scope_manager import ScopeManager


def test_build_and_roundtrip_scope(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Empresa X", name="Auditoria Externa", domain="empresa.com.br"
    )
    scope_path = tmp_path / "scope.yaml"
    scope_manager.write_scope(scope_path, scope)

    loaded = scope_manager.load_scope(scope_path)
    assert loaded.project.client == "Empresa X"
    assert loaded.targets.domains == ["empresa.com.br"]
    # Conservative defaults: intrusive categories disabled.
    assert loaded.allowed_tests.destructive_tests is False
    assert loaded.allowed_tests.recon is True


def test_validate_scope_detects_invalid_file(tmp_path: Path, scope_manager: ScopeManager) -> None:
    bad = tmp_path / "scope.yaml"
    # Structurally invalid: malformed domain.
    bad.write_text(
        "project:\n  client: X\n  name: Y\n"
        "targets:\n  domains:\n    - 'not a domain'\n  ips: []\n",
        encoding="utf-8",
    )
    ok, reason = scope_manager.validate_scope(bad)
    assert ok is False
    assert reason is not None


def test_empty_scope_is_valid_but_not_ready(tmp_path: Path, scope_manager: ScopeManager) -> None:
    empty = tmp_path / "scope.yaml"
    empty.write_text(
        "project:\n  client: X\n  name: Y\ntargets:\n  domains: []\n  ips: []\n",
        encoding="utf-8",
    )
    ok, reason = scope_manager.validate_scope(empty)
    assert ok is True
    assert reason is None
    assert scope_manager.is_ready_for_testing(scope_manager.load_scope(empty)) is False


def test_validate_scope_accepts_valid_file(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="X", name="Y", domain="example.com"
    )
    path = tmp_path / "scope.yaml"
    scope_manager.write_scope(path, scope)
    ok, reason = scope_manager.validate_scope(path)
    assert ok is True
    assert reason is None
