"""Unit tests for the ScannerBase class and scope validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import pytest

from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import (
    OutOfScopeError,
    ScannerBase,
    normalize_target,
)
from ghostmirror.modules.models.finding import ScanResultModel


# Concrete implementation of ScannerBase for testing purposes
class DummyScanner(ScannerBase):
    def run(self) -> ScanResultModel:
        self.validate_scope()
        # Stub result
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        return ScanResultModel(
            scanner_name="dummy",
            target=self.target,
            started_at=now,
            finished_at=now,
            status="completed",
            findings=[],
            statistics={},
        )

    def get_metadata(self) -> dict[str, Any]:
        return {"name": "dummy", "version": "0.0.1"}


def test_normalize_target() -> None:
    # URL extraction
    assert normalize_target("https://empresa.com.br/path?query=1") == "empresa.com.br"
    assert normalize_target("http://localhost:8080/") == "localhost"
    # Port stripping
    assert normalize_target("empresa.com.br:8443") == "empresa.com.br"
    # Brackets (IPv6)
    assert normalize_target("[::1]:80") == "::1"
    assert normalize_target("[2001:db8::1]") == "2001:db8::1"
    # Lowercasing and trimming
    assert normalize_target("  EMPRESA.com.br  ") == "empresa.com.br"


def test_scanner_base_scope_validation_success(tmp_path: Path, scope_manager: ScopeManager) -> None:
    # Create scope file with targets
    scope = scope_manager.build_default_scope(
        client="Client A", name="Engagement A", domain="empresa.com.br"
    )
    # Add an IP range
    scope.targets.ips.append("192.168.1.0/24")
    
    scope_path = tmp_path / "scope.yaml"
    scope_manager.write_scope(scope_path, scope)

    # 1. Exact domain match
    scanner = DummyScanner(tmp_path, "empresa.com.br", scope_manager)
    scanner.validate_scope()  # Should not raise

    # 2. Subdomain match
    scanner_sub = DummyScanner(tmp_path, "sub.domain.empresa.com.br", scope_manager)
    scanner_sub.validate_scope()  # Should not raise

    # 3. IP match within CIDR
    scanner_ip = DummyScanner(tmp_path, "192.168.1.50", scope_manager)
    scanner_ip.validate_scope()  # Should not raise


def test_scanner_base_scope_validation_failure(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Client A", name="Engagement A", domain="empresa.com.br"
    )
    scope_path = tmp_path / "scope.yaml"
    scope_manager.write_scope(scope_path, scope)

    # 1. Out of scope domain
    scanner = DummyScanner(tmp_path, "google.com", scope_manager)
    with pytest.raises(OutOfScopeError) as exc:
        scanner.validate_scope()
    assert "not in scope" in str(exc.value)

    # 2. Scope not ready (empty targets)
    scope_empty = scope_manager.build_default_scope(
        client="Client A", name="Engagement A", domain=None
    )
    scope_manager.write_scope(scope_path, scope_empty)
    scanner_empty = DummyScanner(tmp_path, "empresa.com.br", scope_manager)
    with pytest.raises(OutOfScopeError) as exc:
        scanner_empty.validate_scope()
    assert "not ready" in str(exc.value)


def test_scanner_base_scope_file_missing(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scanner = DummyScanner(tmp_path, "empresa.com.br", scope_manager)
    with pytest.raises(FileNotFoundError):
        scanner.validate_scope()
