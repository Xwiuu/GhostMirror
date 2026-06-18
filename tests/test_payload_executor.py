"""Tests for PayloadExecutor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.models.payload_profile import PayloadCategory, SafetyLevel
from ghostmirror.modules.payloads.evidence import EvidenceCapture
from ghostmirror.modules.payloads.executor import PayloadExecutor
from ghostmirror.modules.payloads.models import PayloadDefinition
from ghostmirror.modules.payloads.rate_limiter import RateLimiter
from ghostmirror.modules.payloads.safety import SafetyPolicy


@pytest.fixture()
def safe_payload() -> PayloadDefinition:
    return PayloadDefinition(
        id="gm_test_probe",
        name="Test Probe",
        category=PayloadCategory.XSS_REFLECTION,
        description="Safe test",
        value="<test>",
        safety_level=SafetyLevel.SAFE_REFLECTION,
    )


@pytest.fixture()
def executor(tmp_path: Path) -> PayloadExecutor:
    ev = EvidenceCapture(tmp_path / "evidence")
    return PayloadExecutor(
        target="http://example.com",
        rate_limiter=RateLimiter(max_requests_per_second=100, max_payloads_per_target=100),
        safety_policy=SafetyPolicy(),
        evidence_capture=ev,
        dry_run=False,
    )


def test_dry_run_does_not_execute(safe_payload: PayloadDefinition) -> None:
    executor = PayloadExecutor(
        target="http://example.com",
        dry_run=True,
    )
    result = executor.execute(safe_payload)
    assert result.dry_run
    assert not result.blocked
    assert result.status_code_baseline == 0
    assert result.status_code_probe == 0


def test_blocked_by_safety_policy(executor: PayloadExecutor) -> None:
    destructive = PayloadDefinition(
        id="gm_destructive",
        name="Destructive",
        category=PayloadCategory.XSS_REFLECTION,
        description="Bad",
        value="rm -rf /",
        destructive=True,
        safety_level=SafetyLevel.SAFE_REFLECTION,
    )
    result = executor.execute(destructive)
    assert result.blocked
    assert result.blocked_reason is not None


def test_execute_success(executor: PayloadExecutor, safe_payload: PayloadDefinition) -> None:
    with patch.object(executor, "_request") as mock_request:
        mock_request.side_effect = [
            (200, {"content-type": "text/html"}, "<html>Hello</html>", 0.1),
            (200, {"content-type": "text/html"}, "<html><test>Hello</test></html>", 0.15),
        ]
        result = executor.execute(safe_payload)
        assert not result.blocked
        assert not result.dry_run
        assert result.status_code_baseline == 200
        assert result.status_code_probe == 200
        assert result.payload_id == "gm_test_probe"


def test_execute_with_signal_match(executor: PayloadExecutor) -> None:
    payload = PayloadDefinition(
        id="gm_sql_test",
        name="SQL Test",
        category=PayloadCategory.SQL_ERROR_INDICATOR,
        description="SQL",
        value="'",
        safety_level=SafetyLevel.SAFE_ERROR_TRIGGER,
        expected_signal="sql_error_message",
    )
    with patch.object(executor, "_request") as mock_request:
        mock_request.side_effect = [
            (200, {}, "Welcome to our site", 0.1),
            (500, {}, "You have an error in your SQL syntax", 0.2),
        ]
        result = executor.execute(payload)
        assert result.matched_signal == "sql_error_message"


def test_rate_limit_blocks(executor: PayloadExecutor, safe_payload: PayloadDefinition) -> None:
    executor.rate_limiter = RateLimiter(max_requests_per_second=100, max_payloads_per_target=0)
    result = executor.execute(safe_payload)
    assert result.blocked
    assert "rate limit" in result.blocked_reason.lower()


def test_evidence_saved(tmp_path: Path, safe_payload: PayloadDefinition) -> None:
    ev = EvidenceCapture(tmp_path / "payloads")
    executor = PayloadExecutor(
        target="http://example.com",
        rate_limiter=RateLimiter(max_requests_per_second=100, max_payloads_per_target=100),
        evidence_capture=ev,
    )
    with patch.object(executor, "_request") as mock_request:
        mock_request.side_effect = [
            (200, {}, "Hello", 0.1),
            (200, {}, "Hello<test>", 0.15),
        ]
        result = executor.execute(safe_payload)
        assert result.evidence_path is not None
        evidence_file = tmp_path / "payloads" / Path(result.evidence_path).name
        assert evidence_file.exists()


def test_execute_batch(executor: PayloadExecutor) -> None:
    payloads = [
        PayloadDefinition(
            id=f"gm_batch_{i}",
            name=f"Batch {i}",
            category=PayloadCategory.XSS_REFLECTION,
            description=f"Batch {i}",
            value=f"<test{i}>",
            safety_level=SafetyLevel.SAFE_REFLECTION,
        )
        for i in range(3)
    ]
    with patch.object(executor, "_request") as mock_request:
        mock_request.return_value = (200, {}, "OK", 0.1)
        results = executor.execute_batch(payloads)
        assert len(results) == 3
        for r in results:
            assert r.status_code_baseline == 200


def test_build_url() -> None:
    executor = PayloadExecutor(target="http://example.com")
    url = executor._build_url("http://example.com/page", "q", "<test>")
    assert "q=%3Ctest%3E" in url or "q=<test>" in url
