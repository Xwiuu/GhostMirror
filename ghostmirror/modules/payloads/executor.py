"""PayloadExecutor — executes safe payloads against target endpoints."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from ghostmirror.core.logger import get_logger
from ghostmirror.models.payload_profile import SafetyLevel
from ghostmirror.models.payload_result import PayloadResult
from ghostmirror.modules.payloads.comparators import (
    ComparisonResult,
    ErrorSignatureComparator,
    RedirectComparator,
    ReflectionComparator,
    StatusComparator,
    TimingComparator,
)
from ghostmirror.modules.payloads.evidence import EvidenceCapture, sanitize_body
from ghostmirror.modules.payloads.models import PayloadDefinition
from ghostmirror.modules.payloads.rate_limiter import RateLimiter
from ghostmirror.modules.payloads.safety import SafetyPolicy

logger = get_logger()

REQUEST_TIMEOUT = 10
USER_AGENT = "GhostMirror-PayloadEngine/1.0 (Security Assessment)"


class PayloadExecutor:
    """Executes safe payloads with baseline comparison, rate limiting, and dry-run support.

    Responsibilities:
    - Mount HTTP request with payload
    - Respect scope, timeout, rate limit
    - Capture baseline vs probe responses
    - Run comparators for signal detection
    - Generate PayloadResult
    """

    def __init__(
        self,
        target: str,
        rate_limiter: RateLimiter | None = None,
        safety_policy: SafetyPolicy | None = None,
        evidence_capture: EvidenceCapture | None = None,
        dry_run: bool = False,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self.target = target.rstrip("/")
        self.rate_limiter = rate_limiter or RateLimiter()
        self.safety_policy = safety_policy or SafetyPolicy()
        self.evidence_capture = evidence_capture
        self.dry_run = dry_run
        self.timeout = timeout

        self._reflection_cmp = ReflectionComparator()
        self._error_cmp = ErrorSignatureComparator()
        self._redirect_cmp = RedirectComparator()
        self._status_cmp = StatusComparator()
        self._timing_cmp = TimingComparator()

    def _build_url(self, base_url: str, param: str, value: str) -> str:
        """Build URL with the payload value injected into the specified parameter."""
        parsed = urlparse(base_url)
        query_params: dict[str, str] = {}
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query_params[k] = v

        query_params[param] = value

        new_query = urlencode(query_params)
        return urlunparse(parsed._replace(query=new_query))

    def _request(
        self, url: str
    ) -> tuple[int, dict[str, str], str, float]:
        """Execute a single HTTP GET request and return (status, headers, body, elapsed)."""
        req = Request(url, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        start = time.monotonic()
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = time.monotonic() - start
                return resp.status, headers, body, elapsed
        except URLError as exc:
            elapsed = time.monotonic() - start
            logger.debug("HTTP error for {}: {}", url, exc)
            if hasattr(exc, "code") and exc.code is not None:
                return exc.code, {}, "", elapsed
            return 0, {}, "", elapsed
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.debug("Request failed for {}: {}", url, exc)
            return 0, {}, "", elapsed

    def execute(
        self,
        payload: PayloadDefinition,
        base_url: str = "",
        parameter: str = "q",
    ) -> PayloadResult:
        """Execute a single safe payload against the target.

        Args:
            payload: The payload definition to execute.
            base_url: Optional override URL (defaults to self.target).
            parameter: The query parameter to inject the payload into.

        Returns:
            A PayloadResult with comparison data.
        """
        url = base_url or self.target
        probe_url = self._build_url(url, parameter, payload.value)

        result = PayloadResult(
            target=self.target,
            url=probe_url,
            method=payload.method,
            parameter=parameter,
            payload_id=payload.id,
            payload_category=payload.category.value,
            safety_level=payload.safety_level.value,
            dry_run=self.dry_run,
        )

        # Safety gate
        allowed, reason = self.safety_policy.validate(payload)
        if not allowed:
            result.blocked = True
            result.blocked_reason = reason
            logger.info("PAYLOAD_BLOCKED id={} reason={}", payload.id, reason)
            return result

        if self.dry_run:
            logger.info(
                "PAYLOAD_DRY_RUN id={} url={} category={}",
                payload.id,
                probe_url,
                payload.category.value,
            )
            return result

        # Rate limit gate
        if not self.rate_limiter.acquire(self.target):
            result.blocked = True
            result.blocked_reason = "Rate limit atingido para o alvo"
            logger.info("PAYLOAD_RATE_LIMITED id={} target={}", payload.id, self.target)
            return result

        try:
            # Baseline request
            baseline_status, baseline_headers, baseline_body, baseline_time = (
                self._request(url)
            )
            result.status_code_baseline = baseline_status
            result.content_length_baseline = len(baseline_body)
            result.response_time_baseline = baseline_time

            # Probe request (with payload)
            probe_status, probe_headers, probe_body, probe_time = self._request(
                probe_url
            )
            result.status_code_probe = probe_status
            result.content_length_probe = len(probe_body)
            result.response_time_probe = probe_time
            result.content_length_diff = abs(
                len(probe_body) - len(baseline_body)
            )

            # Run comparators
            signals: list[ComparisonResult] = [
                self._reflection_cmp.compare(baseline_body, probe_body, payload.value),
                self._error_cmp.compare(
                    baseline_body, probe_body, payload.expected_signal
                ),
                self._redirect_cmp.compare(
                    baseline_status,
                    probe_status,
                    baseline_headers,
                    probe_headers,
                ),
                self._status_cmp.compare(baseline_status, probe_status),
                self._timing_cmp.compare(baseline_time, probe_time),
            ]

            for signal in signals:
                if signal.matched:
                    result.matched_signal = signal.signal
                    result.signal_detail = signal.detail
                    break

            # Capture sanitized body snippet
            result.body_snippet_sanitized = sanitize_body(probe_body)

            # Persist evidence if configured
            if self.evidence_capture:
                evidence_path = self.evidence_capture.save_result(
                    result, probe_body
                )
                result.evidence_path = evidence_path

            logger.info(
                "PAYLOAD_EXECUTED id={} matched={} signal={}",
                payload.id,
                result.matched_signal is not None,
                result.matched_signal,
            )

        except Exception as exc:
            logger.exception("PAYLOAD_EXECUTION_ERROR id={} error={}", payload.id, exc)
            result.error = str(exc)

        return result

    def execute_batch(
        self,
        payloads: list[PayloadDefinition],
        base_url: str = "",
        parameter: str = "q",
    ) -> list[PayloadResult]:
        """Execute multiple payloads and return their results."""
        results: list[PayloadResult] = []
        for payload in payloads:
            result = self.execute(payload, base_url, parameter)
            results.append(result)
        return results
