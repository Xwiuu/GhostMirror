"""Comparators — compare baseline vs probe responses for signal detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ComparisonResult:
    """Result of a single comparison operation."""

    matched: bool = False
    signal: str | None = None
    detail: str | None = None


REFLECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r'<script[^>]*>alert\s*\(?\s*1\s*\)?\s*<', re.IGNORECASE),
    re.compile(r'<img[^>]*onerror\s*=', re.IGNORECASE),
    re.compile(r'<svg[^>]*onload\s*=', re.IGNORECASE),
    re.compile(r'javascript\s*:\s*alert', re.IGNORECASE),
    re.compile(r'\{7\s*\*\s*7\}'),
    re.compile(r'\{7\s*\*\s*\'7\'\}'),
]

SQL_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*mysql_.*", re.IGNORECASE),
    re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"Driver.*SQLite", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"System\.Data\.SQLite", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB.*SQL", re.IGNORECASE),
    re.compile(r"Invalid query", re.IGNORECASE),
    re.compile(r"SQL command not properly ended", re.IGNORECASE),
    re.compile(r"you have an error in your sql", re.IGNORECASE),
    re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
    re.compile(r"PL/SQL", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"ghostmirror_probe", re.IGNORECASE),
    re.compile(r"No such file|not found|failed to open", re.IGNORECASE),
    re.compile(r"path.*traversal", re.IGNORECASE),
]

HEADER_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"X-GhostMirror-Probe", re.IGNORECASE),
]

TEMPLATE_PATTERNS: list[re.Pattern] = [
    re.compile(r"49", re.IGNORECASE),
    re.compile(r"config", re.IGNORECASE),
    re.compile(r"7\*'7'", re.IGNORECASE),
]


class ReflectionComparator:
    """Detect reflected payload content in response body."""

    def compare(
        self, baseline_body: str, probe_body: str, payload_value: str
    ) -> ComparisonResult:
        for pattern in REFLECTION_PATTERNS:
            if pattern.search(probe_body):
                match = pattern.search(probe_body)
                return ComparisonResult(
                    matched=True,
                    signal="reflected_content_detected",
                    detail=f"Padrão de reflexão detectado: {pattern.pattern[:80]}",
                )

        payload_escaped = re.escape(payload_value)
        if re.search(payload_escaped, probe_body, re.IGNORECASE):
            return ComparisonResult(
                matched=True,
                signal="reflected_content_detected",
                detail=f"Payload refletido no body: {payload_value[:80]}",
            )

        return ComparisonResult(matched=False)


class ErrorSignatureComparator:
    """Detect error signatures (SQL errors, path traversal errors, etc.)."""

    def __init__(self) -> None:
        self.pattern_map: dict[str, list[re.Pattern]] = {
            "sql_error_message": SQL_ERROR_PATTERNS,
            "path_traversal_error": PATH_TRAVERSAL_PATTERNS,
            "template_injection_error": TEMPLATE_PATTERNS,
        }

    def compare(
        self,
        baseline_body: str,
        probe_body: str,
        expected_signal: str | None = None,
    ) -> ComparisonResult:
        if expected_signal and expected_signal in self.pattern_map:
            patterns = self.pattern_map[expected_signal]
            for pattern in patterns:
                if pattern.search(probe_body) and not pattern.search(baseline_body):
                    return ComparisonResult(
                        matched=True,
                        signal=expected_signal,
                        detail=f"Assinatura de erro detectada: {pattern.pattern[:80]}",
                    )

        for signal_name, patterns in self.pattern_map.items():
            for pattern in patterns:
                if pattern.search(probe_body) and not pattern.search(baseline_body):
                    return ComparisonResult(
                        matched=True,
                        signal=signal_name,
                        detail=f"Assinatura de erro detectada: {pattern.pattern[:80]}",
                    )

        return ComparisonResult(matched=False)


class RedirectComparator:
    """Detect differences in redirect behavior between baseline and probe."""

    def compare(
        self,
        baseline_status: int,
        probe_status: int,
        baseline_headers: dict[str, str],
        probe_headers: dict[str, str],
    ) -> ComparisonResult:
        is_redirect_baseline = baseline_status in (301, 302, 303, 307, 308)
        is_redirect_probe = probe_status in (301, 302, 303, 307, 308)

        if is_redirect_probe and not is_redirect_baseline:
            probe_location = probe_headers.get("location", "")
            return ComparisonResult(
                matched=True,
                signal="redirect_to_third_party",
                detail=f"Redirecionamento detectado no probe (status {probe_status}): {probe_location[:120]}",
            )

        if is_redirect_probe and is_redirect_baseline:
            baseline_location = baseline_headers.get("location", "")
            probe_location = probe_headers.get("location", "")
            if baseline_location != probe_location:
                return ComparisonResult(
                    matched=True,
                    signal="redirect_target_changed",
                    detail=f"Alvo de redirecionamento alterado: '{baseline_location[:60]}' -> '{probe_location[:60]}'",
                )

        return ComparisonResult(matched=False)


class StatusComparator:
    """Compare status code changes between baseline and probe."""

    def compare(
        self, baseline_status: int, probe_status: int
    ) -> ComparisonResult:
        if baseline_status != probe_status:
            diff_class_baseline = baseline_status // 100
            diff_class_probe = probe_status // 100
            if diff_class_baseline != diff_class_probe:
                return ComparisonResult(
                    matched=True,
                    signal="status_class_changed",
                    detail=(
                        f"Classe de status alterada: "
                        f"{baseline_status} ({diff_class_baseline}xx) -> "
                        f"{probe_status} ({diff_class_probe}xx)"
                    ),
                )

            return ComparisonResult(
                matched=True,
                signal="status_code_changed",
                detail=f"Código de status alterado: {baseline_status} -> {probe_status}",
            )

        return ComparisonResult(matched=False)


class TimingComparator:
    """Compare response time differences between baseline and probe."""

    def compare(
        self,
        baseline_time: float,
        probe_time: float,
        threshold: float = 5.0,
    ) -> ComparisonResult:
        time_diff = abs(probe_time - baseline_time)
        if time_diff > threshold and probe_time > baseline_time:
            return ComparisonResult(
                matched=True,
                signal="response_time_increased",
                detail=(
                    f"Tempo de resposta aumentou {time_diff:.2f}s "
                    f"(baseline: {baseline_time:.2f}s, probe: {probe_time:.2f}s)"
                ),
            )

        return ComparisonResult(matched=False)
