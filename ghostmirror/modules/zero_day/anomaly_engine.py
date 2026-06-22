from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

RARE_HEADER_PATTERNS: list[str] = [
    "x-debug",
    "x-test",
    "x-internal",
    "x-dev",
    "x-staging",
    "x-admin",
    "x-env",
    "x-environment",
    "x-server-info",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal",
    "x-joomla",
    "x-wordpress",
    "x-backend",
    "x-forwarded",
]

SENSITIVE_HEADER_PATTERNS: list[str] = [
    "x-api-key",
    "x-auth-token",
    "x-session",
    "x-csrf",
    "authorization",
    "set-cookie",
    "cookie",
]

RARE_ENDPOINT_PATTERNS: list[tuple[str, str]] = [
    (r"admin", "admin"),
    (r"debug", "debug"),
    (r"swagger", "swagger"),
    (r"api-docs", "api_docs"),
    (r"openapi", "openapi"),
    (r"graphql", "graphql"),
    (r"internal", "internal"),
    (r"staging", "staging"),
    (r"beta", "beta"),
    (r"test", "test"),
    (r"dev", "dev"),
    (r"console", "console"),
    (r"phpmyadmin", "phpmyadmin"),
    (r"\.git", "git_exposed"),
    (r"\.env", "env_exposed"),
    (r"backup", "backup"),
    (r"dbadmin", "dbadmin"),
    (r"log", "log_exposed"),
    (r"config", "config_exposed"),
    (r"hidden", "hidden"),
    (r"private", "private"),
    (r"secret", "secret"),
    (r"health", "health_check"),
    (r"metrics", "metrics"),
    (r"actuator", "actuator"),
    (r"prometheus", "prometheus"),
]

RARE_STATUS_PATTERNS: dict[int, str] = {
    301: "redirect_moved",
    302: "redirect_found",
    307: "redirect_temporary",
    308: "redirect_permanent",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found_standard",
    405: "method_not_allowed",
    406: "not_acceptable",
    407: "proxy_auth_required",
    409: "conflict",
    410: "gone",
    411: "length_required",
    412: "precondition_failed",
    413: "payload_too_large",
    414: "uri_too_long",
    415: "unsupported_media",
    422: "unprocessable_entity",
    425: "too_early",
    429: "rate_limited",
    431: "header_too_large",
    451: "legal_restrictions",
    500: "internal_error",
    501: "not_implemented",
    502: "bad_gateway",
    503: "unavailable",
    504: "gateway_timeout",
    505: "version_not_supported",
    511: "network_auth_required",
}


class AnomalyEngine:
    def __init__(self) -> None:
        self.anomalies: list[dict[str, Any]] = []

    def analyze(self, project_path: Path | str) -> list[dict[str, Any]]:
        project_path = Path(project_path)
        logger.info("ANOMALY_ENGINE_START project={}", project_path.name)
        self.anomalies = []
        signals: list[dict[str, Any]] = []

        web_intel_dir = project_path / "profiles" / "web_intelligence"
        api_dir = project_path / "profiles" / "api_security"
        bounty_dir = project_path / "profiles" / "bug_bounty"

        endpoints = self._load_endpoints(web_intel_dir, api_dir, bounty_dir)

        if not endpoints:
            logger.info("ANOMALY_ENGINE_SKIPPED no endpoints available")
            return []

        signals.extend(self._detect_rare_endpoints(endpoints))
        signals.extend(self._detect_status_anomalies(endpoints))
        signals.extend(self._detect_content_anomalies(endpoints))
        signals.extend(self._detect_rare_headers(endpoints))

        self.anomalies = self._group_signals(signals)
        logger.info("ANOMALY_ENGINE_DONE signals={} anomalies={}", len(signals), len(self.anomalies))
        return self.anomalies

    def _load_endpoints(
        self,
        web_intel_dir: Path,
        api_dir: Path,
        bounty_dir: Path,
    ) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []

        web_endpoints = self._load_json_list(web_intel_dir / "endpoint_inventory.json")
        for ep in web_endpoints:
            ep["_source"] = "web_intelligence"
            endpoints.append(ep)

        api_inv = self._load_json_dict(api_dir / "api_inventory.json") or {}
        api_endpoints = api_inv.get("endpoints", []) if isinstance(api_inv, dict) else []
        for ep in api_endpoints:
            ep["_source"] = "api_security"
            endpoints.append(ep)

        routes = self._load_json_list(bounty_dir / "headless_routes.json")
        for ep in routes:
            ep["_source"] = "bug_bounty"
            endpoints.append(ep)

        seen = set()
        unique: list[dict[str, Any]] = []
        for ep in endpoints:
            url = ep.get("url", "") or ep.get("path", "") or ep.get("endpoint", "")
            method = ep.get("method", "GET")
            key = f"{method}:{url}"
            if key not in seen:
                seen.add(key)
                ep.setdefault("url", url)
                ep.setdefault("method", method)
                unique.append(ep)

        return unique

    def _detect_rare_endpoints(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []
        seen_patterns: set[str] = set()

        for ep in endpoints:
            url = ep.get("url", "")
            for pattern, category in RARE_ENDPOINT_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    key = f"{category}:{url}"
                    if key not in seen_patterns:
                        seen_patterns.add(key)
                        signals.append({
                            "signal_type": "rare_endpoint",
                            "source": ep.get("_source", "unknown"),
                            "endpoint": url,
                            "method": ep.get("method", "GET"),
                            "expected": "standard_endpoint",
                            "observed": category,
                            "severity": "MEDIUM",
                            "description": f"Rare endpoint pattern detected: {category} at {url}",
                        })

        logger.debug("ANOMALY_RARE_ENDPOINTS count={}", len(signals))
        return signals

    def _detect_status_anomalies(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for ep in endpoints:
            status = ep.get("status_code", 0) or ep.get("status", 0)
            if status in RARE_STATUS_PATTERNS:
                category = RARE_STATUS_PATTERNS[status]
                signals.append({
                    "signal_type": "unexpected_status",
                    "source": ep.get("_source", "unknown"),
                    "endpoint": ep.get("url", ""),
                    "method": ep.get("method", "GET"),
                    "expected": "200",
                    "observed": str(status),
                    "severity": "HIGH" if status >= 500 else "MEDIUM" if status >= 400 else "LOW",
                    "description": f"Unexpected status {status} ({category}) at {ep.get('url', '')}",
                })

        logger.debug("ANOMALY_STATUS_ANOMALIES count={}", len(signals))
        return signals

    def _detect_content_anomalies(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        sizes = sorted([ep.get("size", 0) or ep.get("content_length", 0) or ep.get("response_size", 0) for ep in endpoints if (ep.get("size", 0) or ep.get("content_length", 0) or ep.get("response_size", 0))])
        if not sizes:
            return signals

        n = len(sizes)
        median = sizes[n // 2] if n % 2 == 1 else (sizes[n // 2 - 1] + sizes[n // 2]) / 2
        deviations = sorted(abs(s - median) for s in sizes)
        mad = deviations[n // 2] if n % 2 == 1 else (deviations[n // 2 - 1] + deviations[n // 2]) / 2
        mad = mad if mad > 0 else median * 0.1
        threshold = median + 5 * mad

        for ep in endpoints:
            size = ep.get("size", 0) or ep.get("content_length", 0) or ep.get("response_size", 0)
            if size > threshold and threshold > 0 and len(sizes) >= 3:
                signals.append({
                    "signal_type": "size_inconsistency",
                    "source": ep.get("_source", "unknown"),
                    "endpoint": ep.get("url", ""),
                    "method": ep.get("method", "GET"),
                    "expected": int(median),
                    "observed": size,
                    "severity": "LOW",
                    "description": f"Response size {size} significantly larger than median {int(median)} at {ep.get('url', '')}",
                })

        logger.debug("ANOMALY_CONTENT_ANOMALIES count={}", len(signals))
        return signals

    def _detect_rare_headers(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for ep in endpoints:
            headers = ep.get("headers", {}) or ep.get("response_headers", {})
            if isinstance(headers, list):
                headers = {h.get("name", ""): h.get("value", "") for h in headers}
            if isinstance(headers, str):
                continue

            for header_name in headers:
                header_lower = header_name.lower()
                for pattern in RARE_HEADER_PATTERNS:
                    if pattern in header_lower:
                        signals.append({
                            "signal_type": "rare_header",
                            "source": ep.get("_source", "unknown"),
                            "endpoint": ep.get("url", ""),
                            "method": ep.get("method", "GET"),
                            "expected": "standard_header",
                            "observed": header_name,
                            "severity": "MEDIUM",
                            "description": f"Rare header '{header_name}' found on {ep.get('url', '')}",
                        })

                for pattern in SENSITIVE_HEADER_PATTERNS:
                    if pattern in header_lower:
                        signals.append({
                            "signal_type": "sensitive_header",
                            "source": ep.get("_source", "unknown"),
                            "endpoint": ep.get("url", ""),
                            "method": ep.get("method", "GET"),
                            "expected": "no_sensitive_header",
                            "observed": header_name,
                            "severity": "HIGH",
                            "description": f"Sensitive header '{header_name}' exposed on {ep.get('url', '')}",
                        })

        logger.debug("ANOMALY_RARE_HEADERS count={}", len(signals))
        return signals

    def _group_signals(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}

        for sig in signals:
            key = f"{sig['endpoint']}:{sig.get('signal_type', 'unknown')}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(sig)

        anomalies: list[dict[str, Any]] = []
        for key, sigs in grouped.items():
            endpoint = sigs[0]["endpoint"]
            types = list(set(s.get("signal_type", "") for s in sigs))
            severities = [s.get("severity", "LOW") for s in sigs]
            max_sev = "CRITICAL" if "HIGH" in severities else "HIGH" if "MEDIUM" in severities else "MEDIUM" if len(severities) > 1 else "LOW"

            title = f"Anomaly: {', '.join(types)} on {endpoint}"
            description = f"{len(sigs)} signal(s) detected on {endpoint}: " + "; ".join(s.get("description", "") for s in sigs[:3])

            anomalies.append({
                "title": title,
                "description": description,
                "endpoint": endpoint,
                "signals": sigs,
                "severity": max_sev,
                "confidence": "HIGH" if len(sigs) >= 3 else "MEDIUM" if len(sigs) >= 2 else "LOW",
                "score": self._calculate_anomaly_score(sigs),
                "category": types[0] if types else "unknown",
            })

        anomalies.sort(key=lambda a: a["score"], reverse=True)
        return anomalies

    def _calculate_anomaly_score(self, signals: list[dict[str, Any]]) -> int:
        base = min(len(signals) * 15, 60)
        severity_boost = 0
        for s in signals:
            sev = s.get("severity", "LOW")
            if sev == "CRITICAL":
                severity_boost += 30
            elif sev == "HIGH":
                severity_boost += 20
            elif sev == "MEDIUM":
                severity_boost += 10
        return min(base + severity_boost, 100)

    def _load_json_list(self, path: Path) -> list[Any]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _load_json_dict(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
