from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

FEATURE_FLAG_PATTERNS: list[str] = [
    r"isAdmin\w*",
    r"isDebug\w*",
    r"debugMode",
    r"debug_mode",
    r"featureFlag",
    r"feature_flag",
    r"featureToggle",
    r"feature_toggle",
    r"betaFeature",
    r"beta_feature",
    r"experimental",
    r"isInternal",
    r"internalApi",
    r"internal_api",
    r"isPreview",
    r"previewMode",
    r"showDebug",
    r"show_debug",
    r"adminOverride",
    r"admin_override",
    r"enableDebug",
    r"enable_debug",
    r"isTestMode",
    r"test_mode",
    r"useMock",
    r"mockApi",
    r"mock_api",
    r"stagingOnly",
    r"staging_only",
    r"hidden\w*",
    r"__debug",
    r"__hidden",
    r"bypass\w*",
    r"override\w*",
]

DEBUG_ROUTE_PATTERNS: list[tuple[str, str]] = [
    (r"/__webpack_hmr", "webpack_hmr"),
    (r"/sockjs-node", "sockjs"),
    (r"/__debug", "debug_route"),
    (r"/dev", "dev_route"),
    (r"/test", "test_route"),
    (r"/admin", "admin_route"),
    (r"/internal", "internal_route"),
    (r"/actuator", "actuator"),
    (r"/heapdump", "heapdump"),
    (r"/threaddump", "threaddump"),
    (r"/healthz", "healthz"),
    (r"/readyz", "readyz"),
    (r"/livez", "livez"),
    (r"/metrics", "metrics_endpoint"),
    (r"/prometheus", "prometheus"),
    (r"/debug/", "debug_prefix"),
    (r"/api/internal", "internal_api"),
    (r"/api/v\d+/internal", "internal_api_versioned"),
    (r"/api/private", "private_api"),
    (r"/graphql", "graphql_endpoint"),
    (r"/playground", "graphql_playground"),
    (r"/voyager", "graphql_voyager"),
]

INTERNAL_FUNCTION_PATTERNS: list[str] = [
    r"getInternal\w*",
    r"loadInternal\w*",
    r"fetchInternal\w*",
    r"\_private",
    r"\_internal",
    r"\_hidden",
    r"\_secret",
    r"\_admin",
    r"\_debug",
    r"\_bypass",
    r"\_test",
]


class HiddenFunctionalityEngine:
    def __init__(self) -> None:
        self.hypotheses: list[dict[str, Any]] = []

    def analyze(self, project_path: Path | str) -> list[dict[str, Any]]:
        project_path = Path(project_path)
        logger.info("HIDDEN_FUNCTIONALITY_ENGINE_START project={}", project_path.name)
        self.hypotheses = []

        web_intel_dir = project_path / "profiles" / "web_intelligence"
        api_dir = project_path / "profiles" / "api_security"
        bounty_dir = project_path / "profiles" / "bug_bounty"

        js_intel = self._load_json_dict(web_intel_dir / "js_intelligence.json") or {}
        sourcemap_data = self._load_json_list(bounty_dir / "sourcemap_profile.json")
        bundle_data = self._load_json_list(bounty_dir / "js_bundle_profile.json")
        api_inventory = self._load_json_list(api_dir / "api_inventory.json")
        discovered_apis = self._load_json_list(bounty_dir / "api_inventory.json")
        endpoints = self._load_json_list(web_intel_dir / "endpoint_inventory.json")

        flag_signals = self._scan_feature_flags(js_intel, bundle_data)
        route_signals = self._scan_debug_routes(endpoints, api_inventory, discovered_apis)
        function_signals = self._scan_internal_functions(js_intel, bundle_data)
        sourcemap_signals = self._analyze_sourcemaps(sourcemap_data)

        all_signals = flag_signals + route_signals + function_signals + sourcemap_signals

        self.hypotheses = self._build_hypotheses(all_signals)

        logger.info(
            "HIDDEN_FUNCTIONALITY_ENGINE_DONE flags={} routes={} functions={} hypotheses={}",
            len(flag_signals), len(route_signals), len(function_signals), len(self.hypotheses),
        )
        return self.hypotheses

    def _scan_feature_flags(
        self,
        js_intel: dict[str, Any],
        bundle_data: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []
        content = self._extract_text(js_intel, bundle_data)

        for pattern in FEATURE_FLAG_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                signals.append({
                    "signal_type": "feature_flag",
                    "source": "js_intelligence",
                    "endpoint": "javascript",
                    "method": "N/A",
                    "expected": "standard_code",
                    "observed": match,
                    "severity": "MEDIUM",
                    "description": f"Feature flag or debug control detected: '{match}'",
                })

        return signals

    def _scan_debug_routes(
        self,
        endpoints: list[dict[str, Any]],
        api_inventory: list[dict[str, Any]],
        discovered_apis: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []
        all_urls: set[str] = set()

        for ep in endpoints:
            url = ep.get("url", "") or ep.get("path", "") or ""
            if url:
                all_urls.add(url)

        for ep in api_inventory:
            url = ep.get("url", "") or ep.get("path", "") or ""
            if url:
                all_urls.add(url)

        for ep in discovered_apis:
            url = ep.get("url", "") or ep.get("path", "") or ""
            if url:
                all_urls.add(url)

        for url in all_urls:
            for pattern, category in DEBUG_ROUTE_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    signals.append({
                        "signal_type": "debug_route",
                        "source": "endpoint_analysis",
                        "endpoint": url,
                        "method": "GET",
                        "expected": "production_route",
                        "observed": category,
                        "severity": "HIGH" if "internal" in category or "admin" in category else "MEDIUM",
                        "description": f"Debug/internal route detected: {url} (type: {category})",
                    })

        return signals

    def _scan_internal_functions(
        self,
        js_intel: dict[str, Any],
        bundle_data: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []
        content = self._extract_text(js_intel, bundle_data)

        for pattern in INTERNAL_FUNCTION_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                signals.append({
                    "signal_type": "internal_function",
                    "source": "js_intelligence",
                    "endpoint": "javascript",
                    "method": "N/A",
                    "expected": "public_api",
                    "observed": match,
                    "severity": "MEDIUM",
                    "description": f"Internal/admin function detected: '{match}'",
                })

        return signals

    def _analyze_sourcemaps(self, sourcemap_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for sm in sourcemap_data:
            if sm.get("exposed", False):
                signals.append({
                    "signal_type": "sourcemap_exposed",
                    "source": "sourcemap_analyzer",
                    "endpoint": sm.get("sourcemap_url", ""),
                    "method": "GET",
                    "expected": "sourcemap_hidden",
                    "observed": "exposed",
                    "severity": "HIGH",
                    "description": f"Source map exposed at {sm.get('sourcemap_url', '')}",
                })

            files = sm.get("files", [])
            endpoints_found = sm.get("endpoints", [])
            comments = sm.get("comments", [])

            if endpoints_found:
                signals.append({
                    "signal_type": "sourcemap_routes",
                    "source": "sourcemap_analyzer",
                    "endpoint": sm.get("sourcemap_url", ""),
                    "method": "N/A",
                    "expected": "no_routes",
                    "observed": endpoints_found,
                    "severity": "HIGH",
                    "description": f"Source map reveals {len(endpoints_found)} internal routes",
                })

            for comment in comments:
                if any(kw in comment.lower() for kw in ["todo", "fixme", "hack", "bypass", "admin", "internal", "debug"]):
                    signals.append({
                        "signal_type": "sourcemap_comment",
                        "source": "sourcemap_analyzer",
                        "endpoint": sm.get("sourcemap_url", ""),
                        "method": "N/A",
                        "expected": "clean_comment",
                        "observed": "sensitive_comment",
                        "severity": "LOW",
                        "description": f"Sensitive comment in source map: '{comment[:100]}'",
                    })

        return signals

    def _build_hypotheses(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []

        flag_signals = [s for s in signals if s["signal_type"] == "feature_flag"]
        if flag_signals:
            flags = list(set(s["observed"] for s in flag_signals))
            hypotheses.append({
                "title": "Potential Feature Flags / Debug Controls in JavaScript",
                "hypothesis_type": "Hidden Functionality Research",
                "confidence": "HIGH" if len(flags) >= 3 else "MEDIUM",
                "impact": "HIGH",
                "score": min(60 + len(flags) * 5, 100),
                "signals": [f"Feature flag: {f}" for f in flags[:10]],
                "reasoning": f"{len(flags)} feature flag(s) or debug control(s) detected in client-side code. These may enable hidden functionality, administrative features, or debug modes when activated.",
                "attack_scenario": "An attacker could enable hidden debug modes or admin overrides by manipulating feature flags in browser storage, URL parameters, or API requests.",
                "recommendation": "Manual review of JavaScript code is required to identify feature flag activation mechanisms and assess if they can be abused.",
            })

        route_signals = [s for s in signals if s["signal_type"] == "debug_route"]
        if route_signals:
            routes = list(set(s["endpoint"] for s in route_signals))
            categories = list(set(s["observed"] for s in route_signals))
            hypotheses.append({
                "title": "Potential Hidden / Debug Routes Exposed",
                "hypothesis_type": "Hidden Functionality Research",
                "confidence": "HIGH" if len(routes) >= 3 else "MEDIUM",
                "impact": "CRITICAL" if any("internal" in c or "admin" in c for c in categories) else "HIGH",
                "score": min(65 + len(routes) * 5, 100),
                "signals": [f"Route: {r}" for r in routes[:15]],
                "reasoning": f"{len(routes)} hidden, debug, or internal route(s) detected. These may expose administrative interfaces, internal APIs, or sensitive functionality. Categories: {', '.join(set(categories))}",
                "attack_scenario": "An attacker could discover and access hidden/debug routes to bypass authentication, access internal functionality, or leak sensitive information.",
                "recommendation": "Manual validation of each hidden route is required. Assess authentication requirements, information disclosure, and potential for privilege escalation.",
            })

        internal_func_signals = [s for s in signals if s["signal_type"] == "internal_function"]
        if internal_func_signals:
            funcs = list(set(s["observed"] for s in internal_func_signals))
            hypotheses.append({
                "title": "Potential Internal / Private Functions Exposed in JavaScript",
                "hypothesis_type": "Hidden Functionality Research",
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "score": min(40 + len(funcs) * 3, 80),
                "signals": [f"Function: {f}" for f in funcs[:10]],
                "reasoning": f"{len(funcs)} internal or private function name(s) detected in client-side code. These may reveal hidden API calls or administrative functionality.",
                "attack_scenario": "An attacker could invoke internal functions through client-side manipulation to access unauthorized functionality.",
                "recommendation": "Review client-side code for exposed internal functions and assess if they can be triggered through developer console or parameter manipulation.",
            })

        sm_signals = [s for s in signals if s["signal_type"] in ("sourcemap_exposed", "sourcemap_routes")]
        if sm_signals:
            sm_urls = list(set(s["endpoint"] for s in sm_signals if s["endpoint"]))
            hypotheses.append({
                "title": "Source Maps Exposing Internal Application Structure",
                "hypothesis_type": "Hidden Functionality Research",
                "confidence": "HIGH",
                "impact": "HIGH",
                "score": min(70 + len(sm_urls) * 5, 100),
                "signals": [f"Source map: {u}" for u in sm_urls[:10]],
                "reasoning": f"{len(sm_urls)} source map(s) exposed, potentially revealing application source code, internal routes, API endpoints, and sensitive comments.",
                "attack_scenario": "An attacker can download exposed source maps to reconstruct application source code, discover internal APIs, and find sensitive information in comments.",
                "recommendation": "Verify source map exposure and ensure they are disabled in production environments.",
            })

        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        return hypotheses

    def _extract_text(self, js_intel: dict[str, Any], bundle_data: list[dict[str, Any]]) -> str:
        parts: list[str] = []

        scripts = js_intel.get("scripts_analyzed", [])
        if isinstance(scripts, list):
            for s in scripts:
                if isinstance(s, dict):
                    parts.append(s.get("content", ""))
                elif isinstance(s, str):
                    parts.append(s)

        content = js_intel.get("content", "")
        if content:
            parts.append(str(content))

        raw = js_intel.get("raw_content", "")
        if raw:
            parts.append(str(raw))

        for bundle in bundle_data:
            if isinstance(bundle, dict):
                parts.append(bundle.get("content", ""))
                parts.append(bundle.get("raw", ""))

        return "\n".join(parts)

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
