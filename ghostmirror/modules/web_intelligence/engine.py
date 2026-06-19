from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.web_indicator import IndicatorType, WebIndicator
from ghostmirror.models.web_intelligence_report import WebIntelligenceReport
from ghostmirror.models.web_attack_surface import IndicatorSummary, WebAttackSurface
from ghostmirror.modules.web_intelligence.endpoint_mapper import EndpointMapper
from ghostmirror.modules.web_intelligence.parameter_discovery import ParameterDiscovery
from ghostmirror.modules.web_intelligence.js_intelligence import JSIntelligence
from ghostmirror.modules.web_intelligence.auth_intelligence import AuthIntelligence
from ghostmirror.modules.web_intelligence.injection_indicators import InjectionIndicators
from ghostmirror.modules.web_intelligence.xss_indicators import XSSIndicators
from ghostmirror.modules.web_intelligence.ssti_indicators import SSTIIndicators
from ghostmirror.modules.web_intelligence.ssrf_indicators import SSRFIndicators
from ghostmirror.modules.web_intelligence.idor_indicators import IDORIndicators
from ghostmirror.modules.web_intelligence.redirect_indicators import RedirectIndicators
from ghostmirror.modules.web_intelligence.traversal_indicators import TraversalIndicators
from ghostmirror.modules.web_intelligence.business_logic_indicators import BusinessLogicIndicators
from ghostmirror.modules.web_intelligence.correlation import CorrelationEngine
from ghostmirror.modules.web_intelligence.scoring import WebScoringEngine
from ghostmirror.modules.web_intelligence.recommendations import WebRecommendationEngine
from ghostmirror.modules.web_intelligence.findings_mapper import WebFindingsMapper

logger = get_logger()


class WebIntelligenceEngine:
    def __init__(self, max_crawl_depth: int = 1) -> None:
        self.max_crawl_depth = max_crawl_depth
        self.endpoint_mapper = EndpointMapper(max_depth=max_crawl_depth)
        self.parameter_discovery = ParameterDiscovery()
        self.js_intelligence = JSIntelligence()
        self.auth_intelligence = AuthIntelligence()
        self.injection_indicators = InjectionIndicators()
        self.xss_indicators = XSSIndicators()
        self.ssti_indicators = SSTIIndicators()
        self.ssrf_indicators = SSRFIndicators()
        self.idor_indicators = IDORIndicators()
        self.redirect_indicators = RedirectIndicators()
        self.traversal_indicators = TraversalIndicators()
        self.business_logic_indicators = BusinessLogicIndicators()
        self.correlation_engine = CorrelationEngine()
        self.scoring_engine = WebScoringEngine()
        self.recommendation_engine = WebRecommendationEngine()
        self.findings_mapper = WebFindingsMapper()

    def analyze_project(
        self,
        project_path: Path | str,
        target_url: str | None = None,
    ) -> WebIntelligenceReport:
        project_path = Path(project_path)
        logger.info("WEB_INTELLIGENCE_START project={}", project_path.name)

        profiles_dir = project_path / "profiles"
        web_intel_dir = profiles_dir / "web_intelligence"
        web_intel_dir.mkdir(parents=True, exist_ok=True)

        tech_profile = self._load_json(profiles_dir / "technology_profile.json") or {}
        headers_file = self._load_json(project_path / "findings" / "headers.json") or {}
        headers = self._extract_headers(headers_file)

        target = target_url or tech_profile.get("target") or ""

        if not target:
            logger.warning("WEB_INTELLIGENCE_SKIPPED no target available")
            return self._empty_report()

        normalized_target = target if target.startswith("http") else f"https://{target}"

        endpoints = self.endpoint_mapper.discover(normalized_target)
        parameters = self.parameter_discovery.discover(endpoints)

        script_urls = []
        for ep in endpoints:
            script_urls.extend(self.endpoint_mapper.get_script_urls(ep.response_body_sample, ep.url))
        js_findings = self.js_intelligence.analyze(script_urls)

        auth_profile = self.auth_intelligence.analyze(endpoints, headers=headers)

        all_indicators: list[WebIndicator] = []
        all_indicators.extend(self.injection_indicators.analyze(endpoints, parameters))
        all_indicators.extend(self.xss_indicators.analyze(endpoints, parameters))
        all_indicators.extend(self.ssti_indicators.analyze(endpoints, tech_profile))
        all_indicators.extend(self.ssrf_indicators.analyze(parameters, js_findings))
        all_indicators.extend(self.idor_indicators.analyze(endpoints))
        all_indicators.extend(self.redirect_indicators.analyze(parameters))
        all_indicators.extend(self.traversal_indicators.analyze(parameters))
        business_areas, business_indicators = self.business_logic_indicators.analyze(endpoints, parameters)
        all_indicators.extend(business_indicators)

        correlations = self.correlation_engine.correlate(
            endpoints=endpoints,
            indicators=all_indicators,
            tech_profile=tech_profile,
            js_findings=js_findings,
            auth_profile=auth_profile,
        )

        opportunities = self.scoring_engine.calculate_opportunities(correlations)

        attack_surface = self._build_attack_surface(endpoints, parameters, all_indicators, auth_profile, js_findings)

        exposure_map = {"INFO": 0, "LOW": 20, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
        report = WebIntelligenceReport(
            target=normalized_target,
            endpoints=endpoints,
            parameters=parameters,
            indicators=all_indicators,
            correlations=correlations,
            opportunities=opportunities,
            business_areas=business_areas,
            auth_profile=auth_profile,
            js_findings=js_findings,
            attack_surface=attack_surface,
            overall_score=exposure_map.get(attack_surface.overall_exposure, 0),
            risk_level=attack_surface.overall_exposure,
            total_endpoints=len(endpoints),
            total_parameters=len(parameters),
            total_indicators=len(all_indicators),
            total_opportunities=len(opportunities),
        )

        recommendations = self.recommendation_engine.generate(report)

        findings = self.findings_mapper.map_to_findings(all_indicators, normalized_target)

        self._save_artifacts(web_intel_dir, report, recommendations, findings, attack_surface)
        self._save_findings(project_path, findings)

        logger.info("WEB_INTELLIGENCE_COMPLETE endpoints={} indicators={} opportunities={}",
                    len(endpoints), len(all_indicators), len(opportunities))
        return report

    def _build_attack_surface(
        self,
        endpoints: list[WebEndpoint],
        parameters: list[ParameterProfile],
        indicators: list[WebIndicator],
        auth_profile: dict[str, Any],
        js_findings: dict[str, Any],
    ) -> WebAttackSurface:
        indicator_summary = IndicatorSummary()
        high_conf = 0
        for ind in indicators:
            field = ind.indicator_type.value
            if hasattr(indicator_summary, field):
                setattr(indicator_summary, field, getattr(indicator_summary, field) + 1)
            if ind.confidence.value in ("high", "confirmed"):
                high_conf += 1

        sensitive_params = sum(1 for p in parameters if p.sensitivity.value in ("high", "critical"))

        total_endpoints = len(endpoints)
        total_indicators = len(indicators)

        if total_endpoints == 0:
            exposure = "LOW"
        elif total_indicators >= 10 or high_conf >= 3:
            exposure = "CRITICAL"
        elif total_indicators >= 5 or high_conf >= 1:
            exposure = "HIGH"
        elif total_indicators >= 2:
            exposure = "MEDIUM"
        else:
            exposure = "LOW"

        return WebAttackSurface(
            total_endpoints=total_endpoints,
            auth_endpoints=auth_profile.get("total_auth_endpoints", 0),
            api_endpoints=sum(1 for e in endpoints if e.is_api),
            admin_endpoints=sum(1 for e in endpoints if e.is_admin),
            js_endpoints=js_findings.get("scripts_analyzed", 0),
            param_count=len(parameters),
            sensitive_params=sensitive_params,
            forms_count=sum(len(ep.forms) for ep in endpoints),
            indicator_summary=indicator_summary,
            high_confidence_indicators=high_conf,
            overall_exposure=exposure,
        )

    def _save_artifacts(
        self,
        output_dir: Path,
        report: WebIntelligenceReport,
        recommendations: list[dict[str, Any]],
        findings: list[Any],
        attack_surface: WebAttackSurface,
    ) -> None:
        self._save_json(output_dir / "endpoint_inventory.json", [ep.model_dump(mode="json") for ep in report.endpoints])
        self._save_json(output_dir / "parameter_inventory.json", [p.model_dump(mode="json") for p in report.parameters])
        self._save_json(output_dir / "js_intelligence.json", report.js_findings)
        self._save_json(output_dir / "auth_profile.json", report.auth_profile)
        self._save_json(output_dir / "web_indicators.json", [i.model_dump(mode="json") for i in report.indicators])
        self._save_json(output_dir / "business_logic.json", [a.model_dump(mode="json") for a in report.business_areas])
        self._save_json(output_dir / "correlation_results.json", [c.model_dump(mode="json") for c in report.correlations])
        self._save_json(output_dir / "opportunity_scores.json", [o.model_dump(mode="json") for o in report.opportunities])
        self._save_json(output_dir / "web_recommendations.json", recommendations)
        self._save_json(output_dir / "attack_surface.json", attack_surface.model_dump(mode="json"))
        self._save_json(output_dir / "web_intelligence_report.json", report.model_dump(mode="json"))

    def _save_findings(self, project_path: Path, findings: list[Any]) -> None:
        if not findings:
            return
        try:
            findings_dir = project_path / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            path = findings_dir / "web_intelligence.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    [f.model_dump(mode="json") for f in findings],
                    f, indent=2, ensure_ascii=False,
                )
            logger.info("WEB_INTELLIGENCE_FINDINGS_SAVED count={}", len(findings))
        except Exception as exc:
            logger.warning("WEB_INTELLIGENCE_FINDINGS_SAVE_FAILED error={}", exc)

    def _extract_headers(self, headers_file: dict[str, Any] | None) -> dict[str, str]:
        if not headers_file:
            return {}
        try:
            findings = headers_file.get("findings", [])
            if not findings:
                return {}
            result = {}
            for f in findings:
                if isinstance(f, dict) and "title" in f and "evidence" in f:
                    result[f["title"]] = f["evidence"]
            return result
        except Exception:
            return {}

    def _load_json(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load JSON {}: {}", path, exc)
            return None

    def _save_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug("Saved {}", path)
        except Exception as exc:
            logger.warning("Failed to save JSON {}: {}", path, exc)

    def _empty_report(self) -> WebIntelligenceReport:
        return WebIntelligenceReport(target="", overall_score=0, risk_level="INFO")
