from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.zero_day.confidence_engine import ConfidenceEngine

logger = get_logger()

HYPOTHESIS_TEMPLATES: dict[str, dict[str, str]] = {
    "authorization": {
        "title": "Potential Authorization Logic Flaw",
        "reasoning": "The combination of sensitive resources, administrative endpoints and authentication may indicate an authorization control weakness that warrants manual review.",
        "recommendation": "Manual validation required. Test for IDOR, privilege escalation, and missing function-level access controls.",
    },
    "business_logic": {
        "title": "Potential Business Logic Vulnerability",
        "reasoning": "Complex business flows combined with financial parameters may contain logic flaws exploitable through parameter manipulation or race conditions.",
        "recommendation": "Manual validation required. Map the complete business flow and test for parameter tampering, race conditions, and state manipulation.",
    },
    "hidden_functionality": {
        "title": "Potential Hidden Functionality Exposure",
        "reasoning": "Client-side code analysis reveals feature flags, debug controls, or internal routes that may enable unauthorized functionality when activated.",
        "recommendation": "Manual validation required. Investigate feature flag activation mechanisms and assess exposure of hidden routes.",
    },
    "api": {
        "title": "Potential API Security Vulnerability",
        "reasoning": "API endpoints discovered with sensitive operations may lack proper authentication, authorization, or rate limiting controls.",
        "recommendation": "Manual validation required. Test authentication requirements, authorization controls, and rate limiting on discovered API endpoints.",
    },
    "graphql": {
        "title": "Potential GraphQL Vulnerability",
        "reasoning": "GraphQL endpoint detected with introspection capabilities may expose sensitive data or allow abusive queries.",
        "recommendation": "Manual validation required. Test for introspection exposure, batching attacks, depth/complexity issues, and authorization bypass.",
    },
    "jwt": {
        "title": "Potential JWT Security Issue",
        "reasoning": "JWT-based authentication detected. Common issues include weak secrets, algorithm confusion, and missing signature verification.",
        "recommendation": "Manual validation required. Test JWT implementation for algorithm confusion, weak secrets, token expiration, and signature verification.",
    },
    "financial": {
        "title": "Potential Financial Logic Vulnerability",
        "reasoning": "Financial operations (transfers, payments, wallets) detected. These flows often contain critical logic flaws that can lead to financial loss.",
        "recommendation": "Manual validation required. Focus on parameter manipulation, race conditions in financial transactions, and authorization bypass.",
    },
}


class HypothesisBuilder:
    def __init__(self) -> None:
        self.confidence_engine = ConfidenceEngine()

    def build(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        logger.info("HYPOTHESIS_BUILDER_START")
        hypotheses: list[dict[str, Any]] = []

        hypotheses.extend(self._build_from_attack_chains(attack_chains))
        hypotheses.extend(self._build_from_anomalies(anomalies, signals))
        hypotheses.extend(self._build_from_opportunities(opportunities, signals))
        hypotheses.extend(self._build_cross_cutting(anomalies, attack_chains, opportunities, signals))

        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        logger.info("HYPOTHESIS_BUILDER_DONE count={}", len(hypotheses))
        return hypotheses

    def _build_from_attack_chains(self, attack_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        for chain in attack_chains:
            htype = self._detect_hypothesis_type(chain.get("components", []))
            template = HYPOTHESIS_TEMPLATES.get(htype, HYPOTHESIS_TEMPLATES["authorization"])

            hypotheses.append({
                "title": template["title"],
                "hypothesis_type": htype.replace("_", " ").title() + " Research",
                "confidence": chain.get("confidence", "MEDIUM"),
                "impact": chain.get("severity", "MEDIUM"),
                "score": chain.get("score", 50),
                "signals": chain.get("components", []),
                "reasoning": chain.get("description", "") + " " + template["reasoning"],
                "attack_scenario": chain.get("attack_vector", ""),
                "recommendation": template["recommendation"],
            })
        return hypotheses

    def _build_from_anomalies(
        self,
        anomalies: list[dict[str, Any]],
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        high_sev = [a for a in anomalies if a.get("severity") in ("CRITICAL", "HIGH")]

        if len(high_sev) >= 2:
            sigs_for_hypothesis = []
            for a in high_sev:
                sigs_for_hypothesis.extend(a.get("signals", []))

            confidence = self.confidence_engine.evaluate_from_signals(sigs_for_hypothesis)
            hypotheses.append({
                "title": "Potential Security Control Weakness",
                "hypothesis_type": "Authorization Research",
                "confidence": confidence,
                "impact": "HIGH",
                "score": min(len(high_sev) * 20, 90),
                "signals": [f"{a.get('title', '')}" for a in high_sev[:5]],
                "reasoning": f"Multiple high-severity anomalies detected ({len(high_sev)}). This pattern may indicate weak security controls or missing authentication/authorization checks.",
                "attack_scenario": "An attacker could exploit these weaknesses to access unauthorized resources or perform privileged actions.",
                "recommendation": "Manual validation of each high-severity anomaly is required. Review authentication and authorization controls.",
            })

        auth_anomalies = [a for a in anomalies if a.get("category") in ("rare_endpoint", "sensitive_header")]
        if auth_anomalies:
            hypotheses.append({
                "title": "Potential Information Disclosure",
                "hypothesis_type": "Information Disclosure Research",
                "confidence": "MEDIUM",
                "impact": "MEDIUM",
                "score": min(len(auth_anomalies) * 15, 70),
                "signals": [a.get("title", "") for a in auth_anomalies[:5]],
                "reasoning": f"Sensitive endpoints or headers exposed ({len(auth_anomalies)} findings). This may leak internal application structure or sensitive data.",
                "attack_scenario": "An attacker could leverage exposed information for reconnaissance and targeted attacks.",
                "recommendation": "Review exposed endpoints and headers. Restrict access to sensitive information.",
            })

        return hypotheses

    def _build_from_opportunities(
        self,
        opportunities: list[dict[str, Any]],
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []

        bl_opps = [o for o in opportunities if o.get("opportunity_type") == "Business Logic Research"]
        if bl_opps and len(bl_opps) >= 2:
            confidence = self.confidence_engine.evaluate_from_signals(signals)
            hypotheses.append({
                "title": "Potential Business Logic Vulnerability Chain",
                "hypothesis_type": "Business Logic Research",
                "confidence": confidence,
                "impact": "HIGH",
                "score": min(sum(o.get("score", 0) for o in bl_opps) // len(bl_opps) + 10, 95),
                "signals": [o.get("title", "") for o in bl_opps[:5]],
                "reasoning": f"Multiple business logic opportunities detected ({len(bl_opps)}). Combined, these may represent a critical business logic vulnerability chain.",
                "attack_scenario": "An attacker could chain multiple business logic flaws to achieve financial gain or privilege escalation.",
                "recommendation": "Comprehensive manual review of all business logic flows is recommended. Focus on parameter manipulation and state transitions.",
            })

        return hypotheses

    def _build_cross_cutting(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        total_findings = len(anomalies) + len(attack_chains) + len(opportunities)

        if total_findings >= 5:
            confidence = self.confidence_engine.evaluate_from_signals(signals)
            signal_types = list(set(s.get("signal_type", "") for s in signals))

            hypotheses.append({
                "title": "High-Value Research Target",
                "hypothesis_type": "Composite Research",
                "confidence": confidence,
                "impact": "CRITICAL" if total_findings >= 10 else "HIGH",
                "score": min(total_findings * 8, 95),
                "signals": [f"Signal type: {st}" for st in signal_types[:10]],
                "reasoning": f"High concentration of signals detected: {len(anomalies)} anomalies, {len(attack_chains)} attack chains, {len(opportunities)} opportunities. Signal types: {', '.join(signal_types[:5])}. This application appears to have a large attack surface worthy of manual investigation.",
                "attack_scenario": "The combination of multiple vulnerability signals suggests a broad attack surface with potential for critical findings.",
                "recommendation": "Prioritize this target for manual testing. Start with high-confidence signals and attack chains.",
            })

        return hypotheses

    def _detect_hypothesis_type(self, components: list[str]) -> str:
        type_keywords = {
            "jwt": "jwt",
            "graphql": "graphql",
            "admin": "authorization",
            "api": "api",
            "business": "business_logic",
            "logic": "business_logic",
            "financial": "financial",
            "money": "financial",
            "hidden": "hidden_functionality",
            "debug": "hidden_functionality",
        }

        for comp in components:
            comp_lower = comp.lower()
            for keyword, htype in type_keywords.items():
                if keyword in comp_lower:
                    return htype

        return "authorization"
