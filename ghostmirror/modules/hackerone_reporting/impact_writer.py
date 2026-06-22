"""Generate professional business and technical impact descriptions."""
from __future__ import annotations

BUSINESS_IMPACTS = {
    "missing_header": "This weakness may increase the likelihood of successful exploitation of client-side or protocol-level attacks, depending on the affected application context.",
    "open_redirect": "Open redirects can be leveraged in phishing campaigns by making malicious URLs appear legitimate, potentially eroding user trust and leading to credential theft.",
    "information_disclosure": "Exposed internal information may assist attackers in fingerprinting the application, identifying attack surface, and crafting more precise attacks.",
    "bola": "Broken object-level authorization may allow an attacker to access or modify another user data, leading to data breaches and regulatory non-compliance.",
    "source_map": "Source maps in production expose application source code, including internal logic, API endpoints, and secrets.",
    "exposed_secret": "Exposed credentials or API keys may allow unauthorized access to internal or third-party services.",
    "graphql_introspection": "Enabling introspection in production reveals the complete API schema, including undocumented mutations and sensitive data types.",
    "jwt_weak": "Weak JWT configuration may allow token forgery, leading to authentication bypass and account takeover.",
    "cve_potential": "Known vulnerabilities in internet-facing software components may be exploited to compromise the affected system.",
}

TECHNICAL_IMPACTS = {
    "missing_header": "The affected endpoint does not include a security header that could prevent or mitigate specific attack classes.",
    "open_redirect": "The endpoint accepts URL-like values that may influence the redirect destination without adequate validation.",
    "information_disclosure": "The application returns information that may assist an attacker in reconnaissance.",
    "bola": "An API endpoint accepts object identifiers without verifying ownership or authorization.",
    "source_map": "Source map files are publicly accessible, revealing the application original source code.",
    "exposed_secret": "A credential or token was identified in a publicly accessible location.",
    "graphql_introspection": "The GraphQL endpoint responds to introspection queries, exposing the full schema.",
    "jwt_weak": "JWT tokens using weak algorithms or configurations may be vulnerable to forgery or tampering.",
    "cve_potential": "The identified software version or configuration corresponds to a known vulnerability (CVE).",
}

class ImpactWriter:
    @staticmethod
    def write_business_impact(title="", category="", severity=""):
        k = ImpactWriter._resolve_key(title, category)
        return BUSINESS_IMPACTS.get(k, "This finding may have business impact depending on the affected application context and the nature of the weakness.")
    @staticmethod
    def write_technical_impact(title="", category="", severity=""):
        k = ImpactWriter._resolve_key(title, category)
        return TECHNICAL_IMPACTS.get(k, "The finding represents a security weakness that may affect the confidentiality, integrity, or availability of the affected system.")
    @staticmethod
    def write_impact_section(title="", category="", severity=""):
        return {"business": ImpactWriter.write_business_impact(title, category, severity), "technical": ImpactWriter.write_technical_impact(title, category, severity)}
    @staticmethod
    def _resolve_key(title, category):
        t, c = title.lower(), category.lower()
        if "csp" in t or "missing header" in c: return "missing_header"
        if "redirect" in t: return "open_redirect"
        if "information disclosure" in t or "information disclosure" in c: return "information_disclosure"
        if "bola" in t or "broken object" in t: return "bola"
        if "source map" in t or "sourcemap" in t: return "source_map"
        if "secret" in t or "exposed" in t: return "exposed_secret"
        if "graphql" in t or "introspection" in t: return "graphql_introspection"
        if "jwt" in t: return "jwt_weak"
        if "cve" in t or "cve" in c: return "cve_potential"
        return "generic"
