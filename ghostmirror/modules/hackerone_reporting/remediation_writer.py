"""Generate specific remediation recommendations for bounty submissions."""
from __future__ import annotations

REMEDIATIONS = {
    "missing_csp": "Add a Content-Security-Policy header with appropriate directives to restrict resource loading and mitigate XSS attacks.",
    "missing_hsts": "Add a Strict-Transport-Security header with sufficient max-age to enforce HTTPS connections.",
    "open_redirect": "Validate and sanitize all redirect destinations against a whitelist of allowed URLs.",
    "information_disclosure": "Remove or restrict access to endpoints that disclose internal information.",
    "source_map": "Remove source map files from production deployments.",
    "exposed_secret": "Immediately rotate the exposed credential. Remove hardcoded secrets from source code.",
    "bola": "Enforce object-level authorization checks on every API endpoint.",
    "bfla": "Enforce function-level authorization checks on all privileged operations.",
    "graphql_introspection": "Disable GraphQL introspection in production environments.",
    "jwt_weak": "Use a strong signing algorithm (RS256 or ES256). Never accept the none algorithm.",
    "debug_endpoint": "Remove or disable debug endpoints in production.",
    "cve_remediation": "Apply the vendor-recommended patch, update, or mitigation for the identified CVE.",
}

class RemediationWriter:
    @staticmethod
    def generate(category="", title="", severity=""):
        t, c = title.lower(), category.lower()
        if "csp" in t: return REMEDIATIONS["missing_csp"]
        if "hsts" in t: return REMEDIATIONS["missing_hsts"]
        if "redirect" in t: return REMEDIATIONS["open_redirect"]
        if "information disclosure" in t: return REMEDIATIONS["information_disclosure"]
        if "source map" in t or "sourcemap" in t: return REMEDIATIONS["source_map"]
        if "secret" in t or "key" in t: return REMEDIATIONS["exposed_secret"]
        if "bola" in t or "broken object" in t: return REMEDIATIONS["bola"]
        if "bfla" in t or "broken function" in t: return REMEDIATIONS["bfla"]
        if "graphql" in t or "introspection" in t: return REMEDIATIONS["graphql_introspection"]
        if "jwt" in t: return REMEDIATIONS["jwt_weak"]
        if "debug" in t or "actuator" in t: return REMEDIATIONS["debug_endpoint"]
        if "cve-" in t or "cve" in c: return REMEDIATIONS["cve_remediation"]
        return "Review the finding and apply the appropriate security control to address the identified weakness."
