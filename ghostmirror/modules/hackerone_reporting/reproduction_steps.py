"""Generate safe, non-destructive reproduction steps for bounty submissions."""
from __future__ import annotations
from typing import Any
from ghostmirror.models.reproduction_step import ReproductionStep

class SafeReproductionStepGenerator:
    @staticmethod
    def from_finding(finding):
        title = ""
        category = ""
        if isinstance(finding, dict):
            title = finding.get("title", "")
            category = finding.get("category", "")
        else:
            title = getattr(finding, "title", "")
            category = getattr(finding, "category", "")
        tl = title.lower()
        cl = category.lower()
        if "csp" in tl or "missing header" in cl: return SafeReproductionStepGenerator._for_missing_header("Content-Security-Policy")
        if "open redirect" in tl or "redirect" in tl: return SafeReproductionStepGenerator._for_open_redirect(title)
        if "information disclosure" in tl: return SafeReproductionStepGenerator._for_information_disclosure(title)
        if "source map" in tl or "sourcemap" in tl: return SafeReproductionStepGenerator._for_source_map()
        if "secret" in tl or "exposed" in tl: return SafeReproductionStepGenerator._for_exposed_secret()
        if "bola" in tl or "broken object" in tl: return SafeReproductionStepGenerator._for_bola()
        if "bfla" in tl or "broken function" in tl: return SafeReproductionStepGenerator._for_bfla()
        if "graphql" in tl or "introspection" in tl: return SafeReproductionStepGenerator._for_graphql_introspection()
        if "jwt" in tl: return SafeReproductionStepGenerator._for_jwt_weak()
        if "debug" in tl or "/actuator" in tl: return SafeReproductionStepGenerator._for_debug_endpoint()
        if "cve" in tl or "cve-" in tl: return SafeReproductionStepGenerator._for_cve_potential()
        if "hypothesis" in cl: return SafeReproductionStepGenerator._for_hypothesis()
        return SafeReproductionStepGenerator._generic_steps(title)

    @staticmethod
    def _for_missing_header(header_name):
        return [ReproductionStep(step_number=1, description="Send a GET request to the affected URL.", expected_observation="Server responds with 200 OK."), ReproductionStep(step_number=2, description=f"Inspect HTTP response headers.", expected_observation=f"{header_name} header is missing."), ReproductionStep(step_number=3, description="Compare with security best practices.", expected_observation="OWASP recommends including this header.")]

    @staticmethod
    def _for_open_redirect(title):
        return [ReproductionStep(step_number=1, description=f"Identify redirect parameter in: {title}.", expected_observation="Parameter accepting URL values is present."), ReproductionStep(step_number=2, description="Confirm endpoint accepts external URL-like values.", expected_observation="Parameter may influence redirect destination."), ReproductionStep(step_number=3, description="Manual validation required before exploitation claims.", expected_observation="Verify if arbitrary redirects are possible.")]

    @staticmethod
    def _for_information_disclosure(title):
        return [ReproductionStep(step_number=1, description=f"Access the identified endpoint: {title}.", expected_observation="Endpoint returns content with potential internal data."), ReproductionStep(step_number=2, description="Review returned content for internal paths.", expected_observation="Information aiding fingerprinting may be exposed."), ReproductionStep(step_number=3, description="Document the information exposed.", expected_observation="Review by development team is recommended.")]

    @staticmethod
    def _for_source_map():
        return [ReproductionStep(step_number=1, description="Identify source map file URL (.map extension).", expected_observation="A .map file is publicly accessible."), ReproductionStep(step_number=2, description="Access the source map URL.", expected_observation="Original source code is revealed."), ReproductionStep(step_number=3, description="Remove source maps in production.", expected_observation="Source maps expose original source code.")]

    @staticmethod
    def _for_exposed_secret():
        return [ReproductionStep(step_number=1, description="Identify where a potential secret was detected.", expected_observation="Pattern matching a credential is present."), ReproductionStep(step_number=2, description="Manually verify if the pattern is an active credential.", expected_observation="Secret type should be assessed."), ReproductionStep(step_number=3, description="If confirmed, rotate credential immediately.", expected_observation="Credentials should be removed and rotated.")]

    @staticmethod
    def _for_bola():
        return [ReproductionStep(step_number=1, description="Identify API endpoint using object identifiers.", expected_observation="Endpoint accepts a user-supplied identifier."), ReproductionStep(step_number=2, description="Assess if authorization is enforced.", expected_observation="Unauthorized access to other resources may be possible."), ReproductionStep(step_number=3, description="Manual validation required.", expected_observation="Object-level authorization should be enforced.")]

    @staticmethod
    def _for_bfla():
        return [ReproductionStep(step_number=1, description="Identify admin or privileged API endpoints.", expected_observation="Endpoint performs privileged operations."), ReproductionStep(step_number=2, description="Assess if RBAC restricts access.", expected_observation="Non-admin users might access admin functions."), ReproductionStep(step_number=3, description="Manual validation required.", expected_observation="Function-level authorization should be verified.")]

    @staticmethod
    def _for_graphql_introspection():
        return [ReproductionStep(step_number=1, description="Send POST request with introspection query to GraphQL endpoint.", expected_observation="Full GraphQL schema is returned."), ReproductionStep(step_number=2, description="Review schema for sensitive operations.", expected_observation="Schema may reveal internal data structures."), ReproductionStep(step_number=3, description="Disable introspection in production.", expected_observation="Introspection should be development-only.")]

    @staticmethod
    def _for_jwt_weak():
        return [ReproductionStep(step_number=1, description="Capture a JWT token (redacted in report).", expected_observation="Application uses JWT for authentication."), ReproductionStep(step_number=2, description="Decode JWT payload and inspect algorithm/claims.", expected_observation="Weak algorithms or sensitive claims may be present."), ReproductionStep(step_number=3, description="Follow JWT best practices.", expected_observation="JWT configuration should be hardened.")]

    @staticmethod
    def _for_debug_endpoint():
        return [ReproductionStep(step_number=1, description="Access the debug or admin endpoint.", expected_observation="Endpoint responds with debug information."), ReproductionStep(step_number=2, description="Document exposed information.", expected_observation="Debug endpoints may leak internal state."), ReproductionStep(step_number=3, description="Remove or restrict debug endpoints in production.", expected_observation="Debug endpoints should be protected.")]

    @staticmethod
    def _for_cve_potential():
        return [ReproductionStep(step_number=1, description="Verify software version of affected component.", expected_observation="Version matches a known vulnerability pattern."), ReproductionStep(step_number=2, description="Review CVE details and assess reachability.", expected_observation="Exploitability depends on context."), ReproductionStep(step_number=3, description="Apply vendor-recommended patch or mitigation.", expected_observation="CVE findings require manual verification.")]

    @staticmethod
    def _for_hypothesis():
        return [ReproductionStep(step_number=1, description="Review hypothesis details and supporting signals.", expected_observation="Based on observable signals."), ReproductionStep(step_number=2, description="Manually validate using safe techniques.", expected_observation="Hypotheses require human validation."), ReproductionStep(step_number=3, description="If validated, treat as standard finding.", expected_observation="Hypotheses are research suggestions.")]

    @staticmethod
    def _generic_steps(title):
        return [ReproductionStep(step_number=1, description=f"Access the affected resource: {title}.", expected_observation="Resource responds as expected."), ReproductionStep(step_number=2, description="Observe behavior and compare with expected controls.", expected_observation="Manual validation is required.")]
