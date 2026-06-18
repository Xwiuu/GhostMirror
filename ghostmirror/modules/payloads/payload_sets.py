"""Pre-defined safe, non-destructive payload sets organized by category."""

from ghostmirror.models.payload_profile import PayloadCategory, SafetyLevel
from ghostmirror.modules.payloads.models import PayloadDefinition


XSS_REFLECTION_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_xss_probe_001",
        name="Basic XSS Probe - script alert",
        category=PayloadCategory.XSS_REFLECTION,
        description='Reflected XSS indicator with <script>alert(1)</script>',
        value="<script>alert(1)</script>",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_script_tag",
    ),
    PayloadDefinition(
        id="gm_xss_probe_002",
        name="Basic XSS Probe - img onerror",
        category=PayloadCategory.XSS_REFLECTION,
        description='Reflected XSS indicator with <img src=x onerror=alert(1)>',
        value="<img src=x onerror=alert(1)>",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_img_onerror",
    ),
    PayloadDefinition(
        id="gm_xss_probe_003",
        name="Basic XSS Probe - svg onload",
        category=PayloadCategory.XSS_REFLECTION,
        description='Reflected XSS indicator with <svg onload=alert(1)>',
        value="<svg onload=alert(1)>",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_svg_onload",
    ),
    PayloadDefinition(
        id="gm_xss_probe_004",
        name="XSS Probe - javascript URL",
        category=PayloadCategory.XSS_REFLECTION,
        description='Reflected XSS indicator with javascript:alert(1)',
        value="javascript:alert(1)",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_javascript_url",
    ),
]

SQL_ERROR_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_sql_probe_001",
        name="SQL Error Probe - single quote",
        category=PayloadCategory.SQL_ERROR_INDICATOR,
        description="SQL error indicator using a single quote",
        value="'",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_ERROR_TRIGGER,
        destructive=False,
        expected_signal="sql_error_message",
    ),
    PayloadDefinition(
        id="gm_sql_probe_002",
        name="SQL Error Probe - double quote",
        category=PayloadCategory.SQL_ERROR_INDICATOR,
        description="SQL error indicator using a double quote",
        value='"',
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_ERROR_TRIGGER,
        destructive=False,
        expected_signal="sql_error_message",
    ),
    PayloadDefinition(
        id="gm_sql_probe_003",
        name="SQL Error Probe - closing paren",
        category=PayloadCategory.SQL_ERROR_INDICATOR,
        description="SQL error indicator using a closing parenthesis",
        value=")",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_ERROR_TRIGGER,
        destructive=False,
        expected_signal="sql_error_message",
    ),
    PayloadDefinition(
        id="gm_sql_probe_004",
        name="SQL Error Probe - union select",
        category=PayloadCategory.SQL_ERROR_INDICATOR,
        description="SQL error indicator using UNION SELECT (no data extraction)",
        value=" UNION SELECT 1,2,3--",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_ERROR_TRIGGER,
        destructive=False,
        expected_signal="sql_error_message",
    ),
]

OPEN_REDIRECT_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_redirect_probe_001",
        name="Open Redirect Probe - ghostmirror.invalid",
        category=PayloadCategory.OPEN_REDIRECT_INDICATOR,
        description="Open redirect indicator pointing to ghostmirror.invalid (safe, non-routable test domain)",
        value="https://ghostmirror.invalid/",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="redirect_to_third_party",
    ),
    PayloadDefinition(
        id="gm_redirect_probe_002",
        name="Open Redirect Probe - double slash",
        category=PayloadCategory.OPEN_REDIRECT_INDICATOR,
        description="Open redirect indicator using // bypass technique",
        value="//ghostmirror.invalid",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="redirect_to_third_party",
    ),
]

SSRF_SURFACE_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_ssrf_probe_001",
        name="SSRF Surface Probe - localhost",
        category=PayloadCategory.SSRF_SURFACE_INDICATOR,
        description="SSRF surface indicator pointing to localhost (safe probe, no callback)",
        value="http://127.0.0.1/",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="ssrf_surface_detected",
    ),
    PayloadDefinition(
        id="gm_ssrf_probe_002",
        name="SSRF Surface Probe - localhost IPv6",
        category=PayloadCategory.SSRF_SURFACE_INDICATOR,
        description="SSRF surface indicator pointing to IPv6 localhost (safe probe)",
        value="http://[::1]/",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="ssrf_surface_detected",
    ),
    PayloadDefinition(
        id="gm_ssrf_probe_003",
        name="SSRF Surface Probe - localhost with port",
        category=PayloadCategory.SSRF_SURFACE_INDICATOR,
        description="SSRF surface indicator pointing to localhost:8080 (safe probe)",
        value="http://127.0.0.1:8080/",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="ssrf_surface_detected",
    ),
]

PATH_TRAVERSAL_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_path_probe_001",
        name="Path Traversal Probe - ghostmirror_probe",
        category=PayloadCategory.PATH_TRAVERSAL_INDICATOR,
        description="Path traversal indicator using safe probe filename (no real sensitive files)",
        value="../ghostmirror_probe",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="path_traversal_error",
    ),
    PayloadDefinition(
        id="gm_path_probe_002",
        name="Path Traversal Probe - windows dotdot backslash",
        category=PayloadCategory.PATH_TRAVERSAL_INDICATOR,
        description="Path traversal indicator with Windows-style backslash",
        value="..\\ghostmirror_probe",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="path_traversal_error",
    ),
    PayloadDefinition(
        id="gm_path_probe_003",
        name="Path Traversal Probe - encoded dotdot",
        category=PayloadCategory.PATH_TRAVERSAL_INDICATOR,
        description="Path traversal indicator with URL-encoded traversal",
        value="%2e%2e/ghostmirror_probe",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="path_traversal_error",
    ),
]

HEADER_INJECTION_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_header_probe_001",
        name="Header Injection Probe - CRLF probe",
        category=PayloadCategory.HEADER_INJECTION_INDICATOR,
        description="Header injection indicator using CRLF (safe probe, no response splitting)",
        value="%0d%0aX-GhostMirror-Probe: 1",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="header_injection_detected",
    ),
]

TEMPLATE_INJECTION_INDICATOR_PAYLOADS: list[PayloadDefinition] = [
    PayloadDefinition(
        id="gm_ssti_probe_001",
        name="SSTI Probe - math expression",
        category=PayloadCategory.TEMPLATE_INJECTION_INDICATOR,
        description="Server-side template injection indicator using math expression {{7*7}}",
        value="{{7*7}}",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_template_expression",
    ),
    PayloadDefinition(
        id="gm_ssti_probe_002",
        name="SSTI Probe - variable reference",
        category=PayloadCategory.TEMPLATE_INJECTION_INDICATOR,
        description="Server-side template injection indicator using variable reference {{config}}",
        value="{{config}}",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.PASSIVE,
        destructive=False,
        expected_signal="reflected_template_config",
    ),
    PayloadDefinition(
        id="gm_ssti_probe_003",
        name="SSTI Probe - jinja2 expression",
        category=PayloadCategory.TEMPLATE_INJECTION_INDICATOR,
        description="Server-side template injection indicator using {{7*'7'}}",
        value="{{7*'7'}}",
        method="GET",
        parameter_type="query",
        safety_level=SafetyLevel.SAFE_REFLECTION,
        destructive=False,
        expected_signal="reflected_template_expression",
    ),
]

PAYLOAD_SET_MAP: dict[PayloadCategory, list[PayloadDefinition]] = {
    PayloadCategory.XSS_REFLECTION: XSS_REFLECTION_PAYLOADS,
    PayloadCategory.SQL_ERROR_INDICATOR: SQL_ERROR_INDICATOR_PAYLOADS,
    PayloadCategory.OPEN_REDIRECT_INDICATOR: OPEN_REDIRECT_INDICATOR_PAYLOADS,
    PayloadCategory.SSRF_SURFACE_INDICATOR: SSRF_SURFACE_INDICATOR_PAYLOADS,
    PayloadCategory.PATH_TRAVERSAL_INDICATOR: PATH_TRAVERSAL_INDICATOR_PAYLOADS,
    PayloadCategory.HEADER_INJECTION_INDICATOR: HEADER_INJECTION_INDICATOR_PAYLOADS,
    PayloadCategory.TEMPLATE_INJECTION_INDICATOR: TEMPLATE_INJECTION_INDICATOR_PAYLOADS,
}


def get_default_payloads(
    category: PayloadCategory | None = None,
) -> list[PayloadDefinition]:
    """Return the default payload list, optionally filtered by category."""
    if category:
        return PAYLOAD_SET_MAP.get(category, [])
    result: list[PayloadDefinition] = []
    for payloads in PAYLOAD_SET_MAP.values():
        result.extend(payloads)
    return result
