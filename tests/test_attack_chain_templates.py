from __future__ import annotations

from ghostmirror.models.attack_chain_signal import SignalType
from ghostmirror.modules.attack_chain.chain_templates import (
    TEMPLATES, get_template_by_name, get_templates_by_type,
)


class TestChainTemplates:
    def test_templates_loaded(self):
        assert len(TEMPLATES) == 10

    def test_all_templates_have_required_signals(self):
        for t in TEMPLATES:
            assert len(t.required_signals) >= 1
            assert t.name
            assert t.chain_type

    def test_get_template_by_name_found(self):
        t = get_template_by_name("JWT + Admin API + Sensitive Object")
        assert t is not None
        assert SignalType.JWT_DETECTED in t.required_signals

    def test_get_template_by_name_not_found(self):
        t = get_template_by_name("Non Existent Template")
        assert t is None

    def test_get_templates_by_type(self):
        auth_templates = get_templates_by_type("authentication_bypass")
        assert len(auth_templates) >= 1
        for t in auth_templates:
            assert t.chain_type == "authentication_bypass"

    def test_first_template_jwt_admin_sensitive(self):
        t = TEMPLATES[0]
        assert SignalType.JWT_DETECTED in t.required_signals
        assert SignalType.EXPOSED_ADMIN in t.required_signals
        assert SignalType.SENSITIVE_OBJECT in t.required_signals
        assert t.chain_type == "authentication_bypass"

    def test_template_sourcemap(self):
        t = get_template_by_name("Source Map + Hidden Functionality + Internal API")
        assert t is not None
        assert SignalType.SOURCE_MAP_EXPOSED in t.required_signals
        assert t.chain_type == "information_disclosure"

    def test_template_public_cve(self):
        t = get_template_by_name("Public CVE + Internet Exposed Service + No WAF")
        assert t is not None
        assert SignalType.CVE_KNOWN_EXPLOITED in t.required_signals
        assert t.chain_type == "known_vulnerability"

    def test_all_chain_types(self):
        types = set(t.chain_type for t in TEMPLATES)
        assert "authentication_bypass" in types
        assert "api_abuse" in types
        assert "information_disclosure" in types
        assert "known_vulnerability" in types
        assert "business_logic_abuse" in types
        assert "credential_exposure" in types
        assert "client_side_attack" in types
        assert "zero_day" in types
