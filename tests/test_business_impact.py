import pytest

from ghostmirror.modules.finding_intelligence.impact_engine import (
    get_business_impact,
    get_technical_impact,
)


class TestImpactEngine:
    def test_business_impact_security_header(self) -> None:
        result = get_business_impact("Missing Content Security Policy")
        assert "XSS" in result
        assert len(result) > 20

    def test_business_impact_open_database(self) -> None:
        result = get_business_impact("Open Database Exposure")
        assert "vazamento" in result.lower()
        assert len(result) > 20

    def test_business_impact_open_port(self) -> None:
        result = get_business_impact("Open Port 3306")
        assert "superfície de ataque" in result
        assert len(result) > 20

    def test_business_impact_generic(self) -> None:
        result = get_business_impact("Unknown Issue")
        assert "Possível impacto" in result

    def test_business_impact_by_category(self) -> None:
        result = get_business_impact("Server Error", category="Missing Security Header")
        assert "ataques XSS" in result

    def test_business_impact_generic_with_category(self) -> None:
        result = get_business_impact("Unknown", category="Unknown Category")
        assert "Possível impacto" in result

    def test_technical_impact_missing_header(self) -> None:
        result = get_technical_impact("Missing Content Security Policy")
        assert "scripts" in result.lower()
        assert len(result) > 20

    def test_technical_impact_open_db(self) -> None:
        result = get_technical_impact("Open Database")
        assert "acesso direto" in result

    def test_technical_impact_weak_cipher(self) -> None:
        result = get_technical_impact("Weak Cipher Suite")
        assert "Criptografia" in result or "descriptografia" in result

    def test_technical_impact_generic(self) -> None:
        result = get_technical_impact("Random Bug")
        assert "Configuração insegura" in result

    def test_technical_impact_by_category(self) -> None:
        result = get_technical_impact("Something", category="Missing Security Header")
        assert "scripts" in result.lower() or "framing" in result.lower()
