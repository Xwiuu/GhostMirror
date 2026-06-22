from __future__ import annotations

from ghostmirror.modules.api_security.bola_indicators import BOLAIndicators


class TestBOLAIndicators:
    def test_no_indicators(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/health", "method": "GET"}], [])
        assert result == []

    def test_detects_user_id_in_path(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/users/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1
        assert result[0]["type"] == "BOLA"

    def test_detects_account_with_id(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/accounts/{id}", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1

    def test_high_confidence_without_auth(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/users/123", "method": "GET", "auth_required": False}], [])
        assert result[0]["confidence"] == "HIGH"

    def test_lower_confidence_with_auth(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/users/123", "method": "GET", "auth_required": True}], [])
        assert result[0]["confidence"] in ("LOW", "MEDIUM")

    def test_detects_wallet(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/wallets/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1
        assert result[0]["object"] == "wallet"

    def test_detects_invoice(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/invoices/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1

    def test_detects_payment(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/payments/123", "method": "DELETE", "auth_required": False}], [])
        assert len(result) >= 1

    def test_confidence_high_with_delete(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/users/123", "method": "DELETE", "auth_required": False}], [])
        assert result[0]["confidence"] == "HIGH"

    def test_path_contains_object_util(self):
        bola = BOLAIndicators()
        assert bola._path_contains_object("/api/users", "user")
        assert bola._path_contains_object("/api/accounts", "account")
        assert not bola._path_contains_object("/health", "user")

    def test_has_id_reference(self):
        bola = BOLAIndicators()
        assert bola._has_id_reference("/api/users/123")
        assert bola._has_id_reference("/api/users/{id}")
        assert not bola._has_id_reference("/api/users")
