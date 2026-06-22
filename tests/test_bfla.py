from __future__ import annotations

from ghostmirror.modules.api_security.bfla_indicators import BFLAIndicators


class TestBFLAIndicators:
    def test_no_indicators(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/api/public", "method": "GET"}])
        assert result == []

    def test_detects_admin_path(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/admin/users", "method": "GET"}])
        assert len(result) >= 1
        assert result[0]["type"] == "BFLA"

    def test_detects_internal_path(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/internal/api", "method": "GET"}])
        assert len(result) >= 1

    def test_detects_backoffice(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/backoffice/dashboard", "method": "GET"}])
        assert len(result) >= 1

    def test_detects_management(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/manage/settings", "method": "GET"}])
        assert len(result) >= 1

    def test_detects_privileged_action(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/api/users/delete", "method": "POST"}])
        assert len(result) >= 1

    def test_higher_confidence_without_auth(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/admin/users", "method": "DELETE", "auth_required": False}])
        assert result[0]["confidence"] == "HIGH"

    def test_lower_confidence_with_auth(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/admin/users", "method": "GET", "auth_required": True}])
        assert result[0]["confidence"] in ("LOW", "MEDIUM")

    def test_detects_private_path(self):
        bfla = BFLAIndicators()
        result = bfla.analyze([{"path": "/private/api", "method": "GET"}])
        assert len(result) >= 1

    def test_is_admin_path(self):
        bfla = BFLAIndicators()
        assert bfla._is_admin_path("/admin/")
        assert bfla._is_admin_path("/backoffice/")
        assert not bfla._is_admin_path("/api/public/")

    def test_is_privileged_action(self):
        bfla = BFLAIndicators()
        assert bfla._is_privileged_action("/api/users/delete")
        assert bfla._is_privileged_action("/api/users/promote")
        assert not bfla._is_privileged_action("/api/users/list")
