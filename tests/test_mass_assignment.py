from __future__ import annotations

from ghostmirror.modules.api_security.mass_assignment_indicators import MassAssignmentIndicators


class TestMassAssignmentIndicators:
    def test_no_indicators(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/health", "method": "GET"}])
        assert result == []

    def test_ignores_get_requests(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/users", "method": "GET"}])
        assert result == []

    def test_detects_post_with_user(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/users", "method": "POST"}])
        assert len(result) >= 1
        assert result[0]["type"] == "MASS_ASSIGNMENT"

    def test_detects_put_with_account(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/accounts/123", "method": "PUT"}])
        assert len(result) >= 1

    def test_detects_patch_with_profile(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/profile", "method": "PATCH"}])
        assert len(result) >= 1

    def test_higher_confidence_with_sensitive_fields(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/users/role", "method": "PUT"}])
        assert result[0]["confidence"] in ("HIGH", "MEDIUM")

    def test_higher_confidence_with_patch(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/users/123", "method": "PATCH"}])
        assert result[0]["confidence"] in ("HIGH", "MEDIUM")

    def test_detects_role_in_path(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([{"path": "/api/users/admin", "method": "POST"}])
        assert len(result) >= 1
        assert len(result[0]["sensitive_fields_hint"]) > 0

    def test_has_complex_object(self):
        ma = MassAssignmentIndicators()
        assert ma._has_complex_object("/api/users")
        assert ma._has_complex_object("/api/orders")
        assert not ma._has_complex_object("/api/health")

    def test_multiple_endpoints(self):
        ma = MassAssignmentIndicators()
        result = ma.analyze([
            {"path": "/api/users", "method": "POST"},
            {"path": "/api/users/123", "method": "PATCH"},
            {"path": "/health", "method": "GET"},
        ])
        assert len(result) == 2
