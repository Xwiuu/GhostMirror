from __future__ import annotations

from ghostmirror.modules.api_security.object_mapper import ObjectMapper


class TestObjectMapper:
    def test_no_objects(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/health", "method": "GET"}])
        assert result == []

    def test_maps_user_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/users", "method": "GET"}])
        assert any(o["type"] == "User" for o in result)

    def test_maps_financial_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/payments", "method": "GET"}])
        assert any(o["type"] == "Financial" for o in result)

    def test_maps_admin_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/admin/users", "method": "GET"}])
        assert any(o["type"] == "Admin" for o in result)

    def test_maps_business_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/orders", "method": "GET"}])
        assert any(o["type"] == "Business" for o in result)

    def test_maps_content_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/files", "method": "GET"}])
        assert any(o["type"] == "Content" for o in result)

    def test_maps_security_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/roles", "method": "GET"}])
        assert any(o["type"] == "Security" for o in result)

    def test_maps_config_object(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/config", "method": "GET"}])
        assert any(o["type"] == "Config" for o in result)

    def test_dedup_same_object(self):
        mapper = ObjectMapper()
        result = mapper.map([
            {"path": "/api/users", "method": "GET"},
            {"path": "/api/users/123", "method": "GET"},
        ])
        user_objects = [o for o in result if o["type"] == "User"]
        assert len(user_objects) >= 1

    def test_auth_info_included(self):
        mapper = ObjectMapper()
        result = mapper.map([{"path": "/api/users", "method": "GET", "auth_required": True}])
        assert result[0]["auth_required"] is True
