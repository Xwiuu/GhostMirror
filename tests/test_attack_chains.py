from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.zero_day.attack_chain_engine import AttackChainEngine


class TestAttackChainEngine:
    def test_init(self):
        engine = AttackChainEngine()
        assert engine.chains == []

    def test_analyze_no_data(self, tmp_path: Path):
        engine = AttackChainEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_chain_jwt_admin_object_detected(self):
        engine = AttackChainEngine()
        engine._chain_jwt_admin_object(
            {"jwt_detected": True},
            {"endpoints": [{"url": "/admin/users"}]},
            [{"name": "User"}, {"name": "Payment"}],
        )
        assert len(engine.chains) >= 1
        assert "JWT" in engine.chains[0]["title"]

    def test_chain_jwt_admin_object_no_jwt(self):
        engine = AttackChainEngine()
        engine._chain_jwt_admin_object(
            {"jwt_detected": False},
            {"endpoints": [{"url": "/admin/users"}]},
            [{"name": "User"}],
        )
        assert len(engine.chains) == 0

    def test_chain_jwt_admin_object_no_admin(self):
        engine = AttackChainEngine()
        engine._chain_jwt_admin_object(
            {"jwt_detected": True},
            {"endpoints": [{"url": "/api/users"}]},
            [{"name": "User"}],
        )
        assert len(engine.chains) == 0

    def test_chain_graphql_introspection_detected(self):
        engine = AttackChainEngine()
        engine._chain_graphql_introspection(
            {"endpoint": "/graphql", "introspection_enabled": True},
            {},
        )
        assert len(engine.chains) >= 1

    def test_chain_graphql_introspection_disabled(self):
        engine = AttackChainEngine()
        engine._chain_graphql_introspection(
            {"endpoint": "/graphql", "introspection_enabled": False},
            {},
        )
        assert len(engine.chains) == 0

    def test_chain_sourcemap_internal_routes_detected(self):
        engine = AttackChainEngine()
        engine._chain_sourcemap_internal_routes(
            [{"sourcemap_url": "https://example.com/map", "exposed": True, "endpoints": ["/admin"], "files": [], "comments": []}],
            [],
            [],
        )
        assert len(engine.chains) >= 1

    def test_chain_sourcemap_no_exposed(self):
        engine = AttackChainEngine()
        engine._chain_sourcemap_internal_routes(
            [{"sourcemap_url": "https://example.com/map", "exposed": False, "endpoints": [], "files": [], "comments": []}],
            [],
            [],
        )
        assert len(engine.chains) == 0

    def test_chain_jwt_graphql_detected(self):
        engine = AttackChainEngine()
        engine._chain_jwt_graphql(
            {"jwt_detected": True},
            {"detected": True},
            {},
        )
        assert len(engine.chains) >= 1

    def test_chain_jwt_graphql_missing_jwt(self):
        engine = AttackChainEngine()
        engine._chain_jwt_graphql(
            {"jwt_detected": False},
            {"detected": True},
            {},
        )
        assert len(engine.chains) == 0

    def test_chain_admin_sensitive_access_detected(self):
        engine = AttackChainEngine()
        engine._chain_admin_sensitive_access(
            [],
            {"endpoints": [{"url": "/admin/users"}]},
            [{"name": "User"}, {"name": "Payment"}],
        )
        assert len(engine.chains) >= 1

    def test_chain_api_object_relationships_detected(self):
        engine = AttackChainEngine()
        engine._chain_api_object_relationships(
            {},
            [],
            [{"title": "Corr1", "score": 75}, {"title": "Corr2", "score": 80}],
        )
        assert len(engine.chains) >= 1

    def test_chain_api_object_relationships_low_score(self):
        engine = AttackChainEngine()
        engine._chain_api_object_relationships(
            {},
            [],
            [{"title": "Corr1", "score": 30}],
        )
        assert len(engine.chains) == 0

    def test_find_admin_endpoints(self):
        engine = AttackChainEngine()
        result = engine._find_admin_endpoints({"endpoints": [{"url": "/admin/users"}, {"url": "/api/users"}]})
        assert len(result) == 1
        assert "admin" in result[0]

    def test_find_admin_endpoints_empty(self):
        engine = AttackChainEngine()
        result = engine._find_admin_endpoints({})
        assert result == []

    def test_find_sensitive_objects(self):
        engine = AttackChainEngine()
        result = engine._find_sensitive_objects([{"name": "User"}, {"name": "BlogPost"}, {"name": "Payment"}])
        assert len(result) == 2
        assert "User" in result
        assert "Payment" in result

    def test_find_sensitive_objects_empty(self):
        engine = AttackChainEngine()
        result = engine._find_sensitive_objects([])
        assert result == []

    def test_find_admin_graphql_objects(self):
        engine = AttackChainEngine()
        result = engine._find_admin_graphql_objects({
            "schema": {
                "types": [{"name": "AdminUser"}, {"name": "User"}],
            }
        })
        assert "AdminUser" in result

    def test_chain_sorting(self):
        engine = AttackChainEngine()
        engine._chain_jwt_admin_object(
            {"jwt_detected": True},
            {"endpoints": [{"url": "/admin/users"}, {"url": "/admin/config"}, {"url": "/admin/settings"}]},
            [{"name": "User"}, {"name": "Payment"}, {"name": "Admin"}],
        )
        engine._chain_graphql_introspection(
            {"endpoint": "/graphql", "introspection_enabled": True},
            {},
        )
        assert len(engine.chains) >= 2
        assert engine.chains[0]["score"] >= engine.chains[1]["score"]

    def test_find_admin_graphql_objects_introspection(self):
        engine = AttackChainEngine()
        result = engine._find_admin_graphql_objects({
            "introspection": {"schema": {"types": [{"name": "AdminQuery"}, {"name": "AdminMutation"}]}}
        })
        assert len(result) >= 1
        assert "AdminQuery" in result

    def test_find_admin_graphql_objects_empty(self):
        engine = AttackChainEngine()
        assert engine._find_admin_graphql_objects({}) == []

    def test_find_admin_endpoints_list_input(self):
        engine = AttackChainEngine()
        result = engine._find_admin_endpoints([{"url": "/admin/users"}, {"url": "/api/data"}])
        assert len(result) == 1

    def test_find_sensitive_objects_string_type(self):
        engine = AttackChainEngine()
        result = engine._find_sensitive_objects([{"type": "User"}, {"type": "BlogPost"}])
        assert len(result) == 1
        assert "User" in result

    def test_chain_graphql_introspection_with_admin_objects(self):
        engine = AttackChainEngine()
        engine._chain_graphql_introspection(
            {"endpoint": "/graphql", "introspection_enabled": True, "schema": {"types": [{"name": "AdminUser"}, {"name": "AdminConfig"}]}},
            {},
        )
        assert len(engine.chains) >= 1

    def test_find_admin_endpoints_no_endpoints(self):
        engine = AttackChainEngine()
        assert engine._find_admin_endpoints({"endpoints": []}) == []

    def test_chain_sourcemap_internal_no_exposed(self):
        engine = AttackChainEngine()
        engine._chain_sourcemap_internal_routes(
            [{"exposed": False, "endpoints": ["/admin"], "sourcemap_url": "x", "files": [], "comments": []}],
            [],
            [],
        )
        assert len(engine.chains) == 0
