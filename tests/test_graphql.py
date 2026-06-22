from __future__ import annotations

from ghostmirror.modules.api_security.graphql_discovery import GraphQLDiscovery
from ghostmirror.modules.api_security.graphql_intelligence import GraphQLIntelligence


class TestGraphQLDiscovery:
    def test_no_graphql(self):
        discovery = GraphQLDiscovery()
        endpoints = [{"path": "/api/users"}, {"path": "/login"}]
        result = discovery.discover(endpoints)
        assert not result["detected"]
        assert result["endpoints"] == []

    def test_detects_graphql_path(self):
        discovery = GraphQLDiscovery()
        endpoints = [{"path": "/graphql"}, {"path": "/api/users"}]
        result = discovery.discover(endpoints)
        assert result["detected"]
        assert "/graphql" in result["endpoints"]

    def test_detects_multiple_graphql_paths(self):
        discovery = GraphQLDiscovery()
        endpoints = [{"path": "/graphql"}, {"path": "/api/graphql"}, {"path": "/graphql/v1"}]
        result = discovery.discover(endpoints)
        assert result["detected"]
        assert len(result["endpoints"]) >= 2

    def test_detects_framework(self):
        discovery = GraphQLDiscovery()
        endpoints = [{"path": "/graphql", "headers": {"server": "apollo"}}]
        result = discovery.discover(endpoints)
        assert "apollo" in result["frameworks"]


class TestGraphQLIntelligence:
    def test_no_intelligence_without_indicators(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "body": ""}])
        assert not result["has_introspection"]
        assert not result["has_playground"]
        assert result["exposure_level"] == "LOW"

    def test_detects_introspection(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "body": "__schema"}])
        assert result["has_introspection"]
        assert "__schema" in result["schema_exposure_indicators"]

    def test_detects_playground(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "body": "graphql-playground"}])
        assert result["has_playground"]

    def test_detects_graphiql(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "headers": {"content-type": "text/html"}},
                               {"path": "/graphql", "body": "graphiql"}])
        assert result["has_graphiql"]

    def test_high_exposure(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "body": "__schema __typename graphql-playground"}])
        assert result["exposure_level"] == "HIGH"

    def test_low_exposure_playground_only(self):
        intel = GraphQLIntelligence()
        result = intel.analyze([{"path": "/graphql", "body": "graphql-playground"}])
        assert result["exposure_level"] == "LOW"
