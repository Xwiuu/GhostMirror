from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
]

GRAPHQL_FRAMEWORK_INDICATORS = {
    "apollo": ["apollo", "apollographql"],
    "hasura": ["hasura", "hasura-console"],
    "graphene": ["graphene", "graphene-django"],
    "yoga": ["yoga", "graphql-yoga"],
    "graphql_playground": ["playground", "graphql-playground"],
    "graphiql": ["graphiql"],
    "express_graphql": ["express-graphql"],
}


class GraphQLDiscovery:
    def __init__(self) -> None:
        self.detected = False
        self.endpoints: list[str] = []
        self.frameworks: list[str] = []

    def discover(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("GRAPHQL_DISCOVERY_START")
        self.endpoints = []
        self.frameworks = []
        self.detected = False

        for ep in endpoints:
            path = ep.get("path", ep.get("url", "")).lower().rstrip("/")
            for gql_path in GRAPHQL_PATHS:
                if path.endswith(gql_path):
                    if gql_path not in self.endpoints:
                        self.endpoints.append(gql_path)
                    self.detected = True

            self._detect_framework(ep)

        result = {
            "detected": self.detected,
            "endpoints": self.endpoints,
            "frameworks": list(set(self.frameworks)),
            "total_endpoints": len(self.endpoints),
        }

        if self.detected:
            logger.info("GRAPHQL_DISCOVERY_DONE endpoints={} frameworks={}", self.endpoints, self.frameworks)
        else:
            logger.info("GRAPHQL_DISCOVERY_DONE none detected")

        return result

    def _detect_framework(self, ep: dict[str, Any]) -> None:
        headers = ep.get("headers", {})
        response_body = ep.get("response_body", ep.get("body", ""))
        combined = str(headers).lower() + str(response_body).lower()

        for framework, indicators in GRAPHQL_FRAMEWORK_INDICATORS.items():
            for indicator in indicators:
                if indicator in combined:
                    if framework not in self.frameworks:
                        self.frameworks.append(framework)
                    return
