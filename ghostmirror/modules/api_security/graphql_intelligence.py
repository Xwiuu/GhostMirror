from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

INTROSPECTION_INDICATORS = [
    "__schema",
    "__typename",
    "__type",
    "introspection",
    "schema{",
    "query{__schema",
]

PLAYGROUND_INDICATORS = [
    "graphql-playground",
    "playground",
    "graphiql",
    "explorer",
    "graphql-voyager",
]


class GraphQLIntelligence:
    def __init__(self) -> None:
        self.schema_exposure_indicators: list[str] = []
        self.has_playground: bool = False
        self.has_graphiql: bool = False
        self.has_introspection: bool = False

    def analyze(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("GRAPHQL_INTELLIGENCE_START")
        self.schema_exposure_indicators = []
        self.has_playground = False
        self.has_graphiql = False
        self.has_introspection = False

        for ep in endpoints:
            path = ep.get("path", ep.get("url", "")).lower()
            response_body = ep.get("response_body", ep.get("body", "")).lower()
            headers = str(ep.get("headers", {})).lower()
            combined = response_body + headers

            for indicator in INTROSPECTION_INDICATORS:
                if indicator.lower() in combined:
                    self.has_introspection = True
                    if indicator not in self.schema_exposure_indicators:
                        self.schema_exposure_indicators.append(indicator)

            for indicator in PLAYGROUND_INDICATORS:
                if indicator.lower() in combined:
                    if indicator == "graphiql":
                        self.has_graphiql = True
                    else:
                        self.has_playground = True

        result = {
            "schema_exposure_indicators": self.schema_exposure_indicators,
            "has_playground": self.has_playground,
            "has_graphiql": self.has_graphiql,
            "has_introspection": self.has_introspection,
            "exposure_level": self._calc_exposure_level(),
        }

        logger.info("GRAPHQL_INTELLIGENCE_DONE introspection={} playground={} graphiql={}",
                    self.has_introspection, self.has_playground, self.has_graphiql)
        return result

    def _calc_exposure_level(self) -> str:
        score = 0
        if self.has_introspection:
            score += 3
        if self.has_playground:
            score += 2
        if self.has_graphiql:
            score += 2
        score += len(self.schema_exposure_indicators)
        if score >= 5:
            return "HIGH"
        if score >= 3:
            return "MEDIUM"
        return "LOW"
