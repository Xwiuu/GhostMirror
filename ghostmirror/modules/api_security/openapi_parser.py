from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class OpenAPIParser:
    def __init__(self) -> None:
        self.paths: list[dict[str, Any]] = []
        self.methods: set[str] = set()
        self.schemas: list[str] = []
        self.auth_definitions: list[str] = []
        self.version: str = ""

    def parse(self, spec: dict[str, Any]) -> dict[str, Any]:
        logger.info("OPENAPI_PARSE_START")
        self.paths = []
        self.methods = set()
        self.schemas = []
        self.auth_definitions = []
        self.version = spec.get("info", {}).get("version", "")

        swagger_paths = spec.get("paths", {})
        for path, methods in swagger_paths.items():
            if isinstance(methods, dict):
                for method in methods:
                    if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                        self.methods.add(method.upper())
                        self.paths.append({
                            "path": path,
                            "method": method.upper(),
                            "summary": methods[method].get("summary", "") if isinstance(methods[method], dict) else "",
                        })

        security_schemes = (
            spec.get("components", {}).get("securitySchemes", {})
            or spec.get("securityDefinitions", {})
        )
        for scheme_name, scheme_def in security_schemes.items():
            stype = scheme_def.get("type", "unknown") if isinstance(scheme_def, dict) else "unknown"
            self.auth_definitions.append(f"{scheme_name}:{stype}")

        schemas = (
            spec.get("components", {}).get("schemas", {})
            or spec.get("definitions", {})
        )
        self.schemas = list(schemas.keys()) if isinstance(schemas, dict) else []

        result = {
            "version": self.version,
            "total_paths": len(self.paths),
            "methods": sorted(self.methods),
            "schemas": self.schemas,
            "auth_definitions": self.auth_definitions,
            "paths": self.paths[:100],
        }

        logger.info("OPENAPI_PARSE_DONE paths={} methods={}", len(self.paths), len(self.methods))
        return result
