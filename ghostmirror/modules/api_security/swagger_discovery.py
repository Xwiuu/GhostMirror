from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

SWAGGER_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/redoc",
]


class SwaggerDiscovery:
    def __init__(self) -> None:
        self.detected = False
        self.found_paths: list[str] = []
        self.spec: dict[str, Any] | None = None

    def discover(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("SWAGGER_DISCOVERY_START")
        self.found_paths = []
        self.detected = False

        for ep in endpoints:
            path = ep.get("path", ep.get("url", "")).lower().rstrip("/")
            for sw_path in SWAGGER_PATHS:
                if path.endswith(sw_path):
                    if sw_path not in self.found_paths:
                        self.found_paths.append(sw_path)
                    self.detected = True

        result = {
            "detected": self.detected,
            "found_paths": self.found_paths,
            "found_count": len(self.found_paths),
        }

        if self.detected:
            logger.info("SWAGGER_DISCOVERY_DONE paths={}", self.found_paths)
        else:
            logger.info("SWAGGER_DISCOVERY_DONE none detected")

        return result
