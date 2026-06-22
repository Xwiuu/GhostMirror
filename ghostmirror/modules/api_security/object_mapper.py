from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

OBJECT_PATTERNS: dict[str, list[str]] = {
    "User": ["user", "users", "profile", "account", "accounts", "member", "members"],
    "Financial": ["payment", "payments", "invoice", "invoices", "wallet", "wallets",
                  "transaction", "transactions", "balance", "billing", "charge"],
    "Admin": ["admin", "administrator", "backoffice", "internal", "manage", "management", "staff"],
    "Business": ["order", "orders", "product", "products", "catalog", "inventory",
                 "customer", "customers", "vendor", "supplier"],
    "Content": ["file", "files", "document", "documents", "image", "images",
                "media", "upload", "attachment", "attachments"],
    "Security": ["role", "roles", "permission", "permissions", "audit", "log",
                 "session", "sessions", "token", "tokens", "key", "keys"],
    "Config": ["config", "configuration", "setting", "settings", "preference", "preferences",
               "template", "templates", "feature", "features", "flag", "flags"],
}


class ObjectMapper:
    def __init__(self) -> None:
        self.objects: list[dict[str, Any]] = []

    def map(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("OBJECT_MAPPER_START")
        self.objects = []
        seen: set[str] = set()

        for ep in endpoints:
            path = ep.get("path", ep.get("url", ""))
            for obj_type, patterns in OBJECT_PATTERNS.items():
                for pattern in patterns:
                    if re.search(r"/" + re.escape(pattern) + r"[/\s?]?", path.lower()):
                        key = f"{obj_type}:{pattern}"
                        if key not in seen:
                            seen.add(key)
                            self.objects.append({
                                "type": obj_type,
                                "pattern": pattern,
                                "path": path,
                                "method": ep.get("method", "GET"),
                                "auth_required": ep.get("auth_required", ep.get("auth_required_indicator", False)),
                            })
                        break

        logger.info("OBJECT_MAPPER_DONE objects={}", len(self.objects))
        return self.objects
