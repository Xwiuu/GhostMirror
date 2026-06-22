from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

OBJECT_REFERENCE_PARAMS = [
    "id", "uuid", "guid",
    "user_id", "userId", "user-id",
    "account_id", "accountId", "account-id",
    "order_id", "orderId", "order-id",
    "invoice_id", "invoiceId", "invoice-id",
    "wallet_id", "walletId", "wallet-id",
    "customer_id", "customerId",
    "product_id", "productId",
    "file_id", "fileId",
    "document_id", "documentId",
    "transaction_id", "transactionId",
    "payment_id", "paymentId",
    "token_id", "tokenId",
    "role_id", "roleId",
    "org_id", "orgId",
    "tenant_id", "tenantId",
    "team_id", "teamId",
    "project_id", "projectId",
]


class ParameterAnalyzer:
    def __init__(self) -> None:
        self.parameter_count: int = 0
        self.object_references: list[dict[str, Any]] = []
        self.sensitive_params: list[str] = []

    def analyze(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("PARAMETER_ANALYZER_START")
        self.parameter_count = 0
        self.object_references = []
        self.sensitive_params = []

        for ep in endpoints:
            path = ep.get("path", ep.get("url", ""))
            params = ep.get("params", [])
            self.parameter_count += len(params)

            path_obj_refs = self._find_path_object_references(path)
            self.object_references.extend(path_obj_refs)

            for param in params:
                if isinstance(param, str):
                    if param.lower() in [p.lower() for p in OBJECT_REFERENCE_PARAMS]:
                        self.object_references.append({
                            "param": param,
                            "path": path,
                            "method": ep.get("method", "GET"),
                            "source": "query",
                        })
                    if "password" in param.lower() or "secret" in param.lower() or "token" in param.lower():
                        self.sensitive_params.append(f"{param}@{path}")

        result = {
            "total_parameters": self.parameter_count,
            "total_object_references": len(self.object_references),
            "object_references": self.object_references[:50],
            "sensitive_params": list(set(self.sensitive_params)),
        }

        logger.info("PARAMETER_ANALYZER_DONE refs={}", len(self.object_references))
        return result

    def _find_path_object_references(self, path: str) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        segments = path.split("/")
        for seg in segments:
            if seg and seg[0] == "{" and seg[-1] == "}":
                refs.append({
                    "param": seg,
                    "path": path,
                    "source": "path",
                })
            elif seg and re.match(r"^[a-fA-F0-9\-]{8,}$", seg):
                pass
        return refs
