from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

SENSITIVE_PARAMS = {
    "token", "auth", "session", "password", "passwd", "secret", "key", "api_key",
    "apikey", "access_token", "refresh_token", "jwt", "bearer",
}

AUTH_PARAMS = {
    "login", "register", "signup", "signin", "logout", "forgot", "reset",
    "mfa", "otp", "2fa", "verify", "email", "username",
}

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "next", "return", "return_to",
    "return_url", "callback", "destination", "continue", "forward",
}

FILE_PARAMS = {
    "file", "filename", "path", "dir", "upload", "download", "document",
    "attachment", "image", "avatar", "resume", "pdf",
}

OBJECT_ID_PARAMS = {
    "id", "uid", "uuid", "guid", "user_id", "userId", "account_id",
    "order_id", "product_id", "item_id", "cart_id", "basket_id",
}

PAYMENT_PARAMS = {
    "card", "card_number", "cvv", "ccv", "amount", "price", "total",
    "currency", "payment", "transaction", "billing", "coupon",
}

SEARCH_PARAMS = {
    "q", "query", "search", "keyword", "term", "filter", "sort", "page",
}

PAGINATION_PARAMS = {
    "page", "offset", "limit", "per_page", "perPage", "page_size",
    "from", "to", "skip", "take",
}


class ParameterMining:
    def __init__(self) -> None:
        self._parameters: list[dict[str, Any]] = []

    def mine(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("PARAMETER_MINING_START")
        seen: set[str] = set()

        for source in sources:
            url_params = self._extract_from_url(source.get("url", ""))
            for p in url_params:
                if p not in seen:
                    seen.add(p)
                    self._parameters.append(self._classify(p, source))

            form_params = source.get("form_params", [])
            for p in form_params:
                if p not in seen:
                    seen.add(p)
                    self._parameters.append(self._classify(p, source))

            js_params = source.get("js_params", [])
            for p in js_params:
                if p not in seen:
                    seen.add(p)
                    self._parameters.append(self._classify(p, source))

        logger.info("PARAMETER_MINING_DONE total={}", len(self._parameters))
        return self._parameters

    def _extract_from_url(self, url: str) -> list[str]:
        if "?" not in url:
            return []
        query = url.split("?", 1)[1].split("#")[0]
        params = []
        for pair in query.split("&"):
            if "=" in pair:
                params.append(pair.split("=")[0])
        return params

    def _classify(self, param: str, source: dict[str, Any]) -> dict[str, Any]:
        lower = param.lower()
        classification = "Unknown"

        if lower in SENSITIVE_PARAMS:
            classification = "Sensitive"
        elif lower in AUTH_PARAMS:
            classification = "Auth"
        elif lower in REDIRECT_PARAMS:
            classification = "Redirect"
        elif lower in FILE_PARAMS:
            classification = "File"
        elif lower in OBJECT_ID_PARAMS:
            classification = "Object ID"
        elif lower in PAYMENT_PARAMS:
            classification = "Payment"
        elif lower in SEARCH_PARAMS:
            classification = "Search"
        elif lower in PAGINATION_PARAMS:
            classification = "Pagination"

        return {
            "parameter": param,
            "classification": classification,
            "source": source.get("source", "unknown"),
            "url": source.get("url", ""),
        }
