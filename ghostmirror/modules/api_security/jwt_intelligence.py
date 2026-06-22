from __future__ import annotations

import base64
import json
import re
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

JWT_PATTERN = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)

AUTH_HEADER_PATTERN = re.compile(
    r"(?:bearer|Bearer|JWT|jwt)\s+(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
)

WEAK_ALGORITHMS = {"none", "None", "NONE", "nOnE", "null"}


class JWTIntelligence:
    def __init__(self) -> None:
        self.tokens_found: int = 0
        self.algorithms: list[str] = []
        self.has_kid: bool = False
        self.has_typ: bool = False
        self.has_exp: bool = False
        self.has_none_alg: bool = False
        self.weak_algs: list[str] = []
        self.issuers: list[str] = []
        self.audiences: list[str] = []
        self.redacted: list[str] = []

    def analyze(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("JWT_INTELLIGENCE_START")
        self.tokens_found = 0
        self.algorithms = []
        self.has_kid = False
        self.has_typ = False
        self.has_exp = False
        self.has_none_alg = False
        self.weak_algs = []
        self.issuers = []
        self.audiences = []
        self.redacted = []

        for ep in endpoints:
            self._check_headers(ep.get("headers", {}))
            response_headers = ep.get("response_headers", {})
            self._check_headers(response_headers)
            response_body = ep.get("response_body", ep.get("body", ""))
            if isinstance(response_body, str):
                self._check_body(response_body)

        result = {
            "detected": self.tokens_found > 0,
            "total_tokens_found": self.tokens_found,
            "algorithms": list(set(self.algorithms)),
            "has_kid": self.has_kid,
            "has_typ": self.has_typ,
            "has_exp": self.has_exp,
            "has_none_alg_indicator": self.has_none_alg,
            "weak_algorithms": list(set(self.weak_algs)),
            "issuers": list(set(self.issuers)),
            "audiences": list(set(self.audiences)),
            "redacted_tokens": self.redacted[:10],
        }

        logger.info("JWT_INTELLIGENCE_DONE tokens={} algs={} weak={}",
                    self.tokens_found, len(self.algorithms), len(self.weak_algs))
        return result

    def _check_headers(self, headers: dict[str, Any]) -> None:
        if not headers:
            return
        for key, value in headers.items():
            if key.lower() in ("authorization", "x-authorization", "token", "x-api-key"):
                if isinstance(value, str):
                    self._extract_jwt(value)

    def _check_body(self, body: str) -> None:
        for match in JWT_PATTERN.findall(body):
            self._process_jwt(match)

    def _extract_jwt(self, header_value: str) -> None:
        match = AUTH_HEADER_PATTERN.search(header_value)
        if match:
            token = match.group(1)
            self._process_jwt(token)

    def _process_jwt(self, token: str) -> None:
        self.tokens_found += 1
        redacted = token[:4] + "****" + token[-4:]
        self.redacted.append(redacted)

        try:
            parts = token.split(".")
            if len(parts) >= 2:
                header_b64 = parts[0]
                padding = 4 - len(header_b64) % 4
                if padding != 4:
                    header_b64 += "=" * padding
                decoded = base64.urlsafe_b64decode(header_b64)
                header = json.loads(decoded)

                alg = header.get("alg", "")
                if alg:
                    self.algorithms.append(alg)
                    if alg in WEAK_ALGORITHMS:
                        self.has_none_alg = True
                        self.weak_algs.append(alg)

                if header.get("kid"):
                    self.has_kid = True

                if header.get("typ"):
                    self.has_typ = True

                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                decoded_payload = base64.urlsafe_b64decode(payload_b64)
                payload = json.loads(decoded_payload)

                if "exp" in payload:
                    self.has_exp = True

                if "iss" in payload:
                    iss = payload["iss"]
                    if isinstance(iss, str) and iss not in self.issuers:
                        self.issuers.append(iss)

                if "aud" in payload:
                    aud = payload["aud"]
                    if isinstance(aud, str) and aud not in self.audiences:
                        self.audiences.append(aud)
                    elif isinstance(aud, list):
                        for a in aud:
                            if isinstance(a, str) and a not in self.audiences:
                                self.audiences.append(a)

        except Exception:
            pass
