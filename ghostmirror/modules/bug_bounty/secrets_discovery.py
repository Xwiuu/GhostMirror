from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.discovered_secret import DiscoveredSecret
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

logger = get_logger()

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    ("firebase", r'["\']([A-Za-z0-9_-]{30,50})["\']', r'firebaseConfig|apiKey.*authDomain.*projectId', "HIGH"),
    ("google_maps", r'["\'](AIza[0-9A-Za-z_-]{35})["\']', r'AIza', "MEDIUM"),
    ("stripe_pk", r'["\'](pk_live_[0-9A-Za-z_-]{20,60})["\']', r'pk_live', "HIGH"),
    ("stripe_pk_test", r'["\'](pk_test_[0-9A-Za-z_-]{20,60})["\']', r'pk_test', "HIGH"),
    ("stripe_sk", r'["\'](sk_live_[0-9A-Za-z_-]{20,60})["\']', r'sk_live', "CRITICAL"),
    ("stripe_sk_test", r'["\'](sk_test_[0-9A-Za-z_-]{20,60})["\']', r'sk_test', "CRITICAL"),
    ("sentry_dsn", r'["\'](https://[0-9a-f]{32}@[^"\']+\.ingest\.sentry\.io/\d+)["\']', r'sentry\.io', "MEDIUM"),
    ("supabase_url", r'["\'](https://[^"\']+\.supabase\.co[^"\']*)["\']', r'supabase\.co', "MEDIUM"),
    ("graphql_endpoint", r'["\'](https?://[^"\']+/graphql)["\']', r'/graphql', "LOW"),
    ("aws_key", r'["\'](AKIA[0-9A-Z]{16})["\']', r'AKIA', "HIGH"),
    ("jwt_token", r'["\'](eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+)["\']', r'eyJ', "MEDIUM"),
    ("generic_api_key", r'["\']([0-9a-f]{32,40})["\']', r'api[_-]?key|apikey|api_key|token', "LOW"),
]


class SecretsDiscovery:
    def __init__(self) -> None:
        self._secrets: list[DiscoveredSecret] = []
        self._findings: list[FindingModel] = []

    def scan(self, html_content: str, js_content: str, source_url: str, target: str = "") -> list[DiscoveredSecret]:
        logger.info("SECRETS_DISCOVERY_SCAN url={}", source_url)
        combined = html_content + "\n" + js_content

        for secret_type, value_pattern, context_pattern, severity in SECRET_PATTERNS:
            matches = list(re.finditer(value_pattern, combined))
            for match in matches:
                original = match.group(1)
                context_ok = bool(re.search(context_pattern, combined, re.IGNORECASE))
                if not context_ok:
                    continue

                redacted = self._redact(original)

                secret = DiscoveredSecret(
                    type=secret_type,
                    original_snippet="",  # NEVER stored to disk
                    redacted_snippet=redacted,
                    location=source_url,
                    confidence="high" if severity in ("HIGH", "CRITICAL") else "medium",
                    severity=severity.lower(),
                )
                self._secrets.append(secret)

                finding_sev = FindingSeverity[severity] if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else FindingSeverity.MEDIUM
                finding = FindingModel(
                    title=f"Potential Exposed Secret: {secret_type}",
                    description=(
                        f"A potential {secret_type} key/secret was discovered in {source_url}. "
                        f"Pattern: {context_pattern}. Redacted value: {redacted}"
                    ),
                    severity=finding_sev,
                    target=target or source_url,
                    evidence=f"Location: {source_url}\nType: {secret_type}\nRedacted: {redacted}",
                    recommendation=(
                        f"Review the exposed {secret_type} key. "
                        "If it is a production key, rotate it immediately. "
                        "Ensure secrets are stored in environment variables or a secrets manager, "
                        "not in client-side code."
                    ),
                    category="bug_bounty_secret",
                )
                self._findings.append(finding)
                logger.info("SECRET_DETECTED type={} location={} severity={}", secret_type, source_url, severity)

        return self._secrets

    def _redact(self, value: str) -> str:
        if len(value) <= 8:
            return "****"
        return value[:4] + "****" + value[-4:]

    def get_secrets(self) -> list[DiscoveredSecret]:
        return self._secrets

    def get_findings(self) -> list[FindingModel]:
        return self._findings
