from __future__ import annotations

import pytest

from ghostmirror.modules.bug_bounty.secrets_discovery import SecretsDiscovery
from ghostmirror.modules.models.finding import FindingSeverity


class TestSecretsDiscovery:
    @pytest.fixture
    def discovery(self) -> SecretsDiscovery:
        return SecretsDiscovery()

    def test_init(self, discovery: SecretsDiscovery) -> None:
        assert discovery._secrets == []
        assert discovery._findings == []

    def test_scan_empty(self, discovery: SecretsDiscovery) -> None:
        result = discovery.scan("", "", "https://example.com")
        assert result == []

    def test_scan_no_secrets(self, discovery: SecretsDiscovery) -> None:
        html = "<html><body>Hello World</body></html>"
        result = discovery.scan(html, "", "https://example.com")
        assert result == []

    def test_scan_firebase(self, discovery: SecretsDiscovery) -> None:
        html = 'var firebaseConfig = { apiKey: "AIzaSyABC123DEF456GHI789JKL012MNO345PQR678" };'
        result = discovery.scan(html, "", "https://example.com")
        firebase_secrets = [s for s in result if s.type == "firebase"]
        assert len(firebase_secrets) >= 1

    def test_scan_google_maps(self, discovery: SecretsDiscovery) -> None:
        html = 'const googleKey = "AIzaSyABC123DEF456GHI789JKL012MNO345PQR";'
        result = discovery.scan(html, "", "https://example.com")
        maps_secrets = [s for s in result if s.type == "google_maps"]
        assert len(maps_secrets) >= 1

    def test_scan_stripe_pk(self, discovery: SecretsDiscovery) -> None:
        html = 'const stripePk = "pk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
        result = discovery.scan(html, "", "https://example.com")
        stripe_secrets = [s for s in result if s.type == "stripe_pk_test"]
        assert len(stripe_secrets) >= 1

    def test_scan_stripe_sk(self, discovery: SecretsDiscovery) -> None:
        html = 'const stripeSk = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
        result = discovery.scan(html, "", "https://example.com")
        stripe_secrets = [s for s in result if s.type == "stripe_sk_test"]
        assert len(stripe_secrets) >= 1

    def test_scan_sentry_dsn(self, discovery: SecretsDiscovery) -> None:
        html = 'const sentry = "https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/1234567";'
        result = discovery.scan(html, "", "https://example.com")
        sentry_secrets = [s for s in result if s.type == "sentry_dsn"]
        assert len(sentry_secrets) >= 1

    def test_scan_supabase(self, discovery: SecretsDiscovery) -> None:
        html = 'const supabaseUrl = "https://abcdefghijklmnopq.supabase.co";'
        result = discovery.scan(html, "", "https://example.com")
        supabase_secrets = [s for s in result if s.type == "supabase_url"]
        assert len(supabase_secrets) >= 1

    def test_scan_graphql_endpoint(self, discovery: SecretsDiscovery) -> None:
        html = 'const graphqlUrl = "https://api.example.com/graphql";'
        result = discovery.scan(html, "", "https://example.com")
        graphql_secrets = [s for s in result if s.type == "graphql_endpoint"]
        assert len(graphql_secrets) >= 1

    def test_scan_aws_key(self, discovery: SecretsDiscovery) -> None:
        html = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'
        result = discovery.scan(html, "", "https://example.com")
        aws_secrets = [s for s in result if s.type == "aws_key"]
        assert len(aws_secrets) >= 1

    def test_scan_jwt(self, discovery: SecretsDiscovery) -> None:
        html = 'const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ";'
        result = discovery.scan(html, "", "https://example.com")
        jwt_secrets = [s for s in result if s.type == "jwt_token"]
        assert len(jwt_secrets) >= 1

    def test_redaction(self, discovery: SecretsDiscovery) -> None:
        result = discovery._redact("abcdefghijklmnop")
        assert result == "abcd****mnop"
        assert len(result) == 12

        result = discovery._redact("short")
        assert result == "****"

    def test_never_stores_original(self, discovery: SecretsDiscovery) -> None:
        html = 'const key = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
        result = discovery.scan(html, "", "https://example.com")
        for s in result:
            assert s.original_snippet == ""

    def test_findings_generated(self, discovery: SecretsDiscovery) -> None:
        html = 'const key = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
        discovery.scan(html, "", "https://example.com")
        findings = discovery.get_findings()
        assert len(findings) >= 1
        assert findings[0].title.startswith("Potential Exposed Secret")
        assert findings[0].category == "bug_bounty_secret"

    def test_scan_severity_mapping(self, discovery: SecretsDiscovery) -> None:
        html = 'const stripeSk = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'
        secrets = discovery.scan(html, "", "https://example.com")
        for s in secrets:
            if s.type == "stripe_sk_test":
                assert s.severity == "critical"
    def test_get_secrets_empty(self, discovery: SecretsDiscovery) -> None:
        assert discovery.get_secrets() == []

    def test_get_findings_empty(self, discovery: SecretsDiscovery) -> None:
        assert discovery.get_findings() == []
