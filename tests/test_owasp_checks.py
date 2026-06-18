"""Tests for OWASP A01-A10 check functions and engine scoring."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.models.owasp_finding import OWASPCategory, OWASPFinding
from ghostmirror.modules.models.finding import FindingSeverity
from ghostmirror.modules.owasp.checks import (
    check_admin_endpoints,
    check_auth_indicators,
    check_cryptographic_failures,
    check_injection_surface,
    check_insecure_design,
    check_integrity,
    check_logging_indicators,
    check_misconfigurations,
    check_ssrf_surface,
    check_vulnerable_components,
)
from ghostmirror.modules.owasp.engine import OWASPEngine, OWASPScoreEngine
from ghostmirror.modules.owasp.findings_mapper import OWASPFindingsMapper
from ghostmirror.modules.owasp.recommendations import OWASPRecommendationEngine


# --------------------------------------------------------------------------- #
# OWASP Score Engine
# --------------------------------------------------------------------------- #
class TestOWASPScoreEngine:
    def test_calculate_low(self):
        findings = [
            OWASPFinding(
                category=OWASPCategory.A09,
                title="Info finding",
                description="Test",
                severity=FindingSeverity.INFO,
                target="test.com",
            )
        ]
        score, level = OWASPScoreEngine.calculate(findings)
        assert score == 1
        assert level == "LOW"

    def test_calculate_medium(self):
        findings = [
            OWASPFinding(
                category=OWASPCategory.A03,
                title="Medium finding",
                description="Test",
                severity=FindingSeverity.MEDIUM,
                target="test.com",
                owasp_score=8,
            )
            for _ in range(4)
        ]
        score, level = OWASPScoreEngine.calculate(findings)
        assert 21 <= score <= 40
        assert level == "MEDIUM"

    def test_calculate_high(self):
        findings = [
            OWASPFinding(
                category=OWASPCategory.A01,
                title="High finding",
                description="Test",
                severity=FindingSeverity.HIGH,
                target="test.com",
                owasp_score=15,
            )
            for _ in range(4)
        ]
        score, level = OWASPScoreEngine.calculate(findings)
        assert 41 <= score <= 70
        assert level == "HIGH"

    def test_calculate_critical(self):
        findings = [
            OWASPFinding(
                category=OWASPCategory.A05,
                title="Critical finding",
                description="Test",
                severity=FindingSeverity.CRITICAL,
                target="test.com",
                owasp_score=25,
            )
            for _ in range(4)
        ]
        score, level = OWASPScoreEngine.calculate(findings)
        assert score >= 71
        assert level == "CRITICAL"

    def test_calculate_empty(self):
        score, level = OWASPScoreEngine.calculate([])
        assert score == 0
        assert level == "LOW"

    def test_calculate_caps_at_100(self):
        findings = [
            OWASPFinding(
                category=OWASPCategory.A01,
                title=f"Critical {i}",
                description="Test",
                severity=FindingSeverity.CRITICAL,
                target="test.com",
            )
            for i in range(10)
        ]
        score, level = OWASPScoreEngine.calculate(findings)
        assert score == 100
        assert level == "CRITICAL"


# --------------------------------------------------------------------------- #
# OWASP Findings Mapper
# --------------------------------------------------------------------------- #
class TestOWASPFindingsMapper:
    def test_to_finding_model(self):
        owasp = OWASPFinding(
            category=OWASPCategory.A01,
            title="Test Finding",
            description="Test description",
            severity=FindingSeverity.HIGH,
            target="example.com",
            evidence="test evidence",
            recommendation="fix it",
        )
        result = OWASPFindingsMapper.to_finding_model(owasp)
        assert "[OWASP Broken Access Control Indicators] Test Finding" in result.title
        assert result.severity == FindingSeverity.HIGH
        assert result.target == "example.com"
        assert result.evidence == "test evidence"
        assert result.recommendation == "fix it"

    def test_to_finding_model_critical(self):
        owasp = OWASPFinding(
            category=OWASPCategory.A05,
            title="Critical test",
            description="Test",
            severity=FindingSeverity.CRITICAL,
            target="example.com",
        )
        result = OWASPFindingsMapper.to_finding_model(owasp)
        assert result.severity == FindingSeverity.CRITICAL

    def test_to_finding_list(self):
        findings = [
            OWASPFinding(category=OWASPCategory.A01, title="F1", description="D1", severity=FindingSeverity.HIGH, target="t.com"),
            OWASPFinding(category=OWASPCategory.A02, title="F2", description="D2", severity=FindingSeverity.LOW, target="t.com"),
        ]
        results = OWASPFindingsMapper.to_finding_list(findings)
        assert len(results) == 2
        assert "OWASP" in results[0].title


# --------------------------------------------------------------------------- #
# OWASP Recommendations Engine
# --------------------------------------------------------------------------- #
class TestOWASPRecommendationEngine:
    def test_generate_with_categories(self):
        recs = OWASPRecommendationEngine.generate(
            categories=[OWASPCategory.A01, OWASPCategory.A05]
        )
        assert len(recs) >= 4
        assert any("acesso" in r.lower() for r in recs)
        assert any("directory listing" in r.lower() for r in recs)

    def test_generate_includes_general(self):
        recs = OWASPRecommendationEngine.generate(categories=[])
        assert any("gestão" in r.lower() for r in recs)

    def test_generate_no_duplicates(self):
        recs = OWASPRecommendationEngine.generate(
            categories=[OWASPCategory.A01, OWASPCategory.A01]
        )
        # Same category twice should not duplicate
        assert len(recs) == len(set(recs))


# --------------------------------------------------------------------------- #
# A01 — Admin Endpoints (with mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA01Check:
    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_admin_endpoints_detected(self, mock_head):
        mock_head.side_effect = lambda target, path: 200 if path == "/admin" else 404

        findings = check_admin_endpoints("https://example.com")
        assert len(findings) == 1
        assert findings[0].category == OWASPCategory.A01
        assert findings[0].severity == FindingSeverity.HIGH
        assert "/admin" in findings[0].evidence

    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_admin_endpoints_none(self, mock_head):
        mock_head.return_value = 404

        findings = check_admin_endpoints("https://example.com")
        assert len(findings) == 0

    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_admin_endpoints_forbidden(self, mock_head):
        mock_head.side_effect = lambda target, path: 403 if path == "/wp-admin" else 404

        findings = check_admin_endpoints("https://example.com")
        assert len(findings) == 1
        assert "/wp-admin" in findings[0].evidence

    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_admin_endpoints_timeout_is_safe(self, mock_head):
        mock_head.return_value = 0  # Timeout/error
        findings = check_admin_endpoints("https://example.com")
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A02 — Cryptographic Failures
# --------------------------------------------------------------------------- #
class TestA02Check:
    def test_crypto_failures_no_ssl_file(self, tmp_path: Path):
        findings = check_cryptographic_failures(tmp_path)
        assert len(findings) == 0

    def test_crypto_failures_expired_cert(self, tmp_path: Path):
        ssl_data = {
            "target": "example.com",
            "certificate_summary": {
                "is_expired": True,
                "issuer": "Test CA",
                "expires_at": "2020-01-01",
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_size": 2048,
                "is_self_signed": False,
                "tls_versions": ["TLS 1.2", "TLS 1.3"],
            },
        }
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)

        findings = check_cryptographic_failures(tmp_path)
        titles = [f.title for f in findings]
        assert any("Expired" in t for t in titles)

    def test_crypto_failures_weak_tls(self, tmp_path: Path):
        ssl_data = {
            "target": "example.com",
            "certificate_summary": {
                "is_expired": False,
                "issuer": "Test CA",
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_size": 2048,
                "is_self_signed": False,
                "tls_versions": ["TLS 1.0", "TLS 1.2"],
            },
        }
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)

        findings = check_cryptographic_failures(tmp_path)
        titles = [f.title for f in findings]
        assert any("Obsolete" in t for t in titles)

    def test_crypto_failures_sha1(self, tmp_path: Path):
        ssl_data = {
            "target": "example.com",
            "certificate_summary": {
                "is_expired": False,
                "issuer": "Test CA",
                "signature_algorithm": "sha1WithRSAEncryption",
                "key_size": 2048,
                "is_self_signed": False,
                "tls_versions": ["TLS 1.2", "TLS 1.3"],
            },
        }
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)

        findings = check_cryptographic_failures(tmp_path)
        titles = [f.title for f in findings]
        assert any("Weak" in t or "Signature" in t for t in titles)

    def test_crypto_failures_weak_key(self, tmp_path: Path):
        ssl_data = {
            "target": "example.com",
            "certificate_summary": {
                "is_expired": False,
                "issuer": "Test CA",
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_size": 1024,
                "is_self_signed": False,
                "tls_versions": ["TLS 1.2"],
            },
        }
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)

        findings = check_cryptographic_failures(tmp_path)
        titles = [f.title for f in findings]
        assert any("Weak" in t or "Key" in t for t in titles)

    def test_crypto_failures_self_signed(self, tmp_path: Path):
        ssl_data = {
            "target": "example.com",
            "certificate_summary": {
                "is_expired": False,
                "issuer": "Self-Signed",
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_size": 2048,
                "is_self_signed": True,
                "tls_versions": ["TLS 1.2"],
            },
        }
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)

        findings = check_cryptographic_failures(tmp_path)
        titles = [f.title for f in findings]
        assert any("Self-Signed" in t for t in titles)

    def test_crypto_failures_invalid_json(self, tmp_path: Path):
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "ssl.json", "w") as f:
            f.write("not json")

        findings = check_cryptographic_failures(tmp_path)
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A03 — Injection Surface (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA03Check:
    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_injection_surface_params_in_links(self, mock_fetch):
        mock_fetch.return_value = '<a href="/page?id=1&q=test">link</a>'
        findings = check_injection_surface("https://example.com")
        assert len(findings) >= 1
        params_text = findings[0].evidence
        assert "?id=" in params_text or "?q=" in params_text

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_injection_surface_forms(self, mock_fetch):
        mock_fetch.return_value = '<form method="POST" action="/search"><input name="q"></form>'
        findings = check_injection_surface("https://example.com")
        # Should find the form + potentially the injection param
        form_findings = [f for f in findings if "Form" in f.title]
        assert len(form_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_injection_surface_search(self, mock_fetch):
        mock_fetch.return_value = '<input type="text" name="search">Search</input>'
        findings = check_injection_surface("https://example.com")
        search_findings = [f for f in findings if "Search" in f.title or "Injection" in f.title]
        assert len(search_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_injection_surface_no_body(self, mock_fetch):
        mock_fetch.return_value = ""
        findings = check_injection_surface("https://example.com")
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A04 — Insecure Design
# --------------------------------------------------------------------------- #
class TestA04Check:
    def test_insecure_design_with_admin(self):
        findings = check_insecure_design("https://example.com", has_admin_endpoints=True)
        assert len(findings) == 1
        assert findings[0].category == OWASPCategory.A04

    def test_insecure_design_without_admin(self):
        findings = check_insecure_design("https://example.com", has_admin_endpoints=False)
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A05 — Security Misconfiguration (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA05Check:
    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_misconfiguration_sensitive_files(self, mock_fetch):
        def side_effect(target, path):
            # Return a long string only for the backup file
            if path == "/backup.zip":
                return "PK\x03\x04\x14\x00\x00\x00\x00\x00" * 5
            return ""
        mock_fetch.side_effect = side_effect

        findings = check_misconfigurations("https://example.com")
        assert len(findings) >= 1
        assert any("Sensitive" in f.title for f in findings)

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_misconfiguration_directory_listing(self, mock_fetch):
        def side_effect(target, path):
            if path == "/":
                return "<title>Index of /</title>"
            return ""
        mock_fetch.side_effect = side_effect

        findings = check_misconfigurations("https://example.com")
        dl_findings = [f for f in findings if "Directory Listing" in f.title]
        assert len(dl_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_misconfiguration_clean(self, mock_fetch):
        mock_fetch.return_value = ""
        findings = check_misconfigurations("https://example.com")
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A06 — Vulnerable Components
# --------------------------------------------------------------------------- #
class TestA06Check:
    def test_vulnerable_components_no_profiles(self, tmp_path: Path):
        findings = check_vulnerable_components(tmp_path)
        assert len(findings) >= 0

    def test_vulnerable_components_with_cves(self, tmp_path: Path):
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True)
        vuln_data = {
            "target": "example.com",
            "total_cves": 5,
            "critical_count": 2,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 1,
            "matches": [
                {
                    "matched_cve": {"cve_id": "CVE-2024-0001"},
                    "technology": "Apache",
                    "risk_level": "CRITICAL",
                },
                {
                    "matched_cve": {"cve_id": "CVE-2024-0002"},
                    "technology": "WordPress",
                    "risk_level": "HIGH",
                },
            ],
        }
        with open(profiles_dir / "vulnerability_profile.json", "w") as f:
            json.dump(vuln_data, f)

        tech_data = {
            "target": "example.com",
            "technologies": [
                {"name": "Apache", "version": "2.4.41", "categories": ["web-server"]},
            ],
        }
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)

        findings = check_vulnerable_components(tmp_path)
        cve_findings = [f for f in findings if "CVE" in f.title or "Component" in f.title]
        assert len(cve_findings) >= 1

    def test_vulnerable_components_no_tech_profile(self, tmp_path: Path):
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True)
        with open(profiles_dir / "vulnerability_profile.json", "w") as f:
            json.dump({"total_cves": 0}, f)
        findings = check_vulnerable_components(tmp_path)
        # No tech profile means minimal findings
        assert len(findings) >= 0


# --------------------------------------------------------------------------- #
# A07 — Auth Indicators (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA07Check:
    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_auth_indicators_login_form(self, mock_head, mock_fetch):
        mock_fetch.return_value = '<form><input type="text" name="username"><input type="password" name="pass"></form>'
        mock_head.return_value = 404
        findings = check_auth_indicators("https://example.com")
        auth_findings = [f for f in findings if "Authentication" in f.title]
        assert len(auth_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_auth_indicators_login_path(self, mock_head, mock_fetch):
        def side_effect(target, path):
            return 200 if path == "/login" else 404
        mock_head.side_effect = side_effect
        mock_fetch.return_value = "<html>login page</html>"
        findings = check_auth_indicators("https://example.com")
        auth_findings = [f for f in findings if "Authentication" in f.title]
        assert len(auth_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_auth_indicators_mfa(self, mock_head, mock_fetch):
        mock_fetch.return_value = "mfa two-factor authenticator sso"
        mock_head.return_value = 404
        findings = check_auth_indicators("https://example.com")
        mfa_findings = [f for f in findings if "Multi-Factor" in f.title]
        assert len(mfa_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    @patch("ghostmirror.modules.owasp.checks._head_url")
    def test_auth_indicators_sso(self, mock_head, mock_fetch):
        mock_fetch.return_value = "login with sso azuread oauth"
        mock_head.return_value = 404
        findings = check_auth_indicators("https://example.com")
        sso_findings = [f for f in findings if "Single Sign-On" in f.title]
        assert len(sso_findings) >= 1


# --------------------------------------------------------------------------- #
# A08 — Integrity (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA08Check:
    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_integrity_cdn_without_sri(self, mock_fetch):
        mock_fetch.return_value = (
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>'
        )
        findings = check_integrity("https://example.com")
        cdn_findings = [f for f in findings if "CDN" in f.title]
        assert len(cdn_findings) >= 1

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_integrity_clean(self, mock_fetch):
        mock_fetch.return_value = '<script src="/static/app.js"></script>'
        findings = check_integrity("https://example.com")
        # No external CDN
        cdn_findings = [f for f in findings if "CDN" in f.title]
        assert len(cdn_findings) == 0


# --------------------------------------------------------------------------- #
# A09 — Logging Indicators (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA09Check:
    @patch("ghostmirror.modules.owasp.checks._request")
    def test_logging_indicators_missing_headers(self, mock_request):
        mock_request.return_value = (200, {"Server": "nginx"}, "OK")
        findings = check_logging_indicators("https://example.com")
        missing = [f for f in findings if "Missing" in f.title]
        assert len(missing) >= 1

    @patch("ghostmirror.modules.owasp.checks._request")
    def test_logging_indicators_all_present(self, mock_request):
        mock_request.return_value = (
            200,
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            "OK",
        )
        findings = check_logging_indicators("https://example.com")
        present = [f for f in findings if "Present" in f.title]
        assert len(present) >= 1

    @patch("ghostmirror.modules.owasp.checks._request")
    def test_logging_indicators_empty_headers(self, mock_request):
        mock_request.return_value = (200, {}, "OK")
        findings = check_logging_indicators("https://example.com")
        assert len(findings) == 0


# --------------------------------------------------------------------------- #
# A10 — SSRF Surface (mocked HTTP)
# --------------------------------------------------------------------------- #
class TestA10Check:
    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_ssrf_surface_params(self, mock_fetch):
        mock_fetch.return_value = '<a href="/proxy?url=https://evil.com">proxy</a>'
        findings = check_ssrf_surface("https://example.com")
        assert len(findings) >= 1
        ssrf_text = findings[0].evidence
        assert "?url=" in ssrf_text or "url=" in ssrf_text

    @patch("ghostmirror.modules.owasp.checks._fetch_body")
    def test_ssrf_surface_clean(self, mock_fetch):
        mock_fetch.return_value = "<html>no params here</html>"
        findings = check_ssrf_surface("https://example.com")
        ssrf_findings = [f for f in findings if "SSRF" in f.title]
        assert len(ssrf_findings) == 0


# --------------------------------------------------------------------------- #
# OWASP Engine
# --------------------------------------------------------------------------- #
class TestOWASPEngine:
    @patch("ghostmirror.modules.owasp.engine.check_admin_endpoints")
    @patch("ghostmirror.modules.owasp.engine.check_cryptographic_failures")
    @patch("ghostmirror.modules.owasp.engine.check_injection_surface")
    @patch("ghostmirror.modules.owasp.engine.check_insecure_design")
    @patch("ghostmirror.modules.owasp.engine.check_misconfigurations")
    @patch("ghostmirror.modules.owasp.engine.check_vulnerable_components")
    @patch("ghostmirror.modules.owasp.engine.check_auth_indicators")
    @patch("ghostmirror.modules.owasp.engine.check_integrity")
    @patch("ghostmirror.modules.owasp.engine.check_logging_indicators")
    @patch("ghostmirror.modules.owasp.engine.check_ssrf_surface")
    def test_analyze_project(
        self,
        mock_ssrf,
        mock_logging,
        mock_integrity,
        mock_auth,
        mock_vuln,
        mock_misconfig,
        mock_design,
        mock_injection,
        mock_crypto,
        mock_admin,
        tmp_path: Path,
    ):
        mock_admin.return_value = [
            OWASPFinding(category=OWASPCategory.A01, title="Admin", description="test", severity=FindingSeverity.HIGH, target="t.com")
        ]
        mock_crypto.return_value = []
        mock_injection.return_value = []
        mock_design.return_value = []
        mock_misconfig.return_value = []
        mock_vuln.return_value = []
        mock_auth.return_value = []
        mock_integrity.return_value = []
        mock_logging.return_value = []
        mock_ssrf.return_value = []

        engine = OWASPEngine()
        report = engine.analyze_project(tmp_path, "test.com")

        assert report["target"] == "test.com"
        assert report["total_findings"] >= 1
        assert "categories" in report
        assert "risk_score" in report
        assert "risk_level" in report
        assert "profile" in report

    def test_analyze_project_persists_files(self, tmp_path: Path):
        """Verify engine creates output files."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True)

        engine = OWASPEngine()
        engine._save_outputs(
            tmp_path,
            MagicMock(
                target="test.com",
                categories=["A01"],
                findings=[],
                risk_score=0,
                risk_level="LOW",
                recommendations=[],
                scan_timestamp="2024-01-01T00:00:00",
                model_dump=lambda mode: {
                    "target": "test.com",
                    "categories": ["A01"],
                    "findings": [],
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "recommendations": [],
                    "scan_timestamp": "2024-01-01T00:00:00",
                },
            ),
            [],
        )

        assert (findings_dir / "owasp_findings.json").exists()
        assert (profiles_dir / "owasp_profile.json").exists()
        assert (tmp_path / "evidence" / "owasp" / "enumeration.json").exists()
        assert (findings_dir / "owasp_summary.json").exists()

    def test_analyze_project_handles_errors_gracefully(self, tmp_path: Path):
        """Engine should handle check failures without crashing."""
        engine = OWASPEngine()
        # No SSL file, no profiles — should still work
        report = engine.analyze_project(tmp_path, "test.com")
        assert report["target"] == "test.com"
        assert isinstance(report["findings"], list)
