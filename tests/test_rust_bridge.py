"""Tests for the GhostMirror Rust bridge integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.integrations.rust.models import (
    RustBannerResult,
    RustDetectedTechnology,
    RustFingerprintResult,
    RustOpenPort,
    RustPortResult,
)
from ghostmirror.integrations.rust.runner import RustBridge


class TestRustModels:
    def test_port_result_parsing(self):
        data = {
            "target": "example.com",
            "open_ports": [
                {"port": 80, "state": "open"},
                {"port": 443, "state": "open"},
            ],
            "duration_ms": 1500,
        }
        result = RustPortResult.model_validate(data)
        assert result.target == "example.com"
        assert len(result.open_ports) == 2
        assert result.open_ports[0].port == 80
        assert result.open_ports[1].state == "open"
        assert result.duration_ms == 1500

    def test_port_result_empty(self):
        data = {"target": "test.local", "open_ports": [], "duration_ms": 500}
        result = RustPortResult.model_validate(data)
        assert len(result.open_ports) == 0

    def test_banner_result_parsing(self):
        data = {
            "host": "example.com",
            "port": 80,
            "server": "nginx/1.24.0",
            "powered_by": "PHP/8.2",
            "via": "1.1 varnish",
            "technologies": ["nginx/1.24.0", "PHP/8.2"],
        }
        result = RustBannerResult.model_validate(data)
        assert result.host == "example.com"
        assert result.server == "nginx/1.24.0"
        assert result.powered_by == "PHP/8.2"
        assert "PHP/8.2" in result.technologies

    def test_banner_result_empty(self):
        data = {
            "host": "test.local",
            "port": 443,
            "server": "",
            "powered_by": "",
            "via": "",
            "technologies": [],
        }
        result = RustBannerResult.model_validate(data)
        assert result.server == ""
        assert len(result.technologies) == 0

    def test_fingerprint_result_parsing(self):
        data = {
            "target": "https://example.com",
            "technologies": [
                {"name": "WordPress", "category": "cms", "confidence": 85},
                {"name": "PHP", "category": "language", "confidence": 80},
            ],
            "cloudflare": True,
            "waf": "Cloudflare",
            "cms": "WordPress",
        }
        result = RustFingerprintResult.model_validate(data)
        assert result.target == "https://example.com"
        assert len(result.technologies) == 2
        assert result.technologies[0].name == "WordPress"
        assert result.technologies[0].confidence == 85
        assert result.cloudflare is True
        assert result.cms == "WordPress"

    def test_fingerprint_result_empty(self):
        data = {
            "target": "http://test.local",
            "technologies": [],
            "cloudflare": False,
            "waf": "",
            "cms": "",
        }
        result = RustFingerprintResult.model_validate(data)
        assert len(result.technologies) == 0
        assert result.cloudflare is False

    def test_rust_open_port_model(self):
        port = RustOpenPort(port=8080, state="open")
        assert port.port == 8080
        assert port.state == "open"

    def test_rust_detected_technology_model(self):
        tech = RustDetectedTechnology(name="Nginx", category="webserver", confidence=90)
        assert tech.name == "Nginx"
        assert tech.confidence == 90


class TestRustBridge:
    @patch("ghostmirror.integrations.rust.runner.RustBridge._find_binary")
    @patch("ghostmirror.integrations.rust.runner.subprocess.run")
    def test_portscan_success(self, mock_run, mock_find):
        mock_find.return_value = Path("/fake/ghostmirror-rs")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "target": "example.com",
            "open_ports": [{"port": 80, "state": "open"}],
            "duration_ms": 500,
        })
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        bridge = RustBridge(binary_path="/fake/ghostmirror-rs")
        result = bridge.portscan("example.com", "80")
        assert result.target == "example.com"
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 80

    @patch("ghostmirror.integrations.rust.runner.RustBridge._find_binary")
    @patch("ghostmirror.integrations.rust.runner.subprocess.run")
    def test_banner_success(self, mock_run, mock_find):
        mock_find.return_value = Path("/fake/ghostmirror-rs")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "host": "example.com",
            "port": 80,
            "server": "nginx",
            "powered_by": "PHP/8.2",
            "via": "",
            "technologies": ["nginx", "PHP/8.2"],
        })
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        bridge = RustBridge(binary_path="/fake/ghostmirror-rs")
        result = bridge.banner("example.com", 80)
        assert result.server == "nginx"
        assert result.powered_by == "PHP/8.2"

    @patch("ghostmirror.integrations.rust.runner.RustBridge._find_binary")
    @patch("ghostmirror.integrations.rust.runner.subprocess.run")
    def test_fingerprint_success(self, mock_run, mock_find):
        mock_find.return_value = Path("/fake/ghostmirror-rs")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "target": "https://example.com",
            "technologies": [{"name": "Cloudflare", "category": "cdn", "confidence": 95}],
            "cloudflare": True,
            "waf": "Cloudflare",
            "cms": "",
        })
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        bridge = RustBridge(binary_path="/fake/ghostmirror-rs")
        result = bridge.fingerprint("https://example.com")
        assert result.cloudflare is True
        assert result.waf == "Cloudflare"

    @patch("ghostmirror.integrations.rust.runner.RustBridge._find_binary")
    def test_binary_not_found(self, mock_find):
        mock_find.side_effect = FileNotFoundError("Binary not found")
        bridge = RustBridge()

        with pytest.raises(FileNotFoundError):
            bridge.portscan("example.com", "80")

    def test_port_model_json_roundtrip(self):
        original = RustPortResult(
            target="test.com",
            open_ports=[RustOpenPort(port=443, state="open")],
            duration_ms=100,
        )
        data = original.model_dump(mode="json")
        restored = RustPortResult.model_validate(data)
        assert restored.target == original.target
        assert restored.open_ports[0].port == original.open_ports[0].port

    def test_fingerprint_model_json_roundtrip(self):
        original = RustFingerprintResult(
            target="https://test.com",
            technologies=[RustDetectedTechnology(name="React", category="frontend", confidence=65)],
            cloudflare=False,
            waf="",
            cms="",
        )
        data = original.model_dump(mode="json")
        restored = RustFingerprintResult.model_validate(data)
        assert restored.target == original.target
        assert restored.technologies[0].name == "React"
