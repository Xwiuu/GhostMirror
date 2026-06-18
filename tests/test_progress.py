"""Tests for the progress dashboard."""

from __future__ import annotations

from ghostmirror.app.progress import ProgressDashboard, MODULE_LABELS


class TestProgressDashboard:
    def test_module_labels_defined(self):
        """All expected modules should have labels."""
        expected = ["headers", "ssl", "nmap", "fingerprint", "nuclei", "owasp", "payloads", "report"]
        for mod in expected:
            assert mod in MODULE_LABELS, f"{mod} missing from MODULE_LABELS"
            assert MODULE_LABELS[mod], f"{mod} has empty label"

    def test_dashboard_init(self):
        """Dashboard should initialize with module list."""
        modules = ["headers", "ssl", "nmap"]
        dashboard = ProgressDashboard(modules, "example.com", "quick")
        assert dashboard.target == "example.com"
        assert dashboard.profile == "quick"
        assert len(dashboard.modules) == 3

    def test_set_module_status(self):
        """Setting module status should update internal state."""
        dashboard = ProgressDashboard(["headers"], "example.com", "quick")
        dashboard.set_module_status("headers", "completed", 100.0)
        assert dashboard._module_status["headers"] == "completed"
        assert dashboard._module_progress["headers"] == 100.0

    def test_set_current_module(self):
        """Setting current module should track it."""
        dashboard = ProgressDashboard(["headers", "ssl"], "example.com", "quick")
        dashboard.set_current_module("ssl")
        assert dashboard._current_module == "ssl"
