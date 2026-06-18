"""Tests for payload comparators."""

from __future__ import annotations

from ghostmirror.modules.payloads.comparators import (
    ErrorSignatureComparator,
    RedirectComparator,
    ReflectionComparator,
    StatusComparator,
    TimingComparator,
)


class TestReflectionComparator:
    def setup_method(self) -> None:
        self.cmp = ReflectionComparator()

    def test_reflected_script_detected(self) -> None:
        baseline = "<html><body>Hello</body></html>"
        probe = '<html><body><script>alert(1)</script></body></html>'
        result = self.cmp.compare(baseline, probe, "<script>alert(1)</script>")
        assert result.matched
        assert result.signal == "reflected_content_detected"

    def test_no_reflection(self) -> None:
        baseline = "<html><body>Hello</body></html>"
        probe = "<html><body>World</body></html>"
        result = self.cmp.compare(baseline, probe, "<script>alert(1)</script>")
        assert not result.matched

    def test_payload_escaped_in_body(self) -> None:
        baseline = "<html></html>"
        probe = "<html>test_value_123</html>"
        result = self.cmp.compare(baseline, probe, "test_value_123")
        assert result.matched

    def test_empty_bodies(self) -> None:
        result = self.cmp.compare("", "", "<test>")
        assert not result.matched


class TestErrorSignatureComparator:
    def setup_method(self) -> None:
        self.cmp = ErrorSignatureComparator()

    def test_sql_error_detected(self) -> None:
        baseline = "Welcome to our site"
        probe = "You have an error in your SQL syntax"
        result = self.cmp.compare(baseline, probe, expected_signal="sql_error_message")
        assert result.matched
        assert result.signal == "sql_error_message"

    def test_oracle_error_detected(self) -> None:
        baseline = "Page loaded"
        probe = "ORA-00933: SQL command not properly ended"
        result = self.cmp.compare(baseline, probe)
        assert result.matched
        assert "ORA" in result.detail or "sql" in result.signal

    def test_no_error_in_baseline_or_probe(self) -> None:
        result = self.cmp.compare("Hello", "World")
        assert not result.matched

    def test_path_traversal_detected(self) -> None:
        baseline = "Welcome"
        probe = "ghostmirror_probe not found"
        result = self.cmp.compare(baseline, probe, expected_signal="path_traversal_error")
        assert result.matched


class TestRedirectComparator:
    def setup_method(self) -> None:
        self.cmp = RedirectComparator()

    def test_new_redirect_detected(self) -> None:
        baseline_headers = {"content-type": "text/html"}
        probe_headers = {"location": "https://ghostmirror.invalid/"}
        result = self.cmp.compare(200, 302, baseline_headers, probe_headers)
        assert result.matched
        assert result.signal == "redirect_to_third_party"

    def test_both_redirect_same_location(self) -> None:
        headers = {"location": "https://example.com/login"}
        result = self.cmp.compare(302, 302, headers, headers)
        assert not result.matched

    def test_both_redirect_different_location(self) -> None:
        baseline_h = {"location": "https://example.com/a"}
        probe_h = {"location": "https://example.com/b"}
        result = self.cmp.compare(302, 302, baseline_h, probe_h)
        assert result.matched
        assert result.signal == "redirect_target_changed"

    def test_no_redirect(self) -> None:
        result = self.cmp.compare(200, 200, {}, {})
        assert not result.matched


class TestStatusComparator:
    def setup_method(self) -> None:
        self.cmp = StatusComparator()

    def test_class_changed(self) -> None:
        result = self.cmp.compare(200, 500)
        assert result.matched
        assert result.signal == "status_class_changed"

    def test_status_changed_same_class(self) -> None:
        result = self.cmp.compare(200, 201)
        assert result.matched
        assert result.signal == "status_code_changed"

    def test_no_change(self) -> None:
        result = self.cmp.compare(200, 200)
        assert not result.matched

    def test_both_errors(self) -> None:
        result = self.cmp.compare(500, 503)
        assert result.matched


class TestTimingComparator:
    def setup_method(self) -> None:
        self.cmp = TimingComparator()

    def test_large_increase(self) -> None:
        result = self.cmp.compare(0.5, 10.0, threshold=5.0)
        assert result.matched
        assert result.signal == "response_time_increased"

    def test_small_increase_ignored(self) -> None:
        result = self.cmp.compare(0.5, 1.0, threshold=5.0)
        assert not result.matched

    def test_decrease_ignored(self) -> None:
        result = self.cmp.compare(10.0, 0.5, threshold=5.0)
        assert not result.matched

    def test_equal_times(self) -> None:
        result = self.cmp.compare(2.0, 2.0)
        assert not result.matched
