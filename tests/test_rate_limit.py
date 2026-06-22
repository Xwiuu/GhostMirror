from __future__ import annotations

from ghostmirror.modules.api_security.rate_limit_intelligence import RateLimitIntelligence


class TestRateLimitIntelligence:
    def test_unknown_when_no_headers(self):
        rl = RateLimitIntelligence()
        result = rl.analyze([{"path": "/api/users", "headers": {}}])
        assert result["classification"] == "Unknown"
        assert not result["rate_limit_detected"]

    def test_detects_x_ratelimit(self):
        rl = RateLimitIntelligence()
        result = rl.analyze([{"path": "/api/users", "response_headers": {"X-RateLimit-Limit": "100"}}])
        assert result["rate_limit_detected"]
        assert result["classification"] in ("Present", "Strong")

    def test_strong_with_remaining(self):
        rl = RateLimitIntelligence()
        result = rl.analyze([{"path": "/api/users", "response_headers": {
            "X-RateLimit-Remaining": "50",
            "X-RateLimit-Limit": "100",
        }}])
        assert result["classification"] == "Strong"

    def test_detects_retry_after(self):
        rl = RateLimitIntelligence()
        result = rl.analyze([{"path": "/api/users", "response_headers": {"Retry-After": "120"}}])
        assert result["rate_limit_detected"]

    def test_classify_no_headers(self):
        rl = RateLimitIntelligence()
        assert rl._classify() == "Unknown"

    def test_classify_present(self):
        rl = RateLimitIntelligence()
        rl.headers_found = ["X-RateLimit-Limit"]
        assert rl._classify() == "Present"

    def test_classify_weak(self):
        rl = RateLimitIntelligence()
        rl.headers_found = ["X-Throttle-Limit"]
        assert rl._classify() == "Weak"

    def test_multiple_endpoints(self):
        rl = RateLimitIntelligence()
        result = rl.analyze([
            {"path": "/api/users", "headers": {}},
            {"path": "/api/orders", "response_headers": {"X-RateLimit-Limit": "50"}},
        ])
        assert result["rate_limit_detected"]
