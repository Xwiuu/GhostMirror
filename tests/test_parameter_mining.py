from __future__ import annotations

import pytest

from ghostmirror.modules.bug_bounty.parameter_mining import ParameterMining


class TestParameterMining:
    @pytest.fixture
    def miner(self) -> ParameterMining:
        return ParameterMining()

    def test_init(self, miner: ParameterMining) -> None:
        assert miner._parameters == []

    def test_mine_empty(self, miner: ParameterMining) -> None:
        result = miner.mine([])
        assert result == []

    def test_mine_url_params(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/page?q=search&page=1&id=42", "source": "crawl", "form_params": [], "js_params": []}]
        result = miner.mine(sources)
        assert len(result) == 3

    def test_mine_form_params(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/login", "source": "form", "form_params": ["username", "password", "token"], "js_params": []}]
        result = miner.mine(sources)
        assert len(result) == 3

    def test_mine_js_params(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/api", "source": "js", "form_params": [], "js_params": ["api_key", "user_id", "redirect"]}]
        result = miner.mine(sources)
        assert len(result) == 3

    def test_mine_deduplicates(self, miner: ParameterMining) -> None:
        sources = [
            {"url": "https://example.com/page?id=1", "source": "crawl", "form_params": [], "js_params": []},
            {"url": "https://example.com/other?id=2", "source": "crawl", "form_params": [], "js_params": []},
        ]
        result = miner.mine(sources)
        # "id" should only appear once
        id_params = [p for p in result if p["parameter"] == "id"]
        assert len(id_params) == 1

    def test_classify_sensitive(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/api", "source": "test", "form_params": ["token", "password", "secret"], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("token") == "Sensitive"
        assert classifications.get("password") == "Sensitive"
        assert classifications.get("secret") == "Sensitive"

    def test_classify_auth(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/login", "source": "test", "form_params": ["login", "register", "email"], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("login") == "Auth"
        assert classifications.get("register") == "Auth"

    def test_classify_redirect(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/auth?redirect=/admin", "source": "test", "form_params": [], "js_params": ["return_url"]}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("redirect") == "Redirect"
        assert classifications.get("return_url") == "Redirect"

    def test_classify_file_params(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/upload", "source": "test", "form_params": ["file", "filename", "upload"], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("file") == "File"
        assert classifications.get("filename") == "File"

    def test_classify_object_id(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/order?id=42&user_id=5&product_id=10", "source": "test", "form_params": [], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("id") == "Object ID"
        assert classifications.get("user_id") == "Object ID"
        assert classifications.get("product_id") == "Object ID"

    def test_classify_payment(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/checkout", "source": "test", "form_params": ["amount", "card", "coupon", "price"], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("amount") == "Payment"
        assert classifications.get("coupon") == "Payment"

    def test_classify_search(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/search?q=hello&filter=all&page=1", "source": "test", "form_params": [], "js_params": []}]
        result = miner.mine(sources)
        classifications = {p["parameter"]: p["classification"] for p in result}
        assert classifications.get("q") == "Search"
        assert classifications.get("filter") == "Search"

    def test_classify_unknown(self, miner: ParameterMining) -> None:
        sources = [{"url": "https://example.com/page?foo=bar&baz=qux", "source": "test", "form_params": [], "js_params": []}]
        result = miner.mine(sources)
        for p in result:
            assert p["classification"] == "Unknown"

    def test_extract_from_url(self, miner: ParameterMining) -> None:
        assert miner._extract_from_url("https://example.com/page") == []
        assert miner._extract_from_url("https://example.com/page?a=1&b=2") == ["a", "b"]
        assert miner._extract_from_url("https://example.com/page?a=1#frag") == ["a"]
