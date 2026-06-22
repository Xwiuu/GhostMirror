from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.zero_day.business_logic_engine import BusinessLogicEngine


class TestBusinessLogicEngine:
    def test_init(self):
        engine = BusinessLogicEngine()
        assert engine.opportunities == []

    def test_analyze_no_endpoints(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_detect_checkout_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/checkout", "method": "POST", "_source": "test"},
            {"url": "https://example.com/cart/add", "method": "POST", "_source": "test"},
            {"url": "https://example.com/order/confirm", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"checkout": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1
        assert any("checkout" in o["title"].lower() for o in opps)

    def test_detect_coupon_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/coupon/apply", "method": "POST", "_source": "test"},
            {"url": "https://example.com/discount/check", "method": "GET", "_source": "test"},
        ]
        opps = engine._build_opportunities({"coupon_discount": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1

    def test_detect_wallet_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/wallet/balance", "method": "GET", "_source": "test"},
            {"url": "https://example.com/reward/claim", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"wallet_balance": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1

    def test_detect_transfer_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/transfer", "method": "POST", "_source": "test"},
            {"url": "https://example.com/withdraw", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"transfer": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1
        assert opps[0]["priority"] == "CRITICAL"

    def test_detect_subscription_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/subscription/create", "method": "POST", "_source": "test"},
            {"url": "https://example.com/plan/upgrade", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"subscription": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1

    def test_detect_invoice_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/invoice/123", "method": "GET", "_source": "test"},
        ]
        opps = engine._build_opportunities({"invoice": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1

    def test_detect_auth_flow(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/login", "method": "POST", "_source": "test"},
            {"url": "https://example.com/register", "method": "POST", "_source": "test"},
            {"url": "https://example.com/reset-password", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"auth_security": [e["url"] for e in eps]}, [], [], eps)
        assert len(opps) >= 1

    def test_financial_params_opportunity(self):
        engine = BusinessLogicEngine()
        opps = engine._build_opportunities({}, ["price", "amount", "discount"], [], [])
        assert any("Financial" in o["title"] for o in opps)

    def test_complex_flows_opportunity(self):
        engine = BusinessLogicEngine()
        opps = engine._build_opportunities({}, [], ["multi_step_flow", "callback_flow"], [])
        assert any("Complex" in o["title"] for o in opps)

    def test_opportunity_sorting(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": "https://example.com/checkout", "method": "POST", "_source": "test"},
            {"url": "https://example.com/cart", "method": "POST", "_source": "test"},
        ]
        opps = engine._build_opportunities({"checkout": [e["url"] for e in eps]}, [], [], eps)
        if len(opps) > 1:
            assert opps[0]["score"] >= opps[1]["score"]

    def test_confidence_high(self):
        engine = BusinessLogicEngine()
        eps = [
            {"url": f"https://example.com/checkout/{i}", "method": "POST", "_source": "test"}
            for i in range(5)
        ]
        opps = engine._build_opportunities({"checkout": [e["url"] for e in eps]}, [], [], eps)
        assert opps[0]["confidence"] == "HIGH"

    def test_opportunity_score_range(self):
        engine = BusinessLogicEngine()
        eps = [{"url": "https://example.com/checkout", "method": "POST", "_source": "test"}]
        opps = engine._build_opportunities({"checkout": [e["url"] for e in eps]}, [], [], eps)
        assert 0 <= opps[0]["score"] <= 100

    def test_load_json_list_missing(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        assert engine._load_json_list(tmp_path / "nonexistent.json") == []

    def test_load_json_list_valid(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump([1, 2, 3], f)
        assert engine._load_json_list(p) == [1, 2, 3]

    def test_load_json_list_dict_returns_empty(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump({"key": "value"}, f)
        assert engine._load_json_list(p) == []

    def test_load_json_dict_missing(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        assert engine._load_json_dict(tmp_path / "nonexistent.json") is None

    def test_load_json_dict_valid(self, tmp_path: Path):
        engine = BusinessLogicEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump({"key": "value"}, f)
        assert engine._load_json_dict(p) == {"key": "value"}

    def test_analyze_with_web_intel_data(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "endpoint_inventory.json", "w") as f:
            json.dump([{"url": "https://example.com/checkout", "method": "POST"}], f)
        engine = BusinessLogicEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_api_data(self, tmp_path: Path):
        api_dir = tmp_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "api_inventory.json", "w") as f:
            json.dump({"endpoints": [{"url": "https://example.com/coupon", "method": "POST"}]}, f)
        engine = BusinessLogicEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_financial_params_in_dict(self):
        engine = BusinessLogicEngine()
        eps = [{"url": "https://example.com/order", "method": "POST", "parameters": {"price": "100", "amount": "1"}, "_source": "test"}]
        opps = engine._build_opportunities({}, ["price", "amount"], [], eps)
        assert any("Financial" in o["title"] for o in opps)
