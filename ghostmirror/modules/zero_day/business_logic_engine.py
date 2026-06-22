from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

BUSINESS_LOGIC_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "checkout": [
        (r"checkout", "checkout_flow"),
        (r"cart", "shopping_cart"),
        (r"order", "order_management"),
        (r"purchase", "purchase"),
        (r"payment", "payment"),
        (r"billing", "billing"),
    ],
    "coupon_discount": [
        (r"coupon", "coupon"),
        (r"discount", "discount"),
        (r"promo", "promotion"),
        (r"voucher", "voucher"),
        (r"gift", "gift_card"),
        (r"referral", "referral"),
    ],
    "wallet_balance": [
        (r"wallet", "wallet"),
        (r"balance", "balance"),
        (r"credit", "credit"),
        (r"reward", "reward"),
        (r"points", "loyalty_points"),
        (r"cashback", "cashback"),
    ],
    "transfer": [
        (r"transfer", "transfer"),
        (r"withdraw", "withdrawal"),
        (r"deposit", "deposit"),
        (r"refund", "refund"),
        (r"reversal", "reversal"),
    ],
    "subscription": [
        (r"subscription", "subscription"),
        (r"plan", "plan"),
        (r"renew", "renewal"),
        (r"cancel", "cancellation"),
        (r"upgrade", "upgrade"),
        (r"downgrade", "downgrade"),
    ],
    "invoice": [
        (r"invoice", "invoice"),
        (r"receipt", "receipt"),
        (r"statement", "statement"),
        (r"tax", "tax"),
    ],
    "auth_security": [
        (r"login", "login"),
        (r"register", "registration"),
        (r"signup", "registration"),
        (r"forgot", "password_reset"),
        (r"reset", "password_reset"),
        (r"otp", "otp"),
        (r"mfa", "multi_factor"),
        (r"2fa", "two_factor"),
        (r"verify", "verification"),
    ],
    "admin_management": [
        (r"admin", "admin_panel"),
        (r"user", "user_management"),
        (r"role", "role_management"),
        (r"permission", "permission"),
        (r"config", "configuration"),
        (r"setting", "settings"),
    ],
}

FINANCIAL_KEYWORDS: list[str] = [
    "price", "amount", "total", "subtotal", "discount",
    "tax", "fee", "charge", "cost", "currency",
    "payment_method", "card_number", "cvv", "expiry",
    "bank", "account_number", "routing",
]

COMPLEX_FLOW_INDICATORS: list[tuple[str, str]] = [
    (r"step", "multi_step_flow"),
    (r"callback", "callback_flow"),
    (r"webhook", "webhook"),
    (r"redirect", "redirect_flow"),
    (r"confirm", "confirmation_step"),
    (r"review", "review_step"),
]


class BusinessLogicEngine:
    def __init__(self) -> None:
        self.opportunities: list[dict[str, Any]] = []

    def analyze(self, project_path: Path | str) -> list[dict[str, Any]]:
        project_path = Path(project_path)
        logger.info("BUSINESS_LOGIC_ENGINE_START project={}", project_path.name)
        self.opportunities = []

        web_intel_dir = project_path / "profiles" / "web_intelligence"
        api_dir = project_path / "profiles" / "api_security"

        endpoints = self._load_endpoints(web_intel_dir, api_dir)
        if not endpoints:
            logger.info("BUSINESS_LOGIC_ENGINE_SKIPPED no endpoints")
            return []

        categories_found: dict[str, list[str]] = {}
        financial_params: list[str] = []
        complex_flows: list[str] = []

        for ep in endpoints:
            url = ep.get("url", "") or ep.get("path", "") or ep.get("endpoint", "")

            for category, patterns in BUSINESS_LOGIC_PATTERNS.items():
                for pattern, label in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        if category not in categories_found:
                            categories_found[category] = []
                        categories_found[category].append(url)

            params = ep.get("parameters", {}) or ep.get("params", {}) or ep.get("form_params", [])
            if isinstance(params, list):
                for p in params:
                    if isinstance(p, str) and any(kw in p.lower() for kw in FINANCIAL_KEYWORDS):
                        financial_params.append(p)
                    elif isinstance(p, dict):
                        pname = p.get("name", "") or p.get("param", "") or ""
                        if any(kw in pname.lower() for kw in FINANCIAL_KEYWORDS):
                            financial_params.append(pname)
            elif isinstance(params, dict):
                for k in params:
                    if any(kw in k.lower() for kw in FINANCIAL_KEYWORDS):
                        financial_params.append(k)

            for pattern, label in COMPLEX_FLOW_INDICATORS:
                if re.search(pattern, url, re.IGNORECASE):
                    complex_flows.append(label)

        self.opportunities = self._build_opportunities(categories_found, financial_params, complex_flows, endpoints)

        logger.info(
            "BUSINESS_LOGIC_ENGINE_DONE categories={} financial_params={} opps={}",
            len(categories_found), len(financial_params), len(self.opportunities),
        )
        return self.opportunities

    def _load_endpoints(self, web_intel_dir: Path, api_dir: Path) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []

        web_eps = self._load_json_list(web_intel_dir / "endpoint_inventory.json")
        for ep in web_eps:
            ep["_source"] = "web_intelligence"
            endpoints.append(ep)

        api_inv = self._load_json_dict(api_dir / "api_inventory.json") or {}
        api_eps = api_inv.get("endpoints", []) if isinstance(api_inv, dict) else []
        for ep in api_eps:
            ep["_source"] = "api_security"
            endpoints.append(ep)

        return endpoints

    def _build_opportunities(
        self,
        categories: dict[str, list[str]],
        financial_params: list[str],
        complex_flows: list[str],
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        opportunities: list[dict[str, Any]] = []

        flow_description_map = {
            "checkout": "Checkout and payment flows — potential for price manipulation, race conditions, and logic flaws",
            "coupon_discount": "Coupon, discount and promotion logic — potential for abuse, reuse, and bypass",
            "wallet_balance": "Wallet, balance, and reward systems — potential for balance manipulation and double-spending",
            "transfer": "Transfer, withdrawal, and refund operations — potential for unauthorized transfers and bypass",
            "subscription": "Subscription management — potential for privilege escalation and billing bypass",
            "invoice": "Invoice and billing — potential for manipulation and information disclosure",
            "auth_security": "Authentication and security flows — potential for bypass, enumeration, and logic flaws",
            "admin_management": "Administrative and user management — potential for privilege escalation and IDOR",
        }

        for category, urls in categories.items():
            description = flow_description_map.get(category, f"{category} endpoints detected")
            severity = "CRITICAL" if category in ("transfer", "wallet_balance") else "HIGH" if category in ("checkout", "subscription") else "MEDIUM"

            opportunities.append({
                "title": f"Business Logic Research Opportunity: {category.title()}",
                "opportunity_type": "Business Logic Research",
                "confidence": "HIGH" if len(urls) >= 5 else "MEDIUM" if len(urls) >= 2 else "LOW",
                "priority": severity,
                "score": min(len(urls) * 15 + (75 if severity == "CRITICAL" else 50 if severity == "HIGH" else 25), 100),
                "description": description,
                "signals": [f"Endpoint: {u}" for u in urls[:10]],
                "reasoning": f"Found {len(urls)} endpoint(s) related to {category} operations. These flows often contain complex business logic that may be vulnerable to manipulation, race conditions, or bypass attacks.",
                "recommendation": f"Manual review of {category} flows is recommended. Focus on parameter manipulation, state transitions, and authorization checks.",
            })

        if financial_params:
            opportunities.append({
                "title": "Financial Parameters Exposed in Requests",
                "opportunity_type": "Business Logic Research",
                "confidence": "MEDIUM",
                "priority": "HIGH",
                "score": min(len(financial_params) * 10, 80),
                "description": f"Financial or monetary parameters detected in {len(financial_params)} parameter(s)",
                "signals": [f"Financial param: {p}" for p in financial_params[:20]],
                "reasoning": f"Financial parameters (price, amount, discount, etc.) found in request parameters. These may be manipulable client-side.",
                "recommendation": "Review each financial parameter for server-side validation. Test for price manipulation, negative amounts, integer overflow, and type confusion.",
            })

        if complex_flows:
            unique_flows = list(set(complex_flows))
            opportunities.append({
                "title": "Complex Multi-Step Business Flows Detected",
                "opportunity_type": "Business Logic Research",
                "confidence": "MEDIUM",
                "priority": "MEDIUM",
                "score": min(len(unique_flows) * 15, 70),
                "description": f"Multi-step or complex business flows detected: {', '.join(unique_flows)}",
                "signals": [f"Flow type: {f}" for f in unique_flows],
                "reasoning": f"Complex multi-step flows ({len(unique_flows)} type(s)) detected. These often contain logic flaws in state transitions, race conditions, and incomplete validation.",
                "recommendation": "Map the complete flow and test for improper state transitions, race conditions, and incomplete authorization at each step.",
            })

        opportunities.sort(key=lambda o: o["score"], reverse=True)
        return opportunities

    def _load_json_list(self, path: Path) -> list[Any]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _load_json_dict(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
