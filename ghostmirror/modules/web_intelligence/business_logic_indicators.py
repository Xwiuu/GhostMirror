from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.web_intelligence_report import BusinessLogicArea

logger = get_logger()

BUSINESS_LOGIC_PATTERNS: dict[str, list[str]] = {
    "checkout": ["checkout", "cart", "carrinho", "payment", "pagamento", "buy", "comprar", "purchase"],
    "coupon": ["coupon", "cupom", "discount", "desconto", "promo", "promoção", "voucher", "gift-card"],
    "credits": ["credit", "credito", "credits", "wallet", "carteira", "balance", "saldo", "points", "pontos"],
    "rewards": ["reward", "recompensa", "cashback", "bonus", "bônus", "loyalty", "fidelidade"],
    "transactions": ["transaction", "transação", "transfer", "transferência", "invoice", "fatura", "receipt", "comprovante"],
    "subscription": ["subscription", "assinatura", "plan", "plano", "renew", "renovar", "upgrade", "downgrade"],
    "refund": ["refund", "reembolso", "cancel", "cancelamento", "chargeback", "dispute"],
    "pricing": ["price", "preço", "pricing", "precificação", "quote", "orçamento", "budget"],
}

BUSINESS_RISK_MAP: dict[str, str] = {
    "checkout": "high",
    "coupon": "high",
    "credits": "high",
    "rewards": "medium",
    "transactions": "high",
    "subscription": "medium",
    "refund": "critical",
    "pricing": "medium",
}

BUSINESS_LOGIC_PARAMS: set[str] = {
    "price", "total", "quantity", "qty", "discount", "coupon",
    "credit", "wallet", "balance", "points", "cashback",
    "bonus", "reward", "gift", "voucher", "promo",
    "percent", "percentage", "rate", "value", "amount",
    "tax", "shipping", "fee", "installments",
    "plan", "tier", "level", "upgrade", "downgrade",
    "subscription", "billing", "payment_method",
    "refund", "cancel", "return",
    "referral", "commission", "affiliate",
}


class BusinessLogicIndicators:
    def analyze(
        self,
        endpoints: list[WebEndpoint],
        parameters: list[ParameterProfile],
    ) -> tuple[list[BusinessLogicArea], list[WebIndicator]]:
        logger.info("BUSINESS_LOGIC_INDICATORS_START")
        areas: list[BusinessLogicArea] = []
        indicators: list[WebIndicator] = []

        detected_areas: dict[str, BusinessLogicArea] = {}

        for ep in endpoints:
            url_lower = ep.url.lower()
            for area_name, patterns in BUSINESS_LOGIC_PATTERNS.items():
                for pat in patterns:
                    if pat in url_lower:
                        if area_name not in detected_areas:
                            detected_areas[area_name] = BusinessLogicArea(
                                area=area_name,
                                risk=BUSINESS_RISK_MAP.get(area_name, "info"),
                                description=f"Business logic area '{area_name}' identified.",
                            )
                        detected_areas[area_name].endpoints.append(ep.url)
                        break

        for param in parameters:
            if param.name.lower() in BUSINESS_LOGIC_PARAMS:
                location = param.locations[0] if param.locations else ""
                area_hint = "checkout"
                for area_name, patterns in BUSINESS_LOGIC_PATTERNS.items():
                    if param.name.lower() in patterns:
                        area_hint = area_name
                        break

                if area_hint not in detected_areas:
                    detected_areas[area_hint] = BusinessLogicArea(
                        area=area_hint,
                        risk=BUSINESS_RISK_MAP.get(area_hint, "info"),
                        description=f"Business logic area '{area_hint}' identified via parameter.",
                    )
                detected_areas[area_hint].parameters.append(param.name)

                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.BUSINESS_LOGIC,
                    title=f"Business Logic Parameter: {param.name}",
                    description=f"Parameter '{param.name}' is related to business logic in the '{area_hint}' area and requires manual review.",
                    endpoint=location,
                    parameter=param.name,
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Parameter '{param.name}' found in business logic area '{area_hint}'",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation=f"Manually review parameter '{param.name}' for business logic flaws (e.g., price manipulation, coupon abuse).",
                ))

        for area_name, area in detected_areas.items():
            area.endpoints = list(set(area.endpoints))
            area.parameters = list(set(area.parameters))
            areas.append(area)

        logger.info("BUSINESS_LOGIC_INDICATORS_DONE areas={} indicators={}", len(areas), len(indicators))
        return areas, indicators
