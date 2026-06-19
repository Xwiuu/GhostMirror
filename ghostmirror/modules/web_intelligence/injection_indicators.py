from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.parameter_profile import ParameterProfile

logger = get_logger()

SQL_ERROR_PATTERNS = re.compile(
    r"(SQL syntax|MySQL|MariaDB|PostgreSQL|SQLite|sqlite|ORA-\d{5}"
    r"|mysql_fetch|mysql_query|pg_query|SQLSTATE\["
    r"|unclosed quotation mark|incorrect syntax near"
    r"|division by zero|unterminated quoted string"
    r"|supplied argument is not a valid MySQL"
    r"|Microsoft OLE DB.*SQL Server"
    r"|JDBC.*SQL|SQLServer|DB2 Error"
    r")",
    re.IGNORECASE,
)

STACK_TRACE_PATTERN = re.compile(
    r"(Stack trace:|Traceback \(most recent call last\):|at\s+\S+\.\w+\(|\.py:\d+|\.java:\d+)",
    re.IGNORECASE,
)

DB_ERROR_PATTERN = re.compile(
    r"(Database error|DB Error|ERROR:.*SQL|PDOException|mysqli error|mysql error|SQL Error)",
    re.IGNORECASE,
)

DYNAMIC_PARAM_PATTERN = re.compile(r"^[a-z_]+$", re.IGNORECASE)


class InjectionIndicators:
    def analyze(
        self,
        endpoints: list[WebEndpoint],
        parameters: list[ParameterProfile],
    ) -> list[WebIndicator]:
        logger.info("INJECTION_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for ep in endpoints:
            html = ep.response_body_sample

            if SQL_ERROR_PATTERNS.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.SQL_INJECTION,
                    title="SQL Error Message Detected",
                    description="A SQL error message was found in the response, indicating possible SQL injection vulnerability.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.HIGH,
                    severity=SeverityLevel.HIGH,
                    evidence=SQL_ERROR_PATTERNS.search(html).group(0),
                    owasp_category="A03:2021 – Injection",
                    recommendation="Review the parameter for SQL injection vulnerabilities. Use parameterized queries.",
                ))

            if STACK_TRACE_PATTERN.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.INFO_LEAK,
                    title="Stack Trace Exposed",
                    description="A stack trace was found in the response, potentially leaking sensitive information.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.HIGH,
                    severity=SeverityLevel.MEDIUM,
                    evidence=STACK_TRACE_PATTERN.search(html).group(0),
                    owasp_category="A05:2021 – Security Misconfiguration",
                    recommendation="Disable debug mode and detailed error messages in production.",
                ))

            if DB_ERROR_PATTERN.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.SQL_INJECTION,
                    title="Database Error Detected",
                    description="A database error message was found, suggesting potential SQL injection.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=DB_ERROR_PATTERN.search(html).group(0),
                    owasp_category="A03:2021 – Injection",
                    recommendation="Review the affected parameter for SQL injection. Use prepared statements.",
                ))

        for param in parameters:
            if param.name.lower() in ("id", "page", "order", "search", "q", "category"):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.SQL_INJECTION,
                    title=f"Dynamic Parameter: {param.name}",
                    description=f"Parameter '{param.name}' is commonly used in SQL queries and may be injectable.",
                    endpoint=param.locations[0] if param.locations else "",
                    parameter=param.name,
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.INFO,
                    owasp_category="A03:2021 – Injection",
                    recommendation=f"Review the usage of parameter '{param.name}' for SQL injection. Ensure parameterized queries are used.",
                ))

        logger.info("INJECTION_INDICATORS_DONE total={}", len(indicators))
        return indicators
