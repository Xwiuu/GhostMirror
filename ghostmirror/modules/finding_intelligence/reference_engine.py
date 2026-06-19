REFERENCES_BY_CATEGORY: dict[str, list[str]] = {
    "Security Headers": [
        "https://owasp.org/www-project-secure-headers/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
        "https://cwe.mitre.org/data/definitions/693.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ],
    "SSL/TLS": [
        "https://owasp.org/www-project-transport-layer-protection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Security",
    ],
    "Open Port": [
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        "https://nvd.nist.gov/vuln/categories",
    ],
    "Information Disclosure": [
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://owasp.org/www-project-top-ten/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure_Cheat_Sheet.html",
    ],
    "Authentication": [
        "https://cwe.mitre.org/data/definitions/287.html",
        "https://owasp.org/www-project-authentication-cheat-sheet/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
    "Authorization": [
        "https://cwe.mitre.org/data/definitions/862.html",
        "https://owasp.org/www-project-authorization-cheat-sheet/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ],
    "CVE": [
        "https://cve.mitre.org/",
        "https://nvd.nist.gov/",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
}

DEFAULT_REFERENCES: list[str] = [
    "https://owasp.org/www-project-top-ten/",
    "https://cwe.mitre.org/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
]


def get_references(category: str | None = None, title: str | None = None) -> list[str]:
    if category:
        cat_lower = category.lower().strip()
        for key, refs in REFERENCES_BY_CATEGORY.items():
            if key.lower() in cat_lower or cat_lower in key.lower():
                return refs

    if title:
        title_lower = title.lower().strip()
        for key, refs in REFERENCES_BY_CATEGORY.items():
            if key.lower() in title_lower or title_lower in key.lower():
                return refs
            for kw in ("ssl", "tls", "cipher", "certificate"):
                if kw in title_lower and kw in key.lower():
                    return REFERENCES_BY_CATEGORY.get("SSL/TLS", DEFAULT_REFERENCES)
            for kw in ("cve", "cve-"):
                if kw in title_lower and kw in key.lower():
                    return REFERENCES_BY_CATEGORY.get("CVE", DEFAULT_REFERENCES)

    for key in REFERENCES_BY_CATEGORY:
        if key.lower() in (category or "").lower():
            return REFERENCES_BY_CATEGORY[key]

    return DEFAULT_REFERENCES
