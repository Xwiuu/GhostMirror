"""Map references for bounty submissions: OWASP, CWE, PortSwigger, MITRE."""
from __future__ import annotations

REFERENCES_BY_CATEGORY = {
    "missing_header": ["https://owasp.org/www-project-secure-headers/", "https://cwe.mitre.org/data/definitions/693.html"],
    "open_redirect": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards", "https://cwe.mitre.org/data/definitions/601.html", "https://portswigger.net/web-security/ssrf"],
    "information_disclosure": ["https://cwe.mitre.org/data/definitions/200.html", "https://owasp.org/www-project-top-ten/"],
    "bola": ["https://cwe.mitre.org/data/definitions/639.html", "https://owasp.org/www-project-api-security/", "https://portswigger.net/web-security/access-control/idor"],
    "bfla": ["https://cwe.mitre.org/data/definitions/285.html", "https://owasp.org/www-project-api-security/"],
    "graphql": ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html", "https://portswigger.net/web-security/graphql"],
    "jwt": ["https://cwe.mitre.org/data/definitions/347.html", "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html", "https://portswigger.net/web-security/jwt"],
    "cve": ["https://cve.mitre.org/", "https://nvd.nist.gov/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
}

DEFAULT_REFERENCES = ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://portswigger.net/web-security/"]

class ReferencesMapper:
    @staticmethod
    def get_references(category="", title="", cwe=""):
        t, c = title.lower(), category.lower()
        for key in REFERENCES_BY_CATEGORY:
            if key in t or key in c: return REFERENCES_BY_CATEGORY[key]
        if cwe: return [f"https://cwe.mitre.org/data/definitions/{cwe.replace(chr(67)+chr(87)+chr(69)+chr(45), chr(0)).replace(chr(67)+chr(87)+chr(69)+chr(45), "").strip()}.html"]
        return DEFAULT_REFERENCES
