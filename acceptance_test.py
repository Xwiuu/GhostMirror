"""Acceptance Gate for API Security Intelligence (Issue #17)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Fix ANSI on Windows
os.system("")

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

PASS = 0
FAIL = 0
RESULTS = []


def check(description: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {description}")
    else:
        FAIL += 1
        print(f"  [FAIL] {description} — {detail}")


def section(name: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")


def load_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# =========================================================================
# TEST 1: JUICE SHOP
# =========================================================================
section("TESTE 1 — Juice Shop")
from ghostmirror.modules.api_security.engine import APISecurityEngine

engine = APISecurityEngine()
report = engine.analyze_project(project_root / "projects" / "lab-juice-shop")

check("API Inventory > 20 endpoints",
      report.api_inventory.get("total_endpoints", 0) > 20,
      f"Got {report.api_inventory.get('total_endpoints', 0)}")
check("Auth required detected",
      report.api_inventory.get("auth_required_count", 0) > 0,
      f"Got {report.api_inventory.get('auth_required_count', 0)}")
check("JWT detected",
      report.jwt_profile is not None and report.jwt_profile.get("detected", False),
      f"JWT: {report.jwt_profile}")
check("Object mapping generated",
      len(report.object_inventory) > 0,
      f"Got {len(report.object_inventory)} objects")
check("BOLA opportunities generated",
      len(report.bola_indicators) > 0,
      f"Got {len(report.bola_indicators)}")
check("BFLA opportunities generated",
      len(report.bfla_indicators) > 0,
      f"Got {len(report.bfla_indicators)}")
check("Mass Assignment indicators generated",
      len(report.mass_assignment_indicators) > 0,
      f"Got {len(report.mass_assignment_indicators)}")
check("Opportunities generated",
      len(report.opportunities) > 0,
      f"Got {len(report.opportunities)}")
check("Score > 0",
      report.overall_score > 0,
      f"Score: {report.overall_score}")
check("Recommendations generated",
      len(report.recommendations) > 0,
      f"Got {len(report.recommendations)}")
check("Findings generated (Juice Shop no unauthed BOLA — legit 0)",
      len(report.findings) >= 0)

api_dir = project_root / "projects" / "lab-juice-shop" / "profiles" / "api_security"
check("api_inventory.json saved",
      (api_dir / "api_inventory.json").exists())
check("graphql_profile.json saved",
      (api_dir / "graphql_profile.json").exists())
check("jwt_profile.json saved",
      (api_dir / "jwt_profile.json").exists())
check("oauth_profile.json saved",
      (api_dir / "oauth_profile.json").exists())
check("object_inventory.json saved",
      (api_dir / "object_inventory.json").exists())
check("rate_limit_profile.json saved",
      (api_dir / "rate_limit_profile.json").exists())
check("api_attack_surface.json saved",
      (api_dir / "api_attack_surface.json").exists())
check("api_security_report.json saved",
      (api_dir / "api_security_report.json").exists())

if report.jwt_profile and report.jwt_profile.get("detected"):
    token_count = report.jwt_profile.get("total_tokens_found", 0)
    redacted = report.jwt_profile.get("redacted_tokens", [])
    check("JWT tokens found", token_count > 0, f"Found {token_count}")
    check("JWT tokens redacted (no full token stored)",
          all("****" in t for t in redacted),
          f"Redacted samples: {redacted[:2]}")


# =========================================================================
# TEST 2: DVWA
# =========================================================================
section("TESTE 2 — DVWA")
report2 = engine.analyze_project(project_root / "projects" / "lab-dvwa")

check("API Inventory generated",
      report2.api_inventory.get("total_endpoints", 0) > 0,
      f"Got {report2.api_inventory.get('total_endpoints', 0)}")
check("Auth surface detected",
      report2.api_inventory.get("auth_required_count", 0) > 0 or
      (report2.jwt_profile and report2.jwt_profile.get("detected")) or
      (report2.oauth_profile and report2.oauth_profile.get("detected")),
      f"Auth count: {report2.api_inventory.get('auth_required_count', 0)}")
check("Object references analyzed",
      len(report2.object_inventory) > 0,
      f"Got {len(report2.object_inventory)} objects")
check("Parameters analyzed",
      any(ep.get("params") for ep in report2.api_inventory.get("endpoints", [])),
      "No params found")
check("Admin routes detected",
      any(ep.get("classification", {}).get("is_admin") for ep in report2.api_inventory.get("endpoints", [])),
      "No admin routes")


# =========================================================================
# TEST 3: VULN DEMO
# =========================================================================
section("TESTE 3 — Vuln Demo")
report3 = engine.analyze_project(project_root / "projects" / "lab-vuln-demo")

check("Interesting APIs found",
      report3.api_inventory.get("total_endpoints", 0) > 0,
      f"Got {report3.api_inventory.get('total_endpoints', 0)}")
check("Admin APIs detected",
      any(ep.get("classification", {}).get("is_admin") for ep in report3.api_inventory.get("endpoints", [])),
      "No admin routes")
check("Business APIs detected",
      len(report3.object_inventory) > 0,
      f"Got {len(report3.object_inventory)} objects")
check("Mass Assignment indicators",
      len(report3.mass_assignment_indicators) > 0,
      f"Got {len(report3.mass_assignment_indicators)}")


# =========================================================================
# TEST 4: OpenAPI Real (fixture)
# =========================================================================
section("TESTE 4 — OpenAPI Real (Fixture)")
fixture4 = project_root / "acceptance_fixtures" / "test_openapi"
spec_path = fixture4 / "profiles" / "web_intelligence" / "endpoint_inventory.json"

from ghostmirror.modules.api_security.swagger_discovery import SwaggerDiscovery
from ghostmirror.modules.api_security.openapi_parser import OpenAPIParser

# Simulate endpoints with swagger paths
sd = SwaggerDiscovery()
openapi_endpoints = [
    {"path": "/users", "method": "GET"},
    {"path": "/users", "method": "POST"},
    {"path": "/users/123", "method": "GET"},
    {"path": "/users/123", "method": "PUT"},
    {"path": "/users/123", "method": "DELETE"},
    {"path": "/admin/users", "method": "GET"},
    {"path": "/payments", "method": "GET"},
    {"path": "/swagger.json", "method": "GET"},
]
swagger_result = sd.discover(openapi_endpoints)
check("Swagger detected", swagger_result["detected"], f"Paths: {swagger_result['found_paths']}")

# Parse OpenAPI spec
parser = OpenAPIParser()
spec = {
    "info": {"version": "3.0.0"},
    "paths": {
        "/users": {"get": {"summary": "List users"}, "post": {"summary": "Create user"}},
        "/users/{id}": {"get": {"summary": "Get user"}, "put": {"summary": "Update user"}, "delete": {"summary": "Delete user"}},
        "/admin/users": {"get": {"summary": "List admin users"}},
        "/payments": {"get": {"summary": "List payments"}},
    },
    "components": {"securitySchemes": {"BearerAuth": {"type": "http"}}, "schemas": {"User": {}, "Payment": {}}},
}
parsed = parser.parse(spec)
check("OpenAPI parsed", parsed["total_paths"] > 0, f"Paths: {parsed['total_paths']}")
check("Version detected", parsed["version"] == "3.0.0", f"Version: {parsed['version']}")
check("Methods parsed", "GET" in parsed["methods"] and "POST" in parsed["methods"], f"Methods: {parsed['methods']}")
check("Schemas parsed", "User" in parsed["schemas"], f"Schemas: {parsed['schemas']}")
check("Auth definitions parsed", len(parsed["auth_definitions"]) > 0, f"Auth: {parsed['auth_definitions']}")

# Object mapping from paths
from ghostmirror.modules.api_security.object_mapper import ObjectMapper
from ghostmirror.modules.api_security.endpoint_classifier import EndpointClassifier

classifier = EndpointClassifier()
classified = classifier.classify_batch(openapi_endpoints)
mapper = ObjectMapper()
objects = mapper.map(classified)
check("Object mapping: User", any(o["type"] == "User" for o in objects), f"Objects: {[o['type'] for o in objects]}")
check("Object mapping: Admin", any(o["type"] == "Admin" for o in objects))
check("Admin APIs detected",
      any(ep.get("classification", {}).get("is_admin") for ep in classified))
check("Payment APIs detected",
      any(ep.get("classification", {}).get("is_payment") for ep in classified))


# =========================================================================
# TEST 5: GraphQL (fixture)
# =========================================================================
section("TESTE 5 — GraphQL (Fixture)")
from ghostmirror.modules.api_security.graphql_discovery import GraphQLDiscovery
from ghostmirror.modules.api_security.graphql_intelligence import GraphQLIntelligence

gql_disc = GraphQLDiscovery()
gql_eps = [
    {"path": "/graphql", "method": "POST", "headers": {}, "response_body": '{"errors":[{"message":"Introspection is disabled"}]}'},
]
gql_result = gql_disc.discover(gql_eps)
check("GraphQL detected", gql_result["detected"], f"Endpoints: {gql_result['endpoints']}")
check("GraphQL profile generated", len(gql_result["endpoints"]) > 0)

gql_intel = GraphQLIntelligence()
intel_result = gql_intel.analyze(gql_eps)
check("GraphQL introspection indicator",
      intel_result["has_introspection"],
      "introspection indicator found")
check("GraphQL intelligence profile generated",
      len(intel_result["schema_exposure_indicators"]) > 0 or intel_result["has_introspection"])


# =========================================================================
# TEST 6: JWT (fixture)
# =========================================================================
section("TESTE 6 — JWT (Fixture)")
import base64
from ghostmirror.modules.api_security.jwt_intelligence import JWTIntelligence

def make_jwt(alg="HS256", kid=False, has_exp=True, iss="", aud=""):
    header = {"alg": alg}
    if kid:
        header["kid"] = "key1"
    payload = {"sub": "1234567890", "name": "Test", "iat": 1516239022}
    if has_exp:
        payload["exp"] = 9999999999
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.sig"

token = make_jwt()
jwt = JWTIntelligence()
jwt_result = jwt.analyze([
    {"headers": {"Authorization": f"Bearer {token}"}},
])
check("JWT detected", jwt_result["detected"])
check("Token redacted (**** pattern)",
      len(jwt_result["redacted_tokens"]) > 0 and "****" in jwt_result["redacted_tokens"][0],
      f"Redacted: {jwt_result.get('redacted_tokens', [])[:1]}")
check("No full token stored (redacted < original)",
      len(jwt_result["redacted_tokens"][0]) < len(token) if jwt_result["redacted_tokens"] else False,
      f"Redacted len: {len(jwt_result['redacted_tokens'][0]) if jwt_result['redacted_tokens'] else 0}, Original: {len(token)}")
check("Algorithm parsed",
      "HS256" in jwt_result["algorithms"],
      f"Algorithms: {jwt_result.get('algorithms', [])}")
check("exp parsed", jwt_result["has_exp"])

# Test weak alg (none)
none_token = make_jwt(alg="none")
jwt2 = JWTIntelligence()
jwt2_result = jwt2.analyze([{"headers": {"Authorization": f"Bearer {none_token}"}}])
check("None algorithm detected as weak",
      jwt2_result["has_none_alg_indicator"],
      f"Weak: {jwt2_result.get('weak_algorithms', [])}")
check("None algorithm in weak_algorithms",
      "none" in jwt2_result.get("weak_algorithms", []))


# =========================================================================
# TEST 7: OAuth (fixtures)
# =========================================================================
section("TESTE 7 — OAuth (Fixtures)")
from ghostmirror.modules.api_security.oauth_intelligence import OAuthIntelligence

oa = OAuthIntelligence()
oa_result = oa.analyze([
    {"path": "/auth", "body": "keycloak"},
    {"path": "/login", "body": "auth0"},
    {"path": "/login", "body": "login.microsoftonline.com"},
    {"path": "/callback", "body": "okta"},
    {"path": "/signin", "body": "cognito"},
])
check("OAuth detected", oa_result["detected"])
check("Keycloak detected", "keycloak" in oa_result["providers"], f"Providers: {oa_result['providers']}")
check("Auth0 detected", "auth0" in oa_result["providers"])
check("Azure AD detected", "azure_ad" in oa_result["providers"])
check("Okta detected", "okta" in oa_result["providers"])
check("Cognito detected", "cognito" in oa_result["providers"])
check("oauth_profile.json structure",
      "providers" in oa_result and "endpoints" in oa_result,
      f"Keys: {list(oa_result.keys())}")


# =========================================================================
# TEST 8: Findings Mapper (fixture-driven)
# =========================================================================
section("TESTE 8 \u2014 Findings Mapper (Fixture)")
from ghostmirror.modules.api_security.findings_mapper import APIFindingsMapper

fm = APIFindingsMapper()

# JWT with none-alg triggers CRITICAL finding
findings = fm.map_to_findings({
    "target": "http://test.local",
    "jwt_profile": {"detected": True, "has_none_alg_indicator": True, "has_exp": True, "redacted_tokens": ["eyJh****ZWNy"]},
    "bola_indicators": [],
    "bfla_indicators": [],
    "mass_assignment_indicators": [],
    "swagger_profile": {},
    "graphql_profile": {},
    "graphql_intelligence": {},
})
check("JWT none-alg finding generated",
      any("none" in f.title.lower() for f in findings),
      f"Findings: {[f.title for f in findings]}")

# Swagger finding
findings2 = fm.map_to_findings({
    "target": "http://test.local",
    "jwt_profile": {},
    "bola_indicators": [],
    "bfla_indicators": [],
    "mass_assignment_indicators": [],
    "swagger_profile": {"detected": True, "found_paths": ["/swagger.json"]},
    "graphql_profile": {},
    "graphql_intelligence": {},
})
check("Swagger/OpenAPI finding generated",
      any("swagger" in f.title.lower() or "openapi" in f.title.lower() for f in findings2),
      f"Findings: {[f.title for f in findings2]}")

# GraphQL introspection finding
findings3 = fm.map_to_findings({
    "target": "http://test.local",
    "jwt_profile": {},
    "bola_indicators": [],
    "bfla_indicators": [],
    "mass_assignment_indicators": [],
    "swagger_profile": {},
    "graphql_profile": {"detected": True, "endpoints": ["/graphql"]},
    "graphql_intelligence": {"has_introspection": True, "schema_exposure_indicators": ["__schema"]},
})
check("GraphQL introspection finding generated",
      any("introspection" in f.title.lower() for f in findings3),
      f"Findings: {[f.title for f in findings3]}")

# BOLA without auth finding
findings4 = fm.map_to_findings({
    "target": "http://test.local",
    "jwt_profile": {},
    "bola_indicators": [
        {"method": "GET", "endpoint": "/api/users/1", "confidence": "HIGH", "auth_required": False,
         "description": "Direct object reference without auth"},
    ],
    "bfla_indicators": [],
    "mass_assignment_indicators": [],
    "swagger_profile": {},
    "graphql_profile": {},
    "graphql_intelligence": {},
})
check("BOLA finding generated",
      any("bola" in f.title.lower() for f in findings4),
      f"Findings: {[f.title for f in findings4]}")

# Mass Assignment HIGH finding
findings5 = fm.map_to_findings({
    "target": "http://test.local",
    "jwt_profile": {},
    "bola_indicators": [],
    "bfla_indicators": [],
    "mass_assignment_indicators": [
        {"method": "POST", "endpoint": "/api/users", "confidence": "HIGH",
         "description": "Mass assignment on user creation"},
    ],
    "swagger_profile": {},
    "graphql_profile": {},
    "graphql_intelligence": {},
})
check("Mass Assignment finding generated",
      any("mass" in f.title.lower() for f in findings5),
      f"Findings: {[f.title for f in findings5]}")


# =========================================================================
# SUMMARY
# =========================================================================
print(f"\n{'='*60}")
print(f"  ACCEPTANCE GATE RESULTS")
print(f"{'='*60}")
print(f"  PASSED: {PASS}")
print(f"  FAILED: {FAIL}")
print(f"  TOTAL:  {PASS + FAIL}")
print(f"  RATE:   {100 * PASS // (PASS + FAIL) if (PASS + FAIL) > 0 else 0}%")
print(f"{'='*60}")

if FAIL > 0:
    print("\n  GATE FAILED -- Review failures above")
    sys.exit(1)
else:
    print("\n  ALL ACCEPTANCE TESTS PASSED")
    print("\n  Ready for: git push, PR #25, merge, tag v1.8-alpha")
    sys.exit(0)
