# API Security Intelligence

> **Non-destructive API analysis, classification, correlation, and scoring.**

The API Security Intelligence module transforms GhostMirror into a platform capable of discovering, understanding, classifying, correlating, and prioritizing API risks — all without destructive exploitation, brute force, authentication bypass, mass requests, or aggressive fuzzing.

## Architecture

```
ghostmirror/modules/api_security/
├── engine.py                     # Main orchestrator
├── api_inventory.py              # Consolidates APIs from all sources
├── swagger_discovery.py          # Detects Swagger/OpenAPI docs
├── openapi_parser.py             # Parses OpenAPI specs
├── graphql_discovery.py          # Detects GraphQL endpoints
├── graphql_intelligence.py       # Analyzes GraphQL exposure
├── jwt_intelligence.py           # Detects and analyzes JWT tokens
├── oauth_intelligence.py         # Detects OAuth/OIDC providers
├── auth_intelligence.py          # Combines JWT + OAuth intelligence
├── endpoint_classifier.py        # Classifies endpoint types
├── object_mapper.py              # Maps resources (users, accounts, etc.)
├── parameter_analyzer.py         # Classifies parameters
├── rate_limit_intelligence.py    # Detects rate limiting headers
├── exposure_analysis.py          # Calculates API exposure score
├── bola_indicators.py            # Generates BOLA hypotheses
├── bfla_indicators.py            # Detects BFLA opportunities
├── mass_assignment_indicators.py # Detects mass assignment surfaces
├── api_correlation.py            # Correlates findings across modules
├── scoring.py                    # Opportunity scoring engine
├── recommendations.py            # Generates specific recommendations
├── findings_mapper.py            # Maps to FindingModel for reports
└── report_builder.py             # Builds APISecurityReport
```

## Pipeline Integration

The `api_security` step runs in all profiles:

| Profile | Step Order |
|---------|-----------|
| **standard** | After `web_intelligence` |
| **deep** | After `web_intelligence` |
| **bounty** | After `finding_intelligence` |

## CLI Commands

```
ghostmirror api                       # Full API Security Intelligence analysis
ghostmirror api inventory             # Consolidated API inventory
ghostmirror api graphql               # GraphQL discovery and intelligence
ghostmirror api jwt                   # JWT token analysis (redacted)
ghostmirror api oauth                 # OAuth/OIDC provider detection
ghostmirror api opportunities         # API opportunity matrix
ghostmirror analyze api               # Full analysis via analyze sub-app
```

## Models

| Model | Purpose |
|-------|---------|
| `APIEndpoint` | Single API endpoint with method, path, auth, source, confidence |
| `APIInventoryProfile` | Aggregated inventory with counts by method, source, confidence |
| `GraphQLProfile` | Detected GraphQL endpoints, frameworks, and exposure indicators |
| `JWTProfile` | JWT token analysis (redacted), algorithms, claims |
| `OAuthProfile` | OAuth/OIDC provider detection and endpoint mapping |
| `APIRisk` | Per-endpoint risk including BOLA, BFLA, Mass Assignment |
| `APIAttackSurface` | Exposure score (0-100) with factor breakdown |
| `APISecurityReport` | Consolidated report aggregating all API intelligence |

## Key Principles

1. **Non-destructive** — All analysis is purely observational
2. **No brute force** — No ID substitution or enumeration
3. **No authentication bypass** — Only detects auth requirements
4. **No mass requests** — Reads existing data only
5. **Token redaction** — JWT tokens are truncated (eyJh****abcd)
6. **No aggressive fuzzing** — Structural analysis only

## Scoring

The API Exposure Score (0-100) is calculated from:

- Endpoint density (10%)
- Authentication coverage (15%)
- Swagger/OpenAPI presence (5%)
- GraphQL presence (5%)
- Sensitive objects (20%)
- Admin/Payment endpoint exposure (25%)
- Rate limiting weakness (10%)
- JWT weaknesses (5%)
- OAuth presence (5%)

## Correlation Engine

Cross-references findings across:
- JWT + Admin API + BFLA → High Value API Surface
- Swagger + Sensitive Objects → Documented Attack Surface
- GraphQL + No Auth → Unauthenticated GraphQL
- BOLA + No Auth → Critical Opportunities
- Admin + PUT/PATCH → Mass Assignment Surface

## Output

All results are saved to `profiles/api_security/`:

```
profiles/api_security/
├── api_inventory.json
├── swagger_profile.json
├── graphql_profile.json
├── graphql_intelligence.json
├── jwt_profile.json
├── oauth_profile.json
├── auth_profile.json
├── object_inventory.json
├── parameter_analysis.json
├── rate_limit_profile.json
├── bola_indicators.json
├── bfla_indicators.json
├── mass_assignment_indicators.json
├── api_attack_surface.json
├── api_correlations.json
├── api_opportunities.json
├── api_recommendations.json
├── api_findings.json
└── api_security_report.json
```

## Lab Validation

Validated against:
- GhostMirror Vuln Demo
- DVWA
- OWASP Juice Shop (generates API Inventory, JWT Indicators, Object Mapping, Auth Surface, Opportunity Matrix)

## Disclaimer

**Use only on targets you own or are explicitly authorized to test.**
