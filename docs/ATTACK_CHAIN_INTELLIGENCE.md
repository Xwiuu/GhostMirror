# Attack Chain Intelligence

## Overview

Attack Chain Intelligence transforms isolated security signals into comprehensible,
prioritized attack chains. It helps pentesters and security engineers understand:

- How an attacker could chain these findings together
- Which finding combinations elevate risk
- Which chain deserves investigation first
- Business and technical impact
- Safe manual validation steps
- Defensive recommendations

> **Warning**: Attack chains are hypotheses for authorized manual review, not proof
> of compromise. Do not use this output for exploitation.

## Architecture

```
project/profiles/attack_chain/
├── signals.json                    # Collected signals from all modules
├── attack_graph.json               # Built attack graph (nodes + edges)
├── chains.json                     # Generated attack chains
├── attack_chain_priorities.json    # Prioritized chains
├── linked_evidence.json            # Evidence references
└── attack_chain_report.json        # Complete report
```

### Components

| Component | Description |
|-----------|-------------|
| `SignalCollector` | Consumes signals from web intelligence, API security, bug bounty, zero-day, vulnerability intelligence, finding intelligence, headers, nuclei, OWASP, SSL/Nmap |
| `GraphBuilder` | Builds an attack graph with typed nodes and edges |
| `ChainBuilder` | Matches signals against templates to build attack chains |
| `ChainTemplates` | 10 predefined attack chain templates |
| `ChainScoring` | Calculates score 0-100 based on severity, confidence, exploitability, exposure, business impact |
| `ChainClassifier` | Classifies chains as critical/high/medium/low |
| `ChainPrioritizer` | Orders chains by priority, score, confidence, business impact, exploitability |
| `BusinessImpact` | Analyzes business impact per chain |
| `TechnicalImpact` | Analyzes technical impact per chain |
| `Recommendations` | Generates defensive recommendations |
| `EvidenceLinker` | Links each chain to source files |
| `FindingsMapper` | Maps signals to standard FindingModel |
| `ReportBuilder` | Builds the complete AttackChainReport |

## Signal Types

| Signal | Source |
|--------|--------|
| `exposed_admin` | Bug Bounty, Web Intelligence |
| `exposed_api` | API Security, Bug Bounty |
| `sensitive_object` | Finding Intelligence, Nuclei, OWASP |
| `jwt_detected` | API Security |
| `oauth_detected` | API Security |
| `bola_indicator` | API Security |
| `bfla_indicator` | API Security |
| `mass_assignment_indicator` | API Security |
| `cve_known_exploited` | Vulnerability Intelligence, Nuclei |
| `public_exploit_available` | Vulnerability Intelligence |
| `missing_header` | Headers Scanner |
| `source_map_exposed` | Bug Bounty |
| `secret_exposed` | Bug Bounty |
| `business_logic_surface` | Web Intelligence |
| `zero_day_hypothesis` | Zero-Day Engine |
| `graphql_surface` | API Security |
| `rate_limit_unknown` | API Security |
| `auth_surface` | Web Intelligence |

## Attack Chain Templates

1. JWT + Admin API + Sensitive Object
2. Swagger/OpenAPI + Admin Endpoint + BOLA Indicator
3. Source Map + Hidden Functionality + Internal API
4. Public CVE + Internet Exposed Service + No WAF
5. Business Logic Surface + Payment Object + Weak Auth Signal
6. GraphQL Surface + Sensitive Object + Auth Weakness
7. Secret Exposure + API Endpoint + Cloud Service Indicator
8. Missing Security Header + XSS Indicator + Auth Flow
9. Rate Limit Unknown + Auth Endpoint + Sensitive Action
10. Zero-Day Hypothesis + Business Logic + API Object

## Scoring

Score 0-100 based on weighted factors:

| Factor | Weight |
|--------|--------|
| Severity | 20% |
| Confidence | 15% |
| Signal Count | 10% |
| Exploitability | 15% |
| Exposure | 10% |
| Business Impact | 10% |
| Known Exploitation | 10% |
| Sensitive Objects | 5% |
| Auth Context | 5% |

### Classification

| Score | Classification |
|-------|--------------|
| 80-100 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| 0-39 | Low |

## CLI Usage

```bash
# Run Attack Chain Intelligence
ghostmirror attack-chain run --project my-project

# View attack graph summary
ghostmirror attack-chain graph --project my-project

# View top prioritized chains
ghostmirror attack-chain top --project my-project --limit 5

# View full report summary
ghostmirror attack-chain report --project my-project

# Run via analyze sub-command
ghostmirror analyze attack-chain --project my-project
```

## Pipeline Integration

Attack Chain runs after `zero_day`, `finding_intelligence`, `api_security`,
`bug_bounty` and before `report` in the following profiles:

- `standard` ✓
- `deep` ✓
- `bounty` ✓

## Lab Validation

### Juice Shop
- JWT + API + Sensitive Objects
- Business Logic + Payment/Basket

### DVWA
- Auth Surface + Admin + Weakness Signals

### Vuln Demo
- Source Map + Hidden Functionality + Internal API
- Business Logic + Sensitive Object

## Safety

- No exploitation is performed
- No destructive payloads are generated
- No active bypass suggestions
- No compromise assertions
- All chains are hypotheses requiring manual validation
- Secrets/tokens are redacted in evidence
