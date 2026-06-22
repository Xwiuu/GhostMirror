# Bug Bounty Mode — GhostMirror

## O que é o Bug Bounty Mode?

O Bug Bounty Mode é um subsistema do GhostMirror focado em **reconhecimento ofensivo e descoberta de superfície de ataque** para programas de bug bounty. Ele automatiza a coleta de informações públicas e semi-públicas de alvos autorizados, gerando um relatório consolidado de oportunidades.

> ⚠️ **Aviso / Warning**
> - O Bug Bounty Mode é **somente para uso autorizado** contra alvos que você possui permissão explícita para testar.
> - Use only on targets you own or are explicitly authorized to test.
> - Respect program scope, rate limits, and disclosure rules.
> - Nenhuma exploração destrutiva, brute force, DoS ou credential stuffing é realizada.
> - Todas as operações respeitam o **Scope Guard**, rate limiting e timeouts configurados.

---

## Arquitetura

```
┌──────────────────────────────────────────────────┐
│           CLI: ghostmirror bounty                 │
│   scan | crawl | js | apis | secrets | report    │
├──────────────────────────────────────────────────┤
│              BugBountyEngine (engine.py)          │
│   Orquestra pipeline completo de recon           │
├─────────────────┬────────────────────────────────┤
│  HeadlessCrawler │   NetworkCapture               │
│  (headless_crawler.py) │   (network_capture.py)              │
│  Playwright crawl │   Captura XHR/fetch/requests  │
│  + form extraction │   + API candidate detection  │
├─────────────────┼────────────────────────────────┤
│  JSBundleAnalyzer │   SourcemapAnalyzer            │
│  (js_bundle_analyzer.py) │   (sourcemap_analyzer.py)            │
│  Baixa + analisa JS │   Descobre + parseia sourcemaps │
├─────────────────┼────────────────────────────────┤
│  APIDiscovery    │   ParameterMining              │
│  (api_discovery.py) │   (parameter_mining.py)                │
│  Combina fontes   │   Minera params ocultos       │
├─────────────────┼────────────────────────────────┤
│  SecretsDiscovery │   InterestingFiles             │
│  (secrets_discovery.py) │   (interesting_files.py)             │
│  Regex de secrets │   robots.txt, .env, backup    │
├─────────────────┼────────────────────────────────┤
│  SubdomainDiscovery │   Scoring + Recommendations │
│  (subdomain_discovery.py) │   (scoring.py, recommendations.py)  │
│  CT logs + DNS    │   Prioriza oportunidades      │
├─────────────────┼────────────────────────────────┤
│  ReportBuilder   │   FindingsMapper               │
│  (report_builder.py) │   (findings_mapper.py)                 │
│  Gera relatório   │   Mapeia para findings        │
└─────────────────┴────────────────────────────────┘
```

---

## Comandos CLI

### ghostmirror bounty scan

Scan completo de bug bounty — executa todos os módulos em sequência:

```bash
ghostmirror bounty scan --project <slug>
ghostmirror bounty scan --project <slug> --target https://example.com
```

Fluxo:
1. Carrega technology profile do projeto
2. Headless crawl (Playwright) — coleta rotas, formulários, requests XHR/fetch
3. Network capture — ingesta requests capturados
4. JS bundle analysis + sourcemap discovery
5. API discovery — combina fontes (network, JS, sourcemap, web intelligence)
6. Parameter mining — extrai parâmetros de formulários e JS
7. Secrets discovery — regex scanning em HTML + JS
8. Interesting files — robots.txt, .env, backup, sitemap, etc.
9. Subdomain discovery — CT logs + DNS + HTML/JS links
10. Scoring + recomendações + relatório

### ghostmirror bounty crawl

Executa apenas o headless crawler (sem pipeline completo):

```bash
ghostmirror bounty crawl --project <slug> --target https://example.com
```

### ghostmirror bounty js

Analisa bundles JavaScript do target:

```bash
ghostmirror bounty js --project <slug> --target https://example.com
```

### ghostmirror bounty apis

Exibe o inventário de APIs descobertas (requer scan anterior):

```bash
ghostmirror bounty apis --project <slug>
```

### ghostmirror bounty secrets

Exibe secrets encontrados (requer scan anterior):

```bash
ghostmirror bounty secrets --project <slug>
```

### ghostmirror bounty report

Exibe o relatório de bug bounty no console:

```bash
ghostmirror bounty report --project <slug>
```

---

## Módulos

### Headless Crawler (`headless_crawler.py`)

- Utiliza **Playwright** para navegação headless
- Intercepta requests XHR/fetch/XDomainRequest
- Extrai formulários HTML (`<form>`) com inputs, CSRF tokens
- Coleta rotas descobertas via links e navegação
- Respeita Scope Guard (max_pages, max_depth, timeout)
- Fallback: se Playwright não estiver disponível, retorna erro tratado

### Network Capture (`network_capture.py`)

- Ingesta requests capturados pelo Headless Crawler
- Filtra por escopo (apenas URLs do domínio alvo)
- Detecta candidatos a API (XHR/fetch com JSON)
- Classifica métodos HTTP e endpoints

### JS Bundle Analyzer (`js_bundle_analyzer.py`)

- Coleta URLs de JS de:
  - Perfil de web intelligence existente
  - Fallback: HTML fetch + regex `<script src>`
- Baixa cada bundle (com timeout de 15s)
- Detecta:
  - Source maps (`//# sourceMappingURL=`)
  - Secrets no JS (regex patterns)
  - Endpoints/URLs internos
  - Comentários sensíveis

### Sourcemap Analyzer (`sourcemap_analyzer.py`)

- Descobre source maps via convenção (`arquivo.js.map`)
- Baixa e parseia JSON do source map
- Extrai:
  - Lista de arquivos fonte originais
  - Endpoints/URLs nos sources
  - Comentários sensíveis

### API Discovery (`api_discovery.py`)

- Combina múltiplas fontes:
  - Network capture entries (requests XHR/fetch)
  - JS bundle endpoints
  - Sourcemap endpoints
  - Web intelligence endpoint inventory
- Deduplica por método + path
- Classifica por tipo (REST, GraphQL, WebSocket)

### Parameter Mining (`parameter_mining.py`)

- Extrai parâmetros de:
  - Formulários HTML (inputs hidden, CSRF tokens)
  - URLs de rotas (query strings)
  - JS bundles (strings com `?param=`)
- Deduplica e categoriza parâmetros

### Secrets Discovery (`secrets_discovery.py`)

- Scanner baseado em regex patterns:
  - Google Maps API keys (`AIza...`)
  - Generic API keys (alfanumérico longo)
  - Slack tokens
  - AWS keys
  - JWT tokens
  - Firebase URLs
  - S3 buckets
  - GitHub tokens
  - Stripe keys
  - Discord tokens
- Redação automática — original value nunca é armazenado
- Classificação por severidade (critical, high, medium, low)

### Interesting Files (`interesting_files.py`)

- Verifica existência de arquivos interessantes conhecidos:
  - `/robots.txt`
  - `/sitemap.xml`
  - `/.env`
  - `/backup/`
  - `/admin/`
  - `/security.txt`
  - `/crossdomain.xml`
  - `/.git/`
- Requisições HEAD/GET com rate limiting

### Subdomain Discovery (`subdomain_discovery.py`)

- Fontes de descoberta:
  - Certificate Transparency logs (crt.sh)
  - Links em HTML (`<a href>`)
  - URLs em JS bundles
- Resolução DNS via `socket.gethostbyname_ex`
- Deduplicação automática

### Scoring & Recommendations

- **Scoring**: calcula pontuação geral (0–100) e nível de risco
  - Baseado em: rotas, APIs, bundles, sourcemaps, secrets, interesting files, parâmetros
  - Oportunidades priorizadas por score individual
- **Recommendations**: gera recomendações acionáveis
  - Payment/business logic routes
  - Admin/dashboard routes
  - Exposed source maps
  - Secrets descobertos
  - APIs sem auth aparente

---

## Segurança

- **Scope Guard**: todas as operações respeitam o escopo definido em `scope.yaml`
- **Rate limiting**: 1 requisição/segundo entre requisições HTTP
- **Timeouts**: 30s por operação, 15s por download de bundle
- **Sem exploração**: nenhum payload destrutivo é enviado
- **Redação de secrets**: o valor original de secrets nunca é salvo em disco — apenas snippets redacionados
- **Playwright opcional**: se Playwright não estiver instalado, o headless crawler falha graciosamente sem crash

---

## Perfil de Configuração

Em `config/default.yaml`:

```yaml
bug_bounty:
  max_pages: 10
  max_depth: 2
  timeout: 30
  rate_limit_delay: 1.0
```

---

## Estrutura de Saída

```
projects/<slug>/
├── profiles/
│   ├── bug_bounty/
│   │   ├── api_inventory.json
│   │   ├── bug_bounty_report.json
│   │   ├── bug_bounty_opportunities.json
│   │   ├── headless_routes.json
│   │   ├── js_bundle_profile.json
│   │   ├── parameter_mining.json
│   │   ├── secrets_discovery.json
│   │   ├── sourcemap_profile.json
│   │   ├── subdomain_profile.json
│   │   └── interesting_files.json
│   └── web_intelligence/
│       └── js_intelligence.json
├── evidence/
│   └── bug_bounty/
│       ├── headless_routes.json
│       ├── network_capture.json
│       └── ...
└── findings/
    └── bug_bounty.json
```

---

## Relatório

O Bug Bounty Report (`BugBountyReport`) contém:

| Campo | Descrição |
|-------|-----------|
| `target` | URL alvo |
| `overall_score` | Pontuação geral (0–100) |
| `risk_level` | INFO / LOW / MEDIUM / HIGH / CRITICAL |
| `headless_routes` | Rotas descobertas pelo crawler |
| `api_inventory` | APIs descobertas consolidadas |
| `js_bundles` | Perfis de bundles JS |
| `sourcemap_findings` | Source maps encontrados |
| `secrets` | Secrets redacionados |
| `interesting_files` | Arquivos interessantes |
| `subdomains` | Subdomínios descobertos |
| `opportunities` | Oportunidades priorizadas |
| `recommendations` | Recomendações acionáveis |

---

## Testes

153 testes unitários cobrem todos os módulos (100% mocked, sem rede real):

```bash
pytest tests/test_bug_bounty_engine.py
pytest tests/test_headless_crawler.py
pytest tests/test_network_capture.py
pytest tests/test_js_bundle_analyzer.py
pytest tests/test_sourcemap_analyzer.py
pytest tests/test_api_discovery.py
pytest tests/test_parameter_mining.py
pytest tests/test_secrets_discovery.py
pytest tests/test_interesting_files.py
pytest tests/test_subdomain_discovery.py
pytest tests/test_recon_profiles.py
pytest tests/test_bug_bounty_reporting.py

# Todos juntos:
pytest tests/test_*.py -k "bug_bounty"
```
