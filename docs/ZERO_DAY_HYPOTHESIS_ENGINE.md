# Zero-Day Hypothesis Engine

## Visão Geral

O **Zero-Day Hypothesis Engine** é um módulo avançado do GhostMirror que **não encontra automaticamente zero-days**. Em vez disso, ele:

- Detecta anomalias e comportamentos inesperados
- Correlaciona sinais fracos entre múltiplas fontes
- Identifica superfícies pouco exploradas
- Gera hipóteses estruturadas de vulnerabilidades desconhecidas
- Prioriza pesquisa manual para pentesters e bug bounty hunters

> **Importante:** O sistema nunca afirma "Zero-Day Encontrado".  
> Ele sempre afirma: *"Zero-Day Hypothesis"*, *"Research Opportunity"* ou *"Potential Vulnerability Hypothesis"*.

## Arquitetura

```
ghostmirror/modules/zero_day/
├── __init__.py
├── engine.py              # Orquestrador principal
├── anomaly_engine.py      # Parte 1: Detecção de anomalias
├── differential_engine.py # Parte 2: Comparação de variantes seguras
├── hidden_functionality.py # Parte 3: Funcionalidades ocultas
├── business_logic_engine.py # Parte 4: Lógica de negócio
├── attack_chain_engine.py  # Parte 6: Cadeias de ataque
├── research_queue.py       # Parte 7/11: Fila de pesquisa
├── confidence_engine.py    # Parte 8: Engine de confiança
├── hypothesis_builder.py   # Parte 9: Construtor de hipóteses
├── scoring.py              # Parte 10: Pontuação
├── recommendations.py      # Recomendações
├── findings_mapper.py      # Mapeamento para findings
└── report_builder.py       # Construtor de relatórios

ghostmirror/models/
├── anomaly_signal.py       # Sinal de anomalia
├── anomaly.py              # Anomalia consolidada
├── anomaly_profile.py      # Perfil de anomalias
├── attack_chain.py         # Cadeia de ataque
├── research_opportunity.py # Oportunidade de pesquisa
├── zero_day_hypothesis.py  # Hipótese de zero-day
└── hypothesis_report.py    # Relatório consolidado
```

## Dependências

O Zero-Day Engine consome dados dos seguintes módulos:

| Módulo | Dados Consumidos |
|--------|-----------------|
| Web Intelligence | Endpoints, parâmetros, JS, auth |
| API Security | API inventory, JWT, GraphQL, objetos |
| Bug Bounty | Source maps, bundles, APIs ocultas |

## Pipeline

O `zero_day` é executado automaticamente nos perfis `standard`, `deep` e `bounty`:

```
standard: ... → api_security → zero_day → report
deep:     ... → api_security → zero_day → report
bounty:   ... → api_security → zero_day → report
```

## CLI

```bash
# Executar engine completo
ghostmirror zero-day run

# Exibir anomalias
ghostmirror zero-day anomalies

# Exibir attack chains
ghostmirror zero-day attack-chains

# Exibir hipóteses
ghostmirror zero-day hypotheses

# Exibir fila de pesquisa
ghostmirror zero-day research

# Via analyze
ghostmirror analyze zero-day
```

## Engines

### 1. Anomaly Engine
Detecta:
- Respostas inesperadas (status codes raros/incomuns)
- Headers incomuns (X-Debug, X-Internal, X-Test)
- Tamanhos inconsistentes (outliers estatísticos)
- Endpoints raros (admin, debug, swagger, .git, .env)
- Headers sensíveis expostos (API keys, auth tokens)

### 2. Differential Engine
Compara variantes seguras de endpoints:
- `/resource` vs `/resource/` vs `/resource?id=1`
- Detecta diferenças de status, tamanho e content-type
- Sem fuzzing, brute force ou exploração

### 3. Hidden Functionality Engine
Analisa JavaScript, source maps e bundles em busca de:
- Feature flags (`isAdmin`, `debugMode`, `featureFlag`)
- Debug routes (`/__webpack_hmr`, `/actuator`, `/heapdump`)
- Internal functions (`_private`, `_internal`, `_admin`)
- Source maps expostos

### 4. Business Logic Engine
Mapeia fluxos de negócio:
- Checkout, pagamentos, carrinho
- Cupons, descontos, promoções
- Carteiras, recompensas, transferências
- Assinaturas, faturas
- Autenticação/autorização

### 5. Attack Chain Engine
Correlaciona sinais entre módulos:
- JWT + Admin API + Sensitive Object → High Value Chain
- GraphQL + Introspection → GraphQL Research Opportunity
- Source Maps + Internal Routes → Hidden Functionality Chain

### 6. Confidence Engine
Níveis: LOW, MEDIUM, HIGH, VERY_HIGH

Baseado em:
- Quantidade de sinais
- Qualidade dos sinais (peso por tipo)
- Correlação entre fontes
- Consistência das evidências

### 7. Hypothesis Builder
Gera hipóteses estruturadas:
- Título e tipo
- Nível de confiança
- Sinais que compõem a hipótese
- Raciocínio detalhado
- Cenário de ataque potencial
- Recomendação de validação

### 8. Scoring (0-100)
Fatores:

| Fator | Peso |
|-------|------|
| Anomaly Score | 25% |
| Attack Chain Score | 25% |
| Hypothesis Score | 20% |
| Business Logic Score | 15% |
| Exposure Score | 10% |
| API/Web Score | 5% |

Classificação: 0–25 LOW, 26–50 MEDIUM, 51–75 HIGH, 76–100 CRITICAL

## Output

Os resultados são salvos em `profiles/zero_day/`:

| Arquivo | Conteúdo |
|---------|----------|
| `anomalies.json` | Anomalias detectadas |
| `differential_signals.json` | Sinais diferenciais |
| `hidden_functionality.json` | Hipóteses de funcionalidades ocultas |
| `business_logic_opportunities.json` | Oportunidades de lógica de negócio |
| `attack_chains.json` | Cadeias de ataque |
| `hypotheses.json` | Hipóteses de vulnerabilidade |
| `research_queue.json` | Fila de pesquisa priorizada |
| `recommendations.json` | Recomendações |
| `zero_day_report.json` | Relatório consolidado |

## Lab Validation

O engine é validado contra:

| Lab | Critérios |
|-----|-----------|
| Juice Shop | Business Logic + Hidden Functionality |
| DVWA | Authorization Opportunities |
| Vuln Demo | Attack Chains + Research Queue |

## Exemplo de Output

```
Zero-Day Hypothesis Engine — Complete
Overall Score: 72/100 (HIGH)
Total Signals: 14
Total Hypotheses: 5
Total Opportunities: 8
Total Attack Chains: 3
Research Queue Size: 16

Top Hypotheses:
  [VERY_HIGH] Source Maps Exposing Internal Application Structure
  [HIGH] Potential Feature Flags / Debug Controls in JavaScript
  [HIGH] JWT + Admin API + Sensitive Object Chain

Attack Chains:
  • JWT + Admin API + Sensitive Object Chain
  • GraphQL Introspection + Admin Objects Chain
  • Source Maps + Internal Routes Chain
```
