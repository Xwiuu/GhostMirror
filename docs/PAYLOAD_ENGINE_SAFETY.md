# Safe Payload Engine

## O que é

O Safe Payload Engine é um framework para registrar, organizar e executar **payloads seguros e não destrutivos** com o objetivo de validar superfícies de risco em alvos autorizados.

O foco é **detecção de indicadores**, não exploração.

## O que é Permitido

- Payloads passivos (apenas observação)
- Payloads reflexivos seguros (detectar se o input é refletido na resposta)
- Probes não destrutivos (sem modificar dados ou estado)
- Validação de superfície (identificar pontos de entrada)
- Comparação de resposta (baseline vs probe)
- Captura de evidência sanitizada (sem corpos completos)
- Dry-run (listar payloads sem executar)
- Rate limit (controle de taxa)
- Timeout (limite de tempo por request)
- Confirmação manual (para payloads sensíveis)

## O que é Bloqueado

- **Brute force**: qualquer tentativa de adivinhação de credenciais
- **DoS/DDoS**: tentativas de sobrecarregar o alvo
- **Credential stuffing**: reuso de credenciais vazadas
- **Exploit automático**: execução de exploits reais
- **Shell/Reverse shell**: qualquer tentativa de acesso interativo
- **File write**: escrita de arquivos no servidor
- **File deletion**: remoção de arquivos
- **Database dump**: extração de dados de banco
- **Bypass agressivo**: contorno de controles de segurança
- **Privilege escalation**: escalonamento de privilégio
- **Payloads destrutivos**: qualquer payload que modifique estado
- **Exfiltração**: extração de dados sensíveis

## Safety Levels

| Nível | Descrição | Exemplo |
|---|---|---|
| `PASSIVE` | Apenas observação, sem expectativa de reflexão | SSRF surface probe |
| `SAFE_REFLECTION` | Detecção de reflexão no body | `<script>alert(1)</script>` |
| `SAFE_ERROR_TRIGGER` | Detecção de mensagens de erro | `'` (SQL error) |
| `MANUAL_CONFIRMATION_REQUIRED` | Requer confirmação via CLI | Payloads sensíveis |
| `BLOCKED` | Bloqueado permanentemente | N/D |

## Categorias de Payload

| Categoria | Descrição | Payloads |
|---|---|---|
| `XSS_REFLECTION` | Detecta reflexão de input HTML/JS | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| `SQL_ERROR_INDICATOR` | Detecta mensagens de erro SQL | `'`, `"`, `)` |
| `OPEN_REDIRECT_INDICATOR` | Detecta redirecionamento aberto | `https://ghostmirror.invalid/` |
| `SSRF_SURFACE_INDICATOR` | Detecta superfície SSRF | `http://127.0.0.1/` |
| `PATH_TRAVERSAL_INDICATOR` | Detecta path traversal | `../ghostmirror_probe` |
| `HEADER_INJECTION_INDICATOR` | Detecta injeção de header | `%0d%0aX-GhostMirror-Probe: 1` |
| `TEMPLATE_INJECTION_INDICATOR` | Detecta injeção de template | `{{7*7}}` |

## Exemplos Seguros

```bash
# Dry-run: listar payloads sem executar
ghostmirror scan payloads --project acme --target https://example.com --dry-run

# Executar apenas payloads XSS reflection
ghostmirror scan payloads --project acme --target https://example.com --category XSS_REFLECTION

# Executar com confirmação para payloads sensíveis
ghostmirror scan payloads --project acme --target https://example.com --confirm-sensitive

# Especificar parâmetro alvo
ghostmirror scan payloads --project acme --target https://example.com --parameter search
```

## Modo Dry-Run

O dry-run lista todos os payloads que seriam executados sem realizar nenhum request HTTP.

```bash
ghostmirror scan payloads --project acme --target https://example.com --dry-run
```

Saída esperada:

```
SAFE PAYLOAD VALIDATION COMPLETE

Target: https://example.com

Dry Run: Sim
Payloads Registered: 20
Payloads Executed: 0
Payloads Blocked: 0
Categories Tested: 7
Findings Generated: 0
```

## Confirmação Manual

Payloads com `requires_confirmation=True` exigem confirmação explícita:

```bash
ghostmirror scan payloads --project acme --target https://example.com --confirm-sensitive
```

## Rate Limiter

- Máximo de **2 requests por segundo**
- Máximo de **25 payloads por alvo**
- Configurável via código

## Política de Evidências

- Corpos de resposta são **sanitizados** (removendo tokens, secrets, sessions)
- Corpos são **truncados** em 500 caracteres
- Evidências são salvas em `evidence/payloads/`
- Nenhum body completo é armazenado por padrão
- Sanitização inclui: tokens, API keys, secrets, sessions, hashes longos

## Arquivos de Saída

| Arquivo | Descrição |
|---|---|
| `findings/payload_findings.json` | Findings gerados |
| `profiles/payload_profile.json` | Perfil consolidado do scan |
| `evidence/payloads/payload_results.json` | Resultados brutos |
| `evidence/payloads/sanitized_evidence.json` | Evidências sanitizadas |

## Integração com OWASP

O Payload Engine consome evidências do OWASP Engine (`evidence/owasp/forms.json`, `evidence/owasp/enumeration.json`) para identificar automaticamente parâmetros e superfícies de teste.

- **A03 (Injection Indicators)**: XSS_REFLECTION, SQL_ERROR_INDICATOR, TEMPLATE_INJECTION_INDICATOR
- **A10 (SSRF Indicators)**: SSRF_SURFACE_INDICATOR (dry-run por padrão)
- **A01 (Broken Access Control)**: OPEN_REDIRECT_INDICATOR, PATH_TRAVERSAL_INDICATOR

## Pipeline de Scan

- **LITE**: não executa payloads
- **STANDARD**: dry-run apenas
- **DEEP**: executa payloads seguros automaticamente (categorias sensíveis ainda exigem confirmação)

## Health Check

```bash
ghostmirror doctor
# Payload Registry [✓] (20 payloads)
# Payload Safety Policy [✓]

ghostmirror health-check
# PayloadReg ..... OK
```
