# Lab Mode — GhostMirror

## O que é o Lab Mode?

O Lab Mode é um subsistema isolado do GhostMirror que permite criar, gerenciar e escanear ambientes vulneráveis **controlados** rodando localmente via Docker.

Ele foi projetado para:

- **Treinar** — praticar segurança ofensiva em ambiente seguro
- **Validar scanners** — testar engines sem apontar para alvos reais
- **Demonstrar** — apresentar o GhostMirror sem riscos
- **Testar releases** — validar novas funcionalidades antes de uso em produção
- **Gerar benchmarks** — medir performance e cobertura das engines

---

## Arquitetura

```
┌──────────────────────────────────────────────┐
│             CLI: ghostmirror lab              │
│   list | start | stop | status | health      │
│   create-project | benchmark                  │
├──────────────────────────────────────────────┤
│            LabManager (manager.py)            │
│   Orquestra ciclo de vida dos laboratórios    │
├─────────────────┬────────────────────────────┤
│  LabCatalog     │   DockerRunner              │
│  (catalog.py)   │   (docker_runner.py)        │
│  4 labs         │   docker compose up/down    │
├─────────────────┼────────────────────────────┤
│  LabHealth      │   LabProjectFactory         │
│  (health.py)    │   (project_factory.py)      │
│  5 checks       │   Cria projetos lab=true    │
├─────────────────┴────────────────────────────┤
│            LabSafetyGuard                     │
│   Bloqueia targets públicos em lab=true       │
├──────────────────────────────────────────────┤
│            LabBenchmark                       │
│   (benchmark.py)                              │
│   Full-scan deep + métricas                   │
└──────────────────────────────────────────────┘
```

---

## Laboratórios Suportados

| ID | Nome | Porta | Dificuldade |
|----|------|-------|-------------|
| `juice-shop` | OWASP Juice Shop | 3000 | medium |
| `dvwa` | Damn Vulnerable Web Application | 80 | easy |
| `webgoat` | OWASP WebGoat | 8080 | medium |
| `vuln-demo` | GhostMirror Vuln Demo | 8000 | beginner |

---

## Pré-requisitos

- Docker Engine instalado e rodando
- Docker Compose (v2, incluído no Docker Desktop)

Para verificar:

```bash
docker --version
docker compose version
```

---

## Comandos CLI

### Listar laboratórios disponíveis

```bash
ghostmirror lab list
```

Exibe nome, ID, dificuldade, porta e URL de cada laboratório.

### Iniciar um laboratório

```bash
ghostmirror lab start juice-shop
```

Executa `docker compose -f labs/docker-compose.juice-shop.yml up -d` e valida se o container subiu.

### Parar um laboratório

```bash
ghostmirror lab stop juice-shop
```

Executa `docker compose -f labs/docker-compose.juice-shop.yml down`.

### Status de todos os laboratórios

```bash
ghostmirror lab status
```

Mostra quais laboratórios estão rodando ou parados.

### Health check de 5 pontos

```bash
ghostmirror lab health juice-shop
```

Verifica:
1. Docker disponível
2. Arquivo compose existe
3. Container rodando
4. Porta respondendo
5. URL acessível

### Criar projeto para laboratório

```bash
ghostmirror lab create-project juice-shop
```

Cria `projects/lab-juice-shop/` com:

```
scope.yaml:
  project:
    client: GhostMirror Lab
    name: OWASP Juice Shop Lab
    lab: true
  targets:
    domains: []
    urls:
      - http://localhost:3000
    ips:
      - 127.0.0.1
  allowed_tests:
    destructive_tests: false
    ssl_scan: false
    ...
```

### Rodar benchmark

```bash
ghostmirror lab benchmark juice-shop
```

Fluxo:
1. Cria projeto lab se não existir
2. Executa `full-scan --profile deep`
3. Coleta duração e findings por step
4. Salva em `projects/lab-juice-shop/benchmarks/lab_benchmark.json`

### Exemplo de fluxo completo

```bash
# 1. Listar labs
ghostmirror lab list

# 2. Iniciar ambiente
ghostmirror lab start juice-shop

# 3. Verificar saúde
ghostmirror lab health juice-shop

# 4. Criar projeto lab
ghostmirror lab create-project juice-shop

# 5. Executar scan completo
ghostmirror full-scan --project lab-juice-shop --profile deep

# 6. Parar ambiente
ghostmirror lab stop juice-shop
```

---

## Safety Guard

O **LabSafetyGuard** é acionado automaticamente em projetos com `lab: true`.

### Regras

- **Permite apenas:**
  - `localhost`
  - `127.0.0.1`
  - `::1`
  - `host.docker.internal`
  - IPs privados RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`)

- **Bloqueia:**
  - Domínios públicos (ex: `example.com`)
  - IPs públicos (ex: `8.8.8.8`)
  - URLs apontando para hosts públicos

Se um scan tentar usar um target fora desses limites, o GhostMirror levanta `LabSafetyViolation` e aborta a operação.

---

## Lab Project (scope.yaml)

Exemplo do arquivo de escopo gerado automaticamente:

```yaml
project:
  client: GhostMirror Lab
  name: OWASP Juice Shop Lab
  lab: true
targets:
  domains: []
  urls:
    - http://localhost:3000
  ips:
    - 127.0.0.1
allowed_tests:
  recon: true
  ssl_scan: false
  web_scan: true
  port_scan: true
  fingerprint: true
  technology_intelligence: true
  cve_intelligence: true
  nuclei: true
  owasp: true
  payload_validation: true
  destructive_tests: false
```

---

## Relatórios

Projetos lab geram relatórios com o badge **LAB TARGET** no cabeçalho, tanto em HTML quanto em Markdown, para diferenciar claramente de avaliações reais.

```
# GHOSTMIRROR SECURITY ASSESSMENT

> 🧪 LAB TARGET — Ambiente Controlado (GhostMirror Lab Mode)

- Projeto: lab-juice-shop
...
```

---

## Benchmark

O comando `benchmark` executa um `full-scan --profile deep` e salva os resultados em:

```
projects/lab-<id>/benchmarks/lab_benchmark.json
```

Estrutura do JSON:

```json
{
  "lab_id": "juice-shop",
  "project_slug": "lab-juice-shop",
  "profile": "deep",
  "total_duration_seconds": 45.32,
  "total_findings": 28,
  "steps": [
    { "step_name": "headers", "duration_seconds": 1.2, "findings_count": 3 },
    { "step_name": "ssl", "duration_seconds": 0.8, "findings_count": 0 },
    ...
  ]
}
```

---

## GhostMirror Vuln Demo

O laboratório `vuln-demo` é um ambiente FastAPI proprietário com endpoints seguros para validação de scanners.

| Endpoint | Propósito |
|----------|-----------|
| `/` | Página inicial |
| `/admin` | Indicador de admin exposto (fake) |
| `/login` | Formulário de login (sem auth real) |
| `/search?q=` | Teste de reflection segura |
| `/redirect?url=` | Teste de open redirect seguro |
| `/debug` | Indicador de debug (seguro) |
| `/robots.txt` | Robots.txt padrão |
| `/sitemap.xml` | Sitemap.xml padrão |
| `/security.txt` | Security.txt de contato |
| `/form` | Formulário HTML |

**Nenhuma vulnerabilidade real destrutiva está presente.**

---

## Limitações

- Requer Docker local
- Não funciona em ambientes sem Docker (CI por padrão não sobe containers)
- Laboratórios rodam apenas em `localhost`
- Benchmarks dependem dos scanners estarem funcionando
- O Vuln Demo não substitui laboratórios reais como Juice Shop

---

## Segurança

- Todo lab project tem `lab: true` e `destructive_tests: false`
- Safety Guard impede scans contra domínios/IPs públicos
- Relatórios são marcados como LAB TARGET
- Projetos lab são isolados de projetos de clientes reais
- Containeres rodam em rede bridge padrão do Docker (isolados)
