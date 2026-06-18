# Security Policy

## Authorized Use Only

GhostMirror is an **internal pentest automation platform**. It is **not** a public
tool and must **only** be used against systems and assets covered by a formally
authorized engagement scope.

- **Never** use GhostMirror against systems you do not own or have explicit
  written permission to test.
- **Never** use GhostMirror for illegal, unauthorized, or malicious purposes.
- Each engagement must have a clearly defined `scope.yaml` that enumerates
  permitted targets and test categories. Intrusive categories are disabled by
  default.

## Reporting a Vulnerability

If you discover a security vulnerability in GhostMirror itself (e.g. a bug that
could lead to unintended data exposure or escalation):

1. **Do not** open a public GitHub Issue.
2. Send details to the internal security team.
3. Allow reasonable time for remediation before any disclosure.

## Disclosure Policy

- **Do not** paste real client reports, scan outputs, findings, or evidence into
  public issues, pull requests, or discussions.
- Test data used in public contexts must be anonymized (e.g. `example.com`,
  `test.local`).
- Screenshots or logs containing real target IPs, domains, or vulnerabilities
  must be redacted before sharing.

## Scope Enforcement

GhostMirror enforces scope at runtime via `ScopeGuard`:

- Targets not listed in `scope.yaml` are **blocked** from scanning.
- The scope file is validated by Pydantic before every scan.
- Out-of-scope attempts are logged to the audit trail.

## Data Retention

- Scan findings are stored per-project under `projects/<slug>/`.
- Logs are rotated and retained according to local policy.
- No telemetry, analytics, or external data exfiltration occurs.
