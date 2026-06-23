# Security Policy

## Authorized Use Only

GhostMirror is an **offensive security intelligence platform**. It must **only** be used against systems and assets you own or have explicit written authorization to test.

Unauthorized use of GhostMirror, or any tool within it, to access, scan, or attack systems without permission is **illegal** and violates this policy.

- **Never** use GhostMirror against systems you do not own or have explicit written permission to test.
- **Never** use GhostMirror for illegal, unauthorized, or malicious purposes.
- **Never** brute force, DoS, credential stuffing, data exfiltration, or any destructive action without explicit scope authorization.

## Scope Rules

- Every project requires a validated `scope.yaml` enumerating permitted targets and test categories.
- Intrusive and destructive categories are disabled by default and must be explicitly opted into.
- Targets not listed in scope are **blocked** at runtime by `ScopeGuard`.
- Out-of-scope attempts are logged to the audit trail.

## Prohibited Usage

The following are strictly prohibited:

- Attacking third-party systems without authorization
- Brute force attacks
- Denial of Service (DoS) attacks
- Credential stuffing
- Unauthorized access to any system or data
- Data exfiltration
- Any activity that violates applicable laws

## Vulnerability Reporting

If you discover a security vulnerability in GhostMirror itself (a bug that could lead to unintended data exposure, privilege escalation, or code execution):

1. **Do not** open a public GitHub Issue.
2. Open a **private security advisory** on GitHub or contact the maintainers directly.
3. Allow reasonable time for remediation before any disclosure.

## Safe Disclosure

- **Do not** paste real client reports, scan outputs, findings, or evidence into public issues, pull requests, or discussions.
- Test data used in public contexts must be anonymized (e.g. `example.com`, `test.local`).
- Screenshots or logs containing real target IPs, domains, or vulnerabilities must be redacted before sharing.

## No Warranty

GhostMirror is provided "AS IS", without warranty of any kind. The user assumes all responsibility for compliance with applicable laws and for any consequences of using this platform.

## Contact

To report a security issue, open a **private security advisory** on GitHub at:
https://github.com/your-org/ghostmirror/security/advisories/new
