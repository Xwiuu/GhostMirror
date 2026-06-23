---
name: Security Research / Zero-Day Hypothesis
about: Submit a structured security research hypothesis or zero-day finding for GhostMirror
title: "[RESEARCH] "
labels: research
assignees: ""
---

## Authorized Use Confirmation

- [ ] I confirm this submission does **not** contain real client data, scan outputs, or unauthorized target information.
- [ ] I confirm this research was conducted exclusively on authorized targets.

## Hypothesis Title

A concise title summarizing the security hypothesis.

## Research Context

- **Target type**: [Web Application / API / Infrastructure / Mobile / Other]
- **Module(s) used**: [recon / ssl / headers / nmap / fingerprint / cve / web / api / bounty / zero-day / attack-chain / pentester-assistant]
- **Project**: [anonymized project slug]

## Signals Observed

Describe the signals, anomalies, or patterns that triggered this hypothesis.

## Hypothesis Details

```yaml
confidence: 0-100
type: [vulnerability / logic-flaw / misconfiguration / design-weakness / unknown]
vectors:
  - vector: description
    evidence: finding_id
```

## Attack Chain (if applicable)

```
Step 1: ...
Step 2: ...
...
```

## Recommended Validation

Steps to confirm or refute this hypothesis:

1. ...
2. ...

## Tests Run

- [ ] `pytest` passes
- [ ] Research was conducted within authorized scope

## Security Impact

If confirmed, what would be the potential impact?

- [ ] Low
- [ ] Medium
- [ ] High
- [ ] Critical
