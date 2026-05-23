# ADR-006: Severity rubric with deadline mapping

## Status

Accepted (since v0.1)

## Context

Posture findings need prioritization. Common approaches:

1. **CVSS-style numeric scores.** Industry-standard for vulnerabilities. Less natural for posture findings (CVSS assumes a vulnerability; posture findings often describe absence of a control).
2. **Heat-map severity (Critical / High / Medium / Low / Info).** Familiar but ambiguous on action timeframes.
3. **Deadline-anchored tiers.** "P1 = within 1 week" makes the operational consequence explicit.

## Decision

Adopt deadline-anchored tiers per SCHEMA.md:

| Severity | Meaning | Action window |
|---|---|---|
| P1 | Exposed identity / credential paths / missing critical authentication controls | Within 1 week |
| P2 | Defense-in-depth gaps, false-positive tuning required, missing monitoring | Within 30 days |
| P3 | Hygiene, transport security, optional posture improvements | Within 90 days |
| INFO | Posture context, no remediation needed | N/A |
| OUT_OF_SCOPE | Domain check not applicable | N/A |

Audit script authors assign severity based on the operator-impact rubric. When in doubt, favor more severe; operators can always downgrade in their own context.

## Consequences

**Positive:**
- Deadline-anchored framing forces honest assessment ("would I really fix this in 30 days?")
- Easier for operators to triage: P1 today, P2 backlog, P3 quarterly review
- Severity distribution in reports gives quick posture sense (lots of P1 = poor posture; lots of P3 = mature posture with hygiene work remaining)

**Negative:**
- "Within 1 week" / "within 30 days" are guidelines, not contracts — some organizations move faster, some slower
- INFO and OUT_OF_SCOPE inflate finding counts in reports (but solve a real problem: explicit confirmation vs ambiguous absence)

**Mitigations:**
- Report displays severity counts in executive summary so reader sees the distribution at a glance
- Ranked gap list groups by severity for clear prioritization
- Audit script authors document the rationale for severity in `description` field

## Why not CVSS

CVSS works for "if exploited, this vulnerability allows X." Posture findings are different shape: "the absence of control Y means class Z of attacks is harder to detect/prevent." CVSS would force awkward "exploitability=missing" workarounds.

Posture controls are categorical: either you have the control or you don't. Severity here is about HOW BAD IT IS that you don't have it — which is a function of (a) what attacks it would have prevented, (b) what other controls compensate. Both are operator-context-dependent. P1/P2/P3 with deadlines anchors this without false precision.
