# ADR-005: Framework anchors over operational specifics

## Status

Accepted (since v0.1)

## Context

Every finding can be described two ways:

1. **Operationally:** "Daily ingestion uncapped — set workspaceCapping.dailyQuotaGb to 0.5"
2. **Framework-anchored:** "Daily ingestion uncapped — violates NIST CSF ID.GV-04 (Cybersecurity risk management framework), ISO27001 A.5.30 (ICT readiness for business continuity)"

The first is immediately actionable. The second tells WHY beyond the technical specifics — and is what GRC stakeholders, auditors, and security architects read.

## Decision

Every finding emits both. The `description` field carries operational specifics. The `framework_controls` array carries the framework anchors using dot-notation per `SCHEMA.md`:

- `NIST.CSF.<FUNCTION>.<CATEGORY>` (e.g. `NIST.CSF.PR.AC-04`)
- `NIST.800-53.<CONTROL>` (e.g. `NIST.800-53.IA-2(1)`)
- `NIST.800-63B.<SECTION>`
- `NIST.800-177.<SECTION>`
- `ISO27001.<ANNEX-CONTROL>`
- `MITRE.<TACTIC>.<TECHNIQUE>`
- `MCSB.<DOMAIN>-<ID>`
- `RFC.<NUMBER>`

`Generate-Report.ps1` produces a framework coverage matrix using these anchors.

## Consequences

**Positive:**
- Audit output is GRC-platform-friendly (export findings → import into Vanta/Drata/Hyperproof control evidence)
- Auditors reading the output see immediate framework context
- Forces audit authors to think about WHY each finding matters at the framework level — increases content quality

**Negative:**
- Audit authors must do framework mapping research per check (~5-10 min per check)
- Multiple frameworks have overlapping controls — mapping isn't always 1:1 obvious
- Framework versions evolve (NIST CSF 1.1 → 2.0, NIST 800-53 Rev 4 → Rev 5) — risk of stale references

**Mitigations:**
- Each ADR sub-decision lists which framework version applies
- Framework version refresh is a documented v-bump event
- Audit authors can cite multiple controls per finding (encouraged)

## Alternatives considered

- **Operational-only.** Simpler authoring. Rejected: undermines the toolkit's value for GRC consumers and auditors.
- **Framework-only.** Less actionable. Rejected: operators need the implementation steps, not just the control reference.
- **Custom internal framework.** Tempting for simplicity. Rejected: defeats the purpose of speaking the language of recognized frameworks.
