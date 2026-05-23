# Finding Schema

All audit scripts emit findings as a JSON array conforming to this schema. The orchestrator (`run-audit.ps1`) and report aggregator (`Generate-Report.ps1`) consume findings via this schema. New audit scripts and contributors must produce output matching this contract.

---

## Top-level structure

Each audit script writes a single JSON file to `reports/<timestamp>/<phase>.json`:

```json
{
  "phase": "string",
  "phase_display_name": "string",
  "tenant_id": "string",
  "subscription_id": "string",
  "domain": "string",
  "timestamp_utc": "ISO 8601 datetime",
  "audit_script_version": "semver string",
  "findings": [ /* array of Finding objects */ ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `phase` | string | yes | Short phase identifier matching domain folder name without ordinal prefix (e.g. `dns-email-auth`, `identity-hardening`) |
| `phase_display_name` | string | yes | Human-readable phase name shown in report headings (e.g. "DNS and Email Authentication") |
| `tenant_id` | string | yes | Microsoft Entra ID tenant ID. Used by the report aggregator for cross-phase context. |
| `subscription_id` | string | yes | Azure subscription ID (or `null` if not applicable to phase) |
| `domain` | string | yes | Primary domain audited (or `null` if not applicable to phase) |
| `timestamp_utc` | string | yes | ISO 8601 datetime in UTC of when the audit ran |
| `audit_script_version` | string | yes | Semver of the audit script (e.g. `"1.0.0"`) for traceability |
| `findings` | array | yes | Array of Finding objects (may be empty if no gaps detected) |

---

## Finding object

Each gap or noteworthy observation is a Finding:

```json
{
  "id": "string",
  "severity": "P1 | P2 | P3 | INFO | OUT_OF_SCOPE",
  "title": "string",
  "description": "string",
  "framework_controls": ["string", "..."],
  "remediation_artifact": "string | null",
  "remediation_steps": ["string", "..."],
  "evidence": { /* optional phase-specific raw data */ }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable identifier: `<PHASE_PREFIX>-<NNN>`. Phase prefixes: `DNS`, `IDENT`, `MAIL`, `SENT`, `MDC`. Numbering: zero-padded three digits within phase. Example: `IDENT-001`. |
| `severity` | enum | yes | One of `P1`, `P2`, `P3`, `INFO`, `OUT_OF_SCOPE`. See severity rubric below. |
| `title` | string | yes | One-sentence summary suitable for a report table row. Max 80 chars. |
| `description` | string | yes | Multi-sentence explanation of what was detected, what it observed, and why it matters. |
| `framework_controls` | array of strings | yes | Framework control identifiers using dot-notation: `<FRAMEWORK>.<CATEGORY>.<CONTROL>`. See framework control naming below. Empty array allowed for INFO findings. |
| `remediation_artifact` | string or null | yes | Path relative to repo root pointing to a deployable artifact (e.g. `04-identity-hardening/policies/require-mfa-all-admins.json`). `null` when remediation is manual or out of scope. |
| `remediation_steps` | array of strings | yes | Ordered actionable steps for remediation. Each step is one sentence; full step-by-step procedure. May be empty for INFO findings. |
| `documentation_url` | string or null | yes (since v0.3) | Authoritative external link explaining the underlying control or vulnerability (Microsoft Learn, NIST publication, RFC, vendor docs). `null` when no canonical reference applies. |
| `evidence` | object | no | Optional phase-specific data dump for debugging or for the report aggregator to reference. Schema is phase-defined. |

---

## Severity rubric

| Severity | Meaning | Remediation deadline |
|---|---|---|
| **P1** | Exposed identity, credential paths, missing critical authentication controls. Immediate operational risk. | Within 1 week |
| **P2** | Defense-in-depth gaps, false-positive tuning required, missing monitoring or alerting. Substantial risk reduction. | Within 30 days |
| **P3** | Hygiene, transport security, brand trust, optional posture improvements. Quality bar. | Within 90 days |
| **INFO** | Informational observation, no remediation needed. Used for posture context (e.g. "DKIM Valid and Enabled"). | N/A |
| **OUT_OF_SCOPE** | Domain check not applicable to this tenant. Documented for completeness so absence isn't ambiguous. | N/A |

Severity assignment is the responsibility of the audit script author. When in doubt, favor more severe — recipients can always downgrade in their own context.

---

## Framework control naming convention

All framework controls use dot-notation prefixes for parsing in `Generate-Report.ps1`:

| Prefix | Framework |
|---|---|
| `NIST.CSF.<FUNCTION>.<CATEGORY>` | NIST Cybersecurity Framework 2.0 (e.g. `NIST.CSF.PR.AC-04`) |
| `NIST.800-53.<CONTROL>` | NIST SP 800-53 Rev. 5 (e.g. `NIST.800-53.IA-2(1)`) |
| `NIST.800-63B.<SECTION>` | NIST SP 800-63B (e.g. `NIST.800-63B.AAL2`) |
| `NIST.800-177.<SECTION>` | NIST SP 800-177 Rev. 1 (e.g. `NIST.800-177.Section-4.6`) |
| `ISO27001.<ANNEX-CONTROL>` | ISO/IEC 27001:2022 Annex A (e.g. `ISO27001.A.5.15`) |
| `MITRE.<TACTIC>.<TECHNIQUE>` | MITRE ATT&CK (e.g. `MITRE.Persistence.T1098`) |
| `MCSB.<DOMAIN>-<ID>` | Microsoft Cloud Security Benchmark (e.g. `MCSB.IM-6`) |
| `RFC.<NUMBER>` | IETF RFC (e.g. `RFC.7489`) |

If a finding maps to multiple frameworks (typical), list all applicable controls. The report aggregator uses these for the framework coverage matrix.

---

## Example finding

```json
{
  "id": "IDENT-001",
  "severity": "P1",
  "title": "Zero Conditional Access policies",
  "description": "Microsoft Graph /identity/conditionalAccess/policies returned an empty value array. No CA policies defined means every sign-in is evaluated against only the Security Defaults baseline. Granular controls (MFA enforcement, sign-in risk thresholds, device compliance, named-location blocks) are not in effect.",
  "framework_controls": [
    "NIST.CSF.PR.AC-04",
    "NIST.CSF.PR.AC-07",
    "NIST.800-53.IA-2(1)",
    "NIST.800-53.IA-2(2)",
    "NIST.800-63B.AAL2",
    "ISO27001.A.5.15",
    "ISO27001.A.5.17"
  ],
  "remediation_artifact": "04-identity-hardening/policies/",
  "remediation_steps": [
    "Review the 6 baseline CA policy JSONs in 04-identity-hardening/policies/.",
    "Identify or create Entra security groups for all-users, all-admins, all-guests. Note their object IDs.",
    "Replace <group-id-all-users> and <group-id-all-admins> placeholders in each policy JSON with actual IDs.",
    "Deploy each in Report-only mode first: az rest --method PUT --uri https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --body @<file>.json",
    "Monitor 7-14 days via Insights & Reporting in Entra portal.",
    "Switch state from enabledForReportingButNotEnforced to enabled after impact review."
  ],
  "evidence": {
    "policy_count": 0,
    "graph_endpoint": "/identity/conditionalAccess/policies",
    "queried_at_utc": "2026-05-22T18:30:12Z"
  }
}
```

---

## Schema version

This document is `SCHEMA.md` version **1.0.0**. Breaking schema changes will be flagged in CHANGELOG.md and the `audit_script_version` field bumped to a new major version. Audit scripts and the report aggregator must agree on schema version; mixed versions in a single `reports/<timestamp>/` directory are not supported.
