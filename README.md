# M365 Security Operations Toolkit

[![CI](https://github.com/ibondarenko1/m365-security-operations/actions/workflows/ci.yml/badge.svg)](https://github.com/ibondarenko1/m365-security-operations/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ibondarenko1/m365-security-operations?display_name=tag&color=blue)](https://github.com/ibondarenko1/m365-security-operations/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://learn.microsoft.com/en-us/powershell)
[![Mock mode](https://img.shields.io/badge/mock--mode-30%20second%20demo-brightgreen)](examples/run-mock.ps1)
[![Pester](https://img.shields.io/badge/Pester-114%20tests%20passing-success)](tests/)

A detect-and-remediate toolkit for solo defenders running Microsoft 365 + Cloudflare in small organizations. Audits five domains in one command, produces a single ranked report, and ships ready-to-deploy remediation artifacts mapped to NIST CSF 2.0, NIST 800-53, ISO 27001, and MITRE ATT&CK.

## Try it in 30 seconds (no Azure access needed)

```powershell
git clone https://github.com/ibondarenko1/m365-security-operations
cd m365-security-operations
./examples/run-mock.ps1
```

The mock run produces a complete sample report (30 findings across 5 domains) using bundled fixtures. Open `reports/<latest-timestamp>/report.md` to see what the toolkit actually produces.

See [`examples/sample-report.md`](examples/sample-report.md) for the same output rendered statically.

## Run against your tenant

```powershell
az login --tenant <your-tenant-id>
./run-audit.ps1 -TenantId <tenant-id> -SubscriptionId <sub-id> -Domain <yourdomain>
```

The script authenticates via your existing Azure CLI session, sweeps Sentinel, Defender for Office 365, Cloudflare DNS, Entra ID identity posture, and Defender for Cloud, then emits a markdown report under `reports/<timestamp>/report.md` ranking findings P1/P2/P3 with per-finding remediation links.

Add `-WorkspaceName <ws> -ResourceGroup <rg>` to include the Sentinel posture audit (Phase 4). Without these, Phase 4 is skipped.

---

## Who this is for

Solo IT/security generalists at small organizations, MSPs servicing M365 tenants, and security consultants doing tenant assessments. The toolkit assumes a Microsoft 365 tenant with Cloudflare DNS and an attached Azure subscription. It does not assume Defender for Endpoint, dedicated SOC tooling, or Entra ID P2 licensing — features that require those are flagged as "out of scope" in audit output, not silently skipped.

It is not for: large enterprises with mature CSPM tools, federal tenants with FedRAMP requirements (use [CISA ScubaGear](https://github.com/cisagov/ScubaGear) instead), or tenants where remediation requires multi-stakeholder change-management workflows.

---

## What it does versus what other tools do

| Tool | Approach |
|---|---|
| Microsoft Secure Score | Score + recommendations, no deploy artifacts |
| Defender Secure Score | Same, Defender-specific |
| CISA ScubaGear | Federal-grade audit, no remediation deliverables |
| Maester | M365 testing framework, no DNS or Sentinel coverage |
| M365DSC | Microsoft DSC configuration compliance, configuration-as-code |
| This toolkit | **Audit + ranked report + ready-to-deploy remediation artifacts per finding** |

The differentiator: every finding surfaced by the audit links to a specific deployable artifact (KQL rule, ARM template, Conditional Access policy JSON, DNS record, PowerShell remediation script). You don't have to research how to fix what was found.

---

## Domains covered

| Domain | What's audited | What gets deployed |
|---|---|---|
| **Sentinel detection engineering** | Workspace state, daily quota, retention, Sentinel onboarding, Analytics Rules count, Fusion state, Activity Log diagnostic setting | 5 MITRE-mapped Scheduled Analytics Rules (ARM), 10 KQL hunting drills |
| **Defender for Office 365** | Anti-phish, anti-spam, anti-malware, Safe Attachments, Safe Links, TenantAllowBlockList, DKIM signing per domain | Impersonation protection enroller, TenantAllowBlockList bulk-add, Strict Preset assigner, outbound spam alerter |
| **DNS + email authentication** | MX, SPF, DKIM selectors, DMARC, MTA-STS, TLS-RPT, BIMI, NS, Autodiscover | Cloudflare API deployers for MTA-STS + TLS-RPT, Cloudflare Worker for serving the MTA-STS policy file |
| **Identity hardening** | Conditional Access policies, authorization policy, directory role assignments, user count, sign-in log access | 6 Conditional Access policy JSONs (block legacy auth, require MFA admins, require MFA users, sign-in risk, user risk, compliant device for management portals) |
| **Defender for Cloud** | Pricing tier per plan, Secure Score, recommendation count by severity | Plan-tier upgrade ARM, recommendation triage methodology |

---

## Output

After running the orchestrator:

```
reports/2026-05-22T18-30-12/
├── dns.json                  Structured findings from DNS audit
├── identity.json              Structured findings from identity audit
├── defender-o365.json         Structured findings from email security audit
├── sentinel.json              Structured findings from Sentinel audit
├── defender-cloud.json        Structured findings from Defender for Cloud audit
└── report.md                  Aggregated markdown report
```

The markdown report contains:

1. **Executive summary** — total findings by severity, framework coverage percentage, top 3 P1 gaps
2. **Per-domain sections** — each finding with severity, framework controls, link to remediation artifact
3. **Consolidated ranked gap list** — P1 (within 1 week), P2 (within 30 days), P3 (within 90 days)
4. **Framework coverage matrix** — NIST CSF function coverage, NIST 800-53 control coverage, ISO 27001 Annex A coverage

See [`examples/sample-report.md`](examples/sample-report.md) for a complete sample output run against a hypothetical `example.com` tenant.

---

## Finding schema

All audit scripts emit findings conforming to a single schema (see [`SCHEMA.md`](SCHEMA.md)). A finding looks like:

```json
{
  "id": "IDENT-001",
  "severity": "P1",
  "title": "Zero Conditional Access policies",
  "description": "/identity/conditionalAccess/policies returned an empty array. No granular access control enforced beyond Security Defaults baseline.",
  "framework_controls": [
    "NIST.CSF.PR.AC-04",
    "NIST.CSF.PR.AC-07",
    "NIST.800-53.IA-2(1)",
    "NIST.800-53.IA-2(2)",
    "ISO27001.A.5.15",
    "ISO27001.A.5.17"
  ],
  "remediation_artifact": "04-identity-hardening/policies/",
  "remediation_steps": [
    "Review the 6 ready-to-deploy CA policy JSONs in 04-identity-hardening/policies/",
    "Replace <group-id-all-admins> and <group-id-all-users> placeholders with actual tenant group object IDs",
    "Deploy each in Report-only mode first via az rest --method PUT --uri https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --body @<file>.json",
    "Monitor 7-14 days via Insights & Reporting",
    "Switch state from 'enabledForReportingButNotEnforced' to 'enabled' after impact review"
  ]
}
```

Severity rubric:
- **P1** — exposed identity, exposed credential paths, missing critical authentication controls. Within 1 week.
- **P2** — defense-in-depth gaps, false-positive tuning required, missing monitoring. Within 30 days.
- **P3** — hygiene, transport security, brand trust, optional posture improvements. Within 90 days.

---

## Prerequisites

| Component | Minimum |
|---|---|
| Azure CLI | 2.86.0+ |
| PowerShell | 5.1 (Windows) or 7+ (cross-platform) |
| Logged in via `az login` | with read access to target subscription |
| Microsoft Graph permissions | `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All` (Security Reader directory role covers all three) |
| Cloudflare access | (only for DNS remediation phase) API token with `Zone.DNS.Edit` scope for target zone |
| Exchange Online PowerShell module | (only for Defender for O365 remediation phase) `Install-Module -Name ExchangeOnlineManagement` |

The audit phase is fully read-only and requires only `az login` + Graph read permissions. The remediation artifacts are gated behind explicit user invocation — running the orchestrator does not modify any tenant configuration.

---

## Quick start

```powershell
# 1. Clone
git clone https://github.com/ibondarenko1/m365-security-operations
cd m365-security-operations

# 2. Authenticate
az login --tenant <your-tenant-id>

# 3. Run audit (read-only)
./run-audit.ps1 -TenantId <tenant-id> -SubscriptionId <sub-id> -Domain <yourdomain>

# 4. Review the report
cat reports/<latest-timestamp>/report.md

# 5. Deploy remediations per the report's ranked gap list
#    Each P1/P2/P3 finding links to a specific artifact under the domain folder.
```

---

## Repository layout

```
m365-security-operations/
├── run-audit.ps1                                   Top-level orchestrator
├── Generate-Report.ps1                              Report aggregator
├── SCHEMA.md                                        Finding object schema
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .github/workflows/ci.yml                         JSON + KQL + PowerShell syntax CI
├── 01-sentinel-detection-engineering/
│   ├── README.md                                    Sentinel methodology + FP tuning patterns
│   ├── audit-sentinel.ps1                           Sentinel posture audit
│   ├── kql/                                          10 hunting query templates
│   └── analytics-rules/                              5 MITRE-mapped ARM templates
├── 02-defender-o365-policy/
│   ├── README.md
│   ├── audit-defender-o365.ps1
│   └── templates/                                    Exchange Online remediation scripts
├── 03-dns-email-auth/
│   ├── README.md
│   ├── audit-dns-posture.ps1
│   └── templates/                                    MTA-STS + TLS-RPT deploy templates
├── 04-identity-hardening/
│   ├── README.md
│   ├── audit-identity-posture.ps1
│   └── policies/                                     6 Conditional Access policy JSONs
├── 05-governance/
│   └── README.md                                    NIST CSF + 800-53 + ISO 27001 + MCSB mapping
└── examples/
    └── sample-report.md                             Full sample output for example.com
```

---

## Framework anchors

Every finding emitted by the toolkit is tagged with framework controls it satisfies. Framework references:

- NIST Cybersecurity Framework 2.0
- NIST SP 800-53 Rev. 5
- NIST SP 800-63B (Authentication and Lifecycle Management)
- NIST SP 800-177 Rev. 1 (Trustworthy Email)
- ISO/IEC 27001:2022
- MITRE ATT&CK
- Microsoft Cloud Security Benchmark
- RFC 7489 (DMARC), RFC 8460 (TLS-RPT), RFC 8461 (MTA-STS), RFC 8617 (ARC)

The Generate-Report output includes a framework coverage matrix showing which controls have at least one passing posture check, which have at least one open finding, and which are out of scope.

---

## Limitations

This toolkit is opinionated for small-org M365 + Cloudflare tenants. It does not handle:

- Multi-tenant deployments (use [CIPP](https://github.com/KelvinTegelaar/CIPP) for MSP multi-tenant work)
- On-premises Active Directory hybrid scenarios
- Endpoint detection and response (no Defender for Endpoint audit; flagged as out-of-scope in identity audit output)
- Microsoft 365 backup and recovery posture
- Vendor risk management workflows
- Federal compliance overlays (FedRAMP, CMMC, DFARS) — use ScubaGear

Findings related to these areas are emitted as `severity: "OUT_OF_SCOPE"` with an explanation, rather than silently absent.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New audit scripts must emit JSON findings per `SCHEMA.md`. New remediation artifacts must link to a parent finding ID and include framework control mapping. Pull requests welcome.

---

## License

MIT. See [`LICENSE`](LICENSE).
