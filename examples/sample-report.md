# Security Posture Report

Generated: 2026-05-22T18:30:12.0000000Z

Tenant: `00000000-0000-0000-0000-000000000000`
Subscription: `11111111-1111-1111-1111-111111111111`
Domain: `example.com`

---

## Executive summary

| Severity | Count | Action window |
|---|---|---|
| **P1** (immediate operational risk) | 3 | within 1 week |
| **P2** (defense-in-depth gap) | 6 | within 30 days |
| **P3** (hygiene / optional) | 5 | within 90 days |
| INFO (posture context) | 11 | - |
| OUT_OF_SCOPE | 1 | - |

### Top P1 findings

- **IDENT-001:** Zero Conditional Access policies
- **IDENT-004:** Excessive standing Global Administrators
- **SENT-002:** Microsoft Sentinel not onboarded

---

## DNS and Email Authentication

Audit script version: `1.0.0`. Schema version: `1.0.0`.

| ID | Severity | Title | Framework controls | Remediation |
|---|---|---|---|---|
| DNS-001 | INFO | MX record points to Microsoft 365 mail | - | manual |
| DNS-002 | INFO | SPF record configured with hard fail | - | manual |
| DNS-003 | INFO | DMARC policy at strictest level (p=reject) | - | manual |
| DNS-004 | INFO | DKIM selector1 CNAME configured | - | manual |
| DNS-005 | INFO | DKIM selector2 CNAME configured | - | manual |
| DNS-006 | P3 | MTA-STS not configured | NIST.CSF.PR.DS-02, RFC.8461, ISO27001.A.8.20 | [`03-dns-email-auth/templates/mta-sts-policy.txt`](03-dns-email-auth/templates/mta-sts-policy.txt) |
| DNS-007 | P3 | TLS-RPT not configured | NIST.CSF.DE.CM-04, RFC.8460, ISO27001.A.8.20 | [`03-dns-email-auth/templates/`](03-dns-email-auth/templates/) |
| DNS-008 | P3 | BIMI not configured | - | manual |

### Details

#### DNS-006: MTA-STS not configured

_Severity: **P3**_

MTA-STS instructs senders to require TLS when delivering to this domain. Without it, downgrade attacks on inbound mail TLS are possible.

**Remediation steps:**

1. Add TXT record at _mta-sts.example.com: v=STSv1; id=a3f9b27c
2. Set up HTTPS endpoint at mta-sts.example.com serving /.well-known/mta-sts.txt with policy content (see template).
3. Use Cloudflare Worker template at 03-dns-email-auth/templates/cloudflare-worker.js if hosting on Cloudflare.
4. Verify with https://aykira.io/mta-sts or similar MTA-STS validator.

---

## Identity Hardening

Audit script version: `1.0.0`. Schema version: `1.0.0`.

| ID | Severity | Title | Framework controls | Remediation |
|---|---|---|---|---|
| IDENT-001 | P1 | Zero Conditional Access policies | NIST.CSF.PR.AC-04, NIST.CSF.PR.AC-07, NIST.800-53.IA-2(1), NIST.800-53.IA-2(2), NIST.800-63B.AAL2, ISO27001.A.5.15, ISO27001.A.5.17 | [`04-identity-hardening/policies/`](04-identity-hardening/policies/) |
| IDENT-002 | P2 | Guest invitations allowed from any user | NIST.CSF.PR.AC-04, NIST.800-53.AC-3, ISO27001.A.5.15 | manual |
| IDENT-003 | P2 | Any user can register OAuth applications | NIST.CSF.PR.AC-04, NIST.800-53.AC-3, ISO27001.A.5.15 | manual |
| IDENT-004 | P1 | Excessive standing Global Administrators | NIST.CSF.PR.AC-04, NIST.CSF.PR.AC-06, NIST.800-53.AC-2, NIST.800-53.AC-6, ISO27001.A.5.18 | manual |
| IDENT-005 | P3 | Legacy MSOL PowerShell module not blocked | NIST.CSF.PR.AC-04, ISO27001.A.5.15 | manual |
| IDENT-006 | P2 | Sign-in log read access not granted | NIST.CSF.DE.CM-03, NIST.800-53.AU-6, ISO27001.A.5.28 | manual |

### Details

#### IDENT-001: Zero Conditional Access policies

_Severity: **P1**_

Microsoft Graph /identity/conditionalAccess/policies returned an empty array. No CA policies defined means every sign-in is evaluated against only the Security Defaults baseline. Granular controls (MFA enforcement, sign-in risk thresholds, device compliance, named-location blocks) are not in effect.

**Remediation steps:**

1. Review the 6 baseline CA policy JSONs in 04-identity-hardening/policies/.
2. Identify or create Entra security groups for all-users, all-admins. Note their object IDs.
3. Replace <group-id-all-users> and <group-id-all-admins> placeholders in each policy JSON.
4. Deploy each in Report-only mode first: az rest --method PUT --uri https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --body @<file>.json
5. Monitor 7-14 days via Insights & Reporting in Entra portal.
6. Switch state from enabledForReportingButNotEnforced to enabled after impact review.

#### IDENT-004: Excessive standing Global Administrators

_Severity: **P1**_

3 Global Administrator accounts. Microsoft's published guidance: 2-4 GA accounts total per tenant maximum, regardless of org size. Each GA account is a high-value compromise target.

**Remediation steps:**

1. Identify the actual admin owner. Keep them as primary GA.
2. Provision exactly one break-glass GA account: no MFA, complex password sealed in physical safe, IP-allowlisted, audit-logged on every sign-in.
3. For other GA-assigned users, switch to least-privilege roles via Privileged Identity Management.
4. Remove standing GA from non-essential accounts.

---

## Defender for Office 365 Policy

Audit script version: `1.0.0`. Schema version: `1.0.0`.

| ID | Severity | Title | Framework controls | Remediation |
|---|---|---|---|---|
| MAIL-001 | P2 | Anti-phish impersonation protection not enrolled | NIST.CSF.DE.AE-02, ISO27001.A.5.7 | [`02-defender-o365-policy/templates/enable-impersonation-protection.ps1`](02-defender-o365-policy/templates/enable-impersonation-protection.ps1) |
| MAIL-002 | P2 | Tenant Allow/Block List is empty | NIST.CSF.DE.AE-02, ISO27001.A.8.16 | [`02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1`](02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1) |
| MAIL-003 | INFO | DKIM enabled for example.com | - | manual |
| MAIL-004 | INFO | DKIM enabled for example.onmicrosoft.com | - | manual |
| MAIL-005 | P3 | Strict Preset Security Policy not applied | NIST.CSF.PR.AC-04, MCSB.IM-6 | [`02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1`](02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1) |

---

## Sentinel Detection Engineering

Audit script version: `1.0.0`. Schema version: `1.0.0`.

| ID | Severity | Title | Framework controls | Remediation |
|---|---|---|---|---|
| SENT-001 | INFO | Log Analytics workspace present | - | manual |
| SENT-002 | P1 | Microsoft Sentinel not onboarded | NIST.CSF.DE.AE-02, NIST.800-53.SI-4, ISO27001.A.5.25 | manual |
| SENT-003 | P2 | Few or no Analytics Rules deployed | NIST.CSF.DE.AE-02, NIST.800-53.SI-4, ISO27001.A.5.25 | [`01-sentinel-detection-engineering/analytics-rules/`](01-sentinel-detection-engineering/analytics-rules/) |
| SENT-004 | P2 | Activity Log not routed to Sentinel workspace | NIST.CSF.DE.CM-01, NIST.800-53.AU-2, ISO27001.A.8.16 | manual |

---

## Defender for Cloud Posture

Audit script version: `1.0.0`. Schema version: `1.0.0`.

| ID | Severity | Title | Framework controls | Remediation |
|---|---|---|---|---|
| MDC-001 | INFO | Defender for Cloud plans inventory | - | manual |
| MDC-002 | INFO | Secure Score not yet calculated | - | manual |

---

## Consolidated ranked gap list

### P1

- **IDENT-001:** Zero Conditional Access policies — see `04-identity-hardening/policies/`
- **IDENT-004:** Excessive standing Global Administrators
- **SENT-002:** Microsoft Sentinel not onboarded

### P2

- **IDENT-002:** Guest invitations allowed from any user
- **IDENT-003:** Any user can register OAuth applications
- **IDENT-006:** Sign-in log read access not granted
- **MAIL-001:** Anti-phish impersonation protection not enrolled — see `02-defender-o365-policy/templates/enable-impersonation-protection.ps1`
- **MAIL-002:** Tenant Allow/Block List is empty — see `02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1`
- **SENT-003:** Few or no Analytics Rules deployed — see `01-sentinel-detection-engineering/analytics-rules/`
- **SENT-004:** Activity Log not routed to Sentinel workspace

### P3

- **DNS-006:** MTA-STS not configured — see `03-dns-email-auth/templates/mta-sts-policy.txt`
- **DNS-007:** TLS-RPT not configured — see `03-dns-email-auth/templates/`
- **DNS-008:** BIMI not configured
- **IDENT-005:** Legacy MSOL PowerShell module not blocked
- **MAIL-005:** Strict Preset Security Policy not applied — see `02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1`

---

## Framework coverage matrix

| Framework | Controls touched | Open issues (P1/P2/P3) |
|---|---|---|
| **NIST.CSF** | 9 | 8 |
| **NIST.800-53** | 7 | 5 |
| **NIST.800-63B** | 1 | 1 |
| **ISO27001** | 7 | 7 |
| **RFC** | 2 | 2 |
| **MCSB** | 1 | 1 |

---

_This is a sample report demonstrating output format. Run `./run-audit.ps1` against your tenant for actual findings._
