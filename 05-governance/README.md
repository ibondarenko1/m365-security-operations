# Governance Mapping

NIST CSF 2.0, NIST SP 800-53, and ISO 27001 control mapping for the four operational domains (Sentinel detection engineering, Defender for Office 365 policy, DNS + email auth, Identity hardening). Plus Microsoft Cloud Security Benchmark cross-reference where the org runs on Azure.

This document is the artifact that demonstrates governance maturity — it shows which framework controls are addressed by which operational artifact, and where the gaps are.

---

## NIST CSF 2.0 — function coverage

| Function | Category | What's addressed | Where |
|---|---|---|---|
| **IDENTIFY** | ID.AM-01 (Hardware inventory) | Not applicable (no managed endpoints) | — |
| | ID.AM-02 (Software inventory) | Defender for Cloud asset graph (ExposureGraphNodes) | 01-sentinel-detection-engineering/kql/10 |
| | ID.AM-05 (Resources prioritized) | Admin-role review | 04-identity-hardening |
| | ID.RA-01 (Vulnerabilities identified) | Defender for Cloud recommendations | (deferred — Defender Free tier limits depth) |
| **PROTECT** | PR.AC-01 (Identities and credentials managed) | Entra ID user lifecycle, MFA enrollment | 04-identity-hardening |
| | PR.AC-04 (Access permissions managed) | Conditional Access library, PIM activation, Preset policy assignment by user group | 04-identity-hardening, 02-defender-o365-policy |
| | PR.AC-06 (Identities proofed) | Authentication strength policy, FIDO2/WHfB requirement for admins | 04-identity-hardening |
| | PR.AC-07 (Users authenticated) | MFA enforcement via Conditional Access | 04-identity-hardening |
| | PR.DS-02 (Data-in-transit protected) | DKIM signing, DMARC enforcement, MTA-STS (pending) | 03-dns-email-auth, 02-defender-o365-policy |
| | PR.PT-01 (Removable media protected) | Not applicable (no managed endpoints) | — |
| **DETECT** | DE.AE-02 (Adverse events analyzed) | 5 Scheduled Analytics Rules + Fusion + anti-phish impersonation | 01-sentinel-detection-engineering, 02-defender-o365-policy |
| | DE.AE-03 (Event data aggregated and correlated) | Sentinel workspace + Activity Log diagnostic setting + outbound spam alerting | 01-sentinel-detection-engineering, 02-defender-o365-policy |
| | DE.CM-01 (Networks and network services monitored) | Activity Log → Sentinel | 01-sentinel-detection-engineering |
| | DE.CM-03 (Personnel activity monitored) | Sign-in logs (pending access grant) | 04-identity-hardening |
| | DE.CM-04 (Malicious activity detected) | Defender XDR threat-type classification, TLS-RPT downgrade detection (pending) | 01-sentinel-detection-engineering, 03-dns-email-auth |
| **RESPOND** | RS.AN-01 (Incidents investigated) | Sentinel Incidents queue + KQL hunting library | 01-sentinel-detection-engineering |
| | RS.MI-02 (Incidents mitigated) | TenantAllowBlockList tuning loop | 02-defender-o365-policy |
| **RECOVER** | RC.RP-01 (Recovery plan executed) | Not in scope of this engagement (M365 retention defaults apply) | — |

---

## NIST SP 800-53 — control coverage

| Control family | Control | Component |
|---|---|---|
| AC (Access Control) | AC-2 (Account Management) | Entra user audit, role assignments |
| | AC-3 (Access Enforcement) | Authorization policy tightening, Conditional Access |
| | AC-6 (Least Privilege) | PIM, role reduction |
| AU (Audit and Accountability) | AU-2 (Event Logging) | Activity Log → AzureActivity |
| | AU-6 (Audit Review, Analysis, Reporting) | KQL hunting library, sign-in logs |
| IA (Identification and Authentication) | IA-2(1) (Network Access to Privileged Accounts) | MFA for admins via Conditional Access |
| | IA-2(2) (Network Access to Non-privileged Accounts) | MFA for all users via Conditional Access |
| SI (System and Information Integrity) | SI-3 (Malicious Code Protection) | Anti-malware policy, Safe Attachments |
| | SI-4 (System Monitoring) | Sentinel as SIEM |
| | SI-8 (Spam Protection) | Anti-spam policy stack |

---

## ISO 27001:2022 — Annex A coverage

| Control | Subject | Component |
|---|---|---|
| A.5.7 | Threat intelligence | Anti-phish impersonation enlistment, Defender XDR feeds |
| A.5.15 | Access control | Conditional Access policy framework |
| A.5.17 | Authentication information | MFA enforcement, password policies |
| A.5.18 | Access rights | PIM elevation, role audit |
| A.5.25 | Assessment and decision on information security events | Sentinel Analytics Rules + Fusion |
| A.5.28 | Collection of evidence | Activity Log retention, sign-in log access |
| A.8.7 | Protection against malware | Anti-malware policy, Safe Attachments |
| A.8.16 | Monitoring activities | TenantAllowBlockList tuning loop, KQL hunting |
| A.8.20 | Networks security | TLS enforcement (MTA-STS pending) |

---

## Microsoft Cloud Security Benchmark — cross-reference

Where the tenant has Azure workloads, the following MCSB controls apply:

| MCSB Control | Component |
|---|---|
| IM-1 (Use centralized identity and authentication system) | Entra ID as IdP, no other auth systems |
| IM-3 (Manage application identities securely) | Service principal lifecycle (workload identity audit not yet completed) |
| IM-6 (Use strong authentication controls) | Conditional Access + Strict Preset policy |
| IM-7 (Restrict resource access based on conditions) | Conditional Access |
| LT-1 (Enable threat detection capabilities) | Sentinel + Defender XDR analytics |
| LT-3 (Enable logging for security investigation) | Activity Log → Sentinel |
| LT-4 (Enable network logging for security investigation) | NSG flow logs (not deployed — no Azure workloads with vnets) |

---

## Posture-gap summary (consolidated from all 4 domains)

Ordered by remediation priority. Each gap has a NIST CSF function category and recommended sequencing.

| # | Gap | Domain | Function | Priority |
|---|---|---|---|---|
| 1 | Zero Conditional Access policies | Identity | PR.AC-04, PR.AC-07 | P1 (deploy in report-only mode immediately) |
| 2 | Excessive standing Global Administrators | Identity | PR.AC-04, PR.AC-06 | P1 (reduce to 2 within 7 days) |
| 3 | Permissive default authorization policy | Identity | PR.AC-04 | P2 (block guest-invite, app-create) |
| 4 | Tenant Allow/Block List empty | Email | DE.AE-02, A.8.16 | P2 (add known-good marketing senders for FP-relief) |
| 5 | Anti-phish impersonation protection not enrolled | Email | DE.AE-02, A.5.7 | P2 (enroll executives + finance + IT admins) |
| 6 | MTA-STS not configured | DNS | PR.DS-02, A.8.20 | P3 (enforce mode appropriate for M365-only mailflow) |
| 7 | TLS-RPT not configured | DNS | DE.CM-04 | P3 (deploy alongside MTA-STS) |
| 8 | Sign-in log read access not granted | Identity | DE.CM-03, AU-6 | P2 (assign Security Reader to operator) |
| 9 | No Strict Preset for high-risk users | Email | PR.AC-04 | P3 (apply to executives + finance group) |
| 10 | No custom outbound anti-spam alerting | Email | DE.AE-03 | P3 (lower thresholds + admin notify) |

P1 = within 1 week. P2 = within 30 days. P3 = within 90 days.

---

## What is intentionally absent

- **Endpoint controls (PR.PT-1, PR.IP-1, DE.CM-7 endpoint-specific).** No managed endpoints in tenant.
- **Data classification + DLP (PR.DS-01, PR.DS-05).** Out of scope for this engagement.
- **Vendor risk management (ID.SC).** Out of scope.
- **Backup + recovery (RC.RP).** M365 retention defaults assumed sufficient for this org size.
- **Physical security (PR.PE).** Not applicable — full cloud deployment, no on-premises infrastructure.
