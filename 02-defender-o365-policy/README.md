# Defender for Office 365 Policy Hardening

Methodology for auditing and hardening Microsoft Defender for Office 365 threat policies in a small Microsoft 365 tenant. Based on a posture audit conducted against a tenant running on default policies with partial Preset Security Policy application.

---

## Audit baseline

Default M365 tenants ship with these policy components active:

| Component | Default state |
|---|---|
| Anti-phishing | `Office365 AntiPhish Default` policy, Always-on, Lowest priority |
| Anti-spam (inbound) | Default policy, Lowest priority |
| Anti-spam (connection filter) | Default, Lowest priority |
| Anti-spam (outbound) | Default, Lowest priority |
| Anti-malware | Default, Always-on |
| Safe Attachments | Off until license enables + policy applied |
| Safe Links | Off until license enables + policy applied |
| Tenant Allow/Block Lists | Empty (no entries) |
| DKIM signing | Per-domain, must be enabled |

The defaults provide baseline filtering but lack: impersonation protection for key users, custom rules for high-risk roles, configured allow-lists for known-good marketing senders, and Strict Preset enforcement.

---

## Posture gaps observed and remediation order

Listed in priority order. Each gap maps to a specific Microsoft documentation reference and a measurable remediation.

### Gap 1: Impersonation protection not configured

**Observed:** Anti-phishing policy shows `0 impersonated domain(s) and user(s)`. The impersonation-protection feature isn't actively monitoring any specific names or domains.

**Why this matters:** Defender's default anti-phishing scoring catches generic phish but misses targeted impersonation of executives or vendors. CEO-fraud, vendor-impersonation, and partner-spoof attacks rely on display-name and email-address similarity that only triggers when specific targets are enlisted.

**Remediation:**
1. Identify high-risk users (executives, finance, HR, IT admins, anyone with authority over financial transfers or system access).
2. Enroll them in the anti-phishing policy's User-impersonation protection list.
3. Identify partner / vendor / customer domains the org corresponds with regularly. Add to Domain-impersonation protection list.
4. Set action on detected impersonation to "Quarantine the message" (not "Move to Junk" which still allows recipient interaction).

**Framework alignment:** NIST CSF DE.AE-02 (Adverse events analyzed), ISO 27001 A.5.7 (Threat intelligence).

### Gap 2: Tenant Allow/Block List is empty

**Observed:** All six tabs (Domains & addresses, Spoofed senders, URLs, Files, IP addresses, Teams senders) show "No data available".

**Why this matters:** False-positive emails repeatedly blocked require manual re-release for each occurrence; legitimate senders with broken DKIM signing are blocked indefinitely. The TenantAllowBlockList is the precision mechanism for FP recovery.

**Remediation:** Add allow entries for senders identified as legitimate but consistently mis-classified (specific entries determined from per-tenant analysis). Each entry should have an expiration date (Microsoft default: 30 days for allow; revisit and renew if pattern persists).

**Framework alignment:** ISO 27001 A.8.16 (Monitoring activities) — feedback loop from analyst review back into prevention controls.

### Gap 3: No Strict Preset Security Policy for high-risk users

**Observed:** Standard Preset Security Policy is applied for Safe Attachments and Safe Links components (priority -2 and -1 respectively). Strict Preset is not applied to any user group.

**Why this matters:** Standard Preset provides Microsoft's recommended baseline. Strict Preset adds aggressive Safe Links rewrites, Safe Attachments dynamic-detonation requirements, and reduced bulk-mail score threshold. For high-risk users (executives, finance, IT), Strict Preset reduces risk at the cost of slightly more friction on benign mail.

**Remediation:** Apply Strict Preset to a security group containing high-risk users. Standard Preset remains in effect for the rest of the tenant.

**Framework alignment:** NIST CSF PR.AC-04 (Access permissions managed), Microsoft Cloud Security Benchmark IM-6.

### Gap 4: No custom anti-spam rule for outbound mailflow

**Observed:** Outbound anti-spam policy runs default thresholds. No alerting on outbound spam (which indicates account compromise) or message-rate spikes.

**Why this matters:** Compromised tenant accounts are weaponized for outbound phishing within hours. Microsoft's default outbound limit (1000 recipients/24h) is permissive for a small org. Lower thresholds + admin alerting on threshold breach = early account-compromise signal.

**Remediation:** Lower outbound recipient and message thresholds appropriate to the org's normal mailflow. Enable admin notifications on threshold breach.

**Framework alignment:** NIST CSF DE.AE-03 (Event data aggregated and correlated), ISO 27001 A.8.7 (Protection against malware).

---

## Strengths observed (preserve these)

| Strength | Why it's good |
|---|---|
| Standard Preset Security Policy applied for Safe Attachments + Safe Links | Microsoft's recommended baseline for advanced threat controls |
| DKIM signing enabled and valid on the primary domain | Outbound DMARC alignment passes; receivers can verify origin |
| DKIM signing enabled on the default tenant domain (`*.onmicrosoft.com`) | Backup signing path |

---

## Configuration artifacts

| File | Purpose |
|---|---|
| `set-anti-phishing-impersonation.ps1` | (To be added) PowerShell template for enrolling protected users + domains via Exchange Online PowerShell. |
| `tenant-allow-block-template.csv` | (To be added) CSV template for bulk Tenant Allow/Block List entries. |
| `preset-security-strict-assignment.md` | (To be added) Steps to apply Strict Preset to a security group. |

---

## Framework alignment summary

| Framework | Control | Component |
|---|---|---|
| NIST CSF 2.0 | PR.DS-02 (Data-in-transit protected) | DKIM, DMARC alignment |
| NIST CSF 2.0 | PR.AC-04 (Access permissions managed) | Preset policy assignment by user group |
| NIST CSF 2.0 | DE.AE-02 (Adverse events analyzed) | Anti-phish impersonation detection |
| NIST CSF 2.0 | DE.AE-03 (Event data correlated) | Outbound spam alerting |
| NIST SP 800-53 | SI-8 (Spam Protection) | Anti-spam policy stack |
| NIST SP 800-53 | SI-3 (Malicious Code Protection) | Anti-malware policy, Safe Attachments |
| ISO 27001:2022 | A.5.7 (Threat intelligence) | Impersonation protection enlistment |
| ISO 27001:2022 | A.8.16 (Monitoring activities) | TenantAllowBlockList feedback loop |
| ISO 27001:2022 | A.8.7 (Protection against malware) | Anti-malware, Safe Attachments |
| Microsoft Cloud Security Benchmark | IM-6 (Use strong authentication controls) | Strict Preset for high-risk users |
