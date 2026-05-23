# Identity Hardening

Methodology for auditing and hardening identity posture in a Microsoft Entra ID tenant. Based on an audit of a small-org tenant with no Conditional Access policies and several admin-role assignments.

---

## Audit method

Microsoft Graph API enumeration is faster and more accurate than the portal UI for identity audits. Authenticated via Azure CLI:

```powershell
az account get-access-token --resource "https://graph.microsoft.com" --query accessToken -o tsv
```

Then `Invoke-RestMethod` against the relevant endpoints. The `audit-identity-posture.ps1` script in `scripts/` runs the full sweep.

| Audit area | Graph endpoint | What it tells you |
|---|---|---|
| Conditional Access policies | `/identity/conditionalAccess/policies` | What policies exist, their state, applied controls |
| Security Defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | Whether the no-CA-needed baseline is enabled |
| Authorization policy | `/policies/authorizationPolicy` | What default-user can do (create apps, invite guests, etc.) |
| Authentication methods | `/policies/authenticationMethodsPolicy` | Which auth methods are enabled tenant-wide |
| Directory roles | `/directoryRoles` + members | Who has which admin role |
| Users | `/users` | Total count, member-vs-guest breakdown |
| Sign-in logs | `/auditLogs/signIns` | Recent sign-ins (requires AuditLog.Read.All) |

---

## Audit findings (representative)

### Gap 1: Zero Conditional Access policies

**Observed:** `/identity/conditionalAccess/policies` returned an empty value array. No CA policies defined.

**Why this matters:** Conditional Access is the granular access-control plane for Entra ID. Without policies, every sign-in is evaluated against the baseline rules only (Security Defaults if enabled, or no MFA enforcement if not). A tenant with no CA policies cannot enforce:

- MFA for specific apps or roles
- Compliant device requirement for sensitive data access
- Block sign-in from named locations (country-block, anonymizer-block)
- Sign-in risk thresholds (auto-block high-risk sign-ins)
- User risk thresholds (require password change on compromised user)
- Session controls (limit sign-in frequency, persistent browser session)
- Authentication strength (require phishing-resistant MFA for admins)

**Remediation:** Deploy a baseline set of CA policies. Microsoft publishes a recommended set including:

1. **Block legacy authentication.** Legacy protocols (POP, IMAP, SMTP-Basic, MAPI, EWS-Basic) cannot enforce MFA. Block them.
2. **Require MFA for all admins.** Apply to all administrative role-holders. Authentication strength: phishing-resistant MFA (FIDO2 or Windows Hello).
3. **Require MFA for all users.** Apply to all users for cloud applications.
4. **Require MFA for high-risk sign-ins.** Apply when sign-in risk = high (requires Entra ID P2 or per-user feature licensing).
5. **Require password change on high-risk users.** When user risk = high.
6. **Require compliant device for management portals.** Apply to Azure portal, Entra admin, M365 admin centers.

Policies should be deployed in Report-only mode first, monitored for impact via Insights & Reporting, then transitioned to On.

**Framework alignment:** NIST CSF PR.AC-01 (Identities and credentials), PR.AC-07 (Auth strength), NIST SP 800-53 IA-2(1), IA-2(2), ISO 27001 A.5.15 (Access control), A.5.17 (Authentication information).

### Gap 2: Excessive standing Global Administrators

**Observed:** Three Global Administrator role members in a 6-user tenant.

**Why this matters:** Microsoft's published guidance: maintain 2-4 Global Admin accounts total per tenant, regardless of org size, and minimize standing assignment. Two is the minimum (one primary, one break-glass). Three or more standing GA accounts in a small tenant means 50%+ of users hold the most powerful role. Each GA account is a high-value compromise target.

**Remediation:**

1. Identify the actual admin owner (likely one user). Keep them as GA.
2. Provision exactly one dedicated break-glass account (no MFA, complex password stored in a sealed envelope, IP-allowlisted, audit-logged on every sign-in). Keep as GA.
3. For other former-GA users: assign least-privilege role matching their actual function (Exchange Admin, User Admin, Conditional Access Admin, Security Admin, etc.) — never multiple at once.
4. Activate Privileged Identity Management (PIM) for those least-privilege roles. PIM converts standing assignments to eligible (just-in-time activation with justification + MFA at activation time).
5. Remove the third standing GA assignment.

**Framework alignment:** NIST CSF PR.AC-04 (Access permissions managed), PR.AC-06 (Identities are proofed), NIST SP 800-53 AC-2 (Account Management), AC-6 (Least Privilege), ISO 27001 A.5.18 (Access rights).

### Gap 3: Permissive default authorization policy

**Observed:** Default authorization policy allows:
- `AllowInvitesFrom: everyone` (any user can invite external guests)
- `AllowedToCreateApps: true` (any user can register OAuth applications)
- `AllowedToCreateSecurityGroups: true` (any user can create security groups)
- `BlockMsolPowerShell: false` (legacy MSOL PowerShell module not blocked)

**Why this matters:** Each setting is an attack-vector amplifier. Guest invitations from any user mean any phished user account can introduce attackers as guests. OAuth app registration is the documented entry path for consent-phishing attacks (rogue apps requesting user consent for Mail.Read, Files.Read.All, etc.). Legacy MSOL PowerShell bypasses some modern auth requirements.

**Remediation:**
1. `AllowInvitesFrom`: change to `adminsAndGuestInviters` (only admins and explicitly-permitted users can invite). Limits guest-introduction blast radius.
2. `AllowedToCreateApps`: change to `false`. Move app registration to a dedicated Application Administrator role.
3. `AllowedToCreateSecurityGroups`: change to `false` if group management is centralized.
4. `BlockMsolPowerShell`: change to `true`. The MSOL module is deprecated in favor of Microsoft Graph PowerShell.

**Framework alignment:** NIST CSF PR.AC-04 (Access permissions managed), NIST SP 800-53 AC-3 (Access Enforcement), ISO 27001 A.5.15 (Access control).

### Gap 4: Sign-in log access restricted

**Observed:** `/auditLogs/signIns` returned 403 Forbidden when queried with the operator's CLI-acquired Graph token.

**Why this matters:** Sign-in logs are the primary forensic artifact for credential compromise. If the operator account cannot read sign-in logs, the SOC analyst function is structurally impaired.

**Remediation:** Assign the operator account the `AuditLog.Read.All` Graph permission via either (a) a Security Reader directory role (covers audit log read access), or (b) explicit consent of the Graph permission for the operator's Azure CLI app context.

**Framework alignment:** NIST CSF DE.CM-03 (Personnel activity monitored), NIST SP 800-53 AU-6 (Audit Review, Analysis, Reporting), ISO 27001 A.5.28 (Collection of evidence).

---

## Configuration artifacts

| File | Purpose |
|---|---|
| `audit-identity-posture.ps1` | Graph API sweep — Conditional Access, authorization policy, role assignments, user counts. |
| `ca-policy-baseline.json` | (To be added) Conditional Access policy library — JSON templates for the 6 baseline policies above. |

---

## Framework alignment summary

| Framework | Control | Component |
|---|---|---|
| NIST CSF 2.0 | PR.AC-01 (Identities and credentials issued, managed) | User lifecycle + MFA enrollment |
| NIST CSF 2.0 | PR.AC-04 (Access permissions managed) | CA policies, role assignments, default permissions |
| NIST CSF 2.0 | PR.AC-06 (Identities proofed) | Authentication strength + phishing-resistant MFA |
| NIST CSF 2.0 | PR.AC-07 (Users authenticated) | MFA enforcement via CA |
| NIST CSF 2.0 | DE.CM-03 (Personnel activity monitored) | Sign-in logs access |
| NIST SP 800-53 | AC-2 (Account Management) | User + role audit |
| NIST SP 800-53 | AC-3 (Access Enforcement) | Authorization policy tightening |
| NIST SP 800-53 | AC-6 (Least Privilege) | Reduce standing GA, PIM elevation |
| NIST SP 800-53 | IA-2(1), IA-2(2) (Identification and Authentication) | MFA for users + admins |
| NIST SP 800-63B | AAL2/AAL3 (Authenticator Assurance Levels) | Phishing-resistant MFA for admins |
| ISO 27001:2022 | A.5.15 (Access control) | CA policy framework |
| ISO 27001:2022 | A.5.17 (Authentication information) | MFA, password policies |
| ISO 27001:2022 | A.5.18 (Access rights) | PIM, role audit |
| ISO 27001:2022 | A.5.28 (Collection of evidence) | Sign-in log access |
