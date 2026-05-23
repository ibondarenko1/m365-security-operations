# Walkthrough: Deploy baseline Conditional Access policies

Roll out the 6 baseline Conditional Access policies in report-only mode, monitor for impact, then transition to enforcement.

Time required: ~30 minutes deployment + 7-14 days monitoring. Cost: $0 baseline (Entra ID P1 included with M365 Business Premium); some policies require P2.

---

## Prerequisites

- Microsoft Graph PowerShell module: `Install-Module -Name Microsoft.Graph -Scope CurrentUser`
- Account with Conditional Access Administrator role
- Break-glass account already provisioned (no MFA, complex password sealed in physical safe, audit-logged)

---

## Step 1: Identify required group + user IDs

The policy JSONs have `<placeholder>` tokens that need real Entra IDs.

```powershell
Connect-MgGraph -Scopes "Group.Read.All","User.Read.All","Policy.ReadWrite.ConditionalAccess"

# Break-glass user
$breakGlassUpn = "breakglass@yourdomain.com"
$breakGlassId = (Get-MgUser -Filter "userPrincipalName eq '$breakGlassUpn'").Id

# Service-accounts group (create if not exists)
$svcGroupName = "sg-service-accounts"
$svcGroup = Get-MgGroup -Filter "displayName eq '$svcGroupName'"
if (-not $svcGroup) {
    $svcGroup = New-MgGroup -DisplayName $svcGroupName -MailEnabled:$false -SecurityEnabled:$true -MailNickname "sg-service-accounts"
}
$svcGroupId = $svcGroup.Id

Write-Host "Break-glass user ID: $breakGlassId"
Write-Host "Service-accounts group ID: $svcGroupId"
```

---

## Step 2: Deploy policies in report-only mode

```powershell
cd 04-identity-hardening/policies

./deploy.ps1 -BreakGlassUserId $breakGlassId -ServiceAccountsGroupId $svcGroupId
```

All 6 policies created with state `enabledForReportingButNotEnforced`:

1. Block legacy authentication
2. Require phishing-resistant MFA for all admins
3. Require MFA for all users
4. Block high-risk sign-ins (requires Entra ID P2)
5. Require password change for high-risk users (requires P2)
6. Require compliant device for management portals (requires Intune)

---

## Step 3: Monitor 7-14 days in Insights & Reporting

Entra admin > Protection > Conditional Access > Insights and reporting.

Filter by each policy. Watch:
- **What would have been blocked:** legitimate sign-ins that would fail under enforcement
- **What would have required MFA:** users who would have been prompted
- **Coverage gaps:** sign-ins not evaluated by any policy

If legitimate users show up in "would have been blocked":
- Add them to policy `excludeUsers` or `excludeGroups`
- Or address the root cause (e.g. update legacy iOS Mail to modern auth client)

---

## Step 4: Pre-flight checks before enforcement

Before flipping ANY policy from report-only to enabled, verify:

1. **All admins have registered phishing-resistant MFA** (FIDO2 or Windows Hello). Check: Entra > Authentication methods > Activity.
2. **Break-glass account works.** Test sign-in from clean browser. Confirm the policy exclusions are in effect.
3. **Service accounts have alternative auth path** (managed identity, certificate auth, or excluded from MFA policy).
4. **Legacy clients identified.** Any legitimate iOS Mail, MFP, line-of-business app using legacy auth should be migrated or excluded.

---

## Step 5: Enforce one policy at a time

Recommended order (low to high disruption risk):

1. **Block legacy auth** — low risk if all clients are modern
2. **Require MFA for all admins** — affects ~10% of users
3. **Require compliant device for management portals** — affects admins
4. **Require MFA for all users** — broad impact, monitor helpdesk closely
5. **Block high-risk sign-ins** (P2)
6. **Require password change for high-risk users** (P2)

For each, change state:

```powershell
$policyId = "<id-from-deployment-step>"
$body = @{ state = "enabled" } | ConvertTo-Json
Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$policyId" -Method PATCH -Body $body
```

Or via portal: Entra > Conditional Access > <policy> > toggle "Enable policy" to "On".

Wait 24-48 hours between enforcements. Watch helpdesk tickets + sign-in logs.

---

## Step 6: Verify via audit toolkit

```powershell
./run-audit.ps1 -TenantId ... -SubscriptionId ... -Domain ...
```

Identity phase should now show INFO-level confirmation: "Conditional Access policies configured" with policy count = 6, not the P1 "Zero Conditional Access policies".

---

## Rollback

If a policy causes unexpected impact:

```powershell
# Revert to report-only
$body = @{ state = "enabledForReportingButNotEnforced" } | ConvertTo-Json
Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$policyId" -Method PATCH -Body $body

# Or disable entirely
$body = @{ state = "disabled" } | ConvertTo-Json
Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$policyId" -Method PATCH -Body $body
```

Break-glass account is the ultimate fallback — designed to remain reachable when all other auth paths fail.

---

## Framework alignment

- NIST CSF 2.0: PR.AC-04, PR.AC-06, PR.AC-07
- NIST SP 800-53 Rev. 5: AC-2, AC-3, AC-6, IA-2(1), IA-2(2)
- NIST SP 800-63B: AAL2 (all users) + AAL3 (admins with phishing-resistant)
- ISO 27001:2022: A.5.15, A.5.17, A.5.18
- Microsoft Cloud Security Benchmark: IM-6, IM-7
