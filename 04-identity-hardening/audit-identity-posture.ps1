# audit-identity-posture.ps1
# Microsoft Entra ID identity posture sweep via Microsoft Graph API.
# Emits findings as JSON per SCHEMA.md. Console summary printed to stdout.
# Prereqs: az login already done with sufficient Graph scopes.
# Usage: .\audit-identity-posture.ps1 -TenantId <tenant-id> -OutputJsonPath reports/<timestamp>/identity.json

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $TenantId,

    [Parameter(Mandatory=$true)]
    [string] $OutputJsonPath,

    [switch] $MockMode,

    [string] $FixturesPath = (Join-Path $PSScriptRoot "..\examples\fixtures")
)

Import-Module (Join-Path $PSScriptRoot "..\lib\Finding.psm1") -Force
if ($MockMode) {
    Import-Module (Join-Path $PSScriptRoot "..\lib\MockClient.psm1") -Force
    Initialize-MockClient -FixturesPath $FixturesPath
    # Wrap Invoke-RestMethod so all Graph calls route through the mock client
    function Invoke-RestMethod {
        param ([string] $Uri, [hashtable] $Headers, [string] $Method = "GET", $Body, [string] $ErrorAction)
        return Invoke-GraphMock -Uri $Uri
    }
    $headers = @{ Authorization = "Bearer mock" }
} else {
    # Find az CLI
    $az = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    if (-not (Test-Path $az)) { $az = "az" }

    $token = & $az account get-access-token --resource "https://graph.microsoft.com" --query accessToken -o tsv 2>$null
    if (-not $token) { Write-Error "Failed to acquire Graph access token. Run 'az login' first."; exit 1 }
    $headers = @{ Authorization = "Bearer $token" }
}

$findings = New-Object System.Collections.ArrayList
$findingCounter = 0
function Next-Id { $script:findingCounter++; return ("IDENT-{0:D3}" -f $script:findingCounter) }

# === Conditional Access policies ===
try {
    $ca = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -ErrorAction Stop
    if ($ca.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
            -Title "Zero Conditional Access policies" `
            -Description "Microsoft Graph /identity/conditionalAccess/policies returned an empty array. No CA policies defined means every sign-in is evaluated against only the Security Defaults baseline. Granular controls (MFA enforcement, sign-in risk thresholds, device compliance, named-location blocks) are not in effect." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","NIST.CSF.PR.AC-07","NIST.800-53.IA-2(1)","NIST.800-53.IA-2(2)","NIST.800-63B.AAL2","ISO27001.A.5.15","ISO27001.A.5.17") `
            -RemediationArtifact "04-identity-hardening/policies/" `
            -RemediationSteps @(
                "Review the 6 baseline CA policy JSONs in 04-identity-hardening/policies/.",
                "Identify or create Entra security groups for all-users, all-admins. Note their object IDs.",
                "Replace <group-id-all-users> and <group-id-all-admins> placeholders in each policy JSON.",
                "Deploy each in Report-only mode first: az rest --method PUT --uri https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --body @<file>.json",
                "Monitor 7-14 days via Insights & Reporting in Entra portal.",
                "Switch state from enabledForReportingButNotEnforced to enabled after impact review."
            ) `
            -Evidence @{ policy_count = 0; graph_endpoint = "/identity/conditionalAccess/policies" }))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Conditional Access policies configured" `
            -Description "Found $($ca.value.Count) CA policies. Manual review of individual policies recommended." `
            -Evidence @{ policy_count = $ca.value.Count }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "Unable to enumerate Conditional Access policies" `
        -Description "Graph API returned an error: $($_.Exception.Message). Likely missing Policy.Read.All scope on the audit account." `
        -FrameworkControls @("NIST.CSF.DE.CM-03","NIST.800-53.AU-6") `
        -RemediationSteps @(
            "Assign Security Reader directory role to the audit account, or grant Policy.Read.All Graph permission.",
            "Re-run the audit."
        )))
}

# === Authorization policy ===
try {
    $authz = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Headers $headers -ErrorAction Stop
    $authzGaps = @()
    if ($authz.allowInvitesFrom -eq "everyone") {
        $authzGaps += "AllowInvitesFrom = 'everyone'"
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Guest invitations allowed from any user" `
            -Description "Authorization policy permits any tenant user to invite external guests. Compromised user account can be weaponized to introduce attackers as guests." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","NIST.800-53.AC-3","ISO27001.A.5.15") `
            -RemediationSteps @(
                "az rest --method PATCH --uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' --body '{\""allowInvitesFrom\"": \""adminsAndGuestInviters\""}'",
                "Or via portal: Entra > External Identities > External collaboration settings > Guest invite settings."
            )))
    }
    if ($authz.defaultUserRolePermissions.allowedToCreateApps) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Any user can register OAuth applications" `
            -Description "Default user role permits app registration. Consent-phishing attacks rely on this — attackers create rogue apps and request user consent for Mail.Read, Files.Read.All scopes." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","NIST.800-53.AC-3","ISO27001.A.5.15") `
            -RemediationSteps @(
                "az rest --method PATCH --uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' --body '{\""defaultUserRolePermissions\"":{\""allowedToCreateApps\"":false}}'",
                "Move app registration to a dedicated Application Administrator role."
            )))
    }
    if (-not $authz.blockMsolPowerShell) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Legacy MSOL PowerShell module not blocked" `
            -Description "MSOL PowerShell is the deprecated administration module. Block it to force admins onto Microsoft Graph PowerShell which supports modern auth requirements." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","ISO27001.A.5.15") `
            -RemediationSteps @(
                "az rest --method PATCH --uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' --body '{\""blockMsolPowerShell\"":true}'"
            )))
    }
    if (-not ($authzGaps) -and -not $authz.defaultUserRolePermissions.allowedToCreateApps -and $authz.blockMsolPowerShell) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Default authorization policy hardened" `
            -Description "AllowInvitesFrom restricted, AllowedToCreateApps disabled, MSOL PowerShell blocked." `
            -Evidence @{ allowInvitesFrom = $authz.allowInvitesFrom; blockMsolPowerShell = $authz.blockMsolPowerShell }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "Unable to read authorization policy" `
        -Description "Graph error: $($_.Exception.Message). Likely missing scope." `
        -FrameworkControls @("NIST.CSF.DE.CM-03") `
        -RemediationSteps @("Assign Security Reader or Policy.Read.All to audit account.")))
}

# === Directory role assignments ===
try {
    $roles = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers -ErrorAction Stop
    $gaCount = 0
    $gaMembers = @()
    $standingAdminMap = @{}
    foreach ($r in $roles.value) {
        $members = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($r.id)/members" -Headers $headers -ErrorAction SilentlyContinue
        if ($members -and $members.value.Count -gt 0) {
            if ($r.displayName -eq "Global Administrator") {
                $gaCount = $members.value.Count
                $gaMembers = $members.value | ForEach-Object { $_.userPrincipalName }
            }
            foreach ($m in $members.value) {
                if (-not $standingAdminMap.ContainsKey($m.userPrincipalName)) { $standingAdminMap[$m.userPrincipalName] = @() }
                $standingAdminMap[$m.userPrincipalName] += $r.displayName
            }
        }
    }

    # Excessive GA check
    if ($gaCount -ge 3) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
            -Title "Excessive standing Global Administrators" `
            -Description "$gaCount Global Administrator accounts. Microsoft's published guidance: 2-4 GA accounts total per tenant maximum, regardless of org size. Each GA account is a high-value compromise target." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","NIST.CSF.PR.AC-06","NIST.800-53.AC-2","NIST.800-53.AC-6","ISO27001.A.5.18") `
            -RemediationSteps @(
                "Identify the actual admin owner. Keep them as primary GA.",
                "Provision exactly one break-glass GA account: no MFA, complex password sealed in physical safe, IP-allowlisted, audit-logged on every sign-in.",
                "For other GA-assigned users, switch to least-privilege roles via Privileged Identity Management.",
                "Remove standing GA from non-essential accounts."
            ) `
            -Evidence @{ ga_count = $gaCount; ga_members = $gaMembers }))
    }

    # Multi-role standing detection
    foreach ($upn in $standingAdminMap.Keys) {
        $roleList = $standingAdminMap[$upn]
        if ($roleList.Count -ge 3 -and ($roleList -notcontains "Global Administrator")) {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
                -Title "User with multiple standing admin roles" `
                -Description "$upn holds $($roleList.Count) admin roles ($($roleList -join ', ')). Standing assignment of multiple admin roles bypasses just-in-time access controls and expands compromise blast radius." `
                -FrameworkControls @("NIST.CSF.PR.AC-04","NIST.800-53.AC-6","ISO27001.A.5.18") `
                -RemediationSteps @(
                    "Convert all roles for $upn to eligible (PIM-elevated) instead of permanent assignments.",
                    "Require justification + MFA at activation time."
                ) `
                -Evidence @{ upn = $upn; roles = $roleList }))
        }
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "Unable to enumerate directory roles" `
        -Description "Graph error: $($_.Exception.Message)" `
        -RemediationSteps @("Assign Directory.Read.All or Security Reader role to audit account.")))
}

# === Sign-in log access ===
try {
    $signins = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1" -Headers $headers -ErrorAction Stop
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "Sign-in logs accessible" `
        -Description "Audit account has AuditLog.Read.All scope. Sign-in forensics available." `
        -Evidence @{ most_recent = $signins.value[0].createdDateTime }))
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "Sign-in log read access not granted" `
        -Description "Audit account cannot read sign-in logs. Forensic investigation of credential compromise will be blocked." `
        -FrameworkControls @("NIST.CSF.DE.CM-03","NIST.800-53.AU-6","ISO27001.A.5.28") `
        -RemediationSteps @(
            "Assign Security Reader directory role to the audit account (covers all read scopes).",
            "Or explicitly grant AuditLog.Read.All Graph permission."
        )))
}

# === Final write ===
$severityCounts = Get-FindingSeverityCount -Findings $findings
Write-Host ""
Write-Host "Identity posture audit complete"
Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
Write-Host ""

Write-PhaseReport `
    -Phase "identity-hardening" `
    -PhaseDisplayName "Identity Hardening" `
    -OutputPath $OutputJsonPath `
    -TenantId $TenantId `
    -AuditScriptVersion "1.0.0" `
    -Findings $findings

Write-Host "Findings written to: $OutputJsonPath"
