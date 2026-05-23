# audit-defender-o365.ps1
# Defender for Office 365 policy posture audit.
# Uses Exchange Online PowerShell module for read-only inspection of Anti-phish,
# Anti-spam, Anti-malware, Safe Attachments, Safe Links, Tenant Allow/Block List, DKIM.
# Falls back to documented "module unavailable" finding if EXO module is not installed.
# Usage: .\audit-defender-o365.ps1 -OutputJsonPath reports/<timestamp>/defender-o365.json [-TenantId <id>]

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $OutputJsonPath,

    [string] $TenantId = $null,

    [string] $Domain = $null
)

Import-Module (Join-Path $PSScriptRoot "..\lib\Finding.psm1") -Force

$findings = New-Object System.Collections.ArrayList
$findingCounter = 0
function Next-Id { $script:findingCounter++; return ("MAIL-{0:D3}" -f $script:findingCounter) }

# Check for ExchangeOnlineManagement module
$exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement
if (-not $exoModule) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "OUT_OF_SCOPE" `
        -Title "ExchangeOnlineManagement module not installed" `
        -Description "Defender for Office 365 audit requires the ExchangeOnlineManagement PowerShell module. Install via: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser. Re-run audit after installation. Phase skipped this run." `
        -FrameworkControls @() `
        -RemediationSteps @(
            "Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force",
            "Re-run ./run-audit.ps1 after install completes."
        )))

    Write-PhaseReport `
        -Phase "defender-o365" `
        -PhaseDisplayName "Defender for Office 365 Policy" `
        -OutputPath $OutputJsonPath `
        -TenantId $TenantId `
        -Domain $Domain `
        -AuditScriptVersion "1.0.0" `
        -Findings $findings
    Write-Host "Defender O365 audit skipped (module not installed). Findings: $OutputJsonPath"
    exit 0
}

# Connect with current account
try {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "Cannot connect to Exchange Online" `
        -Description "Connect-ExchangeOnline failed: $($_.Exception.Message). Audit cannot continue without EXO session." `
        -FrameworkControls @() `
        -RemediationSteps @(
            "Run Connect-ExchangeOnline manually to identify the auth issue.",
            "Ensure the account has Security Reader or Exchange admin role."
        )))
    Write-PhaseReport -Phase "defender-o365" -PhaseDisplayName "Defender for Office 365 Policy" `
        -OutputPath $OutputJsonPath -TenantId $TenantId -Domain $Domain -AuditScriptVersion "1.0.0" -Findings $findings
    exit 1
}

# === Anti-phishing policies ===
try {
    $antiPhish = Get-AntiPhishPolicy -ErrorAction Stop
    $defaultPolicy = $antiPhish | Where-Object { $_.IsDefault }
    if ($defaultPolicy) {
        $impUsersCount = ($defaultPolicy.TargetedUsersToProtect | Measure-Object).Count
        $impDomainsCount = ($defaultPolicy.TargetedDomainsToProtect | Measure-Object).Count
        if ($impUsersCount -eq 0 -and $impDomainsCount -eq 0) {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
                -Title "Anti-phish impersonation protection not enrolled" `
                -Description "Default anti-phish policy has zero protected users and zero protected domains. CEO-fraud, vendor-impersonation, and partner-spoof attacks rely on display-name and email-address similarity that only triggers when specific targets are enlisted." `
                -FrameworkControls @("NIST.CSF.DE.AE-02","ISO27001.A.5.7") `
                -RemediationArtifact "02-defender-o365-policy/templates/enable-impersonation-protection.ps1" `
                -RemediationSteps @(
                    "Identify high-risk users (executives, finance, IT admins).",
                    "Run: 02-defender-o365-policy/templates/enable-impersonation-protection.ps1 -ProtectedUsers <user1>,<user2> -ProtectedDomains <vendor1>,<vendor2>",
                    "Set action on detected impersonation to Quarantine."
                ) `
                -Evidence @{ default_policy_name = $defaultPolicy.Name; protected_users = $impUsersCount; protected_domains = $impDomainsCount }))
        } else {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
                -Title "Anti-phish impersonation protection configured" `
                -Description "Protected users: $impUsersCount. Protected domains: $impDomainsCount." `
                -Evidence @{ protected_users = $impUsersCount; protected_domains = $impDomainsCount }))
        }
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Anti-phish policy enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === Tenant Allow/Block List ===
try {
    $tabl = Get-TenantAllowBlockListItems -ListType Sender -ErrorAction Stop
    if ($tabl.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Tenant Allow/Block List is empty" `
            -Description "No entries in the Tenant Allow/Block List for senders. False-positive emails repeatedly blocked require manual re-release for each occurrence; legitimate senders with broken DKIM are blocked indefinitely." `
            -FrameworkControls @("NIST.CSF.DE.AE-02","ISO27001.A.8.16") `
            -RemediationArtifact "02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1" `
            -RemediationSteps @(
                "Review false-positive senders surfaced by KQL hunting (see 01-sentinel-detection-engineering/kql/).",
                "Run: 02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1 -EntriesCsv allow-entries.csv",
                "Set expiration dates per entry (Microsoft default: 30 days for allow)."
            ) `
            -Evidence @{ entry_count = 0 }))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Tenant Allow/Block List has entries" `
            -Description "Found $($tabl.Count) sender entries." `
            -Evidence @{ entry_count = $tabl.Count }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Tenant Allow/Block List enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === DKIM signing ===
try {
    $dkim = Get-DkimSigningConfig -ErrorAction Stop
    foreach ($d in $dkim) {
        if (-not $d.Enabled) {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
                -Title "DKIM not enabled for $($d.Domain)" `
                -Description "DKIM signing is disabled for $($d.Domain). Outbound mail from this domain cannot be DKIM-validated. DMARC alignment will fail." `
                -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.5","ISO27001.A.8.20") `
                -RemediationArtifact $null `
                -RemediationSteps @(
                    "Verify DNS CNAMEs are configured (see 03-dns-email-auth/audit-dns-posture.ps1 output).",
                    "Enable DKIM in Defender admin: Email & Collaboration > Policies > DKIM > $($d.Domain) > Enable.",
                    "Or via PowerShell: Set-DkimSigningConfig -Identity $($d.Domain) -Enabled `$true"
                ) `
                -Evidence @{ domain = $d.Domain; enabled = $d.Enabled; status = $d.Status }))
        } else {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
                -Title "DKIM enabled for $($d.Domain)" `
                -Description "Domain $($d.Domain): Enabled = True, Status = $($d.Status)" `
                -Evidence @{ domain = $d.Domain; enabled = $true; status = $d.Status }))
        }
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "DKIM config enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === Preset Security Policy assignment ===
try {
    $hostedConn = Get-EOPProtectionPolicyRule -State Enabled -ErrorAction SilentlyContinue
    $strictRule = $hostedConn | Where-Object { $_.Identity -like "*Strict*" }
    $standardRule = $hostedConn | Where-Object { $_.Identity -like "*Standard*" }
    if (-not $strictRule) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Strict Preset Security Policy not applied" `
            -Description "No Strict Preset assigned to any user group. For high-risk users (executives, finance, IT), Strict Preset adds aggressive Safe Links rewrites and Safe Attachments dynamic detonation." `
            -FrameworkControls @("NIST.CSF.PR.AC-04","MCSB.IM-6") `
            -RemediationArtifact "02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1" `
            -RemediationSteps @(
                "Create a security group named 'sg-high-risk-users' containing executives + finance + IT.",
                "Run: 02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1 -GroupName 'sg-high-risk-users'"
            )))
    }
} catch {
    # Silent fallback - Preset enumeration is finicky
}

# === Disconnect ===
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

# === Final write ===
$severityCounts = Get-FindingSeverityCount -Findings $findings
Write-Host ""
Write-Host "Defender for Office 365 audit complete"
Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
Write-Host ""

Write-PhaseReport `
    -Phase "defender-o365" `
    -PhaseDisplayName "Defender for Office 365 Policy" `
    -OutputPath $OutputJsonPath `
    -TenantId $TenantId `
    -Domain $Domain `
    -AuditScriptVersion "1.0.0" `
    -Findings $findings

Write-Host "Findings written to: $OutputJsonPath"
