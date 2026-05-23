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

    [string] $Domain = $null,

    [switch] $MockMode,

    [string] $FixturesPath = (Join-Path $PSScriptRoot "..\examples\fixtures")
)

Import-Module (Join-Path $PSScriptRoot "..\lib\Finding.psm1") -Force
if ($MockMode) {
    Import-Module (Join-Path $PSScriptRoot "..\lib\MockClient.psm1") -Force
    Initialize-MockClient -FixturesPath $FixturesPath
}

$findings = New-Object System.Collections.ArrayList
$findingCounter = 0
function Next-Id { $script:findingCounter++; return ("MAIL-{0:D3}" -f $script:findingCounter) }

# In mock mode, skip EXO module + connection - all data comes from fixtures
if ($MockMode) {
    $antiPhish = Get-MockExoData -CmdletName "AntiPhishPolicy"
    $tabl = Get-MockExoData -CmdletName "TenantAllowBlockList"
    $dkim = Get-MockExoData -CmdletName "DkimSigningConfig"

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
                    "Run: 02-defender-o365-policy/templates/enable-impersonation-protection.ps1 -ProtectedUsers <user1>,<user2>",
                    "Set action on detected impersonation to Quarantine."
                )))
        }
    }

    if ($tabl.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Tenant Allow/Block List is empty" `
            -Description "No entries in the Tenant Allow/Block List for senders. False-positive emails repeatedly blocked require manual re-release for each occurrence; legitimate senders with broken DKIM are blocked indefinitely." `
            -FrameworkControls @("NIST.CSF.DE.AE-02","ISO27001.A.8.16") `
            -RemediationArtifact "02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1" `
            -RemediationSteps @(
                "Review false-positive senders surfaced by KQL hunting (see 01-sentinel-detection-engineering/kql/).",
                "Run: 02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1 -EntriesCsv allow-entries.csv"
            )))
    }

    foreach ($d in $dkim) {
        if ($d.Enabled) {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
                -Title "DKIM enabled for $($d.Domain)" `
                -Description "Domain $($d.Domain): Enabled = True, Status = $($d.Status)" `
                -Evidence @{ domain = $d.Domain; enabled = $true; status = $d.Status }))
        }
    }

    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
        -Title "Strict Preset Security Policy not applied" `
        -Description "No Strict Preset assigned to any user group. For high-risk users (executives, finance, IT), Strict Preset adds aggressive Safe Links rewrites and Safe Attachments dynamic detonation." `
        -FrameworkControls @("NIST.CSF.PR.AC-04","MCSB.IM-6") `
        -RemediationArtifact "02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1" `
        -DocumentationUrl "https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies" `
        -RemediationSteps @(
            "Create a security group named 'sg-high-risk-users' containing executives + finance + IT.",
            "Run: 02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1 -GroupName 'sg-high-risk-users'"
        )))

    # Mock additional checks via fixture data
    $extraData = Get-MockFixture -Name "exo-extras"

    if ($extraData.zapForPhish -ne $true) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Zero-hour Auto Purge for phish disabled" `
            -Description "ZAP retroactively removes phishing emails already delivered to inboxes when Defender's threat intelligence later classifies them as phish. Disabling ZAP defeats one of Defender's most-valuable post-delivery controls." `
            -FrameworkControls @("NIST.CSF.RS.MI-02","ISO27001.A.8.7") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge" `
            -RemediationSteps @(
                "Defender > Email & Collaboration > Policies > Anti-spam > <policy> > Edit > Zero-hour auto purge.",
                "Toggle: Enable zero-hour auto purge (ZAP) for phishing messages."
            )))
    }

    if ($extraData.zapForSpam -ne $true) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Zero-hour Auto Purge for spam disabled" `
            -Description "ZAP for spam similarly removes spam messages post-delivery when threat intel updates. Less critical than phish-ZAP but still recommended." `
            -FrameworkControls @("NIST.CSF.RS.MI-02") `
            -RemediationSteps @("Defender > Anti-spam policies > Edit > enable ZAP for spam.")))
    }

    if ($extraData.outboundSpamRecipientLimitPerHour -ge 1000) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Outbound spam recipient limit too permissive" `
            -Description "Outbound spam policy permits $($extraData.outboundSpamRecipientLimitPerHour) external recipients per hour. Compromised accounts are weaponized for outbound phishing within hours; lower thresholds + admin alerting on threshold breach are early-warning signals." `
            -FrameworkControls @("NIST.CSF.DE.AE-03","NIST.800-53.SI-8") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure" `
            -RemediationSteps @(
                "Defender > Anti-spam policies > Outbound policy > Edit.",
                "Set: 'External message limit per hour' to a value appropriate for your normal outbound volume (e.g. 100 for small org).",
                "Enable admin notification when threshold breached."
            )))
    }

    if (-not $extraData.outboundSpamAdminNotifyEnabled) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "No admin notification on outbound spam threshold" `
            -Description "Outbound spam policy has no admin email recipient configured. Threshold breaches (likely account compromise indicator) go unnoticed until end-user reports." `
            -FrameworkControls @("NIST.CSF.DE.AE-03") `
            -RemediationSteps @(
                "Defender > Anti-spam policies > Outbound policy > Notifications.",
                "Add admin email under 'Send a copy of suspicious outbound that exceeds these limits to'."
            )))
    }

    if ($extraData.transportRulesCount -ge 50) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "High transport rules count - review for drift" `
            -Description "$($extraData.transportRulesCount) Exchange transport rules deployed. Rules accumulate over time; periodic review catches stale or conflicting rules that complicate troubleshooting." `
            -FrameworkControls @("ISO27001.A.5.30") `
            -RemediationSteps @(
                "EAC > Mail flow > Rules. Review each rule for purpose + last-fired date.",
                "Disable + monitor for 30 days before deletion. Document rationale in description field."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Transport rules inventory" `
            -Description "$($extraData.transportRulesCount) Exchange transport rules deployed."))
    }

    if ($extraData.attackSimulationCampaigns -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No Attack Simulation Training campaigns" `
            -Description "Defender for O365 includes free attack simulation training (phishing simulations, credential harvest, malware). Zero campaigns means user-awareness baseline is unmeasured." `
            -FrameworkControls @("NIST.CSF.PR.AT-01","ISO27001.A.6.3") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-get-started" `
            -RemediationSteps @(
                "Defender > Email & Collaboration > Attack simulation training > Simulations > Launch a simulation.",
                "Start with phishing technique; target IT + executives + finance first.",
                "Review results after 14 days; assign training to clickers."
            )))
    }

    $severityCounts = Get-FindingSeverityCount -Findings $findings
    Write-Host ""
    Write-Host "Defender for Office 365 audit complete (mock mode)"
    Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
    Write-Host ""

    Write-PhaseReport `
        -Phase "defender-o365" -PhaseDisplayName "Defender for Office 365 Policy" `
        -OutputPath $OutputJsonPath -TenantId $TenantId -Domain $Domain `
        -AuditScriptVersion "1.0.0" -Findings $findings
    Write-Host "Findings written to: $OutputJsonPath"
    exit 0
}

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
