# run-audit.ps1
# Top-level orchestrator. Runs all 5 phase audits in sequence and aggregates findings into a single markdown report.
# Read-only — no tenant configuration is modified.
# Usage:
#   .\run-audit.ps1 -TenantId <tenant-id> -SubscriptionId <sub-id> -Domain <domain> [-WorkspaceName <ws>] [-ResourceGroup <rg>]

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $TenantId,

    [Parameter(Mandatory=$true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string] $Domain,

    [string] $WorkspaceName = $null,

    [string] $ResourceGroup = $null,

    [string] $Resolver = "1.1.1.1"
)

$ErrorActionPreference = "Continue"

# Verify az CLI
$az = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
if (-not (Test-Path $az)) {
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCmd) {
        Write-Error "Azure CLI not found. Install: winget install Microsoft.AzureCLI"
        exit 1
    }
    $az = $azCmd.Source
}

# Verify az logged in to correct tenant
$currentAccount = & $az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
if (-not $currentAccount -or $currentAccount.tenantId -ne $TenantId) {
    Write-Error "Not logged in to tenant $TenantId. Run: az login --tenant $TenantId"
    exit 1
}

# Create timestamped reports dir
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ss")
$reportsDir = Join-Path $PSScriptRoot "reports\$timestamp"
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  M365 Security Operations Toolkit — audit run" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Tenant:        $TenantId"
Write-Host "Subscription:  $SubscriptionId"
Write-Host "Domain:        $Domain"
Write-Host "Reports dir:   $reportsDir"
Write-Host ""

# Phase 1: DNS + email auth (no Azure resource access needed)
Write-Host ">>> Phase 1: DNS + Email Authentication" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "03-dns-email-auth\audit-dns-posture.ps1") `
        -Domain $Domain `
        -Resolver $Resolver `
        -OutputJsonPath (Join-Path $reportsDir "dns.json") `
        -TenantId $TenantId
} catch { Write-Warning "Phase 1 error: $($_.Exception.Message)" }

# Phase 2: Identity hardening
Write-Host ""
Write-Host ">>> Phase 2: Identity Hardening" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "04-identity-hardening\audit-identity-posture.ps1") `
        -TenantId $TenantId `
        -OutputJsonPath (Join-Path $reportsDir "identity.json")
} catch { Write-Warning "Phase 2 error: $($_.Exception.Message)" }

# Phase 3: Defender for Office 365 (optional - requires EXO module)
Write-Host ""
Write-Host ">>> Phase 3: Defender for Office 365" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "02-defender-o365-policy\audit-defender-o365.ps1") `
        -OutputJsonPath (Join-Path $reportsDir "defender-o365.json") `
        -TenantId $TenantId `
        -Domain $Domain
} catch { Write-Warning "Phase 3 error: $($_.Exception.Message)" }

# Phase 4: Sentinel (optional - requires workspace identification)
if ($WorkspaceName -and $ResourceGroup) {
    Write-Host ""
    Write-Host ">>> Phase 4: Sentinel Detection Engineering" -ForegroundColor Yellow
    try {
        & (Join-Path $PSScriptRoot "01-sentinel-detection-engineering\audit-sentinel.ps1") `
            -SubscriptionId $SubscriptionId `
            -ResourceGroup $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -TenantId $TenantId `
            -OutputJsonPath (Join-Path $reportsDir "sentinel.json")
    } catch { Write-Warning "Phase 4 error: $($_.Exception.Message)" }
} else {
    Write-Host ""
    Write-Host ">>> Phase 4: Sentinel Detection Engineering — SKIPPED" -ForegroundColor DarkGray
    Write-Host "Pass -WorkspaceName and -ResourceGroup to include Sentinel posture audit."
}

# Phase 5: Defender for Cloud
Write-Host ""
Write-Host ">>> Phase 5: Defender for Cloud" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "05-governance\audit-defender-cloud.ps1") `
        -SubscriptionId $SubscriptionId `
        -OutputJsonPath (Join-Path $reportsDir "defender-cloud.json") `
        -TenantId $TenantId
} catch { Write-Warning "Phase 5 error: $($_.Exception.Message)" }

# Aggregate report
Write-Host ""
Write-Host ">>> Generating consolidated report..." -ForegroundColor Yellow
& (Join-Path $PSScriptRoot "Generate-Report.ps1") -ReportsDir $reportsDir

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Audit complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Findings JSON:    $reportsDir\*.json"
Write-Host "Consolidated MD:  $reportsDir\report.md"
Write-Host ""
