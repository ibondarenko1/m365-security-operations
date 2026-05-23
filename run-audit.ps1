# run-audit.ps1
# Top-level orchestrator. Runs all 5 phase audits in sequence and aggregates findings into a single markdown report.
# Read-only — no tenant configuration is modified.
# Usage:
#   .\run-audit.ps1 -TenantId <tenant-id> -SubscriptionId <sub-id> -Domain <domain> [-WorkspaceName <ws>] [-ResourceGroup <rg>]

[CmdletBinding(DefaultParameterSetName="Live")]
param (
    [Parameter(Mandatory=$true, ParameterSetName="Live")]
    [string] $TenantId,

    [Parameter(Mandatory=$true, ParameterSetName="Live")]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true, ParameterSetName="Live")]
    [string] $Domain,

    [Parameter(ParameterSetName="Live")]
    [string] $WorkspaceName = $null,

    [Parameter(ParameterSetName="Live")]
    [string] $ResourceGroup = $null,

    [Parameter(ParameterSetName="Live")]
    [string] $Resolver = "1.1.1.1",

    [Parameter(Mandatory=$true, ParameterSetName="Mock")]
    [switch] $MockMode
)

# Mock mode defaults - synthetic values from fixtures
if ($MockMode) {
    $TenantId       = "00000000-0000-0000-0000-000000000000"
    $SubscriptionId = "11111111-1111-1111-1111-111111111111"
    $Domain         = "example.com"
    $WorkspaceName  = "example-ws"
    $ResourceGroup  = "example-rg"
    $Resolver       = "1.1.1.1"
}

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

# Verify az logged in to correct tenant (skip in mock mode)
if (-not $MockMode) {
    $currentAccount = & $az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (-not $currentAccount -or $currentAccount.tenantId -ne $TenantId) {
        Write-Error "Not logged in to tenant $TenantId. Run: az login --tenant $TenantId"
        exit 1
    }
}

# Create timestamped reports dir
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ss")
$reportsDir = Join-Path $PSScriptRoot "reports\$timestamp"
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
$banner = if ($MockMode) { "  M365 Security Operations Toolkit — MOCK audit run" } else { "  M365 Security Operations Toolkit — audit run" }
Write-Host $banner -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Tenant:        $TenantId"
Write-Host "Subscription:  $SubscriptionId"
Write-Host "Domain:        $Domain"
Write-Host "Reports dir:   $reportsDir"
if ($MockMode) { Write-Host "Mode:          MOCK (no real tenant access)" -ForegroundColor Yellow }
Write-Host ""

$mockArg = @{}
if ($MockMode) { $mockArg = @{ MockMode = $true } }

# Phase 1: DNS + email auth (no Azure resource access needed)
Write-Host ">>> Phase 1: DNS + Email Authentication" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "03-dns-email-auth\audit-dns-posture.ps1") `
        -Domain $Domain `
        -Resolver $Resolver `
        -OutputJsonPath (Join-Path $reportsDir "dns.json") `
        -TenantId $TenantId @mockArg
} catch { Write-Warning "Phase 1 error: $($_.Exception.Message)" }

# Phase 2: Identity hardening
Write-Host ""
Write-Host ">>> Phase 2: Identity Hardening" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "04-identity-hardening\audit-identity-posture.ps1") `
        -TenantId $TenantId `
        -OutputJsonPath (Join-Path $reportsDir "identity.json") @mockArg
} catch { Write-Warning "Phase 2 error: $($_.Exception.Message)" }

# Phase 3: Defender for Office 365 (optional - requires EXO module, fully mocked in mock mode)
Write-Host ""
Write-Host ">>> Phase 3: Defender for Office 365" -ForegroundColor Yellow
try {
    & (Join-Path $PSScriptRoot "02-defender-o365-policy\audit-defender-o365.ps1") `
        -OutputJsonPath (Join-Path $reportsDir "defender-o365.json") `
        -TenantId $TenantId `
        -Domain $Domain @mockArg
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
            -OutputJsonPath (Join-Path $reportsDir "sentinel.json") @mockArg
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
        -TenantId $TenantId @mockArg
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
