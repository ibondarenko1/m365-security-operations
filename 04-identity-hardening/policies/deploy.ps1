# deploy.ps1
# Deploy all 6 baseline Conditional Access policies via Microsoft Graph.
# All policies created in 'enabledForReportingButNotEnforced' (report-only) mode.
# Operator must monitor sign-in logs 7-14 days before switching to 'enabled'.
# Usage: .\deploy.ps1 -BreakGlassUserId <id> -ServiceAccountsGroupId <id> [-Policies <comma-separated>]

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $BreakGlassUserId,

    [string] $ServiceAccountsGroupId = $null,

    [string[]] $Policies = @(
        "01-block-legacy-auth.json",
        "02-require-mfa-all-admins.json",
        "03-require-mfa-all-users.json",
        "04-block-high-risk-signin.json",
        "05-require-password-change-high-risk-user.json",
        "06-require-compliant-device-management.json"
    )
)

$az = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
if (-not (Test-Path $az)) { $az = "az" }

$token = & $az account get-access-token --resource "https://graph.microsoft.com" --query accessToken -o tsv 2>$null
if (-not $token) { Write-Error "Run 'az login' first."; exit 1 }
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

$policyDir = $PSScriptRoot

foreach ($policyFile in $Policies) {
    $path = Join-Path $policyDir $policyFile
    if (-not (Test-Path $path)) {
        Write-Warning "Policy file not found: $path"
        continue
    }
    Write-Host "Deploying $policyFile..."

    $body = Get-Content $path -Raw
    $body = $body.Replace("<user-id-break-glass>", $BreakGlassUserId)
    if ($ServiceAccountsGroupId) {
        $body = $body.Replace("<group-id-service-accounts>", $ServiceAccountsGroupId)
    }

    # Strip _metadata before PUT (Graph rejects unknown fields)
    $obj = $body | ConvertFrom-Json
    $obj.PSObject.Properties.Remove("_metadata")
    $body = $obj | ConvertTo-Json -Depth 10

    if ($body -match "<group-id-") {
        Write-Warning "Policy $policyFile still contains unresolved <group-id-*> placeholders. Skipping. Replace manually."
        continue
    }

    try {
        $res = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Method POST -Headers $headers -Body $body -ErrorAction Stop
        Write-Host "  Deployed. Policy ID: $($res.id). State: $($res.state)" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Deployment complete. All policies are in report-only mode."
Write-Host "Monitor sign-in logs for 7-14 days, then switch policies to 'enabled' state via:"
Write-Host "  az rest --method PATCH --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>' --body '{\"state\":\"enabled\"}'"
