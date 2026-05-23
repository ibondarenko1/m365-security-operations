# audit-defender-cloud.ps1
# Microsoft Defender for Cloud posture audit via Azure REST API.
# Reports: per-plan pricing tier (Free vs Standard), Secure Score current/max,
# recommendation count by severity, summary counts only.
# Usage: .\audit-defender-cloud.ps1 -SubscriptionId <id> -OutputJsonPath reports/<timestamp>/defender-cloud.json

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string] $OutputJsonPath,

    [string] $TenantId = $null,

    [switch] $MockMode,

    [string] $FixturesPath = (Join-Path $PSScriptRoot "..\examples\fixtures")
)

Import-Module (Join-Path $PSScriptRoot "..\lib\Finding.psm1") -Force
if ($MockMode) {
    Import-Module (Join-Path $PSScriptRoot "..\lib\MockClient.psm1") -Force
    Initialize-MockClient -FixturesPath $FixturesPath
}

function Invoke-ArmGet {
    param ([string] $Uri)
    if ($MockMode) {
        return Invoke-ArmMock -Uri $Uri | ConvertTo-Json -Depth 10
    }
    return & $az rest --method get --uri $Uri 2>&1 | Out-String
}

$az = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
if (-not (Test-Path $az)) { $az = "az" }

$findings = New-Object System.Collections.ArrayList
$findingCounter = 0
function Next-Id { $script:findingCounter++; return ("MDC-{0:D3}" -f $script:findingCounter) }

# === Defender plans pricing tier ===
try {
    $pricings = Invoke-ArmGet -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings`?api-version=2024-01-01" | ConvertFrom-Json -ErrorAction Stop

    $freeCount = ($pricings.value | Where-Object { $_.properties.pricingTier -eq "Free" }).Count
    $standardCount = ($pricings.value | Where-Object { $_.properties.pricingTier -eq "Standard" }).Count

    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "Defender for Cloud plans inventory" `
        -Description "Free tier plans: $freeCount. Standard tier plans: $standardCount." `
        -Evidence @{ free_count = $freeCount; standard_count = $standardCount; plans = ($pricings.value | ForEach-Object { @{ name = $_.name; tier = $_.properties.pricingTier } }) }))

    # Flag high-impact plans that are still Free
    $criticalPlans = @("FoundationalCspm","CloudPosture","KeyVaults","Arm","Storage")
    foreach ($plan in $pricings.value) {
        if ($criticalPlans -contains $plan.name -and $plan.properties.pricingTier -eq "Free") {
            $severity = "P3"
            # FoundationalCspm and CloudPosture have free promotions typically — keep as INFO
            if ($plan.name -in @("FoundationalCspm","CloudPosture")) {
                continue
            }
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity $severity `
                -Title "Defender plan on Free tier: $($plan.name)" `
                -Description "$($plan.name) plan is on Free tier. Free provides basic posture only; threat detection, JIT VM access, vulnerability scanning require Standard. Acceptable for tenants without workloads of this type." `
                -FrameworkControls @("MCSB.LT-1","NIST.CSF.DE.CM-04") `
                -RemediationSteps @(
                    "Evaluate whether tenant has workloads of this type that need advanced detection.",
                    "If yes: az security pricing create --name $($plan.name) --tier Standard",
                    "If no workloads: keep Free, document as accepted risk."
                )))
        }
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
        -Title "Defender for Cloud pricing enumeration failed" `
        -Description "Error: $($_.Exception.Message). Audit account may lack Microsoft.Security/pricings/read."))
}

# === Secure Score ===
try {
    $score = Invoke-ArmGet -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores`?api-version=2020-01-01" | ConvertFrom-Json -ErrorAction Stop
    if ($score.value -and $score.value.Count -gt 0) {
        foreach ($s in $score.value) {
            $pct = [math]::Round($s.properties.score.percentage * 100, 1)
            $sev = if ($pct -lt 50) { "P2" } elseif ($pct -lt 80) { "P3" } else { "INFO" }
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity $sev `
                -Title "Secure Score: $($s.name) at $pct%" `
                -Description "Current: $($s.properties.score.current). Max: $($s.properties.score.max). Percentage: $pct%." `
                -FrameworkControls @("MCSB.PV-1","NIST.CSF.ID.RA-01") `
                -RemediationSteps @(
                    "Review individual recommendations in Defender for Cloud portal.",
                    "Each recommendation has framework controls and remediation steps via Microsoft documentation."
                ) `
                -Evidence @{ score_name = $s.name; current = $s.properties.score.current; max = $s.properties.score.max; pct = $pct }))
        }
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Secure Score not yet calculated" `
            -Description "secureScores endpoint returned empty. Defender for Cloud may still be provisioning posture data (typically 24-48 hours after subscription activation)."))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Secure Score read failed" -Description "Error: $($_.Exception.Message)"))
}

# === Recommendation assessments by severity ===
try {
    $assUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/assessments`?api-version=2020-01-01"
    $ass = Invoke-ArmGet -Uri $assUri | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($ass.value -and $ass.value.Count -gt 0) {
        $unhealthy = $ass.value | Where-Object { $_.properties.status.code -eq "Unhealthy" }
        $high   = ($unhealthy | Where-Object { $_.properties.metadata.severity -eq "High" }).Count
        $medium = ($unhealthy | Where-Object { $_.properties.metadata.severity -eq "Medium" }).Count
        $low    = ($unhealthy | Where-Object { $_.properties.metadata.severity -eq "Low" }).Count

        if ($high -gt 0) {
            [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
                -Title "Defender for Cloud high-severity recommendations open" `
                -Description "$high High-severity unhealthy assessments. These are the recommendations Microsoft considers most-critical for the tenant's current resource posture." `
                -FrameworkControls @("MCSB.PV-1","NIST.CSF.ID.RA-01") `
                -DocumentationUrl "https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations" `
                -RemediationSteps @(
                    "Defender for Cloud > Recommendations > filter Severity = High + Status = Unhealthy.",
                    "Address top items via 'Fix' button (one-click remediations) or follow per-recommendation guidance."
                ) `
                -Evidence @{ high = $high; medium = $medium; low = $low }))
        }
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Defender for Cloud recommendations summary" `
            -Description "Open: $high High, $medium Medium, $low Low severity recommendations."))
    }
} catch { }

# === Defender for AI plane status ===
$aiPlan = $pricings.value | Where-Object { $_.name -eq "AI" }
if ($aiPlan -and $aiPlan.properties.pricingTier -eq "Free") {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "Defender for AI plane on Free tier" `
        -Description "Microsoft Defender for AI (formerly Defender for Cloud AI plane) is on Free tier. Tracks model deployments, prompt-injection threats, and AI workload posture. Standard tier is recommended once tenant has production AI workloads." `
        -FrameworkControls @("MCSB.LT-1") `
        -DocumentationUrl "https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection"))
}

# === Continuous export to Sentinel ===
try {
    $exportUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/automations`?api-version=2023-12-01-preview"
    $automations = Invoke-ArmGet -Uri $exportUri | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (-not $automations.value -or $automations.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Defender for Cloud continuous export not configured" `
            -Description "Without continuous export, Defender for Cloud alerts and recommendations stay in MDC and don't flow to Sentinel for unified incident correlation." `
            -FrameworkControls @("NIST.CSF.DE.AE-03") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export" `
            -RemediationSteps @(
                "Defender for Cloud > Environment settings > <subscription> > Continuous export.",
                "Add export target: Event Hub OR Log Analytics workspace (the Sentinel workspace).",
                "Select: Security alerts, Recommendations, Regulatory compliance assessments."
            )))
    }
} catch { }

# === Final write ===
$severityCounts = Get-FindingSeverityCount -Findings $findings
Write-Host ""
Write-Host "Defender for Cloud audit complete"
Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
Write-Host ""

Write-PhaseReport `
    -Phase "defender-cloud" `
    -PhaseDisplayName "Defender for Cloud Posture" `
    -OutputPath $OutputJsonPath `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -AuditScriptVersion "1.0.0" `
    -Findings $findings

Write-Host "Findings written to: $OutputJsonPath"
