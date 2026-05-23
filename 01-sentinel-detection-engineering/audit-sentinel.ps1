# audit-sentinel.ps1
# Microsoft Sentinel workspace posture audit via Azure REST API.
# Verifies: workspace exists, daily quota set, retention configured, Sentinel onboarded,
# Analytics Rules count, Fusion state, Activity Log diagnostic setting wired.
# Usage: .\audit-sentinel.ps1 -SubscriptionId <id> -ResourceGroup <rg> -WorkspaceName <ws> -OutputJsonPath <path>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string] $ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string] $WorkspaceName,

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
function Next-Id { $script:findingCounter++; return ("SENT-{0:D3}" -f $script:findingCounter) }

$baseWs = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

# === Workspace exists ===
try {
    $ws = Invoke-ArmGet -Uri "$baseWs`?api-version=2023-09-01" | ConvertFrom-Json -ErrorAction Stop
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "Log Analytics workspace present" `
        -Description "Workspace $WorkspaceName exists in $ResourceGroup. SKU: $($ws.properties.sku.name). Retention: $($ws.properties.retentionInDays) days." `
        -Evidence @{ sku = $ws.properties.sku.name; retention_days = $ws.properties.retentionInDays }))

    # Retention check
    if ($ws.properties.retentionInDays -lt 30) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Log Analytics retention below 30 days" `
            -Description "Workspace retention set to $($ws.properties.retentionInDays) days. Default free tier is 30 days. Compliance frameworks typically require 90 days minimum for security telemetry." `
            -FrameworkControls @("NIST.800-53.AU-11","ISO27001.A.5.28") `
            -RemediationSteps @(
                "az monitor log-analytics workspace update --resource-group $ResourceGroup --workspace-name $WorkspaceName --retention-time 90",
                "Note: retention beyond 30 days is billable per GB."
            ) `
            -Evidence @{ current_days = $ws.properties.retentionInDays; recommended_min = 90 }))
    }

    # Daily quota check
    $dailyQuota = $ws.properties.workspaceCapping.dailyQuotaGb
    if ($dailyQuota -eq -1) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "No daily ingestion cap configured" `
            -Description "Workspace has no daily quota (dailyQuotaGb = -1). Runaway connectors or compromised log shipping can produce unbounded ingestion charges." `
            -FrameworkControls @("NIST.CSF.ID.GV-04","ISO27001.A.5.30") `
            -RemediationSteps @(
                "Set a daily cap appropriate to baseline ingestion volume.",
                "az monitor log-analytics workspace update --resource-group $ResourceGroup --workspace-name $WorkspaceName --quota <gb-per-day>"
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Daily ingestion cap configured" `
            -Description "dailyQuotaGb = $dailyQuota. Hard limit against runaway ingestion." `
            -Evidence @{ daily_quota_gb = $dailyQuota }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
        -Title "Log Analytics workspace not found or inaccessible" `
        -Description "Cannot read workspace $WorkspaceName in $ResourceGroup. Error: $($_.Exception.Message). Sentinel cannot function without a workspace." `
        -FrameworkControls @("NIST.CSF.DE.CM-01") `
        -RemediationSteps @(
            "Verify workspace exists: az monitor log-analytics workspace show --resource-group $ResourceGroup --workspace-name $WorkspaceName",
            "Check audit account has Log Analytics Reader role.",
            "If workspace missing: az monitor log-analytics workspace create --resource-group $ResourceGroup --workspace-name $WorkspaceName --location <region>"
        )))
    # Save and exit if workspace doesn't exist
    Write-PhaseReport -Phase "sentinel" -PhaseDisplayName "Sentinel Detection Engineering" `
        -OutputPath $OutputJsonPath -TenantId $TenantId -SubscriptionId $SubscriptionId -AuditScriptVersion "1.0.0" -Findings $findings
    exit 1
}

# === Sentinel onboarding ===
try {
    $onboarding = Invoke-ArmGet -Uri "$baseWs/providers/Microsoft.SecurityInsights/onboardingStates/default`?api-version=2024-09-01" | ConvertFrom-Json -ErrorAction Stop
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "Microsoft Sentinel onboarded on workspace" `
        -Description "Sentinel is enabled on $WorkspaceName."))
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
        -Title "Microsoft Sentinel not onboarded" `
        -Description "Workspace exists but Sentinel is not enabled. Detection content cannot be deployed and KQL is limited to Log Analytics tables only." `
        -FrameworkControls @("NIST.CSF.DE.AE-02","NIST.800-53.SI-4","ISO27001.A.5.25") `
        -RemediationSteps @(
            "Register providers first: az provider register --namespace Microsoft.SecurityInsights --wait",
            "az provider register --namespace Microsoft.OperationsManagement --wait",
            "Onboard: az rest --method put --uri '$baseWs/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-09-01' --body '{\""properties\"":{\""customerManagedKey\"":false}}'"
        )))
}

# === Analytics Rules count ===
try {
    $rules = Invoke-ArmGet -Uri "$baseWs/providers/Microsoft.SecurityInsights/alertRules`?api-version=2024-09-01" | ConvertFrom-Json -ErrorAction Stop
    $ruleCount = $rules.value.Count
    $enabledCount = ($rules.value | Where-Object { $_.properties.enabled }).Count
    $fusionEnabled = ($rules.value | Where-Object { $_.kind -eq "Fusion" -and $_.properties.enabled }).Count -gt 0

    if ($ruleCount -le 1) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Few or no Analytics Rules deployed" `
            -Description "Only $ruleCount rule(s) present (Fusion default counts as 1). Detection coverage is effectively absent." `
            -FrameworkControls @("NIST.CSF.DE.AE-02","NIST.800-53.SI-4","ISO27001.A.5.25") `
            -RemediationArtifact "01-sentinel-detection-engineering/analytics-rules/" `
            -RemediationSteps @(
                "Deploy the 5 MITRE-mapped Scheduled Analytics Rule ARM templates in 01-sentinel-detection-engineering/analytics-rules/.",
                "For each: az deployment group create --resource-group $ResourceGroup --template-file <file>.json --parameters workspaceName=$WorkspaceName"
            ) `
            -Evidence @{ total_rules = $ruleCount; enabled_rules = $enabledCount; fusion_enabled = $fusionEnabled }))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Analytics Rules deployed" `
            -Description "Total: $ruleCount. Enabled: $enabledCount. Fusion: $fusionEnabled." `
            -Evidence @{ total_rules = $ruleCount; enabled_rules = $enabledCount; fusion_enabled = $fusionEnabled }))
    }

    if (-not $fusionEnabled) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "Fusion (Advanced Multistage Attack Detection) not enabled" `
            -Description "Microsoft's correlation engine that detects multi-step attacks across data sources is off. Fusion is free and enabled by default at Sentinel onboarding — turning it off is a deliberate downgrade." `
            -FrameworkControls @("NIST.CSF.DE.AE-03","ISO27001.A.5.25") `
            -RemediationSteps @(
                "Enable Fusion via Sentinel portal: Analytics > Active rules > filter for 'Advanced Multistage' > Enable."
            )))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Analytics rules enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === Activity Log diagnostic setting ===
try {
    $diagUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/microsoft.insights/diagnosticSettings`?api-version=2021-05-01-preview"
    $diag = Invoke-ArmGet -Uri $diagUri | ConvertFrom-Json -ErrorAction Stop
    $wiredToWs = $diag.value | Where-Object { $_.properties.workspaceId -eq $ws.id }
    if (-not $wiredToWs) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "Activity Log not routed to Sentinel workspace" `
            -Description "Subscription Activity Log has no diagnostic setting targeting workspace $WorkspaceName. AzureActivity table will be empty; detection rules against it will never fire." `
            -FrameworkControls @("NIST.CSF.DE.CM-01","NIST.800-53.AU-2","ISO27001.A.8.16") `
            -RemediationSteps @(
                "Create diagnostic setting routing all Activity Log categories to the workspace.",
                "See SCHEMA.md sample or repo docs for the full PUT body."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Activity Log routed to workspace" `
            -Description "Diagnostic setting '$($wiredToWs.name)' routes Activity Log to $WorkspaceName." `
            -Evidence @{ diagnostic_setting_name = $wiredToWs.name }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Diagnostic setting enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === Data connectors ===
try {
    $connectorsUri = "$baseWs/providers/Microsoft.SecurityInsights/dataConnectors`?api-version=2024-09-01"
    $connectors = Invoke-ArmGet -Uri $connectorsUri | ConvertFrom-Json -ErrorAction Stop
    if ($connectors.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "No Sentinel data connectors configured" `
            -Description "Sentinel has zero data connectors. Without connectors, only manually-piped log sources (like diagnostic settings) ingest. Detection coverage is structurally limited." `
            -FrameworkControls @("NIST.CSF.DE.CM-01","NIST.800-53.SI-4") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources" `
            -RemediationSteps @(
                "Identify priority data sources: Azure AD (sign-ins + audit logs), Defender XDR, Office 365.",
                "Sentinel > Content management > Content hub > Install solution per source.",
                "Or via API: PUT each dataConnectors/<id> endpoint."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Sentinel data connectors configured" `
            -Description "$($connectors.value.Count) data connector(s) deployed." `
            -Evidence @{ count = $connectors.value.Count; names = ($connectors.value | ForEach-Object { $_.name }) }))
    }
} catch {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" -Title "Data connectors enumeration failed" -Description "Error: $($_.Exception.Message)"))
}

# === Workbooks ===
try {
    $wbUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks`?api-version=2022-04-01&category=sentinel"
    $workbooks = Invoke-ArmGet -Uri $wbUri | ConvertFrom-Json -ErrorAction Stop
    if ($workbooks.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No Sentinel workbooks deployed" `
            -Description "Workbooks provide visual dashboards over Sentinel data. None deployed means analysts rely on raw KQL queries for situational awareness. Microsoft publishes 50+ free workbook templates." `
            -FrameworkControls @("NIST.CSF.DE.AE-03") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/get-visibility" `
            -RemediationSteps @(
                "Sentinel > Threat management > Workbooks > Templates.",
                "Install: Azure Activity, Identity & Access, Microsoft 365, MITRE ATT&CK Workbook, Investigation Insights."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Sentinel workbooks deployed" `
            -Description "$($workbooks.value.Count) workbook(s)."))
    }
} catch { }

# === Hunting queries ===
try {
    $hqUri = "$baseWs/savedSearches`?api-version=2020-08-01"
    $hq = Invoke-ArmGet -Uri $hqUri | ConvertFrom-Json -ErrorAction Stop
    $huntingCount = ($hq.value | Where-Object { $_.properties.category -eq "Hunting Queries" }).Count
    if ($huntingCount -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No saved hunting queries" `
            -Description "Sentinel has zero saved hunting queries. Hunting is the proactive analyst activity layered above analytics rules. Microsoft and community publish hundreds of curated queries." `
            -FrameworkControls @("NIST.CSF.DE.AE-02") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/hunting" `
            -RemediationSteps @(
                "Sentinel > Threat management > Hunting > Queries.",
                "Install community content via Content hub: 'Hunting Queries' solutions per data source.",
                "Or import from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Hunting queries available" `
            -Description "$huntingCount hunting queries saved."))
    }
} catch { }

# === Automation playbooks (Logic Apps tied to Sentinel) ===
try {
    $autoUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows`?api-version=2019-05-01"
    $playbooks = Invoke-ArmGet -Uri $autoUri | ConvertFrom-Json -ErrorAction Stop
    if ($playbooks.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No Sentinel automation playbooks (Logic Apps)" `
            -Description "Zero Logic Apps in the resource group. Sentinel SOAR functionality depends on playbooks for automated response (enrich, contain, notify, ticket)." `
            -FrameworkControls @("NIST.CSF.RS.MI-02","NIST.800-53.IR-4") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/automation/automation" `
            -RemediationSteps @(
                "Identify high-volume incident types worth automating (e.g. disabled-user-signed-in -> auto-disable, suspicious-ip -> add-to-block-list).",
                "Sentinel > Content hub > install 'SOAR' solutions per use case.",
                "Build custom playbooks via Logic Apps designer + Microsoft Sentinel connector."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Logic Apps present in resource group" `
            -Description "$($playbooks.value.Count) Logic App(s). May or may not be tied to Sentinel — manual review needed."))
    }
} catch { }

# === Watchlists ===
try {
    $wlUri = "$baseWs/providers/Microsoft.SecurityInsights/watchlists`?api-version=2024-09-01"
    $wl = Invoke-ArmGet -Uri $wlUri | ConvertFrom-Json -ErrorAction Stop
    if ($wl.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No Sentinel watchlists" `
            -Description "Watchlists let analytics rules and hunting queries reference curated lists (high-value users, terminated employees, known-bad IPs, vendor IP ranges). Without watchlists, similar logic gets hardcoded in queries — harder to maintain." `
            -FrameworkControls @("NIST.CSF.DE.AE-02") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/watchlists" `
            -RemediationSteps @(
                "Sentinel > Configuration > Watchlists.",
                "Start with: 'High Value Assets' (priority accounts), 'Terminated Employees' (HR feed), 'VIP Users' (executives + finance)."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "Sentinel watchlists configured" `
            -Description "$($wl.value.Count) watchlist(s)."))
    }
} catch { }

# === UEBA / behavior analytics ===
try {
    $uebaUri = "$baseWs/providers/Microsoft.SecurityInsights/settings/EntityAnalytics`?api-version=2024-09-01"
    $ueba = Invoke-ArmGet -Uri $uebaUri | ConvertFrom-Json -ErrorAction SilentlyContinue
    $enabled = $false
    if ($ueba.properties.entityProviders -and $ueba.properties.entityProviders.Count -gt 0) { $enabled = $true }
    if (-not $enabled) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "UEBA (Entity Analytics) not enabled" `
            -Description "Sentinel UEBA derives behavioral baselines and risk scores from sign-in + activity data. Without it, anomaly detection relies on hand-authored thresholds in rules." `
            -FrameworkControls @("NIST.CSF.DE.AE-02","NIST.CSF.DE.AE-03") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/enable-entity-behavior-analytics" `
            -RemediationSteps @(
                "Sentinel > Configuration > Settings > Entity behavior.",
                "Requires Azure AD Identity Protection (Entra ID P2). Toggle on after license available."
            )))
    }
} catch { }

# === Threat intelligence indicators ===
try {
    $tiUri = "$baseWs/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators`?api-version=2024-09-01"
    $tiBody = '{"pageSize":1}'
    $tiBodyFile = "$env:TEMP\ti-query.json"
    if (-not $MockMode) {
        Set-Content -Path $tiBodyFile -Value $tiBody -Encoding utf8 -NoNewline
        $ti = & $az rest --method post --uri $tiUri --body "@$tiBodyFile" 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
    } else {
        # Mock empty TI
        $ti = [pscustomobject]@{ value = @() }
    }
    if ($ti.value.Count -eq 0) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "No threat intelligence indicators ingested" `
            -Description "Sentinel has zero TI indicators (TI tables: ThreatIntelligenceIndicator). Without TI feeds, rules cannot pivot suspicious entities against known-bad lists from MISP, OTX, Microsoft, or commercial feeds." `
            -FrameworkControls @("NIST.CSF.ID.RA-02","NIST.CSF.DE.AE-02") `
            -DocumentationUrl "https://learn.microsoft.com/en-us/azure/sentinel/understand-threat-intelligence" `
            -RemediationSteps @(
                "Sentinel > Content hub > install: Threat Intelligence Platforms (TAXII server) OR Microsoft Defender Threat Intelligence solution.",
                "Configure TAXII feeds: AlienVault OTX (free), Anomali Limo (free), MISP (self-hosted)."
            )))
    }
} catch { }

# === Final write ===
$severityCounts = Get-FindingSeverityCount -Findings $findings
Write-Host ""
Write-Host "Sentinel posture audit complete"
Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
Write-Host ""

Write-PhaseReport `
    -Phase "sentinel" `
    -PhaseDisplayName "Sentinel Detection Engineering" `
    -OutputPath $OutputJsonPath `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -AuditScriptVersion "1.0.0" `
    -Findings $findings

Write-Host "Findings written to: $OutputJsonPath"
