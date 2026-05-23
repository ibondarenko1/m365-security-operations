# Finding.psm1
# Shared PowerShell module for emitting findings per SCHEMA.md.
# Audit scripts import this module to standardize their JSON output.

$script:SchemaVersion = "1.0.0"

function New-Finding {
    <#
    .SYNOPSIS
    Construct a Finding object matching SCHEMA.md.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet("P1","P2","P3","INFO","OUT_OF_SCOPE")] [string] $Severity,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Description,
        [string[]] $FrameworkControls = @(),
        [string] $RemediationArtifact = $null,
        [string[]] $RemediationSteps = @(),
        [hashtable] $Evidence = $null
    )
    $obj = [ordered]@{
        id                   = $Id
        severity             = $Severity
        title                = $Title
        description          = $Description
        framework_controls   = $FrameworkControls
        remediation_artifact = $RemediationArtifact
        remediation_steps    = $RemediationSteps
    }
    if ($Evidence) { $obj.evidence = $Evidence }
    return [pscustomobject]$obj
}

function Write-PhaseReport {
    <#
    .SYNOPSIS
    Write a complete phase report to JSON file matching SCHEMA.md top-level structure.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [string] $PhaseDisplayName,
        [Parameter(Mandatory)] [string] $OutputPath,
        [string] $TenantId = $null,
        [string] $SubscriptionId = $null,
        [string] $Domain = $null,
        [string] $AuditScriptVersion = "1.0.0",
        [Parameter(Mandatory)] [array] $Findings
    )
    $report = [ordered]@{
        phase                 = $Phase
        phase_display_name    = $PhaseDisplayName
        tenant_id             = $TenantId
        subscription_id       = $SubscriptionId
        domain                = $Domain
        timestamp_utc         = (Get-Date).ToUniversalTime().ToString("o")
        audit_script_version  = $AuditScriptVersion
        schema_version        = $script:SchemaVersion
        findings              = $Findings
    }
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding utf8 -NoNewline
}

function Get-FindingSeverityCount {
    <#
    .SYNOPSIS
    Tally findings array by severity.
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [array] $Findings)
    $result = [ordered]@{ P1=0; P2=0; P3=0; INFO=0; OUT_OF_SCOPE=0 }
    foreach ($f in $Findings) { $result[$f.severity]++ }
    return $result
}

Export-ModuleMember -Function New-Finding, Write-PhaseReport, Get-FindingSeverityCount
