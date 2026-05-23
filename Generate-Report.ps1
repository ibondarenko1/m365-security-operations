# Generate-Report.ps1
# Aggregate all per-phase JSON findings in reports/<timestamp>/ into a single markdown report.
# Usage: .\Generate-Report.ps1 -ReportsDir reports/2026-05-22T18-30-12

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $ReportsDir,

    [string] $CompareWith = $null
)

if (-not (Test-Path $ReportsDir)) {
    Write-Error "Reports directory not found: $ReportsDir"
    exit 1
}

$jsonFiles = Get-ChildItem -Path $ReportsDir -Filter "*.json" -File
if ($jsonFiles.Count -eq 0) {
    Write-Error "No JSON findings files found in $ReportsDir"
    exit 1
}

$phases = @()
foreach ($f in $jsonFiles) {
    try {
        $obj = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $phases += $obj
    } catch {
        Write-Warning "Skipping malformed JSON: $($f.Name): $($_.Exception.Message)"
    }
}

# Aggregate stats
$allFindings = @()
foreach ($p in $phases) { $allFindings += $p.findings }

$counts = [ordered]@{ P1=0; P2=0; P3=0; INFO=0; OUT_OF_SCOPE=0 }
foreach ($f in $allFindings) { if ($counts.Contains($f.severity)) { $counts[$f.severity]++ } }

# Unique framework controls touched
$allControls = @()
foreach ($f in $allFindings) { if ($f.framework_controls) { $allControls += $f.framework_controls } }
$controlsByFramework = $allControls | Group-Object { ($_ -split '\.')[0] + '.' + ($_ -split '\.')[1] } | Sort-Object Name

# Output buffer
$sb = New-Object System.Text.StringBuilder
function W { param ($Line) [void]$sb.AppendLine($Line) }

W "# Security Posture Report"
W ""
$ts = if ($phases.Count -gt 0) { $phases[0].timestamp_utc } else { (Get-Date).ToUniversalTime().ToString("o") }
W "Generated: $ts"
W ""
function Get-FirstNonEmpty {
    param ([string] $Field)
    foreach ($p in $phases) {
        $v = $p.$Field
        if ($v -and $v -ne "") { return $v }
    }
    return $null
}
$tenantId = Get-FirstNonEmpty "tenant_id"
$subId    = Get-FirstNonEmpty "subscription_id"
$domain   = Get-FirstNonEmpty "domain"
if ($tenantId) { W "Tenant: ``$tenantId``" }
if ($subId)    { W "Subscription: ``$subId``" }
if ($domain)   { W "Domain: ``$domain``" }
W ""
W "---"
W ""

# Executive summary
W "## Executive summary"
W ""
W "| Severity | Count | Action window |"
W "|---|---|---|"
W "| **P1** (immediate operational risk) | $($counts.P1) | within 1 week |"
W "| **P2** (defense-in-depth gap) | $($counts.P2) | within 30 days |"
W "| **P3** (hygiene / optional) | $($counts.P3) | within 90 days |"
W "| INFO (posture context) | $($counts.INFO) | - |"
W "| OUT_OF_SCOPE | $($counts.OUT_OF_SCOPE) | - |"
W ""

# Severity histogram (ASCII)
$maxCount = ($counts.Values | Measure-Object -Maximum).Maximum
if ($maxCount -gt 0) {
    W "### Severity distribution"
    W ""
    W '```'
    foreach ($sev in @("P1","P2","P3","INFO","OUT_OF_SCOPE")) {
        $c = $counts[$sev]
        $barLen = if ($maxCount -gt 0) { [math]::Round(($c / $maxCount) * 30) } else { 0 }
        $bar = if ($barLen -gt 0) { "#" * $barLen } else { "" }
        $padded = $sev.PadRight(12)
        W "$padded | $($c.ToString().PadLeft(3)) | $bar"
    }
    W '```'
    W ""
}

# Diff with previous run
if ($CompareWith -and (Test-Path $CompareWith)) {
    W "### Diff vs previous run"
    W ""
    $prevPhases = @()
    foreach ($f in (Get-ChildItem -Path $CompareWith -Filter "*.json" -File)) {
        try { $prevPhases += (Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch {}
    }
    $prevFindings = @()
    foreach ($p in $prevPhases) { $prevFindings += $p.findings }
    $prevIds = $prevFindings | ForEach-Object { $_.id }
    $curIds  = $allFindings | ForEach-Object { $_.id }
    $newIds = $curIds | Where-Object { $_ -notin $prevIds }
    $resolvedIds = $prevIds | Where-Object { $_ -notin $curIds }
    W "**New findings since previous run:** $($newIds.Count)"
    foreach ($id in $newIds | Select-Object -First 10) {
        $f = $allFindings | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if ($f) { W "- $id ($($f.severity)): $($f.title)" }
    }
    if ($newIds.Count -gt 10) { W "- ...and $($newIds.Count - 10) more." }
    W ""
    W "**Resolved findings since previous run:** $($resolvedIds.Count)"
    foreach ($id in $resolvedIds | Select-Object -First 10) {
        $f = $prevFindings | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if ($f) { W "- $id ($($f.severity)): $($f.title)" }
    }
    if ($resolvedIds.Count -gt 10) { W "- ...and $($resolvedIds.Count - 10) more." }
    W ""
}

# MITRE ATT&CK tactic coverage
$mitreControls = $allControls | Where-Object { $_ -like "MITRE.*" }
if ($mitreControls.Count -gt 0) {
    $tactics = $mitreControls | ForEach-Object { ($_ -split '\.')[1] } | Sort-Object -Unique
    if ($tactics.Count -gt 0) {
        W "### MITRE ATT&CK tactic coverage"
        W ""
        W "Tactics surfaced by analytics rules + detection content:"
        W ""
        foreach ($t in $tactics) {
            $techs = $mitreControls | Where-Object { ($_ -split '\.')[1] -eq $t } | ForEach-Object { ($_ -split '\.')[2] } | Sort-Object -Unique
            W "- **$t** ($($techs.Count) technique$(if ($techs.Count -ne 1) {'s'})): $($techs -join ', ')"
        }
        W ""
    }
}

# Top 3 P1
$p1 = $allFindings | Where-Object { $_.severity -eq "P1" } | Select-Object -First 3
if ($p1.Count -gt 0) {
    W "### Top P1 findings"
    W ""
    foreach ($f in $p1) {
        W "- **$($f.id):** $($f.title)"
    }
    W ""
}

W "---"
W ""

# Per-phase sections
foreach ($p in $phases) {
    W "## $($p.phase_display_name)"
    W ""
    W "Audit script version: ``$($p.audit_script_version)``. Schema version: ``$($p.schema_version)``."
    W ""
    if ($p.findings.Count -eq 0) {
        W "_No findings reported._"
        W ""
        continue
    }

    W "| ID | Severity | Title | Framework controls | Remediation |"
    W "|---|---|---|---|---|"
    foreach ($f in $p.findings) {
        $controls = if ($f.framework_controls) { ($f.framework_controls -join ", ") } else { "-" }
        $rem = if ($f.remediation_artifact) { "[``$($f.remediation_artifact)``]($($f.remediation_artifact))" } else { "manual" }
        $title = $f.title -replace '\|','\|'
        $controls = $controls -replace '\|','\|'
        W "| $($f.id) | $($f.severity) | $title | $controls | $rem |"
    }
    W ""

    # Findings with detail (P1/P2/P3 only)
    $detailFindings = $p.findings | Where-Object { $_.severity -in @("P1","P2","P3") }
    if ($detailFindings.Count -gt 0) {
        W "### Details"
        W ""
        foreach ($f in $detailFindings) {
            W "#### $($f.id): $($f.title)"
            W ""
            W "_Severity: **$($f.severity)**_"
            W ""
            W "$($f.description)"
            W ""
            if ($f.documentation_url) {
                W "_Reference: [$($f.documentation_url)]($($f.documentation_url))_"
                W ""
            }
            if ($f.remediation_steps -and $f.remediation_steps.Count -gt 0) {
                W "**Remediation steps:**"
                W ""
                $i = 1
                foreach ($s in $f.remediation_steps) {
                    W "$i. $s"
                    $i++
                }
                W ""
            }
        }
    }
    W "---"
    W ""
}

# Consolidated ranked gap list
W "## Consolidated ranked gap list"
W ""
foreach ($sev in @("P1","P2","P3")) {
    $gapsThisSev = $allFindings | Where-Object { $_.severity -eq $sev }
    if ($gapsThisSev.Count -eq 0) { continue }
    W "### $sev"
    W ""
    foreach ($g in $gapsThisSev) {
        $rem = if ($g.remediation_artifact) { " — see ``$($g.remediation_artifact)``" } else { "" }
        W "- **$($g.id):** $($g.title)$rem"
    }
    W ""
}

W "---"
W ""

# Framework coverage matrix
W "## Framework coverage matrix"
W ""
W "Framework controls touched by at least one finding (open or info-level posture confirmation):"
W ""
W "| Framework | Controls touched | Open issues (P1/P2/P3) |"
W "|---|---|---|"
foreach ($fw in $controlsByFramework) {
    $fwControls = $fw.Group | Sort-Object -Unique
    $openOnFw = ($allFindings | Where-Object {
        $_.severity -in @("P1","P2","P3") -and
        ($_.framework_controls | Where-Object { $_ -like "$($fw.Name).*" }).Count -gt 0
    }).Count
    W "| **$($fw.Name)** | $($fwControls.Count) | $openOnFw |"
}
W ""

W "---"
W ""
W "_Generated by Generate-Report.ps1. Source data: $ReportsDir_"

$outPath = Join-Path $ReportsDir "report.md"
$sb.ToString() | Set-Content -Path $outPath -Encoding utf8
Write-Host ""
Write-Host "Report written: $outPath" -ForegroundColor Green
Write-Host "Open with: code $outPath"
