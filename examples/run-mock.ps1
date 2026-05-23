# run-mock.ps1
# One-liner: clone the repo, run this script, get a full sample report in 30 seconds.
# No Azure access, no az login, no tenant required. Uses fixtures in examples/fixtures/.

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

& (Join-Path $repoRoot "run-audit.ps1") -MockMode

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Mock audit complete." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Open the latest report:"
Write-Host "  Get-ChildItem reports -Directory | Sort-Object Name -Descending | Select-Object -First 1"
Write-Host "  cat reports\<latest>\report.md"
Write-Host ""
