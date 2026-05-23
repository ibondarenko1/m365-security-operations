# add-tenant-allow-list-entries.ps1
# Bulk-add allow entries to the Tenant Allow/Block List from a CSV.
# CSV format: Type,Value,ExpirationDays,Notes
#   Type: Sender | Url | FileHash | IP
#   Value: domain, email, URL, hash, or IP per Type
#   ExpirationDays: 30 (default), 90, or 365. Permanent = leave blank.
#   Notes: free-text describing why this allow exists
# Example row: Sender,marketing@censys.com,90,Legit security marketing with broken DKIM
# Usage: .\add-tenant-allow-list-entries.ps1 -EntriesCsv allow-entries.csv

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $EntriesCsv
)

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Error "ExchangeOnlineManagement module required. Install: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser"
    exit 1
}
if (-not (Test-Path $EntriesCsv)) {
    Write-Error "CSV file not found: $EntriesCsv"
    exit 1
}

Connect-ExchangeOnline -ShowBanner:$false

$entries = Import-Csv $EntriesCsv
$added = 0
$failed = 0

foreach ($entry in $entries) {
    $expiration = if ($entry.ExpirationDays) {
        (Get-Date).AddDays([int]$entry.ExpirationDays)
    } else {
        # Permanent
        (Get-Date).AddYears(99)
    }

    try {
        $params = @{
            ListType        = $entry.Type
            Allow           = $true
            Entries         = @($entry.Value)
            Notes           = $entry.Notes
            ExpirationDate  = $expiration
        }
        if (-not $entry.ExpirationDays) {
            $params.NoExpiration = $true
            $params.Remove("ExpirationDate")
        }
        New-TenantAllowBlockListItems @params -ErrorAction Stop | Out-Null
        Write-Host "Added [$($entry.Type)] $($entry.Value) (notes: $($entry.Notes))" -ForegroundColor Green
        $added++
    } catch {
        Write-Host "FAILED [$($entry.Type)] $($entry.Value): $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "Summary: $added added, $failed failed"
Disconnect-ExchangeOnline -Confirm:$false
