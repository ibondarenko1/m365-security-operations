# deploy-mta-sts-dns-cloudflare.ps1
# Add MTA-STS TXT records to a Cloudflare-managed DNS zone via Cloudflare API v4.
# Adds two records:
#   1. TXT _mta-sts.<domain> with policy id (random 16-char hex, bump on policy change)
#   2. TXT _smtp._tls.<domain> with TLS-RPT reporting destination
# Note: this script only manages DNS. You must separately set up the HTTPS endpoint
# serving mta-sts.<domain>/.well-known/mta-sts.txt (see cloudflare-worker.js).
# Usage: .\deploy-mta-sts-dns-cloudflare.ps1 -Domain example.com -ZoneId <cf-zone-id> -ApiToken <cf-api-token> -TlsRptMailbox tls-rpt@example.com

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $Domain,

    [Parameter(Mandatory=$true)]
    [string] $ZoneId,

    [Parameter(Mandatory=$true)]
    [string] $ApiToken,

    [Parameter(Mandatory=$true)]
    [string] $TlsRptMailbox,

    [string] $PolicyId = $null
)

if (-not $PolicyId) {
    $PolicyId = -join ((48..57) + (97..102) | Get-Random -Count 16 | ForEach-Object {[char]$_})
}

$headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

function Add-CloudflareTxt {
    param ([string] $Name, [string] $Content)
    $body = @{
        type    = "TXT"
        name    = $Name
        content = $Content
        ttl     = 3600
    } | ConvertTo-Json

    $uri = "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records"
    try {
        $res = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body -ErrorAction Stop
        Write-Host "Added: $Name = $Content" -ForegroundColor Green
        return $res
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exists") {
            Write-Warning "Record $Name already exists. Update manually or delete first."
        } else {
            Write-Error "Failed to add $Name : $msg"
        }
    }
}

Write-Host "Deploying MTA-STS + TLS-RPT DNS records for $Domain..."
Write-Host ""

# MTA-STS TXT
Add-CloudflareTxt -Name "_mta-sts.$Domain" -Content "v=STSv1; id=$PolicyId"

# TLS-RPT TXT
Add-CloudflareTxt -Name "_smtp._tls.$Domain" -Content "v=TLSRPTv1; rua=mailto:$TlsRptMailbox"

# Note: mta-sts.<domain> A record / proxied CNAME must be added manually OR
# via the Cloudflare Worker route — see cloudflare-worker.js for full setup.

Write-Host ""
Write-Host "DNS records deployed. Next steps:"
Write-Host "  1. Deploy cloudflare-worker.js to serve the policy file at https://mta-sts.$Domain/.well-known/mta-sts.txt"
Write-Host "  2. Validate with https://aykira.io/mta-sts or similar"
Write-Host "  3. Configure $TlsRptMailbox to receive aggregate TLS reports"
Write-Host ""
Write-Host "Policy ID generated for this deployment: $PolicyId"
Write-Host "Bump this ID whenever the policy content changes (max_age, mx list, mode)."
