# apply-strict-preset-to-group.ps1
# Apply the Strict Preset Security Policy to a specific security group of high-risk users.
# Strict Preset enforces aggressive Safe Links, Safe Attachments dynamic detonation, reduced bulk threshold.
# Usage: .\apply-strict-preset-to-group.ps1 -GroupName "sg-high-risk-users"

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $GroupName
)

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Error "ExchangeOnlineManagement module required. Install: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser"
    exit 1
}

Connect-ExchangeOnline -ShowBanner:$false

# Verify group exists
$group = Get-DistributionGroup -Identity $GroupName -ErrorAction SilentlyContinue
if (-not $group) {
    # Try as Mail-enabled security group / Microsoft 365 group
    $group = Get-Recipient -Identity $GroupName -RecipientTypeDetails MailUniversalSecurityGroup,GroupMailbox -ErrorAction SilentlyContinue
}
if (-not $group) {
    Write-Error "Group '$GroupName' not found. Create it first: New-DistributionGroup -Name '$GroupName' -Type 'Security'"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Strict Preset has these underlying policy rules — update each to include the group
$strictAntiPhish = Get-AntiPhishRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
if ($strictAntiPhish) {
    Set-AntiPhishRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add=$GroupName}
    Write-Host "Strict anti-phish: applied to $GroupName" -ForegroundColor Green
}

$strictSafeAttach = Get-SafeAttachmentRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
if ($strictSafeAttach) {
    Set-SafeAttachmentRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add=$GroupName}
    Write-Host "Strict Safe Attachments: applied to $GroupName" -ForegroundColor Green
}

$strictSafeLinks = Get-SafeLinksRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
if ($strictSafeLinks) {
    Set-SafeLinksRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add=$GroupName}
    Write-Host "Strict Safe Links: applied to $GroupName" -ForegroundColor Green
}

$strictAntiSpam = Get-HostedContentFilterRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
if ($strictAntiSpam) {
    Set-HostedContentFilterRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add=$GroupName}
    Write-Host "Strict anti-spam: applied to $GroupName" -ForegroundColor Green
}

Write-Host ""
Write-Host "Strict Preset Security Policy now applies to members of '$GroupName'."
Write-Host "Add users: Add-DistributionGroupMember -Identity '$GroupName' -Member <user@domain>"

Disconnect-ExchangeOnline -Confirm:$false
