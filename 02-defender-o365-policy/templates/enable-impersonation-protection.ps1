# enable-impersonation-protection.ps1
# Enroll high-risk users and partner domains in the default anti-phish impersonation protection.
# Usage: .\enable-impersonation-protection.ps1 -ProtectedUsers user1@org.com,user2@org.com -ProtectedDomains partner1.com,partner2.com

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string[]] $ProtectedUsers,

    [string[]] $ProtectedDomains = @(),

    [string] $PolicyName = "Office365 AntiPhish Default"
)

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Error "ExchangeOnlineManagement module required. Install: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser"
    exit 1
}

Connect-ExchangeOnline -ShowBanner:$false

# Build TargetedUsersToProtect array — each entry is "DisplayName;email@domain"
$targetedUsers = @()
foreach ($u in $ProtectedUsers) {
    $user = Get-User -Identity $u -ErrorAction SilentlyContinue
    if ($user) {
        $targetedUsers += "$($user.DisplayName);$($user.WindowsEmailAddress)"
    } else {
        Write-Warning "User not found: $u"
    }
}

$policyParams = @{
    Identity                              = $PolicyName
    TargetedUsersToProtect                = $targetedUsers
    EnableTargetedUserProtection          = $true
    TargetedUserProtectionAction          = "Quarantine"
    TargetedUserQuarantineTag             = "DefaultFullAccessWithNotificationPolicy"
}

if ($ProtectedDomains.Count -gt 0) {
    $policyParams.TargetedDomainsToProtect          = $ProtectedDomains
    $policyParams.EnableTargetedDomainsProtection   = $true
    $policyParams.TargetedDomainProtectionAction    = "Quarantine"
    $policyParams.TargetedDomainQuarantineTag       = "DefaultFullAccessWithNotificationPolicy"
}

Set-AntiPhishPolicy @policyParams

Write-Host "Anti-phish impersonation protection updated:"
Write-Host "  Protected users: $($targetedUsers.Count)"
Write-Host "  Protected domains: $($ProtectedDomains.Count)"
Write-Host "  Action on detection: Quarantine"

Disconnect-ExchangeOnline -Confirm:$false
