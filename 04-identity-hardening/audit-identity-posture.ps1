# audit-identity-posture.ps1
# Microsoft Entra ID identity posture sweep via Microsoft Graph API.
# Authenticates via Azure CLI (operator must be az login'd already with appropriate scopes).
# Reports: Conditional Access policies, authorization policy, directory role assignments,
# user counts, and sign-in log access.
# Usage: .\audit-identity-posture.ps1

[CmdletBinding()]
param ()

$az = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
if (-not (Test-Path $az)) { $az = "az" }

$token = & $az account get-access-token --resource "https://graph.microsoft.com" --query accessToken -o tsv 2>$null
if (-not $token) { Write-Error "Failed to acquire Graph access token. Run 'az login' first."; exit 1 }
$headers = @{ Authorization = "Bearer $token" }

function Write-Section([string]$Title) {
    Write-Output ""
    Write-Output "=== $Title ==="
}

Write-Section "Conditional Access policies"
try {
    $ca = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -ErrorAction Stop
    Write-Output "Policy count: $($ca.value.Count)"
    if ($ca.value.Count -gt 0) {
        $ca.value | ForEach-Object {
            Write-Output "----"
            Write-Output "Name: $($_.displayName)"
            Write-Output "State: $($_.state)"
            Write-Output "Created: $($_.createdDateTime)"
            Write-Output "GrantControls: $($_.grantControls.builtInControls -join ', ')"
        }
    }
} catch { Write-Output "ERROR: $($_.Exception.Message)" }

Write-Section "Authorization policy"
try {
    $authz = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Headers $headers -ErrorAction Stop
    Write-Output "BlockMsolPowerShell: $($authz.blockMsolPowerShell)"
    Write-Output "AllowInvitesFrom: $($authz.allowInvitesFrom)"
    Write-Output "AllowedToCreateApps: $($authz.defaultUserRolePermissions.allowedToCreateApps)"
    Write-Output "AllowedToCreateSecurityGroups: $($authz.defaultUserRolePermissions.allowedToCreateSecurityGroups)"
    Write-Output "AllowedToReadOtherUsers: $($authz.defaultUserRolePermissions.allowedToReadOtherUsers)"
} catch { Write-Output "ERROR: $($_.Exception.Message)" }

Write-Section "Directory role assignments (assigned roles only)"
try {
    $roles = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers -ErrorAction Stop
    foreach ($r in $roles.value) {
        $members = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($r.id)/members" -Headers $headers -ErrorAction SilentlyContinue
        if ($members -and $members.value.Count -gt 0) {
            Write-Output "$($r.displayName): $($members.value.Count) member(s)"
            $members.value | ForEach-Object { Write-Output "  - $($_.userPrincipalName)" }
        }
    }
} catch { Write-Output "ERROR: $($_.Exception.Message)" }

Write-Section "User count"
try {
    $users = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$select=displayName,userPrincipalName,userType&`$top=100" -Headers $headers -ErrorAction Stop
    Write-Output "Total users: $($users.value.Count)"
    $users.value | Group-Object userType | ForEach-Object { Write-Output "  $($_.Name): $($_.Count)" }
} catch { Write-Output "ERROR: $($_.Exception.Message)" }

Write-Section "Sign-in log access check"
try {
    $signins = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1" -Headers $headers -ErrorAction Stop
    Write-Output "Accessible. Most recent entry: $($signins.value[0].createdDateTime)"
} catch {
    Write-Output "NOT ACCESSIBLE: $($_.Exception.Message)"
    Write-Output "Resolution: assign Security Reader directory role or AuditLog.Read.All Graph permission to the audit account."
}
