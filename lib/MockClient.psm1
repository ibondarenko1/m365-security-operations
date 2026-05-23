# MockClient.psm1
# Drop-in mocks for Graph / ARM / DNS / Exchange Online calls during mock-mode audit runs.
# Each function reads a JSON fixture from examples/fixtures/ and shapes the response
# to match what the real API would return.

$script:FixturesDir = $null

function Initialize-MockClient {
    <#
    .SYNOPSIS
    Set the fixtures directory. Call once at audit-script entry when -MockMode is true.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $FixturesPath
    )
    if (-not (Test-Path $FixturesPath)) {
        throw "Fixtures directory not found: $FixturesPath"
    }
    $script:FixturesDir = (Resolve-Path $FixturesPath).Path
}

function Get-MockFixture {
    <#
    .SYNOPSIS
    Load a fixture JSON file as a PowerShell object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Name
    )
    if (-not $script:FixturesDir) {
        throw "MockClient not initialized. Call Initialize-MockClient first."
    }
    $path = Join-Path $script:FixturesDir "$Name.json"
    if (-not (Test-Path $path)) {
        throw "Fixture not found: $path"
    }
    return Get-Content $path -Raw | ConvertFrom-Json
}

function Invoke-GraphMock {
    <#
    .SYNOPSIS
    Mock for Microsoft Graph API calls. Maps URI path to fixture file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Uri
    )

    # Handle per-role members lookup: /directoryRoles/<id>/members
    if ($Uri -match "/directoryRoles/([0-9a-f-]+)/members") {
        $roleId = $matches[1]
        $allRoles = Get-MockFixture -Name "graph-directory-roles-with-members"
        $role = $allRoles.value | Where-Object { $_.id -eq $roleId }
        if ($role) {
            return [pscustomobject]@{ value = $role.members }
        }
        return [pscustomobject]@{ value = @() }
    }

    # Signin logs - simulate 403 to surface the access-gap finding
    if ($Uri -like "*/auditLogs/signIns*") {
        $fixture = Get-MockFixture -Name "graph-signin-logs-403"
        $err = [System.Net.WebException]::new("403 Forbidden: " + $fixture.error_message)
        throw $err
    }

    $map = @{
        "*/identity/conditionalAccess/policies*" = "graph-conditional-access-policies"
        "*/policies/authorizationPolicy*"         = "graph-authorization-policy"
        "*/directoryRoles*"                       = "graph-directory-roles-with-members"
        "*/users*"                                = "graph-users"
    }
    foreach ($pattern in $map.Keys) {
        if ($Uri -like $pattern) {
            return Get-MockFixture -Name $map[$pattern]
        }
    }
    throw "MockClient: no fixture mapping for URI $Uri"
}

function Invoke-ArmMock {
    <#
    .SYNOPSIS
    Mock for Azure Resource Manager REST API calls.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Uri
    )
    $map = @{
        "*/Microsoft.Security/pricings*"                                              = "arm-pricings"
        "*/Microsoft.Security/secureScores*"                                          = "arm-secure-score"
        "*/Microsoft.OperationalInsights/workspaces/*?*"                              = "arm-workspace"
        "*/Microsoft.SecurityInsights/onboardingStates*"                              = "arm-sentinel-onboarding"
        "*/Microsoft.SecurityInsights/alertRules*"                                    = "arm-analytics-rules"
        "*/providers/microsoft.insights/diagnosticSettings*"                          = "arm-diagnostic-settings"
    }
    foreach ($pattern in $map.Keys) {
        if ($Uri -like $pattern) {
            return Get-MockFixture -Name $map[$pattern]
        }
    }
    throw "MockClient: no fixture mapping for ARM URI $Uri"
}

function Resolve-DnsMock {
    <#
    .SYNOPSIS
    Mock for Resolve-DnsName. Maps name+type to dns-records.json subkeys.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Type
    )
    $dns = Get-MockFixture -Name "dns-records"
    $key = $null
    if ($Name -match "^_mta-sts\." -and $Type -eq "TXT")               { $key = "mta-sts-txt" }
    elseif ($Name -match "^mta-sts\." -and $Type -eq "CNAME")          { $key = "mta-sts-host" }
    elseif ($Name -match "^_smtp\._tls\." -and $Type -eq "TXT")        { $key = "tls-rpt" }
    elseif ($Name -match "^default\._bimi\." -and $Type -eq "TXT")     { $key = "bimi" }
    elseif ($Name -match "^_dmarc\." -and $Type -eq "TXT")             { $key = "dmarc" }
    elseif ($Name -match "^selector1\._domainkey\." -and $Type -eq "CNAME") { $key = "dkim-selector1" }
    elseif ($Name -match "^selector2\._domainkey\." -and $Type -eq "CNAME") { $key = "dkim-selector2" }
    elseif ($Name -match "^autodiscover\." -and $Type -eq "CNAME")     { $key = "autodiscover" }
    elseif ($Type -eq "MX")                                            { $key = "mx" }
    elseif ($Type -eq "TXT")                                           { $key = "spf" }
    elseif ($Type -eq "NS")                                            { $key = "ns" }

    if (-not $key) { throw "MockClient: unmapped DNS query ($Name $Type)" }
    $entry = $dns.$key
    if ($entry.nxdomain) { throw "MockClient: NXDOMAIN simulation for $Name" }

    # Shape result to look like Resolve-DnsName output
    if ($entry.txt) {
        return [pscustomobject]@{ Strings = @($entry.txt); Type = "TXT" }
    } elseif ($entry.target) {
        return [pscustomobject]@{ NameHost = $entry.target; Type = "CNAME" }
    } elseif ($entry.records -and $entry.records[0].nameExchange) {
        return $entry.records | ForEach-Object {
            [pscustomobject]@{ Preference = $_.preference; NameExchange = $_.nameExchange; Type = "MX" }
        }
    } elseif ($entry.records) {
        return $entry.records | ForEach-Object {
            [pscustomobject]@{ NameHost = $_; Type = "NS" }
        }
    }
    return $null
}

function Get-MockExoData {
    <#
    .SYNOPSIS
    Mock for Exchange Online PowerShell cmdlet results.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("AntiPhishPolicy","TenantAllowBlockList","DkimSigningConfig")]
        [string] $CmdletName
    )
    $map = @{
        "AntiPhishPolicy"          = "exo-anti-phish-policy"
        "TenantAllowBlockList"     = "exo-tenant-allow-block"
        "DkimSigningConfig"        = "exo-dkim"
    }
    return Get-MockFixture -Name $map[$CmdletName]
}

Export-ModuleMember -Function Initialize-MockClient, Get-MockFixture, Invoke-GraphMock, Invoke-ArmMock, Resolve-DnsMock, Get-MockExoData
