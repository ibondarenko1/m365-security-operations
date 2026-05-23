#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.0.0" }

# Pester smoke tests for audit scripts - validates parameter binding + script parsing,
# without actually running against a real tenant.

# All paths resolved absolutely at file-load time (Pester 5 -ForEach is sensitive to timing)
$repoRoot = Split-Path -Parent $PSScriptRoot

$auditScriptCases = @(
    @{ Path = (Join-Path $repoRoot "01-sentinel-detection-engineering/audit-sentinel.ps1");      Name = "audit-sentinel.ps1" }
    @{ Path = (Join-Path $repoRoot "02-defender-o365-policy/audit-defender-o365.ps1");           Name = "audit-defender-o365.ps1" }
    @{ Path = (Join-Path $repoRoot "03-dns-email-auth/audit-dns-posture.ps1");                   Name = "audit-dns-posture.ps1" }
    @{ Path = (Join-Path $repoRoot "04-identity-hardening/audit-identity-posture.ps1");          Name = "audit-identity-posture.ps1" }
    @{ Path = (Join-Path $repoRoot "05-governance/audit-defender-cloud.ps1");                    Name = "audit-defender-cloud.ps1" }
)

$remediationCases = @(
    @{ Path = (Join-Path $repoRoot "02-defender-o365-policy/templates/enable-impersonation-protection.ps1");  Name = "enable-impersonation-protection.ps1" }
    @{ Path = (Join-Path $repoRoot "02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1");    Name = "add-tenant-allow-list-entries.ps1" }
    @{ Path = (Join-Path $repoRoot "02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1");     Name = "apply-strict-preset-to-group.ps1" }
    @{ Path = (Join-Path $repoRoot "03-dns-email-auth/templates/deploy-mta-sts-dns-cloudflare.ps1");           Name = "deploy-mta-sts-dns-cloudflare.ps1" }
    @{ Path = (Join-Path $repoRoot "04-identity-hardening/policies/deploy.ps1");                              Name = "deploy.ps1" }
)

$orchestratorCases = @(
    @{ Path = (Join-Path $repoRoot "run-audit.ps1");        Name = "run-audit.ps1" }
    @{ Path = (Join-Path $repoRoot "Generate-Report.ps1");  Name = "Generate-Report.ps1" }
)

$caPolicyCases = Get-ChildItem -Path (Join-Path $repoRoot "04-identity-hardening/policies") -Filter "*.json" |
    ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } }

$armCases = Get-ChildItem -Path (Join-Path $repoRoot "01-sentinel-detection-engineering/analytics-rules") -Filter "*.json" |
    ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } }

$kqlCases = Get-ChildItem -Path (Join-Path $repoRoot "01-sentinel-detection-engineering/kql") -Filter "*.kql" |
    ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } }

Describe "Audit script <Name>" -ForEach $auditScriptCases {
    It "exists at <Path>" {
        Test-Path $Path | Should -Be $true
    }

    It "parses without syntax errors" {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content $Path -Raw), [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It "has CmdletBinding attribute" {
        Get-Content $Path -Raw | Should -Match "\[CmdletBinding\(\)\]"
    }

    It "declares OutputJsonPath parameter" {
        Get-Content $Path -Raw | Should -Match "OutputJsonPath"
    }

    It "imports Finding.psm1 module" {
        Get-Content $Path -Raw | Should -Match "Import-Module.*Finding\.psm1"
    }

    It "calls Write-PhaseReport" {
        Get-Content $Path -Raw | Should -Match "Write-PhaseReport"
    }
}

Describe "Remediation template <Name>" -ForEach $remediationCases {
    It "exists" {
        Test-Path $Path | Should -Be $true
    }

    It "parses without syntax errors" {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content $Path -Raw), [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It "has CmdletBinding attribute" {
        Get-Content $Path -Raw | Should -Match "\[CmdletBinding\(\)\]"
    }
}

Describe "Orchestrator <Name>" -ForEach $orchestratorCases {
    It "exists" {
        Test-Path $Path | Should -Be $true
    }

    It "parses without syntax errors" {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content $Path -Raw), [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }
}

Describe "Conditional Access policy library" {
    It "has at least 6 baseline policies" {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $count = (Get-ChildItem -Path (Join-Path $repoRoot "04-identity-hardening/policies") -Filter "*.json").Count
        $count | Should -BeGreaterOrEqual 6
    }
}

Describe "CA policy <Name>" -ForEach $caPolicyCases {
    It "is valid JSON" {
        { Get-Content $Path -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It "has _metadata block" {
        $obj = Get-Content $Path -Raw | ConvertFrom-Json
        $obj._metadata | Should -Not -BeNullOrEmpty
    }

    It "has framework_controls in _metadata" {
        $obj = Get-Content $Path -Raw | ConvertFrom-Json
        $obj._metadata.framework_controls | Should -Not -BeNullOrEmpty
    }
}

Describe "Sentinel Analytics Rule ARM templates" {
    It "has at least 5 ARM templates" {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $count = (Get-ChildItem -Path (Join-Path $repoRoot "01-sentinel-detection-engineering/analytics-rules") -Filter "*.json").Count
        $count | Should -BeGreaterOrEqual 5
    }
}

Describe "ARM template <Name>" -ForEach $armCases {
    It "is valid JSON" {
        { Get-Content $Path -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    # ARM templates use Microsoft.OperationalInsights/workspaces/providers/alertRules and reference
    # Microsoft.SecurityInsights via the name property (per ARM nested resource conventions).
    It "declares Sentinel alert rule resource" {
        $content = Get-Content $Path -Raw
        $content | Should -Match "Microsoft\.OperationalInsights/workspaces/providers/alertRules"
        $content | Should -Match "Microsoft\.SecurityInsights"
    }
}

Describe "KQL hunting library" {
    It "has at least 10 KQL templates" {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $count = (Get-ChildItem -Path (Join-Path $repoRoot "01-sentinel-detection-engineering/kql") -Filter "*.kql").Count
        $count | Should -BeGreaterOrEqual 10
    }
}

Describe "KQL file <Name>" -ForEach $kqlCases {
    It "is non-empty" {
        (Get-Content $Path -Raw).Length | Should -BeGreaterThan 100
    }

    It "has a comment header line" {
        (Get-Content $Path -TotalCount 1) | Should -Match "^//"
    }
}
