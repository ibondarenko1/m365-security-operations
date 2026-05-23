#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.0.0" }

# Pester tests for lib/Finding.psm1 — schema enforcement + helper behavior

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot "lib\Finding.psm1") -Force
    $script:RepoRoot = $repoRoot
}

Describe "New-Finding" {
    It "creates a finding with all required fields" {
        $f = New-Finding -Id "TEST-001" -Severity "P1" -Title "Test" -Description "Test desc"
        $f.id | Should -Be "TEST-001"
        $f.severity | Should -Be "P1"
        $f.title | Should -Be "Test"
        $f.description | Should -Be "Test desc"
        # framework_controls and remediation_steps are present as properties (may be empty)
        $f.PSObject.Properties.Name | Should -Contain "framework_controls"
        $f.PSObject.Properties.Name | Should -Contain "remediation_steps"
    }

    It "preserves null remediation_artifact (not converted to empty string)" {
        $f = New-Finding -Id "TEST-002" -Severity "P2" -Title "T" -Description "D"
        $f.remediation_artifact | Should -BeNullOrEmpty
        # Verify it serializes as null, not ""
        $json = $f | ConvertTo-Json -Depth 5
        $json | Should -Match '"remediation_artifact":\s*null'
    }

    It "preserves string remediation_artifact" {
        $f = New-Finding -Id "TEST-003" -Severity "P3" -Title "T" -Description "D" `
            -RemediationArtifact "04-identity-hardening/policies/"
        $f.remediation_artifact | Should -Be "04-identity-hardening/policies/"
    }

    It "rejects invalid severity values" {
        { New-Finding -Id "TEST-004" -Severity "CRITICAL" -Title "T" -Description "D" } |
            Should -Throw
    }

    It "accepts all valid severity values" {
        foreach ($sev in @("P1","P2","P3","INFO","OUT_OF_SCOPE")) {
            $f = New-Finding -Id "TEST-$sev" -Severity $sev -Title "T" -Description "D"
            $f.severity | Should -Be $sev
        }
    }

    It "includes evidence when provided" {
        $f = New-Finding -Id "TEST-005" -Severity "P1" -Title "T" -Description "D" `
            -Evidence @{ count = 0; api = "/test" }
        $f.evidence.count | Should -Be 0
        $f.evidence.api | Should -Be "/test"
    }

    It "omits evidence field when not provided" {
        $f = New-Finding -Id "TEST-006" -Severity "P1" -Title "T" -Description "D"
        $f.PSObject.Properties.Name | Should -Not -Contain "evidence"
    }
}

Describe "Write-PhaseReport" {
    BeforeEach {
        $script:TempPath = Join-Path ([System.IO.Path]::GetTempPath()) "phase-test-$([guid]::NewGuid()).json"
    }
    AfterEach {
        if (Test-Path $TempPath) { Remove-Item $TempPath -Force }
    }

    It "writes a valid phase report JSON" {
        $f = New-Finding -Id "TEST-001" -Severity "P1" -Title "T" -Description "D"
        Write-PhaseReport -Phase "test-phase" -PhaseDisplayName "Test Phase" `
            -OutputPath $TempPath -Findings @($f)

        Test-Path $TempPath | Should -Be $true
        $obj = Get-Content $TempPath -Raw | ConvertFrom-Json
        $obj.phase | Should -Be "test-phase"
        $obj.phase_display_name | Should -Be "Test Phase"
        $obj.findings.Count | Should -Be 1
        $obj.findings[0].id | Should -Be "TEST-001"
    }

    It "includes schema_version field in output" {
        Write-PhaseReport -Phase "p" -PhaseDisplayName "P" -OutputPath $TempPath -Findings @()
        $obj = Get-Content $TempPath -Raw | ConvertFrom-Json
        $obj.schema_version | Should -Be "1.0.0"
    }

    It "writes valid ISO 8601 timestamp_utc" {
        Write-PhaseReport -Phase "p" -PhaseDisplayName "P" -OutputPath $TempPath -Findings @()
        # Read raw JSON text - avoids ConvertFrom-Json auto-coercing ISO strings to [DateTime]
        # on PowerShell 7+ Linux/Mac which then stringifies via culture-default format.
        $rawJson = Get-Content $TempPath -Raw
        $rawJson | Should -Match '"timestamp_utc"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    }

    It "creates parent directory if needed" {
        $deepPath = Join-Path ([System.IO.Path]::GetTempPath()) "deep/nested/dir/$([guid]::NewGuid()).json"
        Write-PhaseReport -Phase "p" -PhaseDisplayName "P" -OutputPath $deepPath -Findings @()
        Test-Path $deepPath | Should -Be $true
        Remove-Item (Join-Path ([System.IO.Path]::GetTempPath()) "deep") -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "passes through tenant_id, subscription_id, domain" {
        Write-PhaseReport -Phase "p" -PhaseDisplayName "P" -OutputPath $TempPath -Findings @() `
            -TenantId "tenant-x" -SubscriptionId "sub-y" -Domain "example.com"
        $obj = Get-Content $TempPath -Raw | ConvertFrom-Json
        $obj.tenant_id | Should -Be "tenant-x"
        $obj.subscription_id | Should -Be "sub-y"
        $obj.domain | Should -Be "example.com"
    }
}

Describe "Get-FindingSeverityCount" {
    It "tallies findings by severity correctly" {
        $findings = @(
            (New-Finding -Id "X-1" -Severity "P1" -Title "T" -Description "D"),
            (New-Finding -Id "X-2" -Severity "P1" -Title "T" -Description "D"),
            (New-Finding -Id "X-3" -Severity "P2" -Title "T" -Description "D"),
            (New-Finding -Id "X-4" -Severity "INFO" -Title "T" -Description "D")
        )
        $counts = Get-FindingSeverityCount -Findings $findings
        $counts.P1 | Should -Be 2
        $counts.P2 | Should -Be 1
        $counts.P3 | Should -Be 0
        $counts.INFO | Should -Be 1
        $counts.OUT_OF_SCOPE | Should -Be 0
    }

    It "returns zero counts for empty findings array" {
        $counts = Get-FindingSeverityCount -Findings @()
        $counts.P1 | Should -Be 0
        $counts.P2 | Should -Be 0
        $counts.P3 | Should -Be 0
    }
}
