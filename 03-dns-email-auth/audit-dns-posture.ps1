# audit-dns-posture.ps1
# Email-auth + transport-security DNS sweep for a Microsoft 365-hosted domain.
# Emits findings as JSON per SCHEMA.md. Console summary printed to stdout.
# Usage: .\audit-dns-posture.ps1 -Domain example.com -OutputJsonPath reports/<timestamp>/dns.json

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string] $Domain,

    [string] $Resolver = "1.1.1.1",

    [Parameter(Mandatory=$true)]
    [string] $OutputJsonPath,

    [string] $TenantId = $null
)

Import-Module (Join-Path $PSScriptRoot "..\lib\Finding.psm1") -Force

function Resolve-OrNull {
    param ([string] $Name, [string] $Type, [string] $Server)
    try {
        $r = Resolve-DnsName -Name $Name -Type $Type -DnsOnly -Server $Server -ErrorAction Stop
        return $r
    } catch {
        return $null
    }
}

function Get-TxtValue {
    param ($Records)
    if (-not $Records) { return $null }
    $txt = $Records | Where-Object { $_.Strings } | Select-Object -First 1
    if ($txt) { return ($txt.Strings -join '') }
    return $null
}

function Get-CnameTarget {
    param ($Records)
    if (-not $Records) { return $null }
    $cname = $Records | Where-Object { $_.NameHost -and $_.Type -eq "CNAME" } | Select-Object -First 1
    if ($cname) { return $cname.NameHost }
    return $null
}

$findings = New-Object System.Collections.ArrayList
$findingCounter = 0
function Next-Id { $script:findingCounter++; return ("DNS-{0:D3}" -f $script:findingCounter) }

# === MX ===
$mx = Resolve-OrNull -Name $Domain -Type "MX" -Server $Resolver
$mxTarget = if ($mx) { ($mx | Where-Object { $_.NameExchange } | Select-Object -First 1).NameExchange } else { $null }
if ($mxTarget) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "MX record points to Microsoft 365 mail" `
        -Description "MX target: $mxTarget. Mail flow is delivered via Microsoft 365 Exchange Online Protection." `
        -FrameworkControls @() `
        -Evidence @{ mx_target = $mxTarget }))
}

# === SPF ===
$spfText = Get-TxtValue (Resolve-OrNull -Name $Domain -Type "TXT" -Server $Resolver | Where-Object { $_.Strings -join '' -match '^v=spf1' })
$spfRecords = Resolve-OrNull -Name $Domain -Type "TXT" -Server $Resolver
$spfText = $null
if ($spfRecords) {
    foreach ($r in $spfRecords) {
        $joined = ($r.Strings -join '')
        if ($joined -match '^v=spf1') { $spfText = $joined; break }
    }
}
if (-not $spfText) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
        -Title "SPF record missing" `
        -Description "No v=spf1 TXT record found on $Domain. Inbound mail from this domain cannot be SPF-validated by receivers; outbound mail is at higher risk of being rejected." `
        -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.4","ISO27001.A.8.20") `
        -RemediationArtifact "03-dns-email-auth/templates/" `
        -RemediationSteps @(
            "Add a TXT record at $Domain with value: v=spf1 include:spf.protection.outlook.com -all",
            "If using auxiliary mail relay (e.g. GoDaddy), include its SPF: v=spf1 include:spf.protection.outlook.com include:secureserver.net -all",
            "Verify with: Resolve-DnsName -Name $Domain -Type TXT"
        )))
} elseif ($spfText -match '\+all|\?all' -or -not ($spfText -match '\-all|\~all')) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
        -Title "SPF record lacks hard fail" `
        -Description "SPF record present but uses permissive qualifier (+all, ?all, or no terminating qualifier). Receivers cannot reliably reject unauthorized mail." `
        -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.4") `
        -RemediationArtifact "03-dns-email-auth/templates/" `
        -RemediationSteps @(
            "Update SPF record to end with -all (hard fail) instead of permissive qualifier.",
            "Current value: $spfText",
            "Recommended: v=spf1 include:spf.protection.outlook.com -all"
        ) `
        -Evidence @{ spf_text = $spfText }))
} else {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
        -Title "SPF record configured with hard fail" `
        -Description "SPF: $spfText" `
        -Evidence @{ spf_text = $spfText }))
}

# === DMARC ===
$dmarcRecords = Resolve-OrNull -Name "_dmarc.$Domain" -Type "TXT" -Server $Resolver
$dmarcText = Get-TxtValue $dmarcRecords
if (-not $dmarcText) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
        -Title "DMARC record missing" `
        -Description "No DMARC record at _dmarc.$Domain. Domain is vulnerable to direct-spoof phishing (attackers can send mail claiming to be from $Domain with no DMARC enforcement)." `
        -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.6","RFC.7489","ISO27001.A.8.20") `
        -RemediationArtifact "03-dns-email-auth/templates/" `
        -RemediationSteps @(
            "Add TXT record at _dmarc.$Domain with value: v=DMARC1; p=none; rua=mailto:dmarc@$Domain",
            "Monitor aggregate reports (rua) for 30 days to identify legitimate senders.",
            "After confirming no FP, upgrade policy: p=none -> p=quarantine -> p=reject."
        )))
} else {
    $policy = if ($dmarcText -match 'p=(\w+)') { $matches[1] } else { 'unknown' }
    if ($policy -eq 'none') {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P2" `
            -Title "DMARC policy set to none (monitoring only)" `
            -Description "DMARC present but policy is 'none' — receivers honor monitoring but do not reject or quarantine unauthorized mail. Move to enforcement after monitoring period." `
            -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.6","RFC.7489") `
            -RemediationArtifact "03-dns-email-auth/templates/" `
            -RemediationSteps @(
                "After 30-day monitoring with no FP in aggregate reports, upgrade to p=quarantine.",
                "After another 30 days at quarantine, upgrade to p=reject for full enforcement.",
                "Current DMARC: $dmarcText"
            ) `
            -Evidence @{ dmarc_text = $dmarcText; policy = $policy }))
    } elseif ($policy -eq 'quarantine') {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
            -Title "DMARC policy set to quarantine (not full reject)" `
            -Description "DMARC at quarantine level. Receivers send unauthorized mail to spam folder. Full rejection (p=reject) is the stricter posture." `
            -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.6","RFC.7489") `
            -RemediationArtifact "03-dns-email-auth/templates/" `
            -RemediationSteps @(
                "After 30+ days at quarantine with stable aggregate reports, upgrade to p=reject.",
                "Current DMARC: $dmarcText"
            ) `
            -Evidence @{ dmarc_text = $dmarcText; policy = $policy }))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "DMARC policy at strictest level (p=reject)" `
            -Description "DMARC enforced. Receivers reject unauthorized mail." `
            -Evidence @{ dmarc_text = $dmarcText; policy = $policy }))
    }
}

# === DKIM selector1 + selector2 ===
foreach ($sel in @("selector1","selector2")) {
    $dkim = Resolve-OrNull -Name "$sel._domainkey.$Domain" -Type "CNAME" -Server $Resolver
    $dkimTarget = Get-CnameTarget $dkim
    if (-not $dkimTarget) {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P1" `
            -Title "DKIM $sel CNAME missing" `
            -Description "$sel._domainkey.$Domain has no CNAME. Microsoft 365 DKIM signing is not properly delegated." `
            -FrameworkControls @("NIST.CSF.PR.DS-02","NIST.800-177.Section-4.5","ISO27001.A.8.20") `
            -RemediationArtifact "03-dns-email-auth/templates/" `
            -RemediationSteps @(
                "In Defender admin center, navigate to Email & Collaboration > Policies > DKIM.",
                "Generate DKIM keys for $Domain.",
                "Microsoft will display two CNAME values to add at the DNS provider.",
                "Add both CNAMEs, wait 30 minutes for propagation, then enable signing in Defender."
            )))
    } else {
        [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "INFO" `
            -Title "DKIM $sel CNAME configured" `
            -Description "$sel._domainkey.$Domain -> $dkimTarget" `
            -Evidence @{ selector = $sel; target = $dkimTarget }))
    }
}

# === MTA-STS TXT + policy host ===
$mtaStsTxt = Get-TxtValue (Resolve-OrNull -Name "_mta-sts.$Domain" -Type "TXT" -Server $Resolver)
$mtaStsHost = Resolve-OrNull -Name "mta-sts.$Domain" -Type "CNAME" -Server $Resolver
if (-not $mtaStsTxt -or -not $mtaStsHost) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
        -Title "MTA-STS not configured" `
        -Description "MTA-STS instructs senders to require TLS when delivering to this domain. Without it, downgrade attacks on inbound mail TLS are possible." `
        -FrameworkControls @("NIST.CSF.PR.DS-02","RFC.8461","ISO27001.A.8.20") `
        -RemediationArtifact "03-dns-email-auth/templates/mta-sts-policy.txt" `
        -RemediationSteps @(
            "Add TXT record at _mta-sts.${Domain}: v=STSv1; id=$(([guid]::NewGuid().ToString('N').Substring(0,16)))",
            "Set up HTTPS endpoint at mta-sts.${Domain} serving /.well-known/mta-sts.txt with policy content (see template).",
            "Use Cloudflare Worker template at 03-dns-email-auth/templates/cloudflare-worker.js if hosting on Cloudflare.",
            "Verify with https://aykira.io/mta-sts or similar MTA-STS validator."
        )))
}

# === TLS-RPT ===
$tlsRpt = Get-TxtValue (Resolve-OrNull -Name "_smtp._tls.$Domain" -Type "TXT" -Server $Resolver)
if (-not $tlsRpt) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
        -Title "TLS-RPT not configured" `
        -Description "TLS-RPT collects daily reports of TLS negotiation outcomes from sending MTAs. Without it, downgrade attempts go undetected." `
        -FrameworkControls @("NIST.CSF.DE.CM-04","RFC.8460","ISO27001.A.8.20") `
        -RemediationArtifact "03-dns-email-auth/templates/" `
        -RemediationSteps @(
            "Add TXT record at _smtp._tls.${Domain}: v=TLSRPTv1; rua=mailto:tls-rpt@${Domain}",
            "Configure the reporting mailbox to receive aggregate reports (typically daily)."
        )))
}

# === BIMI ===
$bimi = Get-TxtValue (Resolve-OrNull -Name "default._bimi.$Domain" -Type "TXT" -Server $Resolver)
if (-not $bimi) {
    [void]$findings.Add((New-Finding -Id (Next-Id) -Severity "P3" `
        -Title "BIMI not configured" `
        -Description "BIMI displays a verified brand logo in Gmail/Yahoo inbox views. Optional. Requires DMARC at enforcement + a Verified Mark Certificate (~`$1500/year)." `
        -FrameworkControls @() `
        -RemediationArtifact $null `
        -RemediationSteps @(
            "Defer unless brand-impersonation is a problem.",
            "If pursuing: obtain VMC from DigiCert or Entrust.",
            "Add TXT at default._bimi.${Domain}: v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
        )))
}

# === Final write ===
$severityCounts = Get-FindingSeverityCount -Findings $findings
Write-Host ""
Write-Host "DNS posture audit complete for $Domain"
Write-Host "  P1: $($severityCounts.P1)  P2: $($severityCounts.P2)  P3: $($severityCounts.P3)  INFO: $($severityCounts.INFO)"
Write-Host ""

Write-PhaseReport `
    -Phase "dns-email-auth" `
    -PhaseDisplayName "DNS and Email Authentication" `
    -OutputPath $OutputJsonPath `
    -TenantId $TenantId `
    -Domain $Domain `
    -AuditScriptVersion "1.0.0" `
    -Findings $findings

Write-Host "Findings written to: $OutputJsonPath"
