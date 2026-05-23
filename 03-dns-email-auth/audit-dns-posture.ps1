# audit-dns-posture.ps1
# Email-auth + transport-security DNS sweep for a Microsoft 365-hosted domain.
# Queries each record class against a public resolver (1.1.1.1) to avoid local-cache bias.
# Usage: .\audit-dns-posture.ps1 -Domain example.com

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [string]$Resolver = "1.1.1.1"
)

$records = @(
    @{ Name = "MX (mail servers)";           Query = $Domain;                        Type = "MX" }
    @{ Name = "SPF (TXT @)";                 Query = $Domain;                        Type = "TXT" }
    @{ Name = "DMARC";                       Query = "_dmarc.$Domain";               Type = "TXT" }
    @{ Name = "DKIM selector1";              Query = "selector1._domainkey.$Domain"; Type = "CNAME" }
    @{ Name = "DKIM selector2";              Query = "selector2._domainkey.$Domain"; Type = "CNAME" }
    @{ Name = "MTA-STS TXT";                 Query = "_mta-sts.$Domain";             Type = "TXT" }
    @{ Name = "MTA-STS policy host";         Query = "mta-sts.$Domain";              Type = "CNAME" }
    @{ Name = "TLS-RPT";                     Query = "_smtp._tls.$Domain";           Type = "TXT" }
    @{ Name = "BIMI default";                Query = "default._bimi.$Domain";        Type = "TXT" }
    @{ Name = "Autodiscover";                Query = "autodiscover.$Domain";         Type = "CNAME" }
    @{ Name = "NS (name servers)";           Query = $Domain;                        Type = "NS" }
)

foreach ($r in $records) {
    Write-Output "=== $($r.Name): $($r.Query) [$($r.Type)] ==="
    try {
        $res = Resolve-DnsName -Name $r.Query -Type $r.Type -DnsOnly -Server $Resolver -ErrorAction Stop
        $res | ForEach-Object {
            if ($_.Strings)           { Write-Output "  TXT: $($_.Strings -join '')" }
            elseif ($_.NameExchange)  { Write-Output "  MX $($_.Preference) -> $($_.NameExchange)" }
            elseif ($_.NameHost)      { Write-Output "  $($_.Type) -> $($_.NameHost)" }
            elseif ($_.IPAddress)     { Write-Output "  $($_.Type) -> $($_.IPAddress)" }
            else                      { Write-Output "  $($_.Type) record present" }
        }
    } catch {
        Write-Output "  [NOT FOUND or NXDOMAIN]"
    }
    Write-Output ""
}
