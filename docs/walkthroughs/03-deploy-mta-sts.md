# Walkthrough: Deploy MTA-STS + TLS-RPT for a Microsoft 365 domain

Inbound mail transport-security hardening. Add MTA-STS (instructs senders to require TLS) and TLS-RPT (aggregate reports of TLS negotiation outcomes).

Time required: ~20 minutes. Cost: $0 with Cloudflare. Other DNS providers may require a small HTTPS host for the policy file.

Assumes M365-managed mail flow with MX targeting `*.mail.protection.outlook.com` and Cloudflare-managed DNS.

---

## Prerequisites

- Domain DNS managed by Cloudflare
- Cloudflare API token with `Zone.DNS.Edit` scope for the zone
- Account ID + Zone ID from Cloudflare dashboard

---

## Step 1: Generate policy ID

Bump this string whenever the policy content changes; senders use it to detect policy refresh.

```powershell
$policyId = -join ((48..57) + (97..102) | Get-Random -Count 16 | ForEach-Object {[char]$_})
```

---

## Step 2: Add DNS records via Cloudflare API

```powershell
$apiToken = "<your-cf-api-token>"
$zoneId = "<your-cf-zone-id>"
$domain = "yourdomain.com"
$tlsRptMailbox = "tls-rpt@$domain"

$headers = @{
    Authorization = "Bearer $apiToken"
    "Content-Type" = "application/json"
}

# MTA-STS TXT
$mtaStsRecord = @{
    type = "TXT"
    name = "_mta-sts.$domain"
    content = "v=STSv1; id=$policyId"
    ttl = 3600
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records" -Method POST -Headers $headers -Body $mtaStsRecord

# TLS-RPT TXT
$tlsRptRecord = @{
    type = "TXT"
    name = "_smtp._tls.$domain"
    content = "v=TLSRPTv1; rua=mailto:$tlsRptMailbox"
    ttl = 3600
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records" -Method POST -Headers $headers -Body $tlsRptRecord
```

Or use the toolkit's wrapper: `03-dns-email-auth/templates/deploy-mta-sts-dns-cloudflare.ps1 -Domain ... -ZoneId ... -ApiToken ... -TlsRptMailbox ...`.

---

## Step 3: Deploy Cloudflare Worker for policy file

The HTTPS-served policy file lives at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`.

1. Cloudflare dashboard > Workers & Pages > Create > "Hello World" template > rename to `mta-sts`.
2. Replace code with content from `03-dns-email-auth/templates/cloudflare-worker.js`.
3. Deploy.
4. Add Worker route: `mta-sts.yourdomain.com/*` → this worker.
5. Add DNS: A record at `mta-sts.yourdomain.com` pointing to `192.0.2.1` (placeholder; the Worker route intercepts before the IP is hit), Proxied via Cloudflare orange-cloud.

---

## Step 4: Verify deployment

External validator: https://aykira.io/mta-sts

Expected output:
- DNS record present (_mta-sts.yourdomain.com TXT)
- Policy file fetched successfully at mta-sts.yourdomain.com/.well-known/mta-sts.txt
- Policy content valid (version, mode, mx, max_age)
- Policy mode = enforce

CLI verification:
```powershell
Resolve-DnsName -Name "_mta-sts.yourdomain.com" -Type TXT
Resolve-DnsName -Name "_smtp._tls.yourdomain.com" -Type TXT
curl -s https://mta-sts.yourdomain.com/.well-known/mta-sts.txt
```

---

## Step 5: Monitor TLS-RPT reports

Daily aggregate reports arrive at `tls-rpt@yourdomain.com`. Each report is a JSON payload listing TLS negotiation outcomes per sending domain over the day. Spikes in failures indicate either policy issue (your MX changed and the MTA-STS policy still lists old hosts) or downgrade-attempt activity.

Sample handling: set up a mailbox rule to forward TLS-RPT reports to a dedicated SOC mailbox or pipe through a parser.

---

## Step 6: Bump policy ID when changing content

If you later modify the policy file (e.g. add a backup MX, change `max_age`), regenerate `policyId` and update the `_mta-sts.yourdomain.com` TXT record. Senders cache policies by ID — they won't refresh until ID changes.

---

## Step 7: Verify via audit toolkit

```powershell
./run-audit.ps1 -TenantId ... -SubscriptionId ... -Domain yourdomain.com
```

DNS phase should now show INFO-level findings for MTA-STS + TLS-RPT (previously P3 NXDOMAIN gaps).

---

## Framework alignment

- NIST CSF 2.0: PR.DS-02, DE.CM-04
- NIST SP 800-177 Rev. 1: Section 4.6 (TLS in SMTP)
- ISO 27001:2022: A.8.20
- RFC 8460 (TLS-RPT), RFC 8461 (MTA-STS)
