# DNS and Email Authentication Posture

Methodology for auditing the DNS zone of a Microsoft 365-hosted domain for email authentication (SPF, DKIM, DMARC), transport security (MTA-STS, TLS-RPT), and brand trust (BIMI). Based on a posture audit of a small-org domain hosted on Cloudflare DNS with M365 mail.

---

## Audit method

Run public DNS lookups against `1.1.1.1` (Cloudflare) or `8.8.8.8` (Google) for each record class. Reading from the user's own resolver risks misleading results if local DNS is cached or proxied. The `audit-dns-posture.ps1` script (in `scripts/`) runs the full record sweep.

| Record | Query | Expected for M365-hosted domain |
|---|---|---|
| MX | `<domain>` MX | `<domain>-com.mail.protection.outlook.com` (priority 0) |
| SPF | `<domain>` TXT | `v=spf1 include:spf.protection.outlook.com -all` (hard fail) |
| DKIM selector1 | `selector1._domainkey.<domain>` CNAME | `selector1-<domain>._domainkey.<tenant>.onmicrosoft.com` (Microsoft signing) |
| DKIM selector2 | `selector2._domainkey.<domain>` CNAME | `selector2-<domain>._domainkey.<tenant>.onmicrosoft.com` (Microsoft signing) |
| DMARC | `_dmarc.<domain>` TXT | `v=DMARC1; p=reject; rua=mailto:<reporting-mailbox>` (strictest) |
| MTA-STS TXT | `_mta-sts.<domain>` TXT | `v=STSv1; id=<timestamp-id>` |
| MTA-STS policy | `mta-sts.<domain>` | Served over HTTPS at `/.well-known/mta-sts.txt` |
| TLS-RPT | `_smtp._tls.<domain>` TXT | `v=TLSRPTv1; rua=mailto:<reporting-mailbox>` |
| BIMI | `default._bimi.<domain>` TXT | `v=BIMI1; l=<logo-svg-url>; a=<vmc-cert-url>` |
| Autodiscover | `autodiscover.<domain>` CNAME | `autodiscover.outlook.com` |

---

## Audit findings (representative)

### Strengths

| Control | State | Note |
|---|---|---|
| MX | M365 only | No backup mail server (acceptable for small org on M365) |
| SPF | `v=spf1` with hard fail `-all`, includes M365 + auxiliary mail relay | Strict |
| DKIM | Both selectors configured, CNAMEd to Microsoft signing infrastructure | Microsoft Defender confirms `Valid` + `Enabled` |
| DMARC | `p=reject` policy with aggregate reporting (`rua`) | Strictest possible enforcement |
| Autodiscover | Properly delegates to `autodiscover.outlook.com` | Outlook auto-config works |

DMARC `p=reject` is uncommon outside of mature security programs. Many enterprises still run `p=none` or `p=quarantine` to monitor before enforcement. Direct `p=reject` indicates the operator chose the strict path. Receivers honoring DMARC will hard-reject any unauthenticated mail claiming to be from the domain.

### Gaps

| Control | State | Impact |
|---|---|---|
| MTA-STS | Not configured (no `_mta-sts.<domain>` TXT, no `mta-sts.<domain>` policy CNAME) | Downgrade attacks on inbound TLS possible |
| TLS-RPT | Not configured | No telemetry on TLS negotiation failures, can't detect downgrade activity |
| BIMI | Not configured | No brand-indicator logo in Gmail/Yahoo inbox display |

---

## Remediation order

**1. Deploy MTA-STS in enforce mode.**

MTA-STS instructs sending MTAs to require TLS when delivering mail to the domain. For domains delivering via M365 (which always supports TLS), enforce mode is safe.

Required setup:
- TXT record `_mta-sts.<domain>`: `v=STSv1; id=<unique-id-string>`
- Policy file served at `https://mta-sts.<domain>/.well-known/mta-sts.txt` with content:
  ```
  version: STSv1
  mode: enforce
  mx: *.mail.protection.outlook.com
  max_age: 86400
  ```
- DNS record for the `mta-sts.<domain>` hostname (A or CNAME to a host serving the policy file over HTTPS with a valid certificate).

For Cloudflare-hosted domains, the simplest deployment is a Cloudflare Worker or Cloudflare Page serving the policy file. Alternative: any cloud provider with HTTPS-enabled static hosting.

**2. Deploy TLS-RPT.**

TXT record `_smtp._tls.<domain>`: `v=TLSRPTv1; rua=mailto:<reporting-mailbox>@<domain>`

The reporting mailbox receives daily aggregate reports of TLS negotiation outcomes from receiving MTAs. Spike in TLS negotiation failures indicates either MTA-STS policy issue or downgrade attempt.

**3. BIMI — defer unless brand-impersonation is a problem.**

BIMI requires a Verified Mark Certificate (VMC) from a CA like DigiCert or Entrust (~$1500/year), plus a properly formatted SVG logo. The benefit is a logo displayed in Gmail and Yahoo inbox views, which signals authenticated mail. For small orgs without brand-impersonation pressure, BIMI is low-ROI.

---

## Framework alignment

| Framework | Control | Component |
|---|---|---|
| NIST CSF 2.0 | PR.DS-02 (Data-in-transit protected) | DKIM signing, DMARC enforcement, MTA-STS |
| NIST CSF 2.0 | DE.CM-04 (Malicious activity detected) | TLS-RPT downgrade detection |
| NIST SP 800-177 Rev. 1 | Section 4.6 (DMARC) | `p=reject` policy |
| NIST SP 800-177 Rev. 1 | Section 4.4 (SPF) | `v=spf1 ... -all` |
| NIST SP 800-177 Rev. 1 | Section 4.5 (DKIM) | Both selectors enabled and Valid |
| RFC 7489 | DMARC enforcement | `p=reject` + `rua` reporting |
| RFC 8461 | MTA-STS | Pending deployment |
| RFC 8460 | TLS-RPT | Pending deployment |
| ISO 27001:2022 | A.8.20 (Networks security) | TLS enforcement across mail transport |
