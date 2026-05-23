# Threat Model

Honest scope statement: what this toolkit catches, what it doesn't, and what assumptions underlie both.

---

## What the toolkit catches

### Identity-layer threats

| Threat | Detection mechanism |
|---|---|
| No granular access controls (Security Defaults only) | Zero CA policies finding |
| Excessive standing Global Administrators | GA count > 2 finding |
| Permissive default user permissions (any user can invite guests / create apps) | Authorization policy findings |
| Legacy auth path open (MSOL PowerShell) | `blockMsolPowerShell=false` finding |
| Sign-in log forensics inaccessible to audit account | 403 on sign-in logs finding |
| Multi-role standing admin assignment | Per-user role aggregation finding |
| SMS-based MFA enabled tenant-wide | Authentication methods policy finding |
| FIDO2 not enabled | Authentication methods policy finding |
| Permissive user app-consent policy (consent-phishing exposure) | Permission grant policy finding |
| Service principal credentials expiring within 60 days | SP credential audit finding |
| No named locations defined | Conditional Access named locations finding |
| Cross-tenant inbound B2B unrestricted | XTAP policy finding |
| Sign-in risk policy disabled (Identity Protection) | Identity Protection finding |
| Self-service password reset disabled | SSPR finding |

### Email-security threats

| Threat | Detection mechanism |
|---|---|
| Anti-phish impersonation protection not enrolled | Zero protected users/domains finding |
| Tenant Allow/Block List empty | Entry count finding |
| Strict Preset not applied | Preset assignment finding |
| ZAP for phish/spam disabled | ZAP state finding |
| Outbound spam threshold too permissive | Recipient limit finding |
| Outbound spam admin notification missing | Notification recipient finding |
| Transport rules accumulating | Rule count finding |
| No attack simulation training campaigns | Campaign count finding |

### DNS / transport threats

| Threat | Detection mechanism |
|---|---|
| Missing SPF / DMARC / DKIM | Per-record NXDOMAIN finding |
| SPF permissive (no hard fail) | SPF text analysis |
| DMARC at p=none or p=quarantine (not enforcing) | DMARC policy parse |
| MTA-STS not configured (TLS downgrade attacks) | NXDOMAIN finding |
| TLS-RPT not configured (downgrade detection) | NXDOMAIN finding |
| BIMI not configured | NXDOMAIN finding |
| CAA records missing (cert mis-issuance) | NXDOMAIN finding |
| DNSSEC not deployed (DNS cache poisoning) | No DS record finding |
| SPF approaching RFC 7208 lookup limit | SPF text count |
| DMARC sub-policy not explicit | DMARC parse |

### Sentinel / detection-engineering threats

| Threat | Detection mechanism |
|---|---|
| Sentinel not onboarded | Onboarding state check |
| Workspace not present | Workspace existence check |
| Daily ingestion uncapped | workspaceCapping.dailyQuotaGb check |
| Activity Log not routed to workspace | Diagnostic setting check |
| Few or no analytics rules | Rule count |
| Fusion disabled | Rule kind check |
| No data connectors | Connector enumeration |
| No workbooks deployed | Workbook count |
| No hunting queries | Saved search count |
| No automation playbooks | Logic App count |
| No watchlists | Watchlist count |
| UEBA disabled | Entity Analytics endpoint |
| No threat intelligence indicators | TI table count |

### Cloud-workload threats

| Threat | Detection mechanism |
|---|---|
| Defender for Cloud plans on Free tier when workloads present | Per-plan tier check |
| Secure Score not calculated | secureScores endpoint |
| High-severity recommendations open | Assessment status code |
| Continuous export to Sentinel not configured | Automation endpoint |

---

## What the toolkit does NOT catch

### Out of scope by design

| Domain | Why excluded | Where to look instead |
|---|---|---|
| Endpoint detection + response | No managed endpoints assumed | Defender for Endpoint native + EDR vendor tooling |
| On-premises Active Directory | Cloud-only scope | Defender for Identity, on-prem ATA |
| Data Loss Prevention | Heavier scope, separate product | Microsoft Purview, DLP policies |
| Information protection / sensitivity labels | Out of scope | Microsoft Purview Information Protection |
| eDiscovery / legal hold | Out of scope | Microsoft Purview eDiscovery |
| M365 backup posture | Out of scope | Veeam, Druva, Barracuda, or M365 native retention review |
| Microsoft Teams security configuration | Out of scope (Defender XDR covers Teams email/file phishing) | Teams admin center policies |
| SharePoint / OneDrive sharing policies | Out of scope | M365 admin center sharing settings |
| Power Platform security (Power Apps, Power Automate) | Out of scope | Power Platform admin center |

### Not detected within in-scope domains

The toolkit checks **posture state**, not **active threats**. It will not detect:

- An active credential compromise in progress (no sign-in log analysis)
- A live phishing email landing right now (no real-time mail flow analysis)
- An attacker actively probing the tenant (no live sign-in monitoring)
- A compromised admin account performing legitimate-looking operations (no behavior analytics — UEBA finding flags absence of capability, not active threat)
- Insider threat (no DLP, no user behavior baselining)

For active-threat detection, the toolkit's role is to ensure Sentinel is configured to ingest the right data so OTHER detection content (rules, hunting queries, Fusion ML) can do the work. The toolkit itself is a posture audit.

---

## Assumptions

### About the tenant

- Single Microsoft 365 tenant
- Subscription primarily on Azure (other cloud workloads optional)
- DNS managed by a programmable provider (Cloudflare assumed; others work for audit, remediation templates are Cloudflare-specific)
- M365 mail flow via Exchange Online (`*.mail.protection.outlook.com`)
- No on-premises hybrid (no Exchange Server, no on-prem AD federation)

### About the operator

- Has Security Reader or higher in Entra
- Has Azure CLI logged in with at least Reader on subscription
- Reads PowerShell + KQL
- Operates in good faith — the toolkit doesn't defend against an audit account that is itself the attacker

### About licensing

- Defender for Office 365 Plan 1 minimum (P2 features flagged as such)
- Entra ID P1 minimum (P2 features flagged as out-of-tier when license absent)
- Defender for Cloud Free tier acceptable for tenants without workloads

---

## Trust boundaries

| Surface | Trust level | Notes |
|---|---|---|
| Audit script execution context | High trust | Runs with operator's access |
| Mock fixtures | No trust assumed | All identifiers synthetic; no real data |
| Remediation artifacts (CA policies, PS scripts) | High trust | Deploy to real tenant; review before applying |
| Generated reports (`reports/<timestamp>/*`) | Contain tenant data | `.gitignore` excludes them by default; do not commit |
| Repository contents | Public (post v1.0) | Methodology only; zero tenant data |

---

## What an attacker could do to subvert the toolkit

| Attack | Mitigation |
|---|---|
| Modify Mock fixtures to produce reassuring findings | Mock mode is a demo, never an audit. Real-tenant audit doesn't use fixtures. |
| Modify audit scripts to skip checks | Pin to released tags; review `git diff` between versions. |
| Inject malicious remediation steps via PR | CI catches PSScriptAnalyzer Error severity; reviewer judgment matters. |
| Compromise the audit account to delete real findings | Audit doesn't write to tenant; reports/<timestamp>/ are append-only local. |
| Replay old reports as current posture | Each report contains timestamp_utc + tenant_id in JSON. |

---

## Limitations of the security posture this toolkit can deliver

Even with all findings remediated, the toolkit cannot deliver:

- Network segmentation security (no Azure VNet / NSG audit beyond Sentinel detection rules)
- Application-layer security (no SAST, no DAST, no SBOM)
- Identity governance + access reviews automation (the toolkit reports state, doesn't manage access-review lifecycle)
- Privileged access workflows (no PIM activation automation, no break-glass account testing)
- Threat hunting (provides hunting queries, doesn't perform hunts)
- Incident response (provides playbooks count, doesn't execute response)
- Compliance auditing (maps to framework controls, doesn't generate certification evidence packets)

For these, pair the toolkit with specialized tooling (CIS-CAT, Splunk, Tenable, dedicated GRC platforms).
