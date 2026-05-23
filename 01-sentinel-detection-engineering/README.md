# Microsoft Sentinel Detection Engineering

Methodology for deploying Microsoft Sentinel on a Log Analytics workspace, authoring MITRE ATT&CK-mapped Scheduled Analytics Rules, and running KQL hunting drills against Defender XDR telemetry.

---

## Deployment principles

**Subscription-level provider registration order matters.** Sentinel onboarding fails on a fresh subscription if any of these providers are unregistered. Register before workspace creation:

- `Microsoft.OperationalInsights` — Log Analytics
- `Microsoft.OperationsManagement` — Sentinel solution wrapper
- `Microsoft.SecurityInsights` — Sentinel API surface
- `Microsoft.Insights` — diagnostic settings (Activity Log routing)
- `Microsoft.Security` — Defender for Cloud assessments

Each is idempotent. Registration takes 1-5 minutes per provider. They can be registered in parallel.

**Workspace SKU and retention floor.** `PerGB2018` is the modern pay-per-GB ingestion SKU. Retention floor is 30 days (free); longer retention is billable. Apply a daily ingestion cap (`workspaceCapping.dailyQuotaGb`) as a hard physical limit independent of any budget alert. Caps are non-overridable at the data plane and protect against runaway connectors.

**Onboarding state PUT registers the workspace with Sentinel.** Without this PUT against `Microsoft.SecurityInsights/onboardingStates/default`, the workspace exists in Log Analytics but is not visible to Sentinel APIs or UI.

**Decommission discipline.** A workspace can be torn down with `az group delete --name <rg> --yes`, which removes the workspace, all attached Sentinel artifacts (rules, watchlists, hunting queries), and any diagnostic settings pointing into the workspace. The subscription and tenant are not affected.

---

## Activity Log telemetry routing

Subscription-level Activity Log events are routed to the workspace via a diagnostic setting at the subscription scope. The categories that matter for SOC use cases:

| Category | Why it matters |
|---|---|
| Administrative | Resource lifecycle, RBAC changes, deployment operations |
| Security | Defender for Cloud alerts, regulatory compliance events |
| ServiceHealth | Azure service incidents that affect tenant workloads |
| Alert | Azure Monitor alert firings |
| Recommendation | Advisor and Defender recommendations |
| Policy | Azure Policy evaluations and violations |
| Autoscale | Scale-set scaling activity |
| ResourceHealth | Per-resource health transitions |

Events land in the `AzureActivity` table with a 10-15 minute lag from API call to ingestion.

---

## Analytics rule MITRE ATT&CK coverage

Five Scheduled Analytics Rules deployed against `AzureActivity`, each tied to MITRE tactics and techniques. Templates are in `analytics-rules/`. Each rule follows the same Sentinel schema (`kind=Scheduled`, `queryFrequency`, `queryPeriod`, `triggerThreshold`, `tactics`, `techniques`, `eventGroupingSettings`).

| Rule | MITRE Tactic | Technique | Trigger |
|---|---|---|---|
| Suspicious resource deployment | Persistence | T1098 | Any successful write operation |
| Mass resource deletion | Impact | T1485 | 5+ deletes per caller in 5 min |
| Failed Activity spike | Discovery | T1087 | 10+ failures per caller in 5 min |
| RBAC role assignment changes | Privilege Escalation, Persistence | T1098 | Any successful roleAssignment write |
| NSG rule modifications | Defense Evasion | T1562 | Any successful NSG securityRules change |

The MITRE tactic-to-technique mapping must be valid per Microsoft Sentinel's enum. Common mismatches that cause `BadRequest`:

- T1078 (Valid Accounts) is in tactics `InitialAccess`, `Persistence`, `PrivilegeEscalation`, `DefenseEvasion` - NOT `Discovery`
- T1087 (Account Discovery) is in `Discovery`
- T1098 (Account Manipulation) is in `Persistence`, `PrivilegeEscalation`

Validate the mapping before deployment by referencing the [MITRE ATT&CK matrix](https://attack.mitre.org/).

A Fusion rule (Advanced Multistage Attack Detection) is enabled by default at onboarding and uses Microsoft's correlation engine across multiple data sources. No template required.

---

## KQL hunting library

KQL drills live in `kql/`. They run against Microsoft Defender XDR tables (`EmailEvents`, `EmailUrlInfo`, `AlertInfo`, `AlertEvidence`, `ExposureGraphNodes`) via the Defender Advanced Hunting console at `security.microsoft.com/v2/advanced-hunting`, and against Sentinel workspace tables (`AzureActivity`, `Operation`) via Sentinel Logs blade.

**Census drills first.** Before running detection drills, establish what tables actually have data. Empty tables silently produce zero results that look like clean detections. Drill `01-table-census.kql` returns row counts per source table — start there.

**Drill catalog (each is a copy-paste-ready KQL file in `kql/`):**

| Drill | Purpose | SC-200 KQL pattern tested |
|---|---|---|
| 01-table-census | Tables with non-zero row count over a time window | `union withsource=*`, `count()` |
| 02-time-bucket-mailflow | Hourly email volume by delivery action | `bin(Timestamp, 1h)`, `summarize ... by ...` |
| 03-threat-types-summary | Defender-classified threats grouped by classification + action | filter + `summarize` |
| 04-auth-fail-patterns | SPF/DKIM/DMARC/CompAuth combinations + delivery outcome | `parse_json`, `extend`, multi-dim group |
| 05-url-tld-distribution | TLD frequency analysis to spot suspicious TLDs | `split`, `extend`, `dcount` |
| 06-ip-as-url-detection | URLs where domain is a raw IPv4 (classic phishing indicator) | regex matching, `matches regex` |
| 07-display-name-spoofing | Brand impersonation in display name from non-matching sender domain | `case()`, multiple-condition filter |
| 08-keyword-subject-scan | Classic phishing keyword detection in subjects | `has_any` |
| 09-emailevents-emailurlinfo-join | Sender domain to URL domain correlation | `join kind=inner ... on ...` |
| 10-exposuregraph-overview | What asset/config types Defender for Cloud tracks | basic `summarize` on label |

**Time range parameter.** Default to `Timestamp > ago(30d)` in EmailEvents-based drills. Defender Advanced Hunting has a 30-day retention on basic plans; queries beyond that return empty.

---

## False positive recognition

The most consequential analyst work in Sentinel/Defender is recognizing false positives and codifying them as tuning rules. Five FP patterns observed and documented during this engagement:

### Pattern 1: Privacy-forwarding alias domains

Mail-forwarding services (Bugcrowd's `bugcrowdninja.com`, AnonAddy, SimpleLogin, ProtonMail aliases, Hide.com) rewrite envelope sender during relay. The result: emails appear to come from the forwarding service domain even though originating content domain is something else. Detection rules that flag sender-to-URL domain mismatch fire on these legitimately.

Tuning: maintain an exclusion list of known forwarding-service domains. Suppress sender-vs-URL mismatch alerts when sender domain matches the list.

### Pattern 2: Website contact form relays through external hosting

Contact-form submissions sent via third-party website hosting (GoDaddy, Wix, Squarespace) generate emails where the apparent sender is the form submitter (auth-fail because the email isn't really from that domain) and the actual transport is the host's relay. Defender's CompAuth fails and the email is classified as Phish.

Signal: `SenderFromAddress = webcontact@*`, all four authentication checks fail (`SPF=none, DKIM=fail, DMARC=fail, CompAuth=fail`), `EmailDirection = Outbound`, recipient address contains `mail.conversations.godaddy.com` or similar relay pattern.

Tuning: suppress phish classification for outbound mail matching this signal. The original form submission should be evaluated for content, not envelope authentication.

### Pattern 3: B2B SaaS cold-outreach with broken DKIM

SaaS marketing platforms commonly send through providers that don't sign DKIM correctly for the From domain (or use a relay domain that fails DMARC alignment). Defender classifies these as Phish due to authentication failure even though the content is legitimate sales outreach.

Tuning: review TenantAllowBlockList allow entries for known-good marketing domains where DKIM is structurally broken. Lower severity to Spam (Junk) rather than Phish (Block) for this pattern.

### Pattern 4: Newsletter relay through social platforms

LinkedIn's branded-newsletter feature delivers third-party brand newsletters through LinkedIn's mail infrastructure. The display name shows the brand (`Google Cloud via LinkedIn`), the sender domain is `linkedin.com`. Naive display-name spoofing detection flags this even though the convention is intentional and the `" via "` suffix is the transparency indicator.

Tuning: exclude `SenderDisplayName has " via "` (LinkedIn convention) from brand-impersonation detection, or exclude `SenderFromDomain endswith "linkedin.com"` from this signal class.

### Pattern 5: Outbound security research correspondence with payload URLs in body

Vulnerability disclosure emails sent to vendor security teams (MSRC, GHSA reports, bug bounty platforms) contain demonstration URLs that look like attack payloads — cloud metadata endpoints (`169.254.169.254`), loopback addresses (`127.0.0.1`), internal Docker gateways (`172.17.0.1`). IP-as-URL detection rightly flags these as anomalous.

Tuning: for outbound mail from security-research workflow accounts, exclude IP-as-URL detection unless paired with additional adverse signals (recipient is not a known vendor security inbox, content lacks CVE/GHSA references, etc).

**Operational note:** investigating outbound security correspondence exposes pre-disclosure vulnerability details. In a mature SOC, alert rules targeting this signal class should be access-restricted to senior analysts to maintain operational security around active research.

---

## Framework alignment

The Sentinel deployment satisfies the following framework controls:

| Framework | Control | How satisfied |
|---|---|---|
| NIST CSF 2.0 | DE.CM-01 (Networks and network services monitored) | Activity Log diagnostic setting + Sentinel ingestion |
| NIST CSF 2.0 | DE.AE-02 (Potentially adverse events analyzed) | 5 Scheduled Analytics Rules + Fusion |
| NIST CSF 2.0 | RS.AN-01 (Incidents notifications investigated) | Sentinel Incidents queue + analyst KQL drilldowns |
| NIST SP 800-53 | AU-2 (Event Logging) | Activity Log → AzureActivity table |
| NIST SP 800-53 | AU-6 (Audit Record Review, Analysis, Reporting) | KQL hunting library |
| NIST SP 800-53 | SI-4 (System Monitoring) | Sentinel as SIEM |
| ISO 27001:2022 | A.5.25 (Assessment and decision on information security events) | Analytics rules + Fusion |
| ISO 27001:2022 | A.8.16 (Monitoring activities) | Workspace + connectors |
| MITRE ATT&CK | Persistence, Impact, Discovery, Privilege Escalation, Defense Evasion | 5 Scheduled Rules per the mapping table above |

---

## What is intentionally absent

- **Endpoint telemetry (Defender for Endpoint).** No managed endpoints in this engagement, so `DeviceEvents` / `DeviceProcessEvents` / `DeviceLogonEvents` / `DeviceNetworkEvents` are not populated. Adding even a single Windows endpoint via MDE onboarding script unlocks the full DeviceX hunting surface.
- **Office 365 connector.** Defender for Office 365 alerts and EmailEvents flow through the Defender XDR side, not the Sentinel side. Bridging them requires either the Microsoft 365 Defender connector (free 90 days, then per-GB ingestion) or the unified Defender portal which Microsoft is migrating Sentinel into.
- **Custom workbooks.** Workbooks are a Sentinel-visualization layer; this writeup focuses on detection and hunting. Workbooks should follow once a baseline of incident volume exists to justify dashboards.
