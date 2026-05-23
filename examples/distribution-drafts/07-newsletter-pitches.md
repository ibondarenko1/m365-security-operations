# Newsletter outreach pitches — Day 8-14

**Why later:** Each editor reads dozens of pitches per week. A pitch sent BEFORE Reddit/HN traction looks like "spray and pray." Pitch AFTER 50+ stars + thread activity → editor sees credible launch + community interest.

**Cadence:** ONE pitch per editor per week. Don't blast all three on the same day.

**Reply expectation:** 1-2 weeks. Editors are slow. Don't follow up sooner than 10 days.

---

## Newsletter 1: Detection Engineering Weekly (Florian Roth + community)

**URL:** https://www.detectionengineering.net/

**Contact:** Look up current contact form OR Twitter/Bluesky DM Florian directly (@cyb3rops).

**Why this newsletter:** Most-aligned audience — detection engineers are the primary user persona for the Sentinel side of this toolkit.

**Pitch (email body):**

```
Subject: Open-source M365 + Cloudflare detection-engineering toolkit (v1.0 just released)

Hi Florian,

I noticed Detection Engineering Weekly has covered open-source SIEM tooling and detection content in past issues. Wanted to send a quick pitch in case it fits.

I just released v1.0 of an audit-and-remediate toolkit for solo defenders running Microsoft 365 + Cloudflare in small organizations. Key detection-engineering content:

- 5 MITRE-mapped Scheduled Analytics Rule ARM templates (T1098, T1485, T1087, T1562) ready for deployment via az deployment group create
- 10 KQL hunting drill templates demonstrating SC-200 KQL patterns (bin time-bucketing, multi-table joins, parse_json auth extraction, regex IP-as-URL detection)
- Sentinel posture audit script checking: workspace daily quota, retention, onboarding state, analytics rules count, Fusion enablement, data connectors, workbooks, hunting queries, watchlists, UEBA, threat intelligence ingestion
- 5 false-positive tuning patterns documented (privacy-forwarding aliases, contact-form relay through GoDaddy, B2B SaaS broken-DKIM cold-outreach, LinkedIn branded newsletter via-attribution, outbound security disclosure IP-as-URL payloads)

Repository: https://github.com/ibondarenko1/m365-security-operations

Mock mode: `git clone` + `./examples/run-mock.ps1` produces full sample report in 30 seconds without Azure access.

The FP-tuning patterns are the part I think Detection Engineering Weekly readers would find most useful — they're surfaced from real tenant runs and translate to tuning logic any Sentinel/Defender XDR operator can apply.

MIT licensed. Solo project but with a 12-month maintenance commitment per ROADMAP.

If this fits, happy to provide whatever framing works for your Issue format. If not, no worries.

Thanks,
Ievgen Bondarenko
```

---

## Newsletter 2: TLDR Cyber

**URL:** https://tldr.tech/cyber

**Submission:** TLDR has a submit form. Quick + brief.

**Pitch:**

```
Subject: Open-source M365 + Cloudflare audit toolkit (v1.0 release)

v1.0 of a single-tenant Microsoft 365 audit-and-remediate toolkit released today. Targets solo defenders in small orgs (5-50 users). Five domains audited in one PowerShell command (Sentinel, Defender for O365, DNS + email auth, Entra ID identity, Defender for Cloud). ~60 framework-tagged checks (NIST CSF, NIST 800-53, ISO 27001, MITRE ATT&CK, MCSB).

Differentiator: every finding links to a ready-to-deploy remediation artifact (Conditional Access policy JSONs, Sentinel ARM templates, KQL hunting drills, Exchange Online PowerShell scripts, Cloudflare deployment kit). Most posture audit tooling tells you what's wrong without giving you the deploy package.

Mock mode for 30-second demo without any Azure access. MIT licensed.

https://github.com/ibondarenko1/m365-security-operations

Ievgen Bondarenko
```

---

## Newsletter 3: Risky Business News

**URL:** https://news.risky.biz/

**Contact:** Catalin Cimpanu via Twitter/Mastodon. Skim recent issues to see what kind of items get included.

**Caveat:** Risky Biz News covers breaches, vendor news, threat-actor activity. Open-source tools occasionally featured but rarely as primary item. Lower hit rate than DE Weekly.

**Pitch (only if newsletter has historically covered analogous open-source releases):**

```
Subject: Open-source M365 + Cloudflare audit toolkit (v1.0 release)

Hi Catalin,

Wanted to flag a release in case it fits Risky Biz News. v1.0 of an open-source audit-and-remediate toolkit for Microsoft 365 + Cloudflare environments, released today.

Single-tenant, small-org positioning. Differentiated from CISA ScubaGear (federal-grade audit) and CIPP (multi-tenant MSP) by pairing audit with ready-to-deploy remediation artifacts. Every finding (~60 across 5 domains) links to a Conditional Access policy JSON, Sentinel ARM template, KQL hunting drill, or Exchange Online PowerShell script.

Mock mode lets anyone evaluate without Azure access in 30 seconds.

https://github.com/ibondarenko1/m365-security-operations

If it doesn't fit, no worries. Just wanted to make sure it crossed your desk.

Ievgen Bondarenko
```

---

## Other newsletters to consider after primary 3 land

- SOC Goulash (https://socgoulash.com) — podcast + newsletter; pitch a guest segment
- Security Affairs (Pierluigi Paganini)
- The Hacker News (more breaking-news focused, lower fit)
- Crying Out Cloud (Wiz newsletter)
- The Aviation Newsletter (some security crossover audience)

## What to do after sending

- Mark sent date in calendar
- Don't follow up before day 10
- If no response by day 14: silent decline, accept and move on
- If accepted: editor will likely ask for clarifying detail or screenshot — respond same-day
- If declined with feedback: extract the feedback, improve next time

## Honest expectation

Most pitches won't get picked up. That's normal. The win is:
- Subject line in editor's mailbox (puts your project on their radar even if not run this issue)
- 1 pickup in 3 tries is good
- Pickup → 200-500 new visitors to repo
