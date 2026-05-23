# r/AZURE post — Day 7

**Subreddit:** r/AZURE (~110K subscribers)

**Why later:** Smaller, more specialized audience. Best landing after r/cybersecurity + r/sysadmin + HN have built initial repo activity. Azure-specific community appreciates polish.

**Posting time:** Sunday afternoon PT (catches Monday-morning EU + US audiences).

**Flair:** "Security" most likely.

---

## Title

```
Sentinel audit + ARM analytics rule templates + Azure security posture toolkit
```

**Why this title:**
- Sentinel + ARM specific (Azure community keywords)
- Posture toolkit (the practitioner-facing framing)
- No "I built" / "released" / "new" (lowest-promotion-feel)

---

## Post body

```
Sharing a v1.0 audit toolkit covering Azure-specific security surfaces for solo defenders running M365 + Cloudflare in small orgs.

Azure-specific content (the parts relevant to /r/AZURE):

**Sentinel detection engineering:**
- Workspace + onboarding audit (provider registration order, daily cap, retention, diagnostic settings)
- 5 ready-to-deploy MITRE-mapped Scheduled Analytics Rule ARM templates (Persistence/T1098, Impact/T1485, Discovery/T1087, PrivEsc+Persistence/T1098, DefenseEvasion/T1562)
- 10 KQL hunting drill templates against EmailEvents, EmailUrlInfo, AlertInfo, AlertEvidence, ExposureGraphNodes
- Data connector audit, workbook audit, hunting query audit, automation playbook audit, watchlist audit, UEBA enablement, threat intelligence indicator ingestion

**Defender for Cloud:**
- Per-plan pricing tier audit (Free vs Standard matching to actual workloads)
- Secure Score percentage check
- Recommendation severity breakdown
- Continuous export to Sentinel verification

**Identity (Entra ID):**
- Conditional Access policy enumeration + 6 baseline policy JSONs ready for Graph PUT
- Authorization policy hardening (block legacy MSOL PowerShell, restrict guest invites, restrict app registration)
- Directory role audit (excessive Global Admin detection, multi-role standing detection)
- Authentication methods policy (SMS deprecation, FIDO2 enablement)
- App consent policy (consent-phishing exposure detection)
- Service principal credential expiration tracking

Built specifically for the "Sentinel + Defender XDR + Cloudflare DNS" stack that small orgs commonly run. Every finding tagged with Microsoft Cloud Security Benchmark controls in addition to NIST/ISO/MITRE.

**30-second demo:**

```
git clone https://github.com/ibondarenko1/m365-security-operations
cd m365-security-operations
./examples/run-mock.ps1
```

Repository: https://github.com/ibondarenko1/m365-security-operations

Walkthroughs:
- docs/walkthroughs/01-deploy-sentinel.md (workspace + onboarding + rules + diagnostic setting + budget alert)
- docs/walkthroughs/04-deploy-conditional-access.md (group IDs + report-only → enforcement sequence)
- docs/walkthroughs/05-defender-cloud-tuning.md (Free vs Standard tier decision matrix)

MIT licensed. 6 ADRs documenting design choices including why PowerShell (not Python) and why single-tenant scope.

Particularly interested in feedback on:
- Sentinel ARM template structure (MITRE tactic/technique mapping at deployment time)
- KQL drill quality + whether the time-bucketing patterns translate to your tenant
- Defender for Cloud tier-decision matrix (whether the recommendations match your actual workload mix)
```

---

## Anticipated comments

**"Should integrate with Bicep modules"**
> "On the v1.1+ roadmap. ARM JSON was the v1.0 path; Bicep equivalents would be a clean PR."

**"My Sentinel workspace looks different from your example"**
> "Mock fixtures represent ONE archetype. Real tenants vary widely. The audit script reads the real workspace state when run with `-WorkspaceName ... -ResourceGroup ...`. If something specific surfaces wrong on your tenant, open an issue with the fixture you'd expect."

**"Sentinel free trial ends in 30 days — your budget alert isn't enough."**
> "Right — 31-day free trial covers Sentinel ingestion, not Log Analytics retention or Defender for Cloud Standard plans. The walkthroughs explain. Budget alert + workspace daily cap together give you the cost ceiling."

---

## Expected metrics

- 20-100 upvotes
- 5-15 comments
- 10-40 repo stars
- 0-2 issues from thread
- Smaller community = fewer trolls + higher signal/noise
