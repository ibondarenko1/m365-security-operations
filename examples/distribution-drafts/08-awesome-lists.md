# Awesome-list submissions

GitHub-internal discovery via community-curated "awesome" lists. Each list = a separate PR. Each PR = 1-3 days curator review.

## Targets (priority order)

### 1. awesome-microsoft-365-security

**URL:** https://github.com/Yamout/awesome-microsoft-365-security

**Best fit.** Most-aligned audience. List groups tools by category (audit, configuration, monitoring). Likely placement: "Audit & Compliance" section.

**PR title:**
```
Add m365-security-operations: audit-and-remediate toolkit for small-org tenants
```

**Entry suggestion (alphabetical sort or by category):**
```markdown
- [m365-security-operations](https://github.com/ibondarenko1/m365-security-operations) - Detect-and-remediate audit toolkit for solo defenders. Five domains (Sentinel, Defender for O365, DNS + email auth, Entra ID, Defender for Cloud), 60+ framework-tagged checks, ready-to-deploy remediation artifacts. Mock mode for 30-second demo. MIT.
```

**PR body:**
```
Submitting `m365-security-operations` for inclusion.

What it is: opinionated audit-and-remediate toolkit for solo defenders running Microsoft 365 + Cloudflare in small organizations. Single PowerShell command audits five domains and produces a markdown report ranking findings P1/P2/P3, with each gap linked to a deployable remediation artifact (Conditional Access policy JSONs, Sentinel ARM templates, KQL hunting drills, Exchange Online PowerShell scripts).

Differentiated from related tools listed here: detect-AND-remediate (not just audit), single-tenant scope (not multi-tenant MSP), commercial small-org (not federal compliance).

Repository: https://github.com/ibondarenko1/m365-security-operations
License: MIT
Active development: v1.0 released [date]; monthly release cadence per ROADMAP

Mock-mode demo path lets reviewers see the output in 30 seconds without any Azure access.
```

---

### 2. awesome-azure-security

**URL:** Various — search for `awesome-azure-security`. Most-maintained: https://github.com/kmcquade/awesome-azure-security (verify currently maintained).

**Placement:** "Security Assessment Tools" section.

**Entry suggestion:**
```markdown
- [m365-security-operations](https://github.com/ibondarenko1/m365-security-operations) - Audit-and-remediate toolkit covering Microsoft Sentinel, Defender for Cloud, Entra ID Conditional Access, and Azure subscription posture. ~60 framework-tagged checks; ready-to-deploy ARM templates + PowerShell remediation scripts. MIT.
```

---

### 3. awesome-sentinel

**URL:** https://github.com/Yamout/awesome-sentinel (verify maintainer)

**Placement:** "Tools" or "Audit & Assessment" section.

**Entry:**
```markdown
- [m365-security-operations](https://github.com/ibondarenko1/m365-security-operations) - Includes Sentinel-specific audit (data connectors, workbooks, hunting queries, playbooks, watchlists, UEBA, threat intelligence) + 5 MITRE-mapped Scheduled Analytics Rule ARM templates + 10 KQL hunting drill templates. MIT.
```

---

### 4. awesome-detection-engineering

**URL:** https://github.com/infosecB/awesome-detection-engineering

**Placement:** "Detection Engineering Resources" or "Tools" section.

**Entry:**
```markdown
- [m365-security-operations](https://github.com/ibondarenko1/m365-security-operations) - Microsoft Sentinel detection engineering: 5 MITRE-mapped Scheduled Analytics Rule ARM templates (Persistence/T1098, Impact/T1485, Discovery/T1087, PrivEsc+Persistence/T1098, DefenseEvasion/T1562) + 10 KQL hunting drills + 5 documented FP-tuning patterns. MIT.
```

---

### 5. awesome-soc

**URL:** https://github.com/cyb3rxp/awesome-soc

**Placement:** "Open-source tools" section.

**Entry:**
```markdown
- [m365-security-operations](https://github.com/ibondarenko1/m365-security-operations) - SOC operations toolkit for solo defenders in small orgs running Microsoft 365 + Cloudflare. Five-domain audit + remediation: SIEM (Sentinel), email security (Defender for O365), DNS/email-auth, identity (Entra ID CA + roles), cloud posture (Defender for Cloud). MIT.
```

---

## Submission strategy

**Cadence:** ONE PR per week per list. Curators get tired of `-related` author batch submissions.

**Order:** Submit in priority order — list 1 first. Wait 1 week for response. List 2 next week. List 3 the week after.

**Why staggered:** If list 1 rejects with specific feedback (e.g. "needs more depth in X"), apply that feedback BEFORE submitting list 2. Saves N-1 wasted submissions.

**Expected acceptance rate:** 2-3 out of 5. Reasons for rejection: list considered the domain saturated, maintainer inactive, list won't accept newly-released tools (< 6 months age), scope misfit.

**If rejected:** Polite thank you, note the feedback for future improvements, move on. Don't argue.

**If accepted:** Acceptance = 100-300 new visitors to the repo over the next 6 months (these lists have steady traffic). Bigger than HN spike but more sustained.

## Pre-submission checklist

Before each PR:

- [ ] Repo has minimum 50 stars (otherwise looks bare)
- [ ] CI is green on main
- [ ] README is current
- [ ] At least one closed issue (shows engagement)
- [ ] Honest scope statement in README (curators ban submissions that overclaim scope)
- [ ] LICENSE present and visible

## Per-list watch list

After submitting, monitor:
- PR notifications (curator may have questions)
- Repo stars from the awesome-list source (traffic referrer in Insights → Traffic)
- Issues opened by users finding via the list (usually within 4 weeks of acceptance)
