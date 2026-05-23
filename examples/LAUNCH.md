# v1.0 Launch checklist

Distribution plan for the v1.0 public release. Operator executes these in sequence.

---

## Pre-launch (all complete before flipping public)

- [x] All 6 phases tagged: v0.1.0, v0.2.0, v0.3.0, v0.4.0, v0.5.0, v0.6.0
- [x] 114 Pester tests passing on Windows
- [x] CI matrix configured (ubuntu, windows, macos)
- [x] No tenant data in committed files (audit-output / reports / mock-output via .gitignore)
- [x] README quickstart leads with mock-mode demo
- [x] CONTRIBUTING.md, LICENSE (MIT), SCHEMA.md, ROADMAP.md present
- [x] examples/sample-report.md updated
- [x] docs/ tree complete: walkthroughs, THREAT-MODEL, FAQ, adr/
- [x] Generate-Report polish: severity histogram, MITRE coverage, diff mode

## Day 1: Flip visibility + initial post

1. **Flip repo to public:**

```powershell
gh repo edit ibondarenko1/m365-security-operations --visibility public --accept-visibility-change-consequences
```

2. **Tag v1.0.0 release** with comprehensive release notes (see release-notes-v1.md draft below)

3. **Post companion blog post.** Source: `examples/launch-post.md`. Publish to:
   - dev.to (audience overlap with sysadmin community)
   - personal site (if available)
   - LinkedIn long-form post (tied to job-search legend per project memory)

4. **First Reddit post:** `r/cybersecurity` with link + 1-paragraph honest scope statement. NOT salesy. Title format: "Released v1.0 of an opinionated M365 + Cloudflare audit-and-remediate toolkit for small orgs"

5. **First lobste.rs post:** "Show" tag. Same neutral scope statement.

## Day 2-3: Broader distribution

6. **`r/sysadmin` post.** Slightly different framing — emphasize the operational walkthroughs in `docs/walkthroughs/`.

7. **`r/AZURE` post.** Sentinel-detection-engineering emphasis.

8. **Hacker News Show HN.** ONE submission. Title: "Show HN: Audit-and-remediate toolkit for small-org Microsoft 365 + Cloudflare". Anticipate critique about scope ("why not multi-tenant", "why PowerShell"); answer politely with links to ADRs documenting the decisions.

## Week 1: Newsletter outreach

9. **Detection Engineering Weekly** (Florian Roth + Anton Chuvakin newsletter): email with link + 2-sentence honest scope summary
10. **TLDR Cyber**: similar email
11. **Risky Biz News** (Catalin Cimpanu): similar email
12. **SOC Goulash podcast / blog**: pitch a guest segment

## Ongoing community infrastructure

13. **GitHub Discussions enabled.** Seed topics:
    - Show & Tell ("What did your audit find?")
    - Ideas ("What checks should v1.1 add?")
    - Q&A
14. **Issue templates** for: bug, feature request, new check proposal, FP-pattern report
15. **PR template** with the checklist from CONTRIBUTING.md
16. **Roadmap visibility**: pin ROADMAP.md in README, link from issues

## Maintenance SLO post-launch

- **Issue first response:** 48 hours
- **PR first review:** 1 week
- **Monthly minor release:** last Friday of month, with community-contributed checks where reviewed and approved
- **Security patches:** within 1 week of report
- **Microsoft API monitoring:** subscribe to Graph changelog

## Success criteria (6 months post-v1.0)

- 200+ GitHub stars
- 5+ external contributors (non-operator commits)
- 10+ closed issues
- Featured in at least 1 security newsletter
- PowerShell Gallery downloads: 500+
- Per-domain check count: 20+ in each domain
