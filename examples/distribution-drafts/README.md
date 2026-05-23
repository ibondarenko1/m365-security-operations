# Distribution drafts

Ready-to-paste copy for each launch channel. Reviewed and approved by operator before publishing.

## Sequencing (7-day rollout)

| Day | Channel | Draft file |
|---|---|---|
| Day 1 (Sun PT eve OR Mon AM PT) | LinkedIn (warm network first) | `01-linkedin-post.md` |
| Day 2 (Tue AM PT) | Dev.to blog post | `02-devto-article.md` |
| Day 3 (Wed eve PT) | r/cybersecurity | `03-reddit-cybersecurity.md` |
| Day 4 (Thu AM PT) | r/sysadmin | `04-reddit-sysadmin.md` |
| Day 5 (Fri AM PT) | Hacker News Show HN | `05-hackernews-show.md` |
| Day 6 (Sat) | Quiet — monitor responses | — |
| Day 7 (Sun) | r/AZURE | `06-reddit-azure.md` |
| Day 8-14 | Newsletter outreach (each editor separately) | `07-newsletter-pitches.md` |

## Why this sequence

- LinkedIn first: warm audience starts repo with non-zero stars before strangers visit
- Dev.to before Reddit: Reddit posts link to blog (more depth than tweet-length)
- Reddit cybersecurity before sysadmin: highest signal/noise → broader audience
- HN later: momentum from Reddit traction is fresh by Day 5
- r/AZURE last: technical community appreciates polished package
- Newsletters separate: each editor expects personalized pitch

## Anti-patterns to avoid

1. **Don't post everywhere Day 1.** Burn-out and fragmented comments.
2. **Don't HN with salesy title.** Mod-flag instant kill.
3. **Don't link to repo before mock-mode tested.** Visitors clone, hit bug, never return.
4. **Don't ignore first 24h notifications.** Early responders abandon if no reply.
5. **Don't get defensive about scope.** Acknowledge + link ADR-004.

## Anticipated critique → response

| Critique | Response |
|---|---|
| "Why not multi-tenant?" | "Scope decision documented in ADR-004 — single-tenant focus enables depth. For multi-tenant use CIPP." |
| "Why PowerShell vs Python?" | "Target audience (M365 admins, SOC analysts) is PowerShell-fluent. ADR-003 has full rationale." |
| "How does this compare to ScubaGear?" | "Different positioning — ScubaGear is federal-grade audit. This is small-org commercial with detect-AND-remediate." |
| "X tool already does this" | "Often partial — show specific check or remediation artifact this toolkit has that the other doesn't." |
| "Your check Y has bug Z" | "Open an issue, I'll triage within 48h per SLO." |
| "Looks like personal portfolio" | "MIT licensed, contributions welcome. ROADMAP.md has 12+ month commitment." |

## Per-channel maintenance time after publishing

- First 24h after each post: monitor for replies, respond within 2h
- First 7 days: respond to all issues within 48h (SLO commitment)
- After: monthly release cadence, weekly issue triage

Realistic week-1 load: ~4-8h depending on traction.
