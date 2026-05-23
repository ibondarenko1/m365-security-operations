# Roadmap

Public roadmap for `m365-security-operations`. Updated each release. Issues and PRs welcome on roadmap items — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Current focus

**Phase 1: Stabilize what exists** — making sure every audit script produces valid output against a real tenant. Bug-fix iteration. Pester smoke test coverage. Target: `v0.1.0`.

---

## Releases roadmap

### v0.1.0 — Stabilize (current)

- End-to-end execution validated against a real tenant
- Bugs from initial framework upgrade fixed
- Pester smoke tests for each audit script + Finding module
- Cross-platform PowerShell 7 (Windows + Linux) validation
- Consistent use of Microsoft.Graph PowerShell module (replace mixed `az rest` + `Invoke-RestMethod`)

### v0.2.0 — Mock mode + onboarding

- Sanitized API response fixtures in `examples/fixtures/`
- `-MockMode` parameter on all audit scripts
- `./examples/run-mock.ps1` runs full pipeline against fixtures (30 seconds, no Azure access required)
- README quickstart updated to lead with mock-mode

### v0.3.0 — Per-domain depth: Identity + DNS

- Identity: +15 checks (PIM eligibility, app consent, service principal audit, named locations, authentication methods, B2B, cross-tenant access, token lifetime, password protection)
- DNS: +8 checks (DNSSEC, CAA, DKIM key strength, DMARC sub-policy, SPF lookup count, DKIM rotation, ARC headers, MX backup)
- Per-finding `documentation_url` field linking Microsoft Learn / RFC / NIST publication

### v0.4.0 — Per-domain depth: Sentinel + Defender O365

- Sentinel: +10 checks (data connectors state, workbooks, hunting queries, playbooks, watchlists, threat indicators, ML/UEBA, solutions, ingestion baselines)
- Defender O365: +10 checks (quarantine policies, priority account protection, ZAP, attack simulation, Safe Documents, anti-spoofing tuning, outbound spam thresholds, connection filter, transport rules, bulk threshold)

### v0.5.0 — Per-domain depth: Defender for Cloud + reliability

- Defender for Cloud: +8 checks (individual recommendations, regulatory compliance per standard, JIT VM, FIM, AAC, Defender for AI, workflow automation, continuous export to Sentinel)
- GitHub Actions matrix: PowerShell 5.1, 7+ on Windows + Linux + Mac
- 80%+ Pester test coverage
- Codecov integration

### v0.6.0 — Documentation depth

- `docs/walkthroughs/` — pace-yourself deployment guides per domain
- `docs/THREAT-MODEL.md` — what this catches vs what it does not
- `docs/FAQ.md`
- `docs/adr/` — Architecture Decision Records for design choices

### v1.0.0 — First public release

- Generate-Report: severity histogram, MITRE tactic coverage map, framework heatmap
- Diff mode: compare against previous run
- PowerShell Gallery publication
- Public visibility flip on GitHub
- Distribution wave 1: blog post, r/cybersecurity, r/sysadmin, r/AZURE, Hacker News Show HN, lobste.rs, security newsletters

### Post-v1.0 (community-driven)

- Microsoft Defender for Endpoint domain (once Defender for Endpoint use case becomes relevant)
- Intune / device compliance domain
- Microsoft Purview (data classification, DLP, eDiscovery) — separate companion repo if scope warrants
- M365 backup posture
- Multi-tenant orchestration (probably as a companion CIPP-style tool, not in this repo)

---

## Out of scope (will not be added)

These domains are explicitly out of scope for this repository regardless of community requests. Each has a better home elsewhere:

- **Multi-tenant management for MSPs** — see [CIPP](https://github.com/KelvinTegelaar/CIPP)
- **Federal compliance overlays (FedRAMP, CMMC, DFARS)** — see [CISA ScubaGear](https://github.com/cisagov/ScubaGear)
- **On-premises Active Directory hybrid scenarios**
- **Microsoft Defender for Identity** (on-prem AD security)
- **Penetration testing / red team tooling**

If your contribution targets one of these, propose a companion repository or use the existing tools above. This keeps `m365-security-operations` focused on small-org cloud-only M365 + Cloudflare environments.

---

## Cadence + commitments

- **Release cadence:** monthly minor versions (last Friday of month)
- **Security patches:** within 1 week of report
- **Issue first response:** 48 hours
- **PR first review:** 1 week
- **Microsoft API changes monitoring:** continuous via [Graph changelog](https://learn.microsoft.com/en-us/graph/changelog)

---

## How to influence the roadmap

1. Open a GitHub issue using the "Feature request" or "New check proposal" template
2. Engage in the relevant GitHub Discussion (Ideas category)
3. Submit a draft PR — implementation work-in-progress drives priority more than abstract requests

This roadmap is living. Updated each release. Open issue with `roadmap` label if you disagree with a sequencing decision.
