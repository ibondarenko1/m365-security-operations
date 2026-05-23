# Walking through a 5-domain Microsoft 365 audit in 30 seconds

If you administer a small Microsoft 365 tenant, here's the question that probably stopped you somewhere between "I should check our security posture" and actually doing it:

**Which tool?**

Microsoft Secure Score gives recommendations but no remediation artifacts. CISA ScubaGear is excellent but federal-grade — overkill for a 20-person mid-market shop. M365DSC is configuration-as-code, which is great when you're a DSC shop and terrible when you're not. CIPP is purpose-built for MSPs managing many tenants — solo defenders don't need that fan-out.

There was a gap: an opinionated audit-plus-remediation toolkit for a solo defender running M365 + Cloudflare in a small org. I built one. Tagged 1.0 today.

[github.com/ibondarenko1/m365-security-operations](https://github.com/ibondarenko1/m365-security-operations)

## What it actually does

One PowerShell command sweeps five domains, produces a single markdown report ranking findings P1/P2/P3, and links every gap to a ready-to-deploy remediation artifact:

| Domain | Audit | Remediation |
|---|---|---|
| Sentinel detection engineering | Workspace state, daily quota, retention, Sentinel onboarding, analytics rules, Fusion, Activity Log diagnostic, data connectors, workbooks, hunting queries, automation playbooks, watchlists, UEBA, threat intelligence | 5 MITRE-mapped ARM templates + 10 KQL hunting drills |
| Defender for Office 365 | Anti-phish impersonation, anti-spam, anti-malware, Safe Attachments, Safe Links, Tenant Allow/Block List, DKIM, ZAP, outbound thresholds, transport rules, Attack Simulation Training | Exchange Online PowerShell remediation scripts |
| DNS + email authentication | MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, NS, Autodiscover, CAA, DNSSEC, SPF lookup count, DMARC sub-policy | Cloudflare Worker + DNS deployment script for MTA-STS + TLS-RPT |
| Identity hardening | Conditional Access policies, authorization policy, directory roles, sign-in logs, authentication methods, app consent, service principal credentials, named locations, cross-tenant access, sign-in risk, SSPR | 6 baseline Conditional Access policy JSONs ready for Graph PUT |
| Defender for Cloud | Per-plan pricing tier, Secure Score, recommendations by severity, AI plane, continuous export to Sentinel | Plan-tier upgrade methodology + walkthrough |

Every finding is tagged with framework controls — NIST CSF 2.0, NIST SP 800-53, NIST SP 800-63B, ISO 27001:2022, MITRE ATT&CK, Microsoft Cloud Security Benchmark, RFC references.

## Try it in 30 seconds

```powershell
git clone https://github.com/ibondarenko1/m365-security-operations
cd m365-security-operations
./examples/run-mock.ps1
```

That runs the full audit against bundled sanitized fixtures and produces a complete sample report — 58 findings across 5 domains. No Azure access required. Open `reports/<latest-timestamp>/report.md` to see exactly what the tool produces.

When you're ready to run against your tenant:

```powershell
az login --tenant <your-tenant-id>
./run-audit.ps1 -TenantId <id> -SubscriptionId <id> -Domain <yourdomain> -WorkspaceName <ws> -ResourceGroup <rg>
```

## Why opinionated scope matters

This toolkit explicitly does NOT cover:
- Multi-tenant MSP management (use CIPP)
- Federal compliance overlays (use ScubaGear)
- On-premises Active Directory (use Defender for Identity)
- Endpoint detection at device level (use Defender for Endpoint native)
- Data Loss Prevention (use Microsoft Purview)

The toolkit is opinionated for **small-org cloud-only M365 + Cloudflare**. Concentration enables depth: each domain has 15-25 checks, not the surface-level 5 a broader-scope tool can maintain.

## Architecture you can actually contribute to

- Schema-first: every audit script emits findings conforming to `SCHEMA.md`, enforced by `lib/Finding.psm1`
- Mock mode: `lib/MockClient.psm1` provides drop-in mocks for Graph + ARM + DNS + EXO. Contributors iterate on audit logic without burning real-tenant quota
- 114 Pester tests in CI on Windows + Linux + Mac
- 6 Architecture Decision Records document the design rationale
- 5 walkthroughs cover end-to-end deployment of the remediation artifacts

## What's next

v1.0 is the public-release baseline. Roadmap continues with v1.1-v1.5 expanding per-domain checks, adding documentation_url to every finding (currently P1/P2 only), and surfacing community-contributed checks.

If you administer M365 in a small org, give it a try and open issues for what you'd like to see next.

[github.com/ibondarenko1/m365-security-operations](https://github.com/ibondarenko1/m365-security-operations)

---

*MIT licensed. Methodology, schema, fixtures, walkthroughs, ADRs, Pester tests, and CI matrix all in the repo.*
