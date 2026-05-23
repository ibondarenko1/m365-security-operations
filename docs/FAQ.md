# FAQ

Common operator questions about the toolkit. Open an issue if your question isn't answered here.

---

## General

### Q: Is this maintained?

Active development. Monthly release cadence (last Friday of month per [`ROADMAP.md`](../ROADMAP.md)). First-response SLO on issues is 48 hours.

### Q: Will this stay free?

Yes. MIT licensed in perpetuity. Methodology and artifacts are public goods; commercial work happens in consulting engagements, not in the toolkit.

### Q: How does this compare to ScubaGear / Maester / M365DSC?

| Tool | Approach |
|---|---|
| CISA ScubaGear | Federal-grade baseline audit. Deeper per-domain. No remediation artifacts. |
| Maester | M365 testing framework. Test-as-code style. No remediation. |
| M365DSC | Full DSC configuration-as-code. Heavy, declarative, complex to learn. |
| CIPP | MSP multi-tenant management dashboard. Different category. |
| This | Detect + remediate. Each gap links to a deployable artifact. Mock mode for demo. |

### Q: Does it work on multi-tenant deployments?

No. Single-tenant scope. For multi-tenant MSP work, use [CIPP](https://github.com/KelvinTegelaar/CIPP).

---

## Running the toolkit

### Q: Why does mock mode produce different counts than my real tenant?

Mock fixtures represent a typical small-org tenant with realistic gaps. Your real tenant will have different counts based on its actual configuration. The mock is a demo of *what the tool produces*, not a benchmark.

### Q: Audit script errors with "Failed to acquire Graph access token"

You're not logged into Azure CLI, or your token expired.

```powershell
az login --tenant <your-tenant-id>
```

### Q: "Insufficient privileges" / 403 errors during audit

The audit account lacks read scopes. Assign the `Security Reader` directory role in Entra — it covers the read scopes the toolkit needs (Policy.Read.All, Directory.Read.All, AuditLog.Read.All).

```powershell
# As a Global Admin, assign Security Reader to audit account:
Connect-MgGraph -Scopes RoleManagement.ReadWrite.Directory
$user = Get-MgUser -Filter "userPrincipalName eq 'audit@yourdomain.com'"
$role = Get-MgDirectoryRole -Filter "displayName eq 'Security Reader'"
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{"@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"}
```

### Q: Defender for O365 phase shows OUT_OF_SCOPE

The `ExchangeOnlineManagement` PowerShell module isn't installed. Phase skips with documented installation steps.

```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
```

### Q: Sentinel phase says SKIPPED

You didn't pass `-WorkspaceName` and `-ResourceGroup` to `run-audit.ps1`. Sentinel audit needs both to locate the workspace.

### Q: How do I run on Linux / Mac?

Install PowerShell 7+:
- Linux: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux
- Mac: `brew install --cask powershell`

Then: `pwsh ./run-audit.ps1 -TenantId ... -SubscriptionId ... -Domain ...`. CI tests against ubuntu-latest and macos-latest, so cross-platform should hold.

### Q: Can I exclude phases?

Not currently via parameter. Workaround: comment out the relevant section in `run-audit.ps1`, or run individual `audit-<phase>.ps1` scripts directly with `-OutputJsonPath`.

---

## Remediation artifacts

### Q: Are CA policies safe to deploy directly?

All 6 baseline policies in `04-identity-hardening/policies/` deploy in `enabledForReportingButNotEnforced` state. Nothing is enforced until you explicitly switch to `enabled`. See [`docs/walkthroughs/04-deploy-conditional-access.md`](walkthroughs/04-deploy-conditional-access.md) for the safe rollout sequence.

### Q: What if I don't have Entra ID P2?

P2-dependent policies (sign-in risk, user risk) will deploy but won't have access to risk-score data. The toolkit's audit flags these as out-of-tier when relevant. Either: drop those policies, or upgrade license.

### Q: The MTA-STS Cloudflare worker — what if I don't use Cloudflare?

The policy file just needs to be served over HTTPS at `mta-sts.<your-domain>/.well-known/mta-sts.txt`. Any cloud provider with HTTPS-enabled static hosting works (AWS S3 + CloudFront, GitHub Pages with custom domain, Azure Static Web Apps). The DNS TXT records `_mta-sts.<domain>` and `_smtp._tls.<domain>` can be added at any DNS provider; only the deploy script targets Cloudflare's API.

### Q: Does deploying TenantAllowBlockList entries open security holes?

Only entries you explicitly add. The `add-tenant-allow-list-entries.ps1` reads from a CSV — review the CSV before running. Each entry has a 30-day default expiration; revisit at expiration to confirm the allow is still warranted.

---

## Findings + reports

### Q: Why is `findings` count higher in v0.5 than v0.3?

Each release added depth checks. v0.3 added Identity + DNS depth (~14 checks). v0.4 added Sentinel depth (~7 checks). v0.5 added Defender O365 + Defender Cloud depth (~9 checks). Same tenant audited at v0.5 produces ~25 more findings than at v0.3.

### Q: How do I track posture over time?

`Generate-Report.ps1` has a `-CompareWith <previous-reports-dir>` mode (added v1.0+) that produces a diff. Before that: keep timestamped `reports/<timestamp>/` directories and compare manually.

### Q: Can I add custom checks?

Yes. See [`CONTRIBUTING.md`](../CONTRIBUTING.md). New audit scripts must emit JSON per `SCHEMA.md`. Drop a `.ps1` in the appropriate domain folder, add it to the orchestrator, write Pester tests covering the new check, submit PR.

### Q: How are severities decided?

Per `SCHEMA.md`:
- P1 (within 1 week): exposed identity, missing critical auth controls
- P2 (within 30 days): defense-in-depth gaps, missing monitoring
- P3 (within 90 days): hygiene, transport security, optional improvements

When in doubt, audit script authors favor more severe. Operator can downgrade in their own context.

---

## Framework alignment

### Q: How do I prove compliance with NIST CSF / ISO 27001 using this?

The toolkit maps findings to framework controls but isn't a compliance-certification tool. Use the framework coverage matrix in generated reports as **evidence** for your existing compliance auditor or GRC platform. Pair with a real GRC tool (Vanta, Drata, Hyperproof, etc.) for full certification workflows.

### Q: Is this CMMC / FedRAMP applicable?

No. The toolkit is opinionated for commercial small-org M365. For federal-tenant workloads use [CISA ScubaGear](https://github.com/cisagov/ScubaGear) — it's purpose-built for FedRAMP/CMMC baselines.

### Q: Microsoft Cloud Security Benchmark coverage?

Partial. The toolkit covers MCSB domains: IM (Identity Management), LT (Logging & Threat Detection), PV (Posture & Vulnerability Management). Not covered: NS (Network Security), DP (Data Protection), AM (Asset Management), BR (Backup & Recovery), GS (Governance & Strategy).

---

## Contributing

### Q: I want to add a check for X. Where do I start?

Open an issue with the "New check proposal" template first — quick way to validate scope fit. Then read `CONTRIBUTING.md`. Then draft PR.

### Q: I found a false-positive finding pattern. Can I contribute the tuning logic?

Yes. False-positive recognition is the most operator-valuable contribution category. Submit PR with: example trigger (sanitized fixture entry), tuning logic in the audit script, framework controls remain accurate, Pester test verifies the tuning works.
