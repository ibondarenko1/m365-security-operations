# Contributing

Contributions welcome. The toolkit is opinionated for small-org M365 + Cloudflare tenants — keep that scope in mind when proposing changes.

---

## Three contribution paths

### 1. New audit script

Audit scripts go under the appropriate domain folder (`01-sentinel-detection-engineering/`, `02-defender-o365-policy/`, etc) or under a new top-level domain folder if introducing a new domain (`06-data-loss-prevention/`, `07-backup-recovery/`).

Requirements:

- **Read-only.** Audit scripts must never modify tenant state. Remediation is a separate artifact under `templates/` or `policies/`.
- **Output schema.** Emit findings via `lib/Finding.psm1` per [`SCHEMA.md`](SCHEMA.md). Use `New-Finding` and `Write-PhaseReport`. Do not invent ad-hoc JSON formats.
- **CLI parameters.** Accept `-OutputJsonPath <path>` as a mandatory parameter. Optional but recommended: `-TenantId`, `-SubscriptionId`, `-Domain` for cross-phase context.
- **Failure modes.** Wrap each Graph or ARM call in try/catch. Emit a `severity: "P2"` or `severity: "P3"` finding when a call fails, naming the missing permission or scope. Never throw an unhandled exception that breaks the orchestrator.
- **Optional-dependency handling.** If the script requires a non-default PowerShell module (e.g. `ExchangeOnlineManagement`), check for the module first. If missing, emit a `severity: "OUT_OF_SCOPE"` finding with installation steps and exit 0 (not 1).
- **Update orchestrator.** Add the new audit script to `run-audit.ps1` in the appropriate phase position.

### 2. New remediation artifact

Remediation artifacts go under the appropriate domain folder's `templates/` (PowerShell scripts) or `policies/` (JSON for Graph/ARM PUT) subfolder.

Requirements:

- **Parameterized.** Use `<placeholder>` syntax for tenant-specific values (object IDs, domain names, group names). Never commit real tenant data.
- **Reference parent finding.** In a `_metadata.purpose` field or top-of-script comment, name the finding ID that this artifact remediates.
- **Framework alignment.** In `_metadata.framework_controls` or top-of-script comment, list the framework controls the artifact addresses. Use dot-notation per SCHEMA.md.
- **Idempotent or safely re-runnable.** If the script creates resources, check for existing first (e.g. via `-ErrorAction SilentlyContinue` followed by `Set-*` vs `New-*`).
- **Document deployment.** Top-of-file comment must include usage example with concrete parameters.

### 3. KQL hunting template

KQL templates go under `01-sentinel-detection-engineering/kql/`. Numbered sequentially.

Requirements:

- **Self-documenting header.** Top of file: purpose, SC-200 KQL pattern demonstrated, expected data source.
- **Commented variations.** Include 1-2 commented alternative formulations (different time buckets, different join kinds, drill-down filters) so readers learn the pattern.
- **No tenant-specific values.** Use 30-day default time ranges. Don't bake in specific domain names, sender lists, or hardcoded thresholds.

---

## Pull request checklist

Before submitting a PR:

- [ ] New audit scripts emit valid JSON per `SCHEMA.md` (verify with: `Get-Content reports/*/your-phase.json | ConvertFrom-Json`).
- [ ] All findings have non-empty `id`, `severity`, `title`, `description`, `framework_controls` (or explicit empty array), `remediation_steps` (or explicit empty array).
- [ ] Framework controls use dot-notation prefixes (`NIST.CSF.*`, `NIST.800-53.*`, `ISO27001.*`, `MITRE.*`, `MCSB.*`, `RFC.*`).
- [ ] No tenant IDs, subscription IDs, real user UPNs, or organization names in committed files.
- [ ] PowerShell scripts pass `Invoke-ScriptAnalyzer` without errors (warnings acceptable with justification).
- [ ] JSON files (CA policies, ARM templates) are syntactically valid.
- [ ] README updated if you added a new top-level domain or remediation pattern.
- [ ] `examples/sample-report.md` updated if your finding ID prefix is new.

---

## Code style

PowerShell:

- Use approved verbs (`Get-`, `Set-`, `New-`, `Remove-`, `Test-`, etc).
- camelCase for parameter names. PascalCase for function names.
- 4-space indentation.
- Comment-based help block at top of every script (`<# .SYNOPSIS ... #>`).
- Prefer `[CmdletBinding()]` and typed parameters.

JSON (CA policies, ARM templates):

- 2-space indentation.
- Always include `_metadata` block with `purpose`, `framework_controls`, `deployment_notes`.
- Placeholders use `<placeholder-name>` format consistently.

KQL:

- `// double-slash comments` not `// SQL-style`.
- `| pipe at start of new line` for multi-line queries.
- Use `bin(Timestamp, 1h)` not `bin(Timestamp, 1hr)` (KQL hates colloquial duration).

---

## Reporting issues

If `run-audit.ps1` produces an unexpected result or crashes, open an issue with:

1. Output of `$PSVersionTable` (PowerShell version)
2. Output of `az --version` (Azure CLI version)
3. The full error message (redact tenant IDs / object IDs first)
4. The phase that failed (last `>>>` line printed by orchestrator)

---

## Scope reminder

Out of scope for this repo:

- Multi-tenant management (see [CIPP](https://github.com/KelvinTegelaar/CIPP))
- Federal compliance overlays — FedRAMP, CMMC, DFARS (see [ScubaGear](https://github.com/cisagov/ScubaGear))
- On-premises Active Directory hybrid scenarios
- Microsoft Defender for Endpoint device-level audit (managed-endpoint tooling assumed absent)
- DLP, eDiscovery, Purview
- Backup and recovery posture (M365 retention defaults assumed sufficient)

If your contribution targets one of these, consider whether the existing toolkit is the right home or whether a separate companion project is a better fit.
