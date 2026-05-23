# Mock-mode fixtures

JSON fixtures simulating Graph + ARM + DNS responses from a representative small Microsoft 365 tenant with typical posture gaps. Used by `-MockMode` to allow tool demonstration without real Azure access.

All identifiers in these fixtures are synthetic:

| Field | Synthetic value |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000000` |
| Subscription ID | `11111111-1111-1111-1111-111111111111` |
| Workspace ID | `22222222-2222-2222-2222-222222222222` |
| Domain | `example.com` |
| User UPNs | `<role>@example.com` (admin, ceo, finance, etc.) |
| Group IDs | `33333333-3333-3333-3333-30000000000N` (incremented per group) |

## Fixture inventory

| File | Source endpoint | What it represents |
|---|---|---|
| `graph-conditional-access-policies.json` | `/identity/conditionalAccess/policies` | Zero CA policies (P1 finding) |
| `graph-authorization-policy.json` | `/policies/authorizationPolicy` | Permissive defaults (multiple P2/P3 findings) |
| `graph-directory-roles.json` | `/directoryRoles` | Excessive standing GAs (P1 finding) |
| `graph-directory-role-members.json` | `/directoryRoles/<id>/members` | 3 GAs + 1 multi-role user |
| `graph-users.json` | `/users` | 6 users (matches typical small org) |
| `graph-signin-logs-403.json` | `/auditLogs/signIns` | 403 forbidden (P2 finding) |
| `arm-pricings.json` | `Microsoft.Security/pricings` | Mostly Free tier (several P3) |
| `arm-secure-score-empty.json` | `Microsoft.Security/secureScores` | Empty (INFO) |
| `arm-workspace.json` | Workspace resource | Configured with quota |
| `arm-sentinel-onboarding-state.json` | Sentinel onboarding | Onboarded (INFO) |
| `arm-analytics-rules.json` | SecurityInsights/alertRules | 6 rules incl. Fusion |
| `arm-diagnostic-settings.json` | `microsoft.insights/diagnosticSettings` | Activity Log wired (INFO) |
| `dns-mx.json` | DNS MX | M365 mail (INFO) |
| `dns-spf.json` | DNS TXT root | SPF with hard fail (INFO) |
| `dns-dmarc.json` | DNS TXT `_dmarc` | p=reject (INFO) |
| `dns-dkim.json` | DNS CNAME selectors | Both selectors configured (INFO) |
| `dns-mta-sts.json` | DNS TXT `_mta-sts` | NXDOMAIN (P3) |
| `dns-tls-rpt.json` | DNS TXT `_smtp._tls` | NXDOMAIN (P3) |
| `dns-bimi.json` | DNS TXT `default._bimi` | NXDOMAIN (P3) |
| `exo-anti-phish-policy.json` | EXO `Get-AntiPhishPolicy` | Zero impersonation users (P2) |
| `exo-tenant-allow-block.json` | EXO `Get-TenantAllowBlockListItems` | Empty list (P2) |
| `exo-dkim.json` | EXO `Get-DkimSigningConfig` | Both enabled + Valid (INFO) |

## Refreshing fixtures

If the audit scripts add new check categories, fixtures may need extension. Process:

1. Capture real (anonymized) sample from your own tenant.
2. Run through `examples/fixtures/sanitize.ps1` (Phase 2.1 deliverable) to swap real IDs with synthetic.
3. Drop into appropriate fixture file.
4. Add a row to the inventory table above.
5. Test: `./run-audit.ps1 -MockMode` should consume the new fixture without errors.

Fixtures must not contain any real tenant data, real domain names, or real user identifiers. CI includes a fixture-sanity check (see `.github/workflows/ci.yml`).
