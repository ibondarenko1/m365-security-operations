# ADR-003: PowerShell as primary implementation language

## Status

Accepted (since v0.1)

## Context

The toolkit calls Microsoft Graph, Azure Resource Manager, Exchange Online, and DNS. Language candidates:

- PowerShell (5.1 / 7+)
- Python with `azure-sdk-for-python`
- Go with `azure-sdk-for-go`
- C# / .NET via `Microsoft.Graph` SDK
- Mixed: Bash + Python + PowerShell per domain

## Decision

PowerShell as the primary language. Specifically:

- PowerShell 7+ (cross-platform Windows/Linux/Mac)
- Backward compatible with Windows PowerShell 5.1 for Windows admins not on PS7 yet
- Microsoft.Graph PowerShell module for Graph calls
- Azure CLI (`az`) for ARM REST calls (cleaner than direct REST)
- ExchangeOnlineManagement module for EXO-specific functionality
- Native `Resolve-DnsName` for DNS lookups (with mock fallback in mock mode)

## Consequences

**Positive:**
- Target audience (M365 admins, SOC analysts in mid-market) is already PowerShell-fluent
- Microsoft official tooling is PowerShell-first (ExchangeOnlineManagement, MicrosoftGraph, Az)
- Existing knowledge: most M365 documentation provides PowerShell examples
- Direct interop with all Microsoft cloud auth flows
- Lower-cognitive-overhead than a polyglot project

**Negative:**
- Limits contributor pool — Python developers may not contribute
- PS 5.1 / 7+ compatibility quirks waste time (e.g. case-sensitivity differences, `$null` handling, parameter binding edge cases)
- Slower than compiled languages — but not the bottleneck (API latency dominates)
- Verbose syntax compared to Python equivalents

**Mitigations:**
- KQL hunting queries are language-neutral; contributors can add KQL without touching PowerShell
- ARM templates + Conditional Access policy JSONs are language-neutral
- Mock mode fixtures are JSON, language-neutral
- Future expansion: if Python becomes important, expose audit findings via JSON output (already done — see ADR-001) so other-language consumers can plug in.

## Alternatives considered

- **Python primary.** Better for cross-platform open-source contributors. Rejected: target audience is PowerShell-fluent; mixing introduces complexity.
- **Go primary.** Compile-once, run-anywhere advantage. Rejected: M365 admins don't typically have Go toolchains.
- **Mixed (PowerShell for M365, Python for DNS/HTTP).** Rejected: complexity without proportional benefit. Better to keep one language.
