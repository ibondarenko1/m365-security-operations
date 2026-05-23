# ADR-002: Mock mode via fixture replay

## Status

Accepted (since v0.2)

## Context

Adoption barrier was high in v0.1: a potential user had to acquire an Azure subscription, perform Graph permission setup, install Exchange Online module, and authenticate before seeing any tool output. Several reviewers reported "I'd love to see what it produces, but the setup cost is too high for evaluation."

Two architectural choices for lowering barrier:

1. **Hosted demo.** Run the audit on a public-but-controlled tenant and publish the report. Single static demo.
2. **Mock mode.** Bundle sanitized API responses; tool replays them as if hitting real APIs. User runs locally with no Azure access.

## Decision

Mock mode via fixture replay. `lib/MockClient.psm1` provides drop-in replacements for Graph + ARM + DNS + EXO calls; reads from `examples/fixtures/*.json`. Audit scripts honor `-MockMode` switch parameter.

## Consequences

**Positive:**
- 30-second demo path: `git clone && ./examples/run-mock.ps1` → complete report
- No Azure infrastructure required for evaluation
- Fixtures double as test data — Pester suite can validate audit logic without real APIs
- Contributors can iterate on audit logic without burning real-tenant quota
- Real-tenant audit path unchanged — mock is a parallel mode, not a replacement

**Negative:**
- Fixture maintenance overhead — new check categories require fixture updates
- Fixtures represent ONE archetype (small-org with realistic gaps); doesn't show high-maturity tenant output
- Drift risk between mock and live behavior — if Graph response shape changes, mock continues working but live audits may fail

**Mitigations:**
- CI runs mock mode every commit, catches mock regressions
- Live-mode E2E test required before each release
- Fixtures are versioned with the audit script that consumes them (SCHEMA.md schema_version tracks compatibility)

## Alternatives considered

- **Hosted demo on Microsoft Sentinel sandbox tenant.** Considered. Rejected: not under operator control, can disappear; reviewers still want to run locally.
- **Recorded HTTP cassettes (VCR-style).** More accurate replay of real API behavior. Rejected for v0.2: heavier implementation, JSON fixtures are sufficient for current depth and easier to hand-edit.
- **In-memory Graph emulator.** Too complex. The fixture-replay approach captures the same information at 1/10 the implementation cost.
