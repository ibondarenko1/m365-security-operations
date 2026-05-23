# ADR-001: Schema-first finding emission

## Status

Accepted (since v0.1)

## Context

Audit scripts need to produce structured output for downstream aggregation (markdown report, framework coverage matrix, diff mode). Two architectural choices were available:

1. **Free-form output per script.** Each audit script emits whatever shape makes sense to its author. Report aggregator does shape normalization.
2. **Schema-first.** All audit scripts emit findings conforming to a single versioned schema. Report aggregator consumes that schema.

## Decision

Schema-first. `SCHEMA.md` v1.0 documents the finding object contract. `lib/Finding.psm1` enforces it via `New-Finding` and `Write-PhaseReport` exports.

## Consequences

**Positive:**
- Report aggregator code stays simple — same logic across all phases
- Contributors writing new audit scripts have a clear contract
- Schema changes are visible — `audit_script_version` field captures version mismatches
- Easier to add new consumers (e.g. JSON-to-Splunk converter) without modifying audit scripts

**Negative:**
- Schema rigidity. Adding new optional fields requires schema bump.
- Audit scripts can't emit truly idiosyncratic data — must fit the finding model. Worked around via `evidence` field which accepts arbitrary phase-specific data.

## Alternatives considered

- **OpenAPI / JSON Schema validation at runtime.** Heavier dependency, less PowerShell-idiomatic. Decided structural enforcement via `New-Finding` parameter validation is sufficient for solo-author scope.
- **YAML-based DSL for audit checks.** Tempting for declarative simplicity but loses PowerShell native access to Graph + ARM APIs. Audit checks frequently need conditional logic that DSL would have to express awkwardly.
