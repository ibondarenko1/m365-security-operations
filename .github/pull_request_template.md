# Pull request

## What this changes

Brief 1-2 sentence summary.

## Type of change

- [ ] New audit check
- [ ] New remediation artifact
- [ ] New KQL hunting template
- [ ] Bug fix
- [ ] FP-tuning improvement
- [ ] Documentation / walkthrough
- [ ] Infrastructure (CI, fixtures, schema, tests)
- [ ] Other (describe):

## Linked issue

Closes #___

## Checklist

Required for all PRs:

- [ ] Pester tests pass locally (`Invoke-Pester -Path tests/`)
- [ ] No tenant IDs, user UPNs, real domain names, or other tenant-specific data in committed files
- [ ] New scripts pass PSScriptAnalyzer (Error severity)
- [ ] If adding a new check: conforms to SCHEMA.md (use `New-Finding` from `lib/Finding.psm1`)
- [ ] If adding a remediation artifact: parameterized with placeholders, references parent finding ID
- [ ] If touching public-facing copy: no em-dashes, no operational specifics that betray scale

For new audit checks specifically:

- [ ] `framework_controls` array uses SCHEMA.md dot-notation
- [ ] `severity` follows the rubric (P1/P2/P3/INFO/OUT_OF_SCOPE)
- [ ] `documentation_url` points to Microsoft Learn / NIST / RFC where applicable
- [ ] Mock fixture added to `examples/fixtures/` so mock-mode produces the finding
- [ ] `lib/MockClient.psm1` URI mapping added if new API endpoint

For new remediation artifacts:

- [ ] CmdletBinding + parameter validation
- [ ] Documented usage example in top-of-file comment
- [ ] `_metadata` block with `purpose` + `framework_controls` (JSON artifacts)

## Testing

How was this verified? Mock-mode results before/after? Live-tenant test (if possible)?

## Anything reviewers should know

Surprises, trade-offs, follow-ups deferred to subsequent PRs.
