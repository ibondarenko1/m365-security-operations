# ADR-004: Out-of-scope domains explicitly excluded

## Status

Accepted (since v0.1, refined v0.6)

## Context

Security tooling has a strong gravitational pull toward "do everything." Each feature request adds maintenance surface; uncontrolled scope creep dilutes the focused value of the toolkit.

## Decision

Explicit out-of-scope statements in README and ROADMAP. The following domains are permanently excluded from this repository:

| Excluded domain | Reason | Recommended alternative |
|---|---|---|
| Multi-tenant management (MSP) | Different operational model; multi-tenant context dilutes single-tenant simplicity | [CIPP](https://github.com/KelvinTegelaar/CIPP) |
| Federal compliance overlays (FedRAMP, CMMC, DFARS) | Specialized regulatory framework | [CISA ScubaGear](https://github.com/cisagov/ScubaGear) |
| On-premises Active Directory | Cloud-only scope by design | [Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity) |
| Endpoint detection (Defender for Endpoint device-level audit) | Endpoint security is its own discipline | Defender for Endpoint native tooling |
| Data Loss Prevention / Information Protection | Separate Microsoft product (Purview) with different operational model | Microsoft Purview |
| Penetration testing / red team tooling | Different intent | OSCP toolchains, AtomicRedTeam |
| M365 backup and recovery posture | Separate ISV ecosystem | Veeam, Druva, etc. |
| Microsoft Teams security configuration beyond Defender XDR coverage | Adjacent product, separate operational model | Teams Admin Center |
| Power Platform (Power Apps, Power Automate) security | Adjacent product | Power Platform Admin Center |
| SharePoint / OneDrive sharing policies | Adjacent product | M365 admin center sharing settings |

## Consequences

**Positive:**
- Maintainers have a clear "no" template — saves PR review time when contributions cross scope lines
- README clarity helps users evaluate fit before cloning
- Concentration of effort in the chosen scope drives depth (per-domain check coverage is higher than a broader-scope tool could maintain)

**Negative:**
- Some users have to coordinate multiple tools instead of one (e.g. ScubaGear for federal + this for small-org commercial)
- Some legitimate contributions get routed elsewhere

**Mitigations:**
- README explicitly references the alternative tools so users find them quickly
- Issue templates ask "is this in scope?" to filter out-of-scope work early

## Review cadence

Scope is reviewed annually. New domains may be added when there's evidence of community demand AND ability to maintain depth. Domains never removed mid-version.
