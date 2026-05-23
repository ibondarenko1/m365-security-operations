# Microsoft 365 Security Operations

Operational security methodology for a small Microsoft 365 tenant. End-to-end coverage across SIEM, detection engineering, email security, DNS posture, identity hardening, and governance.

Not a tutorial. Not a study artifact. Methodology, parameterized artifacts, and tuning principles drawn from running the stack for a real tenant. Specific tenant data is not published; templates and patterns are.

---

## Scope

| Domain | Tooling | Frameworks |
|---|---|---|
| SIEM & Detection Engineering | Microsoft Sentinel, Log Analytics | MITRE ATT&CK, NIST 800-53 SI-4 |
| Email Security | Microsoft Defender for Office 365 | NIST 800-53 SI-8, ISO 27001 A.13.2 |
| DNS & Email Authentication | Cloudflare DNS, DMARC, SPF, DKIM, MTA-STS | NIST 800-177r1, RFC 7489, RFC 8461 |
| Identity & Access | Microsoft Entra ID (Conditional Access) | NIST 800-63B, ISO 27001 A.9 |
| Cloud Workload Security | Microsoft Defender for Cloud, AI Security | Microsoft Cloud Security Benchmark |
| Governance | NIST CSF 2.0, ISO 27001 | mapping matrix |

Endpoint security (Defender for Endpoint) is out of scope for this engagement; the tenant operates without managed endpoints.

---

## Repository structure

```
01-sentinel-detection-engineering/   SIEM workspace, MITRE-mapped analytics rules, KQL hunting library
02-defender-o365-policy/             Anti-phishing, Safe Links, Safe Attachments, tenant allow/block tuning
03-dns-email-auth/                   DMARC enforcement, SPF, DKIM, MTA-STS, TLS-RPT, BIMI
04-identity-hardening/               Conditional Access policy library, MFA enforcement, sign-in risk
05-governance/                       NIST CSF, ISO 27001, MCSB control mapping
assets/                              Diagrams, reference material
```

---

## Phase status

- [x] Phase 1 - Sentinel detection engineering and KQL hunting library
- [ ] Phase 2 - Defender for Office 365 policy hardening
- [ ] Phase 3 - DNS and email authentication posture
- [ ] Phase 4 - Identity hardening
- [ ] Phase 5 - Governance mapping

---

## Principles

**Framework first.** Every control, rule, and policy is tied to a published framework (NIST CSF, MITRE ATT&CK, ISO 27001, RFC). Frameworks are scale-neutral and let readers evaluate methodology rather than scope.

**Parameterized, not tenant-specific.** Public artifacts are templates. Workspace names, subscription IDs, resource group names, and operational thresholds are placeholders. Tenant data stays internal.

**Lifecycle, not snapshots.** Each domain includes a teardown / decommission path, not only deployment. Production work has a lifecycle; portfolio work that ignores it is incomplete.

**Tuning is the work.** False-positive recognition, baseline establishment, and signal calibration are documented as first-class outputs, not afterthoughts. Most analyst time goes to tuning, not novel detection.

---

## Frameworks referenced

- NIST Cybersecurity Framework 2.0
- NIST SP 800-53 Rev. 5
- NIST SP 800-63B
- NIST SP 800-177 Rev. 1 (Trustworthy Email)
- ISO/IEC 27001:2022
- MITRE ATT&CK
- Microsoft Cloud Security Benchmark
- RFC 7489 (DMARC), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 8617 (ARC)

---

## License

Methodology and parameterized artifacts are released under MIT for reuse. Tenant data and operational specifics are not included in this repository.
