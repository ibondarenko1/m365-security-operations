# Walkthrough: Harden Defender for Office 365 baseline

Apply Microsoft's recommended Defender for O365 baseline + tune for false positives identified by the audit. Target audience: M365 tenant admin in small org with mostly-default mail-flow security posture.

Time required: ~45 minutes. Cost: $0 (uses included Defender for O365 P1/P2 licensing — verify with `Get-MsolAccountSku` or Admin Center).

---

## Prerequisites

- Exchange Online PowerShell module: `Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser`
- Account with `Security Administrator` or `Exchange Administrator` role
- Defender for Office 365 license active (Plan 1 minimum, Plan 2 for full features)

---

## Step 1: Connect

```powershell
Connect-ExchangeOnline -ShowBanner:$false
Connect-IPPSSession -ShowBanner:$false  # For PolicyAndCompliance cmdlets
```

---

## Step 2: Apply Standard Preset Security Policy to all users

Microsoft's recommended baseline. Covers anti-phish, anti-spam, anti-malware, Safe Attachments, Safe Links.

```powershell
$standardRuleNames = @(
    "AntiPhishRule",
    "HostedContentFilterRule",
    "SafeAttachmentRule",
    "SafeLinksRule"
)

# Enable Standard Preset for all users
Set-AntiPhishRule -Identity "Standard Preset Security Policy" -Enabled $true
Set-HostedContentFilterRule -Identity "Standard Preset Security Policy" -Enabled $true
Set-SafeAttachmentRule -Identity "Standard Preset Security Policy" -Enabled $true
Set-SafeLinksRule -Identity "Standard Preset Security Policy" -Enabled $true
```

---

## Step 3: Enroll high-risk users in impersonation protection

CEO-fraud and vendor-impersonation attacks need specific targets enlisted.

```powershell
$protectedUsers = @(
    "CEO Name;ceo@yourdomain.com",
    "CFO Name;cfo@yourdomain.com",
    "IT Director Name;itdirector@yourdomain.com"
)

$protectedDomains = @(
    "key-vendor-1.com",
    "key-vendor-2.com",
    "primary-customer.com"
)

Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" `
    -TargetedUsersToProtect $protectedUsers `
    -EnableTargetedUserProtection $true `
    -TargetedUserProtectionAction Quarantine `
    -TargetedDomainsToProtect $protectedDomains `
    -EnableTargetedDomainsProtection $true `
    -TargetedDomainProtectionAction Quarantine
```

---

## Step 4: Apply Strict Preset to high-risk user group

Strict adds aggressive Safe Links rewrites + Safe Attachments dynamic detonation + tighter bulk threshold. Apply to executives + finance + IT.

```powershell
# Create group if not exists
New-DistributionGroup -Name "sg-high-risk-users" -Type Security -ErrorAction SilentlyContinue

Add-DistributionGroupMember -Identity "sg-high-risk-users" -Member "ceo@yourdomain.com"
Add-DistributionGroupMember -Identity "sg-high-risk-users" -Member "cfo@yourdomain.com"

# Apply Strict Preset to this group
Set-AntiPhishRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add="sg-high-risk-users"}
Set-SafeAttachmentRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add="sg-high-risk-users"}
Set-SafeLinksRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add="sg-high-risk-users"}
Set-HostedContentFilterRule -Identity "Strict Preset Security Policy" -SentToMemberOf @{Add="sg-high-risk-users"}
```

Or use the toolkit's wrapper: `02-defender-o365-policy/templates/apply-strict-preset-to-group.ps1 -GroupName 'sg-high-risk-users'`.

---

## Step 5: Tighten outbound spam policy

Limits outbound recipient count + enables admin notification on threshold breach. Catches compromised-account amplification early.

```powershell
Set-HostedOutboundSpamFilterPolicy -Identity "Default" `
    -RecipientLimitExternalPerHour 100 `
    -RecipientLimitInternalPerHour 200 `
    -RecipientLimitPerDay 200 `
    -NotifyOutboundSpam $true `
    -NotifyOutboundSpamRecipients @("admin@yourdomain.com", "security@yourdomain.com") `
    -AutoForwardingMode Off
```

`AutoForwardingMode Off` disables automatic mail forwarding (closes data-exfil path used in BEC).

---

## Step 6: Tune Tenant Allow/Block List for known FPs

The toolkit identifies false-positive sender domains via the audit findings. Apply them:

```powershell
# Allow legitimate marketing senders with broken DKIM
$allowEntries = @(
    @{ Value = "marketing@example-saas.com"; Notes = "Legit cold-outreach; broken DKIM" },
    @{ Value = "newsletter@another-vendor.com"; Notes = "Subscribed newsletter" }
)

foreach ($entry in $allowEntries) {
    New-TenantAllowBlockListItems `
        -ListType Sender `
        -Allow `
        -Entries @($entry.Value) `
        -Notes $entry.Notes `
        -ExpirationDate (Get-Date).AddDays(90)
}
```

Or use the toolkit's bulk wrapper: `02-defender-o365-policy/templates/add-tenant-allow-list-entries.ps1 -EntriesCsv allow-entries.csv`.

---

## Step 7: Enable ZAP for phish + spam

Zero-hour Auto Purge retroactively removes already-delivered messages when Defender's threat intel later flags them.

```powershell
Set-HostedContentFilterPolicy -Identity "Default" `
    -ZapEnabled $true `
    -PhishZapEnabled $true `
    -SpamZapEnabled $true
```

---

## Step 8: Verify

```powershell
./run-audit.ps1 -TenantId ... -SubscriptionId ... -Domain yourdomain.com
```

The Defender for Office 365 phase should now show fewer P2 findings. INFO-level confirmations on impersonation protection, ZAP enabled, outbound thresholds tuned, Tenant Allow/Block List populated.

---

## Framework alignment

- NIST CSF 2.0: DE.AE-02, PR.AC-04, PR.DS-02
- NIST SP 800-53 Rev. 5: SI-3, SI-8
- ISO 27001:2022: A.5.7, A.8.7, A.8.16
- Microsoft Cloud Security Benchmark: IM-6
