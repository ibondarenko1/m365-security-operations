# Walkthrough: Defender for Cloud tuning

Right-size Defender for Cloud plan tiers and triage initial recommendations for a small Azure subscription. Avoid paying for Standard tiers on plans that protect workloads you don't have.

Time required: ~20 minutes. Cost: depends on tier choices.

---

## Step 1: Understand Free vs Standard tier

Free tier (default):
- Basic security posture recommendations
- No threat detection
- No just-in-time VM access
- No file integrity monitoring
- No adaptive application controls
- No vulnerability scanning

Standard tier (paid per resource type):
- Full threat detection + alerts
- Advanced posture analytics
- JIT VM, FIM, AAC where applicable
- Vulnerability scanning (Defender for Servers + Containers)

Microsoft offers FoundationalCspm Standard tier as a free promotion for tenants without other paid Defender plans. Discovery is similarly free.

---

## Step 2: Audit your current plan tiers

```powershell
az rest --method get --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/providers/Microsoft.Security/pricings?api-version=2024-01-01" | ConvertFrom-Json | Select-Object -ExpandProperty value | Select-Object name, @{n='tier';e={$_.properties.pricingTier}}
```

---

## Step 3: Match tier to actual workloads

| Defender plan | Upgrade to Standard if you have... | Otherwise |
|---|---|---|
| VirtualMachines | Azure VMs running workloads | Free |
| SqlServers | Azure SQL databases | Free |
| AppServices | Azure App Service / Function Apps | Free |
| StorageAccounts | Storage accounts with sensitive data | Free |
| KubernetesService | AKS clusters | Free |
| ContainerRegistry | ACR with images that hit AKS or App Service | Free |
| KeyVaults | Key Vaults storing production secrets | Free |
| Dns | High DNS query volume (rare for small org) | Free |
| Arm | High ARM-control-plane activity (CSP, MSP scenarios) | Free |
| Containers | Cloud-native container workloads | Free |
| AI | Azure AI Foundry deployments with production models | Free |

For a small org with no Azure workloads (subscription mainly for Sentinel lab), Free across the board is correct.

---

## Step 4: Upgrade selectively

Example: tenant runs a single Web App + a SQL database.

```powershell
az security pricing create --name AppServices --tier Standard
az security pricing create --name SqlServers --tier Standard
# Leave others Free
```

Cost typically $15-50/resource/month depending on plan + region. Check pricing details: https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/.

---

## Step 5: Wait 24-48 hours for posture data

After enabling Defender on a workload type, MDC scans the resources and generates recommendations. Secure Score percentage materializes ~24-48 hours after subscription registration.

```powershell
az rest --method get --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/providers/Microsoft.Security/secureScores?api-version=2020-01-01"
```

---

## Step 6: Triage recommendations

```powershell
az rest --method get --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/providers/Microsoft.Security/assessments?api-version=2020-01-01" `
    | ConvertFrom-Json `
    | Select-Object -ExpandProperty value `
    | Where-Object { $_.properties.status.code -eq "Unhealthy" } `
    | Sort-Object { $_.properties.metadata.severity } -Descending `
    | Select-Object @{n='sev';e={$_.properties.metadata.severity}}, @{n='name';e={$_.properties.displayName}} -First 20
```

For each High-severity unhealthy item:
1. Click through in portal: Defender for Cloud > Recommendations > select assessment.
2. Microsoft documents the underlying control + remediation steps inline.
3. Many have "Fix" button for one-click remediation; some require manual deployment changes.

---

## Step 7: Configure continuous export to Sentinel

So MDC alerts + recommendations land in Sentinel for unified incident correlation.

```powershell
$rg = "sec-rg"  # The Sentinel resource group
$wsId = az monitor log-analytics workspace show -g $rg -n sec-ws --query id -o tsv
$subId = az account show --query id -o tsv

$exportUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/automations/export-to-sentinel?api-version=2023-12-01-preview"
$exportBody = @{
    location = "eastus"
    properties = @{
        description = "Export MDC alerts + recommendations to Sentinel workspace"
        scopes = @( @{ description = "Subscription"; scopePath = "/subscriptions/$subId" } )
        sources = @(
            @{ eventSource = "Alerts"; ruleSets = $null }
            @{ eventSource = "Assessments"; ruleSets = $null }
        )
        actions = @(
            @{
                actionType = "Workspace"
                workspaceResourceId = $wsId
            }
        )
        isEnabled = $true
    }
} | ConvertTo-Json -Depth 6

az rest --method put --uri $exportUri --body $exportBody
```

---

## Step 8: Verify via audit toolkit

```powershell
./run-audit.ps1 -TenantId ... -SubscriptionId ...
```

Defender for Cloud phase should show:
- Plans inventory with intended Standard upgrades reflected
- Secure Score percentage reported
- Recommendation severity breakdown
- Continuous export to Sentinel confirmed

---

## Framework alignment

- NIST CSF 2.0: ID.RA-01, DE.CM-04, DE.AE-03
- Microsoft Cloud Security Benchmark: PV-1, LT-1
