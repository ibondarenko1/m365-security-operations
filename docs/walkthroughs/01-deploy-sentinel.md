# Walkthrough: Deploy Microsoft Sentinel on a fresh subscription

End-to-end deployment of a working Sentinel workspace with detection content + cost controls. Target audience: solo defender bringing up SIEM from scratch on a small-org Azure subscription.

Time required: ~30 minutes. Cost: ~$0 during 31-day Sentinel free trial that auto-starts on first onboarding.

---

## Prerequisites

- Active Azure subscription (Pay-As-You-Go or Free Trial)
- Azure CLI 2.86+ installed and logged in: `az login --tenant <your-tenant-id>`
- Account has Contributor role on subscription
- PowerShell 7+ (or Windows PowerShell 5.1)

---

## Step 1: Register required resource providers

Five providers must be registered before workspace + Sentinel deployment. They're idempotent; safe to re-run.

```powershell
$providers = @(
    "Microsoft.OperationalInsights",
    "Microsoft.OperationsManagement",
    "Microsoft.SecurityInsights",
    "Microsoft.Insights",
    "Microsoft.Security"
)
foreach ($p in $providers) {
    az provider register --namespace $p --wait
}
```

Each takes 1-5 minutes. Run them sequentially or in parallel via `--no-wait` + a final loop.

---

## Step 2: Create resource group + Log Analytics workspace

```powershell
$rg = "sec-rg"
$ws = "sec-ws"
$location = "eastus"  # Use the same region as your existing Azure resources

az group create --name $rg --location $location

az monitor log-analytics workspace create `
    --resource-group $rg `
    --workspace-name $ws `
    --location $location `
    --sku PerGB2018 `
    --retention-time 30
```

`PerGB2018` is the modern pay-per-GB SKU. 30-day retention is the free floor.

---

## Step 3: Apply daily ingestion cap (cost safety)

```powershell
az monitor log-analytics workspace update `
    --resource-group $rg `
    --workspace-name $ws `
    --quota 0.5
```

0.5 GB/day is a sane starting cap for a small org. Workspace stops ingesting after the cap is hit until reset at 22:00 UTC. Adjust upward once you understand your baseline.

---

## Step 4: Onboard Sentinel

```powershell
$wsId = az monitor log-analytics workspace show -g $rg -n $ws --query id -o tsv
$subId = az account show --query id -o tsv
$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-09-01"

az rest --method put --uri $onboardUri --body '{"properties":{"customerManagedKey":false}}'
```

Triggers the 31-day Sentinel free trial automatically.

---

## Step 5: Route Activity Log to the workspace

```powershell
$diagUri = "https://management.azure.com/subscriptions/$subId/providers/microsoft.insights/diagnosticSettings/activity-to-sentinel?api-version=2021-05-01-preview"
$body = @{
    properties = @{
        workspaceId = $wsId
        logs = @(
            @{ category = "Administrative";   enabled = $true }
            @{ category = "Security";         enabled = $true }
            @{ category = "ServiceHealth";    enabled = $true }
            @{ category = "Alert";            enabled = $true }
            @{ category = "Policy";           enabled = $true }
        )
    }
} | ConvertTo-Json -Depth 4

az rest --method put --uri $diagUri --body $body
```

`AzureActivity` table starts populating within 10-15 minutes.

---

## Step 6: Deploy the 5 baseline analytics rules from this repo

```powershell
cd m365-security-operations/01-sentinel-detection-engineering/analytics-rules

foreach ($file in Get-ChildItem -Filter "*.json") {
    Write-Host "Deploying $($file.Name)..."
    az deployment group create `
        --resource-group $rg `
        --template-file $file.FullName `
        --parameters workspaceName=$ws
}
```

5 MITRE-mapped Scheduled Analytics Rules deployed. Fusion (Advanced Multistage Attack Detection) auto-enables during Sentinel onboarding.

---

## Step 7: Set $5/month budget alert (cost safety)

```powershell
$budgetUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Consumption/budgets/sec-budget?api-version=2024-08-01"
$start = (Get-Date -Format "yyyy-MM-01")
$end = ((Get-Date).AddYears(5).ToString("yyyy-MM-01"))

$budgetBody = @{
    properties = @{
        category = "Cost"
        amount = 5
        timeGrain = "Monthly"
        timePeriod = @{ startDate = $start; endDate = $end }
        notifications = @{
            Actual_GT_80 = @{
                enabled = $true; operator = "GreaterThan"; threshold = 80; thresholdType = "Actual"
                contactEmails = @("you@example.com")
            }
        }
    }
} | ConvertTo-Json -Depth 5

az rest --method put --uri $budgetUri --body $budgetBody
```

---

## Step 8: Verify

```powershell
./run-audit.ps1 `
    -TenantId (az account show --query tenantId -o tsv) `
    -SubscriptionId $subId `
    -Domain <your-domain> `
    -WorkspaceName $ws `
    -ResourceGroup $rg
```

The Sentinel phase should show no P1 findings. Workspace status, daily quota, retention, onboarding, rules count, and Activity Log diagnostic setting should all return INFO-level confirmations.

---

## Decommission

When study/lab is done:

```powershell
az group delete --name sec-rg --yes --no-wait
```

Removes workspace, Sentinel content, rules, analytics — everything. Subscription untouched.

---

## Framework alignment

This deployment satisfies:
- NIST CSF 2.0: DE.CM-01, DE.AE-02
- NIST SP 800-53 Rev. 5: AU-2, AU-6, SI-4
- ISO 27001:2022: A.5.25, A.8.16

MITRE ATT&CK tactic coverage via the 5 rules: Persistence (T1098), Impact (T1485), Discovery (T1087), Privilege Escalation (T1098 via RBAC), Defense Evasion (T1562 via NSG modifications).
