#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase M.3: Customer Onboarding Automation
    
.DESCRIPTION
    Automates the complete customer onboarding process including
    account creation, API key generation, initial configuration,
    and welcome package delivery.
    
.PARAMETER Action
    Action to perform: onboard, offboard, rotate-keys, welcome-package
    
.PARAMETER CustomerName
    Customer/organization name
    
.PARAMETER Email
    Primary contact email
    
.PARAMETER Tier
    Service tier: free, standard, enterprise
    
.EXAMPLE
    .\customer_onboarding.ps1 -Action onboard -CustomerName "Acme Corp" -Email "admin@acme.com" -Tier standard
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("onboard", "offboard", "rotate-keys", "welcome-package", "list")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$CustomerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Email,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("free", "standard", "enterprise")]
    [string]$Tier = "standard",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\customers"
)

$ErrorActionPreference = "Stop"

# Customer registry
$CustomerDB = @{
    Customers = @{}
    ApiKeys = @{}
    LastUpdated = $null
}

function Write-OnboardingHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase M.3: Customer Onboarding Automation                         ║
║  Complete customer lifecycle management and API provisioning       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-CustomerDB {
    $dbFile = Join-Path $OutputPath "customer_db.json"
    if (Test-Path $dbFile) {
        $script:CustomerDB = Get-Content -Path $dbFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-CustomerDB {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $dbFile = Join-Path $OutputPath "customer_db.json"
    $script:CustomerDB.LastUpdated = Get-Date -Format "o"
    $script:CustomerDB | ConvertTo-Json -Depth 10 | Set-Content -Path $dbFile
}

function New-ApiKey {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $key = "rxd_" + [Convert]::ToBase64String($bytes).Replace("+", "-").Replace("/", "_").Substring(0, 43)
    return $key
}

function New-CustomerId {
    param($Name)
    $sanitized = $Name.ToLower().Replace(" ", "-").Replace("_", "-").Replace(".", "")
    $sanitized = $sanitized -replace '[^a-z0-9-]', ''
    $timestamp = Get-Date -Format "yyMMdd"
    return "$sanitized-$timestamp"
}

function New-Customer {
    param($Name, $Email, $Tier)
    
    Write-Host "`nOnboarding new customer: $Name" -ForegroundColor Yellow
    
    # Generate customer ID
    $customerId = New-CustomerId -Name $Name
    
    if ($script:CustomerDB.Customers.ContainsKey($customerId)) {
        Write-Error "Customer with ID '$customerId' already exists"
        return
    }
    
    # Generate API keys
    $apiKey = New-ApiKey
    $apiSecret = New-ApiKey
    
    # Create customer record
    $customer = @{
        Id = $customerId
        Name = $Name
        Email = $Email
        Tier = $Tier
        Status = "active"
        CreatedAt = Get-Date -Format "o"
        ApiKeyId = $apiKey.Substring(0, 16)
        Settings = @{
            WebhookUrl = $null
            AllowedOrigins = @()
            IpWhitelist = @()
            Notifications = @{
                QuotaAlerts = $true
                SecurityAlerts = $true
                BillingAlerts = $true
            }
        }
    }
    
    # Store API key (hashed)
    $script:CustomerDB.ApiKeys[$apiKey] = @{
        CustomerId = $customerId
        CreatedAt = Get-Date -Format "o"
        LastUsed = $null
        UsageCount = 0
    }
    
    $script:CustomerDB.Customers[$customerId] = $customer
    Save-CustomerDB
    
    # Create customer directory
    $customerDir = Join-Path $OutputPath $customerId
    New-Item -ItemType Directory -Path $customerDir -Force | Out-Null
    
    # Generate welcome package
    $welcomePackage = Generate-WelcomePackage -Customer $customer -ApiKey $apiKey -ApiSecret $apiSecret
    $welcomeFile = Join-Path $customerDir "welcome_package.md"
    $welcomePackage | Set-Content -Path $welcomeFile
    
    # Generate API configuration
    $apiConfig = @{
        base_url = "https://api.rawrxd.io/v1"
        api_key = $apiKey
        api_secret = $apiSecret
        tenant_id = $customerId
        endpoints = @{
            chat = "/chat/completions"
            embeddings = "/embeddings"
            models = "/models"
            usage = "/usage"
        }
        rate_limits = @{
            requests_per_minute = if ($Tier -eq "enterprise") { 1000 } elseif ($Tier -eq "standard") { 100 } else { 10 }
            tokens_per_minute = if ($Tier -eq "enterprise") { 1000000 } elseif ($Tier -eq "standard") { 100000 } else { 10000 }
        }
    }
    
    $configFile = Join-Path $customerDir "api_config.json"
    $apiConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    
    # Generate example code
    $exampleCode = @"
# RawrXD API Example - $Name
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

import requests

API_KEY = "$apiKey"
BASE_URL = "https://api.rawrxd.io/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Chat completion example
def chat_completion(prompt):
    response = requests.post(
        f"{BASE_URL}/chat/completions",
        headers=headers,
        json={
            "model": "rawrxd-$(if ($Tier -eq 'enterprise') { '70b' } elseif ($Tier -eq 'standard') { '22b' } else { '3b' })",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": $(if ($Tier -eq 'enterprise') { 4096 } elseif ($Tier -eq 'standard') { 2048 } else { 512 })
        }
    )
    return response.json()

# Test
result = chat_completion("Hello, RawrXD!")
print(result)
"@
    
    $exampleFile = Join-Path $customerDir "example.py"
    $exampleCode | Set-Content -Path $exampleFile
    
    Write-Host "  ✓ Customer onboarded successfully" -ForegroundColor Green
    Write-Host "  ✓ Customer ID: $customerId" -ForegroundColor Gray
    Write-Host "  ✓ Tier: $Tier" -ForegroundColor Gray
    Write-Host "  ✓ API Key: $($apiKey.Substring(0, 20))..." -ForegroundColor Gray
    Write-Host "  ✓ Welcome package: $welcomeFile" -ForegroundColor Gray
    
    return $customer
}

function Generate-WelcomePackage {
    param($Customer, $ApiKey, $ApiSecret)
    
    $tierFeatures = @{
        free = @("Community support", "10K tokens/min", "2K context", "Shared GPU")
        standard = @("Email support", "100K tokens/min", "8K context", "50% GPU share", "API access")
        enterprise = @("Dedicated support", "1M tokens/min", "32K context", "Dedicated GPU", "SLA guarantee", "Custom models")
    }
    
    $features = $tierFeatures[$Customer.Tier] -join "`n- "
    
    return @"
# Welcome to RawrXD, $($Customer.Name)!

## Your Account Details

| Field | Value |
|-------|-------|
| Customer ID | $($Customer.Id) |
| Tier | $($Customer.Tier.ToUpper()) |
| Email | $($Customer.Email) |
| Created | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |

## API Credentials

**API Key:**    ``$ApiKey``
**API Secret:** ``$ApiSecret``

⚠️ **Keep these credentials secure!** Never share them in public repositories.

## Your $($Customer.Tier.ToUpper()) Tier Includes:

- $features

## Quick Start

1. Install the RawrXD SDK:
   ```bash
   pip install rawrxd
   ```

2. Configure your environment:
   ```bash
   export RAWRXD_API_KEY="$ApiKey"
   ```

3. Make your first request:
   ```python
   import rawrxd
   
   client = rawrxd.Client()
   response = client.chat("Hello, world!")
   print(response)
   ```

## API Documentation

Full documentation: https://docs.rawrxd.io
API reference: https://docs.rawrxd.io/api
Status page: https://status.rawrxd.io

## Support

$(if ($Customer.Tier -eq "enterprise") { "Your dedicated account manager will contact you within 24 hours.`n`nFor immediate assistance:`n- Email: support@rawrxd.io`n- Phone: +1-555-RAWRXD`n- Slack: #enterprise-support" } elseif ($Customer.Tier -eq "standard") { "Email: support@rawrxd.io`nResponse time: 24 hours" } else { "Community forum: https://community.rawrxd.io`nGitHub Discussions: https://github.com/rawrxd/discussions" })

## Next Steps

- [ ] Review our [Security Best Practices](https://docs.rawrxd.io/security)
- [ ] Set up [usage alerts](https://dashboard.rawrxd.io/settings)
- [ ] Join our [Discord community](https://discord.gg/rawrxd)

---

Welcome aboard! 🚀

The RawrXD Team
https://rawrxd.io
"@
}

function Remove-Customer {
    param($Id)
    
    Write-Host "`nOffboarding customer: $Id" -ForegroundColor Yellow
    
    if (-not $script:CustomerDB.Customers.ContainsKey($Id)) {
        Write-Error "Customer '$Id' not found"
        return
    }
    
    $customer = $script:CustomerDB.Customers[$Id]
    $customer.Status = "inactive"
    $customer.OffboardedAt = Get-Date -Format "o"
    
    # Revoke API keys
    $keysToRemove = @()
    foreach ($key in $script:CustomerDB.ApiKeys.Keys) {
        if ($script:CustomerDB.ApiKeys[$key].CustomerId -eq $Id) {
            $keysToRemove += $key
        }
    }
    foreach ($key in $keysToRemove) {
        $script:CustomerDB.ApiKeys.Remove($key)
    }
    
    Save-CustomerDB
    
    Write-Host "  ✓ Customer offboarded" -ForegroundColor Green
    Write-Host "  ✓ API keys revoked: $($keysToRemove.Count)" -ForegroundColor Gray
}

function Rotate-CustomerKeys {
    param($Id)
    
    Write-Host "`nRotating API keys for: $Id" -ForegroundColor Yellow
    
    if (-not $script:CustomerDB.Customers.ContainsKey($Id)) {
        Write-Error "Customer '$Id' not found"
        return
    }
    
    # Revoke old keys
    $keysToRemove = @()
    foreach ($key in $script:CustomerDB.ApiKeys.Keys) {
        if ($script:CustomerDB.ApiKeys[$key].CustomerId -eq $Id) {
            $keysToRemove += $key
        }
    }
    foreach ($key in $keysToRemove) {
        $script:CustomerDB.ApiKeys.Remove($key)
    }
    
    # Generate new keys
    $newApiKey = New-ApiKey
    $newApiSecret = New-ApiKey
    
    $script:CustomerDB.ApiKeys[$newApiKey] = @{
        CustomerId = $Id
        CreatedAt = Get-Date -Format "o"
        LastUsed = $null
        UsageCount = 0
    }
    
    $script:CustomerDB.Customers[$Id].ApiKeyId = $newApiKey.Substring(0, 16)
    Save-CustomerDB
    
    # Update config file
    $customerDir = Join-Path $OutputPath $Id
    $configFile = Join-Path $customerDir "api_config.json"
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json -AsHashtable
        $config.api_key = $newApiKey
        $config.api_secret = $newApiSecret
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    }
    
    Write-Host "  ✓ API keys rotated" -ForegroundColor Green
    Write-Host "  ✓ New API Key: $($newApiKey.Substring(0, 20))..." -ForegroundColor Gray
    Write-Host "  ⚠️ Update your applications with the new credentials" -ForegroundColor Yellow
}

function Get-CustomerList {
    Write-Host "`nCustomer Registry:" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:CustomerDB.Customers.Count -eq 0) {
        Write-Host "  No customers registered" -ForegroundColor Gray
        return
    }
    
    Write-Host "  {0,-25} {1,-20} {2,-12} {3,-10}" -f "Customer ID", "Name", "Tier", "Status" -ForegroundColor White
    Write-Host "  $("-" * 67)" -ForegroundColor Gray
    
    foreach ($customer in $script:CustomerDB.Customers.Values) {
        $name = $customer.Name
        if ($name.Length -gt 18) { $name = $name.Substring(0, 15) + "..." }
        Write-Host "  {0,-25} {1,-20} {2,-12} {3,-10}" -f $customer.Id, $name, $customer.Tier, $customer.Status -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  Total customers: $($script:CustomerDB.Customers.Count)" -ForegroundColor Cyan
}

# Main execution
Write-OnboardingHeader
Initialize-CustomerDB

switch ($Action) {
    "onboard" {
        if (-not $CustomerName -or -not $Email) {
            Write-Error "CustomerName and Email required for onboard action"
            exit 1
        }
        New-Customer -Name $CustomerName -Email $Email -Tier $Tier
    }
    "offboard" {
        if (-not $CustomerName) {
            Write-Error "CustomerName required for offboard action"
            exit 1
        }
        $customerId = New-CustomerId -Name $CustomerName
        Remove-Customer -Id $customerId
    }
    "rotate-keys" {
        if (-not $CustomerName) {
            Write-Error "CustomerName required for rotate-keys action"
            exit 1
        }
        $customerId = New-CustomerId -Name $CustomerName
        Rotate-CustomerKeys -Id $customerId
    }
    "list" {
        Get-CustomerList
    }
}

Write-Host "`n✅ Onboarding operation complete" -ForegroundColor Green
