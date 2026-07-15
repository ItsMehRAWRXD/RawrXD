# Phase M: Multi-Tenant SaaS Features

## Overview

Phase M transforms RawrXD from a single-tenant runtime into a full multi-tenant SaaS platform with enterprise-grade isolation, usage metering, and automated customer onboarding.

## Components

### M.1: Tenant Isolation (`phase_m1_tenant_isolation/`)

Multi-tenant namespace and resource isolation system.

**Features:**
- Kubernetes namespace generation per tenant
- Resource quotas (CPU, memory, GPU share)
- Network policies for tenant isolation
- Tier-based quota definitions (Free, Standard, Enterprise)
- Tenant lifecycle management (create, delete, update)

**Usage:**
```powershell
# Create a new enterprise tenant
.\tenant_isolation.ps1 -Action create -TenantId "acme-corp" -Tier enterprise

# List all tenants
.\tenant_isolation.ps1 -Action list

# Upgrade tenant tier
.\tenant_isolation.ps1 -Action update-quota -TenantId "acme-corp" -Tier enterprise

# Validate tenant isolation
.\tenant_isolation.ps1 -Action validate
```

**Tier Specifications:**

| Tier | Concurrent | Tokens/Min | Context | GPU Share | Storage |
|------|------------|------------|---------|-----------|---------|
| Free | 10 | 10,000 | 2K | 10% | 1GB |
| Standard | 100 | 100,000 | 8K | 50% | 10GB |
| Enterprise | 1,000 | 1,000,000 | 32K | 100% | 100GB |

### M.2: Usage Metering (`phase_m2_usage_metering/`)

Token usage tracking, quota enforcement, and billing report generation.

**Features:**
- Real-time token usage recording
- Per-tenant quota enforcement
- Monthly billing report generation
- Usage dashboard with top tenants
- JSONL audit logs for compliance

**Usage:**
```powershell
# Record token usage
.\usage_metering.ps1 -Action record -TenantId "acme-corp" -Tokens 1500

# Check quota status
.\usage_metering.ps1 -Action check-quota -TenantId "acme-corp"

# Generate billing report
.\usage_metering.ps1 -Action export-billing -Period "2026-07"

# View dashboard
.\usage_metering.ps1 -Action dashboard
```

**Pricing:**

| Tier | Input/1K | Output/1K | Storage/GB | Compute/Hr |
|------|----------|-----------|------------|------------|
| Free | $0.0000 | $0.0000 | $0.00 | $0.00 |
| Standard | $0.0001 | $0.0002 | $0.10 | $0.50 |
| Enterprise | $0.00005 | $0.0001 | $0.05 | $0.25 |

### M.3: Customer Onboarding (`phase_m3_customer_onboarding/`)

Automated customer lifecycle management and API provisioning.

**Features:**
- Automated customer ID generation
- Secure API key generation (256-bit)
- Welcome package generation (Markdown)
- Example code generation (Python)
- API key rotation
- Customer offboarding

**Usage:**
```powershell
# Onboard new customer
.\customer_onboarding.ps1 -Action onboard -CustomerName "Acme Corp" -Email "admin@acme.com" -Tier standard

# List all customers
.\customer_onboarding.ps1 -Action list

# Rotate API keys
.\customer_onboarding.ps1 -Action rotate-keys -CustomerName "Acme Corp"

# Offboard customer
.\customer_onboarding.ps1 -Action offboard -CustomerName "Acme Corp"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD SaaS Platform                      │
├─────────────────────────────────────────────────────────────┤
│  M.3 Customer Onboarding  │  M.2 Usage Metering            │
│  ├─ Account creation      │  ├─ Token tracking              │
│  ├─ API key generation    │  ├─ Quota enforcement          │
│  ├─ Welcome packages      │  ├─ Billing reports            │
│  └─ Lifecycle management    │  └─ Dashboard                  │
├─────────────────────────────────────────────────────────────┤
│                    M.1 Tenant Isolation                      │
│  ├─ Kubernetes namespaces                                   │
│  ├─ Resource quotas                                         │
│  ├─ Network policies                                        │
│  └─ Tier-based isolation                                    │
├─────────────────────────────────────────────────────────────┤
│                    RawrXD Inference Engine                   │
└─────────────────────────────────────────────────────────────┘
```

## Integration

### With Existing Infrastructure

1. **Phase J Performance Tuning**: Tenant tiers map to performance profiles
2. **Phase I CI/CD**: SaaS deployment via GitHub Actions
3. **Phase L Governance**: Security patches apply to all tenants
4. **Phase H Enterprise**: SSO integration for enterprise tenants

### Data Flow

```
Customer Request → API Gateway → Tenant Validation → Quota Check
                                              ↓
                                    [Pass] → Inference Engine
                                    [Fail] → 429 Rate Limit
                                              ↓
                                    Usage Recorded → Billing
```

## Security

- **Tenant Isolation**: Kubernetes network policies prevent cross-tenant access
- **API Keys**: 256-bit random keys with secure storage
- **Encryption**: AES-256-GCM for tenant data at rest
- **Audit Logs**: Immutable JSONL logs for compliance
- **Quota Enforcement**: Hard limits prevent resource exhaustion

## Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- PowerShell 7.0+

### Quick Start

```powershell
# 1. Create tenant
.\phase_m1_tenant_isolation\tenant_isolation.ps1 -Action create -TenantId "demo" -Tier standard

# 2. Onboard customer
.\phase_m3_customer_onboarding\customer_onboarding.ps1 -Action onboard -CustomerName "Demo Corp" -Email "demo@example.com" -Tier standard

# 3. Record usage
.\phase_m2_usage_metering\usage_metering.ps1 -Action record -TenantId "demo" -Tokens 1000

# 4. View dashboard
.\phase_m2_usage_metering\usage_metering.ps1 -Action dashboard
```

## Monitoring

### Key Metrics

- **Active Tenants**: Number of currently active tenants
- **Token Throughput**: Total tokens processed per minute
- **Revenue**: Monthly recurring revenue (MRR)
- **Quota Utilization**: Average quota usage across tenants
- **API Latency**: P50/P95/P99 response times

### Alerts

- Quota utilization > 80%
- API error rate > 1%
- New tenant onboarding failures
- Unusual usage patterns (potential abuse)

## Roadmap

### Phase M.4 (Planned)
- Stripe billing integration
- Usage-based pricing automation
- Customer self-service portal

### Phase M.5 (Planned)
- Multi-region deployment
- Data residency compliance (GDPR)
- Advanced analytics dashboard

## License

Part of RawrXD Enterprise Platform - See LICENSE for details.
