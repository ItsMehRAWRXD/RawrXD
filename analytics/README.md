# Phase O: Analytics & Business Intelligence

## Overview

Phase O provides comprehensive analytics and business intelligence capabilities for the RawrXD SaaS platform. This phase delivers data-driven insights for usage patterns, customer health, and executive reporting.

## Components

### O.1: Usage Analytics (`phase_o1_usage_analytics/`)

Comprehensive usage analytics engine for tracking token consumption and API patterns.

**Features:**
- Token consumption analysis by period (daily/weekly/monthly)
- Usage trends and growth rate calculations
- Predictive forecasting (moving average)
- Top consumer identification
- Daily usage pattern analysis
- JSON/CSV export for external systems

**Usage:**
```powershell
# Analyze monthly usage
.\usage_analytics.ps1 -Action analyze -Period monthly

# View trends
.\usage_analytics.ps1 -Action trends -TenantId "acme-corp"

# Generate 30-day forecast
.\usage_analytics.ps1 -Action forecast -ForecastDays 30

# Export data
.\usage_analytics.ps1 -Action export

# View dashboard
.\usage_analytics.ps1 -Action dashboard
```

**Metrics Tracked:**
- Total tokens by tenant
- Token growth rates
- Daily/weekly patterns
- Top 10 consumers
- Revenue correlation

### O.2: Customer Insights (`phase_o2_customer_insights/`)

Customer behavior analysis and health scoring system.

**Features:**
- Health score calculation (0-100)
- Churn risk identification
- Expansion opportunity detection
- Customer segmentation
- Activity tracking

**Health Score Components:**
| Component | Weight | Description |
|-----------|--------|-------------|
| Usage Frequency | 30% | Days active per month |
| Token Growth | 25% | Week-over-week growth |
| Feature Adoption | 20% | Feature utilization |
| Support Tickets | 15% | Support burden |
| Uptime | 10% | Service availability |

**Usage:**
```powershell
# Calculate health scores
.\customer_insights.ps1 -Action score

# Check specific tenant
.\customer_insights.ps1 -Action health -TenantId "acme-corp"

# Identify churn risks
.\customer_insights.ps1 -Action churn

# Find expansion opportunities
.\customer_insights.ps1 -Action expansion

# View customer segments
.\customer_insights.ps1 -Action segments
```

**Customer Segments:**
- **Champions**: High usage + long tenure
- **Power Users**: >1M tokens, >20 days active
- **Regular Users**: >100K tokens, >10 days active
- **Light Users**: Below regular thresholds
- **At Risk**: Declining usage patterns

### O.3: Business Intelligence (`phase_o3_business_intelligence/`)

Executive dashboards and financial metrics for SaaS business tracking.

**Features:**
- MRR (Monthly Recurring Revenue) tracking
- ARR (Annual Recurring Revenue) calculation
- ARPU (Average Revenue Per User) metrics
- Customer churn analysis
- Gross margin tracking
- Net Revenue Retention (NRR)
- Executive summary dashboard

**Pricing Tiers:**
| Tier | Monthly Price |
|------|---------------|
| Free | $0 |
| Standard | $99 |
| Enterprise | $999 |

**Usage:**
```powershell
# View executive dashboard
.\business_intelligence.ps1 -Action dashboard

# Calculate MRR
.\business_intelligence.ps1 -Action mrr -Period current

# View business metrics
.\business_intelligence.ps1 -Action metrics

# Export BI report
.\business_intelligence.ps1 -Action export
```

**Key Metrics:**
- MRR/ARR
- ARPU
- Churn Rate
- Net Revenue Retention
- Logo Retention
- Gross Margin

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Analytics                         │
├─────────────────────────────────────────────────────────────┤
│  O.3 Business Intelligence │  O.2 Customer Insights         │
│  ├─ Executive dashboard      │  ├─ Health scoring             │
│  ├─ MRR/ARR tracking         │  ├─ Churn prediction           │
│  ├─ Financial metrics        │  ├─ Expansion opportunities    │
│  └─ BI reporting             │  └─ Customer segmentation      │
├─────────────────────────────────────────────────────────────┤
│                    O.1 Usage Analytics                        │
│  ├─ Token consumption analysis                              │
│  ├─ Usage trends and forecasting                            │
│  ├─ Top consumer identification                               │
│  └─ Pattern analysis                                          │
├─────────────────────────────────────────────────────────────┤
│                    RawrXD SaaS Data                         │
└─────────────────────────────────────────────────────────────┘
```

## Integration

### With Phase M (SaaS)
- Reads tenant data from Phase M metering system
- Uses tenant tiers for segmentation
- Consumes usage logs for analysis

### With Phase N (Operations)
- Health scores feed into monitoring alerts
- Churn risks trigger incident creation
- Business metrics inform capacity planning

### With Phase J (Performance)
- Usage patterns inform performance tuning
- Forecasts drive capacity planning

## Data Flow

```
Phase M Metering Data
         ↓
    Analytics Engine
         ↓
    ├─ Usage Analytics → Trends, Forecasts
    ├─ Customer Insights → Health Scores, Churn Risk
    └─ Business Intelligence → MRR, ARR, Metrics
         ↓
    Dashboards & Reports
```

## Deployment

### Prerequisites
- PowerShell 7.0+
- Phase M metering data (for data source)
- Sufficient disk space for analytics cache

### Quick Start

```powershell
# 1. Generate usage analysis
.\phase_o1_usage_analytics\usage_analytics.ps1 -Action analyze -Period monthly

# 2. Calculate customer health scores
.\phase_o2_customer_insights\customer_insights.ps1 -Action score

# 3. View executive dashboard
.\phase_o3_business_intelligence\business_intelligence.ps1 -Action dashboard

# 4. Identify churn risks
.\phase_o2_customer_insights\customer_insights.ps1 -Action churn
```

## Analytics Best Practices

### Usage Analytics
1. **Regular Analysis**: Run weekly trend analysis
2. **Forecasting**: Use 30-day forecasts for capacity planning
3. **Export**: Export monthly for external BI tools
4. **Monitoring**: Watch for unusual patterns

### Customer Insights
1. **Health Scores**: Review weekly, act on critical scores
2. **Churn Prevention**: Contact at-risk customers proactively
3. **Expansion**: Reach out to upgrade candidates
4. **Segmentation**: Tailor messaging by segment

### Business Intelligence
1. **MRR Tracking**: Monitor daily, report weekly
2. **Churn Analysis**: Monthly deep-dive on churn reasons
3. **NRR Goals**: Target >100% net revenue retention
4. **Executive Reports**: Weekly summary to leadership

## Metrics Reference

### Usage Metrics
- **Total Tokens**: Lifetime token consumption
- **Daily Average**: Average tokens per day
- **Growth Rate**: Week-over-week percentage change
- **Peak Usage**: Highest daily consumption

### Customer Metrics
- **Health Score**: 0-100 composite score
- **Activity Rate**: % of days with usage
- **Churn Risk**: High/Medium/Low classification
- **Segment**: Champion/Power/Regular/Light

### Business Metrics
- **MRR**: Monthly Recurring Revenue
- **ARR**: Annual Recurring Revenue
- **ARPU**: Average Revenue Per User
- **NRR**: Net Revenue Retention
- **Churn Rate**: % customers lost per period

## Roadmap

### Phase O.4 (Planned)
- Real-time analytics streaming
- Advanced ML forecasting
- Cohort analysis
- Funnel tracking

### Phase O.5 (Planned)
- Custom dashboard builder
- Alert-based analytics
- A/B testing framework
- Predictive customer lifetime value

## License

Part of RawrXD Enterprise Platform - See LICENSE for details.
