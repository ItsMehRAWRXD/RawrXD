# Phase H.1 Batch 3/5: SLA Guarantees

## Service Level Agreement Framework

---

## Overview

This document defines the Service Level Agreements (SLAs) for RawrXD enterprise deployments, including availability commitments, support tiers, and escalation procedures.

---

## Availability SLAs

### Standard Tier (99.9%)

**Monthly Uptime:** 99.9% (43.8 minutes downtime/month)

**Scope:**
- RawrXD inference API
- Telemetry dashboard
- Hotpatch engine

**Exclusions:**
- Scheduled maintenance (4 hours/month max)
- Customer-caused issues
- Third-party service failures
- Force majeure events

### Enterprise Tier (99.95%)

**Monthly Uptime:** 99.95% (21.9 minutes downtime/month)

**Scope:**
- Everything in Standard
- Multi-node cluster coordination
- Automatic failover
- Priority support

### Mission Critical Tier (99.99%)

**Monthly Uptime:** 99.99% (4.38 minutes downtime/month)

**Scope:**
- Everything in Enterprise
- Dedicated infrastructure
- 24/7 NOC monitoring
- 15-minute response guarantee

---

## Performance SLAs

### Inference Latency

| Tier | P50 Latency | P99 Latency |
|------|-------------|-------------|
| Standard | < 50ms | < 100ms |
| Enterprise | < 40ms | < 80ms |
| Mission Critical | < 30ms | < 60ms |

### Throughput (TPS)

| Tier | Minimum TPS | Burst Capability |
|------|-------------|------------------|
| Standard | 40 TPS | 60 TPS (5 min) |
| Enterprise | 50 TPS | 80 TPS (10 min) |
| Mission Critical | 60 TPS | 100 TPS (15 min) |

### Hotpatch Deployment

| Metric | Guarantee |
|--------|-----------|
| Deployment Time | < 5ms |
| Rollback Time | < 2ms |
| Success Rate | > 99.9% |

---

## Support Tiers

### Standard Support

**Hours:** Business hours (9 AM - 5 PM, Mon-Fri, US Pacific)

**Channels:**
- Email: support@rawrxd.io
- Community Discord
- Documentation

**Response Times:**
| Severity | Response | Resolution Target |
|----------|----------|-------------------|
| Critical | 4 hours | 24 hours |
| High | 8 hours | 48 hours |
| Medium | 24 hours | 5 days |
| Low | 48 hours | 10 days |

### Enterprise Support

**Hours:** Extended (7 AM - 7 PM, Mon-Fri, US Pacific)

**Channels:**
- Everything in Standard
- Phone support
- Slack Connect
- Dedicated support engineer

**Response Times:**
| Severity | Response | Resolution Target |
|----------|----------|-------------------|
| Critical | 1 hour | 4 hours |
| High | 4 hours | 24 hours |
| Medium | 8 hours | 48 hours |
| Low | 24 hours | 5 days |

### Mission Critical Support

**Hours:** 24/7/365

**Channels:**
- Everything in Enterprise
- Direct phone line
- PagerDuty integration
- On-call escalation

**Response Times:**
| Severity | Response | Resolution Target |
|----------|----------|-------------------|
| Critical | 15 minutes | 1 hour |
| High | 1 hour | 4 hours |
| Medium | 4 hours | 24 hours |
| Low | 8 hours | 48 hours |

---

## Severity Definitions

### Critical (P1)
- Production system down
- Data loss or corruption
- Security breach
- Complete service unavailability

### High (P2)
- Major feature unavailable
- Significant performance degradation
- Workaround exists but is difficult

### Medium (P3)
- Minor feature unavailable
- Performance issues with workaround
- Non-production system down

### Low (P4)
- Cosmetic issues
- Documentation errors
- Feature requests

---

## Escalation Procedures

### Standard Escalation

```
L1 Support → L2 Engineering → Engineering Manager → VP Engineering
(4 hours)    (8 hours)         (24 hours)          (48 hours)
```

### Enterprise Escalation

```
Support Engineer → Senior Engineer → Engineering Manager → VP → CTO
(1 hour)           (4 hours)         (8 hours)           (24 hrs)
```

### Mission Critical Escalation

```
NOC → On-Call Engineer → Engineering Manager → VP → CTO → CEO
(15 min)  (30 min)        (1 hour)          (2 hrs) (4 hrs)
```

---

## Service Credits

### Availability Credits

| Downtime | Standard | Enterprise | Mission Critical |
|----------|----------|------------|------------------|
| < 1 hour | 5% | 10% | 25% |
| 1-4 hours | 10% | 25% | 50% |
| 4-8 hours | 25% | 50% | 100% |
| > 8 hours | 50% | 100% | 100% + account review |

### Performance Credits

| Violation | Credit |
|-----------|--------|
| P99 latency > SLA | 10% monthly fee |
| TPS < minimum | 10% monthly fee |
| Hotpatch failure > 0.1% | 5% monthly fee |

**Maximum Credit:** 100% of monthly fee

---

## SLA Monitoring

### Metrics Tracked

1. **Availability**
   - Measured per minute
   - Probed from 3+ locations
   - Excludes scheduled maintenance

2. **Latency**
   - P50, P95, P99 percentiles
   - Measured end-to-end
   - Geographic breakdown

3. **Throughput**
   - Sustained TPS
   - Burst capability
   - Error rate

4. **Hotpatch Success**
   - Deployment success rate
   - Rollback frequency
   - Performance delta

### Reporting

- **Real-time:** Dashboard at https://status.rawrxd.io
- **Daily:** Automated email summary
- **Monthly:** SLA compliance report
- **Quarterly:** Business review meeting

---

## Exclusions

SLA does not cover:

1. **Customer-caused issues**
   - Misconfiguration
   - Resource exhaustion
   - Invalid API calls

2. **Third-party services**
   - Cloud provider outages
   - CDN failures
   - DNS issues

3. **Scheduled maintenance**
   - Announced 7 days in advance
   - Max 4 hours/month
   - Outside business hours preferred

4. **Force majeure**
   - Natural disasters
   - Acts of war
   - Government actions

5. **Beta features**
   - Experimental functionality
   - Preview releases
   - Non-production environments

---

## SLA Modification

### Process

1. Customer requests SLA change
2. Technical review of requirements
3. Pricing adjustment if needed
4. Contract amendment
5. Implementation

### Timeline

- Standard changes: 30 days
- Complex changes: 60 days
- Emergency changes: 7 days (with approval)

---

## Contact Information

### Support Channels

| Tier | Email | Phone | Slack |
|------|-------|-------|-------|
| Standard | support@rawrxd.io | — | Community |
| Enterprise | enterprise@rawrxd.io | +1-555-RAW-RXD1 | Connect |
| Mission Critical | critical@rawrxd.io | +1-555-RAW-RXD9 | Dedicated |

### Escalation Contacts

| Role | Name | Email | Phone |
|------|------|-------|-------|
| VP Engineering | [TBD] | vp-eng@rawrxd.io | +1-555-RAW-RXD2 |
| CTO | [TBD] | cto@rawrxd.io | +1-555-RAW-RXD3 |
| CEO | [TBD] | ceo@rawrxd.io | +1-555-RAW-RXD0 |

---

## SLA Agreement Template

```
SERVICE LEVEL AGREEMENT

Customer: [Customer Name]
Tier: [Standard/Enterprise/Mission Critical]
Effective Date: [Date]
Term: 12 months

1. AVAILABILITY COMMITMENT
   [ ] 99.9% (Standard)
   [ ] 99.95% (Enterprise)
   [ ] 99.99% (Mission Critical)

2. PERFORMANCE COMMITMENTS
   P50 Latency: < [30/40/50] ms
   P99 Latency: < [60/80/100] ms
   Minimum TPS: [60/50/40]

3. SUPPORT
   Hours: [Business/Extended/24x7]
   Response Time (Critical): [4/1/0.25] hours
   Dedicated Engineer: [No/Yes/Yes]

4. PRICING
   Monthly Fee: $[Amount]
   Overage Rate: $[Amount] per TPS

5. SIGNATURES
   ___________________    ___________________
   Customer Signature     RawrXD Signature
   
   ___________________    ___________________
   Date                   Date
```

---

## Review Schedule

| Review | Frequency | Next Review |
|--------|-----------|-------------|
| SLA Performance | Monthly | Monthly |
| SLA Terms | Annual | 2027-01-01 |
| Pricing | Annual | 2027-01-01 |
| Support Process | Quarterly | 2026-10-01 |
