# Phase L.5/5: Long-Term Support (LTS) Policy

## Overview

This document defines the Long-Term Support (LTS) policy for RawrXD Sovereign AI Runtime, ensuring predictable release cycles, clear support timelines, and stable production deployments.

**Version:** 1.0.0  
**Effective Date:** 2026-07-13  
**Last Updated:** 2026-07-13

---

## Release Cadence

### Version Numbering

RawrXD follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

- **MAJOR**: Incompatible API changes, architectural overhauls
- **MINOR**: New features, backwards-compatible additions
- **PATCH**: Bug fixes, security patches, performance improvements

### Release Types

| Type | Frequency | Support Duration | Purpose |
|------|-----------|------------------|---------|
| **Development** | Continuous | N/A | Active development, unstable |
| **Stable** | Monthly | 3 months | Latest features, short-term support |
| **LTS** | Every 6 months | 24 months | Production deployments, long-term stability |

### Release Schedule

```
2026-Q3: v1.0.0 LTS (Initial Release)
2026-Q4: v1.1.0 Stable
2027-Q1: v1.2.0 Stable
2027-Q2: v2.0.0 LTS
2027-Q3: v2.1.0 Stable
2027-Q4: v2.2.0 Stable
2028-Q1: v3.0.0 LTS
```

---

## Support Lifecycle

### LTS Releases

LTS releases receive:

- **Security patches**: Within 72 hours of CVE disclosure
- **Critical bug fixes**: Within 7 days
- **High-priority fixes**: Within 30 days
- **Documentation updates**: Continuous
- **Community support**: Full

### Stable Releases

Stable releases receive:

- **Security patches**: Within 7 days
- **Critical bug fixes**: Within 14 days
- **Community support**: Best effort

### End-of-Life (EOL)

| Version | Release Date | EOL Date | Status |
|---------|--------------|----------|--------|
| v1.0.0 | 2026-07-13 | 2028-07-13 | **Current LTS** |

---

## Support Channels

### Community Support (Free)

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Q&A, usage help
- **Discord**: Real-time community chat
- **Stack Overflow**: Tag `rawrxd`

**Response Times:**
- Critical issues: 24 hours
- General issues: 7 days
- Questions: 14 days

### Commercial Support

Available for enterprise customers:

- **24/7 Phone Support**: P0 incidents
- **Dedicated Slack Channel**: Direct engineering access
- **SLA Guarantees**: Defined response and resolution times
- **Custom Development**: Feature prioritization
- **Training**: On-site or virtual

Contact: enterprise@rawrxd.ai

---

## Patch Policy

### Security Patches

**Severity Levels:**

| Severity | CVSS Score | Response Time | Deployment |
|----------|------------|---------------|------------|
| Critical | 9.0-10.0 | 4 hours | Emergency |
| High | 7.0-8.9 | 24 hours | Expedited |
| Medium | 4.0-6.9 | 7 days | Standard |
| Low | 0.1-3.9 | 30 days | Next release |

**Emergency Deployment Process:**

1. Security team validates vulnerability
2. Patch developed and tested
3. Emergency release created (vX.Y.Z+security.1)
4. Immediate notification to users
5. Available via hotpatch system

### Bug Fix Releases

**Release Schedule:**

- **Weekly**: Patch releases for critical/high bugs
- **Bi-weekly**: Standard bug fix releases
- **Monthly**: Cumulative patch releases

**Versioning:**

```
v1.0.1  # First patch
v1.0.2  # Second patch
v1.0.3  # Third patch
```

---

## Upgrade Policy

### Supported Upgrade Paths

```
v1.0.0 → v1.0.1 ✓ (Patch)
v1.0.0 → v1.1.0 ✓ (Minor)
v1.0.0 → v2.0.0 ✓ (Major, migration required)
v1.0.0 → v3.0.0 ✗ (Must upgrade through v2.0.0)
```

### Breaking Changes

Breaking changes are only introduced in **major releases** with:

- 6-month advance notice
- Migration guide documentation
- Automated migration tools where possible
- Parallel support period (old + new API)

### Deprecation Policy

1. **Announcement**: Feature marked deprecated in release notes
2. **Warning Period**: 6 months of deprecation warnings
3. **Removal**: Feature removed in next major release

---

## Compatibility Guarantees

### API Compatibility

**Within Major Version:**
- REST API: Backwards compatible
- CLI: Backwards compatible
- Configuration: Backwards compatible
- Model format: Backwards compatible

**Across Major Versions:**
- Migration guide provided
- Breaking changes documented
- Compatibility layer where feasible

### Platform Compatibility

| Platform | Minimum Version | Support Status |
|----------|-----------------|----------------|
| Windows | 10/Server 2019 | ✅ Supported |
| Ubuntu | 20.04 LTS | ✅ Supported |
| Debian | 11 | ✅ Supported |
| RHEL | 8 | ✅ Supported |
| macOS | 12 (Monterey) | ✅ Supported |

### GPU Compatibility

| Vendor | Architecture | Support Status |
|--------|--------------|----------------|
| NVIDIA | Turing+ | ✅ Full support |
| AMD | RDNA2+ | ✅ Full support |
| Intel | Arc/Xe | ⚠️ Beta support |

---

## End-of-Life Process

### 6 Months Before EOL

- EOL announcement in release notes
- Migration guide published
- Support timeline communicated

### 3 Months Before EOL

- Final security patches released
- Migration assistance offered
- Upgrade incentives provided

### At EOL

- Version moved to archive
- No further patches released
- Documentation archived
- Community support only

### Post-EOL

- Critical security issues: Best effort
- No bug fixes
- No feature backports

---

## Service Level Agreements (SLA)

### Response Times

| Severity | Community | Enterprise |
|----------|-----------|------------|
| P0 - Critical | 24 hours | 1 hour |
| P1 - High | 7 days | 4 hours |
| P2 - Medium | 14 days | 24 hours |
| P3 - Low | 30 days | 72 hours |

### Resolution Times

| Severity | Community | Enterprise |
|----------|-----------|------------|
| P0 - Critical | Best effort | 24 hours |
| P1 - High | Best effort | 72 hours |
| P2 - Medium | Best effort | 7 days |
| P3 - Low | Best effort | 30 days |

### Uptime Guarantee

- **LTS Releases**: 99.9% uptime
- **Stable Releases**: 99.5% uptime
- **Development**: No guarantee

---

## Contact Information

### Support Channels

| Channel | URL/Contact | Purpose |
|---------|-------------|---------|
| GitHub Issues | github.com/ItsMehRAWRXD/RawrXD/issues | Bug reports |
| GitHub Discussions | github.com/ItsMehRAWRXD/RawrXD/discussions | Q&A |
| Discord | discord.gg/rawrxd | Community chat |
| Email | support@rawrxd.ai | General support |
| Enterprise | enterprise@rawrxd.ai | Commercial inquiries |

### Security Reports

**DO NOT** file public issues for security vulnerabilities.

Email: security@rawrxd.ai

PGP Key: [security@rawrxd.ai.asc](https://rawrxd.ai/security-pgp.asc)

---

## Frequently Asked Questions

### Q: Which version should I use in production?

**A:** Use the latest LTS release (currently v1.0.0) for production deployments. Stable releases are suitable for development and testing.

### Q: How do I know when a new version is available?

**A:** Subscribe to:
- GitHub releases (watch repository)
- Release announcement mailing list
- RSS feed: https://rawrxd.ai/releases.xml

### Q: Can I get extended support for an EOL version?

**A:** Enterprise customers can purchase extended support for up to 12 months past EOL. Contact enterprise@rawrxd.ai.

### Q: What happens if I don't upgrade before EOL?

**A:** You can continue using the software, but will not receive security patches or bug fixes. We strongly recommend upgrading before EOL.

### Q: Are there paid support options?

**A:** Yes, enterprise support includes 24/7 phone support, SLA guarantees, dedicated Slack channel, and custom development. See "Commercial Support" section above.

---

## Policy Updates

This policy may be updated periodically. Changes will be:

1. Announced 30 days in advance
2. Documented in CHANGELOG
3. Communicated via mailing list
4. Posted on website

**Policy Version History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial policy |

---

## Legal

This support policy is provided "as is" without warranty of any kind. RawrXD reserves the right to modify this policy at any time.

For enterprise support contracts, specific terms and conditions apply as defined in the service agreement.

---

**Document Information:**
- **Version:** 1.0.0
- **Owner:** Support Team
- **Review Cycle:** Quarterly
- **Next Review:** 2026-10-13

*Last updated: 2026-07-13*
