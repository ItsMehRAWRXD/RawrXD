# Issue Triage Workflow

**Version:** 1.0.0  
**Purpose:** Systematic handling of GitHub issues

---

## Overview

This document defines the process for triaging issues in the RawrXD repository. All issues must be triaged within 24 hours of creation.

---

## Issue Types

### Bug Reports
- Something is broken
- Unexpected behavior
- Performance degradation
- Crash reports

### Feature Requests
- New functionality
- Improvements to existing features
- Integration requests

### Support Requests
- Usage questions
- Configuration help
- Troubleshooting

### Security Reports
- Vulnerabilities
- Security concerns
- Privacy issues

---

## Triage Process

### Step 1: Initial Review (Within 4 hours)

**Actions:**
1. Read the issue completely
2. Check for duplicates
3. Verify completeness
4. Add appropriate labels

**Labels to Apply:**
- `triage/needs-review` - Initial state
- `type/bug`, `type/feature`, `type/support`, `type/security`
- `status/confirmed` or `status/needs-info`

### Step 2: Classification (Within 24 hours)

**Priority Assignment:**

| Priority | Description | Response Time |
|----------|-------------|---------------|
| P0 - Critical | Production outage, data loss | Immediate |
| P1 - High | Major functionality broken | 24 hours |
| P2 - Medium | Feature not working as expected | 1 week |
| P3 - Low | Minor issues, enhancements | Next release |

**Severity Assignment:**

| Severity | Impact |
|----------|--------|
| SEV-1 | All users affected |
| SEV-2 | Most users affected |
| SEV-3 | Some users affected |
| SEV-4 | Few users affected |

### Step 3: Assignment

**Auto-Assignment Rules:**

| Component | Assignee |
|-----------|----------|
| GPU/Vulkan | @gpu-team |
| API/Server | @api-team |
| Models | @model-team |
| Security | @security-team |
| Documentation | @docs-team |

### Step 4: Tracking

**Status Updates:**
- `status/triaged` - Issue classified
- `status/in-progress` - Work started
- `status/needs-review` - PR submitted
- `status/resolved` - Fix merged
- `status/closed` - Released

---

## Response Templates

### Bug Report Response

```markdown
Hi @username,

Thanks for reporting this issue. I've triaged it as:
- **Priority:** P{0-3}
- **Severity:** SEV-{1-4}
- **Component:** {component}

To help us investigate, could you please provide:
1. RawrXD version: `rawrxd --version`
2. Operating system and version
3. GPU model and driver version
4. Steps to reproduce
5. Expected vs actual behavior
6. Relevant logs (if any)

We'll update this issue as we make progress.

Thanks!
```

### Feature Request Response

```markdown
Hi @username,

Thanks for the feature request! This is an interesting idea.

To help us evaluate this:
1. What's the use case?
2. Are there workarounds currently?
3. Would you be interested in contributing?

We're adding this to our backlog for consideration in a future release.

Thanks!
```

### Support Request Response

```markdown
Hi @username,

This looks like a support question rather than a bug report.

Please check our documentation:
- [Getting Started](https://docs.rawrxd.local/getting-started)
- [Troubleshooting](https://docs.rawrxd.local/troubleshooting)
- [FAQ](https://docs.rawrxd.local/faq)

If you still need help, please:
1. Join our [Discord](https://discord.gg/rawrxd)
2. Post in the #support channel
3. Include your configuration and logs

Closing this as it's not a bug report, but feel free to reopen if you find a bug!
```

---

## Escalation Procedures

### When to Escalate

- P0 issues not acknowledged within 1 hour
- Security issues
- Issues affecting enterprise customers
- Issues with no clear owner

### Escalation Path

1. **Team Lead** - @team-lead
2. **Tech Lead** - @tech-lead
3. **Project Lead** - @project-lead
4. **Emergency** - emergency@rawrxd.local

---

## Metrics

### Key Performance Indicators

| Metric | Target | Measurement |
|--------|--------|-------------|
| Triage Time | <24 hours | Time to first response |
| Resolution Time | Varies by priority | Time to close |
| Reopen Rate | <5% | Issues reopened |
| Customer Satisfaction | >90% | Survey responses |

### Weekly Reports

Generated every Monday:
- New issues this week
- Closed issues this week
- Average resolution time
- Open issues by priority
- Open issues by component

---

## Tools

### GitHub Actions

**Auto-triage:**
```yaml
name: Auto Triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v4
      - uses: actions/first-interaction@v1
```

### Slack Integration

**Notifications:**
- P0 issues → #critical-alerts
- Security issues → #security-alerts
- All issues → #github-activity

---

## Best Practices

1. **Be kind** - Every issue is someone's problem
2. **Be thorough** - Ask for details early
3. **Be transparent** - Update issues regularly
4. **Be decisive** - Make clear decisions
5. **Be consistent** - Apply rules uniformly

---

**Workflow Version:** 1.0.0  
**Last Updated:** 2026-07-13
