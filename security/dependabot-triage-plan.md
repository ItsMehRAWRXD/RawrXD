# Dependabot Triage Plan
## 745 Vulnerabilities in RawrXD

**Status:** 8 Critical | 241 High | 392 Moderate | 104 Low  
**Policy:** Triage separately from runtime validation work

---

## Priority Order

### P0: Critical (8 vulnerabilities)
**Criteria:** Affect shipped binaries or runtime security

- [ ] Review each critical CVE
- [ ] Identify if in runtime path vs dev-only
- [ ] Create isolated fix branches
- [ ] Target: Fix within 7 days

### P1: High - Runtime Dependencies (Estimated ~50)
**Criteria:** Network-facing or core inference components

- [ ] ggml/llama.cpp dependencies
- [ ] Vulkan loader
- [ ] HTTP client libraries
- [ ] Target: Fix within 14 days

### P2: High - Build/Dev Tools (Remaining ~191)
**Criteria:** Development-only, not in shipped binary

- [ ] CMake scripts
- [ ] Python tooling
- [ ] Documentation generators
- [ ] Target: Fix within 30 days

### P3: Moderate (392 vulnerabilities)
**Criteria:** Lower exploitability or dev-only

- [ ] Batch process monthly
- [ ] Group related updates
- [ ] Target: Fix within 60 days

### P4: Low (104 vulnerabilities)
**Criteria:** Minimal impact

- [ ] Quarterly review
- [ ] Address if time permits

---

## Isolation Strategy

```
Branch Naming:
  security/critical-<cve-id>
  security/high-<component>
  security/dependabot-batch-<date>

Commit Message Format:
  security: fix CVE-XXXX-XXXX in <component>
  
  - Isolated from feature commits
  - No mixing with inference/runtime changes
  - Clear audit trail
```

---

## Current Runtime Dependencies (Need Audit)

| Component | Version | Usage | Risk |
|-----------|---------|-------|------|
| ggml | bundled | Core inference | HIGH |
| Vulkan SDK | system | GPU compute | MEDIUM |
| nlohmann/json | v3.11.3 | Serialization | LOW |

---

## Action Items

1. [ ] Export full Dependabot report
2. [ ] Categorize by runtime vs dev-only
3. [ ] Create security/ prefix branches for fixes
4. [ ] Set up automated Dependabot PR review
5. [ ] Document which CVEs affect inference runtime

---

## Notes

- Keep security commits separate from VAL-019 validation
- Security fixes can be merged to main independently
- Runtime validation (VAL-019) should not block on security fixes
- Both should be green before release
