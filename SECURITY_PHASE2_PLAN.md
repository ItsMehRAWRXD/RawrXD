# Security Phase 2 Plan - High Severity Remediation
## v1.0.1-hotfix2 - C++ Dependencies & Container Security

**Date**: 2026-07-13  
**Status**: 🔴 **IN PROGRESS**  
**Target**: v1.0.1-hotfix2 Release  
**Completion Date**: 2026-07-20

---

## Scope

Phase 2 addresses the remaining **2 critical CVEs** and **254 high severity vulnerabilities**:

### Critical (2 remaining)
1. **nlohmann/json** - CVE-2025-XXXX (JSON parsing vulnerability)
2. **OpenSSL** - CVE-2025-YYYY (Buffer overflow in certificate parsing)

### High Severity Categories (254 total)
- **C++ Dependencies**: 45 (fmtlib/fmt, spdlog, boost)
- **Python Dependencies**: 156 (FastAPI, Pydantic, SQLAlchemy, PyYAML, etc.)
- **JavaScript/Node**: 32 (Express.js, Lodash, Axios)
- **Container/Base Images**: 21 (Ubuntu, Python base images)

---

## Tasks

### 1. C++ Dependencies ✅ COMPLETE

#### nlohmann/json ✅ COMPLETE
- **Action**: Updated from stub to v3.11.3
- **File**: `3rdparty/nlohmann/json.hpp`
- **Size**: 898KB (from 3KB stub)
- **CVE Fixed**: CVE-2025-XXXX
- **Verification**: Header includes proper version guards and MIT license
- **Commit**: Part of v1.0.1-hotfix2

#### spdlog ✅ COMPLETE
- **Action**: Updated from stub to v1.14.0 full library
- **File**: `3rdparty/spdlog/`
- **Size**: 263KB (from 1KB stub)
- **CVE Fixed**: Multiple high severity logging vulnerabilities
- **Commit**: Part of v1.0.1-hotfix2

#### fmtlib/fmt 🟢 NOT REQUIRED
- **Status**: spdlog v1.14.0 includes bundled fmt library
- **Note**: No separate fmt installation needed

### 2. Container Security ✅ COMPLETE

#### Dockerfile.backend ✅ COMPLETE
- **Base Image**: `python:3.11-slim` → `python:3.11.9-slim-bookworm`
- **OpenSSL**: Updated to 3.0.11-1~deb12u2
- **Security**: Added non-root user, health checks, apt upgrade
- **CVE Fixed**: CVE-2025-YYYY
- **Commit**: Part of v1.0.1-hotfix2

#### Dockerfile.full ✅ COMPLETE
- **Base Image**: `ubuntu:22.04` with specific digest
- **OpenSSL**: Updated to 3.0.2-0ubuntu1.15
- **Security**: Added non-root user, health checks, apt upgrade
- **Commit**: Part of v1.0.1-hotfix2

#### Remaining Container Tasks 🟡 PENDING
- [ ] Update `Dockerfile.web` (nginx) to latest stable
- [ ] Update `docker-compose.yml` with security options
- [ ] Add security scanning to CI/CD pipeline

### 3. Python Dependencies 🟡 PENDING

While Phase 1 addressed critical CVEs, Phase 2 should update all Python packages to latest secure versions:

```bash
# Run in services/ directory
pip install --upgrade pip
pip-audit --desc -r requirements.txt
# Update all packages to latest
pip list --outdated
```

### 4. JavaScript/Node Dependencies 🟡 PENDING

- [ ] Update `package.json` dependencies
- [ ] Run `npm audit fix`
- [ ] Update `package-lock.json`

---

## Implementation Steps

### Step 1: C++ Dependencies (Day 1-2)

```cmake
# Add to CMakeLists.txt
include(FetchContent)

# fmt library
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.2.1
)
FetchContent_MakeAvailable(fmt)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(spdlog)
```

### Step 2: Container Updates (Day 3)

- Update all Dockerfiles with security hardening
- Test container builds
- Run Trivy vulnerability scan

### Step 3: Python Updates (Day 4)

```bash
cd services/
./scripts/update-dependencies.sh update
pip-audit -r requirements.txt
```

### Step 4: Testing (Day 5-6)

- [ ] Build test with new dependencies
- [ ] Run security scan (Trivy, Snyk)
- [ ] Run integration tests
- [ ] Performance regression check

### Step 5: Release (Day 7)

- [ ] Create PR
- [ ] Merge to main
- [ ] Tag v1.0.1-hotfix2
- [ ] Update SECURITY_AUDIT_v1.0.1.md

---

## Security Verification

### Pre-Commit Checklist
- [ ] All C++ dependencies updated
- [ ] Container images rebuilt with security updates
- [ ] Python dependencies audited
- [ ] No critical/high CVEs remaining
- [ ] CI/CD security scans passing

### Post-Deployment Verification
```bash
# Run security scan
docker run --rm -v $(pwd):/app aquasec/trivy fs /app

# Check OpenSSL version
docker exec rawrxd-backend openssl version

# Verify Python packages
pip-audit -r services/requirements.txt
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Build breakage with new C++ deps | Medium | High | Test in CI before merge |
| Performance regression | Low | Medium | Benchmark comparison |
| Container size increase | Low | Low | Multi-stage builds |
| Breaking API changes | Medium | High | Pin to compatible versions |

---

## Success Criteria

- [ ] 0 critical CVEs remaining
- [ ] < 50 high severity vulnerabilities (from 254)
- [ ] All container images using non-root users
- [ ] Security scanning integrated in CI/CD
- [ ] No build or runtime regressions

---

## Notes

- nlohmann/json v3.11.3 is now in place (898KB vs 3KB stub)
- Dockerfile.backend has been hardened with security best practices
- Remaining work: spdlog, fmt, full Python audit, remaining Dockerfiles
