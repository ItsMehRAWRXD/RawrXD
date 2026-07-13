# Security Phase 3 Plan - High Severity Remediation
## v1.0.1-hotfix3 - Python, Node.js & Container Hardening

**Date**: 2026-07-13  
**Status**: 🔴 **IN PROGRESS**  
**Target**: v1.0.1-hotfix3 Release  
**Completion Date**: 2026-07-27

---

## Scope

Phase 3 addresses **254 high severity vulnerabilities** across multiple categories:

### High Severity Categories (254 total)
- **Python Dependencies**: 156 (FastAPI, Pydantic, SQLAlchemy, PyYAML, etc.)
- **JavaScript/Node**: 32 (Express.js, Lodash, Axios)
- **Container/Base Images**: 21 (Ubuntu, Python base images)
- **C++ Dependencies**: 45 (fmtlib/fmt, spdlog, boost) - ✅ Already addressed in Phase 2

---

## Tasks

### 1. Python Dependencies 🟡 IN PROGRESS

#### services/requirements.txt ✅ UPDATED
- **Action**: Updated all packages to latest secure versions
- **New Packages Added**:
  - werkzeug==3.0.3 (Flask dependency)
  - starlette==0.40.0 (FastAPI dependency)
  - email-validator==2.2.0
  - pyjwt==2.9.0
  - python-jose[cryptography]==3.3.0
  - passlib[bcrypt]==1.7.4
  - bcrypt==4.2.0
  - pandas==2.2.2
  - jinja2==3.1.4
  - click==8.1.7
  - python-multipart==0.0.9
  - anyio==4.4.0
  - sniffio==1.3.1
  - typing-extensions==4.12.2
  - prometheus-client==0.20.0
  - opentelemetry-api==1.26.0
  - opentelemetry-sdk==1.26.0
  - pytest==8.3.2
  - pytest-asyncio==0.23.8
  - bandit==1.7.9
  - safety==3.2.7
  - pip-audit==2.7.3

#### Verification Commands
```bash
cd services/
pip install -r requirements.txt
pip-audit -r requirements.txt
safety check
bandit -r .
```

### 2. JavaScript/Node Dependencies 🟡 IN PROGRESS

#### package.json ✅ UPDATED
- **Version**: 1.0.0 → 1.0.1-hotfix3
- **New Dependencies**:
  - axios==^1.7.2
  - express==^4.19.2
  - ws==^8.18.0
  - lodash==^4.17.21
- **Dev Dependencies**:
  - eslint==^9.7.0
  - eslint-plugin-security==^3.0.1
- **New Scripts**:
  - `security:audit`: npm audit
  - `security:fix`: npm audit fix
  - `security:scan`: npm audit --audit-level=high

#### Verification Commands
```bash
npm install
npm audit
npm audit fix
npm run security:scan
```

### 3. Container Security 🟡 IN PROGRESS

#### docker-compose.yml ✅ UPDATED
- **Security Options Added**:
  - `security_opt: no-new-privileges:true`
  - `cap_drop: ALL`
  - `cap_add`: Minimal required capabilities
  - `read_only: true`
  - `tmpfs`: Secure temporary directories
  - `user`: Non-root user specification
  - `healthcheck`: Container health monitoring
- **Services Hardened**:
  - rawrxd-backend
  - rawrxd-web
  - rawrxd-desktop

#### Remaining Container Tasks
- [ ] Update `Dockerfile.web` (nginx) to latest stable
- [ ] Test container builds with new security options
- [ ] Run Trivy security scan on containers

### 4. CI/CD Security Integration 🟡 PENDING

#### GitHub Actions Workflow
- [ ] Add container scanning to security-scan.yml
- [ ] Add npm audit to CI pipeline
- [ ] Add pip-audit to CI pipeline
- [ ] Fail builds on high/critical vulnerabilities

---

## Implementation Steps

### Step 1: Python Dependencies (Day 1-3)

```bash
# Update requirements.txt
cd services/
pip install --upgrade pip
pip install -r requirements.txt

# Verify security
pip-audit -r requirements.txt
safety check
bandit -r .
```

### Step 2: Node.js Dependencies (Day 4-5)

```bash
# Update package.json
npm install
npm audit
npm audit fix

# Verify security
npm audit --audit-level=high
```

### Step 3: Container Testing (Day 6-7)

```bash
# Build containers
docker-compose build

# Run security scan
docker run --rm -v $(pwd):/app aquasec/trivy fs /app
docker run --rm aquasec/trivy image rawrxd-backend
docker run --rm aquasec/trivy image nginx:1.27-alpine

# Test with security options
docker-compose up -d
```

### Step 4: CI/CD Integration (Day 8-10)

- Update `.github/workflows/security-scan.yml`
- Add container scanning
- Add npm/pip audit steps
- Configure failure thresholds

### Step 5: Testing & Release (Day 11-14)

- [ ] Full integration testing
- [ ] Security regression testing
- [ ] Performance testing
- [ ] Create PR
- [ ] Merge to main
- [ ] Tag v1.0.1-hotfix3

---

## Security Verification

### Pre-Commit Checklist
- [ ] All Python packages updated and audited
- [ ] All Node.js packages updated and audited
- [ ] Container builds successful with security options
- [ ] No high severity CVEs remaining
- [ ] CI/CD security scans passing

### Post-Deployment Verification
```bash
# Python security check
pip-audit -r services/requirements.txt

# Node.js security check
npm audit --audit-level=high

# Container security scan
docker run --rm -v $(pwd):/app aquasec/trivy fs /app

# Full stack test
docker-compose up -d
curl http://localhost:23959/health
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Breaking API changes in updates | Medium | High | Pin to compatible versions, test in CI |
| Container security options break app | Medium | High | Test with read-only, tmpfs mounts |
| Performance regression | Low | Medium | Benchmark comparison |
| Dependency conflicts | Medium | Medium | Use virtual environments |

---

## Success Criteria

- [ ] 0 critical CVEs remaining
- [ ] < 50 high severity vulnerabilities (from 254)
- [ ] All containers running with security hardening
- [ ] CI/CD security scanning integrated
- [ ] No build or runtime regressions
- [ ] Security documentation updated

---

## Notes

- Phase 3 focuses on high severity vulnerabilities (254 total)
- Python dependencies are the largest category (156)
- Container hardening adds defense-in-depth
- CI/CD integration ensures ongoing security
