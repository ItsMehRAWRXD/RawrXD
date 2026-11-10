# PROD_AUDIT_BATCH5_001 — CI runner_id=0 / steps=[] receipt

```
AUDIT_DATE=2026-11-03
REPO=ItsMehRAWRXD/RawrXD
PROMOTE=0
REBUILD_AUTHORITY=0
SEAL_CB34EF4E_UNTOUCHED=1
```

## Sampled runs (gh)

| Workflow | Run ID | Event | Job | runner_id | steps | Duration |
|----------|--------|-------|-----|-----------|-------|----------|
| Native Win32 No-Dependency Build Gate | 41580914199 | pull_request | native-ide | 0 | [] / 0 | ~3s (04:55:46→04:55:49Z) |
| Security Suite | 41580914184 | pull_request | Security suite (MSVC…), ASan, Portability | 0 | [] / 0 | ~3–4s |
| Self-Release | 41415511079 | schedule (main) | self_release | 0 | [] / 0 | ~4s (08:46:31→08:46:35Z) |

Head SHA (PR #60 tip sampled): `94ded48edb6505567b8a510ca1364913e54969d3`

Native workflow YAML authority: `.github/workflows/native-win32-nodeps-build.yml`
- `runs-on: windows-latest`
- Build target: `RawrXD-Win32IDE-Native`

Self-Release YAML: `.github/workflows/self_release.yml`
- `runs-on: windows-latest`
- Post-build step explicitly requires `RawrXD-Agent.exe` (Qt target) — would FAIL even after runners recover until a native agent exists.

## Root cause (visible)

Jobs never acquire a GitHub-hosted runner. Evidence:

- `runner_id=0`, empty `runner_name`
- `steps=[]` (checkout/configure/build never started)
- Wall time ~3–4 seconds (allocation/reject, not compile)
- Repo Actions permissions API: `enabled=true`, `allowed_actions=all` (not org-disabled)
- Billing minutes API: 404 (token lacks billing scope) — cannot prove minutes exhaustion from API alone
- Last 15 Native Win32 No-Dependency runs: all `failure`
- Last 10 Self-Release schedule runs: all `failure` with same pre-step pattern

**Classification:** CI infrastructure / runner allocation failure — **not** a product compile or test FAIL.
`NOT_RUN != PASS`. These failures supply **no** acceptance evidence for gates 68–71 / 73–74.

## Exact next action (Gate 69)

1. Owner inspects GitHub Actions billing/minutes + concurrent job caps for `ItsMehRAWRXD`.
2. After a job shows non-zero `runner_id` and non-empty `steps`, re-run Native + Security.
3. Treat Self-Release separately: even with runners, step 2 fails until native agent target exists (YAML hard-error).
