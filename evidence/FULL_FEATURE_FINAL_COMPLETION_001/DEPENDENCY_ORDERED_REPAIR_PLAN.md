# Dependency-ordered repair plan (smallest set → integrated workflow)

```text
ASOF_UTC=2026-11-09T14:50:00Z
PROMOTE=0
MATURITY=82%
SCOPE=RELEASE_SCOPE_FREEZE.md
STRATEGY=repair_blockers_once → build_once → E2E_on_that_SHA → fix_forward_new_SHA
```

## Ordered blockers (symptoms collapsed)

| # | Blocker | Unlocks | Depends on |
|--:|---------|---------|------------|
| 1 | **B12** GUI caret nav (Problems click → file/line/caret) | Problems acceptance; agent diagnose loop; four-panel useful | Problems populate path + editor open |
| 2 | **Chat** stream/Stop/Clear/recovery on same image | Model response + cancel in integrated workflow | Stable GUI HWND (no early-exit) |
| 3 | **PowerShell panel `ls`** (pane-local; chat untouched) | Terminal user surface ≠ term-smoke | Panel proc + output routing (G active-tab route risk) |
| 4 | **Extension cleanup** re-prove on acceptance SHA | Extension shutdown in E2E | — (B20 closed only on `27E2263E…`) |
| 5 | **Output producer ↔ selected tab** | Blank-tab ≠ feature | Panel routing |
| 6 | **Debugger UI min** (BP/step/continue/stop) | Four-panel Debug leg | — |
| 7 | **Four-panel simultaneous** | Integrated milestone | 1–6 |
| 8 | **Agent edit → durable diff → cancel/rollback** | Issue #49 core | Chat + editor + build |
| 9 | **Build cancel / JobObject / VS_UNICODE scrub regression** | Compile→Problems chain | — |
| 10 | **Packaging + clean-machine + rollback** | Delivery | Single SHA with 1–9 PASS |
| 11 | **B01** Problems on CC79 *or* authorized tip-move after matrix | Controlling-tip honesty | Tip auth (B03) after candidate E2E |
| 12 | **B03 / B05 / B78** tip-move / PROMOTE / CERTIFIED | Governance | Explicit auth after gates |

**Do not** open parallel rebuilds for Terminal-only, Chat-only, and B12-only tips. Terminal PASS already exists on `2CCAE57A…` and `B50A2AB1…` — carry forward by **source merge into one branch**, then one rebuild.

## Execution steps (matches acceleration table)

1. Freeze = `RELEASE_SCOPE_FREEZE.md` (this track).  
2. This ordered list = confirmed blocker reconciliation.  
3. Apply repairs 1–9 on **one** candidate branch (prefer F:\rawrxd product tree).  
4. **One** Release|RelWithDebInfo Native-Ext build → record full SHA.  
5. Run integrated workflow + Required gates on that SHA.  
6. On failure: fix → **new** SHA → re-run **affected** + full integrated acceptance.  
7. Package → clean-machine → rollback → seal; only then consider B03 request.

## Out of critical path (park)

UNVERIFIED×81, INVESTIGATE×18, OPTIONAL×9 from MASTER_REGISTER — park unless a Required gate fails because of them.  
PS panel ANSI on F: — fold into repair #3 if acceptance SHA builds from F; prefer G Unicode panel sources when merging.
