# Project: Sovereign Inference IDE (v1.1) - 10-Day Sprint

**Status:** In Progress - Day 1 Complete ✅
**Sprint Start:** June 1, 2026
**Objective:** Deliver a hardened, policy-driven AI IDE with full engine observability and deterministic fault recovery.

---

## Sprint Execution Board

| Day | Task | Acceptance Criteria | Status |
| :--- | :--- | :--- | :--- |
| **1-2** | Status Dashboard | Polls `/status` @ 1Hz; UI reflects engine states (0=IDLE/Gray, 1=LOADING/Blue, 2=READY/Green, 3=FAULT/Red). Error panel renders `last_error_tag` + `suggested_action`. | ✅ **COMPLETE** |
| **3-4** | Inference Loop | UI "Send" button bounded by `state == 2` (READY); disabled during LOADING. Token stream renders via SSE/WebSocket. Live `tokens/sec` ticker visible. | Not Started |
| **5** | Sidecar Resilience | UI detects `/status` timeout (>1.5s), triggers `headless_fault_policy.json` reader. "Crash Recovery" modal rendered with `fault_class` and `suggested_action`. | Not Started |
| **6** | Integration Test (Lightweight) | Execute 3 "Golden Prompts": `Generate Boilerplate`, `Debug Snippet`, `Explain Complexity`. Log pass/fail + latency (ms) to local `regressions.db`. | Not Started |
| **7-8** | Benchmarking & Model Selector | Build "Performance Tab" with `tokens/sec` and `memory_utilization` histograms. Implement Model Selector with engine-recommended model highlighted. | Not Started |
| **9** | Safety Guardrails & Hardening | UI guardrails: `can_retry: false` → grey out "Regenerate" button. Code audit for legacy hardcoded strings. Final UI/API stream stability. | Not Started |
| **10** | CI/CD Gate & Alpha Release | Automate pipeline: [Build Engine] → [Handshake Test] → [UI-API Probe Test] → [Package Alpha]. All gates must pass. | Not Started |

---

## Governance Rules (All Days)

**Engine-as-Authority Principle:**
- ✅ UI reads `state`, `suggested_action`, `can_retry`, `recommended_model` from `/status`.
- ✅ UI disables/enables controls based on engine policy, never on UI-side timers.
- ✅ All faults surface via engine policy, never via UI-side exception handling.
- ❌ No retry timers in frontend code.
- ❌ No fault-guessing logic in frontend code.
- ❌ No model-selection logic in frontend code.

---

## CI/CD Gate Checklist (Day 10 Automation)

### Pre-Flight Checks
- [ ] `_build_ide_integration.cmd` compiles without errors (exit 0).
- [ ] `hexmag_client_handshake.py --launch` completes successfully (exit 0).
- [ ] `test_ui_api_connection.py` validates engine reachability (exit 0).

### Post-Flight Validation
- [ ] All 3 regression prompts execute and log results.
- [ ] Alpha package includes: Engine binary, handshake script, IDE frontend.
- [ ] Release tag: `v1.1-alpha-[DATE]`.

---

## Daily Standup Template

**Format:** One line per day.
```
Day N: [Task] - [Status] | [Blocker/Win]
```

**Example:**
```
Day 1: Status Dashboard - 90% Complete | Waiting on `/status` schema confirmation.
Day 2: Status Dashboard - Complete | Dashboard renders all 4 states correctly.
```

---

## Artifact Registry

| Artifact | Location | Responsibility |
| :--- | :--- | :--- |
| Engine Binary | `d:\rawrxd-ci-bootstrap\IDE_Integration.exe` | Backend Hardening (LOCKED) |
| Handshake Script | `d:\rawrxd-ci-bootstrap\hexmag_client_handshake.py` | Infrastructure Validation (LOCKED) |
| Sidecar Reader | UI Service Layer | Application Layer (THIS SPRINT) |
| Status Dashboard | UI Component (Day 1-2) | Application Layer (THIS SPRINT) |
| CI/CD Gate | `ci_gate.ps1` | Deployment Lock (Day 10) |

---

## Success Criteria (End of Sprint)

- [ ] IDE successfully launches and polls engine status at 1Hz.
- [ ] User can execute a model inference and see real-time token output.
- [ ] On engine fault, IDE surfaces sidecar-derived recovery policy without user manual intervention.
- [ ] All 3 regression tests pass with latency < 5s per prompt.
- [ ] CI/CD pipeline fully automated; no manual gate intervention required.
- [ ] Alpha package ready for internal dogfooding.

---

**Last Updated:** June 1, 2026
**Next Sync:** [End of Day 2]
