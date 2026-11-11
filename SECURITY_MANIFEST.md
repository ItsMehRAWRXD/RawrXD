# SECURITY_MANIFEST.md
## Sovereign Inference IDE — Security Architecture & Operator Guide

**Version:** Day 20 Final  
**Date:** 2026-06-01  
**Classification:** Internal — Operator Reference

---

## 1. System Overview

The Sovereign Inference IDE implements a **defense-in-depth** architecture for agentic AI operations. It combines static policy enforcement (ToolRegistry), dynamic behavioral analysis (GovernanceEnforcer), immutable audit logging (AuditLogService), and adversarial resilience testing (ReplayEngine) into a single cohesive security posture.

### 1.1 Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 5: Resilience Testing (ReplayEngine)                 │
│  └─ Shadow-context adversarial scenarios                    │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: Active Defense (GovernanceEnforcer)                 │
│  └─ Sliding-window threshold detection + ratcheting          │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Human-in-the-Loop (HITL Gate)                     │
│  └─ Proposal/approval/denial workflow with engine pause      │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Policy Enforcement (ToolRegistry)               │
│  └─ Static risk levels + dynamic override resolution       │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1: Audit & Compliance (AuditLogService)            │
│  └─ Immutable event timeline + compliance classification     │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Component Reference

### 2.1 ToolRegistry (`frontend/src/agent/ToolRegistry.ts`)

**Purpose:** Static manifest of all available tools with baseline risk classifications.

**Risk Levels:**
- `LOW` — Auto-approved (read-only operations)
- `MEDIUM` — Proposed, requires explicit approval
- `HIGH` — Proposed, requires explicit approval + engine pause

**Key Tools:**
| Tool | Baseline Risk | Description |
|------|--------------|-------------|
| `read_file` | LOW | Read file content |
| `write_file` | MEDIUM | Write file content |
| `pe_writer` | HIGH | Emit raw PE32+ binary |
| `execute_shell` | HIGH | Execute shell command |
| `git_commit` | HIGH | Create git commit |

**StatefulRegistry:** Wraps the static registry with runtime override resolution via `getEffectiveRiskLevel()`.

### 2.2 GovernanceEnforcer (`frontend/src/telemetry/GovernanceEnforcer.ts`)

**Purpose:** Active policy layer that monitors audit events and ratchets tool permissions upward when thresholds are breached.

**Thresholds (Default):**
- `maxSuspiciousEventsPerWindow`: 3 events per 1-hour window
- `consecutiveDenialsThreshold`: 2 denials per 10-minute window

**Ratchet Behavior:**
```
LOW → MEDIUM → HIGH → HARD_LOCK (permanent until human reset)
```

**Break Glass:** Human operator can call `reset()` to clear all overrides and restore static risk definitions.

### 2.3 AuditLogService (`frontend/src/telemetry/AuditLogService.ts`)

**Purpose:** Immutable timeline of all agentic events.

**Event Kinds:**
- `PROPOSAL` — Tool call proposed
- `PENDING_APPROVAL` — Blocked awaiting HITL decision
- `USER_APPROVED` / `USER_DENIED` — Human decision recorded
- `EXECUTION_RESULT` — Tool execution completed
- `GOVERNANCE_ENFORCED` — Automatic ratchet triggered
- `ENGINE_PAUSED` / `ENGINE_RESUMED` — Execution lane control

**Compliance Report:** Automatically classifies write operations as `COMPLIANT` or `SUSPICIOUS` based on approval status, execution result, and retry patterns.

### 2.4 ReplayEngine (`frontend/src/telemetry/ReplayEngine.ts`)

**Purpose:** Non-destructive adversarial testing via shadow-context replays.

**Scenarios:**
1. `brute-force-write` — Repeated denials should ratchet to HARD_LOCK
2. `failure-cascade` — Multiple failures should trigger demotion
3. `normal-operation` — Baseline: no false positives
4. `pewriter-hitl-gate` — HIGH-risk tool always requires approval
5. `mixed-attack-legit` — Attack isolation without breaking valid work

**Stability Score:** 0–100 composite metric. Deadlocks penalize heavily (-40 points).

### 2.5 PEWriter Integration (`frontend/src/agent/PeWriterAdapter.ts`)

**Purpose:** Bridge to the MASM PE32+ emitter with cryptographic accountability.

**Security Features:**
- Pre-write SHA-256 hash of code buffer (captured in audit trail)
- Post-write SHA-256 hash of emitted PE file (captured in audit trail)
- `/tool/verify_pe_hash` endpoint for forensic disk verification
- HITL gate: always blocked when `agentic_paused`

---

## 3. Operator Procedures

### 3.1 Daily Security Check

1. Open the **Security Posture Dashboard** (sidebar: "Posture")
2. Review the **Overall Score** — should be ≥ 80
3. Check **Active Overrides** — investigate any non-zero values
4. Run the **Replay Suite** — verify all scenarios pass
5. Export the **Certificate of Resilience** for record-keeping

### 3.2 Responding to a Governance Alert

1. Check the **HITL Audit Timeline** (sidebar: "Audit") for `GOVERNANCE_ENFORCED` events
2. Review the **Agent Panel** (sidebar: "Agent") for active governance chips
3. Determine if the ratchet was legitimate:
   - **Legitimate:** Agent was misbehaving → leave override in place
   - **False Positive:** Agent was performing valid work → click **Break Glass Reset**
4. Document the decision in the audit log via the compliance export

### 3.3 Emergency Reset (Break Glass)

**When to use:**
- GovernanceEnforcer has over-restricted the agent
- Critical task is deadlocked due to HARD_LOCK
- Operator confirms the agent is performing legitimate work

**Procedure:**
1. Navigate to **Agent Panel** → click **🚨 Break Glass Reset**
2. Confirm the dialog: "This will clear all governance overrides. Continue?"
3. Verify overrides cleared in **Security Posture Dashboard**
4. Re-run the **Replay Suite** to confirm stability restored

**⚠️ WARNING:** Break Glass resets are logged as `GOVERNANCE_ENFORCED` events with action `NONE`. They are visible in the audit trail for forensic review.

### 3.4 Forensic Binary Verification

1. Locate the PE emission event in the **HITL Audit Timeline**
2. Click **Verify Hash** next to the `peFileHash` field
3. The system will:
   - Re-compute the SHA-256 of the file on disk
   - Compare it to the hash recorded at emission time
   - Display ✅ Verified or ❌ Mismatch
4. If mismatch: the binary has been tampered with post-emission

---

## 4. Interpreting Governance Logs

### 4.1 Event Patterns

**Normal Operation:**
```
PROPOSAL → USER_APPROVED → EXECUTION_RESULT (EXECUTED)
```

**Blocked Operation:**
```
PROPOSAL → PENDING_APPROVAL → [USER_DENIED | timeout]
```

**Governance Triggered:**
```
PROPOSAL → PENDING_APPROVAL → USER_DENIED
PROPOSAL → PENDING_APPROVAL → USER_DENIED
GOVERNANCE_ENFORCED (DEMOTE: write_file MEDIUM → HIGH)
```

### 4.2 Suspicious Indicators

| Pattern | Interpretation | Action |
|---------|---------------|--------|
| Repeated `PENDING_APPROVAL` for same tool | Brute-force attempt | Check if override exists |
| `EXECUTION_RESULT` with `FAILED` status | System error or attack | Review error message |
| `GOVERNANCE_ENFORCED` without prior denials | Threshold drift | Adjust thresholds if needed |
| `pe_writer` with no `peHash` | Hash computation failed | Check browser crypto support |

---

## 5. Audit Trail Retention

- **Max Events:** 1500 (circular buffer, oldest evicted first)
- **Export Formats:** JSON (`hitl-audit-{timestamp}.json`)
- **Compliance Reports:** JSON (`compliance-report-{timestamp}.json`)
- **Security Posture Certificates:** JSON (`security-posture-{timestamp}.json`)

**Recommended Retention:** Export compliance reports daily. Retain for minimum 90 days.

---

## 6. Regression Testing

### 6.1 Sovereign Proof Suite (`regression_test_pe.py`)

Run before every deployment:
```bash
python regression_test_pe.py --host http://localhost:11435
```

**Expected Result:** `14 passed, 0 failed`

**Test Coverage:**
- Engine readiness validation
- HITL gate blocking (423 when paused)
- Legitimate emission (200 when ready)
- Forensic hash verification
- Denial simulation (file NOT created)

### 6.2 Replay Stability Suite

Run via the **Replay Panel** (sidebar: "Replay"):
1. Click **Run All Scenarios**
2. Verify overall stability score ≥ 80
3. Verify deadlock count = 0

---

## 7. Threat Model

### 7.1 Addressed Threats

| Threat | Mitigation |
|--------|-----------|
| Agent brute-forcing approvals | Sliding-window ratchet → HARD_LOCK |
| Agent emitting malicious binaries | HITL gate + SHA-256 audit trail |
| Post-emission binary tampering | Forensic hash verification endpoint |
| Governance rule deadlock | ReplayEngine stability scoring |
| Policy drift over time | Break Glass reset + compliance reports |

### 7.2 Known Limitations

- **Browser Crypto:** `PeWriterAdapter` relies on `crypto.subtle.digest`. Legacy browsers without Web Crypto API will fail hash computation.
- **Mock Backend:** Current backend is a simulation. Production deployment requires hardened path validation and authenticated endpoints.
- **Audit Buffer:** 1500-event limit may be insufficient for high-frequency agents. Consider external log aggregation for production.

---

## 8. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND (React + Vite)              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ AgentPanel  │  │ HitlAudit   │  │ SecurityPosture     │  │
│  │ (Proposals) │  │ Panel       │  │ Dashboard           │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────┘  │
│         │                │                                   │
│  ┌──────┴──────┐  ┌──────┴──────┐  ┌─────────────────────┐  │
│  │ Agentic     │  │ AuditLog    │  │ ReplayEngine        │  │
│  │ Controller  │  │ Service     │  │ (Shadow Testing)    │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────┘  │
│         │                │                                   │
│  ┌──────┴──────┐  ┌──────┴──────┐  ┌─────────────────────┐  │
│  │ ToolRegistry│  │ Governance  │  │ EngineService       │  │
│  │ (Stateful)  │  │ Enforcer    │  │ (HTTP Bridge)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTP/JSON
┌─────────────────────────────────────────────────────────────┐
│                      BACKEND (Python)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ /status     │  │ /tool/      │  │ /tool/verify_pe_hash│  │
│  │ /control    │  │ pe_writer   │  │ (Forensic Verify)   │  │
│  │ /inference  │  │ write_file  │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Glossary

| Term | Definition |
|------|-----------|
| **HITL** | Human-in-the-Loop — requiring explicit human approval before execution |
| **Ratchet** | One-way permission demotion (LOW → MEDIUM → HIGH → HARD_LOCK) |
| **Shadow Context** | Isolated clone of audit state for non-destructive testing |
| **Sovereign Proof** | Regression test suite proving the agent cannot bypass governance |
| **Break Glass** | Emergency human override to clear all governance restrictions |
| **Stability Score** | 0–100 metric measuring governance rule resilience |

---

## 10. Changelog

| Day | Feature | Files |
|-----|---------|-------|
| 12 | HITL Gate + AgenticController | `AgenticController.ts`, `HitlGate.ts` |
| 16 | AuditLogService + Compliance Reports | `AuditLogService.ts`, `HitlAuditPanel.tsx` |
| 17 | Safety Audit Panel + Benchmarks | `SafetyAuditPanel.tsx` |
| 18 | GovernanceEnforcer + Ratcheting | `GovernanceEnforcer.ts`, `ToolRegistry.ts` |
| 19 | ReplayEngine + Shadow Testing | `ReplayEngine.ts`, `ReplayPanel.tsx` |
| 19 | PEWriter Integration + Forensics | `PeWriterAdapter.ts`, `mock_backend.py` |
| 20 | Security Posture Dashboard | `SecurityPostureDashboard.tsx` |
| 20 | Security Manifest Documentation | `SECURITY_MANIFEST.md` |

---

**End of Document**

*This manifest is a living document. Update it whenever the security architecture changes.*
