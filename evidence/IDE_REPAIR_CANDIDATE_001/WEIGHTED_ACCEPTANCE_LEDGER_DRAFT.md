# WEIGHTED_ACCEPTANCE_LEDGER_DRAFT

```text
ASOF=DRAFT
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
MATURITY=82% (held; not measured completion)
MEASURED_COMPLETION_PERCENT=NOT_ESTABLISHED
WEIGHTS=TBD (placeholders only — do not invent totals)
```

## Purpose

Skeleton ledger mapping Wave1 obligations → local evidence classes.
Weights are **TBD placeholders**. Do not sum to a completion %.

Sources:
- `ISSUE57_GATES_OBLIGATIONS.csv`
- `LAYERS_0_10_GITHUB_LOCAL.csv`
- `WORKSTREAMS_01_25_WAVE1_CROSSWALK.csv`
- `LANE.txt` / runtime receipts under `IDE_REPAIR_CANDIDATE_001/`

## Candidate identity (tip_repair / rc5)

| Artifact | SHA256 |
|---|---|
| RawrXD-Win32IDE-Native-Ext.exe | `089B9C72923B7C4A04658B216C375FBEA7AA5BB5F0C05E720F75D17514A4AB8A` |
| deep2_agentic_loop.exe | `F33D14A78191B1FB5C3833AC489247133FE5794AC24C28D0636D0895CA499316` |
| rawrxd_computer_use_ide_verify.exe | `FD6E932C59C630ECE4096595AA2C8ECD0461BDEB84B78F1A0380F779A5FDDD81` |
| RC4 Ext (immutable control) | `78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596` |

## Wave1 workstream rows (weights TBD)

| WS | Workstream | Wave1 touch | Weight | Runtime class | Evidence |
|---:|---|---|---:|---|---|
| 02 | Chat input | direct_cu_path | TBD | SOURCE_WIRED (AGENT_MODE route) | Ext string `AGENT_MODE_AGENTIC_LOOP`; lifecycle BN_CLICKED |
| 03 | Chat sessions | direct | TBD | SOURCE_WIRED | `ensureProductAgentSession` + session_registry markers |
| 04 | AgentSession | direct_critical | TBD | SOURCE_WIRED | `AGENT_SESSION_SPAWNED` / `session_registry=1` |
| 05 | Agent loop | direct_critical | TBD | SOURCE_WIRED / RUNTIME_PARTIAL | AgenticLoopBridge CU tool-surface keep |
| 06 | Tool protocol | direct_critical | TBD | RUNTIME_PARTIAL | tool-read PASS; edit FAIL on nano |
| 07 | File tools | direct_critical | TBD | RUNTIME_PARTIAL | read PASS; write/compile FAIL |
| 08 | Computer use | direct_critical | TBD | RUNTIME_PARTIAL | Registry register PASS; GUI HWND FAIL |
| 09 | Cancellation | adjacent | TBD | SOURCE_WIRED / VERIFY_PASS | `bridge_cancel` PASS in ide_verify |
| 15 | Ollama | direct_protocol | TBD | RUNTIME_MIXED | gpt-oss empty; nano read PASS |
| 22 | Security | direct_cu_approval | TBD | VERIFY_PASS (deny) | approval_deny + policy_launch_deny |
| 25 | Certification | final | TBD | NOT_ESTABLISHED | PROMOTE=0 |

## Issue #57 / Layer crosswalk (weights TBD)

| Layer | Issue | Weight | Wave1 note |
|---:|---:|---:|---|
| 3 | #42 Agent Reasoning + Tool Authority | TBD | Primary Wave1 owner; orphan CU registry repair |
| 4 | #43 Autonomous Edit/Build/Test | TBD | tool-read PASS on rc5 loop; edit not closed |
| 6 | #45 IDE Surface | TBD | AGENT_MODE Send route; not product-final |
| 10 | #49 Product-Final | TBD | NOT_ESTABLISHED on rc5 |

## Runtime disposition classes (fail-closed)

| Gate | Class | Invented? |
|---|---|---|
| TOOL_READ_BUG_CPP | **PASS** (nemotron-3-nano:4b / NEW loop) | no |
| AGENT_WORKFLOW_E2E | **FAIL** after read (edit compile) | no |
| CU_REGISTRY_REGISTER | **PASS** (`agent_tools_registered`) | no |
| CU_GUI_DISPATCH | **FAIL** first=`screenshot_own_window` | no |
| CLI_RAWR_CU | **ABSENT** | no |
| PROMOTE | **0** | n/a |

## Weight assignment rules (later)

1. Do not assign numeric weights until product owners lock the matrix.
2. Do not derive `MEASURED_COMPLETION_PERCENT` from this draft.
3. `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`.
4. `NOT_RUN != PASS`.
