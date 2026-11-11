# RELEASE_SCOPE_FREEZE — finite 100% definition

```
ASOF_UTC=2026-11-09T15:00:00Z
MOTD_ACK=1
LANE=F:\rawrxd\evidence\RELEASE_FREEZE_001
AUTHORITY=CONTROLLING_COMPLETION_STRATEGY.md
HIDDEN_GAP_AUDIT=SEALED_REFERENCE_ONLY
ENGINEERING_MATURITY=82%_UNCHANGED_UNTIL_SUBSTANTIAL_ACCEPTANCE_MILESTONE
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS=1
INVESTIGATION_NE_CONFIRMED=1
NO_ARITHMETIC_18_POINTS=1
SCOPE_FROZEN=1
```

## Law

```
100% = all REQUIRED gates PASS on one final candidate SHA
PROMOTE ≠ CERTIFIED ≠ ENGINEERING_COMPLETE
AUDIT_SEAL ≠ MATURITY_INCREASE
LISTED_INVESTIGATION ≠ CONFIRMED_DEFECT
CC79 tip_cc79_integ_002 F5F4807E… = input progress, not product-final alone
Issue #49 RAWRXD_PRODUCT_FINAL_001 = decisive integrated acceptance milestone
```

---

## REQUIRED — release features + acceptance gates

Finite conjunction. Every gate must PASS on the **same final SHA**. No inheritance across SHAs.

### R1 — Daily-driver integrated workflow (single SHA)

| Gate ID | Feature | Acceptance |
|---------|---------|------------|
| R1.OPEN | Open file / project | User opens real source; editor shows content |
| R1.EDIT | Edit + Save | Dirty→save→disk match; no silent truncate |
| R1.BUILD | Compile / link / run | Native build path produces EXE; run launches; failures appear in Output+Problems |
| R1.OUTPUT | Output panel | Build/run text in Output HWND (id1604 family); not chat-contaminated |
| R1.PROBLEMS | Problems panel | Diagnostics listed; click-to-line navigates editor |
| R1.MODEL | Model response | One user submit → correlated backend request → one response stream bound to session |
| R1.AGENT_TOOL | Agent tool action | Real tool call executes under tool authority; result reinjected |
| R1.CANCEL | Cancel + recover | Cancel stops in-flight work; UI recovers; no zombie agent/tool |
| R1.SESSION | Session persistence | Session id survives across turns in same IDE run |
| R1.EXT_SHUTDOWN | Extension shutdown | ExtHost stops without FORCE_KILL; no orphan workers |
| R1.EXIT | Clean exit | IDE exits; no leftover IDE/debuggee/ext processes |
| R1.REPEAT | Repeated-use | Workflow R1.OPEN…R1.EXIT succeeds twice on same SHA |
| R1.FAILREC | Failure recovery | Injected build failure → diagnose → repair → rebuild PASS on same SHA |

### R2 — Issue #49 product-final (decisive maturity milestone)

**REQUIRED.** Maturity stays **82%** until this passes on the final SHA.

Cert target: `=== RAWRXD_PRODUCT_FINAL_001 ===` (GitHub Issue #49).

| Gate family | Must demonstrate on final SHA |
|-------------|-------------------------------|
| I49-CLEAN_CLONE / STRICT_BUILD | Clean tree builds |
| I49-LOCAL_MODEL + GPU/CPU inference | Local model load; generation with finite logits |
| I49-AGENT_* | Reasoning → tool authority → real tool → reinjection → continuation |
| I49-REAL_SOURCE_EDIT | Agent edits real project source |
| I49-BUILD_FAILURE_RECOVERY → FINAL_BUILD / FINAL_TESTS | Fail once → diagnose → second edit → build+tests PASS |
| I49-IDE_* | Chat / Editor / Terminal / Git used in the loop |
| I49-STUB_*=0 | No stub providers/fallbacks/synthetic receipts |
| I49-VERDICT | Conjunction PASS only — no partial credit |

Narrative acceptance (required): launch → local model → open project → agent find/fix/build/test → edit → build fail once → diagnose → second edit → build+tests succeed → evidence. Packaging/clean-machine/rollback follow only after this SHA seals.

### R3 — Release packaging (after R1∧R2)

| Gate ID | Acceptance |
|---------|------------|
| R3.PACKAGE | Installable package from final SHA |
| R3.CLEAN_MACHINE | Launch + smoke on clean machine |
| R3.ROLLBACK | Documented rollback to prior sealed package |

`100% = R1 ∧ R2 ∧ R3` on one final SHA.

---

## OPTIONAL — deferred from release scope

Explicit deferrals. Not chased for 100% unless they block a REQUIRED gate.

| Item | Reason |
|------|--------|
| Track D H61–H120 INVESTIGATE rows (except where they are Issue #49 reqs) | Investigation ≠ confirmed; no 78+120+45 arithmetic |
| Multi-GPU / multi-device (H82/H83) | N_A out of daily-driver scope |
| Cross-platform non-native (H114) | Out of Windows daily-driver release |
| Specialty GPU device-loss (H87) | Not on default workflow unless model path fails |
| Full H01–H60 audit completeness theater | Prefer workflow unlock; chase Hnn only if REQUIRED fails |
| Layer ladder #50 L1–L9 seals as separate maturity climb | Held; Issue #49 is the maturity yardstick for this freeze |
| Experimental SSM / tip-climb promotions | `PROMOTE=0` · `TIP_CLIMB=HOLD` |
| Parallel tip packages (30B9, 2B1D, C43B, tip006) | Absorb evidence; do not remeasure all |

---

## DEPENDENCY_OF_REQUIRED

Invisible or subsystem items that stay in scope because REQUIRED gates need them.

| Dep | Unlocks |
|-----|---------|
| Native EXE link map (Core/DPI surgical or equivalent) | Stable HWND/layout for Output/Problems/chat (H01/H21 class) |
| `RAWRXD_NATIVE_IDE_EXT=ON` tip_ext path when Ext gates required | R1.EXT_SHUTDOWN / four-panel Ext leg (H04/H43) |
| AgentSession / agentic backend on Native product path | R1.AGENT_TOOL + Issue #49 agent loop (H57) |
| ExtHost cleanup FORCE_KILL=0 on candidate SHA | R1.EXT_SHUTDOWN / R1.EXIT (H51) |
| Native PE/COFF linker execution (not adapter-only) | R1.BUILD + I49 build-failure recovery (H41/H42) |
| VS_UNICODE / Problems env scrub on candidate | R1.PROBLEMS stability (H27 CONFIRMED_PRIOR on CC79) |
| Chat dispatch correlation (input→dispatch id→backend→transcript) | R1.MODEL; `EXACTLY_ONCE` must leave NOT_VERIFIED | 
| Output HWND bind on candidate | R1.OUTPUT — **mitigated on tip_cc79_integ_002 `F5F4807E…` (OUTPUT_HWND=PASS verified); must re-prove on replacement SHA** |
| Debug session real (WaitForDebugEvent) when four-panel Debug required | Four-panel conjunction input — measured on `F5F4807E…` per CC79 SCOREBOARD 14:52Z; **no cross-SHA inherit** |
| Terminal panel usable for agent/shell tools | R1 / I49-IDE_TERMINAL — currently `TERMINAL_PANEL_E2E=PARTIAL` on controlling tip |

---

## Integrated workflow checklist

Execute on **one candidate SHA** end-to-end. Mark only from live run evidence.

```
[ ] open file/project
[ ] edit
[ ] save
[ ] compile
[ ] link
[ ] run
[ ] Output panel shows build/run (not chat-contaminated)
[ ] Problems panel lists diags + click-to-line
[ ] model response (correlated single dispatch)
[ ] agent tool action + result reinject
[ ] cancel
[ ] recover
[ ] session persistence (same session id)
[ ] extension shutdown (FORCE_KILL=0)
[ ] clean exit (no orphans)
[ ] repeat workflow once more
[ ] failure-recovery: break build → diagnose → repair → PASS
[ ] Issue #49 product-final loop on same SHA  ← decisive maturity milestone
[ ] package + clean-machine + rollback (R3)
```

Status now: `INTEGRATED_WORKFLOW=NOT_DEMONSTRATED` · `MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED`.

---

## Issue #49 mapping

```
ISSUE_49_IN_REQUIRED=1
ISSUE_49_ROLE=DECISIVE_INTEGRATED_ACCEPTANCE_MILESTONE
MATURITY_REASSESS_ONLY_IF=Issue #49 PASS on final SHA
CC79_PREREQ_INPUT_SHA=F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15
CC79_PREREQ_NOTE=OUTPUT_HWND=PASS on tip_cc79_integ_002; four-panel/debug claimed on same SHA in CC79 SCOREBOARD — still ≠ Issue #49
EXACTLY_ONCE=NOT_VERIFIED
PROMOTE=0
```

---

## Freeze stamp

```
SCOPE_FROZEN=1
REQUIRED=R1_INTEGRATED_WORKFLOW + R2_ISSUE49_PRODUCT_FINAL + R3_PACKAGE
OPTIONAL=DEFERRED_LIST_ABOVE
DEPENDENCY_OF_REQUIRED=LIST_ABOVE
ENGINEERING_MATURITY=82%
PROMOTE=0
CERTIFIED=0
NEXT=BLOCKER_DEPENDENCY_ORDER.md → one candidate repairs
```
