# Wave2 Issue #49 gap map vs CERTIFICATION_LADDER_MAP.md (roadmap 85→88)

```text
ASOF_UTC=2026-11-10T08:10:00Z
OWNER=swarm-w2
ROADMAP_BAND=85->88 ISSUE49_CHAT_SESSION_TOOL_LOOP_EXACTLY_ONCE
RC4=SEALED_IMMUTABLE SHA=78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596
WAVE1_LANE_SHA=6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C
WAVE1_NEW_PUBLISH_SHA=ABSENT
PROMOTE=0
CERTIFIED=0
MATURITY=82%_UNCHANGED
TIP_CLIMB=HOLD
INVENT_PASS=0
NO_RC4_MUTATION=1
NO_CROSS_SHA_INHERIT=1
```

Authority inventory: `../CERTIFICATION_LADDER_MAP.md` + `../MATURITY_ROADMAP_82_100.txt`.  
This file maps gaps only. It does **not** raise maturity or seal Issue #49.

---

## Band meaning (85→88)

| Claim | Required evidence | Wave2 status |
|-------|-------------------|--------------|
| Chat input → AgentSession bind | Same-SHA live Send + session-owned Registry | Wave1 claimed SOURCE_WIRED on 6E59; Wave2 **does not re-certify** until new publish SHA |
| Tool loop (not Copilot text-only) | RAWRXD_AGENT_MODE → AgenticLoop; real TOOL calls | Wave1 READ path credited; CU_GUI E2E held by P0 (orphan verify ≠ live) |
| Exactly-once tool dispatch | Each `tool_call_id` executes ≤1 per turn; empty id rejected | **NEW** guard + fixture harness (unit); product-path **NOT_VERIFIED** |
| Issue #49 engineering 11/11 | One SHA; steps 01/04/05/06/08/10–15 | **WAITING** Wave1 new SHA; pinned harness fail-closed |

---

## Ladder §2a engineering 11-step (vs wait state)

| Step | Ladder vs RC4 | vs Wave1 6E59 (no Wave2 remeasure) | Wave2 disposition |
|-----:|---------------|------------------------------------|-------------------|
| 01 LAUNCH | PARTIAL | Wave1 package present | NOT_RUN until publish SHA |
| 04 OPEN_PROJECT | PARTIAL | fixture prepared under `fixtures/bug.cpp` | FIXTURE_READY / runtime NOT_RUN |
| 05 AGENT_PROMPT | FAIL-closed on RC4 CU | Wave1 chat/agent path claimed | NOT_RUN Wave2 seal |
| 06 AGENT_READS | FAIL required TOOL read on RC4 | Wave1 READ_PASS on other loop SHAs — **no inherit** | NOT_RUN on publish SHA |
| 08 TOOL_AUTHORITY | FAIL orphan CU | Wave1 session Registry claim | NOT_RUN Wave2 |
| 10 REAL_SOURCE_EDIT | NOT_RUN | C4067 write-path gap documented by edit owner | BLOCKED / NOT_RUN |
| 11–15 repair/build/test | NOT_RUN | blocked on durable edit | NOT_RUN |

```text
ISSUE49_ENGINEERING_WAVE2=NOT_RUN_AWAITING_WAVE1_PUBLISH_SHA
ISSUE49_11_11_ON_35C22=HISTORICAL_ONLY
ISSUE49_ON_RC4=NOT_PASS (immutable)
```

---

## Ladder §2b product-final keys (Wave2-relevant)

| Key | Wave2 note |
|-----|------------|
| AGENT_REASONING / TOOL_AUTHORITY / REAL_TOOL_CALL | Require same-SHA live loop; EXACTLY_ONCE not yet product-wired |
| RESULT_REINJECTION / AGENT_CONTINUATION | Hold; P0 CU_GUI coordination open |
| REAL_SOURCE_EDIT … FINAL_TESTS | Hold on durable ledger write + content edit |
| VERDICT | FAIL_CLOSED_HOLD; G15 NOT_ESTABLISHED |

---

## Workstream crosswalk (Wave2 slice)

From ladder §4 / `WORKSTREAMS_01_25_WAVE1_CROSSWALK.csv`:

| WS | Role for Wave2 |
|----|----------------|
| 02–05 | Consume Wave1 session/loop; measure exactly-once + 11-step on **new** SHA |
| 06–07 | Protocol + file tools — do not edit Wave1 Ext/CU/AgentCommands |
| 08 | Computer use — Wave1/P0 owned; Wave2 only records CU string presence in structural probe |
| 19 | Agent orchestration — Wave2 primary after 04–07 live |

```text
WAVE2_EXIT_CRITERIA=
  EXACTLY_ONCE verified on product tool path (same SHA)
  AND Issue #49 11-step measured on that SHA (no inherit)
  AND PROMOTE=0 until higher conjunction
WAVE1_EXIT_ALREADY_CLAIMED=WAVE1_REAL_TOOL_READ_AND_CU_E2E on 6E59
  (Wave2 does not treat that as 85->88 seal; CU_GUI held by P0)
```

---

## Non-conflict surface

| Owner | Paths Wave2 will not edit |
|-------|---------------------------|
| Wave1 | `Win32IDE_ComputerUse*`, `ComputerUse*`, `Win32IDE_AgentCommands*`, `Win32IDE_lifecycle*` (per LANE) |
| Wave2 | `evidence/.../issue49_wave2/**`, `scripts/issue49_wave2/**`, `tools/issue49_wave2/**`, `src/agentic/ToolCallExactlyOnceGuard.hpp` |

Absorb of guard into `ToolCallBridge::ExecuteToolCall` deferred until Wave1 publish SHA + absorb review.
