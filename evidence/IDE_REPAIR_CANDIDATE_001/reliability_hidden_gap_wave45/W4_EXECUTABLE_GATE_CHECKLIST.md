# W4 Executable Gate Checklist — 91→94 (planning weight only)

```text
BAND=91->94
MILESTONE=EXTENSIONS_CANCEL_MODEL_SWITCH_PERSIST_RECOVERY
WEIGHT=+3_PLANNING_ONLY
MATURITY_EARNED=0
PROMOTE=0
SHA_RULE=prove_on_ONE_post_Wave1_candidate_SHA
NO_INHERIT_FROM=RC4_78E187 | 4DE0 | CC79 | 47451
```

Executable gates. Each row needs a revision-specific runtime receipt. Owners are workstream owners from `WORKSTREAMS_01_25_WAVE1_CROSSWALK.csv`.

| GateID | Executable proof | Owner WS | Primary owners (paths) | Status class | Current evidence note | Runnable after Wave1? |
|--------|------------------|----------|------------------------|--------------|-----------------------|-----------------------|
| W4-EXT-01 | Extension host start → load one extension → query alive | WS20 | `src/win32app/*Extension*` / ExtensionHost; harness MAP8 pattern | OBLIGATION_ONLY | RC4 **G10=NOT_RUN**. 4DE0 EXT lifecycle PASS is historical only. | YES (needs IDE launch) |
| W4-EXT-02 | Extension clean shutdown: `--ext-quit` with `FORCE_KILL=0` | WS20 | ExtensionHost cleanup; `ISSUE49_EXTENSION_LIFECYCLE_*` harness | HISTORICAL_NOTE / OBLIGATION | Sealed INTEG_004 `47451…` had **EXT_CLEANUP=FAIL** (FORCE_KILL=1) — **HISTORICAL CONFIRMED on that SHA only**; re-prove, do not auto-defect new SHA. | YES |
| W4-EXT-03 | Extension remains healthy across agent tool turn (no orphan process) | WS20 + WS05 | Agent loop + Ext host join | OBLIGATION_ONLY | Blocked until Wave1 tools attach on candidate SHA. | AFTER W1 |
| W4-CAN-01 | Chat cancel_requested → cancel_acknowledged mid-generation | WS09 | Chat runtime cancel path; `chat_runtime.log` markers | HISTORICAL_NOTE | RC4 **G09=PASS** (post-RESPONSE_END cancel). Re-prove on new SHA. Mid-token cancel still open. | YES |
| W4-CAN-02 | Mid-flight computer_use cancel + cleanup (no orphan CU) | WS09 + WS08 | `Win32IDE_ComputerUse.cpp`, session Registry, CU dispatcher | OBLIGATION_ONLY / BLOCKED_AFTER_W1 | RC4: mid-CU cancel **NOT_RUN** (no CU in flight). Requires Wave1 CU attach. | AFTER W1 |
| W4-CAN-03 | Cancel during agent tool-read/edit does not corrupt session | WS09 + WS04 | AgentSession cancel + recovery | OBLIGATION_ONLY / BLOCKED_AFTER_W1 | 4DE0 MAP6 cancel PASS historical only. | AFTER W1 |
| W4-MSW-01 | Switch local Ollama model mid-session; next Send uses new model | WS15 + WS03 | Model picker / session model bind; Ollama backend | OBLIGATION_ONLY | RC4 G07 PASS used one backend; **model-switch E2E NOT_RUN**. | YES |
| W4-MSW-02 | Switch model while idle after tool loop; tools still bound to session Registry | WS15 + WS04 + WS08 | AgentSession + model rebind | OBLIGATION_ONLY / BLOCKED_AFTER_W1 | Needs Wave1 session-owned Registry. | AFTER W1 |
| W4-PER-01 | `--user-data-dir` write `ide_session.json`; restart; sessions/models restore | WS21 | userdata persistence path | HISTORICAL_NOTE | RC4 **G11=PASS**. Re-prove on post-Wave1 SHA. | YES |
| W4-PER-02 | Persistence survives cancel + model-switch (same userdata) | WS21 + WS09 + WS15 | session JSON after W4-CAN/MSW | OBLIGATION_ONLY | Conjunction not sealed on RC4. | YES (after CAN/MSW) |
| W4-REC-01 | Crash/kill IDE mid-chat → restart → no zombie workers; session recoverable or clean | WS23 | Reliability / process cleanup | OBLIGATION_ONLY | RC4 **G12=NOT_RUN**. | YES |
| W4-REC-02 | Failure recovery after tool FAIL: session usable for next Send/tool | WS23 + WS05 | Agent loop recovery | OBLIGATION_ONLY / BLOCKED_AFTER_W1 | Needs Wave1 loop. 4DE0 repeated-use PASS historical. | AFTER W1 |
| W4-REC-03 | Snapshot/rollback path after failed agent edit (when edit exists) | WS23 + WS07 | agent transactions / snapshot | OBLIGATION_ONLY / BLOCKED_AFTER_W1 | Maps Issue #57 **A15** obligation (related≠PASS). | AFTER W1 |

```text
W4_CONFIRMED_BLOCKERS_ON_REPAIR_CANDIDATE=0_NEW
  (do not promote historical EXT_CLEANUP FAIL into this candidate without same-SHA re-run)
W4_OBLIGATIONS=13
W4_BLOCKED_AFTER_W1=5 (EXT-03, CAN-02, CAN-03, MSW-02, REC-02, REC-03) 
W4_IMMEDIATE_POST_W1_SERIAL=
  EXT-01 → EXT-02 → CAN-01 → MSW-01 → PER-01 → PER-02 → REC-01
  then CAN-02/03 + MSW-02 + REC-02/03 on same SHA
```
