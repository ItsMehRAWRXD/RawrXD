# ISSUE49_MODEL_TOOL_PROTOCOL_BLOCKER

ASOF_UTC=2026-11-09T20:25:00Z
MOTD_ACK=1
LANE=ISSUE49_TOOL_PROTOCOL_MODEL_PROBE
CONTROLLING_TIP=CC79
STAGE_TIP_MEASURED=tip_final_integ_012
SHA_UNDER_TEST=1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9
LOOP_SHA256=7109EFC429C62EB04537E818DE122014D234F392FE98736E89873993F7220B09
HOST_SEED=OFF
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
TIP_013=NOT_FROZEN
E6CF_RESTORE=HELD

## Disposition

```
PROTOCOL_DISPOSITION=FAIL_CLOSED_MODEL_CANNOT_EMIT_TOOL_PREFIX
MODEL_ORIGINATED_TOOL_CALLS_GE_1=0
TOOL_PREFIX_EMITTED=0
SNAP_RELAX=NOT_APPLIED
  (no product law authorization to accept non-TOOL as PASS)
ISSUE49_PASS_COUNT=3/11 (unchanged; tip_012 exclusive)
DO_NOT_CLAIM_11_11=1
```

## Inventory (local)

### GGUF under F:\rawrxd\models (+ nearby chat/instruct candidates)

| Path | Size | Notes |
|------|------|-------|
| F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf | ~940 MB | base; prior SNAP-stop |
| F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf | ~638 MB | chat; EOS empty |
| F:\rawrxd\models\pdurugyan_qwen3.5-9b-...gguf | ~5.4 GB | tools template; KV unstable |
| F:\rawrxd\models\gemma3_latest.gguf | ~3.2 GB | load abort this path |
| F:\rawrxd\models\nemotron-3-nano_4b.gguf | ~2.7 GB | load abort this path |
| F:\rawrxd\models\kiminoto_T0.0.1_latest.gguf | ~6.3 GB | qwen35; EXEC_FAIL residualadd |
| F:\rawrxd\gemma3-1b-Q2_K.gguf | ~667 MB | chat; EOS SNAP expected TOOL |
| F:\rawrxd\llama3.2-3b-Q3_K_S.gguf | ~1.5 GB | chat+tools template; abort mid-prefill |
| F:\rawrxd\phi3-mini-Q2_K.gguf | ~1.4 GB | instruct; abort mid-prefill |
| F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf | ~9.9 GB | chat; load/runtime abort |
| Larger on-disk (skipped for minimal smoke) | multi-GB | deepseek-coder-v2_16b, starcoder2_15b, gpt-oss, deepseek-r1_32b, nemotron-30b, ornith-35b, bigdaddygnative |

### Ollama tags (present; probes used deep2 SNAP GGUF path)

Notable local instruct/chat: `llama3.1:8b`, `llama3.2:3b`, `qwen3:8b`, `gemma3:latest`, `gemma3:4b`, `granite3.3:8b`, `nemotron-3-nano:4b`, `qwen2.5-coder:1.5b-base`, `pdurugyan/qwen3.5-9b-...`, `deepseek-coder-v2:16b`. No Ollama tool channel claimed as Issue #49 PASS.

## Models tried matrix (deep2_agentic_loop tip_012; exclusive; host-seed OFF; opaque fixture)

| Model | Result | tool_calls | Evidence log |
|-------|--------|------------|--------------|
| qwen2.5-coder_1.5b-base | SNAP_STOP expected TOOL / model_output_invalid | 0 | prior tip_011 disposition |
| tinyllama-1.1b-chat-v1.0.Q4_K_M | EOS empty (SNAP OUT bytes=0); expected TOOL | 0 | probe/tinyllama_tool_probe2.log |
| pdurugyan_qwen3.5-9b | PARTIAL_KV fail-closed; serial/load unstable | 0 | probe/qwen9b_tool_probe2.log / probe3 |
| gemma3-1b-Q2_K | EOS empty SNAP expected TOOL; FINAL_VERDICT FAIL | 0 | probe/followup_gemma3_1b_Q2_tool_smoke.log |
| gemma3_latest | LOAD_ABORT after loading model | 0 | probe/followup_gemma3_latest_tool_smoke.log |
| nemotron-3-nano_4b | LOAD_ABORT after loading model | 0 | probe/followup_nemotron3_nano_4b_tool_smoke.log |
| kiminoto_T0.0.1_latest | EXEC_FAIL residualadd attn_proj missing | 0 | probe/followup2_kiminoto_T001_tool_smoke.log |
| llama3.2-3b-Q3_K_S | RUNTIME_ABORT mid-prefill / EXIT=-1; no TOOL | 0 | probe/followup4_llama32_tool_smoke.log, followup5_* |
| phi3-mini-Q2_K | RUNTIME_ABORT mid-prefill / EXIT=-1; no TOOL | 0 | probe/followup4_phi3_tool_smoke.log |
| DeepSeek-V2-Lite-Chat.Q4_K_M | LOAD/RUNTIME_ABORT; no TOOL | 0 | probe/followup2_deepseek_v2_lite_chat_tool_smoke.log |

```
ANY_MODEL_EMITTED_REAL_TOOL_PREFIX=0
ANY_MODEL_RUNTIME_REACHED_TOOL_CALLS_GE_1=0
WRITE_OR_EDIT_FROM_MODEL_TOOL=0
```

## Exact SNAP/EOS samples (completed decode path)

### tinyllama (probe2)
- `[SNAP OUT RAW] bytes=0 text=""`
- `snap_stop ... expected TOOL protocol prefix`
- `error ... model_output_invalid`

### gemma3-1b (followup)
- `[SNAP OUT RAW] bytes=0 text=""` eos_id=1
- `INVALID OUTPUT (snap reason=5 expected TOOL protocol prefix)`
- `MODEL_REQUESTED_TOOL   NO (tool_calls=0)`
- `FINAL_VERDICT          FAIL`

### qwen3.5-9b (probe2)
- `PREFILL_BATCH_PARTIAL_KV ... failing closed`
- `MODEL_REQUESTED_TOOL   NO (tool_calls=0)`
- `FINAL_VERDICT          FAIL`

## Next product gate (not tip_move; not 11/11)

```
NEXT_GATE=BRING_INSTRUCT_TOOL_CAPABLE_GGUF_OR_ALTERNATE_TOOL_CHANNEL
OPTIONS=
  1) Import/build a local instruct GGUF that emits product TOOL line protocol
     under deep2 SNAP (or constrained-decode/grammar ONLY if product law authorizes).
  2) Alternate tool channel (e.g. Ollama native tool_calls) ONLY if product law
     wires it into Issue #49 acceptance without inventing host-seed PASS for 08-11.
  3) Do NOT relax SNAP to accept non-TOOL text as PASS.
  4) Do NOT invent 09-11 via RAWRXD_ISSUE49_HOST_SEED.
BLOCKER_OWNER=MODEL_TOOL_PROTOCOL
TIP_013=HELD_UNTIL_MODEL_ORIGINATED_TOOL_GE_1
PROMOTE=0
TIP_MOVE=0
```

## Paths

```
BLOCKER=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_MODEL_TOOL_PROTOCOL_BLOCKER.md
MATRIX=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\probe\MODEL_TOOL_SMOKE_MATRIX.txt
BOARD=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\ISSUE49_ACCEPTANCE_BOARD.md
PROBE_DIR=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\probe\
LOOP=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe
```

---

## NEXT_EXECUTABLE_GATE (2026-11-09 continue -- model-tool path)

ASOF_UTC=2026-11-09T22:49:47Z
MOTD_ACK=1
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
TIP_013=NOT_FROZEN
E6CF_RESTORE=HELD
A4F_UNTOUCHED=1
TIP_005_UNTOUCHED=1
TIP_010_UNTOUCHED=1
CONTROLLING_TIP=CC79

### 1) AUTHORIZED alternate tool channel?

```
LAW_RESULT=NONE_AUTHORIZED
```

Citations (fail-closed; no Issue #49 wire for non-TOOL / host-invented 08-11):

- F:\rawrxd\src\agentic\NativeToolProtocol.h:67-69 -- response must start with TOOL (native parser fail-closed).
- F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_MODEL_TOOL_PROTOCOL_BLOCKER.md:96-100 -- alternate (e.g. Ollama tool_calls) / grammar ONLY if product law authorizes; SNAP non-TOOL not PASS; no host-seed invent 09-11.
- F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\ISSUE49_ACCEPTANCE_BOARD.md:46-47 -- HOST_SEED=OFF; DO_NOT_INVENT_09_11_VIA_HOST_SEED=1.
- F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt:5 -- MODEL_ORIGINATED_TOOL_REQUIRED=1.
- F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\step08_11_evidence\DISPOSITION.txt:27-28 -- think-skip still requires model-originated TOOL; host-seed WRITE removed.

Host-seed / FORCE_LOCAL ledger seed (Win32IDE_AgentCommands.cpp:1497-1499) is not an authorized path to claim steps 08-11 under tip_012 law. OpenAI-compat / JSON tool_calls / ESP kind= without TOOL prefix: present as code surfaces, not product-law-authorized Issue #49 acceptance channels.

### 2) Net-new GGUF smokes (not in prior MODEL_TOOL_SMOKE_MATRIX)

| Model | Path | Size | Result | tool_calls |
|-------|------|------|--------|------------|
| phi-3-mini-4k-instruct.Q4_K_M | G:\~dev\models\phi-3-mini-4k-instruct.Q4_K_M.gguf | 2282 MB | EOS_EMPTY_SNAP_EXPECTED_TOOL; FINAL_VERDICT FAIL | 0 |
| llama3.2-3b-Q2_K | F:\rawrxd\llama3.2-3b-Q2_K.gguf | 1301 MB | EOS_EMPTY_SNAP_EXPECTED_TOOL; FINAL_VERDICT FAIL | 0 |

Evidence:
- artifacts/issue49_integ012/probe/netnew_phi3_mini_4k_instruct_Q4_tool_smoke.log
- artifacts/issue49_integ012/probe/netnew_llama32_3b_Q2_tool_smoke.log
- artifacts/issue49_integ012/probe/MODEL_TOOL_SMOKE_MATRIX_NETNEW.txt

```
NETNEW_ANY_TOOL_PREFIX=0
NETNEW_ANY_TOOL_CALLS_GE_1=0
PRIOR_MATRIX_NOT_RESMOKED=1
```

HF cache: models--AtomicChat--Qwen3.8-*-GGUF dirs exist but no .gguf bodies. Ollama instruct/tool tags exist; Issue #49 product path remains deep2 SNAP GGUF + TOOL prefix -- Ollama channel NONE_AUTHORIZED for 08-11.

### 3) tip_013 / remasure

```
TIP_013=NOT_FROZEN
REMEASURE_08_11=NOT_RUN
REASON=still_blocked_MODEL_TOOL_PROTOCOL_no_model_originated_TOOL
```

### 4) NEXT_EXECUTABLE_GATE (exact import)

```
NEXT_EXECUTABLE_GATE=IMPORT_QWEN25_CODER_INSTRUCT_GGUF_THEN_SMOKE_DEEP2_SNAP
BLOCKER_OWNER=MODEL_TOOL_PROTOCOL
IMPORT_ARTIFACT_PRIMARY=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
IMPORT_ARTIFACT_PRIMARY_EXPECTED_SIZE=~4.68 GiB (~5010000000 bytes; Qwen2.5-Coder-7B-Instruct-GGUF Q4_K_M class)
IMPORT_ARTIFACT_ALT=F:\rawrxd\models\qwen2.5-coder-14b-instruct.Q4_K_M.gguf
IMPORT_ARTIFACT_ALT_EXPECTED_SIZE=~9.0 GiB
IMPORT_ARTIFACT_Q8_ABSENT=F:\rawrxd\models\qwen2.5-coder-14b-instruct-q8_0.gguf
IMPORT_ARTIFACT_Q8_NOTE=meta log F:\rawrxd\meta_qwen2.5-coder-14b-instruct-q8_0.gguf.log exists; GGUF body ABSENT on scanned drives
SMOKE_AFTER_IMPORT=deep2_agentic_loop tip_012; HOST_SEED=OFF; opaque issue49_project; require TOOL prefix / tool_calls>=1 before tip_013 freeze
DO_NOT=relax SNAP; invent 08-11 via host-seed; re-smoke prior matrix set; tip_move; PROMOTE
STOP=1
```
---

## IMPORT + SMOKE + tip_013 follow-up (2026-11-10T00:00:24Z)

MOTD_ACK=1
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79

### DOWNLOAD_STATUS

```
DOWNLOAD_STATUS=PASS
SOURCE=bartowski/Qwen2.5-Coder-7B-Instruct-GGUF
FILE=Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf
IMPORT_ARTIFACT_PRIMARY=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
SIZE_BYTES=4683074336
SIZE_GB10=4.683
SHA256=1664FCCAB734674A50763490A8C6931B70E3F2F8EC10031B54806D30E5F956B6
HASH_MATCH_HF=1
METHOD=hf download (UTF-8)
```

### SMOKE_STATUS (deep2 SNAP; HOST_SEED=OFF; tip_012/013 loop SHA 7109…)

```
SMOKE_STATUS=PASS
LOOP=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe
LOOP_SHA256=7109EFC429C62EB04537E818DE122014D234F392FE98736E89873993F7220B09
HOST_SEED=OFF
TOOL_PREFIX_EMITTED=1
SNAP_OUT=TOOL read_motd
TOOL_CALLS=2
RESULT_REINJECTION_PASS=2
LOG=artifacts/issue49_integ012/probe/import_qwen25_coder_7b_instruct_Q4_tool_smoke2_20261109-181343.log
NOTE=first attempt mid-prefill cut; retry with prefill-chunk 128 completed TOOL x2 (outer wall killed during step3 MOTD-balloon prefill)
```

### tip_013 freeze + exclusive 08-11 remasure

```
TIP_013=FROZEN
TIP_SHA256=1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9
LOOP_SHA256=7109EFC429C62EB04537E818DE122014D234F392FE98736E89873993F7220B09
MODEL_WIRED=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
CANDIDATE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_013\
NO_INHERIT_TIP011_HOST_SEED=1

IDE_EXCLUSIVE_08_11=FAIL_CLOSED_WATCHDOG_TIMEOUT_PRE_TOOL
  receipt=artifacts/issue49_integ013/ISSUE49_PRODUCT_FINAL_TIP013_RECEIPT.txt
  REQUIRED_PASS_HITS=3/11 (IDE path; watchdog killed during prefill)

LOOP_EXCLUSIVE_08_11=MEASURED
  STEP08=PASS_MODEL_ORIGINATED_TOOL
  STEP09=PASS
  STEP10=NOT_RUN_NO_AGENT_EDIT
  STEP11=NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY
  TOOL_CALLS=1 REINJECT_PASS=1
  evidence=artifacts/issue49_integ013/step08_11_evidence/DISPOSITION.txt
  log=artifacts/issue49_integ013/step08_11_evidence/tip013_loop_exclusive_08_11.log

ISSUE49_PASS_COUNT=still_not_11/11
FULL_11_ADVANCE=NOT_RUN (10/11 still open; no invent)
PROTOCOL_DISPOSITION=MODEL_CAN_EMIT_TOOL_PREFIX (blocker owner shifts)
NEXT_EXECUTABLE_GATE=AGENT_SOURCE_EDIT_THEN_BUILD_RECOVERY_ON_TIP013_INSTRUCT
  (model currently loops TOOL read_motd; need write/edit + recovery)
  IDE_WATCHDOG_TOO_SHORT_FOR_7B_PREFILL=1
BLOCKER_OWNER=NO_AGENT_SOURCE_EDIT;NO_AGENT_OWNED_BUILD_RECOVERY;IDE_WATCHDOG_PREFILL
PROMOTE=0
TIP_MOVE=0
STOP=1
```

---

## tip_014 write-verify fix + measured 10/11 (2026-11-10T02:35:00Z)

```
ROOT_CAUSE=NATIVE_WRITE_VERIFY_MISSING_WITHMSVCENV
  tip013 10_11: TOOL write emitted; PATCH ROLLED BACK (bare cl); HASH_DRIFT=0
  NOT allowlist / NOT prompt / NOT SNAP-after-first-tool

TIP_014_SHA=6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247
LOOP_SHA=CEB669011246266A911613B8648EEFE69D0225506F01F46A4D56EAC8A572D5F7
HOST_SEED=OFF

LOOP_08_11_TIP014=MEASURED
  08=PASS_MODEL_ORIGINATED_TOOL
  09=PASS
  10=PASS_SOURCE_HASH_AND_LEDGER (HASH_DRIFT=1 PATCH_COMMITTED=1)
  11=PASS_WRITE_VERIFY_BUILD_RECOVERY
  evidence=artifacts/issue49_integ014/step08_11_evidence/

IDE_EXCLUSIVE_TIP014=NOT_YET_REMEASURED
  watchdog extended in EXE (180s/40min) + AgentWaitSec=7200 harness
BLOCKER_OWNER=IDE_EXCLUSIVE_REMEASURE_PENDING;KV_PREFIX_FAIL_ON_LOOP_FINAL;ISSUE49_NOT_11_11
NEXT=IDE_EXCLUSIVE_REMEASURE_TIP014_7B_WATCHDOG
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
```
