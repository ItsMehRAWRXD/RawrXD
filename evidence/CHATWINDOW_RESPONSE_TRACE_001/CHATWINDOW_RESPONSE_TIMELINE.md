# CHATWINDOW_RESPONSE_TIMELINE

ASOF_UTC=2026-11-02T13:28:00Z  
GATE=CHATWINDOW_RESPONSE_TRACE_001  
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB  
EVIDENCE_BASE=`F:\rawrxd\evidence\PRODUCT_BINARY_SEAL_001\`  
SOURCE_TREE=`F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef` (read-only)  
`SOURCE_MUTATION=0` · `REBUILD=0` · `PROMOTE=0`

## Lifecycle (dispatch → render)

| # | Transition | Class | Evidence |
|---|------------|-------|----------|
| 0 | Host prereq (Ollama up, no prior UI procs) | OBSERVED | RUNLOG `OLLAMA_UP=1`; receipt FREE_PHYS / F_FREE |
| 1 | Candidate launch | OBSERVED | pid=27064; MAIN_READY `RawrXD_IDE_Window` |
| 2 | Chat UI create/show (1202/1203/1204/1210) | OBSERVED | CREATE_SHOW=1 |
| 3 | Model selection | OBSERVED | COMBO_INDEX_0 (45 entries; preferred names unmatched) |
| 4 | Prompt set + Send click | OBSERVED | INPUT_LEN=33; PROMPT_SUBMITTED=1; text=`Reply with exactly one word: PONG` |
| 5 | `HandleCopilotSend` → `generateResponseAsync` | OBSERVED (by effect) | `bin\ollama_debug.log` written only via `generateOllamaModel` |
| 6 | Model identity bound | OBSERVED | `bigdaddyg-productivity-local:latest` |
| 7 | Thinking/completion probe + MODEL_LOAD | OBSERVED | `MODEL_LOAD=PASS` · ctx=65536 · max_out=512 · mode=Instant |
| 8 | HTTP `/api/generate` send + receive complete | **NOT_VERIFIED / FAIL vs 120s gate** | No `Raw response length` / `GENERATED_TOKENS` / WinHTTP error line before teardown |
| 9 | Worker `finish()` / `onResponse` callback | NOT_VERIFIED | Dependent on (8); UI output length never grew |
| 10 | UI thread `kRawrxdCopilotUiUpdate` / `handleCopilotUiUpdate` | NOT_VERIFIED | Output edit empty after prompt (`output_after_prompt1.txt` empty); no status growth logged |
| 11 | Render accept ("AI: …" / PONG) | FAIL | RESPONSE_OK=0 · RESPONSE_CLASS=NOT_OBSERVED |
| 12 | Cancel / Stop | FAIL | CANCEL_CLICKED with `cancelEnabled=0`; status blank |
| 13 | Teardown | OBSERVED | TEARDOWN_HIDE=1 · TEARDOWN_PROC=1 · CRASH_DURING_RUN=0 |

## Identifiers

| Field | Value | Class |
|-------|-------|-------|
| Request ID | (none in Ollama debug path) | NOT_INSTRUMENTED |
| Generation ID | `m_currentModelGenID` exists for model discovery; not logged on chat send | NOT_INSTRUMENTED |
| Model identity | `bigdaddyg-productivity-local:latest` | OBSERVED |
| Dispatch timestamp | ~2026-11-02T08:12:15.618-05 (PROMPT_SUBMITTED) | OBSERVED |
| Backend MODEL_LOAD | same window; ollama_debug append | OBSERVED |
| Backend completion | absent in log through teardown ~08:14:32 | NOT_VERIFIED |
| Callback arrival | not observed | NOT_VERIFIED |
| Cancellation state | Stop disabled at attempt | OBSERVED (FAIL) |
| Render decision | no output growth / no error string in UI | FAIL |

## ollama_debug.log (verbatim, complete file at capture)

```
[OLLAMA_DEBUG] generateOllamaModel: model='bigdaddyg-productivity-local:latest' prompt_len=87 maxTokens=512 contextTokens=65536 mode=Instant
[OLLAMA_DEBUG] Connecting to localhost:11434
[OLLAMA_RUNTIME] MODEL=bigdaddyg-productivity-local:latest MODEL_LOAD=PASS REQUESTED_CONTEXT=65536 EFFECTIVE_CONTEXT=65536 MAX_OUTPUT_TOKENS=512
```

Next expected instrumented lines (source `Win32IDE.cpp` `generateOllamaModel`) if HTTP finished: `Raw response length` or `WinHttpSendRequest/ReceiveResponse failed` then `GENERATED_TOKENS=…`. **None present.**

## Timing note (code vs harness)

- Harness wait: **120s** after submit.  
- Product WinHTTP receive/read timeout: **600000 ms (10 min)** (`kOllamaReceiveTimeoutMs`).  
- Non-streaming `stream:false` generate with `num_ctx=65536` on a large local model can remain inside `WinHttpReceiveResponse` without UI progress.  
- Therefore absence of UI response at 120s is a **gate FAIL**, but does **not** alone prove Ollama crashed; it proves **backend completion was not observed within the acceptance window**, and no failure string was marshaled to the UI before teardown killed the process (~17s after the 120s wait ended).
