# P0 GATES RECEIPT — Provenance / Repeat-Request / Bind Authority (2026-09-28)

Build: rawr-server.exe @ commit 001ab0ee691f, source_dirty=0 (FINAL certified build, UTC 20:34:00)
Certifying run: PID 4140, port 11436, loopback-only.

## GATE=DEEP2_UPSTREAM_REPEAT_REQUEST_001  (FINAL — clean-provenance binary)

```
BINARY_PROVENANCE=PASS        (--build-info: sha=001ab0ee691f dirty=0 ts=2026-09-28T20:34:00 config=Release)
RUNNING_EXE_SHA_MATCH=PASS    (running exe == just-built artifact from committed tree)
SOURCE_COMMIT_MATCH=PASS      (provenance sha == HEAD 001ab0ee691f)

MODEL_LOAD=PASS
HEALTH=PASS                   (provenance JSON incl. source_dirty:false, bind_mode=loopback)

REQUEST_1_GENERATED=PASS      (INDIA: 200 tokens=6 content contains INDIA_ stamp)
REQUEST_2_GENERATED=PASS      (JULIET: 200 tokens=6 content contains JULIET)
REQUEST_3_GENERATED=PASS      (KILO: 200 tokens=6 content contains KILO)

SAME_PROCESS=PASS             (PID 4140 alive across all 3 requests)
SAME_ENGINE_INSTANCE=PASS     (D2LOAD_COUNT=1 — no reload between requests)
REQUEST_2_STATE_RESET=PASS    (CHECKPOINT POST_RESET kv_len=0)
REQUEST_3_STATE_RESET=PASS    (CHECKPOINT POST_RESET kv_len=0)
KV_POSITION_MISMATCH_COUNT=0
POST_REQUEST_HEALTH=PASS      (200, provenance intact, model_loaded=true)
PROMPT_DEPENDENT_OUTPUT=PASS  (each unique stamp echoes into content)

VERDICT=PASS
```

Checkpoint receipts (raw from server stderr, exactly as emitted):
```
CHECKPOINT REQUEST_BEGIN kv_len=0
CHECKPOINT POST_RESET kv_len=0
CHECKPOINT REQUEST_END generated=6 kv_len=25
CHECKPOINT REQUEST_BEGIN kv_len=25
CHECKPOINT POST_RESET kv_len=0
CHECKPOINT REQUEST_END generated=6 kv_len=26
CHECKPOINT REQUEST_BEGIN kv_len=26
CHECKPOINT POST_RESET kv_len=0
CHECKPOINT REQUEST_END generated=6 kv_len=26
MISMATCH=0 D2LOAD_COUNT=1
```

Earlier dirty-source build receipts (superseded but recorded): build
01ec95709421 dirty=1 passed the same 3-request cert (FOXTROT/GOLF/HOTEL).

Checkpoint contract (per request, from server stderr):
```
CHECKPOINT REQUEST_BEGIN kv_len=<n>   # inherited from prior request
CHECKPOINT POST_RESET  kv_len=0       # reset deterministic
CHECKPOINT REQUEST_END generated=N kv_len=<prompt+N>
```

## GATE=DEEP2_SERVER_BIND_AUTHORITY_001

```
DEFAULT_BIND_LOOPBACK=PASS        (default run: BIND=127.0.0.1:11436 measured)
DEFAULT_LAN_REACHABLE=0
REMOTE_BIND_EXPLICIT_OPT_IN=PASS  (--listen 0.0.0.0 --auth <token> required)
REMOTE_BIND_WITHOUT_AUTH=DENIED   (process refuses to start: LISTEN_NO_AUTH_ALIVE=False)
AUTH_ENFORCEMENT=PASS             (POST no token -> 401 in 0.06ms; with token -> 200 + generation)
HEALTH_UNAUTHENTICATED=PASS       (readiness info only: no tokens/keys; model_id + build info)

VERDICT=PASS
```

## Code changes (real, committed in this batch)

1. `deep2_openai_server.h/.cpp`: `run(port, bindAddress="127.0.0.1", authToken="")`;
   INADDR_ANY only on explicit "0.0.0.0" + AUTH_REQUIRED bearer gate on /v1/*;
   health extended with build provenance; Impl gains authToken/authRequired.
2. `deep2_openai_server_main.cpp`: `--listen`, `--auth`, `--build-info`;
   hard refusal to run non-loopback without auth; auth passed to run().
3. `Deep2Engine.h/.cpp`: public `kvCacheLength()` accessor (authority-bearing
   state for checkpoints).
4. `CMakeLists.txt`: bake RAWRXD_BUILD_SHA/DIRTY/TS/CONFIG into rawr-server at
   configure time (find_package(Git) + git rev-parse/diff --quiet).
5. `Deep2Engine.cpp:2697`: KV mismatch diag emit (pos/seqLen/layer) — kept,
   fires only on the error path.

## Fail-closed notes

- source_dirty=1 at build time is the honest value (P0 edits were uncommitted);
  committing flips it to 0 — receipts must be regenerated after that commit.
- P0.3 (engine failure -> HTTP semantics) remains BLOCKED on deeper P0.2 state
  comparison work; `generatedTokens==0 => error` shortcut deliberately avoided.