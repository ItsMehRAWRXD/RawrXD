# Exact-hash production GhostText A/B race receipt

## Authority and binary

- Worktree: `F:\rawrxd`
- Production executable: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8`
- Size: `1,731,072` bytes
- Last write: `2026-11-02T04:12:43.9407929-05:00`
- Test PID: `24076`
- Launch receipt: `2026-11-02T04:41:47.0321907-05:00`
- Environment: `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=5000`, `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS=50`
- Route selected in the native UI: `Local models / Ollama / qwen3:8b`
- Inference route: `qwen3:8b backend=ollama`

## Deterministic sequence

The following lines were captured from the native IDE Debug output after the exact-hash run. The on-disk application log separately records the matching `qwen3:8b backend=ollama` route lines; the `GHOSTTEXT_*` lifecycle lines are emitted by the native debug surface.

```text
[04:42:15] [GhostText] GHOSTTEXT_TRIGGER request_id=1 generation=54 editor_bytes=32
[04:42:15] [GhostText] GHOSTTEXT_REQUEST_SENT request_id=1
[04:42:15] [2026-11-02 04:42:15] [INFO] GhostText inference route: qwen3:8b backend=ollama
[04:42:15] [GhostText] GHOSTTEXT_CANCELLED request_id=1 generation_before=54 pending_before=1
[04:42:15] [GhostText] GHOSTTEXT_INVALIDATED request_id=1 generation_after=55 pending_after=0
[04:42:15] [GhostText] GHOSTTEXT_TRIGGER request_id=2 generation=55 editor_bytes=33
[04:42:15] [GhostText] GHOSTTEXT_REQUEST_SENT request_id=2
[04:42:15] [2026-11-02 04:42:15] [INFO] GhostText inference route: qwen3:8b backend=ollama
[04:42:16] [GhostText] GHOSTTEXT_RESPONSE_RECEIVED request_id=2 success=1 response_bytes=107 generated_tokens=N/A generation_current=1 identity_current=1 snapshot_current=1
[04:42:16] [GhostText] GHOSTTEXT_RENDER_DECISION request_id=2 eligible=1
[04:42:16] [GhostText] GHOSTTEXT_RENDERED request_id=2 response_bytes=107
[04:42:20] [GhostText] GHOSTTEXT_RESPONSE_RECEIVED request_id=1 success=1 response_bytes=107 generated_tokens=N/A generation_current=0 identity_current=1 snapshot_current=1
[04:42:20] [GhostText] GHOSTTEXT_RENDER_DECISION request_id=1 eligible=0
```

## Assessment

- Request A trigger and dispatch: **PASS** (`request_id=1`).
- A invalidated by an editor change while pending: **PASS**.
- Request B dispatched after invalidation: **PASS** (`request_id=2`).
- B response and render before A completion: **PASS** (`04:42:16` before `04:42:20`).
- Late A response rejected without replacement: **PASS** (`generation_current=0`, `eligible=0`).
- Explicit qwen3:8b/Ollama routing: **PASS**.
- Exact production binary association: **PASS** by pre-launch SHA receipt.

## Scope boundary

This receipt proves the combined A/B ordering and late-response fence for the exact SHA above. It does not, by itself, close unrelated numerical/Kimi/GPU certification gates or global IDE certification.

The test-owned IDE was closed through the normal window-close path. The unsaved-changes prompt was answered `No`; no file was written. At the post-close check, PID `24076` had exited and no `RawrXD-Win32IDE-Native` process remained.

```ini
EXACT_HASH_AB_RACE=PASS
PRODUCTION_B_RENDER=PASS
PRODUCTION_LATE_A_REJECTION=PASS
PRODUCTION_QWEN_OLLAMA_ROUTING=PASS
PROCESS_EXIT=NORMAL
NATIVE_IDE_COUNT_AFTER_CLOSE=0
GATE6_PRODUCTION=PASS_SCOPE_AB_RACE
PROMOTE=0
CERTIFIED=0
```
