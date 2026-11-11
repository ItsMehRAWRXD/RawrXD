# Exact-hash physical trace

Executable: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`

SHA-256: `28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8`

## Physical observations

- Process launched and was responsive: PASS
- Native editor received text and keyboard focus: PASS
- Chat model committed through the native selector: `Local models / Ollama / qwen3:8b`
- GhostText model committed through the native selector: `Local models / Ollama / qwen3:8b`
- File log recorded qwen3 Ollama routing for the subsequent requests: PASS
- Process was no longer present after the bounded run: PASS

The native Debug output captured the beginning of the exact-hash lifecycle:

```text
[04:17:24] [GhostText] GHOSTTEXT_TRIGGER request_id=5 generation=16 editor_bytes=34
[04:17:24] [GhostText] GHOSTTEXT_REQUEST_SENT request_id=5
```

The file log recorded:

```text
[2026-11-02 04:17:24] [INFO] GhostText inference route: qwen3:8b backend=ollama
[2026-11-02 04:17:25] [INFO] GhostText inference route: qwen3:8b backend=ollama
[2026-11-02 04:17:25] [INFO] GhostText inference route: qwen3:8b backend=ollama
[2026-11-02 04:17:26] [INFO] GhostText inference route: qwen3:8b backend=ollama
[2026-11-02 04:17:26] [INFO] GhostText inference route: qwen3:8b backend=ollama
[2026-11-02 04:17:27] [INFO] GhostText inference route: qwen3:8b backend=ollama
```

## Limitation

The UI automation lost foreground/process state before the final Debug-output lines for request 5 could be extracted. Therefore this receipt does not claim exact-hash proof of rendered B, Tab acceptance, Escape dismissal, or late-A rejection. Prior hashes remain separate evidence tracks.

```ini
EXACT_HASH_ROUTE=PASS
EXACT_HASH_EDITOR_INPUT=PASS
EXACT_HASH_CLEANUP=PASS
EXACT_HASH_FULL_AB_LIFECYCLE=NOT_VERIFIED
GATE_6=HELD
PROMOTE=0
```
