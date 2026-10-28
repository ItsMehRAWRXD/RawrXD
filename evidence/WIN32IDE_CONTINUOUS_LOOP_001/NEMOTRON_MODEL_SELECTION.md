# Nemotron model selection (authoritative)

```
ASOF_UTC=2026-10-28T13:40:00Z
PROMOTE=0 CERTIFIED=0
NO_CLOUD_SUBSTITUTE=1
```

## “All three” = installed local Ollama tags

| # | Tag | Role |
|---|-----|------|
| 1 | `nemotron-3-nano:4b` | Local Nemotron Nano |
| 2 | `nemotron-3.5-bolt:latest` | Local Nemotron Bolt |
| 3 | `nemotron-3.5-lightning:30b` | Local Nemotron Lightning |

**Not** NVIDIA Super/Ultra cloud SKUs unless those exact tags appear in `ollama list`.

## GhostText matrix (+ Flint)

Also required under `RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001`:

| Tag | Agentic edit | GhostText |
|-----|--------------|-----------|
| nemotron-3-nano:4b | CLI witness may exist — independent of GhostText | PENDING |
| nemotron-3.5-bolt:latest | same | PENDING |
| nemotron-3.5-lightning:30b | same | PENDING |
| flint:latest | PENDING | PENDING |

`AGENTIC_EDIT_PASS ≠ GHOSTTEXT_PASS`. Tab/Esc/stale-cancel/model-switch required for GhostText.
