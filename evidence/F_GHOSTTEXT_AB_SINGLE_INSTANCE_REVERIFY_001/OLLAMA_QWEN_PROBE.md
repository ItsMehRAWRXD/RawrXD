# Independent Ollama Qwen probe

Executed outside the GUI candidate:

```text
ollama run qwen3:8b "Reply exactly RAWRXD_GHOSTTEXT_QWEN_ROUTE_PASS"
```

Observed:

```ini
MODEL=qwen3:8b
OLLAMA_EXIT=0
EXPECTED_MARKER=RAWRXD_GHOSTTEXT_QWEN_ROUTE_PASS
MARKER_OBSERVED=1
```

This proves the local Ollama model responds, but it does not certify GUI GhostText routing or inline rendering.
