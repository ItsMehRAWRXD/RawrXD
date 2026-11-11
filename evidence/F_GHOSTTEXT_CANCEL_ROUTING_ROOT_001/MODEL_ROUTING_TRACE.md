# Model routing trace

The physical UI displayed the main model as `qwen3:8b` and GhostText as `Auto Local`. The candidate runtime log emitted:

`GhostText inference route: bigdaddyg-productivity-local:latest backend=ollama`

The working-tree source now contains an Auto Local branch that follows `m_selectedChatModel` for Ollama routes. Because the tested executable SHA predates or does not contain that source behavior, this is a binary/source provenance mismatch, not yet a proven current-source routing failure.
