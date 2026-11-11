# Next gate

Run a fresh isolated candidate test with an explicitly verified `qwen3:8b` GhostText route and a successful newer request B. The direct Ollama probe passes, but GUI selection-to-dispatch remains unverified. Require request B to render before the delayed request A returns, then require A to be rejected with `eligible=0`. Preserve the candidate SHA and production binary authority.
