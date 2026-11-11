# Next gate

Run a dedicated delayed-response A/B harness that creates two real overlapping GhostText requests and forces response B to arrive before A. Require A to be rejected by request identity, generation, and snapshot checks while B alone may render. Separately select a known Qwen route and verify the emitted Ollama route matches it.
