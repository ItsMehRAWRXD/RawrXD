# Read-only feasibility audit

## Routing

`Win32IDE_GhostTextIntegration.cpp` contains an explicit routing decision:

- `FollowChat` uses `m_selectedChatModel`.
- `AutoLocal` uses `m_selectedChatModel` when it is an Ollama route.
- Otherwise it chooses the first available Ollama model.
- The emitted dispatch log records `route.identifier` and backend.

The candidate runtime emitted `bigdaddyg-productivity-local:latest`, while the physical run never established an explicit `qwen3:8b` selection. Therefore this is insufficient to call routing defective, and Qwen routing remains `NOT_VERIFIED`.

## A/B race

The GhostText controller has request identity, generation, and snapshot checks in `handleMessage()`. `dismiss()` increments generation and clears pending state. The prior cancellation run proved a late response is rejected. The current runtime surface does not expose a deterministic response-delay or callback-order control, so a true two-request reordered A/B race requires a dedicated test seam or controllable local transport.

No source change was made by this audit.
