# Minimal repair plan

Read-only recommendation; no repair was applied in this gate.

1. Add an Escape-entry trace including editor HWND, request ID, generation, pending state, and focus HWND.
2. Make the UI commit check request ID, generation, identity, snapshot, and an explicit cancelled flag immediately before rendering.
3. Ensure editor-change, Escape, detach, and model-switch invalidation all advance the same generation.
4. Rebuild a new candidate from the existing Auto Local routing source and verify the binary hash.
5. Physically rerun cancellation and a delayed two-request stale-response race.
