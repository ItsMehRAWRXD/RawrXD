# Verdict

`CURRENT_BUILD_ROUTING=PASS`

`CURRENT_BUILD_CANCELLATION=PASS_SCOPE_TESTED`

`CURRENT_BUILD_STALE_RESPONSE_FENCE=PASS_SCOPE_TESTED`

`CURRENT_BUILD_B_RENDER=PASS_REBUILT_CANDIDATE`

`GATE_6=HELD`

The original production binary demonstrated the shared `m_inferenceRunning` busy-gate failure: a superseding GhostText request received an immediate empty unsuccessful completion instead of acquiring an independent inference slot. The rebuilt candidate removes that boundary for Ollama-routed requests while retaining controller-side generation and identity fencing.

## Rebuilt candidate physical reverify
- Binary: B527091A5E073AF817C94E73B17C8FFAE3BF42B0EFED04489C1FD441208AB7BE
- Explicit qwen3:8b route: PASS
- Real GhostText suggestion visible in the native editor: PASS
- Native editor focus and input: PASS
- Normal close requested: PASS
- Process exit after the physical run: PASS
- Full A/B lifecycle log extraction: INCOMPLETE; the rebuilt run produced real delivery evidence, but a clean debug-trace receipt proving B-before-A completion and stale-A rejection was not captured.
- Gate 6: PARTIAL, not certified.
