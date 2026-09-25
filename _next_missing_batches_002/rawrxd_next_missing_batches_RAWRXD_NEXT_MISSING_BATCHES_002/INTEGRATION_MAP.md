# Integration map

## Special graph

Wire `Deep2::SpecialGraph::execute()` to the existing Deep2 operation authority. The callback receives an ordered `Node` with `op` and `layer`; translate that to the existing CPU/Vulkan forward operations. Do not implement tensor kernels inside the graph layer.

DeepSeek V4 must populate `RuntimeMeta` from admitted GGUF/runtime metadata before `build()`. A graph with unknown layer/expert geometry is intentionally invalid.

## Dual-GPU agents

Create one Deep2 context per binding and pass explicit Vulkan ordinals. Context pointers must be distinct. The second GPU may fail cleanly when `requireSecondary=false`, but the strict dual-agent certification should use `requireSecondary=true`.

## HexMag

Bind `ResidencyCallbacks` to the existing weight residency manager. The E2E certification sequence should force:

```text
prefetch A/B -> touch B -> budget trim evicts A -> request A -> reload A -> use A
```

and require `RELOAD_BYTES>0`.

## ScreenPilot

Instantiate one `ScreenPilotToolAuthorityBridge` with the same `AgentToolRegistry` used by IDE/CLI/headless agent paths. The ScreenPilot coordinator should use this bridge for every model-originated tool operation. No filesystem/process/Git fallback is allowed around the bridge.

## Multi-agent merge

Use `MultiAgentMergeAuthority` after the reviewer produces edits. It reads the current file through authority, checks the base fingerprint, rejects overlap/staleness, and writes through authority only when deterministic merge is safe.

## Release

`certify_clean_clone_release.ps1` is the final fresh-clone gate. Keep it separate from source/selftests so an existing dirty build directory cannot satisfy release acceptance.
