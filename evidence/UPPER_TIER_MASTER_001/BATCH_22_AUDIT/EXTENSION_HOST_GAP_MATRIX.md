# EXTENSION_HOST_GAP_MATRIX — Batch 22 prep (READ-ONLY)

```
AUDIT=UPPER_TIER_MASTER_001/BATCH_22_AUDIT/EXTENSION_HOST_GAP_MATRIX
ASOF_UTC=2026-11-11T17:20:00Z
PRIMARY=F:\rawrxd
CROSS_CHECK=G:\~dev\rawrxd
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
NO_INVENT_PASS=1
```

Read-only inventory for Upper-Tier Batch 22 Extension Host prep. No product code edits. No runtime cells executed this audit.

## Tree delta (F vs G)

| Surface | F:\rawrxd | G:\~dev\rawrxd |
|---------|-----------|----------------|
| `ProductExtensionRuntime*` | **ABSENT** | Present (Api/Activate/Host/Manifest/Scan/Toggles) |
| `ExtensionHostWorker_main.cpp` | **ABSENT** | Present → intended `RawrXD-ExtensionHost.exe` |
| `ExtensionHost.cpp` | Minimal stub (Start/Stop/LoadExtension) | Full lifecycle + FEATURE_FICTION Activate fail-closed |
| `ExtensionAPI_VSCode*` / Sandbox / ManifestLoader | Present (partial) | Present + broader VSCodeAPIs / Discovery / Process |
| `extensions/**/package.json` | Not found (README only) | rawrxd-vscode, rawrxd-lsp-client, copilot-throttle, js/* |

Product `/api/extensions` authority for Batch 22 prep is the **G** cross-check (plus sealed candidate evidence). F alone cannot claim the product host path.

## Capability matrix

| capability | path (authority) | source_wired | runtime_reached | gaps (short) |
|------------|------------------|-------------:|----------------:|--------------|
| api_surface_vscode_compat_header | `ExtensionAPI_VSCode.h/.cpp`; `ExtensionHost_VSCodeAPIs.cpp` | 1 | 0 | Header claims “functional for real VS Code extensions”; ExecuteCommand/Register*/FireActivation/Dispatcher/SaveAll FEATURE_FICTION FAIL_CLOSED; no full vscode.* surface |
| manifest_package_json_parse | `ExtensionHost.cpp`; `ExtensionHost_Discovery.cpp`; `ProductExtensionRuntime_Manifest.cpp` | 1 | 0 | package.json parse wired on G; VSIX extract unsupported FAIL_CLOSED; F host LoadExtension stub; load-vsix NOT_RUN |
| activation_lifecycle | `ProductExtensionRuntime_Activate.cpp` + Host spawn; `ExtensionHost::ActivateExtension` | 1 | 0 | Spawn needs `RawrXD-ExtensionHost.exe`; worker is stop-event wait only (no `activate()`); recent `EXTENSIONHOST_REACHED=0` |
| process_isolation | `ExtensionHost_MASM_ProcessBroker.asm`; `ExtensionHostProcess.cpp`; product Host | 1 | 0 | MASM Job Object path exists; **product** spawn uses plain `CreateProcessA` without job; F missing worker/host |
| sandbox_permissions | `ExtensionSandboxManager.*`; `ExtensionSecurityCheck.cpp` | 1 | 0 | In-process allowlist fail-closed; not OS AppContainer; not consulted by product spawn; SecurityCheck FEATURE_FICTION |
| sample_extensions_inventory | `G:\~dev\rawrxd\extensions\*`; `plugins\hello_world` | 1 | 0 | Real package.json clients target `engines.vscode`; hello_world is plugin not VS Code host fixture; F has no package.json samples |
| vscode_compatibility_claims_vs_reality | headers + engines.vscode + MATRIX_* + G_EXTENSIONHOST_* | 1 | 0 | C++ façade ≠ Node `vscode` module; worker does not load `main`/call `activate`; MATRIX_002 ≠ tip promote |
| product_http_api_extensions_routes | `ProductExtensionRuntime_Api.cpp`; LocalServer / Headless routes | 1 | 0 | Routes SOURCE_WIRED on G; F absent; MATRIX_001 thin FAIL / MATRIX_002 candidate PASS held; this audit NOT_RUN |
| extension_host_worker_binary | `ExtensionHostWorker_main.cpp` | 1 | 0 | Placeholder wait loop; F absent; candidate EXE cited in evidence; tip absorb CERTIFIED=0 |
| ipc_bridge_and_command_dispatch | `ExtensionHostIpcBridge*`; `ExtensionInstance`; HandleExtensionCommand | 1 | 0 | IPC source present; Dispatch/ExecuteCommand FEATURE_FICTION; menu path ≠ proven leaf activate |

**Counts:** capabilities=10 · source_wired=10 · runtime_reached=0 · CERTIFIED=0 · PROMOTE=0

## Claims vs reality (VS Code)

| Claim | Reality (this inventory) |
|-------|--------------------------|
| “VS Code Extension API Compatibility” / “functional for real VS Code extensions” (`ExtensionAPI_VSCode.h`) | Partial C++ singletons (Workspace/Window/Commands/Languages/Environment). Many bridge methods FEATURE_FICTION FAIL_CLOSED. Not a drop-in `vscode` JS API. |
| `engines.vscode` in sample `package.json` | Declares marketplace VS Code engine range; does not prove RawrXD host can run those extensions. |
| Product host spawn + `host_pid` | Product path can spawn a placeholder EXE when present; worker does not execute extension `main` / `activate(context)`. |
| MATRIX_002 PASS=6/6 | Candidate-only (`TIP_CANDIDATE_AGENT_RUN_005`); `PROMOTE=0` `CERTIFIED=0`; **not** revalidated this audit; ≠ tip absorb. |
| Command menu → ExtensionHost | `G_EXTENSIONHOST_COMMAND_HANG_REPRO_001`: `EXTENSIONHOST_REACHED=0`. |

## Prior sealed evidence (cited, not re-run)

- `G:\~dev\rawrxd\evidence\EXTENSION_RUNTIME_MATRIX_001` — product_thin FAIL / isolation BLOCKED
- `G:\~dev\rawrxd\evidence\EXTENSION_RUNTIME_MATRIX_002` — candidate PASS=6/6; PROMOTE=0
- `G:\~dev\rawrxd\evidence\EXTENSIONHOST_CHILD_LAUNCH_ROOT_001` — historical thin-route / linkage root
- `G:\~dev\rawrxd\evidence\G_EXTENSIONHOST_COMMAND_HANG_REPRO_001` — EXTENSIONHOST_REACHED=0

## Batch 22 prep blockers

1. F missing `ProductExtensionRuntime` + `ExtensionHostWorker_main` (product path on G/candidate).
2. VS Code compatibility is header/engines claim — not a JS extension runtime with `activate()`.
3. Sandbox is allowlist metadata; product spawn is not Job-Object/AppContainer isolated.
4. Do not promote MATRIX_002 candidate PASS to tip CERTIFIED.
5. All runtime cells this audit: **NOT_RUN** (≠ PASS).

## Next executable gates (explicitly NOT_RUN here)

1. Tip-coherent build/deploy of `RawrXD-Win32IDE.exe` + side-by-side `RawrXD-ExtensionHost.exe`
2. Re-run EXT matrix on tip binary with `PROMOTE=0`
3. Decide: hold VS Code JS `activate(context)` as OPEN gap vs implement real script host
4. Decide F absorb of G product extension surface vs G-authority-only

Machine-readable twin: `EXTENSION_HOST_GAP_MATRIX.json`
