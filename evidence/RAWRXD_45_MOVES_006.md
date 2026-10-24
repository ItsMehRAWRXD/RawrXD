# RAWRXD 45-move Batch 006 — End-to-end IDE gap audit

**Source-based findings (not runtime certification):**
- Native GhostText source exists at `src/win32app/Win32IDE_GhostText.cpp`; legacy Qt overlay also exists.
- Existing LSP client `src/lsp_client.cpp` imports Qt JSON and QObject/QProcess. New native LSP framing is a dependency-free replacement for **framing only**; a complete Win32 process/JSON-RPC/LSP lifecycle is still missing.
- Native PowerShell source and panel exist, but output capture, cancellation, UI thread safety, and process lifetime are not yet certified.
- Snapshot source exists, but transaction restoration from the running agent IDE is not certified.
- Deep2 engine and REAP projection bridge source exist, but production invocation is not certified.
- Root CMake contains optional Qt configuration and native targets; 'Qt optional' is not 'Qt fully converted'.
- A GitHub Actions native CMake job is configured, but no passing job log has been observed.
- 25-product capability parity remains UNKNOWN, not 100%.

## 15 + 15 + 15 gate inventory

### Batch A: 01–15 — source and UI
01 source audit script [implemented]; 02 native GhostText [source found];
03 Qt GhostText [source found]; 04 native LSP frame codec [implemented];
05 native LSP framing test [implemented]; 06 LSP server process [pending];
07 LSP initialize handshake [pending]; 08 LSP diagnostics [pending];
09 LSP completion [pending]; 10 LSP navigation [pending];
11 PowerShell panel [source found]; 12 terminal lifecycle [pending];
13 browser surface [pending]; 14 debugger expression evaluation [pending];
15 native Win32 UI integration [pending].

### Batch B: 16–30 — agent, storage and model
16 snapshot engine [source found]; 17 snapshot restore [pending];
18 agent edit/build/test [previous evidence, live path pending];
19 rollback after failed build [pending]; 20 Deep2 engine [source found];
21 ROM projection bridge [source found]; 22 pre-top-k mask [source found];
23 model-index parity [pending]; 24 11-shard loader [pending];
25 historical 1.5-bit codec [pending]; 26 GPU packed kernels [pending];
27 Vulkan residency fences [pending]; 28 multi-token decode [pending];
29 semantic parity [pending]; 30 dual-GPU throughput [pending].

### Batch C: 31–45 — proof and packaging
31 Python stdlib source audit [implemented]; 32 machine-readable JSON report [implemented];
33 CI source audit step [configured]; 34 Linux compiler smoke [configured];
35 MSVC compiler smoke [configured]; 36 native CMake build [configured];
37 Windows IDE executable build [pending]; 38 executable launch smoke [pending];
39 IDE ↔ gateway smoke [pending]; 40 agent E2E test [pending];
41 debugger E2E test [pending]; 42 browser E2E test [pending];
43 Qt-free runtime dependency audit [pending]; 44 top-25 competitor evidence [pending];
45 release 100% completeness only on green gates [pending].

## Priority order
P0: Make GitHub Actions actually produce green build receipts; identify errors from logs.
P0: Wire and test the actual IDE launch, gateway, model, edit/build/test/rollback loop.
P1: Native LSP transport/process/JSON-RPC and completion/diagnostics.
P1: PowerShell process output and cancellation; GhostText physical accept/dismiss.
P1: Deep2 ROM native codec, router, projection and Vulkan numerical parity.
P2: Native browser/debugger/expression and extension parity.
P2: Competitor comparison with independent acceptance evidence.

**Important:** The GitHub connector exposes PR-triggered workflow-run lookup, but does not expose general workflow dispatch here. Workflow is configured to trigger on push; actual execution is not confirmed.
