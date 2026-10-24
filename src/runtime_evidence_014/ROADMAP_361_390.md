# RAWRXD IDE completion — Moves 361–390

All items are **PENDING** until independently evidenced. Prior native Win32 build/start and Q2_K finite-FFN results remain separate user-reported progress, not proof for these gates.

## Acceptance-gated execution order

### 361 — Q2_K complete generation
- **Action and PASS proof:** Run a real completed decode and capture generated tokens, exit status, model/shader hashes and generation log.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 362 — Full-model CPU/GPU parity
- **Action and PASS proof:** Compare token sequence and layer outputs on identical prompt, seed and sampling; record tolerance.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 363 — GPU forward dispatch proof
- **Action and PASS proof:** Capture nonzero real Vulkan forward/layer counters and zero strict violations.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 364 — GPU decode TPS measurement
- **Action and PASS proof:** Record prefill separately from decode with prompt tokens, generated tokens, GPU/CPU devices and timings.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 365 — 150 TPS acceptance trial
- **Action and PASS proof:** Run reproducible representative model workloads; report per-model TPS and pass only the explicitly scoped target.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 366 — Q2_K regression matrix
- **Action and PASS proof:** Test quantized models, batch sizes, context lengths, multiple seeds and outlier tensors.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 367 — Nemotron SSM NaN closure
- **Action and PASS proof:** First bad tensor tracing, Q4_K/Q8_0 model kernels, verify fully finite token generation.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 368 — Phi-3 Vulkan crash closure
- **Action and PASS proof:** Resolve production layer-0 access violation and prove repeatable clean runs.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 369 — Device loss and cancellation
- **Action and PASS proof:** Exercise GPU loss, queue timeout, model cancellation, resource cleanup and recovery.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 370 — Dual-GPU correctness and scheduling
- **Action and PASS proof:** Test both GPUs with real layer work and parity versus single GPU; isolate synchronization waits.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 371 — GUI edit/save/reopen E2E
- **Action and PASS proof:** Real Win32 controls: type, undo, redo, save, close and reopen; byte-equal contents.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 372 — Problems panel → editor activation
- **Action and PASS proof:** Trigger real MSVC error and click Problems row; verify file, line and column.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 373 — Debugger lifecycle
- **Action and PASS proof:** Launch/attach, breakpoint, step, watch, continue, stop, detach and cleanup.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 374 — PowerShell termination
- **Action and PASS proof:** Run output-heavy commands, timeout, cancel and assert no descendants remain.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 375 — Native multi-tab workspace recovery
- **Action and PASS proof:** Reopen prior project/tabs/caret locations after normal close and crash restart.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 376 — WebView2 startup and navigation
- **Action and PASS proof:** Render localhost UI, await readiness, navigate and validate meaningful interaction.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 377 — GhostText suggestion acceptance
- **Action and PASS proof:** Exercise live completion provider, surface, accept, reject, cancellation and editor undo.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 378 — VSIX extension activation
- **Action and PASS proof:** Load representative extension, route command, isolate crashes and enforce trust.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 379 — LSP project language services
- **Action and PASS proof:** Verify definition, references, rename, completion and diagnostics on real workspace.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 380 — Git and snapshots UI
- **Action and PASS proof:** Perform safe status/diff/stage/commit and snapshot restore against protected fixture.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 381 — Autonomous edit-build-test
- **Action and PASS proof:** Authorize specific workspace operations; require traceable edit, build and test result.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 382 — Agent failed-test rollback
- **Action and PASS proof:** Deliberately fail a regression test and verify exact original file hashes on rollback.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 383 — Ollama + Deep2 concurrency
- **Action and PASS proof:** Serve both simultaneously with explicit provenance and independent ports/cancellation.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 384 — Multi-model resource admission
- **Action and PASS proof:** Reject oversized context/VRAM commitments and verify CPU/GPU quotas and OOM recovery.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 385 — Native compiler and linker IDE hookup
- **Action and PASS proof:** Build native C/C++ fixture with real diagnostics, run target and debug symbols.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 386 — Extension command → native build
- **Action and PASS proof:** Invoke native compiler from approved extension command and verify UI output.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 387 — Signing and packaging UI
- **Action and PASS proof:** Enforce certificate/profile policy and verify only authorized signing attempts.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 388 — Qt-free clean Win32 release
- **Action and PASS proof:** Configure clean MSVC x64 host release with no Qt dependency and capture full log.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 389 — IDE GUI and runtime soak
- **Action and PASS proof:** Repeated project open/close, edits, inference, terminal, debugger and resource leak checks.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.

### 390 — Independent full IDE acceptance
- **Action and PASS proof:** Aggregate signed/attributed per-gate receipts, no NOT_RUN gates, source revision and reproducibility.
- **FAIL/BLOCKED:** Absence of execution trace, altered test fixture, unverified hardware outcome, unhandled crash, or missing reproducibility data.
- **Integration target:** Existing Win32 IDE, Deep2 runtime, or native build/signing service as applicable. Do not replace functioning repository code.
