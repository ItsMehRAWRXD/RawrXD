# RawrXD Master Completion Plan

## Goal
Complete the remaining certification gates to transition RawrXD from a structurally sound build to a production-quality local IDE/runtime. Focus on runtime certification, GPU correctness, and end-to-end E2E paths.

## Constraints
- Fail-closed law: `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS` → `NOT_RUN != PASS`.
- Strict gates order: W8_HEADLESS_IDLE_LIFECYCLE_001 → RAWRXD_WIN32IDE_CHAT_E2E_001 → RAWRXD_GPU_CORRECTNESS_001.
- Current state: W8 lifecycle gate running; GPU correctness still open.
- **Updated state**: Real Win32IDE→Deep2 chat lane implemented; CLI flags implemented; sampling controls implemented; shutdown stability fixed; W8 harness fixed; model router implemented; Deep2 OpenAI server functional; strict source/link gates passed; stubs classified as dead source debt.

## Affected Boundaries
- RawrXD Win32IDE executable (`RawrXD-Win32IDE.exe`)
- Deep2 inference engine
- GPU/Vulkan runtime
- Win32 GUI IDE (chat panel, streaming, receipts)
- CLI automation (chat prompts, exit-on-done, max-tokens, greedy, seed)
- Certification receipts and evidence chain
- Headless lifecycle harness (`w8_long_duration_stability_gate.ps1`)

## Data Flow
1. W8 headless lifecycle → 30-minute stability receipt
2. Win32IDE chat E2E → prompt → Deep2 → streaming → render → receipt
3. GPU correctness → Vulkan init → model forward → logits → tokens → receipt

## Failure Modes
- W8 receipt not written or VERDICT=FAIL
- IDE chat E2E receipt not written or VERDICT=FAIL
- GPU correctness receipt not VERDICT=PASS
- Missing receipt fields (e.g., STREAMED_TOKEN_COUNT, RENDERED_CHAR_COUNT, GENERATED_TOKEN_COUNT)
- Silent fallback to stub/test-only backend
- Early crash or entry-point mismatch
- Missing model or GGUF file
- Incorrect CLI flag parsing or usage

## Validation Plan
- Verify W8 receipt written with EXIT=0, no crashes, no leaks, no early exits, PID tracking, memory plateau, timer accuracy.
- Verify IDE chat E2E receipt written with IDE_LAUNCH=PASS, CHAT_PANEL=PASS, CHAT_SEND=PASS, REQUEST_DISPATCH=PASS, DEEP2_REQUEST=PASS, FIRST_TOKEN=PASS, STREAM_RETURN=PASS, CHAT_RENDER=PASS, GENERATED_TOKEN_COUNT>=1.
- Verify GPU correctness receipt written with Vulkan init, model load, forward pass, logits finite, generated token, no fallback to stub/test-only backend.
- Verify no unresolved externals, no synthetic links, no silent source filters.
- Verify CLI flags `--chat-prompt`, `--chat-exit-on-done`, `--chat-max-tokens`, `--chat-greedy`, `--chat-seed` are parsed and wired to Deep2.

## Open Questions

### 1. W8 30-minute receipt status
- **Question**: Has the 30-minute lifecycle receipt been written? If not, what is the current receipt status and any errors?
- **Recommended answer**: Provide the contents of `F:\~dev\_w8_long_duration_receipt.txt` or confirm it does not exist. If it exists, state VERDICT and any failures. If it does not exist, confirm the W8 harness is still running and expected completion time.

---

## Tasks

### 1. Confirm W8 30-minute lifecycle receipt status
- **Action**: Check for `F:\~dev\_w8_long_duration_receipt.txt`.
- **Success Criteria**: Receipt exists with VERDICT=PASS, EXIT=0, no crashes, no leaks, no early exits, PID tracking, memory plateau, timer accuracy; or, if not yet written, confirm harness status and expected completion time.
- **Blocked By**: None.
- **Next**: If PASS, proceed to Step 2. If FAIL or not yet written, debug and rerun as needed.

### 2. Execute RAWRXD_WIN32IDE_CHAT_E2E_001
- **Action**: Launch RawrXD-Win32IDE.exe with model and CLI flags to exercise the chat E2E path.
  - Model: `F:\~dev\qwen2.5-coder-1.5b-base.gguf`
  - Flags: `--model "F:\~dev\qwen2.5-coder-1.5b-base.gguf" --chat-prompt "Reply READY only." --chat-exit-on-done --chat-max-tokens 8 --chat-greedy --chat-seed 1 --headless`
- **Success Criteria**: Receipt written at `F:\~dev\_win32ide_chat_e2e_receipt.txt` with all required fields and VERDICT=PASS.
- **Blocked By**: W8 receipt must be PASS.
- **Next**: If PASS, proceed to Step 3. If FAIL, debug and rerun.

### 3. Execute RAWRXD_GPU_CORRECTNESS_001
- **Action**: Launch RawrXD-Win32IDE.exe with Vulkan init and model forward to exercise GPU correctness.
  - Model: `F:\~dev\qwen2.5-coder-1.5b-base.gguf`
  - Flags: `--model "F:\~dev\qwen2.5-coder-1.5b-base.gguf" --gpu-force-adapter "R9700" --gpu-disable-fallback --headless`
- **Success Criteria**: Receipt written at `F:\~dev\_gpu_correctness_receipt.txt` with Vulkan init, model load, forward pass, logits finite, generated token, no fallback to stub/test-only backend, VERDICT=PASS.
- **Blocked By**: W8 receipt must be PASS.
- **Next**: If PASS, proceed to Step 4. If FAIL, debug and rerun.

### 4. Final Product Certification Receipt
- **Action**: Aggregate all receipts into a final product certification receipt at `F:\~dev\_rawrxd_product_cert_001_receipt.txt`.
- **Success Criteria**: Receipt contains all required fields and VERDICT=PASS.
- **Blocked By**: All prior receipts must be PASS.
- **Next**: If PASS, mark RAWRXD_PRODUCT_CERT_001=PASS and close the plan.

### 5. Stub Elimination (Post-Certification Cleanup)
- **Action**: Inventory remaining `// STUB:` translation units referenced in CMakeLists.txt and either delete, replace, or implement them.
- **Success Criteria**: No production stubs remain in CMakeLists.txt.
- **Blocked By**: Product certification must be PASS.
- **Next**: After cleanup, verify build and link still pass.

## Rollback/Migration
- If any gate fails, debug and rerun the specific gate without affecting other gates.
- If W8 fails, do not proceed to chat E2E or GPU correctness.
- If chat E2E fails, do not proceed to GPU correctness.

---

**Plan Status**: Implementation-ready.

**Saved Plan Path**: `F:\~dev\.kilo\plans\1790689678163-rawrxd-master-completion-plan.md`