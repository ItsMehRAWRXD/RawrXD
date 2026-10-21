# RawrXD Sovereign Engine Pipeline Blocker Ledger
## Component: Native CLI and Architecture-Aware Executor Graph
## Status: STRICTLY FAIL-CLOSED (Awaiting Full-Model Parity Closure)

| ID | Component | Severity | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **ERR-CLI-001** | CLI Core Parser | Blocking | Missing `rawr run <model> "<prompt>"` multi-token loop orchestration framework. | IMPLEMENTED — runtime certification pending |
| **ERR-ARC-002** | Arch Registry | Blocking | `ModelArch::LLAMA` missing multi-token state bounds validation and explicit GQA 24:8 mappings. | Wired to Executor |
| **ERR-VLD-003** | End-to-End Loop | Warning | Stream context tracking requires unified tracking for explicit EOS (`<|end_of_text|>`). | Resolved |
| **ERR-VUK-004** | Vulkan Sync | Deferred | Driver-level fence overhead (552 dispatches/token) remains active under Phase 5. | Paused (As Instructed) |
| **ERR-MOE-005** | Expert Registry | Fail-Closed | MoE (`Qwen4Exp` PLE/GDN) and SSM operators remain blocked from full system certification. | Guarded |

## 2026-10-20 execution note

The native CLI now resolves local GGUF/Ollama aliases through the existing
`RawrModelAlias` resolver, accepts a quoted second positional as a one-shot
prompt, and streams Deep2 token callbacks to stdout. These changes are built
but require a local certified Llama 3.2 Q2_K artifact for the end-to-end
receipt. No certification status is changed by the CLI build alone.
