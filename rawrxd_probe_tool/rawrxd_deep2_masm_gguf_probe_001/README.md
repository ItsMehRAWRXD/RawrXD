# RAWRXD_DEEP2_GGUF_EXECIMAGE_PROBE_001

Source-only x64 MASM drop-in for the **selected-GGUF -> generated model/system contract** stage of Deep2.

It is deliberately not a model-server wrapper and does not depend on Ollama, llama.cpp, a C/C++ runtime, ROCm, HIP, Vulkan SDK, JSON, HTTP, Python, or third-party libraries. At runtime it imports only Win32 `kernel32` file/mapping/output functions.

## What is implemented

`deep2_gguf_probe.exe <model.gguf>` performs these operations in one process:

1. Parses the selected path directly from the Win32 command line (no CRT argv).
2. Opens and memory-maps the GGUF.
3. Validates GGUF magic and v2/v3 header layout.
4. Parses every metadata KV, including recursive arrays and strings with bounds checks.
5. Captures `general.architecture` as a stable 64-bit FNV-1a identity hash.
6. Captures `general.alignment` when present; otherwise uses GGUF's conventional 32-byte default.
7. Parses every tensor info record, dimensions, GGML type and relative data offset.
8. Builds a quant/type usage bitmask from the actual tensor inventory.
9. Computes the aligned tensor-data start, absolute tensor offsets, and each tensor's physical storage span to the next tensor/EOF.
10. Emits causal **non-time** trace stamps: sequence, operation, object, classification, and structural values. The trace schema contains no timestamp.
11. Generates model-derived MASM headers.
12. Generates a non-model/system-use MASM header describing what this probe actually uses (file IO/mapping/static arenas) and does not use (network/heap/CRT/GPU).
13. Writes a relocation-safe binary `RXI1` execution-image manifest header plus tensor records. It contains no process pointers.
14. Writes the binary trace.

## Outputs

- `deep2_model_identity.inc`
- `deep2_model_tensors.inc`
- `deep2_model_quant.inc`
- `deep2_system_used.inc`
- `deep2_stamp_schema.inc`
- `deep2_execution_image.rxi`
- `deep2_probe.trace`

The tensor header intentionally uses stable numeric tensor IDs plus `NAME_HASH` rather than synthesizing MASM identifiers from arbitrary UTF-8 tensor names. This prevents invalid symbols and preserves deterministic identity.

## Build

Run from a Visual Studio x64 Native Tools prompt:

```bat
build.bat
```

Only `ml64.exe`, `link.exe`, and the Windows SDK import library for `kernel32` are needed at build time.

## Run

```bat
deep2_gguf_probe.exe "D:\rawrxd\gemma3-1b-Q2_K.gguf"
```

or use the included `run_gemma3.bat`.

Then:

```powershell
.\verify_outputs.ps1
```

## Scope / reality boundary

This drop fully implements the **model compiler front-end/provenance stage** described in the conversation: selected GGUF -> observe/attribute/verify/classify/format/stamp -> model and non-model headers -> RXI manifest.

It does **not** claim to contain GPU inference kernels, Vulkan dispatch, model forward execution, or model-semantic ablation. Those would require separate real implementations and are intentionally not represented by stubs or fake PASS receipts here.

## Stamp model

The trace does not store wall-clock time. Identity is causal/structural:

- monotonically increasing `Seq`
- `ParentSeq`
- `Kind`
- `Op`
- `ObjectId`
- `InputGen` / `OutputGen`
- two operation-specific structural values (`A`, `B`)
- flags
- classification

This is intended to become the provenance input for later Deep2 execution-stream reduction and NOP/ablation passes.
