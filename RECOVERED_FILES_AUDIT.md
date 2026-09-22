# Recovered Files Audit & Integration Plan
## Date: 2026-09-22
## Scope: 15 files extracted from D:\rawrxd history/runoff vs current F:\~dev\rawrxd\src\ tree

---

## CURRENT SOURCE STATUS (F:\~dev\rawrxd\src\)

### Real Implementations (do NOT overwrite)
| File | Status | Notes |
|------|--------|-------|
| `compiler_backend/InstructionEncoderX64.hpp/cpp` | ✅ REAL | Full x64 encoder with REX, ModRM, SIB, labels, fixups, MOV/LEA/PUSH/POP/ALU/IMUL/CMP/TEST/Shift/INC/DEC/CALL/JMP/JCC/RET |
| `compiler_backend/RawrCOFFWriter.hpp/cpp` | ✅ REAL | Full COFF64 writer: symbols, sections, relocations, string table, serialization |
| `compiler_backend/RawrPE64Linker.hpp/cpp` | ⚠️ REAL (partial) | PE64 header builder complete; **import/IAT emission incomplete** — `link()` builds headers but `.idata` section not appended to output |
| `sovereign/puppeteer/JITAssembler.hpp/cpp` | ⚠️ STUB | `emit()` is NOP placeholder; `finalize()` allocates memory but **does not resolve fixups**; missing `encodeInstruction` wiring to `InstructionEncoderX64` |

### Stubs (safe to replace with recovered versions if superior)
| File | Status | Notes |
|------|--------|-------|
| `agent/agentic_puppeteer.cpp` | ❌ STUB | `// STUB: src/agent/agentic_puppeteer.cpp` — 1 line |
| `agentic/GGUFLoader.cpp` | ❌ STUB | `// STUB: src/agentic/GGUFLoader.cpp` — 1 line |
| `gguf_loader.cpp` | ❌ STUB | `int main(){ return 0; }` — empty |

### Missing Entirely
| Component | Status | Notes |
|-----------|--------|-------|
| `agent_hot_patcher` | ❌ MISSING | No files anywhere in tree |
| `autonomous_model_manager` | ❌ MISSING | Only `FeatureRegistry::IsAutonomousModelManagerEnabled()` stub reference |
| `flash_attn_asm_fallback` | ❌ MISSING | No flash attention fallback in tree |
| `coff_reader` | ❌ MISSING | Writer exists; reader does NOT exist |
| `pe_writer` (C standalone) | ❌ MISSING | C++ linker exists; no standalone C writer |
| `masm_instruction_encoder` (C++ class) | ❌ MISSING | Different from `InstructionEncoderX64` |
| `masm_agentic_puppeteer.asm` | ❌ MISSING | Pure MASM version |
| `masm_masm_kernels.cpp` | ❌ MISSING | AVX2 runtime detection + dot product |

---

## AUDIT CLASSIFICATION

| # | Recovered File | Classification | Rationale | Integration Action |
|---|----------------|---------------|-----------|-------------------|
| 1 | `agent_hot_patcher.cpp/hpp` | **MISSING → NEWER** | No current implementation. Recovered file has real Qt-based hot patching with QJson, QUuid, hallucination detection hooks. | ✅ **INTEGRATE** → `src/agent/` |
| 2 | `agentic_puppeteer.cpp/hpp` | **STUB → NEWER** | Current `src/agent/agentic_puppeteer.cpp` is a 1-line stub. Recovered version has real Qt implementation with refusal/hallucination/format/infinite-loop detection, `CorrectionResult` struct, signal/slot pattern. | ✅ **INTEGRATE** → `src/agent/` (replace stub) |
| 3 | `autonomous_model_manager.cpp` | **MISSING → NEWER** | No current source. Recovered has model loading, compression provider selection (BRUTAL_GZIP/Deflate), adaptive settings. Qt-based. | ✅ **INTEGRATE** → `src/agent/` or `src/core/` |
| 4 | `local_gguf_loader.cpp/hpp` | **STUB → NEWER** | Current GGUF loader stubs exist (`agentic/GGUFLoader.cpp`, `gguf_loader.cpp`). Recovered version has full GGUF v3 parser with metadata, tensor info, file validation, streaming support. | ✅ **INTEGRATE** → `src/core/` (but audit overlap with `gguf_adapter.cpp` etc. first) |
| 5 | `flash_attn_asm_fallback.cpp` | **MISSING → NEWER** | No flash attention fallback in tree. Recovered has Q8_0 dequant + scalar fallback path. | ✅ **INTEGRATE** → `src/deep2/kernels/` |
| 6 | `masm_instruction_encoder.hpp` | **MISSING → PARTIAL** | Current `InstructionEncoderX64` is far superior (full IR-based, labels, fixups, 20+ instruction types). Recovered MASM encoder is a simpler string-mnemonic class (nop/mov/push/pop/ret/int/syscall/add/sub/xor/jmp/call). Useful as reference for MASM bridge but not a replacement. | 📁 **ARCHIVE** → `reference/masm/` |
| 7 | `masm_agentic_puppeteer.asm` | **MISSING → PARTIAL** | Pure MASM x64 implementation of puppeteer. Interesting for zero-dependency path but Qt C++ version is more practical for now. | 📁 **ARCHIVE** → `reference/masm/` |
| 8 | `masm_masm_kernels.cpp` | **MISSING → NEWER** | No current AVX2 runtime detection kernel. Has `dot_avx2`, `has_avx2()` with CPUID/XGETBV. Could complement existing deep2 kernels. | ✅ **INTEGRATE** → `src/deep2/kernels/` (audit overlap with `QuantKernelMASM.cpp`) |
| 9 | `coff_reader.c/h` | **MISSING → NEWER** | Current tree has `RawrCOFFWriter` (output) but NO reader (input). Recovered C reader parses headers, sections, symbols, relocations, string table. Needed for loading object files into JIT/linker. | ✅ **INTEGRATE** → `src/compiler_backend/` or `src/toolchain/` |
| 10 | `pe_writer.c/h` | **MISSING → PARTIAL** | Current `RawrPE64Linker.cpp` is the primary C++ linker. Recovered C version is a standalone reference implementation. Useful for cross-checking but C++ linker is the sovereign path. | 📁 **ARCHIVE** → `reference/toolchain/` |

---

## INTEGRATION PLAN

### Phase A: Immediate Integration (NEWER files)
```
src/
├── agent/
│   ├── agent_hot_patcher.hpp      ← recovered (NEW)
│   ├── agent_hot_patcher.cpp      ← recovered (NEW)
│   ├── agentic_puppeteer.hpp      ← recovered (replaces STUB)
│   └── agentic_puppeteer.cpp      ← recovered (replaces STUB)
├── core/
│   ├── autonomous_model_manager.h   ← recovered (NEW)
│   ├── autonomous_model_manager.cpp ← recovered (NEW)
│   ├── local_gguf_loader.hpp      ← recovered (NEW)
│   └── local_gguf_loader.cpp      ← recovered (NEW)
├── deep2/kernels/
│   └── flash_attn_asm_fallback.cpp ← recovered (NEW)
│   └── masm_kernels.cpp           ← recovered (NEW) [rename from masm_masm_kernels.cpp]
└── compiler_backend/
    ├── coff_reader.h              ← recovered (NEW)
    └── coff_reader.c              ← recovered (NEW)
```

### Phase B: Archive Reference Files (PARTIAL files)
```
reference/
├── masm/
│   ├── masm_instruction_encoder.hpp
│   └── masm_agentic_puppeteer.asm
└── toolchain/
    ├── pe_writer.c
    └── pe_writer.h
```

### Phase C: Sovereign Executable Closure (critical fixes)
1. **`RawrPE64Linker::link()`** — append `.idata` section to output; set data directory entry [1] = import table; compute `SizeOfCode`, `SizeOfInitializedData`
2. **`JITAssembler::emit()`** — wire to `InstructionEncoderX64::encode()`; append encoded bytes + record fixups
3. **`JITAssembler::finalize()`** — resolve `FixupKind::LabelRel32` / `LabelRel32_1` / etc. patches
4. **Unify relocation types** — ensure `Fixup` in `rawr_backend_types.hpp` covers both JIT internal labels and COFF/PE external symbols

---

## RISK ASSESSMENT

| Risk | Mitigation |
|------|-----------|
| Recovered files depend on Qt (QJson, QDebug, QThread, etc.) while current backend is mostly std:: | Integrate Qt-dependent files into agent/ layer only; keep compiler_backend/ Qt-free |
| `local_gguf_loader` may duplicate `gguf_adapter.cpp` functionality | Audit `gguf_adapter.cpp` before integration; merge or wrap |
| `coff_reader.c` is plain C, rest of backend is C++ | Wrap in `extern "C"` or provide C++ facade (`CoffReader.hpp`) |
| Recovered files from runoff may have outdated APIs | Compile-test each integrated file; fix API mismatches |

---

## CERTIFICATION TARGETS AFTER INTEGRATION

```
RAWRXD_NATIVE_EXECUTABLE_001
X64_ENCODER=PASS        (InstructionEncoderX64 already real)
RELOCATIONS=PASS        (COFF writer real; need JIT fixup resolution)
JIT=PASS                (wire emit→finalize)
COFF64=PASS             (RawrCOFFWriter real)
PE64_IMPORTS=PASS       (complete RawrPE64Linker::link() idata append)
PE64_LINKER=PASS        (end-to-end link() produces runnable .exe)
HELLO_EXE_RUN=PASS      (produce + run minimal executable)
EXTERNAL_COMPILER_USED=0
EXTERNAL_ASSEMBLER_USED=0
EXTERNAL_LINKER_USED=0
VERDICT=PASS
```
