# RawrXD N-EVM v0.2 Architecture Document
## Neural Execution Virtual Machine - Corrected Design

---

## Executive Summary

**N-EVM is not a quantizer. It is a neural execution layer.**

The model is no longer treated as a tensor file. It becomes an **executable neural ROM image** running inside a custom console.

---

## 1. The ROM Emulator Model

### Old Pipeline (Wrong)
```
GGUF
 |
 v
offline quantizer
 |
 v
Q4/Q8/Nano
 |
 v
runtime
```

### New Pipeline (Correct)
```
GGUF / safetensors / raw blob
              |
              v
       N-EVM Loader
              |
              v
    Virtual Tensor Address Space
              |
              v
 Dynamic Execution Codec
              |
              v
     Kernel Dispatcher
              |
              v
  AVX512 / AMX / Vulkan / ROCm
```

**Key Insight:** GGUF does not need to be modified. The VM exposes a virtual tensor ABI:

```cpp
virtual_weight_ptr(layer, tensor, block)
```

The kernel thinks it is reading weights. The VM decides whether that means:
- Direct mmap
- Q4 decode
- Q8 decode
- nano decode
- latent reconstruction
- streamed block
- cached expansion

**The model format becomes irrelevant.**

---

## 2. Nano Quant is a Backend, Not a Replacement

```
             GGUF
              |
       Tensor Virtualizer
              |
    +---------+---------+
    |         |         |
   FP16      Q4       NANO
    |         |         |
 Direct    Decode    Generate
```

**The winning move:** "Run anything."

```
DeepSeek.gguf
Llama.gguf
Mixtral.gguf
Custom blob
```

All become: **N-EVM virtual machine image**

---

## 3. Multi-State Representation (The "Quantum" Analogy)

A weight block does not have one representation. It has **possible representations**:

```
Tensor Block 4321

State 0: binary approximation     (0.5-bit)
State 1: 2-bit codebook            (1.0-bit)
State 2: Q4                        (2.0-bit)
State 3: FP16 residual             (8.0-bit)
State 4: original mmap             (16.0-bit)
```

The runtime chooses based on:
```
Score = Latency + Memory + Behavior Error
```

The tensor is not compressed. It is **represented in multiple states.**

---

## 4. Neural MMU

### CPU MMU:
```
Virtual Address
      |
      v
    MMU
      |
      v
Physical RAM
```

### N-EVM Neural MMU:
```
Virtual Tensor Address
          |
          v
     Neural MMU
          |
 +--------+---------+
 |        |         |
VRAM    RAM     Compressed ROM
```

**Example:**

Kernel requests: `W[Layer17][4096:8192]`

Neural MMU decides:
- Current token: attention critical → expand FP16 block
- Future token: FFN expert inactive → keep nano compressed

---

## 5. Medusa/Speculative Decoding as Control Loop

Most quantization systems are blind:
```
compress once
    |
    v
   hope
```

N-EVM:
```
Speculative heads
        |
        v
Acceptance telemetry
        |
        v
Precision controller
        |
        v
Tensor representation selection
```

**Example:**

| Scenario | Acceptance | Action |
|----------|-----------|--------|
| "The capital of France is" | 99% | Lower precision allowed |
| Medical reasoning token | 62% | Upgrade active tensors |

---

## 6. Corrected Compression Claim

**Do not claim:** `376GB → 22GB` as guaranteed.

**Correct architecture claim:**

```
376GB source entropy
        |
        v
adaptive representation
        |
        v
runtime working set: 10-40GB typical
```

The VM only materializes the information required for the current computation.

---

## 7. N-EVM Instruction Set

```
NLOAD tensor, block          ; Load tensor block
NDECODE mode                 ; Decode block
NMATMUL tensor, activation   ; Matrix multiply
NVERIFY candidate            ; Verify speculative result
NPROMOTE precision           ; Upgrade precision
NEVICT tensor                ; Evict to lower tier
```

**Example:**
```
NLOAD W17.FFN
NPRECISION AUTO
NMATMUL
NVERIFY
if error:
    NPROMOTE
    retry
```

The model becomes **executable**.

---

## 8. MASM/x64 Advantage

```
Windows
 |
RawrXD N-EVM
 |
MASM kernels
 |
AVX2/AVX512/VNNI
 |
VRAM DMA
```

**No:**
- Python
- CUDA dependency
- Framework runtime
- Vendor lock

**The VM owns the execution path.**

---

## 9. N-EVM v0.2 Engineering Milestone

### Required Components:

| # | Component | Status |
|---|-----------|--------|
| 1 | GGUF passthrough loader | ✅ Implemented |
| 2 | Virtual tensor address space | ✅ Implemented |
| 3 | Block-level decode interface | ✅ Implemented |
| 4 | Precision controller | ✅ Implemented |
| 5 | Medusa feedback hook | ✅ Implemented |
| 6 | Cache residency policy | ✅ Implemented |

### Usage:

```cpp
llama.gguf
        |
        v
RawrXD_N-EVM.exe
        |
        v
     tokens
```

**Without conversion.**

---

## 10. File Structure

```
src/nevm/
├── nevm_core.hpp/cpp              # Core VM (legacy v0.1)
├── nevm_isa.hpp                   # Instruction set architecture
├── nevm_mmu.hpp/cpp               # Neural MMU
├── nevm_precision_controller.hpp/cpp  # Telemetry-driven precision
├── nevm_gguf_loader.hpp           # GGUF passthrough
├── nevm_v2.hpp                    # N-EVM v0.2 complete system
├── nevm_nano_format.hpp/cpp       # Nano backend (optional)
├── nevm_components.hpp            # Supporting components
├── NanoMatMul_LUT2.asm            # 2-bit kernel
├── NanoMatMul_XNOR.asm            # 1-bit kernel
├── Q4_Dequantize.asm              # Q4 kernel
└── Q8_Dequantize.asm              # Q8 kernel
```

---

## 11. Key Design Principles

1. **GGUF is source, not target** - Never modify GGUF
2. **Virtual tensors** - Kernels see virtual addresses
3. **Multi-state blocks** - Same data, multiple representations
4. **Telemetry-driven** - Precision from behavior, not static analysis
5. **Dependency-free** - MASM/x64, no CUDA/Python/frameworks
6. **ROM emulator** - Model is executable, not data

---

## 12. The Breakthrough Point

```
llama.gguf
        |
        v
RawrXD_N-EVM.exe
        |
        v
     tokens
```

**Without conversion.**

The "nano quant engine" becomes not a quantizer, but a **neural execution layer** that can make any existing model behave like a cartridge running inside a custom console.

---

## Implementation Status

| Component | Lines | Status |
|-----------|-------|--------|
| ISA | 200 | ✅ Complete |
| Neural MMU | 400 | ✅ Complete |
| Precision Controller | 500 | ✅ Complete |
| GGUF Loader | 300 | ✅ Complete |
| N-EVM v0.2 System | 200 | ✅ Complete |
| ASM Kernels | 400 | ✅ Compiled |
| **Total** | **2000** | **✅ Ready** |

---

*RawrXD N-EVM v0.2 - The model is no longer data. It is executable.*
