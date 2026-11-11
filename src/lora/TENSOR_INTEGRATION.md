# Tensor Integration - Pure x64 MASM Implementation

## Overview

This implementation provides a complete tensor abstraction and transformer layer integration for the cache-blocked GEMM kernel, written entirely in pure x64 MASM with zero dependencies.

## Files Created

### 1. TensorContext.asm
**Purpose:** Zero-overhead tensor abstraction and arena allocator

**Key Components:**
- `Arena` struct: Bump-pointer allocator for gigabyte-scale weights
- `Tensor` struct: 64-byte cache-line aligned tensor metadata
- `Arena_Init`: Initialize arena with VirtualAlloc (avoids heap fragmentation)
- `Arena_Alloc`: O(1) aligned allocation
- `Arena_Reset`: Reset arena for reuse
- `Arena_Free`: Release arena memory
- `Tensor_Init`: Initialize tensor from existing memory
- `Tensor_Alloc`: Allocate tensor from arena
- `Tensor_GetElement`: Get pointer to element at indices
- `Tensor_Zero`: Zero out tensor data using AVX

**Design Goals:**
- Zero heap fragmentation (arena allocation)
- 32-byte alignment guarantee for AVX operations
- L2 cache blocking preservation
- Minimal overhead (struct is just metadata)

### 2. QKVProjection.asm
**Purpose:** Transformer QKV and FFN layer projections

**Key Components:**
- `Forward_QKV`: Project input into Query, Key, Value matrices
- `Forward_QKV_Packed`: Optimized version with pre-packed weights
- `PackWeightMatrix`: Pre-pack weights for efficient inference
- `FFN_Layer`: Feed-Forward Network layer (up/down projection with GELU)
- `GELU_InPlace_ASM`: Approximate GELU activation using AVX

**Architecture:**
```
Q = Input × Wq  [seq_len, d_model] × [d_model, d_model]
K = Input × Wk  [seq_len, d_model] × [d_model, d_model]
V = Input × Wv  [seq_len, d_model] × [d_model, d_model]
```

### 3. TensorBridge.hpp
**Purpose:** C++ bridge for MASM tensor operations

**Key Components:**
- C declarations for all MASM functions
- `BlockedGemm_Single`: C++ wrapper for cache-blocked GEMM
- `PackBPanel_ASM` / `PackAPanel_ASM`: ASM-callable packing functions
- `TensorArena` C++ wrapper class
- `TensorView` C++ wrapper class

### 4. build_tensor_standalone.bat
**Purpose:** Build script for standalone tensor test

**Build Steps:**
1. Assemble TensorContext.asm
2. Compile test_tensor_standalone.cpp
3. Link into executable

### 5. test_tensor_standalone.cpp
**Purpose:** Test harness for tensor abstraction

**Test Cases:**
1. Arena Allocator - allocation, alignment, reset
2. Tensor Initialization - 2D tensor setup
3. Tensor Zero - AVX zeroing
4. Tensor 3D - 3D tensor strides
5. Arena Tensor Allocation - ownership flags

## Integration with GEMM Kernel

The tensor abstraction integrates with the existing GEMM kernel:

```cpp
// Example: QKV projection using tensor abstraction
TensorArena arena(1 << 30); // 1GB arena

// Allocate tensors from arena
Tensor input, Wq, Q_out;
Tensor_Alloc(&input, &arena, seq_len, d_model);
Tensor_Alloc(&Wq, &arena, d_model, d_model);
Tensor_Alloc(&Q_out, &arena, seq_len, d_model);

// Initialize with data
// ... load weights and input ...

// Forward pass
Forward_QKV(
    input.data, Wq.data, Wk.data, Wv.data,
    Q_out.data, K_out.data, V_out.data,
    seq_len, d_model
);
```

## Performance Characteristics

### Arena Allocator
- **Allocation:** O(1) - single pointer bump
- **Alignment:** Guaranteed 32-byte for AVX
- **Fragmentation:** Zero - contiguous allocation
- **Reset:** O(1) - pointer reset only

### Tensor Operations
- **Initialization:** O(1) - metadata only
- **Element Access:** O(1) - stride calculation
- **Zeroing:** O(n) - AVX-optimized

### QKV Projection
- **Compute:** Uses cache-blocked GEMM (MC=128, KC=256, NC=128)
- **Memory:** Arena-allocated, L2 cache friendly
- **Throughput:** 38-58 GFLOPS (from previous benchmarks)

## Windows x64 ABI Compliance

All functions follow the Windows x64 calling convention:
- **Volatile:** RAX, RCX, RDX, R8, R9, R10, R11, XMM0-XMM5
- **Non-volatile:** RBX, RBP, RSI, RDI, R12-R15, XMM6-XMM15
- **Stack:** 32-byte shadow space for called functions
- **Alignment:** 16-byte stack alignment at entry

## Next Steps

1. **Build and Test:** Run `build_tensor_standalone.bat` to validate the tensor abstraction
2. **Integration:** Wire into transformer execution graph
3. **Benchmark:** Measure QKV projection throughput
4. **Optimize:** Profile and optimize hot paths

## Memory Layout

### Arena Structure (64 bytes)
```
+0x00: base      (8 bytes) - Base pointer
+0x08: current   (8 bytes) - Current allocation pointer
+0x10: capacity  (8 bytes) - Total capacity
+0x18: allocated (8 bytes) - Bytes allocated
+0x20: _reserved (32 bytes) - Future use
```

### Tensor Structure (64 bytes)
```
+0x00: dims[4]    (32 bytes) - Dimensions [d0, d1, d2, d3]
+0x20: strides[4] (32 bytes) - Strides in elements
+0x40: data       (8 bytes)  - Pointer to float data
+0x48: elem_count (8 bytes)  - Total element count
+0x50: flags      (4 bytes)  - Ownership/alignment flags
+0x54: dtype      (4 bytes)  - Data type enum
+0x58: _padding   (16 bytes) - Pad to 64 bytes
```

## Constants

```asm
TENSOR_MAX_DIMS      equ 4
TENSOR_ALIGNMENT     equ 32      ; AVX alignment
ARENA_DEFAULT_SIZE   equ 1073741824  ; 1GB default arena
CACHE_LINE_SIZE      equ 64

TENSOR_FLAG_NONE     equ 00000000h
TENSOR_FLAG_OWNED    equ 00000001h   ; Arena owns the memory
TENSOR_FLAG_ALIGNED  equ 00000002h   ; 32-byte aligned
TENSOR_FLAG_CONTIGUOUS equ 00000004h ; Contiguous memory
```

## Usage Example

```cpp
#include "TensorBridge.hpp"

int main() {
    using namespace RawrXD;
    
    // Create arena for weight storage
    TensorArena arena(2LL * 1024 * 1024 * 1024); // 2GB
    
    // Allocate tensors
    TensorView input, Wq, Q_out;
    Tensor_Alloc(&input.tensor, &arena.arena, 512, 4096);  // 512 tokens, 4096 dim
    Tensor_Alloc(&Wq.tensor, &arena.arena, 4096, 4096);     // d_model × d_model
    Tensor_Alloc(&Q_out.tensor, &arena.arena, 512, 4096);  // Output
    
    // Load weights and input data...
    
    // Forward pass
    Forward_QKV_Simple(
        input.data(), Wq.data(), Wk.data(), Wv.data(),
        Q_out.data(), K_out.data(), V_out.data(),
        512, 4096
    );
    
    return 0;
}
```

## Build Requirements

- **MASM:** ml64.exe (Visual Studio 2022 BuildTools)
- **C++ Compiler:** cl.exe (Visual Studio 2022 BuildTools)
- **Linker:** link.exe (Visual Studio 2022 BuildTools)
- **Libraries:** kernel32.lib (Windows API)

## License

Part of the RawrXD project - pure x64 MASM implementation with no dependencies.