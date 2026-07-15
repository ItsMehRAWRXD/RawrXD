# AVX-512 Intrinsics Compilation Guide

## Optimized Compiler Flags

### MSVC (Visual Studio 2022)

#### Essential Flags
```
/O2          - Maximum optimization (favor speed)
/arch:AVX512 - Enable AVX-512 instructions
/EHsc        - Exception handling (synchronous)
/W3          - Warning level 3
/D_CRT_SECURE_NO_WARNINGS - Disable CRT warnings
```

#### Performance Flags
```
/Oi          - Enable intrinsic functions
/GL          - Whole program optimization (Link Time Code Generation)
/favor:AMD64 - Optimize for AMD64 architecture (for Ryzen)
/Qvec-report:2 - Report vectorization (diagnostic)
```

#### Linker Flags
```
/LTCG        - Link-time code generation
/OPT:REF     - Remove unreferenced functions
/OPT:ICF     - Identical COMDAT folding
```

### Complete Build Command

#### Compile (with LTCG)
```powershell
cl /c /O2 /arch:AVX512 /EHsc /W3 /Oi /GL /D_CRT_SECURE_NO_WARNINGS `
   /Fobenchmark_avx512_intrinsics.obj `
   benchmark_avx512_intrinsics.cpp

cl /c /O2 /arch:AVX512 /EHsc /W3 /Oi /GL /D_CRT_SECURE_NO_WARNINGS `
   /Foaperture_q4_0_avx512_intrinsics.obj `
   aperture_q4_0_avx512_intrinsics.cpp

cl /c /O2 /arch:AVX512 /EHsc /W3 /Oi /GL /D_CRT_SECURE_NO_WARNINGS `
   /Foaperture_q8_0_avx512_intrinsics.obj `
   aperture_q8_0_avx512_intrinsics.cpp
```

#### Link (with LTCG)
```powershell
link /LTCG /OUT:Benchmark_AVX512.exe `
   benchmark_avx512_intrinsics.obj `
   aperture_q4_0_avx512_intrinsics.obj `
   aperture_q8_0_avx512_intrinsics.obj `
   aperture_cpu_features.obj `
   aperture_q4_0_reference.obj `
   kernel32.lib
```

## Code Optimization Tips

### 1. Use `__restrict` Pointers
```cpp
// Tells compiler pointers don't alias
void kernel(float* __restrict dest, const uint8_t* __restrict src);
```

### 2. Assume Alignment (when safe)
```cpp
// Tell compiler data is aligned for vmovaps
__assume_aligned(dest, 64);
__assume_aligned(src, 64);
```

### 3. Loop Unrolling Hints
```cpp
#pragma unroll  // Let compiler decide
// or
#pragma unroll 8 // Force 8x unroll
```

### 4. Avoid Spills
- Keep temporary variables minimal
- Reuse registers where possible
- Check assembly output for `mov` to stack

### 5. Prefetching (if needed)
```cpp
#include <immintrin.h>
_mm_prefetch((const char*)(src + 64), _MM_HINT_T0);
```

## Verification Checklist

Before benchmarking:
- [ ] Compile with `/O2 /arch:AVX512 /Oi /GL`
- [ ] Link with `/LTCG`
- [ ] Verify AVX-512 detected at runtime
- [ ] Run unit tests (bitwise compare with reference)
- [ ] Check for stack spills in assembly output

## Expected Performance

| Format | Target | Minimum | Notes |
|--------|--------|---------|-------|
| Q4_0 | 200M weights/sec | 150M | With alignment optimizations |
| Q8_0 | 300M weights/sec | 200M | Simpler than Q4_0 |

## Troubleshooting

### Low Performance
1. Check for `vmovups` vs `vmovaps` in disassembly
2. Look for unnecessary `vzeroupper` instructions
3. Verify no stack spills (look for `[rsp+...]`)

### Compilation Errors
- Ensure `/arch:AVX512` is set
- Check Windows SDK version (need 10.0.22621.0+)
- Verify MSVC version (need 14.50+)

### Runtime Errors
- Verify CPU supports AVX-512F, AVX-512BW, AVX-512VL
- Check Windows version (Windows 10/11)
- Ensure proper exception handling (`/EHsc`)
