# RawrXD Kernel Tagging Guide

## Quick Start

Tag your completed kernels with `KERNEL_COMPLETE:` comments. This enables automatic inventory generation.

## Tagging Format

### C++ Kernels

```cpp
// KERNEL_COMPLETE: AVX2_Gemm_F32_F32
void AVX2_Gemm_F32_F32(const float* A, const float* B, float* C, 
                       int M, int N, int K) {
    // Implementation
}
```

### MASM Kernels

```asm
; KERNEL_COMPLETE: FlashAttention_AVX512
FlashAttention_AVX512 PROC
    ; Implementation
FlashAttention_AVX512 ENDP
```

### Header Files

```cpp
// KERNEL_COMPLETE: TransformerLayer_Fused
class TransformerLayer_Fused {
    // Implementation
};
```

## Category Auto-Detection

The scanner automatically categorizes kernels based on name patterns:

| Pattern | Category |
|---------|----------|
| `*Gemm*`, `*MatMul*` | GEMM |
| `*Attention*`, `*Attn*` | Attention |
| `*RMSNorm*`, `*Norm*` | RMSNorm |
| `*Softmax*` | Softmax |
| `*DMA*`, `*SDMA*` | DMA |
| `*NF4*`, `*Quant*`, `*Q4*`, `*Q8*` | Quantization |
| `*Medusa*`, `*Speculative*` | Speculative |
| `*Flash*` | FlashAttention |
| `*KV*` | KVCache |
| `*SiLU*`, `*Activation*` | Activation |
| `*RoPE*` | RoPE |

## File Type Detection

| Extension | Type | Language |
|-----------|------|----------|
| `.asm` | MASM | MASM64 |
| `.cpp`, `.hpp`, `.h` | C++ | C++17 |
| `.comp`, `.glsl` | Vulkan | GLSL |
| `.spv` | Vulkan | SPIR-V |

## Generating the Inventory

### Using PowerShell Script

```powershell
# Scan for completed kernels
.\tools\kernel_inventory.ps1

# Scan all files (including potential kernels)
.\tools\kernel_inventory.ps1 -ScanAll

# Generate tag snippets for untagged files
.\tools\kernel_inventory.ps1 -GenerateTags
```

### Using C++ Tool

```bash
# Compile the tool
g++ -std=c++17 -O2 tools/kernel_index.cpp -o tools/kernel_index.exe

# Run with default paths
tools\kernel_index.exe

# Run with custom paths
tools\kernel_index.exe d:\rawrxd d:\rawrxd\KERNEL_INVENTORY.md
```

## Example Output

```markdown
# RawrXD Kernel Inventory

**Generated:** 2026-07-09 14:30:00
**Total Kernels:** 60

## Summary

| Category | Count |
|----------|-------|
| GEMM | 15 |
| Attention | 8 |
| FlashAttention | 3 |
| RMSNorm | 4 |
| ... | ... |

## Complete Kernel List

| Kernel | File | Line | Type | Category |
|--------|------|------|------|----------|
| `AVX2_Gemm_F32_F32` | `src/kernels/avx2_gemm.hpp` | 42 | C++ | GEMM |
| `FlashAttention_AVX512` | `src/asm/FlashAttention_AVX512.asm` | 156 | MASM | FlashAttention |
| ... | ... | ... | ... | ... |
```

## Integration with Build System

Add to your CI/CD pipeline:

```yaml
# .github/workflows/kernel_inventory.yml
name: Update Kernel Inventory
on:
  push:
    paths:
      - 'src/**'
      - 'asm/**'
      
jobs:
  inventory:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - name: Generate Inventory
        run: |
          .\tools\kernel_inventory.ps1
          git add KERNEL_INVENTORY.md
          git commit -m "Update kernel inventory [auto]"
          git push
```

## Best Practices

1. **Tag immediately** when a kernel is complete and tested
2. **Use descriptive names** that indicate function and platform
3. **Keep tags close** to the function/procedure definition
4. **One tag per kernel** - don't tag helper functions separately
5. **Update inventory** before major releases

## Naming Convention

```
[Platform]_[Function]_[Variant]_[Precision]

Examples:
- AVX2_Gemm_F32_F32       (AVX2 GEMM, F32 input/output)
- AVX512_Attention_QK_F16 (AVX-512 Attention Q@K^T, F16)
- RDNA3_MatMul_Q4_0_F32   (RDNA3 GPU, Q4_0 quantized, F32 output)
- MASM_KVCache_Streaming  (MASM x64, streaming KV cache)
```

## Troubleshooting

### Kernel not appearing in inventory
- Check tag format: `// KERNEL_COMPLETE: Name` or `; KERNEL_COMPLETE: Name`
- Ensure no spaces between `:` and kernel name
- Verify file extension is supported

### Wrong category detected
- Use explicit category keywords in kernel name
- Or manually specify in file path (e.g., `src/kernels/avx2/`)

### Scanner too slow
- Exclude directories with `-Exclude` parameter
- Use file extension filters
- Run on specific subdirectories

---

*This guide ensures your kernels are discoverable and trackable across the RawrXD ecosystem.*
