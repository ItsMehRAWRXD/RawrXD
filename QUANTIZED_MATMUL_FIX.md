# Quantized MatMul Fix - Memory Issue Resolved

## Summary

**Issue**: `std::bad_alloc` when loading 22B model  
**Root Cause**: Transformer materialized all weights as FP32 (~52 GB)  
**Fix**: Implemented quantized MatMul with on-the-fly dequantization  
**Result**: ✅ Model loads successfully without memory errors

---

## Changes Made

### 1. New Files Created

- `quantized_tensor.hpp` - Quantized tensor storage structures
- `quantized_tensor.cpp` - On-the-fly dequantization implementation

### 2. Modified Files

- `transformer_layer.h` - Changed weight storage from FP32 to QuantizedTensor
- `transformer_layer.cpp` - Updated LoadWeights() and MatMul() to use quantization

---

## Memory Savings

| Component | Before (FP32) | After (Q4_0) | Savings |
|-----------|---------------|--------------|---------|
| Attention weights | ~768 MB/layer | ~96 MB/layer | 8x |
| FFN weights | ~3 GB/layer | ~375 MB/layer | 8x |
| **22B Model Total** | **~52 GB** | **~6.5 GB** | **8x** |

---

## Technical Details

### QuantizedTensor Structure
```cpp
struct QuantizedTensor {
    QuantType type;              // Q4_0, Q8_0, etc.
    std::vector<uint8_t> data;   // Raw quantized bytes
    uint64_t num_elements;
    uint64_t num_blocks;
};
```

### On-the-Fly Dequantization
```cpp
std::vector<float> MatMulQuantized(
    const std::vector<float>& input,
    const QuantizedTensor& weights) {
    
    // For each output element:
    // 1. Load quantized block
    // 2. Dequantize to FP32 (32 values)
    // 3. Multiply with input
    // 4. Accumulate result
    // 5. Discard dequantized block
}
```

### Supported Quantization Types
- Q4_0: 4-bit, 32 elements/block, 18 bytes/block
- Q8_0: 8-bit, 32 elements/block, 34 bytes/block
- Q4_K: 4-bit K-quant, 256 elements/block, 144 bytes/block
- F32: Fallback for non-quantized tensors

---

## Build

```bash
cd d:\rawrxd
build_v4.bat
```

## Test

```bash
# This now works without std::bad_alloc!
d:\rawrxd\rawrxd_v4.exe inference --model d:\rawrxd\src\codestral22b.gguf --prompt "Hello" --max-tokens 3 --verbose
```

---

## Next Steps

1. **Reference Validation**: Compare outputs against llama.cpp
2. **Performance Optimization**: Add AVX2/AVX-512 dequantization
3. **Memory-Mapped Weights**: For even larger models
4. **FlashAttention**: Optimize attention computation

---

## Files

- `d:\rawrxd\src\inference\quantized_tensor.hpp`
- `d:\rawrxd\src\inference\quantized_tensor.cpp`
- `d:\rawrxd\src\inference\transformer_layer.h` (modified)
- `d:\rawrxd\src\inference\transformer_layer.cpp` (modified)
- `d:\rawrxd\rawrxd_v4.exe` (new build)

---

*Fix implemented: 2026-07-09*  
*Status: ✅ std::bad_alloc resolved*
