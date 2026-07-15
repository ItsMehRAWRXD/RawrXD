# L4.1 Frozen Contract
**Version:** 1.0.0  
**Date:** 2026-07-09  
**Status:** FROZEN - No modifications without version bump

---

## Purpose
This document defines the validated behavior of the L4.1 GGUF Weight Access Layer. Any implementation claiming L4.1 compliance must produce **bit-identical output** to the reference validation procedure defined herein.

---

## 1. GGUF Tensor Addressing Rules

### 1.1 File Layout
```
[GGUF Header]
[Metadata KV Pairs]
[Tensor Info Directory]
[Padding to 32-byte alignment]
[Tensor Data]
```

### 1.2 Tensor Info Structure
Each tensor entry in the directory contains:
- `name`: String (key for lookup)
- `n_dims`: uint32 (1-4 dimensions)
- `dims[]`: uint64[n_dims] (shape)
- `type`: uint32 (GGML quantization type)
- `offset`: uint64 (relative to tensor_data_start)

### 1.3 Absolute Offset Calculation
```
absolute_offset = tensor_data_start + tensor_info.offset + (row_index * row_size)

Where:
  tensor_data_start = file position after tensor info directory
  row_size = (embedding_dim / values_per_block) * bytes_per_block
```

### 1.4 Alignment Requirements
- All tensor offsets must be 32-byte aligned
- Row offsets need not be aligned (calculated from aligned base)

---

## 2. Q4_0 Block Layout

### 2.1 Structure
```
Bytes 0-1:   scale (FP16, little-endian)
Bytes 2-17:  quants[16] (uint8, 32 nibbles)
Total: 18 bytes per block
```

### 2.2 Nibble Packing
```
quant[0] = (quants[0] & 0x0F)      // low nibble of byte 0
quant[1] = (quants[0] >> 4) & 0x0F // high nibble of byte 0
quant[2] = (quants[1] & 0x0F)      // low nibble of byte 1
...
quant[31] = (quants[15] >> 4) & 0x0F // high nibble of byte 15
```

### 2.3 Dequantization Formula
```
scale_fp32 = FP16_to_FP32(scale_fp16)
for i in 0..31:
    value[i] = (quant[i] - 8.0) * scale_fp32
```

---

## 3. FP16 Scale Conversion

### 3.1 Bit Layout (IEEE 754-2008 binary16)
```
Bits 15:    sign (0=positive, 1=negative)
Bits 14-10: exponent (0-31, bias=15)
Bits 9-0:   mantissa (10 bits)
```

### 3.2 Conversion to FP32
```
if exponent == 0:
    // Subnormal number
    value = (-1)^sign * (mantissa / 1024) * 2^-14
elif exponent == 31:
    // Infinity or NaN
    if mantissa == 0:
        value = (-1)^sign * Infinity
    else:
        value = NaN
else:
    // Normal number
    value = (-1)^sign * (1 + mantissa/1024) * 2^(exponent-15)
```

### 3.3 Endianness
- GGUF stores FP16 in **little-endian** byte order
- Byte 0 = low byte, Byte 1 = high byte

---

## 4. NaN/Inf Policy

### 4.1 Detection
A scale value is invalid if:
- `isnan(scale)` returns true
- `isinf(scale)` returns true

### 4.2 Handling Policy: ZERO_FILL (Default)
When invalid scale detected:
1. Output 32 zeros for the block
2. Log warning with block index and raw FP16 value
3. Continue processing remaining blocks

### 4.3 Alternative Policies
- `FAIL_VALIDATION`: Throw exception, abort processing
- `CLAMP`: Clamp scale to valid range (implementation-defined)

### 4.4 Known Invalid Blocks
Ministral-3B Q4_0 contains:
- Block 56: FP16 raw 0x7ca8 (NaN) → 32 zeros output

---

## 5. Reference Validation Procedure

### 5.1 Test Model
- **File:** `ministral3_q4_0.gguf`
- **Tensor:** `token_embd.weight`
- **Token:** 42
- **Dimensions:** [4096, 131072]

### 5.2 Validation Steps
1. Extract token 42 embedding using RawrXD decoder
2. Extract token 42 embedding using reference implementation
3. Compare 4096 FP32 values

### 5.3 Acceptance Thresholds
```
Max Absolute Error:     0.0 (bit-identical)
Mean Absolute Error:    0.0 (bit-identical)
RMSE:                   0.0 (bit-identical)
Cosine Similarity:      1.000000 (perfect)
```

### 5.4 Reference Implementation
```python
# Python reference (extract_reference_direct.py)
def fp16_to_fp32(fp16):
    sign = (fp16 >> 15) & 0x1
    exp = (fp16 >> 10) & 0x1F
    mant = fp16 & 0x3FF
    
    if exp == 0:
        return mant / 1024.0 * (2 ** -14) * (-1 if sign else 1)
    if exp == 0x1F:
        return float('nan') if mant else float('inf') * (-1 if sign else 1)
    
    exp32 = exp + 112
    mant32 = mant << 13
    fp32_bits = (sign << 31) | (exp32 << 23) | mant32
    return struct.unpack('f', struct.pack('I', fp32_bits))[0]

def dequantize_q4_0_block(block_data):
    scale_raw = struct.unpack('<H', block_data[0:2])[0]
    scale = fp16_to_fp32(scale_raw)
    
    if math.isnan(scale) or math.isinf(scale):
        return [0.0] * 32  # ZERO_FILL policy
    
    values = []
    for i in range(16):
        byte = block_data[2 + i]
        low = (byte & 0x0F) - 8
        high = ((byte >> 4) & 0x0F) - 8
        values.append(low * scale)
        values.append(high * scale)
    return values
```

---

## 6. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-09 | Initial frozen contract |

---

## 7. Compliance Statement

An implementation is L4.1 compliant if and only if:
1. It can locate `token_embd.weight` in a GGUF v3 file
2. It produces bit-identical output to the reference for token 42
3. It handles NaN/Inf scales according to Section 4

**Note:** L4.1 compliance does not imply L4.2+ compliance. This contract covers only weight access, not execution.
