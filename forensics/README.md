# GGUF Binary Forensics Tool

## Overview

A surgical reverse engineering tool for GGUF (GGML Universal Format) files. Maps every byte of the format to give you complete sovereignty over your model files.

## Why This Exists

Most tools *use* GGUF files. This tool *understands* them at the byte level:

- **Header analysis** - Magic, version, tensor count, metadata count
- **Metadata forensics** - Every key-value pair with type information
- **Tensor mapping** - Offsets, dimensions, types, sizes
- **Alignment verification** - Check 64-byte alignment, padding patterns
- **Entropy analysis** - Detect compression, encryption, patterns
- **Hex dumping** - Raw byte inspection

## Building

```bash
cd d:/src/forensics
g++ -std=c++17 -O2 -o gguf_forensics gguf_forensics.cpp gguf_types.cpp
```

## Usage

### Basic Analysis
```bash
./gguf_forensics model.gguf
```

Shows:
- Header info (magic, version, counts)
- Tensor table (name, type, dims, offset, size)
- Summary statistics

### Full Forensics
```bash
./gguf_forensics model.gguf --metadata --verify
```

Adds:
- All metadata key-value pairs
- Alignment verification
- Structural integrity checks

### Tensor Deep Dive
```bash
./gguf_forensics model.gguf --tensor token_embd.weight --entropy --hex
```

Analyzes specific tensor:
- Statistics (min/max/mean/std for F32)
- Entropy calculation
- Hex dump of first 256 bytes

## Output Example

```
╔══════════════════════════════════════════════════════════════════╗
║           GGUF BINARY FORENSICS TOOL v1.0                        ║
║           Reverse Engineering at the Byte Level                   ║
╚══════════════════════════════════════════════════════════════════╝

[+] Header Analysis
    Magic:      0x46554747 ('GGUF') ✓
    Version:    3 (latest)
    Tensors:    147
    Metadata:   19 KV pairs
    Header end: offset 0x0018

[+] Metadata Section (19 entries)
    Key                                      Type         Value
    --------------------------------------------------------------------------------
    general.architecture                     string       "llama"
    general.name                             string       "Meta-Llama-3-8B"
    llama.context_length                     uint32       8192
    llama.embedding_length                   uint32       4096
    ...

[+] Tensor Info Section (147 tensors)
    Name                             Type     Dimensions           Offset       Size
    ----------------------------------------------------------------------------------------------------
    token_embd.weight                Q4_K     [128256, 4096]       0x00000000   603979776 bytes
    blk.0.attn_norm.weight           F32      [4096]               0x24100000   16384 bytes
    blk.0.attn_q.weight              Q4_K     [4096, 4096]         0x24104000   18874368 bytes
    ...

[+] Data Section starts at offset 0x0001A000 (aligned to 64)

[+] Summary
    Total file size:     4934532096 bytes
    Header size:         24 bytes
    Metadata section:    1234 bytes
    Tensor info section: 5678 bytes
    Data section offset: 8192 bytes
    Total tensor data:   4934523904 bytes
    Padding/overhead:    0 bytes

    Tensor type distribution:
      Q4_K: 128 tensors
      F32: 19 tensors
```

## Forensics Capabilities

### 1. Header Verification
- Magic number validation
- Version compatibility check
- Count validation

### 2. Metadata Extraction
- All KV pairs with types
- String values decoded
- Array types enumerated
- Nested structures handled

### 3. Tensor Mapping
- Name extraction
- Dimension parsing
- Type identification
- Offset calculation
- Size computation (including quantized)

### 4. Alignment Analysis
- 64-byte boundary checks
- Gap detection between tensors
- Padding pattern analysis

### 5. Entropy Calculation
- Byte-level entropy
- Pattern detection:
  - < 1.0 bits/byte: Highly structured (zeros/constants)
  - 1.0-4.0: Structured (quantized weights)
  - 4.0-7.0: Moderate (compressed/encoded)
  - > 7.0: High entropy (near-random)

### 6. Hex Dumping
- Formatted hex output
- ASCII representation
- Offset markers

## Understanding the Format

### GGUF Structure

```
┌─────────────────────────────────────────────────────────────┐
│ HEADER (24 bytes)                                           │
│   - Magic:        0x46554747 (4 bytes)                       │
│   - Version:     uint32 (4 bytes)                          │
│   - Tensor count: uint64 (8 bytes)                           │
│   - Metadata KV: uint64 (8 bytes)                          │
├─────────────────────────────────────────────────────────────┤
│ METADATA SECTION                                            │
│   - Key-value pairs (variable length)                       │
│   - Keys: uint64 length + string                            │
│   - Values: type + data                                     │
├─────────────────────────────────────────────────────────────┤
│ TENSOR INFO SECTION                                         │
│   - Name: uint64 length + string                            │
│   - Dimensions: uint32 count + uint64[]                   │
│   - Type: uint32                                            │
│   - Offset: uint64 (relative to data section)               │
├─────────────────────────────────────────────────────────────┤
│ PADDING (to 64-byte alignment)                              │
├─────────────────────────────────────────────────────────────┤
│ DATA SECTION (64-byte aligned)                              │
│   - Raw tensor data                                         │
│   - Each tensor at offset + data_offset                     │
└─────────────────────────────────────────────────────────────┘
```

### Quantized Type Sizes

| Type | Block Size | Bytes/Block | Bits/Weight |
|------|------------|-------------|-------------|
| Q4_0 | 32         | 18          | 4.5         |
| Q4_1 | 32         | 20          | 5.0         |
| Q5_0 | 32         | 22          | 5.5         |
| Q5_1 | 32         | 24          | 6.0         |
| Q8_0 | 32         | 34          | 8.5         |
| Q2_K | 256        | 72          | 2.25        |
| Q3_K | 256        | 110         | 3.44        |
| Q4_K | 256        | 144         | 4.5         |
| Q5_K | 256        | 176         | 5.5         |
| Q6_K | 256        | 210         | 6.56        |
| Q8_K | 256        | 324         | 10.125      |

## Use Cases

### 1. Model Verification
```bash
./gguf_forensics model.gguf --verify
```
Verify file integrity before loading.

### 2. Architecture Discovery
```bash
./gguf_forensics model.gguf --metadata | grep -E "(architecture|layer|head)"
```
Extract model architecture from metadata.

### 3. Weight Analysis
```bash
./gguf_forensics model.gguf --tensor blk.0.attn_q.weight --entropy
```
Analyze quantization patterns.

### 4. Format Research
```bash
./gguf_forensics model.gguf --metadata --verify --hex 2>&1 | less
```
Complete format dump for reverse engineering.

### 5. Corruption Detection
```bash
./gguf_forensics model.gguf --verify
```
Detect alignment issues, size mismatches.

## Integration with Runtime

This tool validates the same format your `StreamingGGUFLoader` parses:

```cpp
// Forensics tool confirms:
// - Header layout
// - Tensor offsets
// - Alignment requirements

// Your loader uses:
StreamingGGUFLoader::Open()     // Same header parsing
BuildIndex()                    // Same tensor table walk
CreateTensorView()              // Same offset calculations
```

## Future Extensions

- [ ] JSON output for programmatic use
- [ ] Tensor diff/compare between files
- [ ] Weight histogram generation
- [ ] Automatic format documentation generation
- [ ] Conversion validation (FP32 -> Q4_K)

## References

- [GGUF Spec](https://github.com/ggerganov/ggml/blob/master/docs/gguf.md)
- [llama.cpp GGUF](https://github.com/ggerganov/llama.cpp/blob/master/gguf-py)
- Your `d:/src/runtime/streaming_gguf_loader.hpp`

---

**Status: OPERATIONAL** ✅

You now have complete visibility into the substrate your runtime stands on.
