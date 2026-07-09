# GGUF Forensics Field Guide

## 🎯 Mission Objective

**Complete byte-level understanding of the GGUF format** - the substrate your entire sovereign runtime stands on.

---

## 📋 Quick Start

```bash
# Build
cd d:/src/forensics
build.bat

# Basic analysis
./gguf_forensics model.gguf

# Full forensics
./gguf_forensics model.gguf --metadata --verify

# Deep tensor analysis
./gguf_forensics model.gguf --tensor token_embd.weight --entropy --hex
```

---

## 🔍 What You'll Discover

### 1. **Header Structure** (24 bytes)
```
Offset 0x00: Magic    0x46554747 ('GGUF')
Offset 0x04: Version  3 (latest)
Offset 0x08: Tensors  147
Offset 0x10: Metadata 19
```

### 2. **Metadata Keys** (Architecture Discovery)
```
general.architecture = "llama"
general.name = "Meta-Llama-3-8B"
general.file_type = 15 (Q4_K)
llama.context_length = 8192
llama.embedding_length = 4096
llama.block_count = 32
llama.attention.head_count = 32
llama.attention.head_count_kv = 8
```

### 3. **Tensor Layout** (Memory Map)
```
Name                          Type  Dimensions      File Offset  Size
─────────────────────────────────────────────────────────────────────────
token_embd.weight             Q4_K  [128256, 4096]  0x00002000   603MB
blk.0.attn_norm.weight        F32   [4096]          0x24102000   16KB
blk.0.attn_q.weight           Q4_K  [4096, 4096]    0x24106000   18MB
blk.0.attn_k.weight           Q4_K  [4096, 1024]    0x25346000   4.5MB
blk.0.attn_v.weight           Q4_K  [4096, 1024]    0x2578A000   4.5MB
blk.0.attn_output.weight      Q4_K  [4096, 4096]    0x25BCE000   18MB
blk.0.ffn_norm.weight         F32   [4096]          0x26E32000   16KB
blk.0.ffn_gate.weight         Q4_K  [4096, 14336]   0x26E36000   66MB
blk.0.ffn_up.weight           Q4_K  [4096, 14336]   0x2B08A000   66MB
blk.0.ffn_down.weight         Q4_K  [14336, 4096]   0x2F2DE000   66MB
...
```

### 4. **Alignment Patterns**
```
Data section starts at: 0x00002000 (8192 bytes)
Each tensor aligned to: 64 bytes
Padding between tensors: 0-63 bytes
```

---

## 🧠 Understanding Quantization

### Q4_K Block Structure (256 elements)
```
┌─────────────────────────────────────────────────────────────┐
│ Q4_K Block (144 bytes = 4.5 bits per weight)               │
├─────────────────────────────────────────────────────────────┤
│ d        uint16  F16 scale                                  │
│ dmin     uint16  F16 min scale                              │
│ scales   [12]    6-bit scales packed (16 values)            │
│ qs       [128]   4-bit weights (256 nibbles)                │
└─────────────────────────────────────────────────────────────┘
```

### Entropy Patterns
```
Entropy < 1.0   → Zeros, constants, or highly structured
Entropy 1-4     → Quantized weights (expected)
Entropy 4-7     → Compressed or encoded data
Entropy > 7.0   → Near-random (suspicious)
```

---

## 🔬 Forensics Workflows

### Workflow 1: Model Verification
```bash
./gguf_forensics model.gguf --verify
```
**Checks:**
- ✓ Magic number valid
- ✓ Version supported
- ✓ All tensors 64-byte aligned
- ✓ No gaps/overlaps
- ✓ File size matches expected

### Workflow 2: Architecture Extraction
```bash
./gguf_forensics model.gguf --metadata | grep -E "(architecture|embedding|block|head)"
```
**Reveals:**
- Model family (llama, phi, qwen, etc.)
- Hidden dimensions
- Number of layers
- Attention head configuration
- Context window size

### Workflow 3: Weight Distribution Analysis
```bash
for tensor in token_embd blk.0.attn_q blk.0.ffn_gate; do
    ./gguf_forensics model.gguf --tensor ${tensor}.weight --entropy
done
```
**Shows:**
- Which layers are quantized
- Quantization quality
- Potential outliers

### Workflow 4: Format Reverse Engineering
```bash
./gguf_forensics model.gguf --metadata --verify --hex > model_forensics.txt
```
**Produces:**
- Complete byte-level documentation
- Reference for parser implementation
- Validation for your loader

---

## 🛡️ Security & Integrity

### Detecting Tampering
```bash
./gguf_forensics model.gguf --verify --entropy
```
**Red flags:**
- Unexpected entropy in weight tensors
- Misaligned tensor offsets
- Metadata inconsistencies
- Size mismatches

### Validating Your Loader
```bash
# Forensics tool shows expected offsets
./gguf_forensics model.gguf | grep "token_embd"
# → token_embd.weight at offset 0x00002000

# Your loader should read same offset
# Verify: streaming_gguf_loader.cpp line 127
```

---

## 📊 Integration with Runtime

### Your Stack
```
┌─────────────────────────────────────────────────────────────┐
│ GGUF Forensics Tool (this)                                   │
│   → Validates format, discovers structure                   │
├─────────────────────────────────────────────────────────────┤
│ StreamingGGUFLoader                                          │
│   → Uses same parsing logic                                 │
│   → mmap() at discovered offsets                            │
├─────────────────────────────────────────────────────────────┤
│ TensorView                                                   │
│   → Zero-copy access to mmap'd data                         │
│   → Dequantization on demand                                │
├─────────────────────────────────────────────────────────────┤
│ Transformer Engine                                           │
│   → Uses dequantized tensors                                │
│   → FlashAttention kernels                                  │
└─────────────────────────────────────────────────────────────┘
```

### Validation Chain
1. **Forensics** confirms format correctness
2. **Loader** uses validated parsing logic
3. **TensorView** provides safe access
4. **Engine** operates on verified data

---

## 🚀 Advanced Usage

### Compare Two Models
```bash
./gguf_forensics model1.gguf > m1.txt
./gguf_forensics model2.gguf > m2.txt
diff m1.txt m2.txt
```

### Extract Architecture JSON
```bash
./gguf_forensics model.gguf --metadata | \
    grep -E "^\s+(general|llama)" | \
    sed 's/\s\+/=/' > arch.txt
```

### Find Largest Tensors
```bash
./gguf_forensics model.gguf | \
    grep -E "^\s+\w+\." | \
    sort -k5 -n -r | \
    head -20
```

### Verify Quantization
```bash
./gguf_forensics model.gguf | \
    grep -c "Q4_K"  # Should be ~80% of tensors
```

---

## 🎯 Next Steps

After mastering GGUF forensics:

1. **Hardware Performance Analysis** (Mission C)
   - VTune your kernels
   - Find bottlenecks
   - Optimize memory access

2. **Kernel Disassembly** (Mission B)
   - Extract llama.cpp tricks
   - Learn their AVX-512 patterns
   - Improve your MASM

3. **Agentic Control** (Mission F)
   - Build on verified foundation
   - Self-optimizing runtime
   - Dynamic kernel selection

---

## 📚 References

- [GGUF Specification](https://github.com/ggerganov/ggml/blob/master/docs/gguf.md)
- [llama.cpp GGUF Implementation](https://github.com/ggerganov/llama.cpp/blob/master/ggml.c)
- Your `streaming_gguf_loader.hpp` - Uses same parsing

---

**Status: MISSION A COMPLETE** ✅

You now have complete visibility into the GGUF substrate. Every byte is mapped. Every offset is known. Every tensor is accounted for.

**The ground you stand on is now yours.**
