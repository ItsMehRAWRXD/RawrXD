# Model Digestion Engine - Python CLI (Lightweight Edition)

**No Ollama. No dependencies. Just Python + your drive letters.**

## Quick Start

### Single Model Digestion
```bash
python digest.py -i d:\models\llama.gguf -o d:\digested\llama
```

**Output**:
```
d:\digested\llama\
├── llama.blob              # Normalized format
├── llama.encrypted.blob    # AES-256-GCM encrypted
├── llama.key.json          # Encryption metadata
├── llama.meta.json         # Model info
├── llama.asm               # MASM x64 loader stub
└── llama.hpp               # C++ integration header
```

### Bulk Scan & Digest Entire Drive
```bash
# Find all .gguf files on D: drive and digest them
python digest.py --drive d: --pattern "*.gguf" --output d:\digested-models
```

### Custom Model Name
```bash
python digest.py -i e:\mymodel.blob -o d:\out -n "SuperModel"
```

## What It Does

### Phase 1: Parse Format
- Detects GGUF/BLOB/RAW binary automatically
- Extracts metadata (vocab size, layers, etc.)

### Phase 2: Compute Checksums
- SHA256 verification for integrity

### Phase 3: Create BLOB
- Normalizes any format to BLOB container
- Embeds metadata in header

### Phase 4: Encrypt (Optional)
- AES-256-GCM encryption (Carmilla compatible)
- PBKDF2 key derivation
- Unique IV per file

### Phase 5: Generate MASM Stub
- MASM x64 loader skeleton
- Ready for ml64.exe compilation

### Phase 6: Metadata + Manifest
- JSON metadata file
- Integration configuration

### Phase 7: C++ Header
- Ready-to-include header for IDE
- Model configuration constants

## Installation

### Minimal (No Encryption)
```bash
python digest.py --help
```
Just Python 3.8+

### With Encryption Support
```bash
pip install pycryptodome
python digest.py -i model.gguf -o output
```

## Drive Letter Examples

```bash
# Scan D: for GGUF files
python digest.py --drive d: --output d:\digested

# Find BLOB files on E: drive
python digest.py --drive e: --pattern "*.blob" --output d:\out

# Any pattern
python digest.py --drive g: --pattern "model*" --output d:\models-digested
```

## Integration with RawrXD IDE

After digestion, you have everything ready:

1. **Copy BLOB to IDE**:
   ```powershell
   cp d:\digested\llama\llama.encrypted.blob d:\rawrxd\Ship\encrypted_models\
   ```

2. **Include Header**:
   ```cpp
   #include "llama.hpp"
   ```

3. **Link with Compiled MASM** (if you compile):
   ```bash
   ml64.exe /c llama.asm /Fo llama.obj
   lib llama.obj /out:llama.lib
   ```

4. **Load in IDE**:
   ```cpp
   // In RawrXD_Win32_IDE.cpp
   if (EncryptedModelLoader::LoadFromBlob("encrypted_models/llama.encrypted.blob")) {
       // Ready to use
   }
   ```

## What You Control

- **Input**: Any drive letter + file pattern
- **Output**: Single directory with all artifacts
- **Encryption**: On/off (`--no-encrypt` flag)
- **Naming**: Custom model names
- **Batch**: Process entire drives at once

## What You Don't Need

❌ Ollama (not installed)
❌ Pre-quantized models (you quantize yourself)
❌ Complex configuration (sensible defaults)
❌ External tools (pure Python)

## Output Structure

Each model produces:

| File | Purpose |
|------|---------|
| `*.blob` | Normalized binary format |
| `*.encrypted.blob` | AES-256-GCM encrypted |
| `*.key.json` | Encryption metadata (salt, IV) |
| `*.meta.json` | Model metadata (vocab, layers, checksum) |
| `*.asm` | MASM x64 loader stub |
| `*.hpp` | C++ header with config |

## Performance

- **Parsing**: Instant (reads header only)
- **Encryption**: ~500ms per GB (AES-256-GCM)
- **Total**: 1-2 seconds per model

## Examples

### Digest Single Model
```bash
python digest.py -i "C:\Users\User\Downloads\model.gguf" -o "d:\digested\model1"
```

### Bulk Digest from Multiple Drives
```bash
# D: drive GGUF files
python digest.py --drive d: --pattern "*.gguf" --output d:\models\batch1

# E: drive BLOB files
python digest.py --drive e: --pattern "*.blob" --output d:\models\batch2

# All .gguf anywhere
python digest.py --drive g: --pattern "**/*.gguf" --output d:\models\batch3
```

### Skip Encryption
```bash
python digest.py -i model.gguf -o output --no-encrypt
```

## What's Generated

```bash
$ python digest.py -i llama.gguf -o digested

==============================================================================
  MODEL DIGESTION - llama
==============================================================================

📥 Input: llama.gguf
📤 Output: digested
📋 Format: GGUF

[Phase 1] Parsing metadata...
  ✅ Metadata extracted:
     magic: 0x47475546
     version: 3
     tensor_count: 291
     file_size: 4294967296

[Phase 2] Computing checksums...
  ✅ SHA256: a1b2c3d4e5f6g7h8...

[Phase 3] Creating BLOB package...
  ✅ BLOB created: digested/llama.blob

[Phase 4] Encryption...
  ✅ Encrypted: digested/llama.encrypted.blob

[Phase 5] Generating MASM loader stub...
  ✅ MASM stub: digested/llama.asm

[Phase 6] Generating metadata...
  ✅ Metadata written

[Phase 7] Generating C++ header...
  ✅ C++ header: digested/llama.hpp

==============================================================================
✅ DIGESTION COMPLETE
==============================================================================

📦 Output files:
   Blob: digested/llama.blob
   Meta: digested/llama.meta.json
   ASM:  digested/llama.asm
   HPP:  digested/llama.hpp
```

## Troubleshooting

**"pycryptodome not installed"**
```bash
pip install pycryptodome
```
Or just use `--no-encrypt` flag

**"Drive not found"**
```bash
python digest.py --drive d:  # Make sure D: exists
```

**"File not found"**
```bash
python digest.py -i "d:\full\path\to\model.gguf"  # Use full path
```

## That's It!

Point it at your drive, get encrypted model packages ready for RawrXD IDE. No Ollama needed. No dependencies except what you already have.

```bash
python digest.py --drive d: --output d:\ready-for-ide
# And you're done.
```
