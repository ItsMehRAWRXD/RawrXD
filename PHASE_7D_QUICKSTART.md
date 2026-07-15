# Phase 7D Quickstart: Real Model Integration

**Goal:** Run your first cryptographically verified inference on a real GGUF model in under 5 minutes.

---

## Prerequisites

- [ ] MinGW g++ installed at `C:\ProgramData\mingw64\mingw64\bin\g++.exe`
- [ ] A GGUF model file (TinyLlama recommended for first run)
- [ ] Phase 7B/7C infrastructure already built (`hash_chain.cpp`, etc.)

---

## Step 1: Build (30 seconds)

```batch
cd d:\rawrxd
build_realmodel.bat
```

**Expected output:**
```
[1/6] Compiling hash kernel (MASM)...
[2/6] Compiling hash chain manager...
[3/6] Compiling GGUF checkpoint hooks...
[4/6] Compiling GGUF loader...
[5/6] Compiling transformer inference...
[6/6] Linking RawrXD_RealModel.exe...
[7/7] Building verify_proof.exe...
Build Complete
```

---

## Step 2: Quick Smoke Test (10 seconds)

```batch
REM Compute model hash
certutil -hashfile models\tinyllama.gguf SHA256 > model.sha256

REM Run inference with proofs
.\build_cli\RawrXD_RealModel.exe ^
    --model models\tinyllama.gguf ^
    --prompt "Hello world" ^
    --seed 42 ^
    --tokens 10 ^
    --enable-proofs ^
    --proof-out proof_tiny.rawrproof

REM Verify the proof
.\build_cli\verify_proof.exe models\tinyllama.gguf proof_tiny.rawrproof
```

**Success criteria:**
- ✓ Inference completes without errors
- ✓ `proof_tiny.rawrproof` file created (> 1KB)
- ✓ `verify_proof.exe` returns "VERIFICATION SUCCESS"

---

## Step 3: Determinism Check (30 seconds)

```batch
REM Run 3 times with same seed
for /l %%i in (1,1,3) do (
    .\build_cli\RawrXD_RealModel.exe ^
        --model models\tinyllama.gguf ^
        --prompt "Hello world" ^
        --seed 42 ^
        --tokens 10 ^
        --enable-proofs ^
        --proof-out proof_run%%i.rawrproof
)

REM Compare hashes (should be identical)
certutil -hashfile proof_run1.rawrproof SHA256
certutil -hashfile proof_run2.rawrproof SHA256
certutil -hashfile proof_run3.rawrproof SHA256
```

**Success criteria:**
- ✓ All 3 proof files have identical SHA256 hashes
- ✓ Merkle roots match across runs

---

## Step 4: Compare with llama.cpp (1 minute)

```powershell
powershell -File scripts\compare_llamacpp_rawrxd.ps1 `
    -ModelPath models\tinyllama.gguf `
    -Prompt "Hello world" `
    -Tokens 10 `
    -Seed 42
```

**Expected output:**
```
Step 4: Comparing results...
  ✓ Text output: IDENTICAL
  ✓ Token count: MATCH (10)
Step 5: Verifying RawrXD proof chain...
  ✓ Proof chain: VERIFIED
OVERALL: ✓ ALL CHECKS PASSED
```

---

## Step 5: Full Audit (2 minutes)

```batch
scripts\audit_run_realmodel.bat models\llama-2-7b.gguf full
```

**Output:**
```
[1/7] Validating model file...
[2/7] Extracting model metadata...
[3/7] Configuring test scenarios...
[4/7] Verifying build artifacts...
[5/7] Running inference with checkpoint capture...
[6/7] Verifying proof chain...
[7/7] Generating audit report...

Status: ✓ ALL CHECKS PASSED
```

**Artifacts created:**
- `audit_output\run_YYYYMMDD_HHMMSS\`
  - `model.sha256` - Model file hash
  - `metadata.txt` - GGUF metadata
  - `inference.log` - Execution log
  - `inference.rawrproof` - Cryptographic proof
  - `output.txt` - Generated text
  - `verification.log` - Proof verification
  - `audit_report.json` - Machine-readable report
  - `MANIFEST.txt` - Human-readable summary

---

## Troubleshooting

### "verify_proof.exe not found"
```batch
REM Rebuild verification tool
g++ -std=c++17 -O3 -I src -I src/core src/verify/verify_proof.cpp ^
    build_cli/hash_chain.obj -o build_cli/verify_proof.exe
```

### "Proof verification failed"
1. Check that model file isn't corrupted: `certutil -hashfile model.gguf SHA256`
2. Ensure same build flags used for inference and verification
3. Check `inference.log` for checkpoint errors

### "Text differs from llama.cpp"
1. Verify both use same seed: `--seed 42`
2. Check temperature/top_p/top_k match exactly
3. Ensure llama.cpp uses `--no-mmap` for determinism
4. Both must use CPU-only mode for comparison

### "Hash mismatch between runs"
1. Disable CPU frequency scaling
2. Pin thread affinity: `--threads 1`
3. Check for uninitialized memory (use `-fsanitize=address` in debug)

---

## Command Reference

| Task | Command |
|------|---------|
| Build | `build_realmodel.bat` |
| Quick test | `RawrXD_RealModel.exe --model m.gguf --prompt "Hi" --tokens 10` |
| With proofs | Add `--enable-proofs --proof-out proof.rawrproof` |
| Verify proof | `verify_proof.exe model.gguf proof.rawrproof` |
| Compare | `compare_llamacpp_rawrxd.ps1 -ModelPath m.gguf -Prompt "Hi"` |
| Full audit | `audit_run_realmodel.bat model.gguf full` |

---

## Success Checklist

- [ ] Build completes without errors
- [ ] Smoke test generates proof file
- [ ] Proof verification passes
- [ ] Determinism: 3 runs produce identical proofs
- [ ] Reference comparison matches llama.cpp
- [ ] Full audit completes with "ALL CHECKS PASSED"

**When all checked:** Phase 7D is complete. Ready for production deployment.
