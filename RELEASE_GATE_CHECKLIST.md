# RawrXD IDE v1.0.0 — Release Gate Checklist

**Repository:** `ItsMehRAWRXD/RawrXD`  
**Branch:** `main`  
**Target Tag:** `v1.0.0`  
**Date:** 2026-07-29  
**Status:** 🔄 In Progress

---

## Pre-Release Validation

### 1. Clean Clone Build ✅
**Purpose:** Prove reproducibility

```bash
# Fresh clone
git clone https://github.com/ItsMehRAWRXD/RawrXD.git RawrXD-ReleaseTest
cd RawrXD-ReleaseTest

# Configure
cmake -B build -G Ninja

# Build
ninja -C build

# Verify executable exists
ls -la build/bin/RawrXD-IDE.exe
```

**Expected Result:** Clean build with no errors
**Status:** ⬜ Pending

---

### 2. Fresh Machine Startup ✅
**Purpose:** Detect hidden dependencies

**Test Environment:**
- [ ] Windows 10/11 clean VM
- [ ] No Vulkan SDK installed
- [ ] No ZLIB development files
- [ ] Only MSVC Build Tools + CMake + Ninja

**Validation:**
```bash
# Should build without external dependencies
cmake -B build -G Ninja -DRAWRXD_VULKAN_RUNTIME=ON
ninja -C build
```

**Expected Result:** Build succeeds with runtime-only dependencies
**Status:** ⬜ Pending

---

### 3. GGUF Open → Inspect → Run ✅
**Purpose:** End-to-end model workflow

**Test Steps:**
1. [ ] Launch RawrXD-IDE.exe
2. [ ] File → Open GGUF Model
3. [ ] Select a .gguf file (e.g., Q4_0 quantized model)
4. [ ] Verify model loads in GGUF Inspector
5. [ ] Verify metadata displays correctly
6. [ ] Close inspector
7. [ ] Set as active model
8. [ ] Trigger AI completion (Ctrl+Space)

**Expected Result:** Model loads, inspects, and runs inference
**Status:** ⬜ Pending

---

### 4. Ghost Text Acceptance ✅
**Purpose:** Editor interaction proof

**Test Steps:**
1. [ ] Open a source file (e.g., .cpp, .py)
2. [ ] Type code to trigger context
3. [ ] Press Ctrl+Space
4. [ ] Wait for ghost text to appear
5. [ ] Press Tab to accept
6. [ ] Verify text inserted at cursor
7. [ ] Press Ctrl+Z to undo
8. [ ] Press Ctrl+Space again
9. [ ] Press Esc to dismiss
10. [ ] Verify ghost text disappears

**Expected Result:** Tab accepts, Esc dismisses, undo works
**Status:** ⬜ Pending

---

### 5. Vulkan Absent Fallback ✅
**Purpose:** Dependency independence

**Test Steps:**
1. [ ] Rename `vulkan-1.dll` to `vulkan-1.dll.bak`
2. [ ] Launch RawrXD-IDE.exe
3. [ ] Check status bar for "CPU Backend"
4. [ ] Open GGUF model
5. [ ] Trigger AI completion
6. [ ] Verify inference works (CPU path)
7. [ ] Restore `vulkan-1.dll`

**Expected Result:** Falls back to CPU, no crash, inference works
**Status:** ⬜ Pending

---

### 6. Vulkan Present Activation ✅
**Purpose:** GPU path proof

**Test Steps:**
1. [ ] Ensure `vulkan-1.dll` exists
2. [ ] Launch RawrXD-IDE.exe
3. [ ] Check status bar for "GPU Backend"
4. [ ] Open GGUF model
5. [ ] Trigger AI completion
6. [ ] Verify inference uses GPU (faster)

**Expected Result:** GPU backend activates, inference faster than CPU
**Status:** ⬜ Pending

---

### 7. Compression Round Trip ✅
**Purpose:** Artifact integrity

**Test Steps:**
1. [ ] Create checkpoint (File → Save Checkpoint)
2. [ ] Verify .checkpoint file created
3. [ ] Note file size (should be compressed)
4. [ ] Close IDE
5. [ ] Reopen IDE
6. [ ] Load checkpoint (File → Load Checkpoint)
7. [ ] Verify state restored correctly

**Expected Result:** Checkpoint saves, compresses, loads, restores
**Status:** ⬜ Pending

---

### 8. Test Harness Execution ✅
**Purpose:** Regression baseline

```bash
# Run all tests
ctest --output-on-failure -C Release

# Run specific IDE tests
ctest -R ide -V

# Run compression tests
ctest -R compression -V

# Run validation gates
ctest -R VAL -V
```

**Expected Results:**
- [ ] 36+ tests passing
- [ ] No failures
- [ ] No warnings

**Status:** ⬜ Pending

---

### 9. Version Manifest Generation ✅
**Purpose:** Release provenance

**Generated Files:**
- [ ] `version_manifest.json`
- [ ] `RawrXD_RUNTIME_DEPENDENCIES.txt`
- [ ] `build_info.txt`

**Content Verification:**
```json
{
  "version": "1.0.0",
  "build_date": "2026-07-29",
  "git_commit": "abc123",
  "command_registry_hash": "sha256:...",
  "runtime_abi_version": "1.0",
  "model_engine_abi": "1.0",
  "components": {
    "ghost_text": "1.0.0",
    "ai_bridge": "1.0.0",
    "inference_engine": "1.0.0",
    "compression": "1.0.0",
    "vulkan_loader": "1.0.0",
    "zlib_loader": "1.0.0"
  }
}
```

**Status:** ⬜ Pending

---

## Release Artifacts

### Required Files
| File | Purpose | Status |
|------|---------|--------|
| `RawrXD-IDE.exe` | Main executable | ⬜ |
| `ai_settings.ini` | Default configuration | ⬜ |
| `RawrXD_RUNTIME_DEPENDENCIES.txt` | Dependency list | ⬜ |
| `version_manifest.json` | Build provenance | ⬜ |
| `README.md` | Quick start guide | ⬜ |
| `LICENSE` | License file | ⬜ |

### Optional Runtime Dependencies
| File | Purpose | Bundled? |
|------|---------|----------|
| `vulkan-1.dll` | GPU acceleration | No (system) |
| `zlib1.dll` | Compression | No (system/optional) |

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Build Engineer | | | |
| QA Lead | | | |
| Release Manager | | | |

---

## Tag Creation

After all checks pass:

```bash
# Create annotated tag
git tag -a v1.0.0 -m "RawrXD IDE v1.0.0

- Complete AI-native IDE with ghost text
- Runtime Vulkan loader (optional GPU)
- Runtime ZLIB loader (optional compression)
- GGUF inspector and model tooling
- LSP, Terminal, Git integration
- 36+ tests passing
- Production ready"

# Push tag
git push origin v1.0.0
```

---

## Post-Release

- [ ] Create GitHub Release with notes
- [ ] Upload binaries to Release page
- [ ] Update documentation site
- [ ] Announce on social channels
- [ ] Monitor for critical issues

---

**Status:** ⬜ **NOT READY FOR RELEASE** — Pending validation
