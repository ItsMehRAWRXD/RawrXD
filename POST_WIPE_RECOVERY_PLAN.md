# RawrXD Post-Wipe Recovery Plan
## X870E TAICHI + R9700 AI PRO 32GB Build — 2026-08-14

---

## 1. Pre-Wipe Lock State (DO NOT MODIFY AFTER THIS FILE IS COMMITTED)

### Verified Git State
| Item | Value |
|------|-------|
| **Local branch** | `pre-wipe-local-main-20260813-v2` |
| **Local HEAD** | `56adf109d` |
| **GitHub remote** | `RawrXD-IDE-Final` |
| **Remote main HEAD** | `fc02d546f` |
| **Backup branch** | `pre-wipe-local-main-20260813-v2` → pushed to GitHub |

**Verification command (run before wipe):**
```powershell
cd d:\rawrxd
git log --oneline -5
git branch -v
git remote -v
```

### Build Toolchain Lock
| Item | Value |
|------|-------|
| **CMake** | 3.28+ |
| **Generator** | Ninja |
| **Compiler** | MSVC 14.51.36231 (VS 2022 Enterprise) |
| **MASM** | `ml64.exe` at `C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe` |
| **CMake option** | `-DRAWRXD_BUILD_WIN32IDE=ON` |

### Verified Binary Signature
| Item | Value |
|------|-------|
| **Binary** | `RawrXD-Win32IDE.exe` |
| **Size** | 321,933,824 bytes (~307 MiB) |
| **Subsystem** | Windows GUI (2) |
| **Entry Point** | `WinMainCRTStartup` |
| **Image Base** | 0x400000 |
| **Size of Image** | 0x136C6000 (~319 MB mapped) |

### External Storage (PRESERVE — DO NOT WIPE)
| Drive | Contents | Action |
|-------|----------|--------|
| **External SSD 1 (4TB)** | GGUF models, training data, archives | **Unplug before wipe** |
| **External SSD 2 (4TB)** | Backups, build artifacts, logs | **Unplug before wipe** |

### Model Path Registry (post-wipe mount points)
```
F:\models\qwen3-coder-30b-a3b-q4_k_m.gguf   ← Primary target
F:\models\qwen3-coder-30b-a3b-q5_k_m.gguf   ← If Q4 fits with headroom
F:\models\<small-test-model>.gguf            ← Day 1 smoke test
```

### Known Architecture State
| Component | Status | Note |
|-----------|--------|------|
| `Deep2Engine` | ✅ Real & linked | `src/deep2/Deep2Engine.cpp` line 1569 in CMake |
| `CompleteAPIServer` | ✅ Real & linked | `src/deep2/Deep2APIServer_Complete.cpp` line 5151, 5182 |
| Legacy API (`:11434`) | ✅ Real | `src/api_server.cpp` — CPUInferenceEngine path |
| **Deep2 API (`:11436`)** | ✅ **Proven path** | `POST /api/generate` → `engine_->generateText()` |
| `SpeculativeInferenceEngine` | ❌ Intentionally orphan | `src/core/speculative_inference_engine.cpp` **NOT in CMake** |
| Speculative stub | ✅ Linked NO-OP | `src/core/link_symbols_impl.cpp` — defers integration to Day 3 |
| Win32IDE GUI | ⚠️ Crash at startup | `0xC0000409` in `createPrimarySidebar()` — **B429 blocker** |

---

## 2. Day 1 — Rebuild & Certification

### 2.1 Clone & Verify
```powershell
# On new machine
git clone https://github.com/<user>/RawrXD-IDE-Final.git d:\rawrxd
cd d:\rawrxd
git checkout fc02d546f
git log --oneline -1
# Expected: fc02d546f ... (your final commit message)
```

### 2.2 CMake Configure
```powershell
cd d:\rawrxd
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DRAWRXD_BUILD_WIN32IDE=ON `
  -DCMAKE_C_COMPILER="C:/Program Files/Microsoft Visual Studio/18/Enterprise/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe" `
  -DCMAKE_CXX_COMPILER="C:/Program Files/Microsoft Visual Studio/18/Enterprise/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe"
```

**Checkpoint:** `build/CMakeCache.txt` exists and contains `RAWRXD_BUILD_WIN32IDE:BOOL=ON`.

### 2.3 Build
```powershell
cd d:\rawrxd
ninja -C build RawrXD-Win32IDE
```

**Checkpoint:**
- `build/RawrXD-Win32IDE.exe` exists
- Size ≈ 300-350 MB
- Zero linker errors (no unresolved externals)

### 2.4 PE/Dependency Certification (B428-PE Repeat)
```powershell
cd d:\rawrxd\build
dumpbin /headers RawrXD-Win32IDE.exe | Select-String "subsystem|entry point|image base|size of image"
dumpbin /imports RawrXD-Win32IDE.exe | Select-String "vulkan-1|Qt|gtk|electron|python|ollama|cuda|rocm"
```

**Expected:**
- Subsystem: `WINDOWS GUI`
- Entry: `WinMainCRTStartup`
- Dependencies: standard Windows DLLs + `vulkan-1.dll` only
- **No** Qt, GTK, Electron, Python, Ollama, CUDA, ROCm

### 2.5 Launch — Two Independent Paths

#### Path A: Win32IDE (GUI)
```powershell
cd d:\rawrxd\build
.\RawrXD-Win32IDE.exe
```
**Expected:** Window appears, ActivityBar renders, Deep2Discovery deferred.
**Known risk:** `0xC0000409` in `createPrimarySidebar()` — this is the **B429 blocker**.

#### Path B: Standalone Deep2 Server (HEADLESS)
If the GUI crashes, test inference runtime independently:

Check if a standalone server target exists:
```powershell
cd d:\rawrxd\build
ninja -C build Deep2Server_Sovereign  # or Deep2Server_Minimal
# OR check if deep2_server_main.cpp is built as an executable target
```

If no standalone target exists, the Deep2 API can only be reached through the IDE binary. **Document this.**

---

## 3. Day 1 — Deep2 API Certification (`:11436`)

### 3.1 Health Check
```powershell
# In PowerShell, after launching RawrXD-Win32IDE.exe
Invoke-RestMethod -Uri "http://127.0.0.1:11436/health" -Method GET
```
**Expected:** `{"status":"ok","engine":"Deep2","version":"1.0.0"}`

### 3.2 Status Check
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:11436/status" -Method GET
```
**Expected:** `engine_ready: true`, `gpu: "Vulkan RDNA3/RDNA4"`, devices list includes R9700.

### 3.3 Model Load (Small GGUF First)
```powershell
$body = '{"name": "test-model.gguf"}' | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/model/load" -Method POST -Body $body -ContentType "application/json"
```
**Checkpoint:** Response `{"status":"loaded","model":"test-model.gguf","engine":"Deep2"}`

### 3.4 Generation Smoke Test
```powershell
$body = '{"prompt": "Hello, world."}' | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/generate" -Method POST -Body $body -ContentType "application/json"
```
**Checkpoint:** SSE stream returns tokens. Response contains `"done": true`.

### 3.5 Tags (Ollama-Compatible)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/tags" -Method GET
```
**Checkpoint:** Returns model list in Ollama format.

### 3.6 First Real Model — Qwen3-Coder-30B-A3B
```powershell
$body = '{"name": "qwen3-coder-30b-a3b-q4_k_m.gguf"}' | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/model/load" -Method POST -Body $body -ContentType "application/json"
```
**Checkpoint:**
- Model loads without error
- `Deep2Engine::loadModel()` prints tensor mapping lines
- VRAM allocated on R9700

---

## 4. Day 2 — R9700 Baseline Benchmark

### 4.1 Benchmark Script
```powershell
# benchmark_deep2.ps1
$prompt = "Write a Python function to calculate factorial."
$maxTokens = 256

# Warmup
Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/generate" -Method POST `
  -Body (@{prompt="hi"; max_tokens=10} | ConvertTo-Json) -ContentType "application/json" | Out-Null

# Timed run
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$response = Invoke-RestMethod -Uri "http://127.0.0.1:11436/api/generate" -Method POST `
  -Body (@{prompt=$prompt; max_tokens=$maxTokens} | ConvertTo-Json) -ContentType "application/json"
$sw.Stop()

$elapsed = $sw.Elapsed.TotalSeconds
$tokens = $maxTokens  # Or parse from response if it returns token count
$tps = $tokens / $elapsed

Write-Host "Elapsed: $elapsed s"
Write-Host "Tokens: $tokens"
Write-Host "TPS: $tps"
```

### 4.2 Metrics to Capture
| Metric | Tool | Target |
|--------|------|--------|
| **Model load time** | Stopwatch | < 30s for 30B Q4 |
| **VRAM allocation** | GPU-Z / Adrenalin | ~18-22 GB |
| **Prompt/prefill TPS** | Benchmark script | Baseline (record exact value) |
| **Decode TPS** | Benchmark script | Baseline (record exact value) |
| **First-token latency** | Stopwatch | < 2s |
| **Sustained token rate** | Benchmark script | Stable over 256 tokens |
| **Context size** | API response | 4096+ |
| **Peak GPU utilization** | Adrenalin / GPU-Z | % during decode |
| **CPU utilization** | Task Manager | % during decode |
| **Temperature** | Adrenalin | < 85°C junction |
| **Power** | Adrenalin | Watts sustained |

### 4.3 Baseline Record Format
```markdown
## Baseline: Qwen3-Coder-30B-A3B Q4_K_M on R9700 32GB
Date: 2026-08-XX
Driver: XX.XX.XX
RawrXD commit: fc02d546f

| Metric | Value |
|--------|-------|
| Model load time | XX s |
| VRAM used | XX GB |
| Prefill TPS | XX tok/s |
| Decode TPS | XX tok/s |
| First-token latency | XX ms |
| Sustained 256 tokens | XX s |
| Peak GPU util | XX% |
| Peak CPU util | XX% |
| GPU temp | XX°C |
| Power draw | XX W |
```

---

## 5. Day 3 — Speculative Engine Integration

### 5.1 Pre-Integration Checklist
- [ ] Day 2 baseline is **frozen and recorded**
- [ ] `speculative_inference_engine.cpp` compiles standalone
- [ ] No CMake modifications have been made to Day 2 build

### 5.2 Integration Steps

#### Step 1: Remove Stub
File: `src/core/link_symbols_impl.cpp`

Delete or `#if 0` the entire `SpeculativeInferenceEngine` stub class (lines ~104-140).

#### Step 2: Add Real Implementation to CMake
In `CMakeLists.txt`, find the `RawrXD-Win32IDE` target source list and add:
```cmake
src/core/speculative_inference_engine.cpp
```

**Verify no duplicate symbol conflicts:**
```powershell
cd d:\rawrxd
grep -n "class SpeculativeInferenceEngine" src/core/*.cpp src/core/*.hpp
# Should only appear in speculative_inference_engine.cpp after stub removal
```

#### Step 3: Rebuild
```powershell
ninja -C build RawrXD-Win32IDE
```
**Checkpoint:** Zero linker errors. `SpeculativeInferenceEngine` symbols resolve to real implementation.

#### Step 4: Standalone Certification
Create `test_speculative_standalone.cpp`:
```cpp
#include "speculative_inference_engine.hpp"
#include <cstdio>

int main() {
    auto* engine = SpeculativeEngine_Create(4);  // 4GB arena
    if (!engine) { printf("FAIL: create\n"); return 1; }

    int prompt[] = {1, 2, 3};  // dummy token IDs
    int output[32] = {0};
    int generated = SpeculativeEngine_Generate(engine, output, 32, prompt, 3, 16, 0.8f);

    printf("Generated %d tokens\n", generated);
    printf("TPS: %.2f\n", SpeculativeEngine_GetTPS(engine));
    printf("Acceptance: %.2f%%\n", SpeculativeEngine_GetAcceptanceRate(engine) * 100);

    SpeculativeEngine_Destroy(engine);
    return generated > 0 ? 0 : 1;
}
```

Build and run:
```powershell
cl.exe test_speculative_standalone.cpp /I d:\rawrxd\src\core /link /OUT:test_speculative.exe
.\test_speculative.exe
```
**Checkpoint:** Outputs tokens, TPS > 0, acceptance rate reported.

#### Step 5: Wire into Deep2 Generation
Modify `src/deep2/Deep2APIServer_Complete.cpp`:

In `CompleteAPIServer::handleGenerate()`, replace or augment:
```cpp
// Current:
response = engine_->generateText(prompt, 256);

// Future (Day 3):
// if (speculativeEnabled_) {
//     response = engine_->generateTextSpeculative(prompt, 256);
// } else {
//     response = engine_->generateText(prompt, 256);
// }
```

**Note:** The exact integration point depends on whether `Deep2Engine` gets a speculative adapter or the API server calls both engines. **Design this on Day 3, not now.**

#### Step 6: A/B Benchmark
```powershell
# Run A: Normal Deep2
# (baseline from Day 2)

# Run B: Deep2 + Speculative
# (after wiring)
```

Compare:
| Metric | Normal | Speculative | Delta |
|--------|--------|-------------|-------|
| Decode TPS | XX | XX | +XX% |
| Acceptance rate | N/A | XX% | — |
| VRAM overhead | XX GB | XX GB | +XX GB |

---

## 6. Appendix — Exact Commands Reference

### Build (Full)
```powershell
cd d:\rawrxd
$env:PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64;" + $env:PATH
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DRAWRXD_BUILD_WIN32IDE=ON
ninja -C build RawrXD-Win32IDE
```

### PE Verify
```powershell
cd d:\rawrxd\build
dumpbin /headers RawrXD-Win32IDE.exe > pe_headers.txt
dumpbin /imports RawrXD-Win32IDE.exe > pe_imports.txt
dumpbin /exports RawrXD-Win32IDE.exe > pe_exports.txt
```

### API Test (PowerShell)
```powershell
function Test-Deep2API {
    param([string]$Uri = "http://127.0.0.1:11436", [string]$Method = "GET", [string]$Path = "/health", [string]$Body = "")
    $url = "$Uri$Path"
    if ($Body) {
        Invoke-RestMethod -Uri $url -Method $Method -Body $Body -ContentType "application/json"
    } else {
        Invoke-RestMethod -Uri $url -Method $Method
    }
}

Test-Deep2API -Path "/health"
Test-Deep2API -Path "/status"
Test-Deep2API -Path "/api/tags"
Test-Deep2API -Method POST -Path "/api/model/load" -Body '{"name":"test.gguf"}'
Test-Deep2API -Method POST -Path "/api/generate" -Body '{"prompt":"Hello"}'
```

### Git State Verify
```powershell
cd d:\rawrxd
git status
git log --oneline -5
git diff HEAD --stat
# Expected: clean working tree, HEAD at fc02d546f
```

---

## 7. Appendix — Known Blockers & Risks

| Blocker | Impact | Mitigation |
|---------|--------|------------|
| `createPrimarySidebar()` crash (`0xC0000409`) | Win32IDE GUI won't start | Use `:11436` API for inference testing independently of GUI |
| No standalone Deep2 server target | Inference tied to IDE binary | Verify if `deep2_server_main.cpp` builds as separate exe; if not, use IDE binary headlessly |
| Speculative engine not in CMake | Cannot test speculative without source mod | **Intentional** — Day 3 task |
| R9700 driver readiness | Unknown on new motherboard | Install latest Adrenalin before any GPU inference test |
| 128GB RAM XMP stability | System instability if XMP fails | Test with MemTest86 before heavy inference loads |

---

## 8. Sign-Off

This plan was generated on **2026-08-14** before the X870E TAICHI + R9700 build.

**Pre-wipe verification:**
- [ ] GitHub push verified: `pre-wipe-local-main-20260813-v2` contains `56adf109d`
- [ ] External SSDs unplugged
- [ ] This file committed to repo
- [ ] `DISASTER_RECOVERY_CERTIFICATION.md` preserved

**Post-wipe first action:**
1. Install Windows + VS2022 Enterprise
2. Install CMake + Ninja
3. Clone `RawrXD-IDE-Final`
4. `git checkout fc02d546f`
5. Follow Day 1 steps above

---
*End of plan.*
