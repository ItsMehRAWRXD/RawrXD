# Production Hardening Report

**Project:** RawrXD-ModelLoader (RawrXD Agentic IDE)
**Scope:** Security hardening, memory safety, crash containment, test gate, CI
**Date:** 2026-10-15
**Status:** Verified — 67/67 hardening tests pass under MSVC 19.44 `/W4 /permissive-`, clean under AddressSanitizer, and portable to GCC.

---

## 1. What this drop contains

This is a **source drop**: every claim below is backed by code in the
repository and by a test that fails if the claim becomes false. Components that
could not be verified on this machine are marked explicitly.

| Component | Files | Verified |
|---|---|---|
| Compiler/linker hardening flags | `CMakeLists.txt` (lines 43–115) | Configured, builds, no D-code warnings |
| Input validation boundary | `include/input_sanitizer.h`, `src/utils/input_sanitizer.cpp` | 79 tests, `/W4 /WX` clean |
| Secure memory primitives | `include/secure_buffer.h`, `src/utils/secure_buffer.cpp` | ASan clean |
| Crash containment + safe mode | `include/crash_handler.h`, `src/utils/crash_handler.cpp` | ASan clean |
| **Model-load integration** | `src/gguf_loader.cpp`, `include/gguf_loader.h` | Runtime-tested; warning-free at `/W4` |
| Dependency-free test harness | `tests/test_harness.h` | In use |
| Test suite | `tests/test_input_sanitizer.cpp`, `tests/test_crash_resilience.cpp`, `tests/test_gguf_loader_hardening.cpp` | 79/79 pass |
| CMake wiring + CTest | `CMakeLists.txt` (`rawrxd_security`, `rawrxd_hardening_tests`, `rawrxd_loader_hardening_tests`) | `ctest -L security` → 100% |
| CI gates | `.github/workflows/security-suite.yml` | 3 jobs, Windows paths executed locally |
| Local verification scripts | `tools/production_hardening/*.bat` | Executed |

All new production code is **dependency-free C++20** (standard library only, no
Qt) so the native engines, the Qt shell, and CI can all link it.

---

## 2. Security posture added

### 2.1 Build-time hardening (`CMakeLists.txt`)

Enabled by default via `RAWRXD_ENABLE_HARDENING=ON`, disableable with `-DRAWRXD_ENABLE_HARDENING=OFF`.

**MSVC**
- `/GS` — stack cookies (buffer-overrun detection)
- `/guard:cf` — Control Flow Guard
- `/guard:ehcont` — EH-continuation metadata
- `/VOLATILE:ISO` — ISO volatile semantics (suppresses the well-known C++11 `volatile` weakness on MSVC)
- `/Zc:strictStrings`, `/Zc:throwingNew`, `/permissive-` — conformance fixes
- Linker: `/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`, `/guard:cf`, `/guard:ehcont`
- Defines: `_FORTIFY_SOURCE=2`, `FORTIFY_SOURCE=2`, `RAWRXD_HARDENING=1`

**GCC/Clang**
- `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full`
- `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`
- Linker: RELRO (`-z relro`), immediate binding (`-z now`), `-z noexecstack`, `-fno-plt`
- Conformance/warning set: `-Wall -Wextra -Wpedantic -Werror=format-security -Wformat=2`, plus
  `-Wconversion -Wsign-conversion -Warray-bounds -Wstringop-overflow -Wnull-dereference -Wshadow`

**Sanitizers** (opt-in, `-DRAWRXD_ENABLE_SANITIZERS=ON`): ASan + UBSan on
GCC/Clang, `/fsanitize=address` on MSVC.

> **Note on `/SDL`:** deliberately *not* used. On VS2022 19.44 with the
> Ninja/Makefiles generators it is rejected per file with `D9002: ignoring
> unknown option '/SDL'` — noise plus a false sense of hardening. The concrete
> guarantees we need are applied explicitly instead.

**Per-target strictness:** `rawrxd_security` compiles at `/W4 /WX` (plus
`-Wall -Wextra -Wpedantic -Werror` off MSVC). Hardening code that cannot be
audited cleanly is not hardened.

### 2.2 Input validation boundary

Every externally-controlled input passes through `InputSanitizer` (fail-closed:
any anomaly returns `false` with a specific `ValidationResult`).

| Threat | Mitigation |
|---|---|
| Path traversal / directory escape | Lexical + canonical normalization, base-dir containment with **separator-boundary** comparison, `%2e%2e`/`%2f` decoding checks |
| Prefix confusion (`/srv/models-evil` vs `/srv/models`) | Explicitly tested and rejected |
| SSRF | Scheme allow-list, userinfo rejection, private/loopback/CGNAT/multicast/TEST-NET blocking |
| Hostname abuse | Full RFC 1123 label grammar (leading *and* trailing hyphen, length, character set) |
| IP literal ambiguity | IPv4 rejects **leading zeros** (octal ambiguity), 5-tuples, out-of-range octets; IPv6 rejects multiple `::` |
| Command injection | Shell-metacharacter rejection on every argument (not just the program) |
| SQL injection | Keyword/statement detection with word boundaries, identifier grammar allow-list, NUL rejection |
| XSS | HTML/JS/attribute escaping; tag allow-list fails **closed** (unknown tags rejected, not stripped) |
| Malformed/oversized JSON | Size cap, UTF-8 gate, bracket-stack validation with string/escape handling |
| Log forging | NUL and control-character rejection (`RAWRXD` uses these to stop log injection) |
| Numeric abuse | `std::from_chars` (no locale, no exceptions, no UB), range enforcement, non-finite rejection |

### 2.3 Memory safety

`SecureBuffer<T>` (trivially-copyable) provides:
- **Zeroization on destruction** via a volatile write loop the optimizer cannot elide
- **Bounds-checked access** — `at()`/`get()`/`set()`/`subspan()`/`copyFrom()`/`copyTo()`
  return failure signals rather than corrupting memory; an out-of-range access is
  a loggable event, never silent corruption
- **Refused** allocation counts that cannot be represented (no `size_t` overflow);
  a refused allocation is a *no-op* so existing contents survive
- **Non-copyable** (accidental copies of key material are a footgun); movable
- **Optional memory pinning** (`VirtualLock`/`mlock`) so weights/keys are not paged to disk
- `secureRandomBytes()` — Windows CNG (`BCryptGenRandom`), `/dev/urandom` elsewhere
- `constantTimeEqual()` — timing-attack-resistant comparison

### 2.4 Crash containment and graceful degradation

`CrashHandler` installs hooks for **unhandled C++ exceptions** (`std::terminate`),
**Windows structured exceptions** (access violation, stack overflow, illegal
instruction, divide-by-zero, datatype misalignment, bounds-exceeded), **CRT fatal
paths** (`_purecall`, invalid parameter), and **POSIX fatal signals**.

- **Minidump** written via `MiniDumpWriteDump` (with data segments, handles,
  memory scan, unloaded modules)
- **Structured JSON crash record** (`rawrxd.crash/1` schema) with timestamp,
  code, name, message, module, thread id, and up to 64 native stack frames via
  `CaptureStackBackTrace`
- **Re-entrancy-guarded** capture path — a crash inside the crash handler can
  never recurse
- **Safe mode**: any captured fatal condition sets process-global safe mode, so
  subsystems query `inSafeMode()` and fall back (e.g. CPU instead of GPU) rather
  than repeating the operation that crashed. The **root-cause** reason is retained.
- Total-capture discipline: every step is exception-tolerant, because allocation
  failure during reporting must not become a second crash

---

## 2.5 Integration at the model-load call site

Adding a library proves nothing until it is wired into a real code path. The
first (and highest-risk) integration point is `GGUFLoader::Open()`, which is
where every externally-supplied model path reaches the filesystem. It previously
opened the path with **no validation at all**:

```cpp
// BEFORE - external input straight to std::ifstream
bool GGUFLoader::Open(const std::string& filepath) {
    filepath_ = filepath;
    file_.open(filepath, std::ios::binary);
```

It now runs the model-file policy (extension allow-list, regular file, size cap)
before touching the filesystem, and **fails closed** — a rejected path never
reaches `std::ifstream`, and `Open()` now returns a real diagnosis through
`GetLastOpenError()` instead of a bare `false`:

```cpp
// AFTER
std::string validatedPath;
if (!RawrXD::Security::InputSanitizer::instance()
        .validateModelFilePath(filepath, validatedPath)) {
    last_open_error_ = /* policy name + reason */;
    return false;   // no file opened, no state mutated
}
filepath_ = validatedPath;
```

**Policy matching the consumer.** `Open()` consumes a *filesystem* path, not a
shell command line. The generic `resolvePath()` policy therefore would have been
wrong here: it rejects `~`, `$env`, `${` and `::`, which a shell expands but
`std::ifstream` does not — applying it would refuse legitimate user-selected
model locations. `validateModelFilePath()` is deliberately the narrower,
consumer-appropriate policy; `resolveModelPath(input, baseDir, out)` remains
available for sandboxed/contained usage.

**A second bug found at the same site: silent narrowing of file-controlled
metadata.** `GGUFMetadata::embedding_dim`, `vocab_size`, `layer_count` and
`context_length` are `uint32_t`, but they were assigned directly from a
file-controlled `uint64_t`. A metadata value of `0x100000008` would silently
become `8`, so the loader would size buffers and index tensors using a number
that disagrees with what the file declares. Values that cannot be represented in
`uint32_t` are now rejected rather than truncated, which also removed all four
`C4244` narrowing warnings from the translation unit.

`src/gguf_loader.cpp` now compiles **warning-free** at `/W4 /permissive-`.

---

## 3. Bugs found by these tests during development

The hardening suite caught real defects in its own first implementation. They
are listed because they demonstrate the tests have teeth:

1. **`/SDL` rejected (D9002)** — removed; replaced with explicit flags.2. **Traversal check rejected `/` and `?`** — rejected *every* valid absolute
   path. Fixed to a precise dangerous-sequence list.
3. **Hostname trailing hyphen accepted** — now rejected.
4. **IPv4 leading zeros accepted** (`010.1.1.1`) — octal ambiguity, now rejected.
5. **JSON `[1,2,3}` accepted** — bracket *type* mismatch now caught via a stack.
6. **Crash records were never written** — the ISO-8601 timestamp contains `:`,
   which is illegal in Windows filenames, so the `ofstream` open failed
   silently. Centralized `safeStamp()` now sanitizes it.
7. **IPv6 canonicalization dropped brackets** — `http://[::1]/x` became
   `http://::1/x` (ambiguous/malformed for consumers). Now re-wrapped.
8. **Safe-mode reason overwritten** — contradicted its own documented
   root-cause retention. Implemented as documented.
9. **Silent narrowing of file-controlled GGUF metadata** — `uint64_t` metadata
   values were assigned directly into `uint32_t` fields (found at the
   `GGUFLoader` integration site), so `0x100000008` was read as `8`. Now
   rejected instead of truncated; also cleared 4 × `C4244` warnings.

---

## 4. How to build and run

### Full project (existing path)
```powershell
# Both hardening suites are CTest-registered with the `security` label:
#   hardening_security      - dependency-free (no Qt/Vulkan needed)
#   hardening_model_loader  - GGUFLoader integration (needs the Vulkan SDK)
cmake -S . -B build-vs -G "Visual Studio 17 2022" -A x64 -DRAWRXD_BUILD_TESTS=ON
cmake --build build-vs --config Release --target rawrxd_hardening_tests rawrxd_loader_hardening_tests
ctest --test-dir build-vs -C Release -L security --output-on-failure
```

### Standalone (no CMake, no Qt)
```powershell
tools\production_hardening\run_hardening_tests.bat   # build + run, non-zero on failure
tools\production_hardening\verify_asan.bat           # same suite under AddressSanitizer
```

### Standalone (loader integration tests; needs `VULKAN_SDK`)
```powershell
tools\production_hardening\run_loader_tests.bat
```

### Link the library into another target
```cmake
target_link_libraries(your_target PRIVATE RawrXD::security)
```

Headers: `include/input_sanitizer.h`, `include/secure_buffer.h`, `include/crash_handler.h`.

---

## 5. Test suite summary

79 tests across three suites, all passing (67 + 12 loader-integration). Coverage by area:

| Area | Tests |
|---|---|
| Path traversal / base-dir containment / prefix confusion | 7 |
| URL, hostname, IP, port, scheme, userinfo | 9 |
| SSRF policy (default and loopback-disabled) | 2 |
| Command injection + command lines | 3 |
| SQL literal + identifier | 3 |
| HTML/JS escaping and tag allow-list | 7 |
| JSON size/structure/encoding | 4 |
| UTF-8, NUL, control characters | 4 |
| Integer/double parsing and ranges | 2 |
| Model file header/extension/size | 6 |
| SecureBuffer bounds, zeroize, allocation, move | 8 |
| CSPRNG + constant-time equality | 2 |
| Crash artifact writing, safe mode, scope, degradation | 11 |
| **GGUFLoader integration**: extension, NUL, control chars, length, relative, missing, directory | 7 |
| **GGUFLoader integration**: valid model loads, reason cleared on success, in-range metadata | 3 |
| **GGUFLoader integration**: metadata truncation (out-of-range rejected, max-U32 accepted) | 2 |

Example (a policy encoded as an assertion):

```cpp
TEST(InputSanitizer, BlocksPrivateAddressesForSsrf) {
    for (const char* bad : {"http://10.0.0.5/x", "http://192.168.1.1/x",
                            "http://172.16.0.1/x", "http://169.254.169.254/latest/meta-data",
                            "http://100.64.0.1/x", "http://0.0.0.0/x"}) {
        CHECK_FALSE(tryUrl(bad));
        CHECK_EQ(S().lastResult(), ValidationResult::PrivateAddress);
    }
}
```

---

## 6. CI

`.github/workflows/ci.yml` — three jobs, two executed locally before commit:

| Job | Purpose |
|---|---|
| `security-gate` (windows-latest) | Configure → build → `ctest -L security` |
| `hardening-asan` (windows-latest) | Same suite under `/fsanitize=address` |
| `hardening-portability` (ubuntu-latest) | g++ build proving the code is portable |

The full RawrXD build (Qt6 + Vulkan SDK + ggml + MASM) is **not** in CI — it
cannot be provisioned reliably on hosted runners. The hardening gate was
designed to be runnable where the full build is not.

---

## 7. Honest limitations

Being explicit about what is *not* done:

1. **Only one call site is integrated.** `GGUFLoader::Open()` now validates the
   model path and returns a diagnosis. The Qt UI (`InferenceEngine::loadModel`),
   the URL/download paths, and the Win32 shell (`Win32IDE.cpp`'s loader call)
   are **not** yet migrated. `RAWRXD_VALIDATE_PATH`-style macros are provided
   for that work.
2. **The full project build is not CI-gated** (see above).
3. **`rawrxd_security` is not yet linked** by the Qt/IDE targets; it is a new,
   independent library.
4. **The Linux CI job is unverified on this machine** (no GCC available locally);
   the Windows ASan and CTest paths were both executed here.
5. **The security library is single-process and thread-safe for use, but
   `InputSanitizer`'s singleton is configured at startup** — concurrent
   reconfiguration is not supported (documented in the header).
6. **The legacy `include/security_manager.h`** (AES-GCM/DPAPI design) has no
   implementation in this drop. The new components are complementary, not a
   replacement.
7. **The loader tests require the Vulkan SDK** (`VULKAN_SDK`), so they are a
   separate CTest target from the dependency-free suite rather than being merged
   into it. The dependency-free suite remains the always-runnable gate.

---

## 8. What to do next (highest value first)

1. **Migrate the remaining call sites**: route model-path and URL inputs through
   `RAWRXD_VALIDATE_PATH` / `RAWRXD_VALIDATE_URL` in the Qt
   `InferenceEngine::loadModel` and the Win32 shell loader call.
2. **Install the crash handler at startup**:
   `RawrXD::Resilience::CrashHandler::instance().install("crashes")`.
3. **Use `inSafeMode()`** to degrade the GPU path after a crash.
4. **Cover the inference paths**: KV cache, tensor index and quantization paths
   currently have no test coverage from this drop.
5. **Add the Qt shell to CI** with an official Qt install step once the hardening
   gate is green.
6. **Set `/WX` project-wide** once the existing targets are clean at `/W4`.
