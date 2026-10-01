# RAWRXD_B69_BUILD_AUTHORITY_CLEANUP_001

## Scope

Build-system authority defects found while executing B65-B67. Three items:
the duplicate CMake target, the dead Q3_K MASM stub, and the artifact rename.

```ini
RAWRXD_B69_BUILD_AUTHORITY_CLEANUP_001=PASS
```

## 1. Duplicate `rawrxd` target — now fatal unless acknowledged

The `rawrxd` executable is defined twice in `CMakeLists.txt`:

| Definition | Line | Guard | Active? |
|---|---|---|---|
A | ~328 | `if(RAWRXD_BUILD_CLI)` | NO — cache has `RAWRXD_BUILD_CLI=OFF` |
B | ~14075 | `if(NOT TARGET rawrxd)` | YES |

Which one owns the target depends on a cache option, so a source fix applied to
the inactive block compiles nothing and appears to work. That has bitten three
times: the missing `rawrxd_cpu_math.cpp` TU at B63, and the `q3k_block_diff`
target that silently failed to generate a vcxproj.

Full census of the file: **320+ target definitions, 17228 lines**, with
`q4k_gemv_parity` also duplicated (~729 inert / ~17141 active).

Fixes applied:

- Definition A now raises `FATAL_ERROR` unless
  `-DRAWRXD_B62C_ACK_DUPLICATE_RAWRXD_TARGET=ON` is passed, naming both
  locations and the consequence. The ambiguity is no longer silent.
- Definition B emits a configure-time receipt naming itself as canonical:

```
-- [RAWRXD_B62C_CMAKE_AUTHORITY_001] `rawrxd` owned by line ~14075
   (NOT TARGET rawrxd); duplicate definition at line ~328 is INACTIVE
   (RAWRXD_BUILD_CLI=OFF). Do not add source fixes to the inactive block.
```

Consolidation to a single definition is still outstanding; the guards make the
duplication loud instead of quiet.

## 2. Dead Q3_K MASM stub — removed

`rawrxd/src/deep2/sovereign_q3_k_gemv.asm` was 8 lines:

```asm
sovereign_q3_k_gemv_Stub PROC
    xor eax, eax
    ret
sovereign_q3_k_gemv_Stub ENDP
```

It was compiled into the build (`CMakeLists.txt:13275`) and exported
`sovereign_q3_k_gemv_Stub`. Its only would-be caller, `gemv_q3_k_masm`
(`QuantKernelRegistry.cpp:175`), expected a symbol named `Deep2_Q3_K_GEMV` that
the stub never exported — a link error had it been registered.

It was never registered: grep for `gemv_q3_k_masm` returned exactly one hit, its
own definition. Q3_K resolves to `gemv_q3_k_scalar` (line ~1937), which is the
reference the B65 block-parity gate was measured against.

Deleted:

```ini
sovereign_q3_k_gemv.asm        removed from CMake source list
gemv_q3_k_masm wrapper         deleted (QuantKernelRegistry.cpp)
Deep2_Q3_K_GEMV extern        deleted (QuantKernelRegistry.cpp)
```

All three were dead. Removing them eliminates a trap: a stub named like a real
kernel looks like an implementation and silently is not one. Implementing a
Q3_K MASM kernel is a separate decision and is not warranted while the verified
scalar reference and the GPU native path both exist.

Verified no behavior change:

```ini
EXE_SHA256_PRE  = 354170570D9DA0C4042CC41667FAD91D8882734A4CDE858BD770BDA5A91235AD
EXE_SHA256_POST = 354170570D9DA0C4042CC41667FAD91D8882734A4CDE858BD770BDA5A91235AD
BUILD_EXIT      = 0
DECODE_TPS      = 6.46
TEXT            = "Paris, which is also the capital of France. The city of Paris
                   is famous for its beautiful gardens, beautiful parks,"  (115 chars)
B69_PARITY      = B65_EXACT
```

## 3. Artifact rename — NOT a repository defect

`rawrxd.exe` was observed renamed to `rawrxd_old.exe` mid-session, invalidating
in-flight measurements. Investigated:

```ini
build/ GITIGNORE           = ignored (.gitignore:8 "build*/")
repo reference to rawrxd_old = 0 matches
CMakeLists.txt rename logic  = none
*.bat / *.ps1 rename logic   = none
git history -S rawrxd_old    = no commit introduces it
```

The rename is not performed by anything in the repository. `build/` is entirely
untracked, so it is not in git history at all. The conclusion is that the
artifact path is being managed outside version control — most likely by another
concurrent session's shell or tooling — and therefore cannot be controlled or
audited from inside this repository.

```ini
B62P_RENAME_REPO_CULPRIT=NOT_FOUND
B62P_RENAME_IN_REPO_CONTROL=NO
MITIGATION=hash the binary before and after every run and invalidate on change
```

The mitigation is procedural rather than a fix, and it has been applied to every
measurement in B62P through B67: `EXE_SHA256_PRE` and `EXE_SHA256_POST` recorded
per run, run invalidated if they differ or if the path disappears.

## Cross-cutting finding: authority is never self-establishing

Three items in this receipt share one shape. Source exists; execution authority
does not follow.

```ini
rawrxd (definition A)      valid CMake, unreachable with default cache
sovereign_q3_k_gemv.asm    compiled, exports the wrong symbol, called by nothing
rawrxd_old.exe             real binary at a path the repo does not govern
```

Each looked correct from source alone and was wrong in execution. The general
rule this supports: for any gate, a definition's presence does not establish that
it executes. Receipts must record what actually ran, with hashes, or the gate is
measuring nothing.

## Also observed

A concurrent session's temporary MASM instrumentation
(`RAWRXD_MASM_SCALE_PROBE_001`, writing to a `scale_probe` buffer that was
referenced but never defined) broke the build at 15:23 with
`error A2006: undefined symbol : scale_probe`. It resolved itself when that
session completed the probe. Not this work's defect, and not repaired here;
recorded because it is the second occurrence of a concurrent session breaking
the shared build within one session.

## Not committed

```ini
B69_COMMITTED=NO
B69_PUSHED=NO
```