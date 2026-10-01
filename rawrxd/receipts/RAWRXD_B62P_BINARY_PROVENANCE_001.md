# RAWRXD_B62P_BINARY_PROVENANCE_001

## Purpose

Tie every measured number to a specific binary hash and a specific source
revision. Prior measurements in this session were taken against a binary that
was subsequently renamed out from under the test, so they are not source-level
certification until this receipt exists.

## Status: PASS (provenance captured, hash stable across the run)

```
GIT_HEAD              = 9b843bf039f917040d1c7aeae4eaa3aea090870d
GIT_BRANCH            = model-correctness
WORKING_TREE_DIRTY    = 98 entries
EXE                   = F:\~dev\rawrxd\build\bin\Release\rawrxd.exe
EXE_SIZE              = 1151488
EXE_CREATED_UTC       = 2026-10-01T18:16:40.9131593Z
EXE_WRITTEN_UTC       = 2026-10-01T18:20:40.5600705Z
EXE_SHA256_PRE_RUN    = 0DDD16E41789B302256C0E79A7654569ED3DFFC5BA95ECF40125B44FE9CEF95E
EXE_SHA256_POST_RUN   = 0DDD16E41789B302256C0E79A7654569ED3DFFC5BA95ECF40125B44FE9CEF95E
HASH_STABLE_ACROSS_RUN = 1
```

## The rename event

```
rawrxd.exe      -> RENAMED to rawrxd_old.exe by another session's shell
rawrxd_old.exe  SHA256 = 82154D2CB0D4299148F73AC01D6817E842292C2C3D42A697CA872863FAF9C25C
                  SIZE   = 1149952
                  CREATED_UTC = 2026-10-01T18:13:52Z
rawrxd.exe      SHA256 = 0DDD16E41789B302256C0E79A7654569ED3DFFC5BA95ECF40125B44FE9CEF95E
                  SIZE   = 1151488
                  WRITTEN_UTC = 2026-10-01T18:20:40Z
```

`82154D2C...` (old) != `0DDD16E4...` (current). These are DIFFERENT BINARIES,
not a copy. The other session rebuilt after renaming. No reference to
`rawrxd_old` exists anywhere in the repository (grep: 0 matches), so the rename
is an ad-hoc shell action, not a scripted or declared artifact step.

HEAD also advanced during the session: `54c1edc44` -> `9b843bf039`.

## Consequence for prior measurements

The earlier 11.56 TPS mean and 0.81 TPS were measured on `82154D2C...`
(`rawrxd_old.exe`), not on the binary now at the canonical path. Those numbers
are valid measurements OF THAT BINARY but must not be cited against current
HEAD. They are re-measured below on `0DDD16E4...`.

## Re-measured on 0DDD16E4 (this receipt)

Vulkan active: `BATCH9_VK_DEVICE ordinal=0 name=AMD Radeon AI PRO R9700
vram=34208743424 compute_pipeline=1`

### tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf (Q4_K_M, type 12), --tokens 32

```
ITERATIONS            = 4
CLEAN_EXITS           = 4
NONZERO_EXITS         = 0
TEARDOWN_FAULT        = 0
TPS_MEAN              = 11.44
TPS_MIN               = 11.20
TPS_MAX               = 11.77
ENSURE_F32_STREAM     = 0
```

### llama3.2-3b-Q2_K.gguf (Q2_K, type 11), --tokens 32

```
PROMPT_TOKENS         = 5
GENERATED_TOKENS      = 32
EXIT                  = 0
PREFILL_MS            = 10652.5
DECODE_MS             = 54508.5
DECODE_TPS            = 0.59
ENSURE_F32_STREAM     = 3024
```

## The preserved A/B control

```
                          Q4_K_M (1.1B)    Q2_K (3B)
ENSURE_F32_STREAM         0                3024
DECODE_TPS                11.44            0.59
```

This is the regression pair. Q4_K_M avoids the pathological event entirely;
Q2_K triggers it once per (layer, weight, token). Preserved as the permanent
control for B63: if the prepared-weight cache is correct, the 3024 must
collapse toward once-per-weight BEFORE any TPS number is worth discussing.

## Source state of the fixes under test

```
 M rawrxd/CMakeLists.txt                        (adds rawrxd_cpu_math.cpp TU)
 M rawrxd/src/deep2/Deep2Engine.cpp             (EOS underflow + transport lifetime)
 M rawrxd/src/win32app/cli_main_headless.cpp    (SEH fence C2712 restructure)
?? rawrxd/src/rawrxd_cpu_math.cpp               (untracked; implements rawrxd::cpu::*)
```

Working tree has 98 modified/untracked entries, most belonging to concurrent
sessions. The four files above are the ones this workstream changed.

## Standing rule adopted

Any future run in this workstream records, before and after:

1. `Get-FileHash <exe> -Algorithm SHA256`
2. `git rev-parse HEAD`
3. `git status --short` for the touched files

If the path vanishes, the hash changes, or the file becomes `*_old.exe`, the
run is invalidated rather than following the renamed artifact.

## Open

- B62C: duplicate `rawrxd` target definitions at `CMakeLists.txt:303` and
  `:13971`. With `RAWRXD_BUILD_CLI=OFF` in the active cache, only `:13971`
  generates the target; a fix added to `:303` is silently inert. This already
  cost one wasted build cycle.
- B62P-RENAME: identify and control whatever renames the artifact path.