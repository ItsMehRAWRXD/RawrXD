# Provenance Clean-Tip Checklist

**Purpose:** Bind manifest and K2 certification evidence to an immutable commit SHA.  
**Current state:** Evidence certifies dirty worktree @ `1b10b29de3…` — incomplete provenance.

## Prerequisites

Commit all certification artifacts without modifying frozen baselines:

- `src/deep2/K2NativeStreamGate.{hpp,cpp}`
- `tests/k2_runtime_validation.cpp` (Gate 10/11 flags only — K2-008 untouched)
- `src/deep2/Deep2Bridge.{hpp,cpp}`, `Deep2Engine.{h,cpp}` (Gate 11 + UNREVERSE_HOTPATCH)
- `tools/screenpilot-manifest/*`
- `evidence/K2-*`, `evidence/P1_SCREENPILOT_MANIFEST_TRUTH_001/*`
- `evidence/K2-CERTIFICATION-LADDER-DISPOSITION.md`
- `BigDaddyG-Universal-Manifest-Generator.html` (consumer only)

## Clean-tip rerun sequence

```powershell
$repo = 'F:\~dev\rawrxd'
$shard = 'G:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M'
$exe = Join-Path $repo 'build-ninja\tests\k2_runtime_validation.exe'

# 1. Verify clean tree
git -C $repo status --porcelain   # must be empty

# 2. Record immutable SHA
git -C $repo rev-parse HEAD

# 3. K2 Gate 10 ×2
& $exe --run-generation --prompt hello $shard | Tee-Object (Join-Path $repo 'evidence\K2-008-PARTIAL-FORWARD-STREAM-PASS\gate10_clean_run1.log')
& $exe --run-generation --prompt hello $shard | Tee-Object (Join-Path $repo 'evidence\K2-008-PARTIAL-FORWARD-STREAM-PASS\gate10_clean_run2.log')

# 4. K2 Gate 11 ×2
& $exe --run-generation-deep2 --prompt hello $shard | Tee-Object (Join-Path $repo 'evidence\K2-GATE-11-DEEP2-NATIVE-STREAM-BRIDGE\gate11_clean_run1.log')
& $exe --run-generation-deep2 --prompt hello $shard | Tee-Object (Join-Path $repo 'evidence\K2-GATE-11-DEEP2-NATIVE-STREAM-BRIDGE\gate11_clean_run2.log')

# 5. Manifest + truth gate ×2
& (Join-Path $repo 'tools\screenpilot-manifest\Generate-ScreenPilotManifest.ps1') -RepoRoot $repo -OutPath 'F:\~dev\screenpilot-universal-manifest.json'
& (Join-Path $repo 'tools\screenpilot-manifest\Test-P1-ScreenPilot-Manifest-Truth-001.ps1') -RepoRoot $repo | Tee-Object (Join-Path $repo 'evidence\P1_SCREENPILOT_MANIFEST_TRUTH_001\run_clean1.log')
& (Join-Path $repo 'tools\screenpilot-manifest\Test-P1-ScreenPilot-Manifest-Truth-001.ps1') -RepoRoot $repo | Tee-Object (Join-Path $repo 'evidence\P1_SCREENPILOT_MANIFEST_TRUTH_001\run_clean2.log')
```

## Pass criteria

```text
gitDirty                         = false
K2_GATE_10                       = PASS (2/2, EXIT 0)
K2_GATE_11                       = PASS (2/2, EXIT 0)
P1_SCREENPILOT_MANIFEST_TRUTH    = PASS (10/10 ×2)
manifest.provenance.gitCommit    = HEAD SHA
manifest.provenance.gitDirty     = false
```

Update `K2-CERTIFICATION-LADDER-DISPOSITION.md` with clean SHA and log paths.

## Coherence path (independent — do not reopen G10/G11)

G12 scope: `evidence/K2-GATE-12-SCOPE.md`
