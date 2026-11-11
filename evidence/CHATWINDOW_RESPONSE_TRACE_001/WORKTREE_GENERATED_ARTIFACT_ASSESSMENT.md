# WORKTREE_GENERATED_ARTIFACT_ASSESSMENT

ASOF_UTC=2026-11-02T13:28:00Z
WORKTREE=F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef
AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
SOURCE_MUTATION=0

## Artifact

| Field | Value |
|-------|-------|
| Path | `src/deep2/shaders/deep2_qgemv.spv` |
| Present | YES (binary present; non-text) |
| Companion source | `src/deep2/shaders/deep2_qgemv.comp` (checked-in) |
| Build log | `CLEAN_TIP_BUILD.log` `[26/485] Compiling resident Deep2 Q4/Q6 GEMV shader` |

## Expected?

YES — expected build-side SPIR-V emit into the source tree.

`CMakeLists.txt` (~2067–2084) sets OUTPUT under `CMAKE_SOURCE_DIR/src/deep2/shaders/deep2_qgemv.spv` via glslc from `deep2_qgemv.comp`, with comment that resident Deep2 GEMV loads this SPIR-V at runtime.

An isolated clean worktree build therefore creates/updates `.spv` under the worktree → untracked porcelain even when HEAD matches (`worktree_untracked_count=1`, `CLEAN_TIP_WORKTREE_OK=false`).

## Affects compiled Native IDE product inputs?

| Question | Answer | Class |
|----------|--------|-------|
| Linked into EXE as a resource? | No evidence; runtime file load for Deep2 Vulkan | OBSERVED |
| Changed candidate EXE SHA? | EXE seal independent of regenerating `.spv` without relink | NOT_VERIFIED (no rebuild) |
| Caused ChatWindow RESPONSE_OK=0? | No — ChatWindow used Ollama HTTP, not Deep2 qgemv | OBSERVED |

## Disposition

Treat `.spv` as build-generated expected artifact, not KEEP_BRANCH WIP. Do not delete under this gate. Does not restore CLEAN_TIP_WORKTREE_OK without separate policy. ChatWindow failure is not attributed to this file.
