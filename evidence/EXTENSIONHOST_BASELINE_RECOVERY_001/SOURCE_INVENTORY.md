# EXTENSIONHOST_BASELINE_RECOVERY_001 — source inventory

Status: `PREPARATION_ONLY` · read-only investigation. No source tree was modified.

## Authority

- Primary: `G:\~dev\rawrxd`
- Candidate: `G:\~dev\rawrxd-ext-candidate`
- Candidate HEAD: `273924f9f4b0d75ed770559da448164ec632ce00`
- Frozen SHA-256: `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`

## Materialization result

The candidate filesystem initially appeared to lack the runtime files, but Git inspection shows all required runtime files are already present in the candidate HEAD tree. The candidate worktree is not clean/materialized: `git status --untracked-files=no` reports approximately **301,819** tracked changes, including deletions, and `core.sparseCheckout=true` is set.

This is a worktree materialization conflict, not proof that the committed candidate baseline lacks ExtensionHost source. It is unsafe to extract files from the dirty primary until the candidate worktree is repaired or recreated from the same commit with a known-good checkout configuration.

## Runtime closure present in candidate HEAD but absent from candidate filesystem

| File | Candidate Git tree | Candidate filesystem | Primary provenance |
|---|---|---|---|
| `src/win32app/ProductExtensionRuntime.hpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Internal.hpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_State.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Util.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Scan.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Manifest.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Host.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Toggles.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Activate.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ProductExtensionRuntime_Api.cpp` | present | absent | tracked at `e61f51a86b` |
| `src/win32app/ExtensionHostWorker_main.cpp` | present | absent | tracked at `e61f51a86b` |

The parent of candidate HEAD also contains this closure, so these are not untracked primary-only files.

## Related integration files

The candidate Git tree also contains `CMakeLists.txt`, `Win32IDE_LocalServer.cpp`, `HeadlessIDE_GuiRoutes.cpp`, `HeadlessIDE_ToolRoutes.cpp`, and `ProductGuiRouteAdapters.hpp`. The working-tree deletion/untracked state prevents treating their filesystem contents as a clean candidate source baseline.

