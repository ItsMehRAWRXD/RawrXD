# RAWRXD_B82_IDE_LINK_AND_P0_FALSE_PASS_RECEIPT

    GATES   = RAWRXD_IDE_CMAKE_FULL_AUDIT_001 (section E, link rows)
              RAWRXD_P1_FALSE_PASS_RENAME_001
              RAWRXD_P1_FALSE_PASS_GOTO_DEFINITION_001
    DATE    = 2026-10-01
    HEAD    = 3777093876
    VERDICT = PASS for the link gate; two false passes REPAIRED and linked

---

## 1. The IDE link was blocked, not broken

`cmake --build . --target RawrXD-Win32IDE` failed at **configure**, before any
compiler or linker ran:

```
CMake Error at cmake/RawrAgenticCliQuarantine.cmake:32 (message):
  BUILD_RAWRXD_AGENTIC_CLI references a QUARANTINED phantom source set.
    63 declared sources: 0 exist. 25 declared cert targets: 0 exist.
  Configuring incomplete, errors occurred!
```

The quarantine file is correct and deliberate — it exists precisely to stop a
phantom 63-source agent stack from configuring as if it were real. The option
defaults `OFF`:

```cmake
option(BUILD_RAWRXD_AGENTIC_CLI "QUARANTINED: ..." OFF)
if(BUILD_RAWRXD_AGENTIC_CLI)
  message(FATAL_ERROR ...)
```

Root cause: `build_ide_audit/CMakeCache.txt` held a **stale `ON`** from before
the quarantine was introduced.

```ini
BUILD_RAWRXD_AGENTIC_CLI:BOOL=ON     <-- pre-quarantine value, persisted
```

So the guard was working correctly and the build tree was carrying a value that
no longer meant anything. Resolved with `cmake -DBUILD_RAWRXD_AGENTIC_CLI=OFF .`,
after which configure reported `Configuring done` / `Generating done`.

**This is a cache-hygiene defect, not a quarantine defect.** The guard was doing
its job.

## 2. Link evidence

```ini
BUILD_EXIT                     = 0
LINK_ERRORS                    = 0
COMPILE_ERRORS                 = 0
IDE_EXE_BYTES                  = 20782080
IDE_EXE_LASTWRITE_UTC          = 2026-10-01T21:04:36Z
IDE_EXE_SHA256_BEFORE_REPAIRS  = CF0122EDAF23F986FB2CF6C4F559873383C59DE432261C28D8A48C9E56A399A3
IDE_EXE_SHA256_AFTER_REPAIRS   = 41B9908ED1461F7A318D28173B237130D0327CFC3B7BCB783AFB62C4B1CFFED2
RAWRXD_DROPPED_SOURCE_TOTAL    = 225
```

The two hashes differ, which is the point: the binary provably contains the P1
repairs from section 3 rather than a cached earlier link.

### The 225 dropped sources are still dropped

```ini
RAWRXD_DROPPED_SOURCE_TOTAL = 225
```

Unchanged by any of this work. The link succeeds **with less code than the
source list implies**, and the build log now states that in one greppable line.
Configure is clean; the shipping surface is not. `-DRAWRXD_STRICT_SOURCES=ON`
would make this fatal, and is not enabled for the shipping configuration.

## 3. Two false-pass handlers repaired

Both were in `src/core/auto_feature_registry.cpp` and both are command handlers
wired into the IDE, so both were reachable at runtime.

### 3.1 `handleLspRenameSymbol` — claimed a rename, performed none

```cpp
if (found) {
    provider.rebuildIndex();
    snprintf(buf, sizeof(buf), "[LSP] Renamed '%s' -> '%s' (index rebuilt)\n", ...);
}
return found ? CommandResult::ok("lsp.renameSymbol") : ...;
```

No file was opened, no text was rewritten, no edit recorded. The handler
confirmed the symbol existed, rebuilt the index, and printed "Renamed".

Repaired to state what happened and fail:

```
[LSP] Symbol '<x>' located (<n> in index), but RENAME IS NOT IMPLEMENTED:
no source file was modified. Nothing was changed.
-> CommandResult::error("Rename not implemented", -2)
```

`rebuildIndex()` is no longer called, because rebuilding an index to support a
rename that did not happen is itself part of the false impression.

### 3.2 `handleLspGotoDefinition` — returned success on a miss

```cpp
snprintf(buf, ..., "[LSP] Symbol '%s' not found in index.\n", ctx.args);
ctx.output(buf);                              // told the user it FAILED
...
return CommandResult::ok("lsp.gotoDefinition");   // ...then returned SUCCESS
```

The no-argument branch additionally printed "Navigating to definition of symbol
at cursor…" and returned `ok` without reading a cursor — `CommandContext`
carries no cursor position, so that message asserted an action that had no
mechanism.

Also fixed: the match compared `sym.name == ctx.args` against the **entire**
argument string, so any trailing text made an otherwise valid symbol fail to
resolve. Now the first token is compared.

Repaired: missing argument is a usage error; a miss returns
`CommandResult::error("Symbol not found", -1)`.

## 4. Compile evidence

`src/core/auto_feature_registry.cpp` compiles clean with the project's own
settings (`/std:c++20 /O2 /arch:AVX512 /MD /EHsc /DNOMINMAX`),
`afr_check.obj` = 2438753 bytes, zero errors, and links into the IDE as shown by
the changed hash.

`NOMINMAX` is required. Without it the TU fails with `C2589` at
`RawrCodex.hpp:621` and `:1775` and in this file at `:1279` and `:3378` — all
pre-existing `min`/`max` macro collisions from `Windows.h`, unrelated to these
edits. The CMake targets already define it.

## 5. Extract Function — confirmed genuine gap

```ini
ExtractFunction = 0    ExtractMethod = 0    ExtractFunctionCommand = 0
extract_function = 0   ExtractToFunction = 0
```

Repo-wide, five spellings, zero hits. Unlike the two handlers above there is not
even a stub. Correctly deferred behind P0.

## 6. Explicitly NOT established

```ini
IDE_CLEAN_SHUTDOWN        = NOT_EXERCISED
IDE_SURFACES_RUNTIME      = NOT_EXERCISED
DIAGNOSTICS_RUNTIME       = UNPROVEN (interface only)
CODE_ACTIONS_RUNTIME      = UNPROVEN (interface only)
RENAME_IMPLEMENTED        = NO  (repair was to stop lying, not to implement)
DROPPED_SOURCES           = 225 (unchanged)
IDECore_Shutdown_CALLERS  = 0 (unchanged)
```

A linking binary is not a working IDE. Nothing in this receipt certifies a
surface, a clean shutdown, or that the repaired handlers were exercised at
runtime — only that they compile, link, and no longer report success for work
they do not perform.

## 7. Evidence index

| Artifact | Contents |
|---|---|
| `build_ide_audit/ide_build.log` | first successful IDE link, `EXIT=0` |
| `build_ide_audit/ide_build2.log` | relink containing the P1 repairs, `EXIT=0` |
| `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/IDE_POSITION_AND_NEXT_STEPS.md` | position and ordered next steps |
| `audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/P1_EDITOR_CODE_INTELLIGENCE_AUDIT.md` | repo-wide capability census |
| `receipts/RAWRXD_B81_CANONICAL_SWEEP_BUILD_001.md` | reproducible sweep build, incl. source-overwrite incident |