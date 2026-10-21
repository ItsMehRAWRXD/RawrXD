# RAWRXD_INTEGRATION_PRIORITY.md

**Companion to:** `RAWRXD_GITHUB_REUSE_AUDIT_001.md` · `RAWRXD_COMPONENT_PARITY_MATRIX.csv` · `RAWRXD_MISSING_IMPLEMENTATIONS.md`
**Revision:** 2 — after `RAWRXD_SOURCE_PRESERVATION_AND_PROMOTION_001`
**Date:** 2026-10-21

**Standing rule for every item below:** never overwrite newer local code because a GitHub version exists. `origin/main` does **not** contain the extension host, the native toolchain, or the linker source. Integrating from `origin/main` would delete working work.

---

## What this revision changed

The previous revision said the largest risk was missing infrastructure. It is not. The largest risk was **working implementations that exist outside the tracked tree**, and that risk has now been closed for the 82 files that were exposed.

| | Before | After |
|---|---|---|
| Untracked source files at risk | 43 under `src/`, plus 150 untracked QuickJS files | **0** — all tracked, plus a byte-verified external copy |
| Linker source | only in `_pre_merge_backup`, live tree had build outputs | promoted, tracked, and **certified 32/0 from a clean build of the tracked source** |
| Certification harness | aborted on its first linker invocation | fixed, and the suite now runs unattended |
| Extension runtime | untracked, unbuildable from the tracked tree | tracked with its QuickJS runtime and licence; **6/8 gates pass** |
| Compiler front end | reported ABSENT | **source recovered** on `origin/ci/win32ide-link-msbuild`; path is BLOCKED for a specific, named reason |
| Crucible | UNVERIFIED | **source recovered** and tracked |

---

## Completed

### ✅ P0.1 — Protect the untracked extension source

All 43 untracked source files under `src/` are committed on `preservation/source-baseline-20261021` (commit `715da05cd5`). A byte-verified external copy, with a SHA-256 per file, is at `F:\RawrXD_PRESERVATION_20261021` (82 files, 0 mismatches).

The exposure was larger than the seven files the audit named: the **whole** extension and marketplace subsystem was untracked — `js_extension_host`, `quickjs_extension_host`, `quickjs_vscode_bindings`, `quickjs_node_shims`, `extension_polyfill_engine`, `vscode_extension_api`, `extension_host_bridge`, `vsix_loader`, and the `marketplace/` tree.

### ✅ P0.2 — Restore the linker source to the live tree

The 22 source files were promoted from `_pre_merge_backup` into `toolchain/from_scratch/phase2_linker/`. The live build directory and the four stale binaries were left in place as the before-state evidence. Zero files overwritten; zero tracked files modified; zero deletions.

### ✅ P0.3 — Repair the certification harness

`run_linker_cert.ps1` set `$ErrorActionPreference = 'Stop'`, so the linker's normal stderr progress output became a terminating error and the suite aborted at its first invocation. It is now `'Continue'`; the gates assert on the linker's exit code and its output, not on the absence of stderr.

### ✅ P0.4 — Certify the linker from tracked source

`git archive HEAD toolchain/from_scratch/phase2_linker` was exported to a clean directory outside the repository, built with Ninja/Release/MSVC 19.44, and certified:

**`RAWR_NATIVE_LINKER_CERT_001: 32 passed, 0 failed`** — L1 undefined-symbol rejection, L2/L3 import table and Windows execution, L4 multiple import DLLs, L5 byte-for-byte deterministic output, L6 global data layout. `exit42.exe` was re-run independently after the suite and returned exit code 42.

Evidence: `RAWRXD_LINKER_REPRODUCIBILITY_001.json`, `RAWRXD_NATIVE_LINKER_CERT_001.log`.

### ✅ P0.5 — Track the QuickJS runtime and certify the extension host

The vendored `3rdparty/quickjs_ng` was untracked in its entirety, including every build input — the extension host could not have been built from the tracked tree. It is now tracked (30 files) with its MIT licence, and the vendored copy was verified **byte-for-byte against the recovered upstream bundle tip** (blob `82155b8ea8b89fb518b52f2ffc5dada992b21e98`).

`RAWRXD_EXTENSION_HOST_001` builds the real runtime from tracked source and passes **6 of 8** gates: the shared runtime initializes against the `ExtensionHostBridge`; a native command registers and executes; an unknown command fails cleanly; all seven IDE native commands are registered in the tracked source; and there is **one** extension runtime, reached through the bridge, not two.

Evidence: `RAWRXD_EXTENSION_TRACKING_001.json`.

---

## Open, in priority order

### P1 — EXT-001: a JavaScript extension cannot register a command

**Status: OPEN. Diagnosed, not fixed. Not claimed as fixed.**

The probe in the extension's own context reports `typeof vscode` → `object` but `typeof vscode.commands` → `undefined`. In `JSExtensionHost::bindVSCodeAPI` (`src/core/js_extension_host.cpp`) the `vscode` object is created locally; each namespace binder looks the object up on the global, attaches its namespace and writes it back; `bindVSCodeAPI` then overwrites the global with its own empty local object, discarding the populated one.

An attempted fix — put the shared object on the global before the binders, and drop the redundant trailing assignment — **did expose the namespace**, and then hit a QuickJS refcount assertion (`gc_decref_child`, `quickjs.c:6826`). It was reverted rather than shipped, because a fix that asserts is worse than a diagnosed defect.

**Next step:** resolve the QuickJS reference discipline around the shared `vscode` object, then re-run `RAWRXD_EXTENSION_HOST_001` from tracked source. This is the only thing standing between the extension subsystem and a full pass.

### P1 — The source-backed compiler path is BLOCKED

The C/C++ front end **was** recovered — `Full Source/src/RawrXD_Lexer.{h,cpp}` and `Full Source/src/compiler/compiler_cpp_real.cpp` from `origin/ci/win32ide-link-msbuild` — and is now tracked. It is **not** a native front end:

- `compiler_cpp_real.cpp` (505 lines) locates `cl.exe` in the MSVC toolchain and spawns it with `CreateProcessA`. It contains no parser, no AST and no code generation. Its own header says *"Replaces: `src/compiler/cpp_compiler.h` (no implementation)"*.
- `RawrXD_Lexer.h` is a genuine lexer (`RawrXD::Lexer`, `Token`, a 13-kind `TokenType`), but its includes `RawrXD_Win32_Foundation.h` and `KeywordHashTable.h` exist only under `.kilo/worktrees/thorn-measure/`, not in the live tree, and it is wired into no build target.

**Minimum implementation contract** (also recorded in `RAWRXD_COMPILER_PROVENANCE_001.json`):

1. A lexer that tokenises C++ into a token stream, using the 13 token kinds the recovered `RawrXD::Lexer` already defines.
2. `RawrXD_Win32_Foundation.h` and `KeywordHashTable.h` present in the live tree and tracked.
3. A parser producing an AST from that stream.
4. An IR the existing `phase2_linker` can consume, or a COFF/PE object writer emitting what `rawrxd_link` already reads.
5. A build target, so the path is reproducible from tracked source.
6. The acceptance test is unchanged and already exists: **a `.cpp` compiles to a `.obj`, `rawrxd_link` links it, Windows loads the result and it exits with the expected code** — `RAWR_NATIVE_LINKER_CERT_001` gate L3.

### P2 — D1 and D2: the silent executables and the broken build scripts

`compilers/FINAL_AUDIT_REPORT.md` (2026-07-07) documents 8 of 9 executables producing no output and two build scripts pointing at paths that do not exist. **None of the nine executables is in the live tree**, so D1 is untestable until they are recovered. D2 is directly fixable.

### P2 — Crucible: source recovered, not built

Crucible was UNVERIFIED in the previous audit because no directory or symbol matched in either tree. It exists on `origin/ci/win32ide-link-msbuild`: `modules/crucible_engine.cpp` (75,749 bytes), `crucible_engine.h` (14,480 bytes) and `win32app/Win32IDE_CruciblePanel.cpp` (16,456 bytes). All three are now tracked. It is not built and not certified.

### P3 — the cleanup surface

`audit/deep2_audit.csv` records 73 of 114 `src/deep2/*.cpp` files as **cmake-orphan**; `audit/AUDIT_SUMMARY.md` records 5,488 of 6,265 `src/` files unreferenced by the root CMake. A cleanup surface, not a correctness problem. Do **not** replace `src/deep2/` with the recovery documentation: the documentation describes intent, the tree is the implementation, and 41 files are already wired into shipped targets.

---

## Reconciliation of the earlier C01 and C03 certificates

The earlier session reported **C01 at 97/97** and **C03 at 7/7** (compiler to Windows execution). This audit reported the C/C++ front end as absent. Both can be true, and the evidence says how:

- **No artifact in the tree reports 97 passed.** The only gate named RC-01 is `rc01_test.cpp`, which certifies `NativeProcess`, `NativeTimer`, `NativeJson`, `NativeSettings` and `NativeWidget` — it declares 53 `record()` calls and is **not** a lexer test.
- **No artifact in the tree reports a 7/7 compiler-to-Windows certificate.**
- The recovered C++ compiler is a **wrapper around an external toolchain**, so a 7/7 execution certificate would have exercised that wrapper and the external `cl.exe`, not a native front end.
- `rc01_test.cpp` and `rc01_test.exe` sit at the repository root as loose artifacts, and the recoverable tree contains a `.kilo/worktrees/thorn-measure/` copy — consistent with the earlier certificates having been produced in a different worktree, against an untracked implementation or a prebuilt binary.

**Conclusion:** the earlier certificates do not establish that the production tree contains a reproducible compiler. The source-backed compiler path is recorded as **BLOCKED**, with a named minimum contract. The source has now been recovered, so the path is *closer* to unblocked than the previous audit could say — but it is not unblocked, and it is not claimed to be.

---

## Merge direction, in one table

| Work item | From | Into | Overwrite risk |
|---|---|---|---|
| Extension + marketplace source | working tree | git history | none (untracked → tracked) |
| Linker source | `_pre_merge_backup` | live tree | none (additive) |
| QuickJS runtime | vendored copy | git history | none (untracked → tracked) |
| Lexer / compiler / Crucible | `origin/ci/win32ide-link-msbuild` | `Full Source/` | none (additive) |
| Certification harness fix | local | local | none |
| EXT-001 fix | pending | `src/core/js_extension_host.cpp` | must not regress the 6 passing gates |
| Compiler front end | to be written | new | do not overwrite the recovered sources |

**No item takes content from `origin/main`.** The default branch is the baseline the local tree has diverged from, not a source to merge in.

---

## The next milestone

**Protect, then integrate.** That is done. What remains, in order:

1. **EXT-001** — make a JavaScript extension able to register a command. One defect, one file, already diagnosed down to the function. Unblocks the extension subsystem to 8/8.
2. **The compiler lexer** — the two missing headers, then a parser, then an object writer. The acceptance test already exists and the linker is ready to consume the output.
3. **D1/D2** — recover the nine executables, then make them speak and point the scripts at the tree.

Each step has a completion condition that is a *certificate*, not an intention: a link that runs from tracked source, an extension that registers a command, a `.cpp` that becomes a `.obj` that becomes a running `.exe`.
