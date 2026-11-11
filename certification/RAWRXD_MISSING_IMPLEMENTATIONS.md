# RAWRXD_MISSING_IMPLEMENTATIONS.md

**Companion to:** `RAWRXD_GITHUB_REUSE_AUDIT_001.md` · `RAWRXD_COMPONENT_PARITY_MATRIX.csv` · `RAWRXD_INTEGRATION_PRIORITY.md`
**Date:** 2026-10-21

This document states what is **not** implemented, separates the three reasons a thing can be missing, and gives each one the smallest test that would close it.

**Three kinds of "missing", kept strictly apart:**

| Kind | Meaning | Count here |
|---|---|---|
| **ABSENT** | the implementation does not exist in any reachable tree | 3 |
| **UNREACHABLE** | it exists but could not be reached from the accessible evidence | 3 |
| **MISPLACED** | it exists and works, but not where the build expects it | 4 |

A tree that could not be fetched is **never** counted as absent. A file that is absent from `origin/main` is **not** a missing implementation — it is a local-only one.

---

## 1. ABSENT — no implementation exists in any reachable tree

### M1 — The C/C++ front end: lexer, parser, IR, object emission

| | |
|---|---|
| **Status** | ABSENT |
| **Provenance** | UNVERIFIED (no source located) |
| **First missing executable stage** | **the lexer** |

**The pipeline, end to end, and where it stops:**

```
source text
   ↓
[ MISSING ]  lexer          no source in F:\RawrXD or G:\VSC0de\Deep2Engine
   ↓
[ MISSING ]  parser         no source
   ↓
[ MISSING ]  intermediate representation
   ↓
[ MISSING ]  COFF/PE object emission
   ↓
[ PRESENT ]  rawrxd_link    toolchain/from_scratch/phase2_linker — CERTIFIED 32/0
   ↓
[ PRESENT ]  Windows-loadable .exe
```

**Evidence of the contradiction.** `compilers/FINAL_AUDIT_REPORT.md` states *"Native toolchain (assembler, linker, C compiler) — ✅"* and `compilers/WHAT_IS_TRULY_MISSING.md` lists the C compiler under **Completed**. But `compilers/` contains **23 Markdown reports and 145 tracked files, and no compiler source at all**, and no lexer/parser/IR/emitter source exists in either tree. The documentation is describing an implementation that is not present.

**The three nearest real artifacts, none of which is a C front end:**

| Artifact | What it actually is |
|---|---|
| `recovery/nested-repos/src-asm.bundle` | RawrXD's own MASM64 history, incl. `RAWRXD_PE32_EMITTER_MONOLITHIC.asm` and `GenesisP0_SelfHosting.asm` — an assembler, not a C parser |
| `compilers/assembly_source/` (17 `.asm` files per the audit report) | MASM IDE and compiler stages — **the directory is not present in the live tree**; only the report describing it is |
| `OmegaPolyglot_v5.exe` | A 15,872-byte **binary analyser** (PE parsing, entropy, disassembly, language detection) — not a compiler. Not present in the live tree either; only the report describing it is |

**Required fix.** Recover a C/C++ front end from `src-asm.bundle` or from one named unfetched ref. Then, in order: implement the `cpp` manifest entry (defect **D3**), make the executables speak (defect **D1**), point the scripts at the tree (defect **D2**), and write the tests and docs (defects **D4**, **D5**).

**Acceptance test.** One `.cpp` file compiles to a `.obj`; `rawrxd_link` links that `.obj` into an executable; **Windows loads the executable and it exits with the expected code.** The second half matters: it is the same test `RAWR_NATIVE_LINKER_CERT_001` gate L3 already proves for the linker, so it can be applied unchanged.

**Effort.** The largest single item in the audit. Weeks, not days.

---

### M2 — The extension marketplace backend

| | |
|---|---|
| **Status** | ABSENT (backend) / PARTIAL (directory) |
| **Provenance** | LOCAL-ONLY |

**Present:** `extensions/` (185 files), `vscode-extension/` (26 files), `VSIXLoader` with `GetLoadedPlugins()`, and `VSCodeExtensionManifest` parsing in `Win32IDE_VSCodeExtAPI.cpp:87-91`.

**Absent:** a catalogue/index service behind the directory. Nothing in the tree provides *discovery* of available extensions — only *loading* of extensions already on disk. A marketplace UI or a registry that answers "what can I install" is not present.

**Required fix.** An index (manifest, id, version, engine range) built from `extensions/`, and an install path that materialises a VSIX into the loader's plugin directory.

**Acceptance test.** `rawr extensions list` (see P1.3) enumerates every manifest under `extensions/` with a version, and an install of a packaged VSIX makes its commands dispatchable.

---

### M3 — The `Omega-Polyglot` compiler executables

| | |
|---|---|
| **Status** | ABSENT from the live tree (the *report* about them is present) |
| **Provenance** | LOCAL-ONLY (report) |

`compilers/FINAL_AUDIT_REPORT.md` catalogues nine executables and their sizes. None of the nine is in the live tree. `compilers/` holds the report and the test scripts, not the binaries.

**Consequence:** defect **D1** (8 of 9 silent) is currently **untestable** — there is nothing to run. D1 can only be closed after the binaries are recovered.

**Required fix.** Recover the executables (or their sources) before attempting D1. If they cannot be recovered, D1 should be re-scoped as "the report describes binaries that no longer exist" rather than "eight executables are silent".

**Acceptance test.** Either the recovered executables run and produce output, or the report is corrected to match what exists.

---

## 2. UNREACHABLE — exists, but could not be reached from the accessible evidence

### M4 — The Crucible engine

| | |
|---|---|
| **Status** | UNVERIFIED |
| **Provenance** | UNVERIFIED |

**What is known.** No directory matching `crucible` and no `CrucibleEngine` symbol exists in `F:\RawrXD` or `G:\VSC0de\Deep2Engine`. The only textual hits are incidental: `src/win32app/_header_methods.txt`, `src/test_harness/golden_build_smoke_test.cpp`, `src/tests/e2e/smoke_test.cpp`.

**Why it is not classified MISSING.** The name may denote a subsystem that was renamed, may live in one of the 79 unfetched `origin` branches, or may exist only in the `src-asm` bundle's deeper history. The 79 unfetched branches include `agentic-ide-production`, `audit/consolidated-2026-10-17`, `clean-main`, `codex/single-repo-batched-sync`, `copilot/vscode-mlyextom-3zgo*` and others whose names suggest exactly this kind of content. **Fetching them all is the one thing the audit was told not to do**, and with the API at 59/60 remaining, the cost is in the dozens of requests a per-tree comparison would need — not in the quota.

**Required fix.** Identify the ref from the recovery documentation or from `recovery/nested-repos/`, then **one** targeted `git fetch origin <ref>`. If the name appears in no ref, record that the subsystem does not exist in the accessible trees and close it as such.

**Acceptance test.** Either a Crucible module list (file, lines, hash) with a consumer map, or a written statement that no such subsystem exists.

---

### M5 — The QuickJS upstream histories

| | |
|---|---|
| **Status** | UNVERIFIED (history) / recovered (tip tree) |
| **Provenance** | GITHUB-ONLY |

Both bundles verify as *"okay"* and *"records a complete history"*, yet `git clone` fails with *"remote did not send all necessary objects"* — the pack is missing the parent of the tip (`7bd1ae2c` for quickjs, `3eb06057` for quickjs-ng). The same truncation class broke `git fetch origin recovery-clean-source` on object `786acfad`.

**What was recovered.** Extracting the pack directly — locate the `PACK` signature, then `git index-pack --fix-thin --stdin` — restores the **tip tree** in full. `quickjs.bundle` yields Bellard's QuickJS at `f1139494` (2025-12-22); `quickjs_ng.bundle` yields quickjs-ng at `6d2a9bac` (2026-02-23, with `CMakeLists.txt` and `amalgam.js`). **File contents are verifiable; ancestry is not.**

**Required fix.** Recover the two parent commits from another source, or accept the trees as the reference and record the history as unavailable.

**Acceptance test.** `git cat-file -p f1139494` and `git cat-file -p 6d2a9bac` resolve in a restored repository — **already true** — and the restored quickjs-ng builds its amalgamation.

---

### M6 — The `itsmehrawrxd-master` bundle

| | |
|---|---|
| **Status** | UNVERIFIED |
| **Provenance** | UNVERIFIED |

`BUNDLES_README.md` line 8: `- itsmehrawrxd-master: bundle failed: fatal: Refusing to create empty bundle.` The history was never captured. Whether a tree existed at all is unknown.

**Required fix.** If the source is still reachable from a ref, capture it. If not, record it as unrecoverable so the gap is documented rather than silent.

**Acceptance test.** A bundle file exists for it, or the README records it as unrecoverable with the reason.

---

## 3. MISPLACED — exists and works, but not where the build expects it

### M7 — The phase2_linker source

**Status:** WORKING, but the source is not in the live tree. **Provenance:** LOCAL-ONLY.

The live `toolchain/from_scratch/phase2_linker/` holds **build outputs only**. The source survives in `_pre_merge_backup/toolchain/from_scratch/phase2_linker/` and two `.kilo/worktrees` copies — 19 `.c`/`.h` files, `CMakeLists.txt`, `tests/make_fixtures.c` and `tests/run_linker_cert.ps1`.

**The certification passes** (32/0) when the source is rebuilt. The defect is placement, not function.

**Required fix.** P0.1 — restore the source into the live tree.

**Acceptance test.** `cmake --build` succeeds from the live tree and `RAWR_NATIVE_LINKER_CERT_001` passes 32/0 unattended.

### M8 — The four stale prebuilt linker binaries

**Status:** STALE. **Provenance:** LOCAL-ONLY.

All four predate the source and fail at gate L1 with `Failed to read: -subsys`. Their usage string is `Usage: rawrxd_link obj1.obj [...] -o out.exe [-ghost]`; the source's is `[-o out.exe] [-v] [-entry sym] [-base 0xN] [-subsys N] …`.

**This is the clearest case in the audit where the comparison method matters.** `build_ghost` is the **newest** binary (2026-03-20) and `build_new` is the **largest** (91,989 bytes) — and both are functionally *behind* the source. Date and size would have picked the wrong artefact; ancestry and semantics picked the right one.

**Required fix.** P0.3 — rebuild from source; archive the four rather than delete them.

**Acceptance test.** The shipped binary passes L1–L6; the archived ones are documented as the before-state.

### M9 — The certification harness defect

**Status:** PARTIAL. **Provenance:** LOCAL-ONLY.

`run_linker_cert.ps1` sets `$ErrorActionPreference = 'Stop'` for the whole script, so the linker's normal **stderr** progress output — `[linker] phase 1 complete: 1 object file(s) loaded` — becomes a terminating error and the run aborts at line 206. The suite cannot certify anything in its shipped state, which is why no linker certification result exists anywhere in the tree.

**Required fix.** P0.2 — one line.

**Acceptance test.** The suite completes unattended and reports `32 passed, 0 failed`. **Verified** on a scratch copy; the repository was not modified.

### M10 — The extension host is untracked

**Status:** PARTIAL and **at risk**. **Provenance:** LOCAL-ONLY.

Seven files, 9,221 lines, **untracked in git** and absent from `origin/main`:

| File | Lines |
|---|---|
| `src/core/js_extension_host.cpp` | 2687 |
| `src/core/js_extension_host.hpp` | 375 |
| `src/modules/quickjs_extension_host.cpp` | 1721 |
| `src/modules/quickjs_vscode_bindings.cpp` | 1593 |
| `src/modules/quickjs_node_shims.cpp` | 733 |
| `src/core/extension_polyfill_engine.cpp` | 1631 |
| `src/win32app/Win32IDE_VSCodeExtAPI.cpp` | 481 |

This is the most severe finding in the audit: it is **not missing**, it is **unprotected**. A `git clean`, a re-clone, or a branch switch destroys it, and nothing in the repository can bring it back — unlike the linker source, which has three copies.

**Required fix.** P0.4 — commit all seven.

**Acceptance test.** `git ls-files --error-unmatch` succeeds for all seven.

---

## 4. The five documented audit defects, restated against this tree

| # | Defect | Source of truth | Reachable in the live tree? | Actual status now |
|---|---|---|---|---|
| **D1** | Silent executables | `compilers/FINAL_AUDIT_REPORT.md` §2 | **No** — the executables are not in the tree (M3) | untestable until recovered |
| **D2** | Build scripts reference wrong paths | `compilers/FINAL_AUDIT_REPORT.md` §4 | Yes (`compilers/build_scripts/`) | open, directly fixable |
| **D3** | 16 of 69 manifest languages missing, incl. `cpp` and `csharp` | `compilers/languages_supported_manifest.json` | Manifest yes; implementations no (M1) | open; the `cpp` entry is the critical path |
| **D4** | No comprehensive test suite (5 tests) | `compilers/test_results/COMPILER_TEST_REPORT.json` | Yes | open |
| **D5** | Missing documentation (0 %) | — | `compilers/QUICKSTART.md` exists but is a stub | open |

D4 and D5 also appear in `compilers/WHAT_IS_TRULY_MISSING.md` (2026-07-08) as gaps 4 and 2; D1–D3 are unique to the audit report. `WHAT_IS_TRULY_MISSING.md` adds self-hosting (bootstrap stage 3–4) and an installer, which have no defect entry in the audit report and are therefore listed as D6 and D7 here for completeness:

| # | Additional gap | Source | Acceptance test |
|---|---|---|---|
| **D6** | Self-hosting incomplete (50 %; stages 3–4) | `compilers/WHAT_IS_TRULY_MISSING.md` gap 1 | The linker links itself from its own output; the result passes L1–L6 |
| **D7** | No installer (manual file copying) | `compilers/WHAT_IS_TRULY_MISSING.md` gap 3 | An installer produces a working install; the toolchain builds from it |

**D6 is the most interesting of the seven**, because the linker it would self-host is now certified. The self-hosting gap was written when the linker could not pass its own suite; that is no longer true.

---

## 5. What is NOT missing

Stated explicitly, because the audit method was built to avoid these errors:

- **The native PE/COFF linker is not missing and is not a stub.** It produces loadable, deterministic Windows executables: 32/0 on `RAWR_NATIVE_LINKER_CERT_001`.
- **The VS Code extension API bridge is not missing.** All 7 native commands are registered and implemented; each posts a real `WM_COMMAND` with a real control id.
- **The extension host is not missing.** 9,221 lines implementing `registerCommand`/`executeCommand` on a sandboxed runtime.
- **The QuickJS trees are not missing.** Their tip trees were recovered intact from local bundles.
- **The deleted remote branches are not missing.** They are preserved in `recovery/nested-repos/`; two of them are locally unreadable as clones but their trees are readable.
- **`origin/main` is not a superset of the local tree.** It contains none of the extension host, the native toolchain or the linker source. Integrating *from* it would delete working code.
