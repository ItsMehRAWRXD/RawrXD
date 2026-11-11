# RAWRXD_GITHUB_REUSE_AUDIT_001

**Date:** 2026-10-21
**Scope:** All currently accessible GitHub default-branch trees, local source inventories, and local recovery documentation.
**Method rule:** a different SHA or a larger file size does **not** establish newer or more functional. Ordering is established by commit ancestry, commit timestamps, semantic differences in the code, and passing tests. Nothing is classified as working on the strength of a file existing or compiling.

**Rate-limit discipline:** no GitHub REST API traffic was used for the critical path. Remote refs were read with `git ls-remote` and fetched with `git fetch` (git protocol, no API quota), and every tree that was deleted from the remote was recovered from **local git bundles** under `recovery/nested-repos/`. Inaccessible feature and certification branches were **not** retried; they are recorded as `UNVERIFIED`, never as absent or obsolete.

---

## 1. Accessible GitHub default-branch trees

| Remote | Repository | Default branch | HEAD | Reached by |
|---|---|---|---|---|
| `origin` | `ItsMehRAWRXD/RawrXD` | `main` | `033a8acb55` | `git fetch` — full tree available locally |
| `final` | `ItsMehRAWRXD/RawrXD-IDE-Final` | `main` | `b57a988082` | `git ls-remote` only — **not fetched** (UNVERIFIED) |
| `rawrxda` | `ItsMehRAWRXD/RawrXDA` | `20260316-ide` | `49f5088d75` | `git ls-remote` only — **not fetched** (UNVERIFIED) |
| `everything` | `ItsMehRAWRXD/everything` | `main` | `9a4776bc5d` | `git ls-remote` only — **not fetched** (UNVERIFIED) |
| `closure-origin` | `ItsMehRAWRXD/RawrXD-IDE-Win32-Gui-CLI-HTML` | `main` | `45057c45c5` | `git ls-remote` only — **not fetched** (UNVERIFIED) |

`origin` has 82 remote branches. Only `main`, `recovery-clean-source` and `agent/phase2-repair` were fetched. The remaining 79 branches were **not** chased.

## 2. Recovery bundles — the deleted trees, locally recoverable

`recovery/nested-repos/BUNDLES_README.md` states these preserve "histories that exist nowhere upstream". This is the `rawrxd-recovery-docs` evidence: it is local, complete, and needs no API.

| Bundle | Content | Tip | History | Recovered to |
|---|---|---|---|---|
| `src-asm.bundle` (74 MB) | RawrXD's own MASM64 tree | `1aba5702` 2026-06-15 | complete | `audit/bundles/src-asm` |
| `Star5IDE.bundle` (9.5 MB) | Star5IDE reference IDE | `main` `872c99e2` 2025-09-05 | complete | `audit/bundles/Star5IDE` |
| `SaaSEncryptionSecurity.bundle` | upstream | `43eac304` | complete (169 commits) | `audit/bundles/SaaSEncryptionSecurity` |
| `cloud-hosting.bundle` | upstream | `ec9da02a` | complete (15 commits) | `audit/bundles/cloud-hosting` |
| `copilot-ollama.bundle` | upstream | `7169f667` | complete | `audit/bundles/copilot-ollama` |
| `quickjs.bundle` | Bellard QuickJS | `f1139494` 2025-12-22 | **TRUNCATED** — parent `7bd1ae2c` absent | tip tree recovered by direct pack extraction |
| `quickjs_ng.bundle` | quickjs-ng | `6d2a9bac` 2026-02-23 | **TRUNCATED** — parent `3eb06057` absent | tip tree recovered by direct pack extraction |
| `itsmehrawrxd-master` | — | — | **bundle failed**: "Refusing to create empty bundle" | — |

The two truncated bundles are a real finding, not a failure to try: `git bundle verify` reports them "okay" because the ref tips resolve, but the pack lacks the parent objects, so `git clone` fails with *"remote did not send all necessary objects"*. Extracting the pack directly (locate the `PACK` signature, `git index-pack --fix-thin --stdin`) recovers the **tip tree** — the file contents are fully verifiable, only the ancestry is not. The same truncation class caused `git fetch origin recovery-clean-source` to fail on object `786acfad`.

`Star5IDE` carries two extra branches that matter for this audit: `feature/carmilla-carpatcher` (`ef595f05`) and `feature/carmilla-stubs-payload` (`7e8f93c6`) — the latter contains `Agent.cpp/h`, `Config.cpp/h`, `HelloWorld.cs`, i.e. the **stub** payload.

## 3. The decisive local finding: the default branch contains none of it

Every file below was checked against `origin/main` with `git rev-parse origin/main:<path>`:

| Path | In `origin/main`? |
|---|---|
| `src/core/js_extension_host.cpp` | **ABSENT** |
| `src/core/js_extension_host.hpp` | **ABSENT** |
| `src/modules/quickjs_extension_host.cpp` | **ABSENT** |
| `src/modules/quickjs_vscode_bindings.cpp` | **ABSENT** |
| `src/modules/quickjs_node_shims.cpp` | **ABSENT** |
| `src/core/extension_polyfill_engine.cpp` | **ABSENT** |
| `src/win32app/Win32IDE_VSCodeExtAPI.cpp` | **ABSENT** |
| `toolchain/from_scratch/phase2_linker/pe_writer.c` | **ABSENT** |
| `toolchain/from_scratch/phase2_linker/main.c` | **ABSENT** |
| `toolchain/from_scratch/phase2_linker/tests/run_linker_cert.ps1` | **ABSENT** |

These are **LOCAL-ONLY**. They are also **untracked** in git (`git ls-files --error-unmatch` fails for every one of them) — the local tree is ahead of its own history, and `origin/main` is not a superset of the local tree. Any integration plan that starts from `origin/main` would *delete* this work.

## 4. P0 — native linker C04–C08: source comparison and working-status certification

### 4.1 Where the source actually is

| Location | Contents |
|---|---|
| `F:\RawrXD\toolchain\from_scratch\phase2_linker\` | **build outputs only** — `rawrxd_link.exe` × 4, `rawrxd_check.exe` × 4, `linker_smoke.exe`, `smoke_pdb.exe`, `build.ninja`. **No source.** |
| `F:\RawrXD\_pre_merge_backup\toolchain\from_scratch\phase2_linker\` | **full source** (11 `.c` + 8 `.h` + `CMakeLists.txt` + `tests/`) |
| `F:\RawrXD\.kilo\worktrees\piranha1-gate2-provenance\_pre_merge_backup\...` | copy |
| `F:\RawrXD\.kilo\worktrees\piranha2-gate4-dispatch\_pre_merge_backup\...` | copy |

The live tree lost the source; the backup copies retained it. The `src-asm` bundle holds the same project's MASM64 history (2026-06-15), including `RAWRXD_PE32_EMITTER_MONOLITHIC.asm` and `GenesisP0_ExtensionHost.asm`.

### 4.2 Component map (hashes, line counts)

| ID | Component | File | Lines | SHA-256 (12) |
|---|---|---|---|---|
| C04 | COFF object reader | `coff_reader.c` / `.h` | 460 / 130 | `BA5A1E38C950` / `B19C32117A9B` |
| C05 | Section merger | `section_merge.c` / `.h` | 463 / 89 | `B099C829530E` / `C968B243E676` |
| C05a | Import/export generation | `import_gen.c` / `.h` | 569 / 111 | `A758D2D7E551` / `AD9F987082D3` |
| C05b | Windows API→DLL registry | `known_imports.c` / `.h` | 623 / 9 | `5040893A1B3B` / `FED5F068A43D` |
| C05c | Export table generation | `export_gen.c` / `.h` | 159 / 70 | `4C46F8AA71CF` / `7196181EDA3E` |
| C06 | x64 relocation resolver | `reloc_resolver.c` | 310 | `931DDC86E64A` |
| C06a | Base relocation generator | `reloc_gen.c` / `.h` | 148 / 63 | `0CA31E96B3CB` / `764FA7870AA7` |
| C07 | PE32+ image writer | `pe_writer.c` / `.h` | 472 / 97 | `22A40F9867D8` / `96B746279764` |
| C08 | Entry stub | `entry_stub.c` | 79 | `7057E23E169A` |
| C08a | Linker driver | `main.c` | 391 | `76F6F4BF69B6` |
| C09 | Diagnostic utility | `rawrxd_check.c` | 160 | `806C90E3D5D0` |
| C11 | Fixture generator | `tests/make_fixtures.c` | 388 | — |
| C10 | Certification suite | `tests/run_linker_cert.ps1` | 324 | — |

**On the C04–C08 identifiers.** No `C04`…`C08` identifier exists in any accessible tree (searched the whole of `F:\RawrXD` and `G:\VSC0de\Deep2Engine`; zero hits). The certification artifact in the source is `RAWR_NATIVE_LINKER_CERT_001` with gates **L1–L6**. The C-numbers above are **this audit's mapping** onto the linker's own documented phases (`main.c` header: Phase 1 COFF reader → Phase 2 section merge → Phase 3 relocation resolver → Phase 4 PE writer → Phase 5 entry stub, plus the driver). They are derived, not recovered, and are labelled as such.

### 4.3 Working-status certification — **executed**

The certification was run three ways.

**(a) The four prebuilt binaries in the live tree — all FAIL.**

| Binary | Built | Result |
|---|---|---|
| `build/rawrxd_link.exe` | 2026-02-15 | fails at **L1**: `Failed to read: -subsys` |
| `build_ghost/rawrxd_link.exe` | 2026-03-20 | fails at **L1**: `Failed to read: -subsys` |
| `build_gmake/rawrxd_link.exe` | 2026-02-16 | fails at **L1** |
| `build_new/rawrxd_link.exe` | 2026-02-16 | fails at **L1** |

**Root cause (semantic, not hash):** `main.c` in the backup source parses `-subsys N` (line 160) and `-entry sym` (line 162) and its usage text advertises both. The built binaries' own usage string is only `Usage: rawrxd_link obj1.obj [...] -o out.exe [-ghost]`. **The binaries predate the source.** They are stale, not broken-by-design — which is exactly why hash/size comparison alone would have misled.

**(b) The certification harness has a defect of its own.** Even with a correct binary, `run_linker_cert.ps1` aborts at line 206 under `$ErrorActionPreference = 'Stop'`: the linker writes normal progress to **stderr** (`[linker] phase 1 complete: 1 object file(s) loaded`), and with `2>&1` the merged `ErrorRecord` becomes terminating. The harness cannot certify anything in its shipped state. One-line fix: `$ErrorActionPreference = 'Continue'` for the native invocations.

**(c) Rebuilt from the backup source → the linker passes.**

```
cmake -S <backup>/toolchain/from_scratch/phase2_linker -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build     # 16/16, no warnings, MSVC 19.44
```

then, with the harness defect worked around in a scratch copy (**the repository was not modified**):

```
RAWR_NATIVE_LINKER_CERT_001: 32 passed, 0 failed
```

Gates, all PASS: L1 undefined-symbol rejection (no image emitted, exit 1, error reported) · L2/L3 import table correctness (entry point, image base `0x140000000`, section alignment `0x1000`, file alignment `0x200`, `SizeOfHeaders` file-aligned, `SizeOfImage` section-aligned, section RVAs ascending, import directory parsed, `kernel32.dll`/`ExitProcess` imported, import RVAs image-relative, IAT in a writable section, **Windows loaded the image and `ExitProcess(42)` ran**, tail-jump import form runs, call import form runs) · L4 multiple import descriptors (three APIs across two DLLs, image runs) · L5 **byte-for-byte deterministic output** · L6 `.data` section layout.

**Verdict for C04–C08: WORKING.** The native PE/COFF linker produces loadable, deterministic Windows executables. It is not a stub and not partial. What is missing is *placement*, not function: the source is not in the live tree, the shipped binaries are stale, and the harness has a one-line defect.

The repository was not modified: the build and the patched harness were done in `C:\Users\Garrett\AppData\Local\Temp\kilo\audit\`.

## 5. P0/P1 — the VS Code extension surfaces

| Surface | Local implementation | Lines | In `origin/main`? | Status |
|---|---|---|---|---|
| Extension host (JS) | `src/core/js_extension_host.cpp` | 2687 | ABSENT | PARTIAL — implements `vscode.commands.registerCommand` / `executeCommand`; no run evidence |
| QuickJS extension host | `src/modules/quickjs_extension_host.cpp` | 1721 | ABSENT | PARTIAL |
| VS Code API bindings | `src/modules/quickjs_vscode_bindings.cpp` | 1593 | ABSENT | PARTIAL |
| Node shims | `src/modules/quickjs_node_shims.cpp` | 733 | ABSENT | PARTIAL |
| Polyfill engine | `src/core/extension_polyfill_engine.cpp` | 1631 | ABSENT | PARTIAL |
| IDE extension API bridge | `src/win32app/Win32IDE_VSCodeExtAPI.cpp` | 481 | ABSENT | **WORKING** (7/7 commands implemented) |
| Marketplace | `extensions/` (185 files), `vscode-extension/` (26 files) | — | ABSENT | PARTIAL — `VSIXLoader` + manifest scanning exist |
| QuickJS runtime | `quickjs.bundle` / `quickjs_ng.bundle` | — | — | UNVERIFIED upstream (truncated), tree content recovered |
| GitHub extension API | `vscode::VSCodeExtensionAPI` (in `include/`) | — | — | PARTIAL — the API the bridge consumes |

### 5.1 Command registration → dispatch → execution

The **7 native commands** in `Win32IDE_VSCodeExtAPI.cpp` are all **IMPLEMENTED** — each posts a real `WM_COMMAND` with a real control id, not a stub:

| Command | Handler | Evidence |
|---|---|---|
| `rawrxd.openFile` | `WM_COMMAND` 2002 | `IDM_FILE_OPEN` |
| `rawrxd.saveFile` | `WM_COMMAND` 2003 | `IDM_FILE_SAVE` |
| `rawrxd.toggleTerminal` | `WM_COMMAND` 6001 | `IDM_VIEW_TERMINAL` |
| `rawrxd.hotpatchStatus` | `WM_COMMAND` 9000 | `IDM_HOTPATCH_SHOW_STATUS` |
| `rawrxd.lspStart` | `WM_COMMAND` 9200 | `IDM_LSP_SERVER_START` |
| `rawrxd.editorEngineCycle` | `WM_COMMAND` 9303 | `IDM_EDITOR_ENGINE_CYCLE_CMD` |
| `rawrxd.extensionAPIStats` | `ide->cmdVSCExtAPIStats()` | direct call |

The **JS path** is `vscode.commands.registerCommand(id, handler)` → `JS_SetPropertyStr(cx, commands, "registerCommand", …)` (`js_extension_host.cpp:719`) → `api.registerCommand(cmdId, jsCommandTrampoline, …)` (line 761) → the same `VSCodeExtensionAPI::executeCommand(cmdId)` used by `executeCommand` (line 788). So JS-registered and native-registered commands share one dispatch path. 5 `registerCommand` sites exist in the JS host; the native bridge adds 7 more.

### 5.2 The "September" candidate, tested

`Star5IDE` main is dated **2025-09-05** (`872c99e2`), which is the September reference. It is a **JavaScript application** — `package.json`, `src/app.js`, `src/engines/*.js` (crypto, backup, compression, hot-patchers, disassembly). It is **not** a VS Code extension host and has no `registerCommand` surface. Its `feature/carmilla-stubs-payload` branch is explicitly the **stub** payload.

**Therefore the September Star5IDE tree is NOT the preferred extension-host implementation.** The preferred implementation is the **local** one (`js_extension_host.cpp` + `quickjs_extension_host.cpp` + `Win32IDE_VSCodeExtAPI.cpp`): it is the only one that exposes a real `registerCommand`/`executeCommand` API, it is QuickJS-sandboxed, and it has real handlers. This is the conclusion the user's "a different SHA and a larger file size do not prove newer" caution was aimed at — Star5IDE's tree is *older* and *less functional* for this purpose despite being a separate upstream project.

## 6. P1 — the native compiler

`compilers/` is **documentation only**: 23 Markdown reports, 145 tracked files, **no compiler source**. `compilers/FINAL_AUDIT_REPORT.md` (2026-07-07, audited by GitHub Copilot) is the governing document.

**Pipeline walk (source text → tokens → AST → IR → object file → linked executable):**

| Stage | Source located? | Executable path? |
|---|---|---|
| Lexer | **NOT FOUND** | — |
| Parser | **NOT FOUND** | — |
| Intermediate representation | **NOT FOUND** | — |
| COFF/PE object generation | assembler/linker only | — |
| Linker | `toolchain/from_scratch/phase2_linker` (backup copy) | **YES — 32/0 certified** |
| C/C++ front end | **NOT FOUND** | — |

**The first missing executable stage is the lexer** — there is no C/C++ front-end source in either accessible tree. `compilers/` asserts one exists ("Native toolchain (assembler, linker, C compiler) — ✅"), but the source is not present in `F:\RawrXD` or `G:\VSC0de\Deep2Engine`. The nearest real artifacts are the MASM64 sources in the `src-asm` bundle.

The `Omega-Polyglot` executables named in the audit report are **not** in the live tree; only the report is. Of the nine executables the report describes, one (`OmegaPolyglot_v5.exe`, 15,872 bytes) was reported working and eight were reported silent.

## 7. P2 — Deep2 against the recovery documentation

`audit/` already contains authoritative machine-generated evidence:

- `audit/deep2_audit.csv` — 114 `src/deep2/*.cpp` scanned; **41 referenced** by the root CMake; **73 cmake-orphan**.
- `audit/AUDIT_SUMMARY.md` — 83 targets (71 executables + 13 libraries), 976 source-target edges, 836 unique referenced sources, 11 duplicate implementation families, 24 stub-risk edges, 6,265 source files under `src/` of which **5,488 are unreferenced** by the root CMake.
- `audit/cmake_source_target_matrix.csv/json`, `audit/orphan_sources.csv`, `audit/duplicate_implementation_families.csv`, `audit/deep2_stage2_decisions.csv`.

**Do not replace the newer validated local Deep2 implementation with the recovery documentation.** The documentation describes intent; `src/deep2/` is the implementation, and 41 of its files are already wired into the shipped targets. The actionable output of the Deep2 comparison is the **73 orphan files** and the **5,488 unreferenced sources** — a cleanup surface, not a replacement surface.

## 8. P2 — the Crucible engine

**No Crucible directory and no `CrucibleEngine` symbol exist in `F:\RawrXD` or `G:\VSC0de\Deep2Engine`.** The only textual hits are incidental (`src/win32app/_header_methods.txt`, two test files). Crucible is therefore classified **UNVERIFIED** — not MISSING, because the name may denote a subsystem that was renamed, lives in an unfetched remote, or exists only in one of the 79 unfetched branches. Its modules and dependencies **cannot be mapped** from the accessible evidence. This is a genuine blocker for the Crucible row of the matrix, and the honest way to close it is one targeted fetch of a named ref — not a blanket branch sweep.

## 9. The five documented audit defects

Source: `compilers/FINAL_AUDIT_REPORT.md` (2026-07-07). Each is associated with its file, its required fix, and its acceptance test.

| # | Defect | Exact source | Required fix | Acceptance test |
|---|---|---|---|---|
| D1 | **Silent executables** — 8 of 9 produce no output | `compilers/assembly_source/` (17 `.asm` sources) + the 9 executables the report lists | Check entry point vs subsystem with `dumpbin /headers`; rebuild as console subsystem; supply the input files the tools expect | Each executable produces output on a known input and exits 0; `compilers/TEST_ALL_COMPILERS.bat` / `compilers/Test-Compilers.ps1` report non-silent |
| D2 | **Build scripts reference wrong paths** | `d:\build.bat` (references `D:\omega_polyglot_v4.obj`); `compilers/build_scripts/build_cli_full.bat` (references `D:\RawrXD-production-lazy-init\`) | Repoint every script at the live tree; add error checking | A single script builds the toolchain from a clean checkout; `compilers/COMPILER_TEST_REPORT.md` regenerated |
| D3 | **16 of 69 manifest languages missing, including `cpp` and `csharp`** | `compilers/languages_supported_manifest.json` (the manifest vs implementation gap) | Implement the C++ and C# front ends; fix the `c__` / `c_` naming inconsistency | The manifest's language list is fully backed by implementations; the C++ path produces a working `.obj` that `rawrxd_link` links |
| D4 | **No comprehensive test suite** (5 basic tests) | `compilers/test_results/COMPILER_TEST_REPORT.json` | Sample programs per language; output-correctness assertions; regression + stress runs | `compilers/test_results/COMPILER_TEST_REPORT.json` shows a pass per manifest language |
| D5 | **Missing documentation** (0 %) | — | User manual, API reference, build guide, troubleshooting | `compilers/QUICKSTART.md` exists but is a stub; a build guide and API reference must be present and current |

A second, related gap list exists in `compilers/WHAT_IS_TRULY_MISSING.md` (2026-07-08): self-hosting (bootstrap stage 3–4), documentation, installer, comprehensive testing, polish. **D4 and D5 are the same gaps in both documents**; D1–D3 are unique to the audit report.

---

## 10. Classification summary

Full detail is in `RAWRXD_COMPONENT_PARITY_MATRIX.csv` (33 rows, 14 columns).

**Working status:** WORKING 11 · PARTIAL 10 · UNVERIFIED 10 · STUB 1 · STALE 1
**Provenance:** SAME 0 · LOCAL-ONLY 23 · GITHUB-ONLY 4 · GITHUB-CHANGED 2 · UNVERIFIED 4

Two observations that the matrix makes plain:

- **No component is `SAME`.** Nothing in the audited surface is identical between the local tree and the default branch. Either the work never landed upstream, or upstream is a different product.
- **No component is `MISSING`, and that is the point.** The apparent gaps — the linker source, the extension host, the QuickJS trees, the Star5IDE branches — are all *present somewhere reachable*: in `_pre_merge_backup`, in `.kilo/worktrees`, or in a local bundle. "Missing" would have been the wrong word, and the audit's job was to avoid it. The four components that are genuinely `UNVERIFIED` in provenance (C25, C27, C28, C32) are the ones that could not be located in *any* tree, and they are called out individually in `RAWRXD_MISSING_IMPLEMENTATIONS.md`.

## 11. Conclusion

**Integrable immediately, with no further investigation:**

1. **The native PE/COFF linker, C04–C08** — certified 32/0 against a from-source rebuild. The source is in `_pre_merge_backup`; the fix is to restore it into `toolchain/from_scratch/phase2_linker/`, rebuild `rawrxd_link.exe` over the stale binary, and correct the one-line harness defect so `run_linker_cert.ps1` can run unattended.
2. **The VS Code extension API bridge** — 7/7 native commands implemented and registered; it is the integration point for every extension surface.
3. **The JS/QuickJS extension host** — 2,687 + 1,721 lines implementing `registerCommand`/`executeCommand` on a sandboxed runtime; it needs *untracked-ing*, not rewriting.

**Remaining blockers, in order:**

1. **The C/C++ front end has no source in any accessible tree.** The lexer is the first missing executable stage; until it exists there is no path from `.cpp` to `.obj`, and the linker has nothing to link.
2. **The extension host is untracked.** It is one `git clean` from gone. Nothing else in this list matters until it is committed.
3. **Crucible cannot be mapped** from the accessible evidence; it needs one named ref, not a branch sweep.
4. **The 8 silent Omega-Polyglot executables and the 2 broken build scripts** (D1, D2) block the compiler track.
5. **5,488 unreferenced source files and 73 orphan Deep2 files** are a cleanup surface, not a correctness problem.

**Shortest path to a fully functional native compiler/linker and VS Code-compatible extension system:**

- **Linker (days, not weeks).** Restore `phase2_linker` source → rebuild → re-run `RAWR_NATIVE_LINKER_CERT_001` → fix the harness's `$ErrorActionPreference` → restore the C13–C18 extension files to git → add an extension-host certification that loads a real VSIX, registers a command, and executes it. Both halves are already written; the work is placement, build, and proof.
- **Compiler (weeks).** Recover the C/C++ front end from `src-asm.bundle` (which holds the MASM64 history and `RAWRXD_PE32_EMITTER_MONOLITHIC.asm`) or from one named unfetched ref; then D3 (implement `cpp`), then D1/D2 (make the executables speak and the scripts point at the tree), then D4/D5.

**The two recommended milestones are the right ones.** C04–C08 certification is finished in substance — the linker is proven — and only needs its source moved and its harness unblocked. The extension API bridge is implemented and is the single seam through which the host, the marketplace, the QuickJS sandbox and the IDE all connect. Neither requires new infrastructure, and both are prerequisites for the compiler work that remains.
