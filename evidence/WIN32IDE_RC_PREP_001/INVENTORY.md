# Packaging / installer / regression inventory — WIN32IDE_RC_PREP_001

`PROMOTE=0` · `PRODUCT_CERTIFIED=0` · `RC_PASS=NOT_CLAIMED` · tip `748B210A…`

## Packaging scripts (product-relevant)

| Script | Role | Dry-run status |
|--------|------|----------------|
| `scripts/rc_prep_dry_run_package.ps1` | Phase 10 PREP ZIP of TIP_FREEZE EXE+PDB | **WORKS** (this prep) |
| `scripts/create_release_package.ps1` | OMEGA-1 release tree | **PARTIAL** — defaults fixed to repo root; prefers `TIP_FREEZE_001` EXE; still not an RC seal (docs/inference optional gaps) |
| `scripts/create-release-package.ps1` | Signed release / MSI | **BLOCKED** — expects `RawrXD_Main.exe` / `rawrxd.dll` / `rawrxd-server.exe` (absent) |
| `tools/build_release_package.py` | v15.0.0 bundle | Historical; searches many build dirs; not tip-freeze bound |
| `src/deep2/PackageRelease.ps1` | SovereignSweep deep2 zip | Hardcoded `f:\~dev\…` paths; not Win32IDE RC |
| `scripts/rc_evidence_package.py` | RC0.1 JSON evidence synth | **NOT** product package; do not treat as certify |
| `scripts/generate_deployment_package.py` | Deployment tree | Separate from tip freeze |
| `scripts/release_prep.ps1` | Version bump / tag prep | Prep helper; not binary package |
| `installer/create_installer.bat` | Copies `bin\RawrXD_GUI_Minimal.exe` | **BLOCKED** — source EXE absent |
| `RELEASE_PACKAGE/silent/install_silent.bat` | Silent copy | Expects `build-fd\bin\rawr.exe` — absent |

## Installer sources

| Artifact | Kind | Tooling on machine | Status |
|----------|------|--------------------|--------|
| `installer/RawrXD.iss` | Inno Setup | ISCC **absent** | OPEN — cannot compile; sources `build\Release\RawrXD.exe` (absent); icon `resources\icons\rawrxd.ico` **absent**; redist vulkan/HIP **absent** |
| `installer/RawrXD_Installer.nsi` | NSIS | makensis **absent** | OPEN |
| `installer/RawrXD_Installer.wxs` / `RawrXD_Installer_v14.6.0.wxs` | WiX | candle **absent** | OPEN |
| `installer/setup.bat` / `SetupWizard.exe` | Custom | Present as file | OPEN — not tip-bound; not exercised this prep |
| `installer/windows/silent_install.bat` | Silent helper | Present | OPEN — not tip-bound |

## CMake install targets

- **Root `CMakeLists.txt`:** `add_executable(RawrXD-Win32IDE …)` (~L7519). **No `install(TARGETS RawrXD-Win32IDE …)`** found.
- **Subsystem install()** exists under e.g. `src/agentic`, `src/agents`, `src/ceo`, `src/codex`, `src/completion`, `src/core`, `src/debug`, `src/digestion`, … — not a Win32IDE RC layout.
- **`src/agentic/CMakeLists.txt`:** contains unresolved `<<<<<<< HEAD` merge conflict markers around `install(...)` — **cmake --install route BLOCKED** until resolved (documented OPEN; not fixed here — out of dry-run ZIP scope).
- **`cmake --install` for product tip:** **NOT_RUN** / **NOT_WIRED** for RawrXD-Win32IDE.

## Regression matrix readiness

| Surface | Path | Status |
|---------|------|--------|
| Closure matrix (RC-blocking + feature) | `evidence/WIN32IDE_CLOSURE_MATRIX_001/MATRIX.md` | Many **OPEN** / **BLOCKED** / **HELD** rows; A01/A03/G16/I01/I12 MET ≠ PROMOTE |
| Campaign law | `evidence/WIN32IDE_FULL_COMPLETION_CAMPAIGN_001/LAW.txt` | Phase 10 = Product certification / RC; PREP only here |
| B008 CI regression gate | `scripts/ci/b008_regression_gate.ps1` | Historical B005 path; not tip `748B` RC matrix |
| Production regression TU | `tests/test_production_regression.cpp` | Present; not sealed as Phase 10 RC |
| GhostText absorb regression | Campaign Phase 6 auth string | **ABSORB=NOT_AUTHORIZED** — full absorb regression **HELD** |

## Tip binary authority (dry-run input)

```
PATH=evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe
SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
build-ninja/bin/RawrXD-Win32IDE.exe = DIFFERENT SHA (63CD632A…) — do not package as tip
```

## Missing installer inputs (ISS / tooling) — OPEN

```
ISCC / makensis / candle          ABSENT on machine
build/Release/RawrXD.exe          MISSING (+ SovereignRuntime/LSP/Git/SciLexer DLLs)
resources/icons/rawrxd.ico        MISSING
redist/vulkan-1.dll, amdhip64.dll MISSING
models/tinyllama-1.1b-chat.gguf   MISSING
samples/*, docs/*.pdf             MISSING
LICENSE                           PRESENT
TIP EXE+PDB 748B…                 PRESENT (dry-run only; ≠ installer input for ISS)
```

Seal: `DRY_RUN.txt` · `PROMOTE=0` · `PRODUCT_CERTIFIED=0` · no invent CERTIFIED.
