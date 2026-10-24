# RawrXD — Branch Recovery and Enterprise Audit, 2026-10-24

This is a verified **branch-name discovery inventory**, not proof that each branch
contains complete, working implementations. Do not overwrite the active
`local-30b-backend` tree or import Qt dependencies.

| Workstream | Discovered GitHub branch | Next required audit |
|---|---|---|
| Pure MASM | `masm-pure` | Enumerate assembler sources; build x64/x86 conformance fixtures |
| Native MASM IDE integration | `feature/pure-masm-ide-integration` | Diff against native Win32 IDE; extract non-Qt code |
| MASM tuning | `feat/hexmag-polymorphic-repeat-tuner-masm` | Check source ownership and compatibility |
| Native linker certification | `audit/native-linker-cert-20261024` | Differential COFF/PE relocations, link and run |
| Native IDE CI | `ci/ide-native-build` | Compare workflow and MSVC flags |
| Clean recovery | `recovery-clean-source` | SHA-256 inventory before selective restore |
| Deep2 build recovery | `audit/deep2-build-recovery-20261024` | Compare current compile failures and patches |
| Fused GEMV recovery | `audit/fused-gemv-recovery-20261024` | Require parity before TPS benchmark |
| Deep2 parity certification | `cert/deep2-parity-probe-001` | Review oracle and deterministic token fixture |
| Deep2 local adapter | `feature/deep2-local-adapter` | Verify Ollama + Deep2 coexistence |
| Host GEMV performance | `perf/deep2-fused-host-gemv-20261020` | Reproduce baseline on current GGUF |
| 150 TPS research | `feature/reap-deepseek-671b-150tps` | Validate model/hardware comparability |
| Product preservation | `preservation/source-baseline-20261021` | Do not modify without passing release gates |
| Current Windows runtime | `local-30b-backend` | Current binary provenance and fresh receipts |

## Recovery rules
1. Inventory branch source files and SHA-256 before cherry-picking.
2. Compare file-by-file with the canonical product and active runtime trees.
3. Prefer native Win32/C++20 implementations; convert Qt-dependent logic
   rather than adding Qt or third-party packages.
4. Compile, link, execute and differential-test each recovered compiler/linker
   component. A file existing on a branch is not a passing feature.
5. Maintain separate x86, x64, Windows, Linux, macOS, Android and Apple
   mobile target certifications; cross-compilation support is not equivalent
   to runtime acceptance on the destination platform.
6. Require correct inference outputs before measuring or claiming 150 TPS.
7. Keep PR #58 draft until CI, correctness, security and integration pass.

## Status
Branch discovery: **performed** for the names above.
Per-file source audit: **pending**.
Qt-to-native conversion: **pending**.
Cross-platform compiler/linker certification: **pending**.
Enterprise production readiness: **not certified**.
