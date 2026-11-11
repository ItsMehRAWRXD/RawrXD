# Gate 2 primitive producer provenance repair

Status: **producer/admission regression checks PASS; broader Gate 2 OPEN**.

The audit began at `843a14c3298ab6aade87fbb597748bd8311f2716`. Another commit landed during the work, moving HEAD to `56e749c7bd61e4c15d78c6619e5a082d3a785fd7`. These are working-tree receipts, not clean-tip release certificates. Exact source/executable hashes are recorded in `start_provenance.json` and `repair_provenance.json`.

## Defects and repair

The first producer defect was in `src/deep2/modelgenie/ModelGenomeReader.cpp`: a frozen `FIRST_UNPROVEN_BOUNDARY MLA_DECOMPRESS_FORWARD` string supplied the current missing-primitive verdict, all required primitives were simultaneously copied into the available set, and `runtimeExecutable` was set false unconditionally. The global generated capability header still visibly places MLA in both available and unimplemented sets.

The reader now uses `RefreshModelGenomeCapabilities` at line 113 and invokes it after graph production at line 748. It derives the required set from execution operations, queries the existing authoritative registry's `available && kernelPresent` verdict, partitions implemented/missing requirements, and resets stale prior capability state. `runtimeExecutable` explicitly means complete primitive bindings for a nonempty produced graph. It does not certify numerical/model/GPU execution.

The admission defect was independently reproduced by freshly compiling a probe: an unknown required primitive value `0xffff` was accepted by `QuantParityRegistry::RuntimeExecutable`. The baseline probe exited 1 as expected. The registry now rejects every non-None required primitive whose binding is unavailable or absent. Known primitive bindings and quantization arithmetic are unchanged; MatMul remains unavailable.

Production-source changes:

- `src/deep2/modelgenie/ModelGenomeReader.cpp`
- `src/deep2/modelgenie/ModelGenomeReader.hpp` (existing UTF-16 encoding preserved)
- `src/deep2/QuantParityRegistry.cpp`
- `src/deep2/modelgenie/tests/ModelGenomeCapabilitiesTests.cpp`

Reader consumers now require the registry TU. The narrow dependency addition was applied to `tools/build_deep2_executor_e2e.bat`, `compile_ir_executor.bat`, and `compile_modelgenie_lib.bat`. These batch files are ignored by the repository's `*.bat` rule; integration must deliberately include needed recipes rather than assume their modifications are tracked. No top-level CMake, runtime executor, generated global manifest, or historical receipt was edited.

## Executed validation

All CPU commands and transcripts are retained here. No GPU work ran.

- Current existing-binary C1–C7 consistency run: exit 0; `current_consistency.log` and `current_consistency_command.json`.
- Fresh MSVC 19.44.35228.0 / C++20 configure: exit 0; `configure.log`.
- Fresh build of the admission probe, producer tests, registry certifier and K-quant parity executable: exit 0; `repaired_build.log`.
- Fresh producer/reader tests: exit 0, 15 checks, zero failures; `producer_tests.log` and `producer_tests_command.json`. Cases cover implemented registry bindings, stale MLA diagnostics, exact required-set partitioning, duplicate requirements, missing MatMul, unknown required IDs, empty graphs, and the actual frozen reader with a synthetic MLA graph fixture.
- Fresh repaired admission probe: exit 0, unknown-required admission false; `repaired_admission_probe.log` and `repaired_probe_command.json`.
- Fresh registry/Q8/K-quant C1–C7 comparison against the existing hashed CLI: exit 0; `fresh_registry_consistency.log` and `fresh_registry_consistency_command.json`. This is explicitly a fresh registry/quant build plus an existing CLI binary.
- `git diff --check` on the modified UTF-8 production sources: exit 0.

Initial probe compilation diagnosed the generated header's dependence on an external Primitive alias; an attempted compatibility-shim include also collided with the registry's distinct GGMLType alias. The probe was corrected locally without modifying product headers. Those unsuccessful compile logs are preserved separately; the final baseline and repaired probes compile and run.

## Why broader Gate 2 remains OPEN

Current registry evidence reports 35 known quantization types, 22 kernel bindings, 13 missing kernels, one packing-verified type, zero registry dot-verified types, and zero registry logits-verified types. Its admission test reports one certified type, three probe-only types, and one refused type. A manifest-consistency PASS does not convert that coverage into primitive/numerical certification.

The CLI still transcribes primitive statuses and reports `source_revision` by running git at invocation time. An older unchanged CLI binary reported both starting and later HEAD values in the two runs. Consequently C3 demonstrates repository freshness at execution time, not compiled-binary/source identity. C7 checks that cited artifacts contain `PASS`; it does not bind those artifacts to the current model/backend/source snapshot or validate verdict scope.

The stale global generated capability header and stored `evidence/capability_manifest.json` remain unchanged pending explicit integration/regeneration. Actual runtime graph dispatch uses its own op binding authority and does not call this quant admission registry. Additional requirements must be certified against that real dispatch path.

Root integration should add the CPU regression target with sources `ModelGenomeCapabilitiesTests.cpp`, `ModelGenomeReader.cpp`, and `QuantParityRegistry.cpp`, using existing parity-target include paths. Register a test that passes a build-local fixture directory. No CMake change was made here because that file belongs to the numerical/build workstream.

## Gate reconciliation

`tools/gate2_manifest_consistency.ps1` explicitly identifies historical Gate 2 of `MODEL_GENIE_NATIVE_FORWARD_001`. October 13 re-verification evidence names this gate primitive provenance. The user-proposed roadmap in `evidence/RELEASE_ROADMAP_2026-10-13/ROADMAP.md` uses distinct `RELEASE_G10`–`RELEASE_G20` identifiers. Historical Mamba2/ModelGenie and STRATA gate IDs retain their original meanings. Historical October 13 Gate 12–20 definitions remain `LEDGER_NOT_LOCATED`; neither the July ladder nor K2 substitutes for them.

No commits or pushes were made by this workstream. Integration review and broader primitive certification remain with root.
