# Batch 23 — Dummy-model smoke with negative controls; no false PASS

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Audited and repaired

1. `tools/test_fake_model_registry_e2e.cpp` previously checked only whether its fake `editFiles` arguments contained the string `fixture.cpp`. This could accept wrong old/new values or paths with that substring. Commit `0de2495bffaeaaff9e0e6b6505a7a002eae473bb` requires exact known fixture transaction and validates readFile input.
2. Added negative controls for traversal-shaped payload and wrong old text, including disk-unchanged assertions. Commit `4d609687bfe1c326d999aa4fdf673c769bca47b9`. Harness now contains 19 checks, not 15.
3. CI retains the mock test output as a clearly labeled NON-PRODUCTION-CERTIFICATION artifact and uses `set -o pipefail` to avoid masking a failed test behind `tee`. Commit `aa04c04398b5f473d9a0cd4d6b8cfadc517b4938`.

## Actual local execution (2026-11-05)

- `python /mnt/data/fake_model_pipeline_smoke.py`: 15/15 PASS. This is a separate Python mock simulation, not RawrXD production code.
- `g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer /mnt/data/test_agent_workspace_containment.cpp -o /mnt/data/containment_smoke_v2 && /mnt/data/containment_smoke_v2`: 15/15 PASS. This is a local standalone C++ algorithm smoke, not a linked dispatcher/IDE test.
- Local `git ls-remote https://github.com/ItsMehRAWRXD/RawrXD.git HEAD` failed because container DNS could not resolve github.com. GitHub connector was used for authoritative branch source inspection and commits.
- The new 19-check GitHub C++ mock test was NOT executed in this session. CI runs/status were not confirmed.

## Gate classification

SIMULATED_MODEL_PIPELINE=PASS (local Python only)
STANDALONE_WORKSPACE_CONTAINMENT=PASS (local C++ only)
PRODUCTION_MODEL_TOOL_CALL=NOT_RUN
PRODUCTION_EDITFILES_DISK_READBACK=NOT_RUN
NATIVE_WINDOWS_BUILD=NOT_RUN
DEEP2_NUMERIC_CORRECTNESS=NOT_RUN
GPU_CORRECTNESS=NOT_RUN
GUI_CANCEL_RECOVERY_SOAK=NOT_RUN
INDEPENDENT_CERTIFICATION=NOT_RUN

## Fifteen production acceptance obligations, all still require evidence

01 Windows IDE build, 02 CTest, 03 actual production parser, 04 actual registry routing, 05 model-originated tool call, 06 production mutation approval, 07 production editFiles disk write, 08 exact disk readback, 09 real ToolResult reinjection, 10 strict cancel A-Stop-B, 11 crash recovery, 12 Deep2 CPU numerical reference, 13 GPU numerical reference, 14 soak and packaging, 15 independent certification.

A fake model is a valid deterministic test input; a fake editFiles provider is not proof that the production editFiles provider works. Do not promote based on mock evidence.
