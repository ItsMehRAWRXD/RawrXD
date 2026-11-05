# Batch 6 — Fifteen registry boundary cases and file-read overflow repair

Date: 2026-11-05
Source branch: `fix/deep2-multimodel-safety-20261025`
Disposition: CHANGES_COMMITTED / EXECUTION_NOT_VERIFIED
Promotion: 0
Certification: 0

## Actual source changes

- `7e71d1a48b61d810f9991d9e12f6ee40553cb094`: 15 independent deterministic assertions in `tools/test_agent_registry.cpp` against the production `AgentToolRegistry` class.
- `e0e6d5ce449f6c9f99437b34646b4873fcdafb14`: correct unsigned-overflow and invalid-range behavior in `toolFileRead` in `~dev/src/rawr_agent_dispatch.cpp`.

## Fifteen registry checks added

R01 canonical ID registration
R02 case-insensitive canonical lookup
R03 alias lookup
R04 canonical descriptor lookup
R05 successful handler dispatch
R06 exactly-once handler execution
R07 duplicate canonical ID rejected
R08 duplicate alias rejected
R09 failed registration preserves registry size
R10 unknown tool rejected with exit 127
R11 cancelled dispatch exits 130
R12 cancelled handler not executed
R13 failure accounting includes unknown and cancelled dispatch
R14 unregister by alias
R15 removal invalidates ID and leaves registry empty

These cases are **committed tests, not 15 verified runtime passes**. The repository CI workflow `.github/workflows/agent-registry-portable.yml` is expected to compile and execute the test on Linux; its outcome must be inspected independently.

## Open work

- Confirm C++20 portable test compile and runtime results.
- Isolate production model-reply parser into a dependency-light unit-test target.
- Prove real model-originated tool call -> authorized mutation -> disk readback -> result reinjection.
- Prove Deep2 numerical correctness and GPU execution.
- Re-run native GUI, stress, package and independent certification gates.

Do not claim 100% completion from this evidence.
