# Batch 22 — Deterministic dummy-model acceptance work

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Major finding: test scope must be explicit

The audited `~dev/src/rawr_agent_dispatch.cpp` registers **read-only audit tools** and ledger operations; it does NOT register production `editFiles`. Therefore a fake-model test with a test-only `editFiles` handler cannot certify the actual IDE or CLI edit path. The new harness explicitly labels its editor as TEST-ONLY.

## Production repair

- `44ae700cc44a73bd0bd6ccab50ac11ec0dffefc1`: `AgentToolRegistry::resolveExecutable` now rejects relative executable paths that escape an authorized search root through `..` or symlinks.
- `bed7afc0affb23969937789ac7e8cb477c87e4b8`: portable registry tests for valid relative executable, blocked parent traversal, blocked symlink escape where supported, and explicitly configured absolute executable.
- `46fee69f226851c994b80b902584f408ea060282`: MSVC CI registry tests.

## Deterministic fake-model test committed

- `f65e3881c7af7c5e7293d1021b8ad6ad8dce0876`: C++ smoke with scripted model reply -> production portable reply parser -> production registry -> TEST-ONLY editFiles provider -> real temporary disk mutation -> readback -> simulated reinjection -> final parse, denial, unknown-tool and cancellation.
- `da79e9623fa4440b54f4659754600c06b5d5b077`: Linux CI compiles and executes the C++ smoke against the production portable parser and registry.

## Tests actually executed in this session

Local Python simulation `fake_model_pipeline_smoke.py` with temporary source fixture:
01 model reply parse PASS
02 tool name PASS
03 path argument PASS
04 original digest PASS
05 mutation denied PASS
06 denial preserves disk PASS
07 approved mutation PASS
08 success message PASS
09 exact disk readback PASS
10 digest changed PASS
11 readFile success PASS
12 ToolResult matches disk PASS
13 mock prompt reinjection PASS
14 final reply PASS
15 unknown tool rejected PASS

**15/15 PASS applies ONLY to the self-contained Python simulation.** It does not use RawrXD source, production parser, real agent loop, real editFiles handler, local inference engine, or Windows GUI. It is not a certification gate.

## Not executed

The committed C++ fake-model smoke, registry tests, Windows build, CTest, actual model, Deep2 CPU/GPU, T05 cancellation, GUI soak and independent certification were not executed here. GitHub returned no status checks or workflow runs for latest commit.

## Next decisive gate

Compile and execute the C++ mock against actual production parser and registry, then wire and test a REAL `editFiles` handler in the production agent authority with explicit mutation approval and disk readback. Do not conflate test-only edit success with product edit success.
