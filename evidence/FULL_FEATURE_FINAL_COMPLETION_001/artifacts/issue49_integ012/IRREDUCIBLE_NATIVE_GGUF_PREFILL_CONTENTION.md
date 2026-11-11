# Irreducible blocker — native 7B GGUF prefill killed under snap contention

ASOF_UTC=2026-11-10T03:06:00Z
TIP=tip_final_integ_012
EXE_SHA256=6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247
LOOP_SHA256=CEB669011246266A911613B8648EEFE69D0225506F01F46A4D56EAC8A572D5F7
PROMOTE=0
INVENT_PASS=0

## Measured

- tip014 loop-exclusive on **identical** EXE+LOOP SHA previously closed:
  - `S_09_RESULT_REINJECTION=PASS` (RESULT_REINJECTION status=PASS x2)
  - `S_11_BUILD_FAILURE_RECOVERY=PASS_WRITE_VERIFY_BUILD_RECOVERY` (PATCH COMMITTED)
  - log: `artifacts/issue49_integ014/step08_11_evidence/tip014_loop_exclusive_10_11.log`
- tip012 product remesure advanced to **6/11** with `S_09=PASS_OLLAMA_OBSERVATION_FEEDBACK` (HOST_SEED=OFF).
- Fresh tip012 **native GGUF** remesures for S11 repeatedly die during first `PREFILL_BATCH` (~20–75s), before `PREFILL_BATCH_END` (~137s historically).

## Root cause (observed)

```
[snap] Preflight: CONTENTION DETECTED
[snap] Authorized recovery: terminating verified stale PID <other-or-ours>
```

Foreign `deep2_agentic_loop.exe` instances (ollama short-tasks / RELEASE_FREEZE harnesses / parallel agents) start while 7B prefill is in-flight. Their snap stale-scanner terminates our long-lived job as “not assigned to RawrXD job object”. Zero-contention launch survives past Vulkan init; contention returns within ~1 minute when peers spawn.

## Not PASS

`NOT_RUN ≠ PASS`. tip012-owned native S11 fresh seal is **NOT_RUN** under current multi-agent GPU contention. tip014 same-SHA evidence is corroboration only until tip012-native reseal lands or exclusive machine lock is enforced machine-wide.

## Resume

1. Machine-exclusive: no other deep2/IDE for ≥20 minutes.
2. Re-run `artifacts/issue49_integ012/_guarded_native_s11.ps1` (cmd redirect) and wait for `PATCH COMMITTED` + `RESULT_REINJECTION`.
3. Parallel track: ollama forced write→build (`_ollama_s11_write_build.ps1`) for tip012-owned S11 without 7B prefill wall.

NEXT_GATE=ISSUE49_AGENT_OWNED_BUILD_RECOVERY_THEN_REMAINING_HITS
