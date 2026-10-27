# Agent Instructions

You are a reverse engineer.

## Assembler Tooling

Use this MASM x64 assembler path when needed:

`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe`

(Obsolete: `C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe` — not present on this machine.)

## x64 ABI — FP volatility (permanent)

```text
XMM0-XMM5 = CALLER-VOLATILE ACROSS CALL
ANY LIVE FP VALUE ACROSS CALL = SPILL OR RELOAD
```

Callee may clobber XMM0–XMM5. Callers must spill/reload any live FP state that must survive a `call`.

## RawrXD performance (when working under rawrxd/)

Governing handoff: `rawrxd/evidence/RAWRXD_PERFORMANCE_001/PERF_COMPLETION_CONTRACT.md`

Deep2 scheduling ownership (scoreboard = scheduler; layer-loop join ≠ authority):
`rawrxd/evidence/RAWRXD_PERFORMANCE_001/G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001/`
(`INVERSION_LOCKED=1`; P1 product bind SOURCE_WIRED via `ProductScoreboardBind.hpp`;
`SCOREBOARD_SCHEDULER_LIVE=1` via controlling witness
`G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001` `RUN_ID=2b7091ecdbaf4d06b8edb424897961ce`;
`PROMOTE=0` · `TIP_CLIMB=HOLD` · R28 APPLY held;
`NEXT_GATE=POST_SCHEDULER_PROMOTION_REQUIREMENTS`;
`deep2_benchmark.exe` outside this seal;
P3 ForwardMLALayers joins held — `SCOREBOARD_WAIT_PER_LAYER=1`).

Coverage + epoch only. No directional climb. `TIP_CLIMB=HOLD` until Phase A closes and SEARCH_BASELINE is installed. Finite unique space = 18. Exhaustion without promotion is valid completion.

### Final readiness / promote gate (product path)

```text
SCOREBOARD_SCHEDULER_LIVE=1   # input only; ≠ PROMOTE
                              # witness: G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001
                              # RUN_ID=2b7091ecdbaf4d06b8edb424897961ce

PROMOTE_IF = PRODUCT_OPEN_PASS && SESSION_ENTER_PASS
             && GENERATED_TOKENS>0 && TOKEN_COMMIT_PASS
             [+ independent multi-family/product coverage]
PROMOTE=0 until that higher-level conjunction passes
MULTI_FAMILY = next independent gate
             (≠ TinyLlama R25 ProductOpen seal)
             (≠ scoreboard ownership reopen)
NEXT_GATE=POST_SCHEDULER_PROMOTION_REQUIREMENTS
```

Authority: `Deep2ProductGate.hpp::PromoteReady`. See `READY_PROMOTE_TETRAD_001` and playbook S5 vs S6.
Post-scheduler law: `G3_DEEP2_SCOREBOARD_POST_SCHEDULER_PROMOTE_001/LAW.txt`.

### Experimental SSM (owner E)

```text
RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1  # user-auth scaffolding only
PROMOTE_AUTHORIZATION=RESUME_EXPERIMENTAL_TO_E2E_READY
EXPERIMENTAL_NEQ_SSM_CERTIFIED_IMPL
PROMOTE=0 TIP_CLIMB=HOLD CHAMPION_PROMOTE=0
```

Emit: `lavapath/ExperimentalSsmAuth.hpp` (ProductStreamerPrep + Deep2Engine SSM load).
Live auth+E2E: `G3_E_SSM_EXPERIMENTAL_AUTH_001` / `G3_E_SSM_EXPERIMENTAL_E2E_002` /
`G3_E_SSM_EXPERIMENTAL_E2E_003` (Mamba2 SSM_BUF arm; IDENTITY=0; PROMOTE=0).
Opt-in Nemotron scan (not default): `RAWRXD_DEEP2_NEMOTRON_SSM_SCAN=1`.
Auth promote unblocks experimental E2E readiness only — does not rewrite `G3_E_SSM_CERT_001` or R1 matrix.
Next criteria batch (1 turn + 14): `G3_E_SSM_MAMBA2_NUMERIC_15_001`
(alias → `G3_NEMOTRON_H_MAMBA2_STABILIZE_CRITERIA_015`).
Production ladder plus-14: `G3_NEMOTRON_H_REAL_SSM_CRITERIA_029` (C16–C29 OPEN; PROMOTE=0).
