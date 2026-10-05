# RAWRXD_HEXMAG_CERTIFICATION_001

Scope: the HexMag control-plane chain, from MASM backend to end-to-end cert.
Build: Release (`/O2 /MT`), through CMake and executed through ctest.

```ini
BUILD=Release  CONFIGURE_EXIT=0  BUILD_ERRORS=0  CTEST_EXIT=0

HEXMAG_ABI_001              = 25/25 PASS  exit 0   PROBE_HAS_POWER=1
REPEAT_TUNER_RELEASE        = 33/33 PASS  exit 0
RUNTIME_CONTROLLER_RELEASE  = 27/27 PASS  exit 0
IDE_E2E_RELEASE             = 58/58 PASS  exit 0

CTEST_RUNS=20  CTEST_PASS=20  CTEST_FAIL=0

ARTIFACT_SHA256_16 =
    hexmag_abi_probe.exe               223BBFF5AD8BFBED
    hexmag_repeat_tuner_cert.exe       5064A75A3A25339C
    hexmag_runtime_controller_cert.exe C8281FB265BB0FC5
    hexmag_ide_e2e_cert.exe            D72441305C18EFEB

HEXMAG_SHIPPING_OPTIMIZED_AUTHORITY = PASS
```

All four gates are registered with ctest (`ctest -R hexmag`) and were not
before this change. They were built but never executed.

---

## What this added

| Path | Was | Now |
|---|---|---|
| `src/asm/RawrXD_HexMag_Swarm.asm` | 221 B auto-generated stub exporting only `RawrXD_HexMag_Swarm_Stub` | 15 real exports, 256-slot event ring, fail-closed grant model |
| `src/asm/RawrXD_HexMag_RepeatTuner.asm` | 245 B stub | 10 real exports, deterministic escalation, FNV-1a genome fingerprint |
| `src/asm/RawrXD_HexMag_AbiProbe.asm` | absent | calling-conformance probe (MASM, 2 negative controls) |
| `tests/hexmag_ide_e2e_cert.cpp` | 43 B `// STUB:` | 58 checks |
| `tests/hexmag_runtime_controller_cert.cpp` | 54 B `// STUB:` | 27 checks |
| `tests/hexmag_repeat_tuner_cert.cpp` | 48 B `// STUB:` | 33 checks |
| `src/agent/hexmag_client.cpp` | 24 B stub; `connect()` returned true unconditionally | real transport; backend identity probed, not asserted |
| `include/agent/hexmag_client.hpp` | second copy of the same type | forwards to the one definition |
| CMake | ABI probe unreachable; no cert registered with ctest | probe target added; 4 `add_test()` entries |

---

## The load-bearing property

`claimFromSwarmAnswer()` treats an answer containing `"goal.satisfied"` as
verifier evidence. A swarm that emitted that payload on completing its own
search would certify itself with nothing verified. So the backend reaches
satisfaction **only** after an external grant arrives via `HexMag_Feedback(0)`:

```ini
NO_GRANT_RUN   -> IDLE_FAIL, no GOAL_SATISFIED event
GRANTED_RUN    -> OK, GOAL_SATISFIED emitted
FACADE_NO_GRANT-> success=false, error="FINAL_GATE: claim not verified"
```

---

## Defects found and fixed

Every one of these was found by executing against the real artefact.

### 1. Systematic Windows-x64 ABI violation in the MASM backend

`RSI` and `RDI` are **nonvolatile**. Nearly every routine in the swarm backend
used them without restoring them. This is invisible at `/Od` (which spills
everything) and destructive at `/O2` (which keeps values live across a call).

Found by `HEXMAG_ABI_001`: `FIRST_BAD_EXPORT=HexMag_Shutdown`,
`FIRST_BAD_REGISTER=RDI`, then `HexMag_PollEvent`, `HexMag_Step`,
`HexMag_RunToSatisfied`. Twelve routines repaired.

### 2. The cert aborted its host process

The crash reporter returned `EXCEPTION_EXECUTE_HANDLER`, so an optimized run
killed whatever invoked it — replacing a verdict with a crash code and
producing no receipt. It now records containment as an ordinary failed check
and exits 2.

### 3. Frame overflow in the cert harness

`E10`, `E11` and `E14` each held a live `Drain` plus a `HexMagClient` and
several `std::string`s across every `check()` detail construction. At `/O2`
those functions inlined `drainAll` and became the largest frames in the binary.
The corruption landed on a loop counter and **moved every time a local was
resized** — the signature of a frame overflow. Repaired by keeping one `Drain`
live per frame: `fingerprintForGoal()`, `e11_grant_path()`/`e11_withdraw_path()`,
`runClientTrip()`.

### 4. Unbounded poll loop

`E14` drained with `while (client.pollEvent(...))` and no bound. Now bounded,
reporting `POLL BOUND HIT` rather than running away.

### 5. A 128-byte destination receiving up to 480 bytes

An earlier payload-capture buffer overran and overwrote a saved `RBP` with the
text `"cand=0  "`. Replaced with exact typed values, which also made `E10`'s
assertion stronger (integer equality instead of substring match).

### 6. Inverted success condition in the transport

`HexMagClient::send()` treated `rc > 64` as failure. A real goal id is a 64-bit
digest, so it is *larger* than any `HX_ERR_*` status code. Caught by `E14`.

### 7. Nonexistent source in the build graph

`cmake/RawrXDSovereignFinish.cmake` referenced `src/models/ModelCatalog.cpp`,
which has never existed, and unguarded — every `CMake Error` at generate step
killed the whole project build. No `ModelCatalog` API exists anywhere and
nothing references one, so the vestigial reference was removed and the outcome
reported in the configure log rather than satisfied with an empty file.

---

## The instrument was itself wrong six times

Recorded because a gate that cannot fail is worse than no gate.

1. GPR mask accumulated into `eax` and never folded into the result — all eight
   GPR checks were computed and discarded. Reported 25/25 clean while the
   control's `RSI`/`RBX` clobbers went unseen.
2. Canary values `0x88888888`/`0x99999999` have bit 31 set and `cmp r64, imm32`
   sign-extends, so `R14`/`R15` read as permanently clobbered.
3. The probe never allocated a frame. Windows x64 has no red zone, so its
   locals landed in the caller's frame: first call fine, second corrupted it.
4. Eight pushes is a multiple of 16, so it never realigned the stack.
5. The epilogue popped in the wrong order.
6. It clobbered `xmm6`–`xmm15` on its own caller.

Both negative controls now gate the gate: a plain clobber control
(`RSI+RBX+XMM14`) and a `rep movsb` control matching `HexMag_PollEvent`'s exact
register shape. Both fire; `PROBE_HAS_POWER=1`.

---

## Refuted along the way

Recorded so a later pass does not resurrect them:

```ini
STATIC_CRT_MEMCPY_CAUSAL      = REFUTED   no call memcpy on the path; the copy
                                          is compiler-generated and inline
MEMCPY_ENTRY_TRIPLE           = RETRACTED it was e11_grant_completes' own entry
                                          registers; it takes no arguments
RVA_0x13C438_CODE_IDENTITY    = REFUTED   outside .text, no .pdata entry; it was
                                          a stack value, never a caller
DRAIN_RETURN_SHAPE_CAUSAL     = REFUTED   out-parameter form failed identically
DRAIN_SIZE_CAUSAL             = REFUTED   1280 -> 400 -> 220 bytes, no effect
PARSEHEX64_INLINE_CAUSAL      = REFUTED   noinline did not change the failure
FRAME_BASE_CORRUPTED          = REFUTED   RBP bit-identical at entry, PH7,
                                          before-call and fault
BASIC_BLOCK_REORDERING        = UNPROVEN  /Ob0 disables INLINE EXPANSION; the
                                          defect is inline-sensitive, not proven
                                          to be a reordering bug
MEMCPY_SOURCE_IN_UNCOMMITTED  = RETRACTED the fault address is an advanced
                                          cursor, not the original source
```

Two of my own claims were also retracted mid-hunt: that the faulting routine was
CRT `memcpy` in our image (it is an inline copy inside `e11_grant_completes`),
and that `RAX` at the fault was a memcpy argument.

---

## Reproduce

```
cmake -S rawrxd -B <build> -DBUILD_RAWRXD_AGENTIC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build <build> --config Release --target hexmag_abi_probe
    hexmag_repeat_tuner_cert hexmag_runtime_controller_cert hexmag_ide_e2e_cert
ctest --test-dir <build> -C Release -R hexmag --output-on-failure
```

`BUILD_RAWRXD_AGENTIC` defaults OFF, so none of this is in a default build.

---

## Not proven

- The 20-run stability figure covers these four gates only. The ~330
  sovereign-kernel stubs remain a census, not implementations.
- None of the three certs carries a negative control proving it can reject
  wrong backend behaviour. They can fail (demonstrated repeatedly during this
  work) but no permanent falsification test exists.

---

## `HEXMAG_ABI_SEQUENCE_001` — BUILT, FAILS, NOT REGISTERED

```ini
PROBE_HAS_POWER=1
SEQUENCES_TESTED=5   SEQUENCES_PASS=2   SEQUENCES_FAIL=3
COMPOSITION_ABI_DEFECT=PRESENT   VERDICT=FAIL
```

A composition gate: canaries held across a whole CHAIN of exports rather than
one call at a time. It has two negative controls that both fire correctly (a
clean chain reports `mask=0`; a deliberate clobber is detected as
`RSI+RDI+R12+XMM14`), so its findings are not instrumentation noise.

**It reports a real, unattributed finding:** across 3 of 5 chains the
nonvolatile `R12` comes back modified, holding an address inside this image at
offsets `0x2B580` / `0x2B780` / `0x2BB80` — `.rdata`, spaced `0x200`, so a
static table rather than code.

### What is cleared about the backend

```ini
PUSH_POP_BALANCE = VERIFIED
    hxS_Emit        push 1 / pop 2 (2 exits)
    HexMag_SubmitGoal push 1 / pop 4 (4 exits)
    HexMag_Step     push 1 / pop 8 (8 exits)
    HexMag_PollEvent push 1 / pop 2 (2 exits)
    all other routines 1 / 1
R12_USE_OUTSIDE_hxS_Emit = NONE
hxS_Emit_R12_PUSH_POP     = BALANCED
```

A bisect localised the trigger to `HexMag_SubmitGoal` **followed by**
`HexMag_RunToSatisfied` on a live swarm: either alone is clean, the pair is not.

### What is refuted

```ini
CRT_FIRST_USE_ARTIFACT = REFUTED
```

I hypothesised the hits were a one-time CRT first-use path and added a warm-up
workload to absorb them. **The warm-up does not help — the hits recur.** That
hypothesis is withdrawn, and the source comment says so, so it is not retried.

### `HEXMAG_CALL_TRACE_001` — LOCALISED TO ONE CALL

Logging every export one call at a time, with a full nonvolatile snapshot either
side of each call, reduced "a chain is wrong" to "this call is wrong".

```ini
STEP  CALL                      MASK       DELTA  R12
  1   HexMag_Init               0x000000   -      canary held
  2   HexMag_SetParallelAgents  0x000000   -      canary held
  3   HexMag_SubmitGoal         0x000010   R12    img+0x245B0   <== DAMAGED HERE
  4   HexMag_RunToSatisfied     0x000000   -      canary held
  5   HexMag_PollEvent          0x000000   -      canary held
 ...  every other export       0x000000   -      canary held
```

**Deterministic, and state-dependent.** Three fresh `Init → SubmitGoal → Shutdown`
cycles:

```ini
cycle 1 SubmitGoal   CLEAN
cycle 2 SubmitGoal   R12 -> img+0x24610
cycle 3 SubmitGoal   R12 -> img+0x24610
```

Same value both times, so it is systematic, not a first-use cost.

### Where it is NOT

```ini
hxS_ClearGoal      = CLEAN  (writes exactly 1024 B to a 1024 B buffer; no r12)
hxS_GoalDigest     = CLEAN  (also reached by HexMag_Step, which traces clean)
hxS_ZeroScratch    = CLEAN  (also reached by HexMag_Step, which traces clean)
hxS_Emit           = push/pop r12 BALANCED; no jump bypasses the pop
HexMag_Step        = CLEAN  and it reaches all three helpers above
SubmitGoal(in-flight early return) = CLEAN
```

So the damage is on `SubmitGoal`'s fresh-goal path, past the in-flight check,
and it is not `hxS_ClearGoal`. `hxS_Emit` is the remaining candidate that
`Step` does not reach in the traced state — the next concrete step is to
disassemble `hxS_Emit` in the linked image and confirm the `pop r12` restores
the pushed value.

### Why neither is registered with ctest

Both are built and runnable, and deliberately NOT `add_test`'d. Registering a red
gate would make `ctest -R hexmag` red and would devalue the four green ones.
Neither is hidden: both report `FAIL` every run and both findings are recorded
here.

This is a hardening gate. It does not indicate that the certified four-gate
shipping path is still bleeding: all four remain green through the real build
system.

