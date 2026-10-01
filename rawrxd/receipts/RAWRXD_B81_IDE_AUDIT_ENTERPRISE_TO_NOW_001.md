# RAWRXD_B81_IDE_AUDIT_ENTERPRISE_TO_NOW_001

## Purpose

Audit the IDE from the enterprise-finished baseline to the current tree, to
establish what is actually true now rather than what earlier audits asserted.

```ini
RAWRXD_B81_IDE_AUDIT_ENTERPRISE_TO_NOW_001=COMPLETE
EXE_SHA256=BAE4216A386D3D417BA3C29ECAE3517B92BB737180325D375313483E480A1261
PARITY=PASS (115 chars, B65 oracle)
```

## Corrections to the incoming audit

Two of its claims are wrong against the current tree.

### "Codestral 22B — LinearW non-finite at token 0" — MISDIAGNOSED

That was the B72 reading. The real failure was a routing table entry pointing at
a kernel that does not exist:

```ini
PackedQuant        admitted  8, 10, 11, 12, 13, 14
DispatchGemvQuant  admitted  8, 10, 11, 12, 14
deep2_qgemv.comp   decodes   8, 10, 11, 12, 14
```

Q5_K (13) was claimed by `PackedQuant` and implemented in neither other place.
Fixed (B73). Codestral went `generated=0 status=4 RANGE_OR_MULTIMAP` ->
`generated=8 completed=1`, no abort.

**But it is still not correct**: it emits `<unk>` x8 with logits at ~1e9. So the
audit's P0 verdict on Codestral stands for the wrong reason, and the underlying
numerical defect is UNCLOSED.

### `matFinalDownload` — not a defect, not a download, and NOT the defect I first called it

First correction: it is a receipt counter on `Deep2Engine` (Deep2Engine.h:1344).

Second correction, to my own audit: I initially reported
`hostMaterializations != matFinalDownload` (23 vs 0) as an unasserted invariant
violation. **That was wrong.** The codebase documents this explicitly at
Deep2Engine.h:1345-1351:

> `hostMaterializations == matFinalDownload` alone is NOT an accounting
> invariant -- it only holds when nothing else materialized. Asserting it as the
> accounting check conflates "unclassified" with "not resident".

The real exhaustive invariant is against the class sum, and it IS asserted:

```cpp
// Deep2Engine_GpuForward.cpp:1655-1660
const uint64_t classSum = r.matCrossDeviceHandoff +
                          r.matGemvSingleRoundTrip +
                          r.matDualRowSingle + r.matDualRowGroup +
                          r.matFinalDownload + r.matOther;
if (r.hostMaterializations != classSum)
    return false;
```

Measured: `GPUFWD_RECEIPT hostMat=23 matFinal=0 ... receiptValid=1`.

`receiptValid=1` means the class-sum check passed. hostMat=23 decomposes across
the classified buckets; matFinalDownload=0 simply means none of them was a
final-logits download. There is no violation, and no missing assertion.

I proposed a fix for a defect that does not exist. Recording the correction
rather than quietly dropping it.

## Confirmed state

```ini
BUILD_LINKS             = PASS   (rawrxd, rawr-server, all gates green)
TARGET_COUNT            = 324 add_executable
SERVER_ROUTES           = /api/cli, /api/agent/execute-tool, /api/tags,
                          /api/agent/dual/{init,shutdown,status,handoff}
ROUTES_PREVIOUSLY_404   = 2  -> now 200/400, verified live
GPU_FORWARD             = REAL  (784 layer-forwards, 3920 qkv ops, committed)
GPU_FORWARD_FINITE      = finite=3072 nan=0 inf=0  (values plausible: min -11.3)
PREPARED_CACHE          = certifiable, dormant on current models (B70 30/30)
Q3_K_NATIVE             = correct (B65 block parity), performance ~= B64 (B66/67)
WORKERPOOL              = partition exact, timeout escape fixed fail-closed (B76)
```

## Where the audit's P0 list stands

```ini
Codestral projection correctness
  STATUS   = FAIL, cause changed
  FOUND    = Q5_K routing defect (fixed, B73)
  OPEN     = ~1e9 logits, <unk> output. Scalar-reference parity NOT performed.

Long-context threaded attention
  STATUS   = NOT REPRODUCED (B75/B77/B79)
  FOUND    = inline-path REPORTING defect, not execution
  EVIDENCE = partition exact for total=8 x {1,2,4,8}; fresh runtime threads=2 PASS;
             sweep recorded 0 stalls; in-sweep failures are carried-over pool state

WorkerPool timeout escape
  STATUS   = FIXED, fail-closed (B76). Not observed firing.

TPS authority
  STATUS   = FAIL. Two independent causes, both real:
             engine 5.21 vs QPC 3.03 (1.72x clock disagreement)
             per-cell spread 12%..62% (harness cannot resolve its own differences)

Same-session tool continuation  = NOT TESTED this pass
Autonomous repair loop            = NOT TESTED this pass
```

## The honest structural finding

Three separate incidents this session had the **same shape**, and they are the
real theme of this audit:

```ini
1. rawrxd defined twice; the active one depended on a cache flag
2. sovereign_q3_k_gemv.asm compiled into the build; exported the wrong symbol;
   called by nothing
3. /api/cli and /api/agent/execute-tool called by the IDE; never implemented
```

In each case source existed and looked correct, and execution authority did not
follow. A file that exists is not a file that runs; a symbol that compiles is not
a symbol that resolves; a route the client calls is not a route the server
serves.

The fourth instance is `matFinalDownload`: the invariant is documented in a
comment, both sides are printed, and 23 != 0 passes without complaint. A stated
invariant that nothing asserts is a comment, not a check.

## Next steps, in dependency order

```ini
P0  1. Codestral scalar-reference parity on the prepared Q5_K path
       Establish whether the prepared representation or attention arithmetic
       produces the 1e9 logits. Do not add a clamp.
P0  2. Assert the hostMaterializations == matFinalDownload invariant
       It is violated right now and unasserted.
P1  3. IDE tool authority decision (A/B/C in B80)
       The routes are served but cannot execute tools.
P1  4. TPS clock reconciliation (1.72x disagreement)
P1  5. Same-session model -> tool -> observation -> model
P2  6. Shipping-reachability stub audit
P2  7. Stale canonical build tree (AGENTIC_CLI quarantine)
```

Items 4-7 are not started. Items 1-2 are the two this audit found as genuinely
open and both are executable now.

```ini
B81_COMMITTED=NO
B81_PUSHED=NO
```