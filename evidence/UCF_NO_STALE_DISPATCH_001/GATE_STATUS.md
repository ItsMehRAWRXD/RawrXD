# UCF_NO_STALE_DISPATCH_001

## Authority (locked)

```text
AUTHORITY:  src/deep2/rawr_uncoherent_object_fabric.hpp
PROOF:      deep2_ucf_bounce_smoke.cpp → UCF_BOUNCE_SMOKE=PASS
INTEGRATION: deep2_ucf_no_stale_dispatch_001.cpp
BANKED:     K2RainbowFoldTable.hpp
```

## Non-authority

```text
UncoherentFabric64.asm     — sandbox-only; NOT on disk; NOT in cert path
ml64 @ AGENTS path         — missing; MASM not assumed
src/deep2/ucf/*            — experimental / non-sealed alternate sketches
```

## Cert wording

UCF authority is C++20 header-only object fabric.

- No MASM object required
- No `UncoherentFabric64.asm` on disk
- No `ml64` path assumed
- Sealed behavior is semantic:
  - opaque `DeviceId` lanes
  - expected-generation RW dispatch (`dispatchRWExpected` / `acquireExpected`)
  - stale generation → `GenerationMismatch` (not “latest pointer wins”)
  - host relay fallback (P2P = cost, not correctness)
  - commit-driven generation advance

## Required witness

```text
CREATE gen=1
A acquire expected=1
A commit → gen=2
B acquire/dispatch expected=1 → GenerationMismatch
B ensure current
B acquire expected=2
B commit → gen=3
PASS
```
