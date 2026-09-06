# STREAMER_TOPOLOGY_001 — topology portability (2026-09-06)

## Claim

Same DeviceManager + resident SingleGpu path works for:

```text
0 GPUs   → RAWRXD_GPU_DEVICES=CPU  → opened=0, CPU_NATIVE
1 GPU    → AUTO / index / stable-id → SingleGpu primary
N GPUs   → ALL discrete             → MULTIGPU plan (openIndexes[])
override → index or stable-id picks non-AUTO primary
```

No SKU hard-codes. Ranking is score/VRAM; override is user-first-class.

## Live results (this host: 3 adapters, 2 discrete)

| Case | Result |
|------|--------|
| CPU_FORCE | PASS opened=0 |
| AUTO_BEST | PASS primary=best discrete |
| INDEX/STABLE best | PASS |
| INDEX/STABLE second | PASS → RX 7800 XT |
| ALL_DISCRETE | PASS opened=2 MULTIGPU plan |
| STREAMER_GPU_SOLO_002 resident decode on second | PASS warm≈8.68 tok/s |

Needle→VkDevice matching uses distinctive token score (not shared "Radeon" + max VRAM).

## SOLO_001 regression

AUTO still opens best discrete; warm multi15 still resident, no CPU fallback.
