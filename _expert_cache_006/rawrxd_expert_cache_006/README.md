# RAWRXD_EXPERT_CACHE_006

Cumulative source-only expert-cache drop carrying the Batch 003 packed-expert catalog/slicer,
Batch 004 asynchronous Vulkan transport/staging layer, Batch 005 stack-safety + dual-GPU
scheduler, and Batch 006 multi-GPU cache authority + A/B receipt support.

## Batch 006 additions

- one host/RAM backing copy per expert, registered into multiple per-device VRAM caches
- router-probability + locality + live compute/transfer-pressure device placement
- planned ownership for prefetched experts and ready ownership after demand acquire
- safe migration: target acquire completes before optional source eviction
- cache-OFF mode using the exact same GPU path, with post-compute eviction for fair A/B tests
- prefetch-first poll on demand so a completed async transfer does not create a false fence wait
- corrected accounting: `residentBytes` means ready VRAM, `inflightBytes` means transfer-reserved VRAM
- separate `transferMicros` from unhidden `stallMicros`
- multi-device receipt and cache OFF/ON benchmark formatter
- no CPU expert matmul fallback

## Portable gates

The included deterministic source tests pass 002 through 006. `test_batch006` deliberately uses a
mock transport; its byte/stall figures certify cache behavior and accounting, not AMD hardware TPS.

## Hardware acceptance still required

Attach two real `VulkanExpertTransport` instances to Deep2's existing R9700 / RX 7800 XT Vulkan
handles and run the same prompt/model/token-count twice: cache OFF then cache ON. Only the resulting
Windows hardware receipt should be used as a real TPS claim.
