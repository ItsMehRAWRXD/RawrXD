# RAWRXD Deep2 - Autonomous Certification State
Checkpoint: 2026-10-14. Master ledger: evidence/gate5_head_repro_2026-10-14/PARITY_RECEIPTS.txt (APPEND-ONLY).
Evidence manifest (SHA-256 of surviving raw dumps + new artifacts):
    evidence/BUILD_2026-10-14_UPME_PLAGUE_MEMORY/EVIDENCE_SHA256.txt

## Certified (real, receipted)
G01 freeze baseline | G02 cross-device transfer | G03 independent per-device budgets
G04 concurrent in-flight pinning | G05 native Q2_K/Q3_K GPU coverage (bounded parity, cpu_calls=0)
Phase-1 MoE (01 full-logit bit-identity, 02 secondary routing, 03 residency, 05 prefetch)
UPME ROM policy: 10/10 receipt stages, PASS (include/plague_memory.hpp + tools/plague_rom_receipt.exe)

## Resume queue (in order)
1. UPME Context policy: paged KV receipt - session/layer/token ownership, COW correctness
   (two agents mutate one page -> private copies), version-checked replication, attention-aware
   prefetch. Target: a real context KV stream with token-position assertions.
2. UPME Emulator policy: VAT + demand paging receipt - exec-page validation,
   dirty-page/COW tracking, invalidation of stale translated code, MMIO never replicated.
3. UPME Swarm: live multi-device ROM replica placement (bind a second engine instance so the
   fabric's device slots map 1:1 to physical GPUs; today only one engine is bound at a time).
4. Durable NVMe paging behind the ROM reconstructor (today the source is the model file itself).
5. Then the standing blockers: G06/G08 nemotron_h SSM first-divergent-tensor, G15 150 TPS,
   G07 671B model availability, G16/G18 Qt v143 ABI.

## Evidence integrity
A file-overwrite incident at 00:0x destroyed PARITY_RECEIPTS.txt; it was reconstructed from
the surviving raw dumps (hashed in the manifest) and the transcript numbers. Append-only
convention from here; the recomputed SHA of the reconstructed file is recorded in the manifest.
