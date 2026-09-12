# Deep2 roofline enhancements — Top 15

These enhancements optimize `BYTES_NOT_ALREADY_LOCAL_PER_TOKEN` and the finish
time of the two useful GPU lanes. They do not replace the live packed kernels.

1. **Active-byte token ledger**
   - Counts packed weights + KV + activations + compact-reduction bytes actually
     required by token N.
   - Total model size is never substituted for active token bytes.

2. **Already-local byte accounting**
   - Separates VRAM0/VRAM1 hits from RAM/MMAP/NVMe misses.
   - Governing metric: `BYTES_NOT_ALREADY_LOCAL_PER_TOKEN`.

3. **Local-hit ratio authority**
   - Emits Q16 local-hit ratio for every token.
   - Lets optimization target locality rather than advertised aggregate VRAM BW.

4. **Tier-aware remote penalty**
   - RAM, mmap/NVMe service, and PCIe transport are costed separately.
   - Remote bytes can no longer disappear from a theoretical GPU-only roofline.

5. **Measured-bandwidth dual-GPU splitter**
   - Splits local useful bytes by measured lane bandwidth, not equal rows.

6. **Start-skew correction**
   - Earlier GPU receives extra useful work proportional to its head start.

7. **Finish-time objective**
   - Predicted critical path is `max(GPU0_END, GPU1_END) + unavoidable_remote_ns`.
   - Optimizes completion time, not overlap percentage.

8. **Critical-path NVMe veto**
   - Any token with a critical-path NVMe read is non-authoritative.

9. **N+1 prefetch budget generator**
   - Uses currently free VRAM and a bounded safety margin to make next-token
     misses local before they become token-N+1 stalls.

10. **Selected-expert pin hint**
    - MoE tokens with selected experts produce an explicit pin request.
    - Designed to bind to existing exact-range residency rather than duplicate it.

11. **Packed quant density registry**
    - Q2_K/Q3_K/Q4_K/Q5_K/Q6_K/Q8_0 known directly.
    - Unknown quant forms fail closed instead of silently F32-expanding.

12. **Compact-reduce eligibility**
    - Emits compact-reduce only when both GPU lanes have useful same-token work.

13. **Best-critical-path retention**
    - Learns only from authoritative tokens and remembers the fastest measured
      live split.

14. **5% regression rollback**
    - A materially slower measured token can reuse the best-known split instead
      of allowing an unstable controller to drift.

15. **Fail-closed roofline receipt**
    - Product-linked + packed-native + material overlap + parity are mandatory.
    - Command rebuild, KV host roundtrip, NVMe critical-path read, host
      materialization, CPU F32 expansion, serial GPU chain, weight migration or
      device loss revoke authority.
