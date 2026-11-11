# S07 Q6 per-op timing receipt — 2026-10-20

This receipt is from the rebuilt `deep2_spec_bench` executable with `DEEP2_OP_TIMING=1`. The dominant per-token interval is the quantized dot batch flush (~195 ms); the LM-head operation is ~14.4 ms in the serial arm. This identifies synchronization/submission amortization as the next 40-TPS target. It is diagnostic evidence only and does not close S07.
