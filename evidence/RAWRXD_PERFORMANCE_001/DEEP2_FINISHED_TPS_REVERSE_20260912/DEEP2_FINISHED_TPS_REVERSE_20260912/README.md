# DEEP2_FINISHED_TPS_REVERSE_20260912

A dependency-free C source drop that makes the 12–25 TPS finished-Deep2 projection explicit and falsifiable without touching the certification binary.

The code has two modes:

- `project`: computes the weight-bandwidth requirement for target TPS values. It always prints `FULL_MODEL_TPS_AUTHORITY=0`.
- `observe`: converts measured token/wall/byte counters into TPS, ms/token and effective weight bandwidth, and checks minimum no-shortcut eligibility conditions. It still does **not** mint certification authority; the cert harness remains the authority owner.

Example:

```text
d2_perf_gate --mode project --weight-bytes 25000000000 --peak-bw-gbs 640
```

A candidate 64-token observation can be evaluated with:

```text
d2_perf_gate --mode observe --tokens 64 --wall-ns <measured> --weight-bytes-total <measured> --full-model 1 --all-blocks 1 --steady-allocs 0 --sealed-reuse 0 --synthetic-logits 0 --synthetic-weights 0 --device-lost 0
```

Do not feed estimates into `observe`; the counters are intended to be copied from the timed full-model gate after the running TARGET64 regression is sealed.
