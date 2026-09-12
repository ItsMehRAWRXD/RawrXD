# Product bind map

Use these 15 generators at the seams that already exist in Deep2Engine; do not introduce a second runtime.

- At start of each N>0 token, call `d2g_token_transaction` only to validate/record transaction order.
- Before the packed dual operator, call `d2g_dual_finish_plan`; its returned work split is the *only* balancing authority for that invocation.
- At session/model shape changes, call persistent-command and descriptor generators. Stable signatures must yield `rebuild=0` / `rebind=0` after warmup.
- Before each KV write, call `d2g_kv_advance` and bind the returned device offset to the existing persistent KV owner.
- Residency/prefetch generators feed existing exact-range load queues; token N must not block on an NVMe request first issued inside token N's critical section.
- MoE locality output is a placement plan only; inactive experts remain cold.
- Quant dispatch must resolve packed-native product executors. `D2G_ECAP` means fail closed, not CPU expansion.
- LM-head tiling and compact-reduce generators feed the same product GPU queues.
- Sampler commit is emitted only from the live logits epoch.
- UTF-8 chunking occurs after token commit and never changes token identity.
- Reset increments the generation epoch; stale asynchronous work must compare epochs before commit.
- After each measured token, populate `D2GAuthorityInput` from existing product counters and call `d2g_authority_receipt`.

The live 16-token decode-bind gate must still prove 16/16 authoritative N>0 transactions. This package is source plumbing, not evidence authority.
