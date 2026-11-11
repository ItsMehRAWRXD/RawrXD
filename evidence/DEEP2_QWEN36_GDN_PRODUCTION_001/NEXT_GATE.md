# Next gate

Localize the first GPU/CPU divergence for Qwen3.6 position 0 using an
independent per-operation trace or oracle. Start at the first block/operator
boundary and compare the real GPU and CPU operands/results; retain the current
GDN trace as proof that GDN is reached and passes its local differential check.

Do not relax tolerances or label the current run full-model PASS. After the
first divergence is localized, patch only the demonstrated owner, rebuild the
current target, and rerun the same two-token contract.

Separately map `runtime_ir.cpp` routed MoE and SSM call sites and dispatch
conditions before implementing those currently unimplemented paths.

