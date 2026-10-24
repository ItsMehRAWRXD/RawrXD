# 45-move continuation 004: proof infrastructure

**Scope:** New source and CI wiring, not 45 completed production integrations.

## 01–15: source discovery and safety
01 Check branch continuity; 02 preserve main; 03 preserve original GGUF; 04 inspect K2 offsets;
05 inspect expert count; 06 inspect projection key; 07 inspect stream counters; 08 inspect top-25 matrix;
09 establish pre-top-k masking; 10 reject NaN logits; 11 reject insufficient retained experts;
12 reject invalid selected experts; 13 avoid Qt; 14 avoid third-party C++ libraries;
15 retain opt-in isolation.

## 16–30: test infrastructure
16 Add route-mask header; 17 add mask test; 18 assert retained logits unchanged;
19 assert masked logits negative infinity; 20 assert selected IDs validated;
21 assert top-k retained-count precondition; 22 add Linux smoke workflow;
23 add Windows MSVC smoke workflow; 24 enable warnings; 25 enable warnings-as-errors;
26 run four existing smoke tests; 27 run new route-mask smoke test;
28 isolate test artifacts; 29 run on branch pushes; 30 run on pull requests.

## 31–45: certification protocol
31 Demand CI evidence; 32 demand GPU evidence; 33 demand model output parity;
34 demand per-projection quant parity; 35 demand multi-token parity;
36 demand 11-shard completeness; 37 demand deterministic router tests;
38 demand read amplification measurements; 39 demand cache reuse measurements;
40 demand device-lifetime correctness; 41 demand Qt dependency inventory;
42 demand actual native conversion when required; 43 demand IDE feature tests;
44 demand 25-product capability evidence; 45 forbid 100% certification without receipts.

## Not yet proven
- CI workflow run result, native Windows build, Deep2 live MoE integration, full 1.5-bit codec,
  multi-shard DeepSeek generation, 25-product independent benchmark coverage.
- Workflow has no GPU hardware and cannot certify Vulkan throughput.
- Existing projection bridge is synchronous and uses an unbounded count of resident entries;
  maxReadBytes limits one read, not total residency.
- Model parity remains UNKNOWN until end-to-end receipts are produced.
