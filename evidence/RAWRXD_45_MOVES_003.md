# RAWRXD 45-move batch 003 — 25-target parity and projection correctness

## Batch 1: 01–15 (repository inspection + data correctness)
01 Confirm feature branch; 02 verify preservation branch; 03 inspect K2 shard index;
04 inspect K2 shard I/O; 05 inspect MoE router; 06 inspect MoE loader;
07 inspect LivePath; 08 inspect Slingshot law; 09 verify tensor offsets;
10 check expert bounds; 11 distinguish gate projection; 12 distinguish up projection;
13 distinguish down projection; 14 require all three projections before retention;
15 reject oversized reads.

## Batch 2: 16–30 (new code and tests)
16 Introduce projection-aware key; 17 introduce projection hash;
18 separate resident bindings by projection; 19 use bounded reads;
20 retain only complete experts; 21 track actual read calls;
22 track storage bytes; 23 track resident reuses; 24 reject unknown experts;
25 reject duplicate projections; 26 make eviction explicit;
27 write synthetic three-projection test; 28 assert resident reuse;
29 create 25-target parity manifest; 30 require evidence before certification.

## Batch 3: 31–45 (benchmark protocol and remaining gates)
31 Inventory top-25 comparison targets; 32 define editor capability;
33 define LSP capability; 34 define debugger capability;
35 define terminal capability; 36 define extension capability;
37 define inline completion capability; 38 define agent capability;
39 define multi-file edit capability; 40 define rollback capability;
41 define offline operation capability; 42 prohibit untested PASS;
43 preserve unknown as unknown; 44 require reproducible receipts;
45 require a full 500-cell comparison before claiming 100% parity.

## Status
Projection-aware source and tests are committed; runtime Vulkan integration remains pending.
Matrix initially marks every cell Unknown. A list of comparison products is not a ranking.
A 100% result requires independently reproduced tests, not inferred features.
No Qt dependencies introduced; no Qt conversion undertaken without inspecting relevant source.
