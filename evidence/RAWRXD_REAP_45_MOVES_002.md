# RAWRXD REAP / ROM / Pinball: 45 engineering moves

Branch: `feature/reap-deepseek-671b-150tps`. No Qt, no new external dependencies. Original GGUF shards remain read-only.

## Batch A: 01–15 — index and correctness
01 Identify canonical product and preservation branches.
02 Inventory branch candidates.
03 Inspect `K2GlobalTensorIndex`.
04 Inspect `K2ShardIo`.
05 Inspect `MoERouter`.
06 Inspect `MoEWeightsLoader`.
07 Inspect `Deep2LivePath`.
08 Inspect `SlingshotLaw`.
09 Establish opt-in bridge.
10 Add synthetic bridge test.
11 Validate missing-expert rejection.
12 Verify absolute GGUF `fileOffset`.
13 Verify relative expert `byteOffset`.
14 Reject out-of-range expert IDs.
15 Reject malformed expert strides.

## Batch B: 16–30 — source-level plumbing
16 Add `ResolveExpert` adapter.
17 Bind to native `K2ShardIo_Read`.
18 Validate on-disk shard bounds.
19 Require layer identity.
20 Require expert identity.
21 Require nonzero slice size.
22 Avoid tensor-offset double addition.
23 Keep codec representation explicit.
24 Implement reference ternary pack.
25 Implement reference ternary unpack.
26 Reject invalid ternary symbols.
27 Reject invalid packed codewords.
28 Test 0–99 symbol lengths.
29 Preserve immutable source shards.
30 Keep production decode disabled pending parity.

## Batch C: 31–45 — execution readiness
31 Add bounded per-request counters.
32 Count storage bytes.
33 Count host-to-device bytes.
34 Count packed bytes.
35 Count resident hits.
36 Count cache misses.
37 Count failures.
38 Add portable trace output.
39 Verify Pinball resident binding reuse.
40 Require GPU fence-safe eviction.
41 Separate gate/up/down projection identities (still pending).
42 Integrate validated native 1.5-bit decoder (still pending).
43 Wire live MoE/Vulkan execution (still pending).
44 Run full 11-shard numerical parity (hardware pending).
45 Certify end-to-end TPS only from actual hardware receipts (pending).

## Current scope
The completed work is **repository-source scaffolding and defensive fixes**, not a full 45/45 production certification.
The reference ternary packer is intentionally not claimed to be the historical TCQ/Brutal native 1.5-bit codec.
It packs four trits per byte (2 bits/value in this reference format), and it must not be applied to GGUF Q4_K_M tensors.

## Critical unresolved integration details
- The current bridge key lacks projection identity. One instance per projection is required until fixed.
- `MoERouter` pruning must happen before top-k.
- `K2GlobalTensorIndex` is Kimi K2-oriented; DeepSeek metadata compatibility must be validated.
- `MoEWeightsLoader` exposes a single-file Open API, not full 11-shard proof.
- GPU buffer lifetime and async fence ownership need backend-specific integration.
- Live Deep2 generation is not yet connected or certified.
