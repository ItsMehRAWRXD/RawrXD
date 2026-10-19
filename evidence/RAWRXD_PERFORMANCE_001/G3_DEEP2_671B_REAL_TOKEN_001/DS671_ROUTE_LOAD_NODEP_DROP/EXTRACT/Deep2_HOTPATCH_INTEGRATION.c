/*
Deep2 hotpatch integration point.

Call ds671_require_route() IMMEDIATELY AFTER the real DeepSeek router has
produced its Top-K expert IDs and BEFORE the expert GEMV/GEMM consumes weights.

The returned handles are opaque 64-bit caller-owned values. They may be:
  - CPU pointers to mapped/copied expert packs
  - GPU allocation/descriptor handles
  - Deep2 weight-pack handles

There is no file format logic here. Deep2's existing GGUF tensor index should
implement measure/load/release so this module never scans or streams the model.

DeepSeek-V3 671B reference configuration:
  transformer layers: 61
  dense layers:       3
  MoE layers:         58
  routed experts:     256 per MoE layer
  active routed:      8 per token/layer

Recommended first-run config:

ds671_config cfg;
cfg.moe_layers = 58;
cfg.experts_per_layer = 256;
cfg.top_k = 8;
cfg.mode = DS671_MODE_GROW_NO_EVICT;
cfg.routed_expert_budget_bytes = user_selected_budget;

Runtime hook:

    router_top8(hidden, ids, scores);
    rc = ds671_require_route(&g_ds671, token_index, moe_layer, ids, 8, &rr);
    if (rc != DS671_OK) FAIL_CLOSED(rc);

    // rr.handles[i] is the loaded pack for ids[i].
    deep2_expert_forward(hidden, rr.handles, ids, scores, 8);

After prompt:
    ds671_seal_prompt(&g_ds671, prompt_token_count);

STRICT mode:
    DS671_MODE_STRICT_PROMPT_ONLY
    New expert after prompt => DS671_E_DECODE_MISS.
    Useful for deterministic gate testing.

GROW mode:
    DS671_MODE_GROW_NO_EVICT
    New decode expert => synchronous caller load if budget remains.
    No eviction, no prefetch thread, no background sequential streaming.
*/
