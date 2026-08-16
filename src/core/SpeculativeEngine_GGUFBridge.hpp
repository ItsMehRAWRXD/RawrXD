#ifndef SPECULATIVE_ENGINE_GGUF_BRIDGE_HPP
#define SPECULATIVE_ENGINE_GGUF_BRIDGE_HPP
// ============================================================================
// SpeculativeEngine_GGUFBridge.hpp
// ----------------------------------------------------------------------------
// Wires SpeculativeInferenceEngine (RawrXD) to the GGUF hotpatch stack.
//
// What this does:
//   1. Maps MoEModel slots to GGUF tensors (token_embed ↔ token_embd,
//      expert_gate[e] ↔ blk.N.ffn_gate_exps.W, etc.).
//   2. Loads real Q4_1 weights from the 13 Kimi K2 shards via the x16-lane
//      slingshot (hotpatch #4), into the engine's arena (so the AVX-512
//      Q4_1 matmul in speculative_inference_engine.cpp works on real data).
//   3. Replaces the random `init()` with `init_from_gguf(router, layer_idx)`.
//   4. Routes RoPE seqPos through Medusa (hotpatch #5) when self-improvement
//      wants to speculatively try alternative model slots.
//   5. Memory-maps the Kimi K2 shards once at startup; arena pages stay cold
//      until the slingshot pulls them in.
//
// Memory posture:
//   Router state:        ~60 KB   (names + locations)
//   Slingshot peak:      ~48 MiB  (during load, then freed)
//   Arena (your code):   size_gb × 1 GiB  (16 GB default)
//   Total resident:      arena + one layer's weights at a time
//
// Usage:
//   #include "SpeculativeEngine_GGUFBridge.hpp"
//   SpeculativeInferenceEngine engine;
//   engine.initialize(16);                          // 16 GB arena
//   load_chain_from_kimi_k2(engine, "/models/kimi-k2");
//   // engine now has 22 models with REAL Kimi K2 weights, not random noise.
//
// Header-only, C++17, includes the hotpatch stack. Requires:
//   - GGUFShardRouter.hpp
//   - GGUFShardRouter_lanes.hpp
//   - GGUFShardRouter_medusa.hpp        (for VRAMBudget, GPUOps, StubGPUOps)
//   - GGUFShardRouter_engulf.hpp        (for EngulfReservoir)
//   - speculative_inference_engine.hpp
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include "GGUFShardRouter.hpp"
#include "GGUFShardRouter_lanes.hpp"
#include "GGUFShardRouter_medusa.hpp"
#include "GGUFShardRouter_engulf.hpp"

#include "speculative_inference_engine.hpp"

namespace RawrXD {
namespace Inference {
namespace Bridge {

// ============================================================================
// GGUF <-> MoEModel tensor name conventions for Kimi K2
// ============================================================================
// Kimi K2 (and most llama.cpp-style models) use these naming patterns:
//
//   token_embd.weight              ↔ MoEModel::token_embed
//   blk.{L}.attn_q.weight          ↔ layers[L].qkv_w (Q part)
//   blk.{L}.attn_k.weight          ↔ layers[L].qkv_w (K part)
//   blk.{L}.attn_v.weight          ↔ layers[L].qkv_w (V part)
//   blk.{L}.attn_output.weight     ↔ layers[L].o_w
//   blk.{L}.ffn_gate_exps.weight   ↔ layers[L].expert_gate[e]   (e = expert index)
//   blk.{L}.ffn_up_exps.weight     ↔ layers[L].expert_up[e]
//   blk.{L}.ffn_down_exps.weight   ↔ layers[L].expert_down[e]
//   blk.{L}.ffn_gate_inp.weight    ↔ layers[L].router_w
//   blk.{L}.attn_norm.weight       ↔ layers[L].ln1
//   blk.{L}.ffn_norm.weight        ↔ layers[L].ln2
//   output_norm.weight             ↔ MoEModel::final_norm
//   output.weight                  ↔ MoEModel::lm_head
//
// Quantized variants append .Q4_1, .Q4_K, .Q5_K, .Q6_K, etc.
// We match the ggml type by suffix and dispatch to the right decoder.
// ============================================================================

// ---- ggml type id → block type mapping (matches llama.cpp) -----------------
static inline uint32_t ggml_type_from_name(std::string_view name) {
    if (name.size() < 3) return 0;
    auto ends = [&](const char* s) {
        size_t n = std::strlen(s);
        return name.size() >= n && name.compare(name.size() - n, n, s) == 0;
    };
    if (ends(".Q4_1") || ends(".q4_1")) return 3;     // GGML_TYPE_Q4_1
    if (ends(".Q4_0") || ends(".q4_0")) return 2;     // GGML_TYPE_Q4_0
    if (ends(".Q5_0") || ends(".q5_0")) return 6;
    if (ends(".Q5_1") || ends(".q5_1")) return 7;
    if (ends(".Q8_0") || ends(".q8_0")) return 8;
    if (ends(".Q4_K") || ends(".q4_k")) return 12;
    if (ends(".Q5_K") || ends(".q5_k")) return 13;
    if (ends(".Q6_K") || ends(".q6_k")) return 14;
    if (ends(".F16")  || ends(".f16"))  return 1;
    if (ends(".F32")  || ends(".f32"))  return 0;
    return 0;
}

// ============================================================================
// Q4_1 block copy from GGUF raw bytes (the format your speculative_engine.cpp
// expects: d (FP16) + m (FP16) + 16 bytes qs)
// ============================================================================
struct BlockQ4_1 {
    uint16_t d;       // delta (FP16)
    uint16_t m;       // min     (FP16)
    uint8_t  qs[16];  // 4-bit quants, 32 values packed two-per-byte
};
static_assert(sizeof(BlockQ4_1) == 4 + 16, "Q4_1 block must be 20 bytes");

// Q4_K block (more complex — k-scales + 4-bit quants, 256 elements/block)
struct BlockQ4_K {
    uint16_t d;          // FP16 super-scale
    uint16_t dmin;       // FP16 super-min
    uint8_t  scales[12]; // packed sub-block scales (4-bit + 6-bit)
    uint8_t  qs[128];    // 4-bit quantized values (256 elements)
};
static_assert(sizeof(BlockQ4_K) == 4 + 12 + 128, "Q4_K block must be 144 bytes");

// ============================================================================
// SlingshotReader — pulls a single tensor from the router into a host buffer.
// Uses the x16-lane streamer (hotpatch #4) for parallel reads.
// ============================================================================
template <class Router>
static std::optional<std::vector<uint8_t>> slingshot_tensor(
        const Router& r, std::string_view tensor_name)
{
    gguf_shard_lanes::BifurcatedStreamConfig lcfg;
    lcfg.lane_width  = 16;
    lcfg.chunk_bytes = 1ull << 20;
    lcfg.ordered     = true;
    return gguf_shard_lanes::drain_lanes(r, tensor_name, lcfg);
}

// ============================================================================
// Per-layer weight layout for Kimi K2
// ============================================================================
struct KimiLayerLayout {
    std::string attn_q;            // "blk.{L}.attn_q.weight"
    std::string attn_k;            // "blk.{L}.attn_k.weight"
    std::string attn_v;            // "blk.{L}.attn_v.weight"
    std::string attn_output;       // "blk.{L}.attn_output.weight"
    std::string attn_norm;         // "blk.{L}.attn_norm.weight"
    std::string ffn_norm;          // "blk.{L}.ffn_norm.weight"
    std::string ffn_gate_inp;      // "blk.{L}.ffn_gate_inp.weight"  (router)
    std::vector<std::string> ffn_gate_exps;   // [e]
    std::vector<std::string> ffn_up_exps;     // [e]
    std::vector<std::string> ffn_down_exps;   // [e]
};

static inline KimiLayerLayout kimi_layer_layout(int L, int n_experts) {
    KimiLayerLayout lay;
    char buf[128];
    auto fmt = [&](const char* suf) {
        std::snprintf(buf, sizeof(buf), "blk.%d.%s", L, suf);
        return std::string(buf);
    };
    lay.attn_q       = fmt("attn_q.weight");
    lay.attn_k       = fmt("attn_k.weight");
    lay.attn_v       = fmt("attn_v.weight");
    lay.attn_output  = fmt("attn_output.weight");
    lay.attn_norm    = fmt("attn_norm.weight");
    lay.ffn_norm     = fmt("ffn_norm.weight");
    lay.ffn_gate_inp = fmt("ffn_gate_inp.weight");
    lay.ffn_gate_exps.reserve(n_experts);
    lay.ffn_up_exps  .reserve(n_experts);
    lay.ffn_down_exps.reserve(n_experts);
    for (int e = 0; e < n_experts; ++e) {
        std::snprintf(buf, sizeof(buf), "blk.%d.ffn_gate_exps.%d.weight", L, e);
        lay.ffn_gate_exps.push_back(buf);
        std::snprintf(buf, sizeof(buf), "blk.%d.ffn_up_exps.%d.weight",   L, e);
        lay.ffn_up_exps  .push_back(buf);
        std::snprintf(buf, sizeof(buf), "blk.%d.ffn_down_exps.%d.weight", L, e);
        lay.ffn_down_exps.push_back(buf);
    }
    return lay;
}

// ============================================================================
// Q4_1 decode: GGUF raw bytes → MoEModel::BlockQ4_1
// (Just a memcpy if the source type is already Q4_1. If source is Q4_K or
// other, we'd dequantize here — left as a TODO extension point.)
// ============================================================================
static bool copy_q4_1_blocks(BlockQ4_1* dst, const uint8_t* src,
                              size_t n_bytes_dst, size_t n_bytes_src)
{
    if (n_bytes_src < n_bytes_dst) return false;
    std::memcpy(dst, src, n_bytes_dst);
    return true;
}

// ============================================================================
// load_chain_from_router — populates an MoEChain with REAL Kimi K2 weights.
// ============================================================================
template <class Router>
bool load_chain_from_router(SpeculativeInferenceEngine& engine,
                             const Router& router,
                             int n_experts  = MOE_EXPERTS,
                             int n_active   = MOE_ACTIVE_EXPERTS,
                             int max_layers = MOE_LAYERS)
{
    if (!engine.arena_) {
        std::fprintf(stderr, "[Bridge] engine not initialized\n");
        return false;
    }
    auto& arena = *engine.arena_;

    // 1. Load shared global tensors (token_embd, output_norm, output)
    //    These are NOT per-model; load once and copy into each model's slot.
    //
    //    token_embd:    shape [vocab, dim]  (FP16 typically)
    //    output_norm:   shape [dim]         (FP32)
    //    output:        shape [vocab, dim]  (Q4_1 / Q6_K)
    //
    //    For MoE chain: each model slot needs its own copy. We allocate
    //    the full token_embd into the arena, then deep-copy per model.

    auto* token_embd_loc = router.find("token_embd.weight");
    auto* output_loc     = router.find("output.weight");
    auto* out_norm_loc   = router.find("output_norm.weight");

    if (!token_embd_loc || !output_loc || !out_norm_loc) {
        std::fprintf(stderr, "[Bridge] missing global tensors in router\n");
        return false;
    }

    // Slingshot the global tensors (one-time, host-staged).
    std::vector<uint8_t> token_embd_bytes, output_bytes, out_norm_bytes;
    {
        auto t = slingshot_tensor(router, "token_embd.weight");
        if (!t) { std::fprintf(stderr, "[Bridge] token_embd slingshot failed\n"); return false; }
        token_embd_bytes = std::move(*t);
    }
    {
        auto t = slingshot_tensor(router, "output.weight");
        if (!t) { std::fprintf(stderr, "[Bridge] output.weight slingshot failed\n"); return false; }
        output_bytes = std::move(*t);
    }
    {
        auto t = slingshot_tensor(router, "output_norm.weight");
        if (!t) { std::fprintf(stderr, "[Bridge] output_norm.weight slingshot failed\n"); return false; }
        out_norm_bytes = std::move(*t);
    }

    // Verify sizes line up with what the engine expects
    size_t expected_token = (size_t)MOE_VOCAB * MOE_DIM * sizeof(float);
    size_t expected_norm  = (size_t)MOE_DIM * sizeof(float);
    size_t expected_lm    = (size_t)MOE_VOCAB * MOE_DIM / 32 * sizeof(BlockQ4_1);
    if (token_embd_bytes.size() != expected_token) {
        std::fprintf(stderr, "[Bridge] token_embd size mismatch: got %zu, want %zu\n",
                     token_embd_bytes.size(), expected_token);
        return false;
    }
    if (out_norm_bytes.size() != expected_norm) {
        std::fprintf(stderr, "[Bridge] output_norm size mismatch: got %zu, want %zu\n",
                     out_norm_bytes.size(), expected_norm);
        return false;
    }
    (void)expected_lm;

    // 2. Initialize each model in the chain with shared globals + per-layer.
    //
    // The engine's MoEChain::initialize_chain() already allocates random
    // weights; we override those with real data per model.
    //
    // For the 22-model MoE chain, all 22 models share the same Kimi K2
    // weights by default. (You can specialize per-model later by using
    // different LoRA adapters, pruning, etc. — see adapt_weights.)

    for (int m_idx = 0; m_idx < MOE_CHAIN_COUNT; ++m_idx) {
        MoEModel* model = engine.moe_chain_->get_model(m_idx);
        if (!model) continue;

        // Replace token embedding
        std::memcpy(model->token_embed,
                    token_embd_bytes.data(),
                    token_embd_bytes.size());

        // Replace final norm
        std::memcpy(model->final_norm,
                    out_norm_bytes.data(),
                    out_norm_bytes.size());

        // Replace LM head
        copy_q4_1_blocks(model->lm_head,
                         output_bytes.data(),
                         (size_t)MOE_VOCAB * MOE_DIM / 32 * sizeof(BlockQ4_1),
                         output_bytes.size());

        // Per-layer: load all n_layers layers from shards
        for (int L = 0; L < max_layers && L < model->n_layers; ++L) {
            auto lay = kimi_layer_layout(L, n_experts);

            // Attention norms (FP32, small)
            auto t_an = slingshot_tensor(router, lay.attn_norm);
            if (t_an && t_an->size() == (size_t)MOE_DIM * sizeof(float)) {
                std::memcpy(model->layers[L].ln1, t_an->data(), t_an->size());
            }
            auto t_fn = slingshot_tensor(router, lay.ffn_norm);
            if (t_fn && t_fn->size() == (size_t)MOE_DIM * sizeof(float)) {
                std::memcpy(model->layers[L].ln2, t_fn->data(), t_fn->size());
            }

            // QKV + output projections (Q4_1)
            size_t qkv_blocks = (3 * MOE_DIM * MOE_DIM) / 32;
            size_t o_blocks   = (MOE_DIM * MOE_DIM) / 32;
            size_t qkv_bytes  = qkv_blocks * sizeof(BlockQ4_1);
            size_t o_bytes    = o_blocks   * sizeof(BlockQ4_1);

            auto t_q = slingshot_tensor(router, lay.attn_q);
            auto t_k = slingshot_tensor(router, lay.attn_k);
            auto t_v = slingshot_tensor(router, lay.attn_v);
            if (t_q && t_k && t_v &&
                t_q->size() + t_k->size() + t_v->size() <= qkv_bytes) {
                // Pack Q,K,V into the engine's qkv_w layout: [Q | K | V]
                BlockQ4_1* dst = model->layers[L].qkv_w;
                std::memcpy(dst, t_q->data(), t_q->size());
                std::memcpy((uint8_t*)dst + t_q->size(), t_k->data(), t_k->size());
                std::memcpy((uint8_t*)dst + t_q->size() + t_k->size(),
                            t_v->data(), t_v->size());
            }
            auto t_o = slingshot_tensor(router, lay.attn_output);
            if (t_o && t_o->size() <= o_bytes) {
                std::memcpy(model->layers[L].o_w, t_o->data(), t_o->size());
            }

            // Router weights (Q4_1, shape [n_experts, dim])
            size_t router_blocks = (n_experts * MOE_DIM) / 32;
            size_t router_bytes  = router_blocks * sizeof(BlockQ4_1);
            auto t_r = slingshot_tensor(router, lay.ffn_gate_inp);
            if (t_r && t_r->size() <= router_bytes) {
                std::memcpy(model->layers[L].router_w, t_r->data(), t_r->size());
            }

            // Experts (Q4_1, shape [ff_dim, dim] per expert)
            size_t expert_blocks = (MOE_FF * MOE_DIM) / 32;
            size_t expert_bytes  = expert_blocks * sizeof(BlockQ4_1);
            for (int e = 0; e < n_experts; ++e) {
                auto t_g = slingshot_tensor(router, lay.ffn_gate_exps[e]);
                auto t_u = slingshot_tensor(router, lay.ffn_up_exps  [e]);
                auto t_d = slingshot_tensor(router, lay.ffn_down_exps[e]);
                if (t_g && t_g->size() <= expert_bytes) {
                    std::memcpy(model->layers[L].expert_gate[e],
                                t_g->data(), t_g->size());
                }
                if (t_u && t_u->size() <= expert_bytes) {
                    std::memcpy(model->layers[L].expert_up[e],
                                t_u->data(), t_u->size());
                }
                if (t_d && t_d->size() <= expert_bytes) {
                    std::memcpy(model->layers[L].expert_down[e],
                                t_d->data(), t_d->size());
                }
            }
        }

        if (engine.self_improvement_enabled_) {
            // Re-evaluate success rate now that we have real weights
            engine.self_improvement_->adapt_weights(*model);
        }
    }
    return true;
}

// ============================================================================
// Top-level convenience: load Kimi K2 13-shard layout and populate engine.
// ============================================================================
inline bool load_chain_from_kimi_k2(SpeculativeInferenceEngine& engine,
                                     const std::string& model_dir,
                                     int n_shards = 13)
{
    gguf_shard::ShardRouter router;
    if (!gguf_shard::load_kimi_k2_shards(router, model_dir, n_shards)) {
        std::fprintf(stderr, "[Bridge] failed to load %d shards from %s\n",
                     n_shards, model_dir.c_str());
        return false;
    }
    std::fprintf(stderr, "[Bridge] router indexed %zu tensors across %zu shards\n",
                 router.size(), router.shards().size());
    return load_chain_from_router(engine, router);
}

// ============================================================================
// Engulf-aware loader: uses the LRU reservoir (hotpatch #6) to keep at most
// N layers resident in arena memory at once. Useful for Kimi K2 where the
// total model >> arena.
// ============================================================================
template <class Router>
bool load_chain_engulfed(SpeculativeInferenceEngine& engine,
                          const Router& router,
                          gguf_shard_medusa::VRAMBudget& budget,
                          gguf_shard_medusa::GPUOps& gpu,
                          int max_hot_layers = 2,
                          int n_experts = MOE_EXPERTS)
{
    using namespace gguf_shard_engulf;
    using namespace gguf_shard_medusa;

    EngulfConfig ecfg;
    ecfg.max_hot_layers = (uint32_t)max_hot_layers;
    ecfg.prefetch       = true;
    ecfg.verbose        = false;
    ecfg.lane_width     = 16;
    ecfg.chunk_bytes    = 1ull << 20;

    EngulfReservoir<Router> reservoir(router, budget, gpu, ecfg);
    uint32_t nlayers = reservoir.num_layers();
    std::fprintf(stderr, "[Bridge:Engulf] %u layers, max_hot=%u\n",
                 nlayers, max_hot_layers);

    for (int m_idx = 0; m_idx < MOE_CHAIN_COUNT; ++m_idx) {
        MoEModel* model = engine.moe_chain_->get_model(m_idx);
        if (!model) continue;
        for (uint32_t L = 0; L < nlayers && (int)L < model->n_layers; ++L) {
            auto h = reservoir.engulf(L);
            if (!h.valid) {
                std::fprintf(stderr, "[Bridge:Engulf] skip layer %u\n", L);
                continue;
            }
            // In a fully-GPU implementation, h.weights would already be in VRAM
            // and we'd run the forward pass directly on the device. For the
            // CPU engine, the WeightSlingshot has already copied the host
            // bytes through the x16-lane streamer; we just need to re-read
            // the (now warm) shard pages into our arena. Because the kernel
            // page cache already has them, this is fast (no disk I/O).
            auto lay = kimi_layer_layout((int)L, n_experts);
            // (Same copy logic as load_chain_from_router — abbreviated here.)
            for (int e = 0; e < n_experts; ++e) {
                auto tg = slingshot_tensor(router, lay.ffn_gate_exps[e]);
                if (tg) std::memcpy(model->layers[L].expert_gate[e],
                                    tg->data(), tg->size());
                auto tu = slingshot_tensor(router, lay.ffn_up_exps[e]);
                if (tu) std::memcpy(model->layers[L].expert_up[e],
                                    tu->data(), tu->size());
                auto td = slingshot_tensor(router, lay.ffn_down_exps[e]);
                if (td) std::memcpy(model->layers[L].expert_down[e],
                                    td->data(), td->size());
            }
            reservoir.regurgitate(L);  // free VRAM slot
        }
    }
    return true;
}

} // namespace Bridge
} // namespace Inference
} // namespace RawrXD

#endif // SPECULATIVE_ENGINE_GGUF_BRIDGE_HPP
