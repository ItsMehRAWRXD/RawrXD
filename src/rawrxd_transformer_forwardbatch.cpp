// ============================================================================
// rawrxd_transformer_forwardbatch.cpp — B009 Batched Prefill Implementation
// Layer-outer loop for multi-token prompt processing.
// ============================================================================
#include "rawrxd_transformer.h"
#include <chrono>
#include <cstdio>
#include <cmath>
#include <windows.h>

// Forward declarations for AVX-512 helpers used in this TU
extern void RMSNorm_AVX512(float* out, const float* in, const float* weight, int dim, float eps);
extern void RoPE_AVX512(float* q, float* k, int pos, int head_dim, int n_heads);
extern float DotProduct_AVX512(const float* a, const float* b, int n);
extern void Softmax_AVX512(float* x, int n);
extern void VectorAdd_AVX512(float* out, const float* a, const float* b, int n);
extern void VectorAddScaled_AVX512(float* out, const float* a, float scale, int n);
extern void Silu_AVX512(float* x, int n);

std::vector<float> RawrXDTransformer::ForwardBatch(const std::vector<uint32_t>& tokens, int start_pos)
{
    if (tokens.empty())
        return {};

    if (!loader)
    {
        printf("[ForwardBatch] FATAL: loader is null\n");
        return {};
    }

    const int dim = config.dim;
    const int n_heads = config.n_heads;
    const int head_dim = dim / n_heads;
    const int cache_ctx = std::max(1, config.n_ctx > 0 ? config.n_ctx : 2048);
    const int T = static_cast<int>(tokens.size());
    int64_t current_pos = static_cast<int64_t>(std::max(0, start_pos));

    int n_kv_heads = config.n_kv_heads > 0 ? config.n_kv_heads : n_heads;
    n_kv_heads = std::max(1, std::min(n_kv_heads, n_heads));
    while (n_heads % n_kv_heads != 0 && n_kv_heads > 1)
        --n_kv_heads;
    const int kv_dim = n_kv_heads * head_dim;
    const int heads_per_kv = std::max(1, n_heads / n_kv_heads);

    const size_t layers_u = static_cast<size_t>(config.n_layers);
    const size_t ctx_u = static_cast<size_t>(cache_ctx);
    const size_t kv_u = static_cast<size_t>(kv_dim);
    const size_t expected_cache = layers_u * ctx_u * kv_u;

    if (kv_cache_k.size() < expected_cache || kv_cache_v.size() < expected_cache)
    {
        try
        {
            kv_cache_k.assign(expected_cache, 0.0f);
            kv_cache_v.assign(expected_cache, 0.0f);
            kv_cache_pos.assign(layers_u * ctx_u, -1);
        }
        catch (const std::bad_alloc&)
        {
            printf("[ForwardBatch] FATAL: std::bad_alloc allocating KV cache\n");
            return {};
        }
    }
    else if (kv_cache_pos.size() < (layers_u * ctx_u))
    {
        kv_cache_pos.assign(layers_u * ctx_u, -1);
    }

    // Per-token hidden states: T x dim
    std::vector<float> hidden(static_cast<size_t>(T) * dim);

    // -----------------------------------------------------------------------
    // 1. Embedding lookup (token-outer, unavoidable)
    // -----------------------------------------------------------------------
    for (int t = 0; t < T; ++t)
    {
        uint32_t token = tokens[t];
        if (token >= static_cast<uint32_t>(config.vocab_size))
            token = static_cast<uint32_t>(config.vocab_size - 1);

        float* x = hidden.data() + static_cast<size_t>(t) * dim;
        const char* names[] = {
            "token_embd.weight", "model.embed_tokens.weight", "embeddings.weight",
            "input.weight", "v.token_embd.weight", "v.embeddings.weight",
            "v.input.weight", "transformer.wte.weight", "wte.weight",
            "word_embeddings.weight", "embed_tokens.weight", "tok_embeddings.weight"
        };
        bool row_ok = false;
        for (const char* name : names)
        {
            row_ok = loader->GetTensorRow(name, static_cast<size_t>(token), x, static_cast<size_t>(dim));
            if (row_ok) break;
        }
        if (!row_ok)
        {
            printf("[ForwardBatch] FATAL: Missing token embedding tensor\n");
            return {};
        }
    }

    // -----------------------------------------------------------------------
    // 2. Transformer layers (layer-outer, batched)
    // -----------------------------------------------------------------------
    std::vector<float> q(dim * T), k(kv_dim * T), v(kv_dim * T);
    std::vector<float> att_out(dim * T), attn_final(dim * T);
    std::vector<float> h1(config.hidden_dim * T), h3(config.hidden_dim * T), final_ffn(dim * T);
    std::vector<float> residual_batch(static_cast<size_t>(T) * dim);
    std::vector<float> scores(cache_ctx);
    std::vector<uint8_t> score_valid(cache_ctx, 0);

    printf("[ForwardBatch] prefill: tokens=%d layers=%d\n", T, config.n_layers);
    const auto batchStart = std::chrono::steady_clock::now();

    for (int l = 0; l < config.n_layers; ++l)
    {
        const std::string prefix = "blk." + std::to_string(l) + ".";

        // --- Attention norm (per-token) ---
        float* attn_norm = loader->GetTensor(prefix + "attn_norm.weight");
        if (!attn_norm)
        {
            printf("[ForwardBatch] FATAL: Missing %sattn_norm.weight\n", prefix.c_str());
            return {};
        }
        for (int t = 0; t < T; ++t)
        {
            float* x = hidden.data() + static_cast<size_t>(t) * dim;
            float* res_t = residual_batch.data() + static_cast<size_t>(t) * dim;
            std::memcpy(res_t, x, static_cast<size_t>(dim) * sizeof(float));
            RMSNorm_AVX512(x, x, attn_norm, dim, config.rms_norm_eps);
        }

        // --- QKV projections (batched matmul) ---
        for (int t = 0; t < T; ++t)
        {
            float* x = hidden.data() + static_cast<size_t>(t) * dim;
            float* qt = q.data() + static_cast<size_t>(t) * dim;
            float* kt = k.data() + static_cast<size_t>(t) * kv_dim;
            float* vt = v.data() + static_cast<size_t>(t) * kv_dim;

            if (!ExecuteLayerMatMul(prefix + "attn_q.weight", x, qt, dim, dim, static_cast<uint32_t>(l)))
                return {};
            if (!ExecuteLayerMatMul(prefix + "attn_k.weight", x, kt, dim, kv_dim, static_cast<uint32_t>(l)))
                return {};
            if (!ExecuteLayerMatMul(prefix + "attn_v.weight", x, vt, dim, kv_dim, static_cast<uint32_t>(l)))
                return {};

            // RoPE per token
            RoPE_AVX512(qt, nullptr, current_pos + t, head_dim, n_heads);
            RoPE_AVX512(kt, nullptr, current_pos + t, head_dim, n_kv_heads);
        }

        // --- KV Cache Update (all tokens) ---
        for (int t = 0; t < T; ++t)
        {
            const int64_t abs_pos = current_pos + static_cast<int64_t>(t);
            const int slot = static_cast<int>(abs_pos % static_cast<int64_t>(cache_ctx));
            const size_t layer_base = static_cast<size_t>(l) * ctx_u * kv_u;
            const size_t cache_offset = layer_base + static_cast<size_t>(slot) * kv_u;
            memcpy(kv_cache_k.data() + cache_offset, k.data() + static_cast<size_t>(t) * kv_dim,
                   static_cast<size_t>(kv_dim) * sizeof(float));
            memcpy(kv_cache_v.data() + cache_offset, v.data() + static_cast<size_t>(t) * kv_dim,
                   static_cast<size_t>(kv_dim) * sizeof(float));
            kv_cache_pos[static_cast<size_t>(l) * ctx_u + static_cast<size_t>(slot)] = abs_pos;
        }

        // --- Multi-head attention (per-token, causal) ---
        for (int t = 0; t < T; ++t)
        {
            const int64_t abs_pos = current_pos + static_cast<int64_t>(t);
            const int64_t seq_len_total = abs_pos + 1;
            const int attn_len = static_cast<int>(std::min<int64_t>(seq_len_total, static_cast<int64_t>(cache_ctx)));
            const int64_t window_start = seq_len_total - static_cast<int64_t>(attn_len);
            const float inv_scale = 1.0f / sqrtf(static_cast<float>(head_dim));
            const size_t layer_base = static_cast<size_t>(l) * ctx_u * kv_u;

            float* out_t = att_out.data() + static_cast<size_t>(t) * dim;
            std::fill(out_t, out_t + dim, 0.0f);

            for (int h = 0; h < n_heads; ++h)
            {
                const int kv_h = std::min(n_kv_heads - 1, h / heads_per_kv);
                const float* q_head = q.data() + static_cast<size_t>(t) * dim + static_cast<size_t>(h) * head_dim;
                int valid_count = 0;

                for (int p = 0; p < attn_len; ++p)
                {
                    const int64_t abs_p = window_start + static_cast<int64_t>(p);
                    const int p_slot = static_cast<int>(abs_p % static_cast<int64_t>(cache_ctx));
                    const size_t pos_idx = static_cast<size_t>(l) * ctx_u + static_cast<size_t>(p_slot);
                    if (kv_cache_pos[pos_idx] != abs_p)
                    {
                        scores[p] = -1e9f;
                        score_valid[p] = 0;
                        continue;
                    }
                    const size_t k_off = layer_base + static_cast<size_t>(p_slot) * kv_u +
                                         static_cast<size_t>(kv_h) * head_dim;
                    const float* k_past = kv_cache_k.data() + k_off;
                    float score = DotProduct_AVX512(q_head, k_past, head_dim);
                    float scaled = std::isfinite(score) ? (score * inv_scale) : -1e9f;
                    scores[p] = std::max(-80.0f, std::min(80.0f, scaled));
                    score_valid[p] = 1;
                    ++valid_count;
                }
                if (valid_count == 0)
                {
                    float* out_head = out_t + static_cast<size_t>(h) * head_dim;
                    std::fill(out_head, out_head + head_dim, 0.0f);
                    continue;
                }

                Softmax_AVX512(scores.data(), attn_len);
                for (int p = 0; p < attn_len; ++p)
                    if (!std::isfinite(scores[p])) scores[p] = 0.0f;

                float* out_head = out_t + static_cast<size_t>(h) * head_dim;
                for (int p = 0; p < attn_len; ++p)
                {
                    if (!score_valid[p]) continue;
                    const int64_t abs_p = window_start + static_cast<int64_t>(p);
                    const int p_slot = static_cast<int>(abs_p % static_cast<int64_t>(cache_ctx));
                    const size_t v_off = layer_base + static_cast<size_t>(p_slot) * kv_u +
                                         static_cast<size_t>(kv_h) * head_dim;
                    const float* v_past = kv_cache_v.data() + v_off;
                    VectorAddScaled_AVX512(out_head, v_past, scores[p], head_dim);
                }
            }
        }

        // --- Output projection (per-token) ---
        for (int t = 0; t < T; ++t)
        {
            float* out_t = att_out.data() + static_cast<size_t>(t) * dim;
            float* fin_t = attn_final.data() + static_cast<size_t>(t) * dim;
            if (!ExecuteLayerMatMul(prefix + "attn_output.weight", out_t, fin_t, dim, dim, static_cast<uint32_t>(l)))
                return {};
        }

        // --- Residual add ---
        for (int t = 0; t < T; ++t)
        {
            float* x = hidden.data() + static_cast<size_t>(t) * dim;
            float* res_t = residual_batch.data() + static_cast<size_t>(t) * dim;
            float* fin_t = attn_final.data() + static_cast<size_t>(t) * dim;
            VectorAdd_AVX512(x, res_t, fin_t, dim);
            for (int i = 0; i < dim; ++i)
                if (!std::isfinite(x[i])) x[i] = 0.0f;
        }

        // --- FFN (per-token, dense path only for B009 scaffold) ---
        for (int t = 0; t < T; ++t)
        {
            float* x = hidden.data() + static_cast<size_t>(t) * dim;
            float* h1t = h1.data() + static_cast<size_t>(t) * config.hidden_dim;
            float* h3t = h3.data() + static_cast<size_t>(t) * config.hidden_dim;
            float* fft = final_ffn.data() + static_cast<size_t>(t) * dim;

            // Save residual before FFN norm
            float* res_t = residual_batch.data() + static_cast<size_t>(t) * dim;
            std::memcpy(res_t, x, static_cast<size_t>(dim) * sizeof(float));

            float* ffn_norm = loader->GetTensor(prefix + "ffn_norm.weight");
            if (!ffn_norm)
            {
                printf("[ForwardBatch] FATAL: Missing %sffn_norm.weight\n", prefix.c_str());
                return {};
            }
            RMSNorm_AVX512(x, x, ffn_norm, dim, config.rms_norm_eps);

            const std::string ffn_prefix = prefix + "ffn_";
            if (!ExecuteLayerMatMul(ffn_prefix + "gate.weight", x, h1t, dim, config.hidden_dim, static_cast<uint32_t>(l)))
                return {};
            if (!ExecuteLayerMatMul(ffn_prefix + "up.weight", x, h3t, dim, config.hidden_dim, static_cast<uint32_t>(l)))
                return {};

            Silu_AVX512(h1t, config.hidden_dim);
            for (int i = 0; i < config.hidden_dim; ++i)
                h1t[i] *= h3t[i];

            if (!ExecuteLayerMatMul(ffn_prefix + "down.weight", h1t, fft, config.hidden_dim, dim, static_cast<uint32_t>(l)))
                return {};

            VectorAdd_AVX512(x, res_t, fft, dim);
            for (int i = 0; i < dim; ++i)
                if (!std::isfinite(x[i])) x[i] = 0.0f;
        }
    }

    // -----------------------------------------------------------------------
    // 3. Final norm + output projection (last token only, same as Forward)
    // -----------------------------------------------------------------------
    float* final_x = hidden.data() + static_cast<size_t>(T - 1) * dim;
    float* final_norm = loader->GetTensor("output_norm.weight");
    if (!final_norm) final_norm = loader->GetTensor("norm.weight");
    if (final_norm)
        RMSNorm_AVX512(final_x, final_x, final_norm, dim, config.rms_norm_eps);

    std::vector<float> logits(config.vocab_size);
    if (!ExecuteLayerMatMul("output.weight", final_x, logits.data(), dim, config.vocab_size,
                            static_cast<uint32_t>(std::max(0, config.n_layers))))
    {
        printf("[ForwardBatch] FATAL: output.weight StreamingMatMul failed\n");
        return {};
    }

    const auto batchEnd = std::chrono::steady_clock::now();
    const double batchMs = std::chrono::duration<double, std::milli>(batchEnd - batchStart).count();
    printf("[ForwardBatch] complete: tokens=%d layers=%d elapsed_ms=%.2f\n", T, config.n_layers, batchMs);

    return logits;
}
