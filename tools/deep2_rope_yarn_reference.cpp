// Independent-reference YaRN RoPE probe.
//
// Calls the VENDORED ggml's own GGML_OP_ROPE (the same compute path llama.cpp
// runs for deepseek2) with deepseek2's parameters at several positions and
// prints the resulting rotated vectors. This is the ground truth against which
// Executor::RopeAngle + the NEOX pairing in Executor::OpAttention must match,
// and the nonzero-position evidence that the earlier position-0-only traces
// could not provide (position 0 is the identity rotation for any scheme).
//
// Positions: 1 (first nonzero rotation), 127, 4095 (boundary of the original
// context), 4096 (first position beyond it), 16384 (extended), 65536 (long).

#include <cmath>
#include <cstdio>
#include <cstring>

#include "ggml.h"
#include "ggml-cpu.h"

int main() {
    // deepseek2's own values, read from the GGUF header, plus llama.cpp's
    // deepseek2 defaults for the parameters the file does not carry.
    const int   n_rot      = 64;                 // rope.dimension_count
    const float freq_base  = 10000.0f;           // rope.freq_base
    const float freq_scale = 1.0f / 40.0f;       // 1 / rope.scaling.factor
    const int   n_ctx_orig = 4096;               // rope.scaling.original_context_length
    const float beta_fast  = 32.0f;              // llama.cpp default
    const float beta_slow  = 1.0f;               // llama.cpp default
    const float ext_factor = 0.0f;              // ll.0f; not set by deepseek2
    // llama.cpp deepseek2.cpp: attn_factor = 0.1f*ln(1/freq_scale) + 1.0f
    const float attn_factor = 0.1f * logf(1.0f / freq_scale) + 1.0f;
    const int   rope_type   = GGML_ROPE_TYPE_NEOX;

    const int positions[] = {1, 127, 4095, 4096, 16384, 65536};
    for (int p : positions) {
        ggml_init_params ip = {};
        ip.mem_size = 1u << 20;
        ggml_context* ctx = ggml_init(ip);
        struct ggml_tensor* x = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int64_t)n_rot);
        for (int i = 0; i < n_rot; ++i)
            ((float*)x->data)[i] = sinf((float)i * 0.37f) + 0.5f * cosf((float)i * 0.11f);
        struct ggml_tensor* pos = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, 1);
        memcpy(pos->data, &p, sizeof(int));
        struct ggml_tensor* r = ggml_rope_ext(
            ctx, x, pos, nullptr, n_rot, rope_type, n_ctx_orig, freq_base,
            freq_scale, ext_factor, attn_factor, beta_fast, beta_slow);
        struct ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        ggml_graph_compute_with_ctx(ctx, gf, 1);
        std::printf("pos=%6d  ", p);
        const float* o = (const float*)r->data;
        for (int i = 0; i < 6; ++i) std::printf("%10.6f ", (double)o[i]);
        std::printf("| last %10.6f\n", (double)o[n_rot - 1]);
        ggml_free(ctx);
    }
    return 0;
}
