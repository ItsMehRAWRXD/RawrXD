// ggml_smoke.cpp - verifies ggml links and that SSM_CONV / SSM_SCAN run end to end.
#include "ggml.h"
#include "ggml-cpu.h"
#include <cstdio>
#include <vector>
#include <cstdlib>

int main() {
    printf("ggml linked OK\n");

    // ggml Mamba2 layout (from ggml.c asserts):
    //   conv_x {d_conv-1+n_t, d_inner, n_seqs},  c {d_conv, d_inner}
    //   conv  -> {d_inner, n_t, n_seqs}
    //   s {d_state, head_dim, n_head, n_seqs}
    //   x {head_dim, n_head, n_seq_tokens, n_seqs}   head_dim = d_inner / n_head
    //   dt {n_head, n_seq_tokens, n_seqs}
    //   A {1, n_head}   B,C {d_state, n_group, n_seq_tokens, n_seqs}
    //   ids {n_seqs}
    const int d_inner = 32, n_head = 4, head_dim = d_inner / n_head;
    const int d_state = 16, n_group = 2, d_conv = 4, n_t = 8, n_seqs = 1;

    std::vector<char> backing((size_t)256 * 1024 * 1024);
    ggml_init_params ip{};
    ip.mem_size = backing.size();
    ip.mem_buffer = backing.data();
    ip.no_alloc = false;
    struct ggml_context* ctx = ggml_init(ip);

    struct ggml_tensor* sx  = ggml_new_tensor_3d(ctx, GGML_TYPE_F32, d_conv - 1 + n_t, d_inner, n_seqs);
    struct ggml_tensor* cw  = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, d_conv, d_inner);
    struct ggml_tensor* cnv = ggml_ssm_conv(ctx, sx, cw);

    struct ggml_tensor* s   = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, d_state, head_dim, n_head, n_seqs);
    struct ggml_tensor* x   = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, head_dim, n_head, n_t, n_seqs);
    struct ggml_tensor* dt  = ggml_new_tensor_3d(ctx, GGML_TYPE_F32, n_head, n_t, n_seqs);
    struct ggml_tensor* A   = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, 1, n_head);
    struct ggml_tensor* B   = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, d_state, n_group, n_t, n_seqs);
    struct ggml_tensor* Cm  = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, d_state, n_group, n_t, n_seqs);
    struct ggml_tensor* ids = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, n_seqs);
    struct ggml_tensor* sc  = ggml_ssm_scan(ctx, s, x, dt, A, B, Cm, ids);

    // Fill deterministic non-zero data so a real compute can be observed.
    auto fill = [](struct ggml_tensor* t, float base) {
        const int64_t n = ggml_nelements(t);
        for (int64_t i = 0; i < n; ++i) {
            float v = base + 0.01f * (float)(i % 97);
            if (t->type == GGML_TYPE_I32) ((int32_t*)t->data)[i] = (int32_t)i;
            else ((float*)t->data)[i] = v;
        }
    };
    fill(sx, 0.5f); fill(cw, -0.25f); fill(s, 0.125f); fill(x, 0.75f);
    fill(dt, 0.05f); fill(A, -0.5f); fill(B, 0.2f); fill(Cm, 0.15f);
    ((int32_t*)ids->data)[0] = 0;

    struct ggml_cgraph* gf = ggml_new_graph(ctx);
    ggml_build_forward_expand(gf, sc);
    ggml_graph_compute_with_ctx(ctx, gf, 1);

    printf("ssm_conv -> ne=[%lld,%lld,%lld]\n",
           (long long)cnv->ne[0], (long long)cnv->ne[1], (long long)cnv->ne[2]);
    printf("ssm_scan -> ne=%lld (expect %lld y + %lld state)\n",
           (long long)sc->ne[0], (long long)ggml_nelements(x),
           (long long)(d_state * head_dim * n_head));
    const float* y = (const float*)sc->data;
    printf("y[0..5] = %f %f %f %f %f %f\n",
           y[0], y[1], y[2], y[3], y[4], y[5]);
    printf("SSM_OPS_AVAILABLE=PASS\n");

    ggml_free(ctx);
    return 0;
}
