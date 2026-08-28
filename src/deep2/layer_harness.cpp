// layer_harness.cpp - Single-layer Qwen3.5 correctness harness
// Runs layer 0 (SSM) and layer 3 (non-SSM) independently, dumping every
// intermediate value using FP32 reference operations.
// Establishes the actual computation graph before any forward-pass changes.
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include "Deep2Engine.h"
#include "GGUFLoader.hpp"
#include "Deep2QuantReference.h"

using namespace Deep2;
// block_q4_K / block_q6_K are defined in both Deep2:: and RawrXD::Deep2::
// Use the Deep2:: ones (from GGUFLoader.hpp) which are in scope via using namespace.
// fp16_to_fp32 is in RawrXD::Deep2::
using RawrXD::Deep2::fp16_to_fp32;

// ── FP32 reference GEMV: out[r] = sum_c W[r][c] * x[c] ──
// W is stored row-major: W[r*cols + c]
static void ref_gemv_f32(const float* W, const float* x, float* out,
                         size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        for (size_t c = 0; c < cols; ++c) {
            acc += (double)W[r * cols + c] * (double)x[c];
        }
        out[r] = (float)acc;
    }
}

// ── Q4_K dequantize one block (144 bytes, 256 values) ──
static void dequant_q4k_block(const block_q4_K* blk, float* dst) {
    const float d = fp16_to_fp32(blk->d);
    const float dmin = fp16_to_fp32(blk->dmin);
    const uint8_t* q = blk->qs;
    int is = 0;
    for (int j = 0; j < 256; j += 64) {
        int sc = blk->scales[is / 2] & 0xF;
        int m  = blk->scales[is / 2] >> 4;
        float dl = d * sc, ml = dmin * m;
        for (int l = 0; l < 32; ++l) dst[j + l] = dl * (q[l] & 0xF) - ml;
        for (int l = 0; l < 32; ++l) dst[j + 32 + l] = dl * (q[l] >> 4) - ml;
        q += 32; is += 2;
    }
}

// ── Q6_K dequantize one block (210 bytes, 256 values) ──
static void dequant_q6k_block(const block_q6_K* blk, float* dst) {
    const float d = fp16_to_fp32(blk->d);
    const uint8_t* ql = blk->ql;
    const uint8_t* qh = blk->qh;
    const int8_t* sc = blk->scales;
    float* yp = dst;
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            int is = l / 16;
            const int8_t q1 = (int8_t)((ql[l + 0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int8_t q3 = (int8_t)((ql[l + 0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int8_t q4 = (int8_t)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            yp[l + 0] = d * sc[is + 0] * q1;
            yp[l + 32] = d * sc[is + 2] * q2;
            yp[l + 64] = d * sc[is + 4] * q3;
            yp[l + 96] = d * sc[is + 6] * q4;
        }
        yp += 128; ql += 64; qh += 32; sc += 8;
    }
}

// ── Dequantize a full quantized tensor to FP32 ──
// wt.data points to quantized blocks. rows=out, cols=in.
static void dequant_tensor(const WeightTensor& wt, std::vector<float>& out) {
    out.assign(wt.rows * wt.cols, 0.0f);
    if (!wt.data) {
        printf("  [WARN] dequant_tensor: null data for %s\n", wt.name.c_str());
        return;
    }
    if (wt.rows == 0 || wt.cols == 0) {
        printf("  [WARN] dequant_tensor: zero dims for %s (rows=%zu cols=%zu)\n",
               wt.name.c_str(), wt.rows, wt.cols);
        return;
    }
    size_t blocksPerRow = (wt.cols + 255) / 256;
    if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) {
        const block_q4_K* blk = (const block_q4_K*)wt.data;
        for (size_t r = 0; r < wt.rows; ++r) {
            for (size_t b = 0; b < blocksPerRow; ++b) {
                float tmp[256];
                dequant_q4k_block(&blk[r * blocksPerRow + b], tmp);
                for (size_t i = 0; i < 256 && b * 256 + i < wt.cols; ++i)
                    out[r * wt.cols + b * 256 + i] = tmp[i];
            }
        }
    } else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) {
        const block_q6_K* blk = (const block_q6_K*)wt.data;
        for (size_t r = 0; r < wt.rows; ++r) {
            for (size_t b = 0; b < blocksPerRow; ++b) {
                float tmp[256];
                dequant_q6k_block(&blk[r * blocksPerRow + b], tmp);
                for (size_t i = 0; i < 256 && b * 256 + i < wt.cols; ++i)
                    out[r * wt.cols + b * 256 + i] = tmp[i];
            }
        }
    } else if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        memcpy(out.data(), wt.data, wt.rows * wt.cols * sizeof(float));
    } else {
        printf("  [WARN] Unsupported type %d for dequant\n", wt.type);
    }
}

// ── Reference GEMV on a WeightTensor (dequantize then dot) ──
static void ref_gemv_tensor(const WeightTensor& wt, const float* x, float* out) {
    if (!wt.data || wt.rows == 0 || wt.cols == 0) {
        printf("  [WARN] ref_gemv_tensor: invalid tensor %s (data=%p rows=%zu cols=%zu)\n",
               wt.name.c_str(), wt.data, wt.rows, wt.cols);
        memset(out, 0, wt.rows * sizeof(float));
        return;
    }
    std::vector<float> W;
    dequant_tensor(wt, W);
    ref_gemv_f32(W.data(), x, out, wt.rows, wt.cols);
}

// ── RMSNorm: out = w * x / sqrt(mean(x^2) + eps) ──
static void ref_rmsnorm(const float* w, const float* x, float* out, size_t n, float eps) {
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += (double)x[i] * x[i];
    float rms = sqrtf((float)(sum / n) + eps);
    for (size_t i = 0; i < n; ++i) out[i] = w[i] * x[i] / rms;
}

// ── SiLU ──
static float silu(float x) { return x / (1.0f + expf(-x)); }

// ── Norm helper ──
static float vec_norm(const float* v, size_t n) {
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) s += (double)v[i] * v[i];
    return sqrtf((float)s);
}

// ── Dump a vector's stats ──
static void dump_vec(const char* label, const float* v, size_t n) {
    float mn = 1e30f, mx = -1e30f;
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        if (v[i] < mn) mn = v[i];
        if (v[i] > mx) mx = v[i];
        sum += v[i];
    }
    printf("  %-28s norm=%.6e min=%.6e max=%.6e mean=%.6e\n",
           label, vec_norm(v, n), mn, mx, (float)(sum / n));
}

// ── Run layer 0 (SSM) reference forward ──
static void run_layer0_ssm(const LayerWeights& lw, const float* input, size_t hidden) {
    printf("\n=== LAYER 0 (SSM) FP32 REFERENCE ===\n");
    dump_vec("INPUT", input, hidden);

    std::vector<float> attnNorm(hidden), attnOut(hidden);
    std::vector<float> postAttn(hidden), ffnNorm(hidden), ffnOut(hidden), postFfn(hidden);

    // 1. attn_norm (RMSNorm)
    ref_rmsnorm((const float*)lw.attnNorm.data, input, attnNorm.data(), hidden, 1e-6f);
    dump_vec("ATTN_NORM", attnNorm.data(), hidden);

    // 2. attn_qkv projection: [4096] -> [8192]
    std::vector<float> qkv(8192);
    ref_gemv_tensor(lw.wqkv, attnNorm.data(), qkv.data());
    dump_vec("ATTN_QKV (8192)", qkv.data(), 8192);

    // 3. Split into two 4096 halves
    std::vector<float> proj(4096), gate(4096);
    memcpy(proj.data(), qkv.data(), 4096 * sizeof(float));
    memcpy(gate.data(), qkv.data() + 4096, 4096 * sizeof(float));
    dump_vec("QKV_PROJ (first 4096)", proj.data(), 4096);
    dump_vec("QKV_GATE (second 4096)", gate.data(), 4096);

    // 4. Gated: proj * silu(gate)
    std::vector<float> gated(4096);
    for (size_t i = 0; i < 4096; ++i) gated[i] = proj[i] * silu(gate[i]);
    dump_vec("GATED (proj*silu(gate))", gated.data(), 4096);

    // 5. attn_gate output projection: [4096] -> [4096]
    ref_gemv_tensor(lw.attnO, gated.data(), attnOut.data());
    dump_vec("ATTN_GATE_OUT", attnOut.data(), hidden);

    // 6. Residual: input + attnOut
    for (size_t i = 0; i < hidden; ++i) postAttn[i] = input[i] + attnOut[i];
    dump_vec("POST_ATTN (residual)", postAttn.data(), hidden);

    // 7. post_attention_norm (RMSNorm)
    ref_rmsnorm((const float*)lw.ffnNorm.data, postAttn.data(), ffnNorm.data(), hidden, 1e-6f);
    dump_vec("FFN_NORM", ffnNorm.data(), hidden);

    // 8. SSM path
    // ssm_alpha: [4096] -> [32]
    std::vector<float> xAlpha(32), xBeta(32);
    ref_gemv_tensor(lw.ssmAlpha, ffnNorm.data(), xAlpha.data());
    ref_gemv_tensor(lw.ssmBeta, ffnNorm.data(), xBeta.data());
    dump_vec("SSM_ALPHA (32)", xAlpha.data(), 32);
    dump_vec("SSM_BETA (32)", xBeta.data(), 32);

    // ssm_conv1d: [4, 8192] — causal conv on 8192 channels
    // For single token, only the newest sample is non-zero in conv state
    std::vector<float> convOut(8192, 0.0f);
    const float* convW = (const float*)lw.ssmConv1d.data;
    // conv1d weight dims=[4,8192] → in=4, out=8192. Row-major: convW[k*8192 + c]
    // For single token, x_conv[t] = sum_k convW[k*8192+c] * x[t-k]
    // Only x[0] is non-zero (newest), so convOut[c] = convW[0*8192+c] * xAlpha[c%32]
    for (size_t c = 0; c < 8192; ++c) {
        float xv = (c < 32) ? xAlpha[c] : 0.0f;
        convOut[c] = convW[0 * 8192 + c] * xv;
    }
    dump_vec("SSM_CONV1D (8192)", convOut.data(), 8192);

    // ssm_a, ssm_dt.bias: discrete SSM state update
    std::vector<float> state(32, 0.0f);
    const float* aParam = (const float*)lw.ssmA.data;
    const float* dtBias = (const float*)lw.ssmDtBias.data;
    for (size_t i = 0; i < 32; ++i) {
        float dt = dtBias ? dtBias[i] : 1.0f;
        if (dt <= 0.0f) dt = 0.001f;
        float a = aParam ? aParam[i] : -1.0f;
        float Abar = expf(a * dt);
        float Bbar = dt * xBeta[i];
        state[i] = Abar * state[i] + Bbar * convOut[i];
    }
    dump_vec("SSM_STATE (32)", state.data(), 32);

    // ssm_norm (RMSNorm on 128-dim state)
    std::vector<float> ssmNormed(128, 0.0f);
    for (size_t i = 0; i < 32; ++i) ssmNormed[i] = state[i];
    ref_rmsnorm((const float*)lw.ssmNorm.data, ssmNormed.data(), ssmNormed.data(), 128, 1e-6f);
    dump_vec("SSM_NORM (128)", ssmNormed.data(), 128);

    // ssm_out: [4096] -> [4096] (zero-pad the 128-dim state to 4096)
    std::vector<float> ssmIn(4096, 0.0f);
    memcpy(ssmIn.data(), ssmNormed.data(), 128 * sizeof(float));
    std::vector<float> ssmOut(4096);
    ref_gemv_tensor(lw.ssmOut, ssmIn.data(), ssmOut.data());
    dump_vec("SSM_OUT (4096)", ssmOut.data(), 4096);

    // 9. Residual: postAttn + ssmOut
    for (size_t i = 0; i < hidden; ++i) postFfn[i] = postAttn[i] + ssmOut[i];
    dump_vec("POST_FFN (residual)", postFfn.data(), hidden);
}

// ── Run layer 3 (non-SSM) reference forward ──
static void run_layer3_attn(const LayerWeights& lw, const float* input, size_t hidden) {
    printf("\n=== LAYER 3 (NON-SSM) FP32 REFERENCE ===\n");
    printf("  [L3] wq=%p wqkv=%p wk=%p wv=%p wo=%p attnO=%p\n",
           lw.wq.data, lw.wqkv.data, lw.wk.data, lw.wv.data, lw.wo.data, lw.attnO.data);
    printf("  [L3] wGate=%p wUp=%p wDown=%p ffnNorm=%p\n",
           lw.wGate.data, lw.wUp.data, lw.wDown.data, lw.ffnNorm.data);
    printf("  [L3] attnQNorm=%p attnKNorm=%p\n", lw.attnQNorm.data, lw.attnKNorm.data);
    fflush(stdout);
    dump_vec("INPUT", input, hidden);

    std::vector<float> attnNorm(hidden), attnOut(hidden);
    std::vector<float> postAttn(hidden), ffnNorm(hidden), ffnOut(hidden), postFfn(hidden);

    // 1. attn_norm (RMSNorm)
    ref_rmsnorm((const float*)lw.attnNorm.data, input, attnNorm.data(), hidden, 1e-6f);
    dump_vec("ATTN_NORM", attnNorm.data(), hidden);

    // 2. Q projection: [4096] -> [8192] (Q + gate)
    std::vector<float> qkv(8192);
    ref_gemv_tensor(lw.wq, attnNorm.data(), qkv.data());
    dump_vec("ATTN_QKV (8192)", qkv.data(), 8192);

    // 3. Split into Q (4096) and gate (4096)
    std::vector<float> q(4096), gate(4096);
    memcpy(q.data(), qkv.data(), 4096 * sizeof(float));
    memcpy(gate.data(), qkv.data() + 4096, 4096 * sizeof(float));
    dump_vec("ATTN_Q (first 4096)", q.data(), 4096);
    dump_vec("ATTN_GATE (second 4096)", gate.data(), 4096);

    // 4. K projection: [4096] -> [1024]
    std::vector<float> k(1024);
    ref_gemv_tensor(lw.wk, attnNorm.data(), k.data());
    dump_vec("ATTN_K (1024)", k.data(), 1024);

    // 5. V projection: [4096] -> [1024]
    std::vector<float> v(1024);
    ref_gemv_tensor(lw.wv, attnNorm.data(), v.data());
    dump_vec("ATTN_V (1024)", v.data(), 1024);

    // 6. QK norm (per-head RMSNorm) on Q (16 heads × 256)
    std::vector<float> qNormed(4096), kNormed(1024);
    const float* qNormW = (const float*)lw.attnQNorm.data;
    const float* kNormW = (const float*)lw.attnKNorm.data;
    for (size_t h = 0; h < 16; ++h) {
        ref_rmsnorm(qNormW, q.data() + h * 256, qNormed.data() + h * 256, 256, 1e-6f);
    }
    for (size_t h = 0; h < 4; ++h) {
        ref_rmsnorm(kNormW, k.data() + h * 256, kNormed.data() + h * 256, 256, 1e-6f);
    }
    dump_vec("ATTN_Q_NORMED", qNormed.data(), 4096);
    dump_vec("ATTN_K_NORMED", kNormed.data(), 1024);

    // 7. Gated: qNormed * silu(gate)
    std::vector<float> gated(4096);
    for (size_t i = 0; i < 4096; ++i) gated[i] = qNormed[i] * silu(gate[i]);
    dump_vec("GATED (q*silu(gate))", gated.data(), 4096);

    // 8. attn_output projection: [4096] -> [4096] (use lw.wo for attn_output)
    std::vector<float> attnProj(4096);
    ref_gemv_tensor(lw.wo, gated.data(), attnProj.data());
    dump_vec("ATTN_OUTPUT (4096)", attnProj.data(), 4096);

    // 7. Residual: input + attnOut
    for (size_t i = 0; i < hidden; ++i) postAttn[i] = input[i] + attnProj[i];
    dump_vec("POST_ATTN (residual)", postAttn.data(), hidden);
    fflush(stdout);

    // 8. post_attention_norm (RMSNorm)
    printf("  [FFN] ffnNorm: data=%p rows=%zu cols=%zu type=%d name=%s\n",
           lw.ffnNorm.data, lw.ffnNorm.rows, lw.ffnNorm.cols, lw.ffnNorm.type, lw.ffnNorm.name.c_str());
    fflush(stdout);
    ref_rmsnorm((const float*)lw.ffnNorm.data, postAttn.data(), ffnNorm.data(), hidden, 1e-6f);
    dump_vec("FFN_NORM", ffnNorm.data(), hidden);
    fflush(stdout);

    // 9. FFN gate: [4096] -> [12288]
    printf("  [FFN] wGate: data=%p rows=%zu cols=%zu type=%d name=%s\n",
           lw.wGate.data, lw.wGate.rows, lw.wGate.cols, lw.wGate.type, lw.wGate.name.c_str());
    fflush(stdout);
    std::vector<float> ffnGate(12288), up(12288);
    ref_gemv_tensor(lw.wGate, ffnNorm.data(), ffnGate.data());
    dump_vec("FFN_GATE (12288)", ffnGate.data(), 12288);
    fflush(stdout);

    // 10. FFN up: [4096] -> [12288]
    printf("  [FFN] wUp: data=%p rows=%zu cols=%zu type=%d name=%s\n",
           lw.wUp.data, lw.wUp.rows, lw.wUp.cols, lw.wUp.type, lw.wUp.name.c_str());
    fflush(stdout);
    ref_gemv_tensor(lw.wUp, ffnNorm.data(), up.data());
    dump_vec("FFN_UP (12288)", up.data(), 12288);
    fflush(stdout);

    // 11. SwiGLU: silu(gate) * up
    std::vector<float> swiglu(12288);
    for (size_t i = 0; i < 12288; ++i) swiglu[i] = silu(ffnGate[i]) * up[i];
    dump_vec("SWIGLU (12288)", swiglu.data(), 12288);

    // 12. FFN down: [12288] -> [4096]
    printf("  [FFN] wDown: data=%p rows=%zu cols=%zu type=%d name=%s\n",
           lw.wDown.data, lw.wDown.rows, lw.wDown.cols, lw.wDown.type, lw.wDown.name.c_str());
    ref_gemv_tensor(lw.wDown, swiglu.data(), ffnOut.data());
    dump_vec("FFN_DOWN (4096)", ffnOut.data(), 4096);

    // 13. Residual: postAttn + ffnOut
    for (size_t i = 0; i < hidden; ++i) postFfn[i] = postAttn[i] + ffnOut[i];
    dump_vec("POST_FFN (residual)", postFfn.data(), hidden);
}

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada";

    printf("=== Qwen3.5 Single-Layer Correctness Harness ===\n");
    printf("Model: %s\n\n", modelPath);

    // Load GGUF directly (bypass Deep2Engine.loadModel to avoid ResidencyManager eviction)
    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = false;
    opts.mmap = true;
    GGUFLoadResult res = GGUFLoader::Load(modelPath, opts);
    if (!res.success) {
        printf("[FAIL] GGUFLoader::Load failed: %s\n", res.error);
        return 1;
    }
    printf("Loaded %zu tensors, hidden=%u layers=%u\n",
           res.tensors.size(), res.metadata.hiddenSize, res.metadata.numLayers);

    // Build LayerWeights for layer 0 and layer 3 from GGUF tensors
    auto getTensor = [&](const char* name) -> WeightTensor {
        WeightTensor wt;
        const TensorInfo* t = res.GetTensor(name);
        if (t) {
            wt.data = t->data;
            wt.type = (int)t->type;
            wt.rows = t->dimensions.size() > 1 ? t->dimensions[1] : 1;
            wt.cols = t->dimensions.size() > 0 ? t->dimensions[0] : 0;
            wt.sizeBytes = t->size;
            wt.name = t->name;
        }
        return wt;
    };

    // Layer 0 (SSM)
    LayerWeights l0;
    l0.attnNorm = getTensor("blk.0.attn_norm.weight");
    l0.wqkv = getTensor("blk.0.attn_qkv.weight");
    l0.attnO = getTensor("blk.0.attn_gate.weight");
    l0.ffnNorm = getTensor("blk.0.post_attention_norm.weight");
    l0.ssmA = getTensor("blk.0.ssm_a");
    l0.ssmAlpha = getTensor("blk.0.ssm_alpha.weight");
    l0.ssmBeta = getTensor("blk.0.ssm_beta.weight");
    l0.ssmConv1d = getTensor("blk.0.ssm_conv1d.weight");
    l0.ssmDtBias = getTensor("blk.0.ssm_dt.bias");
    l0.ssmNorm = getTensor("blk.0.ssm_norm.weight");
    l0.ssmOut = getTensor("blk.0.ssm_out.weight");
    l0.hasSSM = true;

    // Layer 3 (non-SSM)
    LayerWeights l3;
    l3.attnNorm = getTensor("blk.3.attn_norm.weight");
    l3.wq = getTensor("blk.3.attn_q.weight");
    l3.wk = getTensor("blk.3.attn_k.weight");
    l3.wv = getTensor("blk.3.attn_v.weight");
    l3.wo = getTensor("blk.3.attn_output.weight");
    l3.attnQNorm = getTensor("blk.3.attn_q_norm.weight");
    l3.attnKNorm = getTensor("blk.3.attn_k_norm.weight");
    l3.ffnNorm = getTensor("blk.3.post_attention_norm.weight");
    l3.wGate = getTensor("blk.3.ffn_gate.weight");
    l3.wUp = getTensor("blk.3.ffn_up.weight");
    l3.wDown = getTensor("blk.3.ffn_down.weight");

    // Use a synthetic input
    size_t hidden = res.metadata.hiddenSize;
    std::vector<float> input(hidden);
    for (size_t i = 0; i < hidden; ++i) {
        input[i] = 0.01f * sinf((float)i * 0.1f);
    }
    dump_vec("SYNTHETIC INPUT", input.data(), hidden);

    // Layer 0 (SSM)
    run_layer0_ssm(l0, input.data(), hidden);

    // Layer 3 (non-SSM)
    run_layer3_attn(l3, input.data(), hidden);

    printf("\n=== DONE ===\n");
    return 0;
}
