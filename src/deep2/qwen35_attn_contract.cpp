// qwen35_attn_contract.cpp - Establish the Qwen3.5 full-attention contract
// Tests BOTH candidate Q/gate layouts and BOTH gate activations for layer 3.
// Freezes production; this harness is authoritative for the attention contract.
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include "GGUFLoader.hpp"
#include "Deep2QuantReference.h"
#include "Deep2Engine.h"

using namespace Deep2;
using RawrXD::Deep2::fp16_to_fp32;

// ── FP32 reference GEMV: out[r] = sum_c W[r][c] * x[c] ──
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
static void dequant_tensor(const WeightTensor& wt, std::vector<float>& out) {
    out.assign(wt.rows * wt.cols, 0.0f);
    if (!wt.data || wt.rows == 0 || wt.cols == 0) return;
    size_t blocksPerRow = (wt.cols + 255) / 256;
    if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) {
        const block_q4_K* blk = (const block_q4_K*)wt.data;
        for (size_t r = 0; r < wt.rows; ++r)
            for (size_t b = 0; b < blocksPerRow; ++b) {
                float tmp[256];
                dequant_q4k_block(&blk[r * blocksPerRow + b], tmp);
                for (size_t i = 0; i < 256 && b * 256 + i < wt.cols; ++i)
                    out[r * wt.cols + b * 256 + i] = tmp[i];
            }
    } else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) {
        const block_q6_K* blk = (const block_q6_K*)wt.data;
        for (size_t r = 0; r < wt.rows; ++r)
            for (size_t b = 0; b < blocksPerRow; ++b) {
                float tmp[256];
                dequant_q6k_block(&blk[r * blocksPerRow + b], tmp);
                for (size_t i = 0; i < 256 && b * 256 + i < wt.cols; ++i)
                    out[r * wt.cols + b * 256 + i] = tmp[i];
            }
    } else if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        memcpy(out.data(), wt.data, wt.rows * wt.cols * sizeof(float));
    }
}

static void ref_gemv_tensor(const WeightTensor& wt, const float* x, float* out) {
    if (!wt.data || wt.rows == 0 || wt.cols == 0) {
        memset(out, 0, wt.rows * sizeof(float));
        return;
    }
    std::vector<float> W;
    dequant_tensor(wt, W);
    ref_gemv_f32(W.data(), x, out, wt.rows, wt.cols);
}

static void ref_rmsnorm(const float* w, const float* x, float* out, size_t n, float eps) {
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += (double)x[i] * x[i];
    float rms = sqrtf((float)(sum / n) + eps);
    for (size_t i = 0; i < n; ++i) out[i] = w[i] * x[i] / rms;
}

static float silu(float x) { return x / (1.0f + expf(-x)); }
static float sigmoid(float x) { return 1.0f / (1.0f + expf(-x)); }

static float vec_norm(const float* v, size_t n) {
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) s += (double)v[i] * v[i];
    return sqrtf((float)s);
}

static void dump_vec(const char* label, const float* v, size_t n) {
    float mn = 1e30f, mx = -1e30f;
    for (size_t i = 0; i < n; ++i) {
        if (v[i] < mn) mn = v[i];
        if (v[i] > mx) mx = v[i];
    }
    printf("  %-32s norm=%.6e min=%.6e max=%.6e\n", label, vec_norm(v, n), mn, mx);
}

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada";

    printf("=== Qwen3.5 Full-Attention Contract Harness (Layer 3) ===\n");
    printf("Model: %s\n\n", modelPath);

    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = false;
    opts.mmap = true;
    GGUFLoadResult res = GGUFLoader::Load(modelPath, opts);
    if (!res.success) { printf("[FAIL] Load failed: %s\n", res.error); return 1; }

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

    WeightTensor attnNorm = getTensor("blk.3.attn_norm.weight");
    WeightTensor wq = getTensor("blk.3.attn_q.weight");
    WeightTensor wk = getTensor("blk.3.attn_k.weight");
    WeightTensor wv = getTensor("blk.3.attn_v.weight");
    WeightTensor wo = getTensor("blk.3.attn_output.weight");
    WeightTensor qNorm = getTensor("blk.3.attn_q_norm.weight");
    WeightTensor kNorm = getTensor("blk.3.attn_k_norm.weight");

    printf("wq: rows=%zu cols=%zu type=%d\n", wq.rows, wq.cols, wq.type);
    printf("wk: rows=%zu cols=%zu type=%d\n", wk.rows, wk.cols, wk.type);
    printf("wv: rows=%zu cols=%zu type=%d\n", wv.rows, wv.cols, wv.type);
    printf("wo: rows=%zu cols=%zu type=%d\n", wo.rows, wo.cols, wo.type);
    printf("qNorm: rows=%zu cols=%zu\n", qNorm.rows, qNorm.cols);
    printf("kNorm: rows=%zu cols=%zu\n", kNorm.rows, kNorm.cols);

    size_t hidden = res.metadata.hiddenSize;  // 4096
    size_t numHeads = 16;                     // full-attention Q heads
    size_t numKVHeads = 4;
    size_t headDim = 256;

    // Synthetic input
    std::vector<float> input(hidden);
    for (size_t i = 0; i < hidden; ++i) input[i] = 0.01f * sinf((float)i * 0.1f);
    dump_vec("INPUT", input.data(), hidden);

    // 1. attn_norm
    std::vector<float> attnNormed(hidden);
    ref_rmsnorm((const float*)attnNorm.data, input.data(), attnNormed.data(), hidden, 1e-6f);
    dump_vec("ATTN_NORM", attnNormed.data(), hidden);

    // 2. q_proj [8192]
    std::vector<float> qproj(8192);
    ref_gemv_tensor(wq, attnNormed.data(), qproj.data());
    dump_vec("QPROJ_RAW (8192)", qproj.data(), 8192);

    // 3. k_proj [1024]
    std::vector<float> kproj(1024);
    ref_gemv_tensor(wk, attnNormed.data(), kproj.data());
    dump_vec("KPROJ_RAW (1024)", kproj.data(), 1024);

    // 4. v_proj [1024]
    std::vector<float> vproj(1024);
    ref_gemv_tensor(wv, attnNormed.data(), vproj.data());
    dump_vec("VPROJ_RAW (1024)", vproj.data(), 1024);

    // ── Candidate A: contiguous [Q(0:4096) | gate(4096:8192)] ──
    std::vector<float> qA(4096), gateA(4096);
    memcpy(qA.data(), qproj.data(), 4096 * sizeof(float));
    memcpy(gateA.data(), qproj.data() + 4096, 4096 * sizeof(float));
    dump_vec("A_Q_CONTIG (4096)", qA.data(), 4096);
    dump_vec("A_GATE_CONTIG (4096)", gateA.data(), 4096);

    // ── Candidate B: per-head interleaved [Q_h | gate_h] per head ──
    // Each head: 512 = Q(256) + gate(256)
    std::vector<float> qB(4096), gateB(4096);
    for (size_t h = 0; h < numHeads; ++h) {
        memcpy(qB.data() + h * headDim, qproj.data() + h * 512, headDim * sizeof(float));
        memcpy(gateB.data() + h * headDim, qproj.data() + h * 512 + headDim, headDim * sizeof(float));
    }
    dump_vec("B_Q_INTERLEAVED (4096)", qB.data(), 4096);
    dump_vec("B_GATE_INTERLEAVED (4096)", gateB.data(), 4096);

    // ── Q/K RMSNorm (per-head) on both candidates ──
    std::vector<float> qA_norm(4096), qB_norm(4096), k_norm(1024);
    for (size_t h = 0; h < numHeads; ++h) {
        ref_rmsnorm((const float*)qNorm.data, qA.data() + h * headDim, qA_norm.data() + h * headDim, headDim, 1e-6f);
        ref_rmsnorm((const float*)qNorm.data, qB.data() + h * headDim, qB_norm.data() + h * headDim, headDim, 1e-6f);
    }
    for (size_t h = 0; h < numKVHeads; ++h) {
        ref_rmsnorm((const float*)kNorm.data, kproj.data() + h * headDim, k_norm.data() + h * headDim, headDim, 1e-6f);
    }
    dump_vec("A_Q_NORMED", qA_norm.data(), 4096);
    dump_vec("B_Q_NORMED", qB_norm.data(), 4096);
    dump_vec("K_NORMED", k_norm.data(), 1024);

    // ── Gate activations: sigmoid vs silu, on both candidates ──
    // CORRECT Qwen3.5 structure: gate is applied to the ATTENTION OUTPUT,
    // not to Q. attention_output * gate, then o_proj.
    // First compute real GQA attention to get attention_output.
    // For single token (seqLen=1), attention is trivial: attn_out = V (only 1 key).
    // But to be faithful, compute Q·K^T softmax V with the KV cache.
    // For a single token, the attention output = V (softmax over 1 key = 1.0).
    // So attention_output = V_proj (1024) broadcast to 16 heads.
    std::vector<float> attnOut(4096);
    for (size_t h = 0; h < numHeads; ++h) {
        size_t kvHead = h % numKVHeads;
        memcpy(attnOut.data() + h * headDim, vproj.data() + kvHead * headDim, headDim * sizeof(float));
    }
    dump_vec("ATTN_OUTPUT (V, single token)", attnOut.data(), 4096);

    // Apply gate to attention output: attnOut * gate_activation(gate)
    // Candidate A (contiguous gate)
    std::vector<float> gatedA_sig(4096), gatedA_silu(4096);
    // Candidate B (interleaved gate)
    std::vector<float> gatedB_sig(4096), gatedB_silu(4096);
    for (size_t i = 0; i < 4096; ++i) {
        gatedA_sig[i] = attnOut[i] * sigmoid(gateA[i]);
        gatedA_silu[i] = attnOut[i] * silu(gateA[i]);
        gatedB_sig[i] = attnOut[i] * sigmoid(gateB[i]);
        gatedB_silu[i] = attnOut[i] * silu(gateB[i]);
    }
    dump_vec("A_GATED_SIGMOID (attnOut*sig)", gatedA_sig.data(), 4096);
    dump_vec("A_GATED_SILU (attnOut*silu)", gatedA_silu.data(), 4096);
    dump_vec("B_GATED_SIGMOID (attnOut*sig)", gatedB_sig.data(), 4096);
    dump_vec("B_GATED_SILU (attnOut*silu)", gatedB_silu.data(), 4096);

    // ── o_proj [4096] -> [4096] for each candidate ──
    std::vector<float> outA_sig(4096), outA_silu(4096), outB_sig(4096), outB_silu(4096);
    ref_gemv_tensor(wo, gatedA_sig.data(), outA_sig.data());
    ref_gemv_tensor(wo, gatedA_silu.data(), outA_silu.data());
    ref_gemv_tensor(wo, gatedB_sig.data(), outB_sig.data());
    ref_gemv_tensor(wo, gatedB_silu.data(), outB_silu.data());
    dump_vec("A_OPROJ_SIGMOID", outA_sig.data(), 4096);
    dump_vec("A_OPROJ_SILU", outA_silu.data(), 4096);
    dump_vec("B_OPROJ_SIGMOID", outB_sig.data(), 4096);
    dump_vec("B_OPROJ_SILU", outB_silu.data(), 4096);

    // ── Residual for each candidate ──
    std::vector<float> postA_sig(4096), postA_silu(4096), postB_sig(4096), postB_silu(4096);
    for (size_t i = 0; i < 4096; ++i) {
        postA_sig[i] = input[i] + outA_sig[i];
        postA_silu[i] = input[i] + outA_silu[i];
        postB_sig[i] = input[i] + outB_sig[i];
        postB_silu[i] = input[i] + outB_silu[i];
    }
    dump_vec("A_POST_ATTN_SIGMOID", postA_sig.data(), 4096);
    dump_vec("A_POST_ATTN_SILU", postA_silu.data(), 4096);
    dump_vec("B_POST_ATTN_SIGMOID", postB_sig.data(), 4096);
    dump_vec("B_POST_ATTN_SILU", postB_silu.data(), 4096);

    printf("\n=== DONE ===\n");
    return 0;
}
