// GDN (Qwen3.5/Qwen4Exp gated delta-net) reference parity test.
//
// Verifies Deep2::Qwen4Exp::GDNQwenReferenceStep against an independent,
// ggml-faithful scalar transcription of
//   ggml_compute_forward_gated_delta_net_one_chunk  (wp01_reference/llama.cpp)
//   + qwen35 build_norm_gated (RMSNorm*norm * silu(gate)).
//
// The single scalar-per-head decay in llama.cpp is:
//   g     = ssm_a * softplus(alpha + dt_bias)      (ssm_a already == -exp(A_log))
//   state *= exp(g)
// Deep2 previously computed exp(-exp(a_log) * softplus(...)), applying an extra
// -exp to the already-folded ssm_a tensor. This test fails on that bug and
// passes once the recurrence uses a_log directly.
//
// Exit 0 => PASS. Standalone: no Qt, no third-party deps (only <cmath>/<vector>).

#include "deep2/op_gdn.hpp"  // resolved via -I src

#include <cmath>
#include <cstdio>
#include <vector>

using Deep2::Qwen4Exp::GDNDescriptor;
using Deep2::Qwen4Exp::GDNQwenReferenceStep;

static float softplus(float x) {
    if (x > 20.0f) return x;
    if (x < -20.0f) return std::exp(x);
    return std::log1p(std::exp(x));
}
static float sigmoid(float x) {
    if (x >= 0.0f) { float e = std::exp(-x); return 1.0f / (1.0f + e); }
    float e = std::exp(x); return e / (1.0f + e);
}

// Independent reference: ggml-faithful, single value-head, single token.
// state layout s_out[j*D+i] (== Deep2 St[v*D+k] with j=v, i=k).
static void ggml_ref_head(const std::vector<float>& qkv, size_t Hk, size_t Hv,
                          size_t D, size_t hv, const std::vector<float>& betaL,
                          const std::vector<float>& alphaL, const std::vector<float>& aLog,
                          const std::vector<float>& dtBias, const std::vector<float>& norm,
                          const std::vector<float>& gate, float eps,
                          std::vector<float>& state, std::vector<float>& out) {
        const size_t hk = hv % Hk;
    const size_t q_base = hk * D;
    const size_t k_base = (Hk + hk) * D;
    const size_t v_base = (2 * Hk + hv) * D;
    const size_t s_base = hv * D * D;
    const float scale = 1.0f / std::sqrt(static_cast<float>(D));

    float qs = 0.0f, ks = 0.0f;
    for (size_t i = 0; i < D; ++i) {
        float q = qkv[q_base + i], k = qkv[k_base + i];
        qs += q * q; ks += k * k;
    }
    const float qinv = 1.0f / std::sqrt(qs + eps);
    const float kinv = 1.0f / std::sqrt(ks + eps);
    std::vector<float> qn(D), kn(D);
    for (size_t i = 0; i < D; ++i) {
        qn[i] = qkv[q_base + i] * qinv;
        kn[i] = qkv[k_base + i] * kinv;
    }

    // ggml scalar path: g = ssm_a * softplus(alpha + dt_bias); decay = exp(g)
    const float g = aLog[hv] * softplus(alphaL[hv] + dtBias[hv]);
    const float decay = std::exp(g);
    const float beta = sigmoid(betaL[hv]);

    float* M = state.data() + s_base;  // [D][D], row j = value index
    for (size_t x = 0; x < D * D; ++x) M[x] *= decay;

    std::vector<float> delta(D);
    for (size_t j = 0; j < D; ++j) {
        float sum = 0.0f;
        for (size_t i = 0; i < D; ++i) sum += M[j * D + i] * kn[i];
        delta[j] = (qkv[v_base + j] - sum) * beta;
    }
    for (size_t j = 0; j < D; ++j)
        for (size_t i = 0; i < D; ++i) M[j * D + i] += kn[i] * delta[j];

    std::vector<float> attn(D);
    float ss = 0.0f;
    for (size_t j = 0; j < D; ++j) {
        float sum = 0.0f;
        for (size_t i = 0; i < D; ++i) sum += M[j * D + i] * qn[i];
        attn[j] = sum * scale;
        ss += attn[j] * attn[j];
    }
    const float inv = 1.0f / std::sqrt(ss / static_cast<float>(D) + eps);
    for (size_t j = 0; j < D; ++j) {
        const float gv = gate[hv * D + j];
        const float silu = gv / (1.0f + std::exp(-gv));
        out[hv * D + j] = attn[j] * inv * norm[j] * silu;
    }
}

int main() {
    const size_t Hk = 2, Hv = 4, D = 8;
    const float eps = 1e-6f;

    // Deterministic pseudo-random inputs.
    std::vector<float> qkv((2 * Hk + Hv) * D), betaL(Hv), alphaL(Hv), aLog(Hv),
        dtBias(Hv), norm(D), gate(Hv * D);
    unsigned rng = 0x1234567u;
    auto nextf = [&]() {
        rng = rng * 1664525u + 1013904223u;
        return ((rng >> 8) & 0xffff) / 65535.0f * 2.0f - 1.0f;
    };
    for (auto& v : qkv) v = nextf();
    for (auto& v : betaL) v = nextf();
    for (auto& v : alphaL) v = nextf() * 2.0f;
    for (auto& v : dtBias) v = nextf();
    for (auto& v : norm) { v = nextf(); v = 1.0f + std::fabs(v); }  // positive norm weight
    for (auto& v : gate) v = nextf();
    // ssm_a holds -exp(A_log) in the GGUF (negative). Emulate that.
    for (auto& v : aLog) v = -std::exp(nextf());

    GDNDescriptor desc;
    desc.channels = static_cast<uint32_t>(Hv * D);
    desc.state_size = static_cast<uint32_t>(D);
    desc.groups = 1;
    desc.key_heads = static_cast<uint32_t>(Hk);
    desc.value_heads = static_cast<uint32_t>(Hv);
    desc.head_dim = static_cast<uint32_t>(D);
    desc.tokens = 1;
    desc.scale = 1.0f / std::sqrt(static_cast<float>(D));
    desc.epsilon = eps;
    desc.gate_sigmoid = 0;  // silu gate (qwen35)

    const size_t stateElems = Deep2::Qwen4Exp::GDNQwenStateElements(desc);
    std::vector<float> stateDeep2(stateElems, 0.0f), stateRef(stateElems, 0.0f);
    // Non-zero initial state to exercise the decay multiply.
    for (size_t i = 0; i < stateElems; ++i) {
        stateDeep2[i] = nextf() * 0.1f;
        stateRef[i] = stateDeep2[i];
    }

    std::vector<float> outDeep2, outRef(Hv * D, 0.0f);
    std::string failure;
    if (!GDNQwenReferenceStep(desc, qkv, betaL, alphaL, aLog, dtBias, norm, gate,
                              stateDeep2, outDeep2, failure)) {
        std::printf("FAIL: GDNQwenReferenceStep error: %s\n", failure.c_str());
        return 2;
    }
    for (size_t hv = 0; hv < Hv; ++hv)
        ggml_ref_head(qkv, Hk, Hv, D, hv, betaL, alphaL, aLog, dtBias, norm, gate,
                      eps, stateRef, outRef);

    // Show the decay discrepancy explicitly for head 0.
    const float sp = softplus(alphaL[0] + dtBias[0]);
    const float decayRef = std::exp(aLog[0] * sp);          // ggml-correct
    const float decayBug = std::exp(-std::exp(aLog[0]) * sp); // previous Deep2
    std::printf("decay head0: reference=%.6f  old_bug=%.6f  a_log=%.6f\n",
                decayRef, decayBug, aLog[0]);

    double maxAbs = 0.0;
    size_t worst = 0;
    double maxStateDiff = 0.0;
    for (size_t i = 0; i < Hv * D; ++i) {
        double d = std::fabs(static_cast<double>(outDeep2[i]) - outRef[i]);
        if (d > maxAbs) { maxAbs = d; worst = i; }
    }
    for (size_t i = 0; i < stateElems; ++i) {
        double d = std::fabs(static_cast<double>(stateDeep2[i]) - stateRef[i]);
        if (d > maxStateDiff) maxStateDiff = d;
    }
    std::printf("max_abs(output) = %.6g at index %zu (deep2=%.6g ref=%.6g)\n",
                maxAbs, worst, outDeep2[worst], outRef[worst]);
    std::printf("max_abs(state)  = %.6g\n", maxStateDiff);

    const bool ok = maxAbs < 1e-4 && maxStateDiff < 1e-4;
    std::printf("%s\n", ok ? "GDN_PARITY=PASS" : "GDN_PARITY=FAIL");
    return ok ? 0 : 1;
}
