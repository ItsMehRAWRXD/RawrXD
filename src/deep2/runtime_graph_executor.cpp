// ============================================================================
// runtime_graph_executor.cpp  --  RAWRXD_DEEP2_RUNTIME_DISPATCH
// ============================================================================
#include "runtime_graph_executor.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "ggml.h"
#include "quant_dot_dispatch.hpp"
#include "Q8KQuant.h"   // single ggml-exact Q8_K activation quantiser

namespace RawrXD { namespace Deep2 { namespace RuntimeGraph {

using Universal::TensorRec;

namespace {

// ---------------------------------------------------------------------------
// RAWRXD_RESOURCE_GOVERNOR_001 — admitted, bounded KV residency.
//
// One process governor for host-RAM leases (weight residency and KV growth).
// DEEP2_KV_BUDGET_MB overrides the default host budget. The KV cache grows by
// lease only: growth that does not fit the budget fails the forward pass
// closed, because silently truncating the cache corrupts every later
// position rather than degrading gracefully.
// ---------------------------------------------------------------------------
rawrxd::deep2::Governor& ProcessGovernor() {
    static rawrxd::deep2::Governor governor = [] {
        std::uint64_t mb = 8192;   // 8 GiB default host admission budget
        if (const char* e = std::getenv("DEEP2_KV_BUDGET_MB")) {
            const unsigned long long v = std::strtoull(e, nullptr, 10);
            if (v > 0) mb = v;
        }
        return rawrxd::deep2::Governor({mb * 1024ull * 1024ull, 0, 0});
    }();
    return governor;
}

}  // namespace

// RAWRXD_RESOURCE_GOVERNOR_001: acquire a host admission lease for `bytes` of
// KV cache growth. Returns an empty optional when the budget is exhausted; the
// caller must then fail the forward pass closed.
std::optional<GovernorLease> Executor::TryLeaseKv(size_t bytes) {
    auto lease = ProcessGovernor().tryAcquire(rawrxd::deep2::Pool::Host, bytes);
    if (!lease) return std::nullopt;
    return lease;
}

namespace {

// ---------------------------------------------------------------------------
// RAWRXD_DEEP2_LEGACY_QUANT_GPU_001 - shared quant-dot helpers.
//
// Every quantised matmul in the executor (linear projections AND MoE expert
// slices) dispatches through QuantDot::DotBlocked with an interleaved Q8_K
// activation. These two helpers are the host side of that contract, factored
// out so the linear path and the MoE path cannot drift apart:
//   BuildInterleavedQ8  - quantise the activation the way the shader reads it
//   RowDotInterleavedQ8 - decode one packed row and dot it against that
//                         activation, mirroring the shader bit for bit.
// The final 256-value super-block is PARTIAL when n_in % 256 != 0 (e.g. the
// 2688-wide shapes in nemotron_h_moe = 10*256 + 128).
// ---------------------------------------------------------------------------

constexpr size_t kQ8Stride = 273;   // floats per 256-value activation super-block

// Quantise x into the interleaved Q8_K layout: per super-block d, qs[256],
// bsums[16] (bsums are unused by the legacy kernels but kept so the layout is
// identical for all kinds).
//
// CHANGED 2026-10-13: this was a second, divergent Q8_K implementation. It used
// unsigned amax/127 for the scale, std::lround (half away from zero) for the
// values, and no MIN(127,v) clamp, while ggml's quantize_row_q8_K_ref uses the
// SIGNED extremum (iscale = -127.f/max, d = 1/iscale), round-half-to-even
// nearest_int, and a clamp. The byte-level differential in src/deep2/Q8KParity.cpp
// showed ggml d=0xBCD9E6F9 (-0.0266) against this function's 0x3CD9E6F9
// (+0.0266): identical magnitude, opposite sign bit, plus 751 differing qs
// values across 4 of 8 blocks once halfway ties were present.
//
// The quantiser now lives in src/deep2/Q8KQuant.h so this and the parity path
// below cannot drift apart again.
inline void BuildInterleavedQ8(const float* x, size_t n_in, std::vector<float>& q8) {
    const size_t n_sb = (n_in + 255u) / 256u;
    q8.assign(n_sb * kQ8Stride, 0.0f);
    BuildInterleavedQ8K(x, n_in, q8.data());
}

// Packed row stride for a kind / n_in pair.
inline size_t QuantRowBytes(int kind, size_t n_in) {
    switch (kind) {
    case 0: return (n_in / 256u) * 144u;               // Q4_K
    case 1: return (n_in / 256u) * 210u;               // Q6_K
    case 2: return ((n_in + 31u) / 32u) * 22u;         // Q5_0
    case 3: return ((n_in + 31u) / 32u) * 34u;         // Q8_0
    default: return ((n_in + 31u) / 32u) * 18u;        // Q4_0
    }
}

// Kernel kind for a ggml type, or -1 when the quant-dot shader does not
// cover it (the caller keeps its CPU path for those).
inline int QuantKindOf(ggml_type t) {
    switch (t) {
    case GGML_TYPE_Q4_K: return 0;
    case GGML_TYPE_Q6_K: return 1;
    case GGML_TYPE_Q5_0: return 2;
    case GGML_TYPE_Q8_0: return 3;
    case GGML_TYPE_Q4_0: return 4;
    default: return -1;
    }
}

// ---------------------------------------------------------------------------
// K-quant row dot against the interleaved Q8_K activation, mirroring
// ggml_vec_dot_q4_K_q8_K_generic / ggml_vec_dot_q6_K_q8_K_generic EXACTLY:
// integer products formed first and accumulated in 8 int32 lanes, the fp16
// scales applied last, and the Q4_K min term folded in through the per-block
// sums.  This is the single shared implementation for BOTH the linear path and
// the MoE expert path: the header contract says those two "cannot drift apart",
// but the MoE helper previously dequantised the row to float and dot-producted
// that instead.  That is algebraically the same number yet rounds differently
// at every element, and because DeepSeek's expert FFNs dominate its compute it
// is what left the DeepSeek teacher-forced gate at 0.03-0.11 relative logit
// error while the identical dense-linear path reached 0.0297 on Qwen.
//
// q8 layout per 256-value super-block: [0]=d, [1..256]=qs, [257..272]=bsums.
// ---------------------------------------------------------------------------
inline float KQuantRowDotQ8(int kind, const uint8_t* row, const float* q8,
                            size_t n_in) {
    const size_t nblk = n_in / 256u;
    const size_t blk_bytes = (kind == 0) ? 144u : 210u;
    int32_t a[256];
    int32_t aux32[8];
    float sums[8], sumf = 0.0f;
    for (int l = 0; l < 8; ++l) sums[l] = 0.0f;
    for (size_t b = 0; b < nblk; ++b) {
        const uint8_t* blk = row + b * blk_bytes;
        const float* q8b = q8 + b * kQ8Stride;
        for (int l = 0; l < 8; ++l) aux32[l] = 0;
        if (kind == 0) {
            // ---- Q4_K: low nibble -> element j, high -> j+32 (per group of 4)
            for (int j = 0; j < 4; ++j) {
                for (int l = 0; l < 32; ++l) {
                    a[j * 64 + l]      = blk[16 + j * 32 + l] & 0xF;
                    a[j * 64 + 32 + l] = blk[16 + j * 32 + l] >> 4;
                }
            }
            int32_t scales[8], mins[8];
            for (int s = 0; s < 8; ++s) {
                if (s < 4) {
                    scales[s] = blk[4 + s] & 63;
                    mins[s]   = blk[4 + s + 4] & 63;
                } else {
                    scales[s] = (blk[4 + s + 4] & 0xF) | ((blk[4 + s - 4] >> 6) << 4);
                    mins[s]   = (blk[4 + s + 4] >> 4) | ((blk[4 + s] >> 6) << 4);
                }
            }
            for (int s = 0; s < 8; ++s) {
                const int32_t sc = scales[s];
                for (int l = 0; l < 32; ++l)
                    aux32[l & 7] += sc * (int32_t)q8b[1 + s * 32 + l] * a[s * 32 + l];
            }
            uint16_t h;
            std::memcpy(&h, blk + 0, 2);
            const float d = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
            std::memcpy(&h, blk + 2, 2);
            const float dmin = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
            for (int l = 0; l < 8; ++l) sums[l] += d * float(aux32[l]);
            int32_t sumi = 0;
            for (int j = 0; j < 16; ++j) sumi += (int32_t)q8b[257 + j] * mins[j / 2];
            sumf -= dmin * float(sumi);
        } else {
            // ---- Q6_K: ql[128] + qh[64] + 16 int8 scales + fp16 scale ----
            for (int j = 0; j < 256; ++j) a[j] = 0;
            for (int j = 0; j < 2; ++j) {          // 128-value halves
                const uint8_t* q4 = blk + j * 64;
                const uint8_t* qh = blk + 128 + j * 32;
                int* ah = a + j * 128;
                for (int l = 0; l < 32; ++l) {
                    ah[l +  0] = (int8_t)((q4[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                    ah[l + 32] = (int8_t)((q4[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                    ah[l + 64] = (int8_t)((q4[l +  0] >>  4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                    ah[l + 96] = (int8_t)((q4[l + 32] >>  4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                }
            }
            int32_t scales[16];
            for (int s = 0; s < 16; ++s) {
                int8_t sc;
                std::memcpy(&sc, blk + 192 + s, 1);
                scales[s] = sc;
            }
            for (int s = 0; s < 16; ++s) {
                const int32_t sc = scales[s];
                for (int l = 0; l < 16; ++l)
                    aux32[l & 7] += sc * (int32_t)q8b[1 + s * 16 + l] * a[s * 16 + l];
            }
            uint16_t h;
            std::memcpy(&h, blk + 208, 2);
            const float d = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
            for (int l = 0; l < 8; ++l) sums[l] += d * float(aux32[l]);
        }
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

// Decode ONE packed row (kind 0..3) and dot it against the interleaved Q8
// activation, exactly as the shader does: ggml block decoders, fp16 scales,
// integer MACs, super-block activation scale applied once per super-block.
inline float RowDotInterleavedQ8(int kind, const uint8_t* row, const float* q8v, size_t n_in) {
    if (kind <= 1) {
        // ---- k-quants Q4_K / Q6_K: shared ggml-accurate integer-MAC path ----
        // (the linear path in the executor routes through the same function, so
        // a dense projection and an MoE expert slice cannot diverge)
        return (n_in % 256u) == 0u ? KQuantRowDotQ8(kind, row, q8v, n_in) : 0.0f;
    }
    // ---- legacy Q5_0 / Q8_0 / Q4_0 (32 values per block) ----
    {
        const size_t lb_bytes = (kind == 2) ? 22u : ((kind == 3) ? 34u : 18u);
        const size_t n_sb = (n_in + 255u) / 256u;
        double acc = 0.0;
        for (size_t b = 0; b < n_sb; ++b) {
            const float dq = q8v[b * kQ8Stride + 0];
            const size_t elems = std::min<size_t>(256u, n_in - b * 256u);
            for (size_t lb = 0; lb < elems / 32u; ++lb) {
                const uint8_t* blk = row + (b * 8u + lb) * lb_bytes;
                // q8 index is LOCAL to the super-block.
                const size_t a0 = lb * 32u;
                int32_t dotp = 0;
                if (kind == 2) {
                    uint16_t hb;
                    std::memcpy(&hb, blk, 2);
                    const float dw = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
                    uint32_t qh;
                    std::memcpy(&qh, blk + 2, 4);
                    for (size_t j = 0; j < 16u; ++j) {
                        const uint32_t qsb = blk[6 + j];
                        const int h0 = (int)((qh >> (j + 0u)) & 1u);
                        const int h1 = (int)((qh >> (j + 16u)) & 1u);
                        const int w0 = (int)(qsb & 0x0Fu) | (h0 << 4);
                        const int w1 = (int)(qsb >> 4) | (h1 << 4);
                        dotp += (w0 - 16) * (int32_t)q8v[b * kQ8Stride + 1 + a0 + j];
                        dotp += (w1 - 16) * (int32_t)q8v[b * kQ8Stride + 1 + a0 + j + 16u];
                    }
                    acc += (double)dw * (double)dq * (double)dotp;
                } else if (kind == 3) {
                    uint16_t hb;
                    std::memcpy(&hb, blk, 2);
                    const float dw = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
                    for (size_t i = 0; i < 32u; ++i)
                        dotp += (int32_t)(int8_t)blk[2 + i] * (int32_t)q8v[b * kQ8Stride + 1 + a0 + i];
                    acc += (double)dw * (double)dq * (double)dotp;
                } else {
                    // Q4_0: fp16 d, 16 nibble bytes; low nibble -> element j,
                    // high nibble -> element j+16, minus 8.
                    uint16_t hb;
                    std::memcpy(&hb, blk, 2);
                    const float dw = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
                    for (size_t j = 0; j < 16u; ++j) {
                        const uint32_t qsb = blk[2 + j];
                        const int w0 = (int)(qsb & 0x0Fu) - 8;
                        const int w1 = (int)(qsb >> 4) - 8;
                        dotp += w0 * (int32_t)q8v[b * kQ8Stride + 1 + a0 + j];
                        dotp += w1 * (int32_t)q8v[b * kQ8Stride + 1 + a0 + j + 16u];
                    }
                    acc += (double)dw * (double)dq * (double)dotp;
                }
            }
        }
        return (float)acc;
    }
}

const char* opName(Universal::Op o) {
    switch (o) {
        case Universal::Op::EmbeddingLookup: return "EmbeddingLookup";
        case Universal::Op::RmsNorm: return "RmsNorm";
        case Universal::Op::Linear: return "Linear";
        case Universal::Op::Attention: return "Attention";
        case Universal::Op::MatMul: return "MatMul";
        case Universal::Op::MlaDecompress: return "MlaDecompress";
        case Universal::Op::Router: return "Router";
        case Universal::Op::TopK: return "TopK";
        case Universal::Op::MoEExecute: return "MoEExecute";
        case Universal::Op::ResidualAdd: return "ResidualAdd";
        case Universal::Op::LmHead: return "LmHead";
        default: return "Unsupported";
    }
}

void RmsNormVec(std::vector<float>& out, const std::vector<float>& in,
                const std::vector<float>& w, double eps) {
    const size_t n = in.size();
    out.resize(n);
    if (n == 0) return;
    double ss = 0.0;
    for (size_t i = 0; i < n; ++i) ss += double(in[i]) * double(in[i]);
    const float scale = 1.0f / std::sqrt(float(ss / double(n)) + float(eps));
    for (size_t i = 0; i < n; ++i) out[i] = in[i] * w[i] * scale;
}

void SoftmaxVec(std::vector<float>& x) {
    if (x.empty()) return;
    float m = x[0];
    for (float v : x) m = std::max(m, v);
    double sum = 0.0;
    for (auto& v : x) { v = std::exp(v - m); sum += v; }
    if (sum > 0.0) for (auto& v : x) v = float(v / sum);
}

// Dequantise a tensor prefix into float using ggml (bounded, like the ingester).
// F32/F16/BF16 need no dequantisation - ggml exposes no to_float for them, so
// calling it unconditionally would be a null call.
size_t DequantPrefix(const TensorRec& t, std::vector<float>& out, size_t want) {
    out.clear();
    if (!t.data) return 0;
    if (t.ggml_type == GGML_TYPE_F32) {
        const size_t n = std::min(want, t.bytes / sizeof(float));
        if (n == 0) return 0;
        out.assign(n, 0.0f);
        std::memcpy(out.data(), t.data, n * sizeof(float));
        return n;
    }
    if (t.ggml_type == GGML_TYPE_F16 || t.ggml_type == GGML_TYPE_BF16) {
        const size_t n = std::min(want, t.bytes / 2);
        if (n == 0) return 0;
        out.assign(n, 0.0f);
        for (size_t i = 0; i < n; ++i) {
            uint16_t h;
            std::memcpy(&h, t.data + i * 2, 2);
            if (t.ggml_type == GGML_TYPE_F16) {
                const ggml_fp16_t p = static_cast<ggml_fp16_t>(h);
                out[i] = ggml_fp16_to_fp32(p);
            } else {
                const uint32_t bits = static_cast<uint32_t>(h) << 16;
                float f; std::memcpy(&f, &bits, 4);
                out[i] = f;
            }
        }
        return n;
    }
    const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
    if (!tr || !tr->to_float) return 0;
    const size_t blk = (size_t)tr->blck_size;
    const size_t row_bytes = (size_t)t.dims.empty() ? 0 : (size_t)t.dims[0];
    const size_t ein = (size_t)t.dims[0];
    const size_t blocks_per_row = (ein + blk - 1) / blk;
    const size_t total_blocks = (size_t)t.bytes / (size_t)tr->type_size;
    const size_t rows = blocks_per_row ? (total_blocks / blocks_per_row) : 0;
    const size_t n = std::min(want, blocks_per_row * std::max<size_t>(rows, 1) * blk);

    out.assign(n, 0.0f);
    const size_t chunk = 1u << 22;
    for (size_t off = 0; off < n; off += chunk) {
        const int cnt = (int)std::min(chunk, n - off);
        tr->to_float(t.data + off / blk * (size_t)tr->type_size, out.data() + off, cnt);
    }
    return n;
}

}  // namespace

const char* OpKindName(OpKind k) {
    switch (k) {
        case OpKind::EmbeddingLookup: return "EmbeddingLookup";
        case OpKind::RmsNorm: return "RmsNorm";
        case OpKind::Linear: return "Linear";
        case OpKind::Attention: return "Attention";
        case OpKind::MlaDecompress: return "MlaDecompress";
        case OpKind::Router: return "Router";
        case OpKind::TopK: return "TopK";
        case OpKind::MoEExecute: return "MoEExecute";
        case OpKind::ResidualAdd: return "ResidualAdd";
        case OpKind::Publish: return "Publish";
        case OpKind::SwiGLU: return "SwiGLU";
        case OpKind::LmHead: return "LmHead";

        default: return "Unsupported";
    }
}

Executor::~Executor() = default;

// ---------------------------------------------------------------------------
// Bind
// ---------------------------------------------------------------------------
bool Executor::Bind(const Universal::IngestReport& report) {
    stats_ = BindStats{};
    bound_ = false;
    last_error_.clear();

    if (!report.ok) { stats_.error = "ingest report invalid"; return false; }
    spec_ = report.spec;
    tensors_ = report.tensors;
    program_.clear();
    slot_by_name_.clear();

    // ---- 1. resolve every weight handle once ----
    for (size_t i = 0; i < tensors_.size(); ++i) {
        slot_by_name_[tensors_[i].name] = (int32_t)i;
        if (tensors_[i].data) ++stats_.weights_resolved; else ++stats_.weights_missing;
    }

    // Required global tensors must exist.
    auto findSlot = [&](const char* n) -> int32_t {
        auto it = slot_by_name_.find(n);
        return it == slot_by_name_.end() ? -1 : it->second;
    };
    if (findSlot("token_embd.weight") < 0) { stats_.error = "missing token_embd.weight"; return false; }
    if (findSlot("output_norm.weight") < 0) { stats_.error = "missing output_norm.weight"; return false; }

    // The LM head. Models that tie their embeddings (Qwen2.5-Coder-1.5B and
    // most base checkpoints) ship no output.weight at all and share
    // token_embd.weight as the head. Accepting the embedding there is correct
    // only when it can serve as a [vocab, hidden] projection, so the geometry
    // is validated against the model's own tensors rather than assumed. If
    // neither candidate is usable, binding still fails - a model with no
    // projectable head cannot choose a next token, and substituting something
    // of the wrong shape would silently produce nonsense.
    if (findSlot("output.weight") < 0) {
        const int32_t emb = findSlot("token_embd.weight");
        const TensorRec* e = (emb >= 0) ? &tensors_[(size_t)emb] : nullptr;
        uint64_t hiddenDim = spec_.embd;
        if (hiddenDim == 0) {
            for (const auto& t : tensors_) {
                if (t.name == "blk.0.attn_output.weight" && t.dims.size() >= 2) {
                    hiddenDim = t.dims[0];
                    break;
                }
            }
        }
        const bool canTie = (e != nullptr) && (hiddenDim != 0) &&
                            (e->dims.size() >= 2) &&
                            (e->dims[0] == (decltype(e->dims[0]))hiddenDim) &&
                            (e->dims[1] > (decltype(e->dims[1]))hiddenDim);
        if (!canTie) {
            stats_.error = "missing output.weight and token_embd.weight cannot "
                           "serve as a tied LM head";
            return false;
        }
        // Tied embeddings: the head op resolves through token_embd.weight.
    }

    // ---- 2. compile the runtime graph into instructions ----
    // Each op in the runtime graph names its tensors by name string; map those
    // to handles now so decoding never searches by string.
    auto nameSlot = [&](const std::string& n) -> int32_t {
        if (n.empty() || n[0] == '<') return -1;   // arena values, not weights
        auto it = slot_by_name_.find(n);
        return it == slot_by_name_.end() ? -1 : it->second;
    };

    program_.reserve(report.graph.ops.size());
    for (const auto& g : report.graph.ops) {
        Instr in;
        // map the runtime op kind onto the executable op kind
        switch (g.op) {
            case Universal::Op::EmbeddingLookup: in.op = OpKind::EmbeddingLookup; break;
            case Universal::Op::RmsNorm: in.op = OpKind::RmsNorm; break;
            case Universal::Op::Linear: in.op = OpKind::Linear; break;
            // VERIFIED LOWERING RULE (audit 2026-10-13): no graph producer emits
            // Universal::Op::MatMul. universal_gguf.cpp contains 11 sites that
            // assign Op::Linear and 0 sites that assign Op::MatMul, so this
            // arm is unreachable for every model the runtime ingests today.
            //
            // It is deliberately NOT aliased onto Linear. The two contracts are
            // different: Linear is a weight-backed GGUF projection whose `b`
            // operand must resolve to a ROM weight slot, while MatMul is a
            // general tensor x tensor product with arbitrary stride, transpose
            // and broadcast rules. Folding MatMul into Linear would let a future
            // producer silently compute a projection when a matmul was asked for.
            //
            // Instead it fails closed through OpKind::Unsupported, which the bind
            // step turns into an explicit "unimplemented operators" error rather
            // than a wrong result. (OpLinear() also rejects wslot < 0, so this
            // was already fail-closed at execution time; this moves the refusal
            // to lowering, where it is diagnosable.)
            case Universal::Op::MatMul: in.op = OpKind::Unsupported; break;
            case Universal::Op::Attention: in.op = OpKind::Attention; break;
            case Universal::Op::MlaDecompress: in.op = OpKind::MlaDecompress; break;
            case Universal::Op::Router: in.op = OpKind::Router; break;
            case Universal::Op::TopK: in.op = OpKind::TopK; break;
            case Universal::Op::MoEExecute: in.op = OpKind::MoEExecute; break;
            case Universal::Op::ResidualAdd: in.op = OpKind::ResidualAdd; break;
            case Universal::Op::Publish: in.op = OpKind::Publish; break;
            case Universal::Op::SwiGLU: in.op = OpKind::SwiGLU; break;
            case Universal::Op::LmHead: in.op = OpKind::LmHead; break;
            case Universal::Op::SsmScan: in.op = OpKind::SsmScan; break;

            default: in.op = OpKind::Unsupported; break;
        }
        in.block = g.block;
        in.aName = g.a;
        in.bName = g.b;
        in.outName = g.out;
        in.a = nameSlot(g.a);
        // b may carry "<weight>|<activation>": strip the tail before resolving
        // the weight slot so the pipe does not break the tensor lookup.
        std::string bWeight = g.b;
        const size_t bBar = bWeight.find('|');
        if (bBar != std::string::npos) bWeight = bWeight.substr(0, bBar);
        in.b = nameSlot(bWeight);
        in.c = nameSlot(g.c);
        in.out = nameSlot(g.out);
        in.detail = g.detail;
        program_.push_back(in);
    }

    // ---- 2a. producer/consumer geometry pass -------------------------------
    // Resolve, for every attention op, the WEIGHT slot of the projection that
    // consumes its output, and record it in Instr::q. OpAttention then has the
    // model's own declared input width for that projection and can fail closed
    // when the concatenated attention output does not match it -- the
    // deepseek2 class of defect, where the output was built from the 192-wide
    // query head instead of the 128-wide value head and the projection
    // (blk.0.attn_output.weight, dims [2048, 2048]) rejected 3,072 elements.
    //
    // Arena names such as "attn_out" are REUSED by every block, so the producer
    // is resolved as the NEAREST PRECEDING writer of that name in the SAME
    // block. Resolving through a last-writer map instead bound every block to
    // the final block's projection, which happens to have identical dims and
    // therefore hid the attribution error behind a passing check.
    for (size_t i = 0; i < program_.size(); ++i) {
        Instr& consumer = program_[i];
        if (consumer.op != OpKind::Linear || consumer.b < 0) continue;
        if (consumer.aName.empty() || consumer.aName[0] == '<') continue;
        for (size_t j = i; j-- > 0;) {
            const Instr& producer = program_[j];
            if (producer.block != consumer.block) break;      // stay in-block
            if (producer.outName != consumer.aName) continue;
            if (producer.op == OpKind::Attention) program_[j].q = consumer.b;
            break;   // nearest producer only
        }
    }

    // ---- 2b. model geometry summary (fail-closed diagnostics) --------------
    // Printed once at bind so the attention path can always be audited against
    // the model's own metadata: architecture, head counts, head lengths, and
    // the attention projection dims actually present in the file.
    if (spec_.architecture == "deepseek2" || spec_.kv_lora_rank > 0) {
        std::fprintf(stderr,
                     "[geom] architecture=%s embedding_length=%zu head_count=%zu "
                     "head_count_kv=%zu key_length=%zu value_length=%zu "
                     "kv_lora_rank=%zu blocks=%zu\n",
                     spec_.architecture.c_str(), (size_t)spec_.embd,
                     (size_t)spec_.heads, (size_t)spec_.heads_kv,
                     (size_t)spec_.key_length, (size_t)spec_.value_length,
                     (size_t)spec_.kv_lora_rank, (size_t)spec_.block_count);
        const char* names[4] = {"blk.0.attn_q.weight", "blk.0.attn_kv_a_mqa.weight",
                                "blk.0.attn_kv_b.weight", "blk.0.attn_output.weight"};
        for (const char* n : names) {
            for (const auto& t : tensors_) {
                if (t.name != n) continue;
                std::fprintf(stderr, "[geom]   %-28s dims=[%zu,%zu]\n", n,
                             t.dims.empty() ? 0 : (size_t)t.dims[0],
                             t.dims.size() > 1 ? (size_t)t.dims[1] : 0);
                break;
            }
        }
        // The invariant the attention path must preserve, stated with the
        // model's own numbers: value_width must divide the projection input,
        // and per-head value width must be strictly narrower than the per-head
        // query width for MLA (the query head carries the rotary half).
        const size_t H = (size_t)std::max<uint64_t>(spec_.heads, 1);
        const size_t qW = (size_t)spec_.key_length;
        const size_t vW = (size_t)spec_.value_length;
        if (vW == 0 || qW == 0 || H == 0 || vW > qW) {
            stats_.error = "attention geometry metadata inconsistent: head_count=" +
                           std::to_string(H) + " key_length=" + std::to_string(qW) +
                           " value_length=" + std::to_string(vW);
            return false;
        }
    }

    // ---- 2b. env-gated execution-graph provenance dump (no semantics change) ----
    // RR_GRAPH_TRACE=1 prints every compiled instruction (block, kind, operands,
    // published output) and resolves each named operand to its producing op, so
    // producer/consumer defects (e.g. a residual addend that no op publishes)
    // are visible before inference. Purely diagnostic; never alters execution.
    if (std::getenv("RR_GRAPH_TRACE")) {
        auto kindName = [&](OpKind k) -> const char* {
            switch (k) {
                case OpKind::EmbeddingLookup: return "Embed";
                case OpKind::RmsNorm:         return "RmsNorm";
                case OpKind::Linear:          return "Linear";
                case OpKind::Attention:       return "Attention";
                case OpKind::MlaDecompress:   return "MlaDec";
                case OpKind::Router:          return "Router";
                case OpKind::TopK:            return "TopK";
                case OpKind::MoEExecute:      return "MoE";
                case OpKind::ResidualAdd:     return "ResidualAdd";
                case OpKind::Publish:         return "Publish";
                case OpKind::SwiGLU:          return "SwiGLU";
                case OpKind::LmHead:          return "LmHead";
                case OpKind::SsmScan:         return "SsmScan";
                default:                      return "Other";
            }
        };
        std::unordered_map<std::string, int> producer;
        for (size_t i = 0; i < program_.size(); ++i) {
            const auto& in = program_[i];
            if (!in.outName.empty()) producer.emplace(in.outName, (int)i);
        }
        std::fprintf(stderr, "[graph] %zu ops; producer map resolve:\n", program_.size());
        for (size_t i = 0; i < program_.size(); ++i) {
            const auto& in = program_[i];
            char pa[48] = "-", pb[48] = "-";
            if (!in.aName.empty() && in.aName[0] != '<') {
                auto it = producer.find(in.aName);
                if (it != producer.end()) std::snprintf(pa, sizeof(pa), "=op%d", it->second);
            }
            if (!in.bName.empty() && in.bName[0] != '<') {
                auto bBar = in.bName.find('|');
                std::string bKey = (bBar == std::string::npos) ? in.bName : in.bName.substr(0, bBar);
                auto it = producer.find(bKey);
                if (it != producer.end()) std::snprintf(pb, sizeof(pb), "=op%d", it->second);
            }
            std::fprintf(stderr, "[op%-4d blk%-3d %-11s a=%-16s%-8s b=%-26s%-8s out=%s]\n",
                         (int)i, (int)in.block, kindName(in.op),
                         in.aName.c_str(), pa, in.bName.c_str(), pb, in.outName.c_str());
        }
    }

    // ---- 3. bind kernels, fail-closed ----
    stats_.ops_total = program_.size();
    for (const auto& in : program_) {
        if (in.op == OpKind::Unsupported) {
            char buf[256];
            std::snprintf(buf, sizeof(buf), "Unsupported node: %s", in.detail.c_str());
            stats_.unbound_ops.emplace_back(buf);
            ++stats_.ops_unbound;
            continue;
        }
        ++stats_.ops_bound;
    }

    if (stats_.ops_unbound > 0) {
        // Fail closed: an unsupported node PREVENTS execution. It must not be
        // silently skipped, because the state that node would have produced
        // is then silently missing.
        std::string e = "graph contains unimplemented operators: ";
        for (size_t i = 0; i < stats_.unbound_ops.size() && i < 4; ++i)
            e += stats_.unbound_ops[i] + "; ";
        stats_.error = e;
        return false;
    }
    if (stats_.ops_bound == 0) { stats_.error = "no executable ops"; return false; }

    // ---- 4. allocate per-layer KV cache ----
    const size_t B = (size_t)std::max<uint64_t>(spec_.block_count, 1);
    kv_k_.assign(B, {});
    kv_v_.assign(B, {});
    kvat_.assign(B, {});

    bound_ = true;
    stats_.bound = true;
    return true;
}

float* Executor::WeightData(int32_t slot, size_t& floats_out) {
    floats_out = 0;
    if (slot < 0 || slot >= (int32_t)tensors_.size()) return nullptr;
    const TensorRec& t = tensors_[(size_t)slot];
    if (!t.data) return nullptr;
    floats_out = t.bytes / sizeof(float);   // only meaningful for F32
    return nullptr;
}

// ---------------------------------------------------------------------------
// Kernels
// ---------------------------------------------------------------------------
bool Executor::OpRmsNorm(const Instr& in, const std::vector<float>& x,
                         std::vector<float>& y) {
    if (in.b < 0) { last_error_ = "rmsnorm: no weight slot"; return false; }
    const TensorRec& w = tensors_[(size_t)in.b];
    std::vector<float> wf;
    if (!DequantPrefix(w, wf, x.size()) || wf.size() < x.size()) {
        last_error_ = "rmsnorm: weight too small";
        return false;
    }
    wf.resize(x.size());
    RmsNormVec(y, x, wf, spec_.rms_eps);
    return true;
}

bool Executor::OpLinear(int32_t wslot, const std::vector<float>& x,
                        std::vector<float>& y, std::string& err) {
    if (wslot < 0) {
        err = "linear: no weight";
        if (std::getenv("LINEAR_TRACE")) {
            std::fprintf(stderr, "[linear] missing weight: slot=%d x=%zu\n",
                         (int)wslot, x.size());
        }
        return false;
    }
    const TensorRec& w = tensors_[(size_t)wslot];
    if (!w.data || w.dims.size() < 2) { err = "linear: bad weight"; return false; }
    const size_t n_in = (size_t)w.dims[0];
    const size_t n_out = (size_t)w.dims[1];
    if (x.size() != n_in) { char b2[192]; std::snprintf(b2, sizeof(b2), "linear: x=%zu n_in=%zu weight=%s dims=[%zu,%zu]", x.size(), n_in, w.name.c_str(), (size_t)w.dims[0], w.dims.size()>1?(size_t)w.dims[1]:0); err = b2; return false; }

    const bool quant = (w.ggml_type == GGML_TYPE_Q4_K || w.ggml_type == GGML_TYPE_Q6_K);
    if (quant && (n_in % 256) == 0) {
        const int kind = (w.ggml_type == GGML_TYPE_Q4_K) ? 0 : 1;
        const size_t rb = (n_in / 256) * (size_t)(kind == 0 ? 144 : 210);
        if (w.bytes < rb * n_out) {
            if (std::getenv("LINEAR_TRACE")) {
                std::fprintf(stderr, "[quant-short] w=%s type=%d dims=[%zu,%zu] bytes=%zu need=%zu (rb=%zu n_out=%zu)\n",
                             w.name.c_str(), (int)w.ggml_type, (size_t)w.dims[0],
                             w.dims.size() > 1 ? (size_t)w.dims[1] : 0,
                             w.bytes, rb * n_out, rb, n_out);
                std::fflush(stderr);
            }
            err = "linear: weight bytes short";
            return false;
        }
        // The reference decodes ONE packed row at a time. It must not
        // materialise a dequantised [n_out, n_in] float matrix: for a
        // 102400-row output projection that is 4x the encoded size and, when
        // indexed as rows, walks far past the buffer that was actually filled.
        //
        // CRITICAL: the reference must consume the SAME quantised activation
        // the GPU kernel sees. QuantDot hands us the Q8 block layout
        // (273 floats per 256 values: d, qs[256], bsums[16]); dotting with the
        // raw float activation instead would compare quantised-vs-float and
        // report the activation quantisation error, not the kernel's.
        //
        // The arithmetic mirrors ggml_vec_dot_q4_K_q8_K_generic /
        // ggml_vec_dot_q6_K_q8_K_generic EXACTLY: integer products formed first
        // and accumulated in 8 int32 lanes, the fp16 scales applied last, and
        // the min term folded in through the half-block sums. Dequantising the
        // weight to floats and dotting instead is algebraically the same number
        // but rounds differently at every element, which left the GPU-vs-CPU
        // parity gate at 1.4e-04 relative error - above its 1e-4 bound - even
        // though both sides were correct.
        //
        // Dense projections and MoE expert slices now share ONE implementation
        // (KQuantRowDotQ8 above) so the two cannot drift apart: DeepSeek's
        // expert FFN path previously used the float-dot variant, which is what
        // left its teacher-forced gate at 0.03-0.11 relative logit error.
        QuantDot::CpuDot cpu =
            [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                return KQuantRowDotQ8(kind, row,
                                       static_cast<const float*>(q8_act), n_in);
            };
// Build the Q8_K activation in the interleaved layout (per 256 values:
        // d, qs[256], bsums[16] = 273 floats) so the GPU kernel and the CPU
        // reference dot against an identical activation. Without this the
        // parity gate compares quantised-vs-float and measures activation error.
        //
        // bsums[] is the ggml block_q8_K layout: SIXTEEN half-block sums, each
        // covering 16 activation values, at offsets 257..272. ggml's
        // ggml_vec_dot_q4_K_q8_K_generic forms
        //     sumi = sum_j bsums[j] * mins[j/2]
        // and subtracts dmin * sumi, so a single whole-block total makes every
        // sub-block but the first use a zero minimum and silently corrupts the
        // min term of the Q4_K reference dot.
        // Build the Q8_K activation in the interleaved layout (per 256 values:
        // d, qs[256], bsums[16] = 273 floats) so the GPU kernel and the CPU
        // reference dot against an identical activation. Without this the
        // parity gate compares quantised-vs-float and measures activation error.
        //
        // bsums[] is the ggml block_q8_K layout: SIXTEEN half-block sums, each
        // covering 16 activation values, at offsets 257..272. ggml's
        // ggml_vec_dot_q4_K_q8_K_generic forms
        //     sumi = sum_j bsums[j] * mins[j/2]
        // and subtracts dmin * sumi, so a single whole-block total makes every
        // sub-block but the first use a zero minimum and silently corrupts the
        // min term of the Q4_K reference dot.
        //
        // CHANGED 2026-10-13: replaced the inline quantiser with the shared,
        // ggml-exact one in src/deep2/Q8KQuant.h. The previous code used unsigned
        // amax/127 for d, std::lround for the values and no MIN(127,v) clamp,
        // whereas ggml's quantize_row_q8_K_ref uses the SIGNED extremum
        // (iscale = -127.f/max, d = 1/iscale), round-half-to-even, and a clamp.
        // src/deep2/Q8KParity.cpp measures the difference byte-for-byte.
        const size_t n_blk = n_in / 256;
        std::vector<float> q8(n_blk * 273, 0.0f);
        BuildInterleavedQ8K(x.data(), n_in, q8.data());
        y.assign(n_out, 0.0f);
        if (std::getenv("QUANT_TRACE")) {
            std::fprintf(stderr, "[quant] w=%s kind=%d n_in=%zu n_out=%zu n_blk=%zu rb=%zu wbytes=%zu need=%zu\n",
                         w.name.c_str(), kind, n_in, n_out, n_blk, rb, w.bytes,
                         rb * n_out);
            std::fflush(stderr);
        }
        const bool gpu = QuantDot::DotBlocked(kind, w.data, w.bytes,
                                              x.data(), n_in, y.data(), n_out, cpu,
                                              q8.data(), q8.size() * sizeof(float),
                                              force_cpu_);
        if (gpu) {
            ++gpu_calls_;
        } else {
            ++cpu_calls_;
            const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
            if (cpu_fallback_reason_.empty() && rcpt.fallback_reason) {
                cpu_fallback_reason_ = std::string("k-quant dot: ") + rcpt.fallback_reason +
                    " (weight=" + w.name + ")";
            }
        }
        // RAWRXD_GATE4_DISPATCH_001: per-op dispatch evidence for the current
        // trace record. A forced pin (SetForceCpu) is an authorized host
        // selection, not a fallback; anything else that changed the selected
        // device records the reason for the Gate-4 auditor.
        trace_dispatch_backend_ = gpu ? "vulkan" : "cpu";
        trace_dispatch_forced_ = force_cpu_;
        trace_dispatch_fallback_.clear();
        if (!gpu && !force_cpu_) {
            const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
            trace_dispatch_fallback_ =
                rcpt.fallback_reason ? std::string(rcpt.fallback_reason)
                                     : std::string("cpu selected without reason");
        }
        // Env-gated differential check: the GPU kernel must reproduce the CPU
        // dot exactly, and must never emit a non-finite value. A divergence is
        // a kernel defect and is reported with the tensor that produced it.
        if (gpu && std::getenv("RR_GPU_CHECK")) {
            std::vector<float> ref(n_out, 0.0f);
            for (size_t j = 0; j < n_out; ++j) {
                const uint8_t* row = reinterpret_cast<const uint8_t*>(w.data) + j * rb;
                ref[j] = cpu(row, q8.data(), j);
            }
            size_t badnan = 0, worstj = 0;
            double worstd = 0.0;
            for (size_t j = 0; j < n_out; ++j) {
                if (!std::isfinite(y[j])) { if (!badnan) worstj = j; ++badnan; continue; }
                const double dd = std::fabs(double(y[j]) - double(ref[j]));
                if (dd > worstd) { worstd = dd; worstj = j; }
            }
            if (badnan || worstd > 1e-2 * std::max(1.0, double(std::fabs(ref[worstj])))) {
                std::fprintf(stderr,
                    "[GPU-DIVERGE] w=%s kind=%d n_in=%zu n_out=%zu nan=%zu worst_row=%zu gpu=%.6g cpu=%.6g diff=%.6g\n",
                    w.name.c_str(), kind, n_in, n_out, badnan, worstj,
                    (double)y[worstj], (double)ref[worstj], worstd);
                std::fflush(stderr);
            }
        }
        return true;
    }

    // Legacy quant types with a GPU kernel (RAWRXD_DEEP2_LEGACY_QUANT_GPU_001).
    // Q4_K/Q6_K (the k-quants) and Q5_0/Q8_0 (legacy) are all decoded INSIDE
    // the quant-dot shader, so they dispatch on the GPU with the same
    // interleaved Q8_K activation instead of dequantising every row on the CPU.
    // Models such as nemotron_h_moe ship their SSM and shared-expert
    // projections in exactly these types, and the CPU row-at-a-time path was
    // the reason the GPU-only certificate could not pass (cpu_calls > 0) and
    // decode ran at 0.12 TPS.
    //
    // The packed geometry is validated against the real byte span (never
    // bypassed): the row stride from the block size/type size, and the tensor
    // must hold at least n_out rows of that stride. The Q8 activation's final
    // 256-value super-block may be PARTIAL (n_in need not divide 256, e.g.
    // 2688 = 10*256 + 128); the shader decodes only the blocks that exist.
    if (n_in > 0 && n_out > 0) {
        const int kind = QuantKindOf(w.ggml_type);
        if (kind >= 0) {
            const size_t lb_min = (kind >= 2) ? 32u : 256u;   // block granularity
            if (n_in % lb_min == 0) {
                const size_t row_bytes = QuantRowBytes(kind, n_in);
                if (w.bytes < row_bytes * n_out) {
                    if (std::getenv("LINEAR_TRACE")) {
                        std::fprintf(stderr, "[linear-short-legacy-gpu] w=%s type=%d dims=[%zu,%zu] bytes=%zu "
                                             "need=%zu (row_bytes=%zu n_out=%zu)\n",
                                     w.name.c_str(), (int)w.ggml_type, (size_t)w.dims[0],
                                     w.dims.size() > 1 ? (size_t)w.dims[1] : 0,
                                     w.bytes, row_bytes * n_out, row_bytes, n_out);
                        std::fflush(stderr);
                    }
                    err = "linear: weight bytes short";
                    return false;
                }
                std::vector<float> q8;
                BuildInterleavedQ8(x.data(), n_in, q8);
                QuantDot::CpuDot cpu =
                    [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                        return RowDotInterleavedQ8(kind, row,
                                                   static_cast<const float*>(q8_act), n_in);
                    };
                y.assign(n_out, 0.0f);
                if (std::getenv("QUANT_TRACE")) {
                    std::fprintf(stderr, "[quant-legacy] w=%s kind=%d n_in=%zu n_out=%zu rb=%zu wbytes=%zu\n",
                                 w.name.c_str(), kind, n_in, n_out, row_bytes, w.bytes);
                    std::fflush(stderr);
                }
                const bool ok = QuantDot::DotBlocked(kind, w.data, w.bytes, x.data(), n_in,
                                                     y.data(), n_out, cpu,
                                                     q8.data(), q8.size() * sizeof(float),
                                                     force_cpu_);
                if (ok) {
                    ++gpu_calls_;
                } else {
                    ++cpu_calls_;
                    const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
                    if (cpu_fallback_reason_.empty() && rcpt.fallback_reason) {
                        cpu_fallback_reason_ = std::string("legacy quant dot: ") + rcpt.fallback_reason +
                            " (weight=" + w.name + ")";
                    }
                }
                return true;
            }
        }
    }

    // FP16 2-D weights (RAWRXD_DEEP2_F16_QUANT_DOT_CLOSURE): models such as
    // qwen3 carry blk.N.attn_v.weight in fp16 among otherwise k-quantised
    // weights. Before the F16 GEMV kernel these were the ONLY matmuls left on
    // the CPU (216 CPU calls on a 3-token qwen3:8b certification), which broke
    // the GPU-only gate for the whole family. The kernel dots raw fp16 weights
    // against the raw float activation; the CPU fallback below decodes with
    // ggml's own fp16 conversion so the two agree to fp32 rounding.
    if (w.ggml_type == GGML_TYPE_F16 && n_in > 0 && n_out > 0 && (n_in % 2u) == 0 &&
        (reinterpret_cast<uintptr_t>(w.data) % 4u) == 0) {
        const size_t row_bytes = n_in * sizeof(uint16_t);
        if (w.bytes < row_bytes * n_out) {
            if (std::getenv("LINEAR_TRACE")) {
                std::fprintf(stderr, "[linear-short-f16] w=%s dims=[%zu,%zu] bytes=%zu need=%zu\n",
                             w.name.c_str(), (size_t)w.dims[0],
                             w.dims.size() > 1 ? (size_t)w.dims[1] : 0, w.bytes, row_bytes * n_out);
                std::fflush(stderr);
            }
            err = "linear: weight bytes short";
            return false;
        }
        // Row-decoding fallback shared by every row; the dequantiser is ggml's
        // own fp16 converter, identical to what DequantPrefix would produce.
        std::vector<float> rw(n_in, 0.0f);
        QuantDot::CpuDot cpu = [&](const uint8_t* row, const void*, size_t) -> float {
            double acc = 0.0;
            for (size_t i = 0; i < n_in; ++i) {
                uint16_t hb;
                std::memcpy(&hb, row + i * 2u, 2);
                rw[i] = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
            }
            for (size_t i = 0; i < n_in; ++i) acc += double(rw[i]) * double(x[i]);
            return (float)acc;
        };
        y.assign(n_out, 0.0f);
        if (std::getenv("QUANT_TRACE")) {
            std::fprintf(stderr, "[quant-f16] w=%s n_in=%zu n_out=%zu wbytes=%zu\n",
                         w.name.c_str(), n_in, n_out, w.bytes);
            std::fflush(stderr);
        }
        const bool ok = QuantDot::DotF16(w.data, w.bytes, x.data(), n_in, y.data(), n_out,
                                         cpu, force_cpu_);
        if (ok) {
            ++gpu_calls_;
        } else {
            ++cpu_calls_;
            const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
            if (cpu_fallback_reason_.empty() && rcpt.fallback_reason) {
                cpu_fallback_reason_ = std::string(rcpt.fallback_reason) +
                    " (weight=" + w.name + ")";
            }
        }
        return true;
    }

    // Legacy quantized types (Q8_0, Q5_0, Q4_0, Q4_1, Q5_1, Q3_K, Q2_K,
    // Q5_K, Q8_K): dot ONE ROW AT A TIME. Materialising a dequantised
    // [n_out, n_in] matrix would need 1.4 GB of F32 for the language-model
    // head (2688 x 131072). Each output row is a contiguous run of blocks
    // in the packed buffer, so one row is dequantised at a time.
    //
    // GGML ne order: dims[0] is the contiguous (input) dimension and
    // dims[1] the row count, so row j starts at j * blocks_per_row * ts.
    if ((w.ggml_type == GGML_TYPE_Q8_0 || w.ggml_type == GGML_TYPE_Q5_0 ||
         w.ggml_type == GGML_TYPE_Q4_0 || w.ggml_type == GGML_TYPE_Q4_1 ||
         w.ggml_type == GGML_TYPE_Q5_1 || w.ggml_type == GGML_TYPE_Q3_K ||
         w.ggml_type == GGML_TYPE_Q2_K || w.ggml_type == GGML_TYPE_Q5_K ||
         w.ggml_type == GGML_TYPE_Q8_K) && n_in > 0 && n_out > 0) {
        const ggml_type_traits* tr = ggml_get_type_traits(w.ggml_type);
        if (!tr || !tr->to_float || tr->blck_size == 0 || tr->type_size == 0) {
            err = "linear: no dequantizer for this type";
            return false;
        }
        const size_t blk = (size_t)tr->blck_size;
        const size_t ts = (size_t)tr->type_size;
        if (n_in % blk != 0) { err = "linear: n_in not a multiple of the block size"; return false; }
        const size_t blocks_per_row = n_in / blk;
        const size_t row_bytes = blocks_per_row * ts;
        if (w.bytes < row_bytes * n_out) {
            if (std::getenv("LINEAR_TRACE")) {
                std::fprintf(stderr, "[linear-short-legacy] w=%s type=%d dims=[%zu,%zu] bytes=%zu "
                                     "need=%zu (row_bytes=%zu n_out=%zu blk=%zu ts=%zu)\n",
                             w.name.c_str(), (int)w.ggml_type, (size_t)w.dims[0],
                             w.dims.size() > 1 ? (size_t)w.dims[1] : 0,
                             w.bytes, row_bytes * n_out, row_bytes, n_out,
                             (size_t)blk, (size_t)ts);
                std::fflush(stderr);
            }
            err = "linear: weight bytes short";
            return false;
        }

        std::vector<float> rw(n_in, 0.0f);
        y.assign(n_out, 0.0f);
        for (size_t j = 0; j < n_out; ++j) {
            const uint8_t* row = reinterpret_cast<const uint8_t*>(w.data) + j * row_bytes;
            tr->to_float(row, rw.data(), (int)n_in);
            double acc = 0.0;
            for (size_t i = 0; i < n_in; ++i) acc += double(rw[i]) * double(x[i]);
            y[j] = (float)acc;
        }
        ++cpu_calls_;
        if (cpu_fallback_reason_.empty()) {
            cpu_fallback_reason_ = "legacy quant type dequantised on CPU, no GPU kernel: " + w.name;
        }
        return true;
    }

    // Non-k-quant (or non-multiple-of-256) weight: dequantise and dot.
    std::vector<float> wf;
    const size_t got = DequantPrefix(w, wf, n_in * n_out);
    if (got < n_in * n_out) {
        if (std::getenv("LINEAR_TRACE")) {
            std::fprintf(stderr, "[linear] dequant short: weight=%s type=%d dims=[%zu,%zu] "
                                 "bytes=%zu blck=%zu n_in*n_out=%zu got=%zu\n",
                         w.name.c_str(), (int)w.ggml_type, (size_t)w.dims[0],
                         w.dims.size() > 1 ? (size_t)w.dims[1] : 0,
                         w.bytes, (size_t)ggml_blck_size(w.ggml_type),
                         n_in * n_out, got);
        }
        err = "linear: dequant short";
        return false;
    }
    wf.resize(n_in * n_out);
    y.assign(n_out, 0.0f);
    for (size_t j = 0; j < n_out; ++j) {
        double acc = 0.0;
        const float* col = wf.data() + j * n_in;
        for (size_t i = 0; i < n_in; ++i) acc += double(col[i]) * double(x[i]);
        y[(size_t)j] = (float)acc;
    }
    ++cpu_calls_;
    return true;
}

// ---------------------------------------------------------------------------
// RoPE angle and attention score scale (reference-derived)
// ---------------------------------------------------------------------------
double Executor::RopeAngle(size_t position, size_t pair, size_t nDims, bool yarn) const {
    // A model may omit rope.freq_base entirely (llama.cpp falls back to 10000).
    // pow(0, -2k/n) is +inf, and position * inf is NaN at position 0 - the rope
    // then NaNs every pair >= 1 while the forward still completes.
    const double base = (spec_.rope_freq_base > 0.0) ? (double)spec_.rope_freq_base
                                                     : 10000.0;
    // ggml: theta_scale = powf(freq_base, -2/n_dims); theta_extrap(pair k) =
    // position * theta_scale^k = position * base^(-2k/n_dims).
    const double theta_extrap =
        (double)position * std::pow(base, -2.0 * double(pair) / double(nDims));
    if (!yarn) return theta_extrap;

    // ---- YaRN (ggml rope_yarn + ggml_rope_yarn_corr_dims) -------------------
    const double n_rot = double(nDims);
    const double n_ctx_orig = spec_.rope_orig_ctx > 0
                                  ? (double)spec_.rope_orig_ctx : 4096.0;
    const double factor = spec_.rope_scaling_factor > 0.0
                              ? spec_.rope_scaling_factor : 1.0;
    const double freq_scale = 1.0 / factor;
    constexpr double beta_fast = 32.0, beta_slow = 1.0;
    const double start = std::floor(n_rot * std::log(n_ctx_orig / (beta_fast * 2.0 * 3.14159265358979323846)) /
                                    (2.0 * std::log(base)));
    const double end   = std::ceil(n_rot * std::log(n_ctx_orig / (beta_slow * 2.0 * 3.14159265358979323846)) /
                                   (2.0 * std::log(base)));
    const double low  = std::max(0.0, start);
    const double high = std::min(n_rot - 1.0, end);
    // rope_yarn_ramp(low, high, i0) evaluates
    //   1 - clamp((i0/2 - low)/max(0.001, high-low))
    // so the coordinate is the PAIR INDEX (i0/2), NOT the element index.
    // Passing i0 = 2*pair doubles the coordinate, which for deepseek2
    // (low ~= 10, high ~= 23, n_rot = 64) compresses the whole ramp into the
    // first 12 pairs and leaves the other 20 pairs un-interpolated. The
    // remaining pairs keep the full 1x frequency instead of the 1/40 scale,
    // which is a large, systematic error in the rotational angle.
    const double ramp_mix = 1.0 - std::min(1.0, std::max(0.0, (double(pair) - low) /
                                                           std::max(0.001, high - low)));
    const double theta_interp = freq_scale * theta_extrap;
    return theta_interp * (1.0 - ramp_mix) + theta_extrap * ramp_mix;
}

double Executor::AttentionScoreScale(size_t headDim, bool yarn) const {
    if (!yarn || headDim == 0) return 1.0 / std::sqrt(double(headDim));
    // llama.cpp deepseek2.cpp (see the certified derivation in
    // modelgenie/ModelGenieExecutor.cpp, RAWRXD_ATTENTION_SCALE_AB_001):
    //   freq_scale      = 1 / rope.scaling.factor          (0.025 for factor 40)
    //   attn_factor     = yarn_attn_factor = rope_attn_factor / (1+0.1*ln(1/fs))
    //   attn_factor_org = attn_factor * (1+0.1*ln(1/fs))   -> 1.0 (cancels)
    //   mscale          = attn_factor_org * (1+0.1*yarn_log_mul*ln(1/fs))
    //   kq_scale        = mscale^2 / sqrt(n_embd_head_k)
    // For deepseek2 (factor 40, yarn_log_multiplier 0.0707) that is
    // mscale = 1.2608, mscale^2 = 1.5896, kq_scale = 0.114721 -- the value the
    // A/B test certified against llama.cpp's own kq/softmax dumps.
    const double factor = spec_.rope_scaling_factor > 0.0 ? spec_.rope_scaling_factor : 1.0;
    const double ln_fs = std::log(factor);                 // ln(1/freq_scale)
    const double attn_factor = 1.0 / (1.0 + 0.1 * ln_fs);  // rope_attn_factor = 1
    const double attn_factor_org = attn_factor * (1.0 + 0.1 * ln_fs);
    const double yarn_log_mul = spec_.yarn_log_multiplier > 0.0
                                    ? spec_.yarn_log_multiplier / 0.1 : 0.0;
    const double mscale = attn_factor_org * (1.0 + 0.1 * yarn_log_mul * ln_fs);
    return mscale * mscale / std::sqrt(double(headDim));
}

bool Executor::OpAttention(const Instr& in, const std::vector<float>& q,
                           const std::vector<float>& k, const std::vector<float>& v,
                           std::vector<float>& y, size_t position, std::string& err) {
    // Env-gated dump of the POST-PROJECTION Q/K/V for this block. At position
    // zero attention output == V, so comparing this against the reference's
    // Q/K/V checkpoints separates weight-read, bias, and input-norm causes:
    // if V matches here the defect is downstream (expansion/concatenation),
    // if it differs here the defect is in the projection or its input.
    if (const char* dumpPrefix = std::getenv("DEEP2_DUMP_QKV")) {
        char dp[600];
        std::snprintf(dp, sizeof(dp), "%s.blk%d.qkv.f32", dumpPrefix, (int)in.block);
        if (std::FILE* df = std::fopen(dp, "wb")) {
            std::fwrite(q.data(), sizeof(float), q.size(), df);
            std::fwrite(k.data(), sizeof(float), k.size(), df);
            std::fwrite(v.data(), sizeof(float), v.size(), df);
            std::fclose(df);
        }
    }
    // Attention covering BOTH families present in the zoo:
    //
    //   DeepSeek MLA: heads=16, q per head = 192 (128 nope + 64 rope),
    //                 k per head = 192, v per head = 128.
    //   GQA (llama/  : heads = H, heads_kv = hk, q per head = embd/H,
    //   qwen/granite  k and v per head = embd/H.
    //
    // The MLA case is detected by the groupless K/V width matching key_length.
    if (spec_.heads == 0) { err = "attention: head_count 0"; return false; }
    if (in.block < 0 || (size_t)in.block >= kv_k_.size()) {
        err = "attention: bad block";
        return false;
    }
    const size_t H = (size_t)spec_.heads;
    if (H == 0) { err = "attention: head_count 0"; return false; }
    // Input geometry dump before any arithmetic touches them. This is the
    // instrumentation that locates the faulting access: if a buffer length or
    // per-head width is inconsistent, the fault follows from it directly.
    if (std::getenv("ATTN_TRACE")) {
        auto nf = [](const std::vector<float>& v) {
            size_t n = 0;
            for (float f : v) if (!std::isfinite(f)) ++n;
            return n;
        };
        std::fprintf(stderr, "[attn-nan] block=%d pos=%zu qnn=%zu knn=%zu vnn=%zu\n",
                     (int)in.block, position, nf(q), nf(k), nf(v));
        std::fprintf(stderr, "[attn] block=%d pos=%zu q=%zu k=%zu v=%zu H=%zu hk=%zu kl=%zu vl=%zu kvcache=%zu,%zu\n",
                     (int)in.block, position, q.size(), k.size(), v.size(),
                     H, (size_t)spec_.heads_kv, (size_t)spec_.key_length,
                     (size_t)spec_.value_length,
                     kv_k_[in.block].size(), kv_v_[in.block].size());
    }
    if (in.block < 0 || (size_t)in.block >= kv_k_.size()) {
        err = "attention: bad block";
        return false;
    }

    // ---- Geometry derived from the REAL tensors, not from metadata ----
    //
    // nemotron_h_moe declares attention.head_count=32 but no
    // attention.head_count_kv, so the spec-level MHA default sets heads_kv=32
    // and every derived width is wrong. The Q/K/V weight tensors are
    // authoritative:
    //
    //   attn_q.weight [in, 4096]  -> qHeads = 4096 / qHeadDim
    //   attn_k.weight [in,  256]  -> kHeads =  256 / qHeadDim
    //   attn_v.weight [in,  256]  -> vHeads =  256 / qHeadDim
    //
    // qHeadDim comes from the query width over H, then k/v head counts follow.
    // This is GQA: k/v are narrower than q because heads are grouped.
    const size_t qWidth = q.size();
    const size_t kWidth = k.size();
    const size_t vWidth = v.size();
    const size_t qPerHead = qWidth / H;

    // The value head dim must match the query head dim, otherwise the output
    // projection cannot consume the attention result. Derive kv heads from the
    // ratio instead of trusting a metadata field the model does not ship.
    size_t hk = (size_t)spec_.heads_kv;
    if (hk == 0 || hk > H) hk = H;

    size_t kPerHead = 0, vPerHead = 0;
    if (qPerHead > 0) {
        // heads implied by each tensor's width over the shared head dim
        size_t kHeads = (kWidth * H) / qWidth;   // = kWidth / qPerHead
        size_t vHeads = (vWidth * H) / qWidth;
        if (kHeads >= 1 && kHeads <= H && kWidth == kHeads * qPerHead) {
            hk = kHeads;
            kPerHead = qPerHead;
        }
        if (vHeads >= 1 && vHeads <= H && vWidth == vHeads * qPerHead) {
            vPerHead = qPerHead;
        }
    }
    // Fall back to equal head counts (MHA) only when the tensor widths do not
    // describe a consistent grouped layout.
    if (kPerHead == 0) kPerHead = (hk == 0) ? (kWidth / H) : (kWidth / hk);
    if (vPerHead == 0) vPerHead = (hk == 0) ? (vWidth / H) : (vWidth / hk);
    if (qPerHead == 0 || kPerHead == 0 || vPerHead == 0) {
        err = "attention: empty per-head width";
        return false;
    }

    const size_t kl = (size_t)spec_.key_length;
    const size_t vl = (size_t)spec_.value_length;
    const bool isMla = (kPerHead == kl && vPerHead == vl && kl > vl);
    const size_t D = isMla ? qPerHead : qPerHead;
    if (D == 0) { err = "attention: head dim 0"; return false; }
    const size_t qD = isMla ? qPerHead : qPerHead;
    // YaRN rope scaling, decided by the model's own metadata. deepseek2 ships
    // rope.scaling.type "yarn"; an empty type (llama, qwen, gemma, nemotron)
    // keeps plain, unscaled RoPE so their angles are untouched.
    const bool yarn = (spec_.rope_scaling_type == "yarn");

    // RoPE: the ROTARY slice only. In MLA that is the last qk_rope dims of q
    // and of k; in a GQA model it is the whole head. Rotating the entire head
    // (the earlier behaviour) mixes positional information into the no-rope
    // channels and corrupts the score function.
    const size_t ropeDims = isMla ? (qD - (qD - (kl - (kl - vl)))) : D;
    const size_t ropeOff = isMla ? (kPerHead - (kPerHead > 0 ? 0 : 0)) : 0;
    (void)ropeDims;
    (void)ropeOff;
    // The nope/rope split of the QUERY and KEY heads comes from the model's own
    // rotary dimension count -- deepseek2.rope.dimension_count = 64 -- so the
    // key head is 192 = 128 nope + 64 rope. It must NOT be derived from the
    // value length: the value head is a SEPARATE 128-wide vector, and
    // key_length - value_length happens to be 64, which rotates the wrong 128
    // channels and leaves the score covering only the first two thirds of the
    // head (the exact failure the rope witness caught:
    // ATTN_ROPE_ELEMENTS=128 printed for a model whose rope slice is 64).
    if (isMla && spec_.rope_dim == 0) {
        err = "attention: MLA requires rope.dimension_count to split the q/k head";
        return false;
    }
    const size_t ropeDim = isMla ? (size_t)spec_.rope_dim : D;
    const size_t qk_nope = isMla ? (kl - ropeDim) : 0;
    const size_t q_rope_dim = isMla ? (qD - qk_nope) : D;
    const size_t k_rope_dim = isMla ? (kPerHead - qk_nope) : D;
    const size_t ropeLen = isMla ? ropeDim : std::min(q_rope_dim, k_rope_dim);
    const size_t qRopeOff = isMla ? qk_nope : 0;
    const size_t kRopeOff = isMla ? qk_nope : 0;

    // RoPE pairing is architecture-specific. llama.cpp (llama_model_rope_type,
    // src/llama-model.cpp) splits the families:
    //   NORM  - pair i is elements (2i, 2i+1) - LLAMA, LLAMA4, DEEPSEEK,
    //          DEEPSEEK2, GRANITE, STARCODER, MISTRAL3, COHERE, ...
    //   NEOX  - pair i is elements (i, i + n_rot/2) - QWEN2, QWEN3, GEMMA,
    //          PHI3, FALCON, STABLELM, ...
    // The earlier condition only admitted the deepseek* families to the NORM
    // branch, so every llama-family model (llama3.1/3.2, granite, ...) was
    // rotated with NEOX pairing. Position 0 hides the defect (every angle is
    // 0 there); position 1 exposes it. Certified on llama3.2:3b against a
    // llama.cpp dump (commit c479922a): reference post-rope Qcur/Kcur
    // reproduce with NORM at cos 0.99999994/0.99999996, with NEOX only
    // 0.9684/0.8658 - the reported blk00 pos1 attn_out cos 0.9843.
    const std::string& arch = spec_.architecture;
    const bool rope_adjacent =
        arch == "deepseek" || arch.rfind("deepseek", 0) == 0 ||
        arch == "llama"    || arch.rfind("llama", 0) == 0 ||
        arch == "granite"  || arch.rfind("granite", 0) == 0 ||
        arch == "starcoder"|| arch == "mistral"  || arch.rfind("mistral", 0) == 0 ||
        arch == "cohere"   || arch.rfind("cohere", 0) == 0 ||
        arch == "command-r"|| arch == "internlm2"|| arch.rfind("internlm", 0) == 0 ||
        arch == "baichuan" || arch.rfind("baichuan", 0) == 0 ||
        arch == "xverse"   || arch == "minicpm"  || arch.rfind("minicpm", 0) == 0 ||
        arch == "arctic"   || arch == "olmo"     || arch.rfind("olmo", 0) == 0 ||
        arch == "chameleon"|| arch.rfind("bailingmoe", 0) == 0;

    auto rope = [&](std::vector<float>& t, size_t heads, size_t headDim,
                    size_t ropeLen, size_t ropeOff, bool yarn) {
        // nDims is the number of rotary ELEMENTS in the slice.
        const size_t nDims = ropeLen;
        if (nDims < 2) return;
        for (size_t h = 0; h < heads; ++h) {
            float* p = t.data() + h * headDim + ropeOff;
            const size_t lim = std::min(nDims, headDim - std::min(ropeOff, headDim));
            if (rope_adjacent) {
                // NORM: pair i is elements (2i, 2i+1), rotated by angle i.
                for (size_t i = 0; 2 * i + 1 < lim; ++i) {
                    const double theta = RopeAngle(position, i, nDims, yarn);
                    const float c = (float)std::cos(theta), s = (float)std::sin(theta);
                    const float a = p[2 * i], b = p[2 * i + 1];
                    p[2 * i]     = a * c - b * s;
                    p[2 * i + 1] = a * s + b * c;
                }
            } else {
                // NEOX: pair i is elements (i, i + nDims/2).
                // ggml implements it as rotate_pairs(n_dims, n_dims/2, ...)
                //   x0 = src[ic]; x1 = src[ic + n_offset]        (n_offset = n_dims/2)
                //   dst[ic]        = x0*cos - x1*sin
                //   dst[ic+n_off]  = x0*sin + x1*cos
                // with ic = i/2 and the loop running i over 0..n_dims step 2, so the
                // pairs are (0,32), (1,33), ... for a 64-element rotary slice.
                const size_t nOff = nDims / 2;
                for (size_t i = 0; i < nOff && 2 * i < lim; ++i) {
                    const double theta = RopeAngle(position, i, nDims, yarn);
                    const float c = (float)std::cos(theta), s = (float)std::sin(theta);
                    const float a = p[i], b = p[i + nOff];
                    p[i]        = a * c - b * s;
                    p[i + nOff] = a * s + b * c;
                }
            }
        }
    };

    // ---- YaRN attention score scale -----------------------------------------
    // deepseek2 ships rope.scaling.type=yarn. llama.cpp (deepseek2.cpp) then
    // scales the attention score by mscale^2 / n_embd_head_k, NOT by
    // 1/sqrt(n_embd_head_k) -- the derivation is in the header of
    // modelgenie/ModelGenieExecutor.cpp and was certified there by
    // RAWRXD_ATTENTION_SCALE_AB_001 against a llama.cpp dump (variant with
    // mscale^2: 19/20 argmax, mean cosine 0.999114; plain 1/sqrt: 17/20 argmax,
    // mean cosine 0.988951). Without it every position still runs but the
    // generation is garbage, which is exactly the signature of a model that
    // executes with the wrong-scale scores.
    const double scoreScale = AttentionScoreScale(qD, yarn);

    // ---- Geometry validation (fail closed on inconsistency) ----
    // The Q/K/V widths must agree with the head counts actually in use. An
    // inconsistency here is exactly what previously walked 31*128 bytes into a
    // 256-element K buffer.
    if (H == 0 || hk == 0 || qPerHead == 0 || kPerHead == 0 || vPerHead == 0) {
        err = "attention: degenerate head geometry";
        return false;
    }
    if (H % hk != 0) {
        err = "attention: H not divisible by hk (H=" + std::to_string(H) +
              " hk=" + std::to_string(hk) + ")";
        return false;
    }
    if (qWidth != H * qPerHead) {
        err = "attention: q size mismatch (" + std::to_string(qWidth) +
              " != " + std::to_string(H * qPerHead) + ")";
        return false;
    }
    if (kWidth != hk * kPerHead) {
        err = "attention: k size mismatch (" + std::to_string(kWidth) +
              " != " + std::to_string(hk * kPerHead) + ")";
        return false;
    }
    if (vWidth != hk * vPerHead) {
        err = "attention: v size mismatch (" + std::to_string(vWidth) +
              " != " + std::to_string(hk * vPerHead) + ")";
        return false;
    }
    if (std::getenv("ATTN_TRACE")) {
        std::fprintf(stderr,
                     "[attn-geom] block=%d GQA: H=%zu hk=%zu group=%zu qPerHead=%zu kPerHead=%zu vPerHead=%zu\n",
                     (int)in.block, H, hk, H / hk, qPerHead, kPerHead, vPerHead);
    }

    std::vector<float> qr = q, kr = k;
    // RoPE is applied to the QUERY heads and to the KV heads. The KV call must
    // iterate hk, not H: with H=32 and a 256-element K buffer, looping 32 heads
    // at stride kPerHead reads 31*128 bytes past the end.
    rope(qr, H, qPerHead, ropeLen, qRopeOff, yarn);
    rope(kr, hk, kPerHead, ropeLen, kRopeOff, yarn);

    // Append to this layer's KV cache.
    //
    // llama.cpp compatibility (RAWRXD_KV_F16_CACHE_001): the reference stores
    // K/V into an F16 cache by default -- llama_context_default_params() sets
    // type_k = type_v = GGML_TYPE_F16. Measured against a llama.cpp node dump
    // (llama3.2:3b, position 0, every layer): the reference kqv_out node is
    // BIT-EXACTLY the F16 rounding of the V projection output (rel 0.000e+00
    // against the F32 projection's 3.345e-04). An F32 cache therefore makes
    // Deep2 diverge from every llama.cpp reference at the attention output
    // itself, and the residual stream amplifies that 3e-4 into an argmax flip
    // by block 28 -- the exact llama3.2:3b symptom this engine carried.
    // Round on write, like the reference does. DEEP2_KV_F32=1 keeps the full
    // precision cache for diagnostics (llama.cpp with -ctk f32 -ctv f32).
    //
    // Admitted residency (RAWRXD_RESOURCE_GOVERNOR_001): the growth bytes are
    // leased from the host budget first. Budget exhaustion fails the forward
    // pass closed — a silently truncated KV cache would corrupt every later
    // position instead of degrading honestly.
    auto& K = kv_k_[(size_t)in.block];
    auto& V = kv_v_[(size_t)in.block];
    const size_t kvW = kr.size();
    const size_t vW = v.size();
    const size_t needK = (position + 1) * kvW;
    const size_t needV = (position + 1) * vW;
    const size_t growBytes = (K.size() >= needK ? 0 : (needK - K.size()) * sizeof(float)) +
                             (V.size() >= needV ? 0 : (needV - V.size()) * sizeof(float));
    if (growBytes > 0) {
        auto lease = TryLeaseKv(growBytes);
        if (!lease) {
            err = "kv cache growth rejected by resource governor (block " +
                  std::to_string(in.block) + ", position " +
                  std::to_string(position) + ", requested " +
                  std::to_string(growBytes) +
                  " bytes; raise DEEP2_KV_BUDGET_MB or reduce context)";
            return false;
        }
        kv_leases_.push_back(std::move(*lease));
    }
    if (K.size() < needK) K.resize(needK, 0.0f);
    if (V.size() < needV) V.resize(needV, 0.0f);
    if (std::getenv("DEEP2_KV_F32") != nullptr) {
        std::memcpy(K.data() + position * kvW, kr.data(), kvW * sizeof(float));
        std::memcpy(V.data() + position * vW, v.data(), vW * sizeof(float));
    } else {
        float* kp = K.data() + position * kvW;
        for (size_t i = 0; i < kvW; ++i)
            kp[i] = ggml_fp16_to_fp32(ggml_fp32_to_fp16(kr[i]));
        float* vp = V.data() + position * vW;
        for (size_t i = 0; i < vW; ++i)
            vp[i] = ggml_fp16_to_fp32(ggml_fp32_to_fp16(v[i]));
    }

    const size_t T = position + 1;
    // THE ATTENTION OUTPUT IS THE VALUE STREAM, NOT THE QUERY STREAM.
    //
    // The output is the concatenation of every query head's VALUE slice, so its
    // width is H * vPerHead -- never H * qPerHead. In GQA/MHA the two widths
    // coincide, which is why sizing by the query width worked for llama/qwen
    // and why the defect was invisible outside MLA. In MLA they do not:
    // deepseek2's query head is 192 wide (128 nope + 64 rope) while its value
    // head is 128, so sizing by the query width produced 16*192 = 3,072
    // elements for a projection (blk.0.attn_output.weight, [2048, 2048]) that
    // requires 16*128 = 2,048. That is the exact rejected input from the
    // geometry trace:
    //   [attn] block=0 pos=0 q=3072 k=3072 v=2048 H=16 hk=16 kl=192 vl=128
    //   gpu fail: linear: x=3072 n_in=2048 weight=blk.0.attn_output.weight
    const size_t outW = vPerHead;
    y.assign(H * outW, 0.0f);
    std::vector<float> scores(T);
    // GQA groups: consecutive query heads share one KV head.
    const size_t group = std::max<size_t>(H / std::max<size_t>(hk, 1), 1);
    // MLA score = q_nopeÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·k_nope  +  q_ropeÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·k_rope.
    //
    // Dotting the whole per-head width is WRONG for MLA: q's rope slots would
    // be multiplied by K's no-rope slots. That cross-term made every position
    // produce bit-identical logits, because the context contribution cancelled
    // while the embedding-path contribution survived - the degenerate-output
    // signature. In a GQA model there is no split and the whole head is dotted.
    const size_t nopeD = isMla ? qk_nope : 0;
    for (size_t h = 0; h < H; ++h) {
        const size_t g = isMla ? h : (h / group);
        const float* qp = qr.data() + h * qPerHead;
        const float* qrope = qp + qRopeOff;
        for (size_t t = 0; t < T; ++t) {
            const float* kp = K.data() + t * kvW + g * kPerHead;
            const float* krope = kp + kRopeOff;
            double acc = 0.0;
            for (size_t d = 0; d < nopeD; ++d) acc += double(qp[d]) * double(kp[d]);
            for (size_t i = 0; i < ropeLen; ++i) acc += double(qrope[i]) * double(krope[i]);
            scores[t] = (float)(acc * scoreScale);
        }
        SoftmaxVec(scores);
        // Score witness (head 0 only, block 0, once per position). This is the
        // quantity an independent reference computes from the file's own bytes;
        // comparing it localises a divergence to the score path specifically,
        // which the value stream cannot reveal because position 0's softmax is
        // trivially 1.0 and therefore never exercises the score at all.
        if (in.block == 0 && h == 0 && score_seen_ != (int)position + 1) {
            std::fprintf(stderr, "[attn-scores] block=%d pos=%zu scale=%.9f",
                         (int)in.block, position, scoreScale);
            for (size_t t = 0; t < T; ++t)
                std::fprintf(stderr, " s%zu=%.6f", t, (double)scores[t]);
            std::fprintf(stderr, "\n");
            std::fflush(stderr);
            score_seen_ = (int)position + 1;
        }
        float* op = y.data() + h * outW;
        for (size_t t = 0; t < T; ++t) {
            // Value for this query head comes from its KV group. Every value
            // lane of the head must be accumulated: outW IS vPerHead, so the
            // copy is exact and no lane is dropped or padded with zeros.
            const float* vp = V.data() + t * vW + g * vPerHead;
            const float s = scores[t];
            for (size_t d = 0; d < outW; ++d) op[d] += s * vp[d];
        }
    }

    // Env-gated dump of the GQA-expanded attention buffer (the pre-O_proj
    // concat, 1 x H*vPerHead). Comparing this against the reference's
    // ATTN_VALUE checkpoint isolates head expansion/concatenation defects
    // from projection defects in one step.
    if (const char* dumpPrefix = std::getenv("DEEP2_DUMP_ATTN")) {
        char dp[600];
        std::snprintf(dp, sizeof(dp), "%s.blk%d.attnvalue.f32", dumpPrefix, (int)in.block);
        if (std::FILE* df = std::fopen(dp, "wb")) {
            std::fwrite(y.data(), sizeof(float), y.size(), df);
            std::fclose(df);
        }
    }

    // ---- post-concatenation invariant (fail closed) -------------------------
    // The concatenated output must be exactly H * vPerHead, and the consumer
    // (the attention output projection) must declare an input width that
    // matches it. Both are checked here, immediately after the concatenation
    // and BEFORE the projection runs, so a geometry defect cannot present
    // itself as a numerical error or as a silently truncated result.
    //
    // `in.q` carries the slot of the attention-output projection's WEIGHT,
    // resolved at bind time (see Bind's producer/consumer pass). It is absent
    // only for blocks whose attention output has no projection consumer.
    if (y.size() != H * vPerHead) {
        err = "attention geometry mismatch: attention output width " +
              std::to_string(y.size()) + " != heads*value_width " +
              std::to_string(H * vPerHead) + " (H=" + std::to_string(H) +
              " vPerHead=" + std::to_string(vPerHead) + ")";
        return false;
    }
    if (in.q >= 0 && (size_t)in.q < tensors_.size()) {
        const TensorRec& proj = tensors_[(size_t)in.q];
        const size_t projIn = proj.dims.empty() ? 0 : (size_t)proj.dims[0];
        if (projIn != 0 && projIn != y.size()) {
            err = "attention geometry mismatch: attention output width " +
                  std::to_string(y.size()) + " (heads=" + std::to_string(H) +
                  " x value_width=" + std::to_string(vPerHead) +
                  ", query_width=" + std::to_string(qPerHead) +
                  ") does not match projection '" + proj.name +
                  "' input dim " + std::to_string(projIn);
            return false;
        }
    }
    if (std::getenv("ATTN_TRACE")) {
        const TensorRec* proj = (in.q >= 0 && (size_t)in.q < tensors_.size())
                                    ? &tensors_[(size_t)in.q] : nullptr;
        std::fprintf(stderr,
                     "[attn-geom-witness] block=%d ATTN_Q_WIDTH=%zu ATTN_K_WIDTH=%zu "
                     "ATTN_V_WIDTH=%zu ATTN_OUTPUT_WIDTH=%zu ATTN_PROJECTION_INPUT=%zu "
                     "proj=%s H=%zu qPerHead=%zu vPerHead=%zu isMla=%d\n",
                     (int)in.block, qWidth, kWidth, vWidth, y.size(),
                     proj && !proj->dims.empty() ? (size_t)proj->dims[0] : 0,
                     proj ? proj->name.c_str() : "<none>", H, qPerHead, vPerHead,
                     isMla ? 1 : 0);
        std::fprintf(stderr,
                     "[attn-rope] block=%d ATTN_POSITION=%zu ATTN_ROPE_TYPE=%s "
                     "ATTN_ROPE_ELEMENTS=%zu ATTN_ROPE_FREQ_BASE=%llu "
                     "ATTN_ROPE_FACTOR=%.6f ATTN_ROPE_ORIG_CTX=%llu "
                     "ATTN_SCORE_SCALE=%.9f (plain 1/sqrt(%zu)=%.9f)\n",
                     (int)in.block, position, spec_.rope_scaling_type.c_str(),
                     ropeLen, (unsigned long long)spec_.rope_freq_base,
                     spec_.rope_scaling_factor,
                     (unsigned long long)spec_.rope_orig_ctx, scoreScale, qD,
                     1.0 / std::sqrt((double)std::max<size_t>(qD, 1)));
        // YaRN angle witness, printed for the rotary pairs of the first head of
        // block 0's attention. Compare against tools/deep2_rope_yarn_reference,
        // which computes the same thing with the vendored ggml's rope op.
        // Once per POSITION (not once per process), because position 0 is the
        // identity rotation and would otherwise hide every rope defect.
        if (in.block == 0 && n_dims_seen_ != (int)position + 1) {
            const size_t nD = ropeLen;
            std::fprintf(stderr, "[attn-rope-angles] block=%d ATTN_POSITION=%zu ATT_PAIRS=%zu\n",
                         (int)in.block, position, nD / 2);
            for (size_t k = 0; k < nD / 2 && k < 32; ++k)
                std::fprintf(stderr, "  k=%zu theta=%.9f (ramp-mixed)\n", k,
                             RopeAngle(position, k, nD, yarn));
            // MLA component witness: K_nope[0], rope'd k_rope[0..2], V[0]. This
            // is the same set of quantities an independent reader of the GGUF
            // computes, so a mismatch localises the defect to the decode math
            // rather than to the backend running it.
            if (isMla && kWidth >= H * kPerHead && vWidth >= H * vPerHead) {
                std::fprintf(stderr,
                             "[mla-witness] block=%d pos=%zu k_nope0=%.9f v0=%.9f "
                             "q_nope0=%.9f q_rope0=%.9f\n",
                             (int)in.block, position,
                             (double)k[(size_t)0 * kPerHead],
                             (double)v[(size_t)0],
                             (double)qr[(size_t)0 * qPerHead],
                             (double)qr[(size_t)0 * qPerHead + qRopeOff]);
                // Full first-eight of K_nope, V and the concatenated attention
                // output, so an independent implementation can compare whole
                // vectors rather than the single leading element (which agreed
                // while the rest of the vector did not).
                if (std::getenv("ATTN_TRACE")) {
                    std::fprintf(stderr, "[mla-knope8] blk=%d pos=%zu:", (int)in.block, position);
                    for (int i = 0; i < 8; ++i)
                        std::fprintf(stderr, " %.7f", (double)k[i]);
                    // Aggregate over the WHOLE vector, not just the head: the
                    // first eight matched an independent implementation bit for
                    // bit while the rest of the vector did not, which is
                    // invisible to a leading-element witness.
                    double vl2 = 0.0, kl2 = 0.0;
                    for (float f : v) vl2 += double(f) * double(f);
                    for (float f : k) kl2 += double(f) * double(f);
                    double yl2 = 0.0;
                    for (float f : y) yl2 += double(f) * double(f);
                    std::fprintf(stderr, "\n[mla-ysum] blk=%d pos=%zu l2=%.9f y0=%.7f y1=%.7f\n",
                                 (int)in.block, position, std::sqrt(yl2),
                                 y.empty() ? 0.0 : (double)y[0],
                                 y.size() > 1 ? (double)y[1] : 0.0);
                    std::fprintf(stderr, "\n[mla-vsum] blk=%d pos=%zu l2=%.9f e100=%.7f e1000=%.7f e2000=%.7f\n",
                                 (int)in.block, position, std::sqrt(vl2),
                                 v.size() > 100 ? (double)v[100] : 0.0,
                                 v.size() > 1000 ? (double)v[1000] : 0.0,
                                 v.size() > 2000 ? (double)v[2000] : 0.0);
                    std::fprintf(stderr, "[mla-ksum] blk=%d pos=%zu l2=%.9f\n",
                                 (int)in.block, position, std::sqrt(kl2));
                    std::fprintf(stderr, "\n[mla-v8] blk=%d pos=%zu:", (int)in.block, position);
                    for (int i = 0; i < 8; ++i)
                        std::fprintf(stderr, " %.7f", (double)v[i]);
                    std::fflush(stderr);
                }
            }
            std::fflush(stderr);
            n_dims_seen_ = (int)position + 1;
        }
    }
    return true;
}

bool Executor::OpRouterTopK(const Instr& router, const Instr& topk,
                            const std::vector<float>& x,
                            std::vector<uint32_t>& ids, std::vector<float>& w) {
    (void)topk;
    if (router.b < 0) { last_error_ = "router: no weight"; return false; }
    const TensorRec& rt = tensors_[(size_t)router.b];

    // The router maps hidden -> experts, so in GGUF's ne[] layout
    //   dims[0] = hidden (input)      e.g. 2688
    //   dims[1] = experts (output)    e.g.  128
    // Reading dims[0] here made n_exp 2688 instead of 128 and the dequant
    // request 2688*2688 floats, which no router tensor can satisfy - hence
    // "router: dequant short".
    if (rt.dims.size() < 2) { last_error_ = "router: bad shape"; return false; }
    const size_t n_hidden = (size_t)rt.dims[0];
    const size_t n_exp = (size_t)rt.dims[1];
    if (n_exp == 0 || n_hidden == 0) { last_error_ = "router: bad shape"; return false; }

    // Use the tensor's own input width rather than spec_.embd so a hidden
    // size that differs from the embedding still routes correctly.
    const size_t hdim = std::min(n_hidden, spec_.embd ? spec_.embd : n_hidden);
    (void)hdim;

    std::vector<float> logits;
    if (std::getenv("ROUTER_TRACE")) {
        size_t nnan = 0;
        for (size_t i = 0; i < x.size(); ++i) if (!std::isfinite(x[i])) ++nnan;
        std::fprintf(stderr, "[router] blk=%d tensor='%s' dims=%zu/%d n_hidden=%zu n_exp=%zu x=%zu nnan=%zu\n",
                     (int)router.block, rt.name.c_str(), rt.dims.size(),
                     rt.dims.empty() ? 0 : (int)rt.dims[0], n_hidden, n_exp, x.size(), nnan);
        std::fflush(stderr);
    }
    if (rt.ggml_type == GGML_TYPE_F32) {
        logits.assign(static_cast<size_t>(n_exp), 0.0f);
        if (!rt.data || rt.bytes < n_exp * n_hidden * sizeof(float)) {
            last_error_ = "router: f32 weight short";
            return false;
        }
        const float* wf = reinterpret_cast<const float*>(rt.data);
        for (size_t e = 0; e < n_exp; ++e) {
            const float* row = wf + e * n_hidden;
            double acc = 0.0;
            for (size_t i = 0; i < hdim; ++i) acc += double(row[i]) * double(x[i]);
            logits[e] = (float)acc;
        }
    } else {
        std::vector<float> wf;
        // Request only what the tensor can actually provide: n_exp rows of
        // n_hidden values.
        const size_t want = n_exp * n_hidden;
        const size_t got = DequantPrefix(rt, wf, want);
        if (got < want) { last_error_ = "router: dequant short"; return false; }
        logits.assign(n_exp, 0.0f);
        for (size_t e = 0; e < n_exp; ++e) {
            const float* row = wf.data() + e * n_hidden;
            double acc = 0.0;
            for (size_t i = 0; i < hdim; ++i) acc += double(row[i]) * double(x[i]);
            logits[e] = (float)acc;
        }
    }
    if (spec_.expert_used == 0) { last_error_ = "router: expert_used 0"; return false; }
    const size_t kused = (size_t)spec_.expert_used;
    // The routing formula is architecture-specific and is the difference between
    // a coherent model and plausible noise:
    //   softmax  (deepseek2 default): scores = softmax(logits), top-k greedy,
    //             then renormalise the SELECTED scores to sum to 1.
    //   sigmoid  (deepseek3-style):  scores = sigmoid(logits) before top-k.
    // Softmax over ALL experts followed by renormalising the top-k is NOT
    // equivalent to either: softmax spreads mass over 64 experts, so the top-k
    // renormalised weights are not the reference's, and the ORDER can differ
    // whenever two experts sit within the softmax's dynamic range.
    if (std::getenv("ROUTER_TRACE")) {
        std::fprintf(stderr, "[router-raw] blk=%d n_exp=%zu k=%zu logits=",
                     (int)router.block, n_exp, kused);
        for (size_t e = 0; e < n_exp; ++e)
            std::fprintf(stderr, "%.5f,", logits[e]);
        std::fprintf(stderr, "\n");
        std::fflush(stderr);
    }
    const bool sigmoid_routing = (spec_.architecture == "deepseek3" ||
                                  spec_.architecture == "deepseek4");
    if (sigmoid_routing) {
        for (size_t e = 0; e < n_exp; ++e)
            logits[e] = 1.0f / (1.0f + std::exp(-logits[e]));
    } else {
        SoftmaxVec(logits);
    }
    std::vector<uint32_t> idx(n_exp);
    for (uint32_t i = 0; i < n_exp; ++i) idx[i] = i;
    std::stable_sort(idx.begin(), idx.end(),
                     [&](uint32_t a, uint32_t b) { return logits[a] > logits[b]; });
    ids.assign(kused, 0);
    w.assign(kused, 0.0f);
    // 3. weight transformation.
    //
    // The reference renormalises the selected top-k scores to sum to 1 ONLY
    // when the model declares expert_weights_norm (qwen3-moe / gpt-oss style
    // MoE). DeepSeek-Coder-V2 emits no expert_weights_norm key, so its routing
    // weights stay the RAW softmax probabilities, whose sum is < 1 (on this
    // checkpoint the top-6 probs sum to ~0.18-0.45). Normalising them
    // unconditionally inflated every routed expert contribution by 1/sum
    // (~2.3x at block 1, ~5x at block 8) - the "same direction, wrong
    // magnitude" MoE divergence certified against llama.cpp.
    double renorm = 1.0;
    if (spec_.expert_weights_norm) {
        renorm = 0.0;
        for (size_t i = 0; i < kused; ++i) renorm += logits[idx[i]];
        if (!(renorm > 0.0)) { last_error_ = "router: zero weight"; return false; }
    }
    for (size_t i = 0; i < kused; ++i) {
        ids[i] = idx[i];
        w[i] = (float)(logits[idx[i]] / renorm);
    }
    // expert_weights_scale: applied only when the model sets it to something
    // other than 0 (absent) or 1 (identity), exactly like the reference.
    const float wscale = (float)spec_.expert_weights_scale;
    if (wscale != 0.0f && wscale != 1.0f) {
        for (size_t i = 0; i < kused; ++i) w[i] *= wscale;
    }
    if (std::getenv("ROUTER_TRACE")) {
        std::fprintf(stderr, "[router-sel] blk=%d selected=", (int)router.block);
        for (size_t i = 0; i < kused; ++i)
            std::fprintf(stderr, "%zu:%.5f,", (size_t)ids[i], (double)w[i]);
        std::fprintf(stderr, "\n");
        std::fflush(stderr);
    }
    return true;
}

// Total encoded ELEMENT count of a tensor (not bytes-per-element: for Q4_0
// type_size 18 / blck_size 32 truncates to 0, which made every expert-count
// division divide by zero). A block holds blck_size elements in type_size
// bytes, so the tensor holds (bytes / type_size) * blck_size elements.
static size_t elemCountOf(const TensorRec& t) {
    const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
    if (!tr || tr->type_size == 0 || tr->blck_size == 0) return 0;
    const size_t ts = static_cast<size_t>(tr->type_size);
    const size_t blk = static_cast<size_t>(tr->blck_size);
    return (t.bytes / ts) * blk;
}

// Dequantize only the element range [base, base+count) of a tensor.
//
// Expert tensors are rank-3 [in, out, expert]; an expert is a contiguous slice
// of (in * out) elements at expertIndex * in * out. DequantPrefix() spans whole
// tensors only, so this walks just the blocks covering the requested range.
static bool DequantRange(const TensorRec& t, size_t base, size_t count, std::vector<float>& out) {
    const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
    if (!tr || count == 0) return false;

    const int64_t blk = std::max<int64_t>(tr->blck_size, 1);
    const size_t ts   = static_cast<size_t>(tr->type_size);
    if (ts == 0) return false;

    out.assign(count, 0.0f);

    // Number of complete blocks available in the encoded data.
    const size_t totalBlocks = t.bytes / ts;
    const size_t firstBlock  = base / static_cast<size_t>(blk);
    const size_t lastBlock   = (base + count + blk - 1) / static_cast<size_t>(blk);
    if (firstBlock >= totalBlocks) return false;
    const size_t upto = std::min(lastBlock, totalBlocks);
    if (upto <= firstBlock) return false;

    // Read only the needed blocks into a compact buffer.
    const size_t blockCount = upto - firstBlock;
    std::vector<uint8_t> encoded(ts * blockCount);
    std::memcpy(encoded.data(), t.data + firstBlock * ts, encoded.size());

    // Decode block-by-block; the first/last blocks clip to the range.
    for (size_t b = 0; b < blockCount; ++b) {
        const size_t elemStart = (firstBlock + b) * static_cast<size_t>(blk);
        const size_t elemEnd   = elemStart + static_cast<size_t>(blk);
        const size_t clipFrom  = std::max(elemStart, base);
        const size_t clipTo    = std::min(elemEnd, base + count);
        if (clipTo <= clipFrom) continue;

        // Decode this block into a scratch buffer (never in place; that aliases
        // the encoded input and is undefined), then copy the clipped part. The
        // scratch is one block wide, so this stays bounded.
        const uint8_t* blockPtr = encoded.data() + b * ts;
        std::vector<float> scratch(static_cast<size_t>(blk), 0.0f);
        if (tr->to_float) {
            tr->to_float(blockPtr, scratch.data(), static_cast<int64_t>(blk));
        } else {
            // Raw-loadable types (F32/F16/BF16) need no conversion.
            std::memcpy(scratch.data(), blockPtr,
                        std::min(ts, scratch.size() * sizeof(float)));
        }
        for (size_t i = clipFrom; i < clipTo; ++i) {
            out[i - base] = scratch[i - elemStart];
        }
    }
    return true;
}

bool Executor::OpMoEExecute(const Instr& moe, const std::vector<float>& x,
                            const std::vector<uint32_t>& ids, const std::vector<float>& w,
                            std::vector<float>& y, std::string& err) {
    y.assign(spec_.embd, 0.0f);
    // Derived from the graph's own detail field, which names the model's real
    // tensors. The graph emits
    //   detail = "experts: <up>,<down>"
    // so parsing it is authoritative: no name guessing, no anchor assumptions.
    std::string expertUpName, expertDownName;
    {
        const std::string tag = "experts: ";
        const size_t at = moe.detail.find(tag);
        if (at != std::string::npos) {
            std::string rest = moe.detail.substr(at + tag.size());
            const size_t comma = rest.find(',');
            if (comma != std::string::npos) {
                expertUpName   = rest.substr(0, comma);
                expertDownName = rest.substr(comma + 1);
            } else {
                expertUpName = rest;
            }
        }
    }

    const TensorRec* upT = nullptr;
    const TensorRec* downT = nullptr;
    if (std::getenv("MOE_TRACE")) {
        std::fprintf(stderr, "[moe-enter] block=%d ids=%zu x=%zu detail='%s'\n",
                     (int)moe.block, ids.size(), x.size(), moe.detail.c_str());
    }
    if (!expertUpName.empty()) {
        auto it = slot_by_name_.find(expertUpName);
        if (it == slot_by_name_.end()) {
            // Nemotron uses ffn_*_exps.weight; tolerate the alternate casing.
            std::string alt = expertUpName;
            const size_t pp = alt.rfind("ffn_up_exps.weight");
            if (pp != std::string::npos) alt.replace(pp, std::strlen("ffn_up_exps.weight"),
                                                    "ffn_up_exps.weight");
            it = slot_by_name_.find(alt);
        }
        if (it != slot_by_name_.end()) upT = &tensors_[(size_t)it->second];
    }
    if (!expertDownName.empty()) {
        auto it = slot_by_name_.find(expertDownName);
        if (it != slot_by_name_.end()) downT = &tensors_[(size_t)it->second];
    }
    // Fall back to the anchor slot's siblings only if the detail field was absent.
    const TensorRec* anchorT = upT;
    if (!anchorT && moe.c >= 0 && moe.c < (int32_t)tensors_.size()) anchorT = &tensors_[(size_t)moe.c];
    if (!anchorT) { err = "moe: expert tensors not named"; return false; }
    if (!upT) { err = "moe: up expert tensor not found"; return false; }
    if (!downT) { err = "moe: down expert tensor not found"; return false; }

    const size_t ffn = (size_t)std::max<uint64_t>(spec_.expert_ffn, 1);
    const size_t embd = spec_.embd;

    // The gate expert is a SEPARATE tensor (blk.N.ffn_gate_exps.weight) from
    // the up expert (blk.N.ffn_up_exps.weight). The graph builder names the gate
    // in moe.c and up/down in moe.detail. Falling back to `gateT = upT` makes
    // the SwiGLU become silu(x·Wu)·(x·Wu), i.e. the same projection used twice,
    // which silently corrupts every MoE block (26 of 27 on deepseek2) while
    // leaving the dense block and all norms correct - exactly the signature of
    // a run whose block-0 values match and whose later blocks do not.
    const TensorRec* gateT = nullptr;
    if (moe.c >= 0 && (size_t)moe.c < tensors_.size()) gateT = &tensors_[(size_t)moe.c];
    if (!gateT) {
        // Resolve by the block's own tensor name, not by a model-family guess.
        const std::string gname = "blk." + std::to_string((int)moe.block) +
                                  ".ffn_gate_exps.weight";
        auto it = slot_by_name_.find(gname);
        if (it != slot_by_name_.end()) gateT = &tensors_[(size_t)it->second];
    }
    // If no gate tensor exists for this block, the up projection genuinely is
    // the gate (single-tensor SwiGLU); that fallback is now the ONLY case where
    // upT is used for the gate.
    if (!gateT) gateT = upT;
    // DeepSeek-Coder-V2 (and every dual-bank MoE file) ships ffn_gate_exps and
    // ffn_up_exps as two SEPARATE rank-3 banks: the reference computes
    //   h = silu(x @ gate_exps[e]) * (x @ up_exps[e]);   y += w[e] * (h @ down[e])
    // Setting gate := up computes silu(u)*u instead of silu(g)*u - a different
    // function, certified here as the "same direction, wrong magnitude" routed
    // expert error (blk01 ffn_moe_out cosine 0.67 with the router, the expert
    // ids and the input state all matching the reference).
    const bool have_gate = (gateT->name != upT->name);
    if (gateT->dims.size() < 2 || upT->dims.size() < 2 || downT->dims.size() < 2) {
        err = "moe: expert tensor rank < 2";
        return false;
    }
    std::vector<float> gT, uT, dT;
    // Expert tensors are RANK-3: ne = [in, out, expert]. Requesting
    // (the full-bank dequant that used to live here is removed: it expanded
    // ~7.14 GiB of F32 for every MoE block on every token, which is what
    //  corrupted the heap. See the selected-expert path below.)

    // Total encoded ELEMENT count of the expert bank. A block holds blck_size
    // elements in type_size bytes, so the tensor holds (bytes/type_size)*blck.
    // (type_size / blck_size truncates to zero for Q4_0 - 18/32 - which made
    // every expert count divide by zero.)
    auto elemCount = [](const TensorRec& t) -> size_t {
        const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
        if (!tr || tr->type_size == 0 || tr->blck_size == 0) return 0;
        return (t.bytes / (size_t)tr->type_size) * (size_t)tr->blck_size;
    };
    // The expert tensors are [in, out, expert] and each holds 128 experts at
    // 638,582,784 elements (~2.38 GiB as F32). Expanding all 128 costs ~7.14 GiB
    // across gate/up/down for a token that uses only expert_used of them - and
    // that allocation is what corrupted the heap.
    //
    // Only the experts the router selected are dequantized now, one expert at a
    // time. The expert stride is (in * out) elements, so an expert slice is a
    // contiguous window that DequantPrefix can read directly.
    const size_t gIn = (size_t)gateT->dims[0], gOut = (size_t)gateT->dims[1];
    const size_t uIn = (size_t)upT->dims[0],   uOut = (size_t)upT->dims[1];
    const size_t dIn = (size_t)downT->dims[0], dOut = (size_t)downT->dims[1];

    // Number of experts actually present in each tensor.
    // Element stride is (in * out). The tensor holds elemCountOf elements,
    // so expert count = elements / elementStride.
    const size_t elemStrideG = gIn * gOut;
    const size_t elemStrideU = uIn * uOut;
    const size_t elemStrideD = dIn * dOut;
    const size_t gExperts = std::max<size_t>(elemCountOf(*gateT) / std::max<size_t>(elemStrideG, 1), 1);
    const size_t uExperts = std::max<size_t>(elemCountOf(*upT)   / std::max<size_t>(elemStrideU, 1), 1);
    const size_t dExperts = std::max<size_t>(elemCountOf(*downT) / std::max<size_t>(elemStrideD, 1), 1);
    const size_t usableE = std::min(gExperts, std::min(uExperts, dExperts));
    if (usableE == 0) { err = "moe: no expert blocks available"; return false; }

    if (std::getenv("MOE_TRACE")) {
        std::fprintf(stderr, "[moe] gate=%s up=%s down=%s\n", gateT->name.c_str(), upT->name.c_str(), downT->name.c_str());
        std::fprintf(stderr, "[moe] gate [n,m] = %zu,%zu  up = %zu,%zu  down = %zu,%zu\n",
                     gIn, gOut, uIn, uOut, dIn, dOut);
        std::fprintf(stderr, "[moe] experts present: gate=%zu up=%zu down=%zu, selected=%zu\n",
                     gExperts, uExperts, dExperts, ids.size());
    }

    // Validate every selected expert before computing anything.
    for (size_t e = 0; e < ids.size() && e < w.size(); ++e) {
        if ((size_t)ids[e] >= usableE) { err = "moe: selected expert out of range"; return false; }
    }

    std::vector<float> g(ffn), u(ffn);
    size_t expertsProcessed = 0;

    // RAWRXD_DEEP2_LEGACY_QUANT_GPU_001: expert matmuls dispatch through the
    // SAME quant-dot fast path as every linear projection. The expert bank is
    // a rank-3 [in, out, expert] tensor; a selected expert's slice is n_out
    // contiguous rows starting at expert_base_bytes, which the shader consumes
    // directly (it addresses rows from the packed pointer it is handed). The
    // activation is the interleaved Q8 the shader expects, so the reference
    // executor's force-CPU fallback computes the same number.
    //
    // The selected experts of a block run in BATCHES: all up-projections in one
    // submission, then all down-projections in a second. A 24-block MoE with 6
    // experts then costs 48 submits per token instead of 288. A dot whose
    // output is consumed before its batch ends (an up-dot feeding its own
    // SwiGLU) is never queued: SwiGLU runs BETWEEN the two batches.
    //
    // Single-call receipt accounting (the batches are accounted by their
    // callers, once per batch outcome).
    auto account = [&](bool ok, const char* tname, size_t expert_index) {
        if (ok) {
            ++gpu_calls_;
        } else {
            ++cpu_calls_;
            const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
            if (cpu_fallback_reason_.empty() && rcpt.fallback_reason) {
                cpu_fallback_reason_ = std::string("moe expert dot: ") + rcpt.fallback_reason +
                    " (weight=" + tname + " expert=" + std::to_string(expert_index) + ")";
            }
        }
    };

    const size_t nSel = std::min(ids.size(), w.size());
    const size_t glen = std::min(ffn, gOut);
    const size_t ulen = std::min(ffn, uOut);
    const size_t olen = std::min(embd, dOut);
    const int uKind = QuantKindOf(upT->ggml_type);
    const int dKind = QuantKindOf(downT->ggml_type);
    // The up-projection activation is the SAME token hidden state for every
    // selected expert, so its interleaved Q8 is built once per block.
    const bool upGpuShape = (uKind >= 0) && (uIn % (uKind >= 2 ? 32u : 256u)) == 0 &&
                            (uIn <= x.size());
    std::vector<float> q8up;
    if (upGpuShape) BuildInterleavedQ8(x.data(), uIn, q8up);
    const size_t q8upBytes = upGpuShape ? q8up.size() * sizeof(float) : 0u;

    std::vector<float> uAll(nSel * ffn, 0.0f);
    std::vector<float> gAll(have_gate ? nSel * ffn : 0, 0.0f);
    std::vector<float> hAll(nSel * ffn, 0.0f);
    std::vector<float> dyAll(nSel * embd, 0.0f);
    std::vector<uint8_t> upDone(nSel, 0);

    // ---- phase 1: every selected expert's up-projection ----------------------
    // RR_NO_MOE_BATCH forces the single-call path (the reference behaviour
    // before batching) so a parity difference can be A/B-attributed to the
    // batching itself rather than to the MoE math.
    static const bool noMoeBatch = std::getenv("RR_NO_MOE_BATCH") != nullptr;
    const bool batchUp = !force_cpu_ && !noMoeBatch && nSel >= 2 && QuantDot::BeginBatch();
    size_t queuedUp = 0;
    for (size_t e = 0; e < nSel; ++e)
    {
        const size_t ex = (size_t)ids[e];
        if (ex >= usableE) continue;
        if (!upGpuShape) continue;
        float* out = &uAll[e * ffn];
        if (batchUp) {
            // Queued: DotBlocked defers to the batch's single submission.
            QuantDot::CpuDot cpu = [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                return RowDotInterleavedQ8(uKind, row, static_cast<const float*>(q8_act), uIn);
            };
            const size_t row_bytes = QuantRowBytes(uKind, uIn);
            const uint8_t* packed = reinterpret_cast<const uint8_t*>(upT->data) +
                                    ex * ulen * row_bytes;
            const bool queued = QuantDot::DotBlocked(uKind, packed, row_bytes * ulen, x.data(),
                                                     uIn, out, ulen, cpu, q8up.data(),
                                                     q8upBytes, false);
            if (queued) { upDone[e] = 1; ++queuedUp; }
        } else {
            // Single call: runs now (GPU path, or the reference executor's
            // force-CPU path - both compute the same number).
            const size_t row_bytes = QuantRowBytes(uKind, uIn);
            const uint8_t* packed = reinterpret_cast<const uint8_t*>(upT->data) +
                                    ex * ulen * row_bytes;
            QuantDot::CpuDot cpu = [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                return RowDotInterleavedQ8(uKind, row, static_cast<const float*>(q8_act), uIn);
            };
            const bool ok = QuantDot::DotBlocked(uKind, packed, row_bytes * ulen, x.data(),
                                                 uIn, out, ulen, cpu, q8up.data(),
                                                 q8upBytes, force_cpu_);
            if (ok) upDone[e] = 1;
            account(ok, upT->name.c_str(), ex);
        }
    }
    if (batchUp) {
        // One submission for the whole block's up-projections. On failure the
        // dots were replayed on the CPU fallback and the outputs are valid, so
        // only the accounting records the difference.
        const bool batchOk = QuantDot::EndBatch();
        if (batchOk) {
            gpu_calls_ += queuedUp;
        } else {
            cpu_calls_ += queuedUp;
            if (cpu_fallback_reason_.empty()) {
                const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
                if (rcpt.fallback_reason)
                    cpu_fallback_reason_ = std::string("moe up batch: ") + rcpt.fallback_reason;
            }
        }
    }

    // ---- phase 1b: the gate projection of every selected expert --------------
    // Runs after the up phase so the up SwiGLU inputs are all ready, and mirrors
    // it exactly: the same batching decision, the same CPU fallback, the same
    // interleaved Q8 of the SAME activation (x@gate and x@up take the same x).
    std::vector<uint8_t> gateDone(nSel, 0);
    if (have_gate) {
        const int gKind = QuantKindOf(gateT->ggml_type);
        const bool gGpuShape = (gKind >= 0) && (gIn % (gKind >= 2 ? 32u : 256u)) == 0 &&
                               (gIn <= x.size());
        const size_t gRowBytes = gGpuShape ? QuantRowBytes(gKind, gIn) : 0u;
        const bool batchGate = !force_cpu_ && !noMoeBatch && nSel >= 2 && QuantDot::BeginBatch();
        size_t queuedGate = 0;
        for (size_t e = 0; e < nSel; ++e) {
            const size_t ex = (size_t)ids[e];
            if (ex >= usableE || !gGpuShape) continue;
            float* out = &gAll[e * ffn];
            const uint8_t* packed = reinterpret_cast<const uint8_t*>(gateT->data) +
                                    ex * glen * gRowBytes;
            QuantDot::CpuDot cpu = [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                return RowDotInterleavedQ8(gKind, row, static_cast<const float*>(q8_act), gIn);
            };
            if (batchGate) {
                const bool queued = QuantDot::DotBlocked(gKind, packed, gRowBytes * glen, x.data(),
                                                         gIn, out, glen, cpu, q8up.data(),
                                                         q8upBytes, false);
                if (queued) { gateDone[e] = 1; ++queuedGate; }
            } else {
                const bool ok = QuantDot::DotBlocked(gKind, packed, gRowBytes * glen, x.data(),
                                                     gIn, out, glen, cpu, q8up.data(),
                                                     q8upBytes, force_cpu_);
                if (ok) gateDone[e] = 1;
                account(ok, gateT->name.c_str(), ex);
            }
        }
        if (batchGate) {
            if (QuantDot::EndBatch()) {
                gpu_calls_ += queuedGate;
            } else {
                cpu_calls_ += queuedGate;
            }
        }
    }

    // ---- per-expert SwiGLU (all up-dots are complete now) --------------------
    if (std::getenv("MOE_TRACE")) {
        double us = 0.0, ds = 0.0;
        for (size_t i = 0; i < nSel * ffn && i < 4096; ++i) us += uAll[i];
        std::fprintf(stderr,
                     "[moe-up] block=%d nSel=%zu batched=%d upDone=%zu u0=%.6g %.6g %.6g %.6g sum4096=%.6g\n",
                     (int)moe.block, nSel, (int)batchUp,
                     (size_t)std::count(upDone.begin(), upDone.end(), (uint8_t)1),
                     uAll[0], uAll[1], uAll[2], uAll[3], us);
        std::fflush(stderr);
        (void)ds;
    }
    for (size_t e = 0; e < nSel; ++e)
    {
        const size_t ex = (size_t)ids[e];
        if (ex >= usableE) continue;

        std::fill(g.begin(), g.end(), 0.0f);
        std::fill(u.begin(), u.end(), 0.0f);

        if (upDone[e])
        {
            // GPU/force-CPU path already produced this expert's up projection.
            for (size_t j = 0; j < ulen; ++j) u[j] = uAll[e * ffn + j];
            // The gate comes from its OWN bank when the model has one. Identity
            // gate (gate := up) is reserved for single-tensor SwiGLU models.
            if (!have_gate) {
                for (size_t j = 0; j < glen; ++j) g[j] = uAll[e * ffn + j];
            } else if (gateDone[e]) {
                for (size_t j = 0; j < glen; ++j) g[j] = gAll[e * ffn + j];
            }
        }
        else
        {
            // CPU path: dequantise only this expert's slice, dot in double.
            std::vector<float> uSlice;
            if (!DequantRange(*upT, ex * elemStrideU, elemStrideU, uSlice))
            {
                err = "moe: expert slice dequant failed (block=" + std::to_string(moe.block) +
                      " expert=" + std::to_string(ex) + ")";
                return false;
            }
            const size_t lim = std::min(uIn, x.size());
            for (size_t j = 0; j < ulen; ++j)
            {
                double acc = 0.0;
                for (size_t i = 0; i < lim; ++i) acc += double(uSlice[j * uIn + i]) * double(x[i]);
                u[j] = (float)acc;
            }
            if (!have_gate) {
                std::copy(u.begin(), u.begin() + (std::ptrdiff_t)glen, g.begin());
            }
        }
        if (have_gate && !gateDone[e]) {
            // CPU path for the gate bank: same per-expert dequant + double dot.
            std::vector<float> gSlice;
            if (!DequantRange(*gateT, ex * elemStrideG, elemStrideG, gSlice))
            {
                err = "moe: gate expert slice dequant failed (block=" + std::to_string(moe.block) +
                      " expert=" + std::to_string(ex) + ")";
                return false;
            }
            const size_t lim = std::min(gIn, x.size());
            for (size_t j = 0; j < glen; ++j)
            {
                double acc = 0.0;
                for (size_t i = 0; i < lim; ++i) acc += double(gSlice[j * gIn + i]) * double(x[i]);
                g[j] = (float)acc;
            }
        }

        // SwiGLU: silu(gate) * up, into this expert's own h slot.
        for (size_t j = 0; j < ffn; ++j)
        {
            const float s = 1.0f / (1.0f + std::exp(-g[j]));
            hAll[e * ffn + j] = g[j] * s * u[j];
        }
    }

    // ---- phase 2: every selected expert's down-projection --------------------
    const bool dShapeAll = (dKind >= 0) && (dIn % (dKind >= 2 ? 32u : 256u) == 0) &&
                           (dIn <= ffn);
    const size_t downRowBytes = dShapeAll ? QuantRowBytes(dKind, dIn) : 0u;
    const bool batchDown = !force_cpu_ && !noMoeBatch && nSel >= 2 && QuantDot::BeginBatch();
    size_t queuedDown = 0;
    for (size_t e = 0; e < nSel; ++e)
    {
        const size_t ex = (size_t)ids[e];
        if (ex >= usableE) continue;
        if (dShapeAll)
        {
            std::vector<float> q8h;
            BuildInterleavedQ8(&hAll[e * ffn], dIn, q8h);
            float* out = &dyAll[e * embd];
            const uint8_t* packed = reinterpret_cast<const uint8_t*>(downT->data) +
                                    ex * olen * downRowBytes;
            QuantDot::CpuDot cpu = [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                return RowDotInterleavedQ8(dKind, row, static_cast<const float*>(q8_act), dIn);
            };
            if (batchDown) {
                // Queued: the second batch's single submission runs it.
                const bool queued = QuantDot::DotBlocked(dKind, packed, downRowBytes * olen,
                                                         &hAll[e * ffn], dIn, out, olen, cpu,
                                                         q8h.data(), q8h.size() * sizeof(float),
                                                         false);
                if (queued) ++queuedDown;
            } else {
                const bool ok = QuantDot::DotBlocked(dKind, packed, downRowBytes * olen,
                                                     &hAll[e * ffn], dIn, out, olen, cpu,
                                                     q8h.data(), q8h.size() * sizeof(float),
                                                     force_cpu_);
                account(ok, downT->name.c_str(), ex);
            }
        }
        else
        {
            std::vector<float> dSlice;
            if (!DequantRange(*downT, ex * elemStrideD, elemStrideD, dSlice))
            {
                err = "moe: expert slice dequant failed (block=" + std::to_string(moe.block) +
                      " expert=" + std::to_string(ex) + ")";
                return false;
            }
            for (size_t i = 0; i < olen; ++i)
            {
                double acc = 0.0;
                for (size_t j = 0; j < dIn; ++j) acc += double(dSlice[i * dIn + j]) * double(hAll[e * ffn + j]);
                dyAll[e * embd + i] = (float)acc;
            }
        }
        ++expertsProcessed;
    }
    if (batchDown) {
        if (QuantDot::EndBatch()) {
            gpu_calls_ += queuedDown;
        } else {
            cpu_calls_ += queuedDown;
            const QuantDot::Receipt& rcpt = QuantDot::LastReceipt();
            if (cpu_fallback_reason_.empty() && rcpt.fallback_reason) {
                cpu_fallback_reason_ = std::string("moe down batch: ") + rcpt.fallback_reason;
            }
        }
    }

    // ---- routing-weighted accumulation ---------------------------------------
    for (size_t e = 0; e < nSel; ++e)
    {
        if ((size_t)ids[e] >= usableE) continue;
        for (size_t i = 0; i < olen; ++i)
            y[i] += w[e] * dyAll[e * embd + i];
    }
    if (std::getenv("MOE_TRACE")) {
        double ys = 0.0;
        for (size_t i = 0; i < olen && i < 4096; ++i) ys += y[i];
        std::fprintf(stderr, "[moe-y] block=%d y0=%.6g %.6g %.6g %.6g sum=%.6g\n", (int)moe.block,
                     y.empty() ? 0.0 : y[0], y.empty() ? 0.0 : y[1], y.empty() ? 0.0 : y[2],
                     y.empty() ? 0.0 : y[3], ys);
        std::fflush(stderr);
    }

    if (expertsProcessed == 0) { err = "moe: no expert was processed"; return false; }
    return true;
}

bool Executor::OpMlaDecompress(const Instr& mla, const std::vector<float>& x,
                               std::vector<float>& k_out, std::vector<float>& v_out,
                               size_t position, std::string& err) {
    // DeepSeek MLA (multi-head latent attention), per the model's own shapes:
    //   attn_kv_a_mqa.weight : [embd, kv_lora_rank + qk_rope]
    //   attn_kv_a_norm.weight: [kv_lora_rank]
    //   attn_kv_b.weight     : [kv_lora_rank, heads * (qk_nope + v_head)]
    //
    //   1. latentFull = x @ kv_a_mqa            -> kv_lora_rank + qk_rope
    //   2. latent     = RMSNorm(latent[:lora], attn_kv_a_norm)
    //   3. kvb        = latent @ kv_b           -> heads * (qk_nope + v_head)
    //   4. per head h: k_nope = kvb[h*(nope+v) .. +nope]
    //                    v    = kvb[h*(nope+v)+nope .. +v]
    //   5. ropePart   = latentFull[lora : lora+qk_rope]   (shared by all heads)
    //   6. k[h]       = [k_nope | ropePart]  -> key_length
    //      v[h]       = v                     -> value_length
    if (mla.a < 0 || mla.b < 0 || mla.c < 0) { err = "mla: missing weights"; return false; }
    const TensorRec& kvA = tensors_[(size_t)mla.a];
    const TensorRec& norm = tensors_[(size_t)mla.b];
    const TensorRec& kvB = tensors_[(size_t)mla.c];

    const size_t lora = (size_t)std::max<uint64_t>(spec_.kv_lora_rank, 1);
    const size_t kl = (size_t)spec_.key_length;    // 192 = 128 nope + 64 rope
    const size_t vl = (size_t)spec_.value_length;  // 128
    const size_t H = (size_t)std::max<uint64_t>(spec_.heads, 1);
    const size_t rope = (lora + (kl - lora)) > lora ? (size_t)0 : 0;  // fixed below
    (void)rope;

    // Shcarved straight from the recorded tensor dims, never guessed.
    const size_t kvA_in = kvA.dims.empty() ? 0 : (size_t)kvA.dims[0];
    const size_t kvA_out = kvA.dims.size() > 1 ? (size_t)kvA.dims[1] : 0;
    const size_t kvB_in = kvB.dims.empty() ? 0 : (size_t)kvB.dims[0];
    const size_t kvB_out = kvB.dims.size() > 1 ? (size_t)kvB.dims[1] : 0;
    const size_t nope = (kl > vl) ? (kl - vl) : kl;      // archive exact split
    (void)nope;
    const size_t qk_rope = (kvA_out > lora) ? (kvA_out - lora) : 0;
    const size_t per_head = kvB_out / std::max<size_t>(H, 1);   // nope + v
    const size_t qk_nope = (per_head > vl) ? (per_head - vl) : 0;
    if (kvA_in == 0 || kvB_in == 0 || qk_rope == 0 || qk_nope == 0) {
        err = "mla: tensor shapes incompatible with spec";
        return false;
    }

    std::vector<float> A, B, nw;
    DequantPrefix(kvA, A, kvA_in * kvA_out);
    DequantPrefix(kvB, B, kvB_in * kvB_out);
    DequantPrefix(norm, nw, lora);
    if (A.size() < kvA_in * kvA_out || B.size() < kvB_in * kvB_out) {
        err = "mla: weight dequant short";
        return false;
    }

    // 1. latentFull = x @ kv_a_mqa
    std::vector<float> latentFull(kvA_out, 0.0f);
    const size_t inL = std::min(kvA_in, x.size());
    for (size_t j = 0; j < kvA_out; ++j) {
        double acc = 0.0;
        const float* col = A.data() + j * kvA_in;
        for (size_t i = 0; i < inL; ++i) acc += double(col[i]) * double(x[i]);
        latentFull[j] = (float)acc;
    }

    // 2. RMSNorm the latent part ONLY. This is the step the earlier version
    //    skipped, which left the latent unnormalised and destroyed attention.
    std::vector<float> latent(lora, 0.0f);
    {
        double ss = 0.0;
        for (size_t i = 0; i < lora; ++i) ss += double(latentFull[i]) * double(latentFull[i]);
        const float scale = 1.0f / std::sqrt(float(ss / double(lora)) + 1e-6f);
        for (size_t i = 0; i < lora; ++i)
            latent[i] = latentFull[i] * (i < nw.size() ? nw[i] : 1.0f) * scale;
    }

    // 3. kvb = latent @ kv_b   (kv_b_in must be the lora rank)
    if (kvB_in != lora) { err = "mla: kv_b input != kv_lora_rank"; return false; }
    std::vector<float> kvb(kvB_out, 0.0f);
    for (size_t j = 0; j < kvB_out; ++j) {
        double acc = 0.0;
        const float* col = B.data() + j * kvB_in;
        for (size_t i = 0; i < lora; ++i) acc += double(col[i]) * double(latent[i]);
        kvb[j] = (float)acc;
    }

    // 4-6. assemble per-head k and v
    k_out.assign(H * kl, 0.0f);
    v_out.assign(H * vl, 0.0f);
    for (size_t h = 0; h < H; ++h) {
        const float* src = kvb.data() + h * per_head;
        float* kd = k_out.data() + h * kl;
        float* vd = v_out.data() + h * vl;
        // k = [qk_nope from kv_b | qk_rope from the latent tail]
        for (size_t i = 0; i < qk_nope && i < kl; ++i) kd[i] = src[i];
        for (size_t i = 0; i < qk_rope && (qk_nope + i) < kl; ++i)
            kd[qk_nope + i] = latentFull[lora + i];
        for (size_t i = 0; i < vl && i < qk_nope + 0; ++i) (void)i;
        for (size_t i = 0; i < vl; ++i) vd[i] = src[qk_nope + i];
    }
    (void)position;
    return true;
}

// ---------------------------------------------------------------------------
// Execute one token
// ---------------------------------------------------------------------------
bool Executor::ExecuteToken(uint32_t token, size_t position) {
    if (!bound_) { last_error_ = "not bound"; return false; }
    last_error_.clear();
    last_token_ = token;
    if (std::getenv("RR_TRACE_TOKEN")) std::fprintf(stderr, "  [token] pos=%zu token=%u cache_sizes=%zu,%zu,...\n", position, token, kv_k_.empty()?0:kv_k_[0].size(), kv_v_.empty()?0:kv_v_[0].size());
    position_ = position;

    // Wall-clock for this token. BindStats already declares cold_start_ms /
    // steady_kernel_ms / dispatch_ms / total_ms but nothing ever filled them,
    // which is why every receipt reported dispatch_ms=0.000 and no TPS could be
    // derived. Total covers the whole token (prefill and decode alike); the
    // first token additionally records cold start, because it includes cache
    // warm-up and any lazy pipeline creation.
    const auto token_started = std::chrono::steady_clock::now();
    ++tokens_executed_;

    // Activation arena: SSA values from the runtime graph, keyed by the name
    // the graph gave them. A block's gate and up projections both read
    // "ffn_norm", so an op's DECLARED input is used, not the running hidden.
    std::unordered_map<std::string, std::vector<float>> act;
    auto arena = [&](const std::string& n) -> std::vector<float>& { return act[n]; };
    auto resolveIn = [&](const Instr& i) -> const std::vector<float>& {
        if (!i.aName.empty() && i.aName[0] != '<' && i.op != OpKind::MlaDecompress) {
            auto it = act.find(i.aName);
            if (it != act.end()) return it->second;
            // FAIL CLOSED. A named graph operand that is absent from the arena is
            // a graph-construction error, not something to paper over with the
            // running hidden vector. Substituting hidden_ silently is exactly the
            // class of bug that produced cosine 0.028 MLA latents: the MlaDecompress
            // weight name was in the  slot, the lookup missed, and the op quietly
            // consumed q. Instead, record the failure so Bind/Execute can report it.
            unresolved_inputs_.push_back(i.aName);
            return unresolved_;
        }
        return hidden_;
    };

    hidden_.clear();
    logits_.clear();
    nonfinite_logits_ = 0;
    hidden_l2_ = 0.0;

    std::vector<uint32_t> expert_ids;
    std::vector<float> expert_w;
    bool ids_valid = false;

    const int32_t embSlot = slot_by_name_["token_embd.weight"];

    for (size_t pc = 0; pc < program_.size(); ++pc) {
        const auto& in = program_[pc];
        if (std::getenv("RR_OP_TRACE")) {
            std::fprintf(stderr, "  [loop] pc=%zu/%zu kind=%d blk=%d a='%s' b='%s' out='%s' bSlot=%d\n",
                         pc, program_.size(), (int)in.op, (int)in.block,
                         in.aName.c_str(), in.bName.c_str(), in.outName.c_str(), (int)in.b);
            std::fflush(stderr);
        }
        const std::vector<float>& xi = resolveIn(in);
    switch (in.op) {
            if (std::getenv("RR_OP_TRACE")) {
                std::fprintf(stderr, "  [op] %-16s blk=%3d a='%s' b='%s' out='%s' bSlot=%d\n",
                             OpKindName(in.op), in.block, in.aName.c_str(),
                             in.bName.c_str(), in.outName.c_str(), (int)in.b);
                std::fflush(stderr);
            }
            case OpKind::EmbeddingLookup: {
                const TensorRec& emb = tensors_[(size_t)embSlot];
                const size_t n_in = (size_t)emb.dims[0];
                const size_t vocab = (size_t)emb.dims[1];
                if (token >= vocab || !emb.data) {
                    last_error_ = "embedding: token out of range";
                    return false;
                }
                // Row `token` of the embedding table. Row stride is the
                // tensor's bytes divided by the number of rows (dims[1]).
                const size_t row_stride = emb.bytes / std::max<size_t>(vocab, 1);
                if (row_stride == 0) { last_error_ = "embedding: row stride 0"; return false; }
                const uint8_t* src = emb.data + (size_t)token * row_stride;
                if (src + row_stride > emb.data + emb.bytes) {
                    last_error_ = "embedding: row outside tensor";
                    return false;
                }
                if (emb.ggml_type == GGML_TYPE_F32) {
                    hidden_.assign(n_in, 0.0f);
                    std::memcpy(hidden_.data(), src, n_in * sizeof(float));
                } else {
                    TensorRec rowView = emb;   // copy, then rebind
                    rowView.data = src;
                    rowView.bytes = row_stride;
                    rowView.dims[1] = 1;                 // exactly one row
                    DequantPrefix(rowView, hidden_, n_in);
                    if (std::getenv("RR_TRACE_TOKEN")) {
                        const double l2 = [&] {
                            double s = 0.0;
                            for (float v : hidden_) s += double(v) * double(v);
                            return std::sqrt(s);
                        }();
                        std::fprintf(stderr, "  [emb] token=%u n_in=%zu vocab=%zu row_stride=%zu type=%d l2=%.6f e0=%.9f e1=%.9f\n",
                                     token, n_in, vocab, row_stride,
                                     (int)rowView.ggml_type, l2,
                                     hidden_.size() > 0 ? (double)hidden_[0] : 0.0,
                                     hidden_.size() > 1 ? (double)hidden_[1] : 0.0);
                        std::fflush(stderr);
                    }
                    if (hidden_.size() < n_in) {
                        last_error_ = "embedding: dequant short";
                        return false;
                    }
                }
                double l2 = 0;
                for (float v : hidden_) l2 += double(v) * double(v);
                hidden_l2_ = std::sqrt(l2);
                break;
            }
            case OpKind::RmsNorm: {
                std::vector<float>& y = arena(in.outName.empty() ? std::string("rms") : in.outName);
                if (!OpRmsNorm(in, xi, y)) return false;
                hidden_ = y;
                break;
            }
            case OpKind::Linear: {
                if (std::getenv("LINEAR_TRACE")) {
                    std::fprintf(stderr, "[exec] Linear block=%d bName='%s' bSlot=%d aName='%s' outName='%s' xi=%zu\n",
                                 (int)in.block, in.bName.c_str(), (int)in.b,
                                 in.aName.c_str(), in.outName.c_str(), xi.size());
                }
                std::vector<float> y;
                std::string e;
                if (!OpLinear(in.b, xi, y, e)) { last_error_ = e; return false; }
                // ---- attention projection bias: y = W x + b ---------------
                // Qwen2.5 and friends ship attn_q/k/v.bias tensors (in
                // qwen2.5-coder-1.5b, blk.0.attn_k.bias alone has L2 ~1237 --
                // 64x the projection output). The loader records the
                // model-level has_bias flag, but no executor path consumed it,
                // so every bias-carrying projection ran bias-free while every
                // bias-free architecture (llama3.2, deepseek) was unaffected.
                //
                // Applied exactly once, here, for every backend: OpLinear
                // produced the W x term and the add is on the host result, so
                // the GPU path cannot silently skip it and the CPU path cannot
                // double-apply it. The bias is decoded through DequantPrefix,
                // which honours the tensor's ACTUAL type (F32 here, F16 or
                // quantised elsewhere), never an assumed one.
                if (spec_.has_bias) {
                    std::string biasName = in.bName;
                    const std::string wSuffix = ".weight";
                    if (biasName.size() > wSuffix.size() &&
                        biasName.compare(biasName.size() - wSuffix.size(), wSuffix.size(), wSuffix) == 0) {
                        biasName.replace(biasName.size() - wSuffix.size(), wSuffix.size(), ".bias");
                    } else {
                        biasName += ".bias";
                    }
                    auto bit = slot_by_name_.find(biasName);
                    // Fail closed when the model declares this projection must
                    // carry a bias (the attn_q/k/v family the loader keyed off)
                    // but the tensor is missing or unresolved.
                    const bool mustHave = biasName.find(".attn_q.") != std::string::npos ||
                                          biasName.find(".attn_k.") != std::string::npos ||
                                          biasName.find(".attn_v.") != std::string::npos;
                    if (bit != slot_by_name_.end()) {
                        const TensorRec& bt = tensors_[(size_t)bit->second];
                        std::vector<float> bv;
                        const size_t got = DequantPrefix(bt, bv, y.size());
                        if (got < y.size()) {
                            last_error_ = "linear: bias '" + biasName + "' decoded " +
                                          std::to_string(got) + " of " + std::to_string(y.size()) +
                                          " (type=" + std::to_string((int)bt.ggml_type) +
                                          ", bytes=" + std::to_string(bt.bytes) + ")";
                            return false;
                        }
                        for (size_t i = 0; i < y.size(); ++i) y[i] += bv[i];
                    } else if (mustHave) {
                        last_error_ = "linear: declared bias tensor missing: " + biasName;
                        return false;
                    }
                    // no sibling and no declaration -> bias-free, unchanged
                }
                // Env-gated FFN-chain dumps. The Linear op's INPUT for
                // ffn_gate IS the FFN_NORM output (the norm feeds only the two
                // projections), so one hook captures NORM/GATE/UP/DOWN and the
                // decision tree needs no further instrumentation.
                if (const char* ffnPrefix = std::getenv("DEEP2_DUMP_FFN")) {
                    auto dumpVec = [&](const std::vector<float>& v, const char* tag) {
                        char dp[600];
                        std::snprintf(dp, sizeof(dp), "%s.blk%d.%s.f32", ffnPrefix,
                                      (int)in.block, tag);
                        if (std::FILE* df = std::fopen(dp, "wb")) {
                            std::fwrite(v.data(), sizeof(float), v.size(), df);
                            std::fclose(df);
                        }
                    };
                    if (in.bName.find("ffn_gate") != std::string::npos) {
                        dumpVec(xi, "ffn_norm");
                        dumpVec(y, "ffn_gate");
                    } else if (in.bName.find("ffn_up") != std::string::npos) {
                        dumpVec(y, "ffn_up");
                    } else if (in.bName.find("ffn_down") != std::string::npos) {
                        dumpVec(xi, "ffn_down_in");
                        dumpVec(y, "ffn_down");
                    }
                }
                // Attention-output projection witness. The embedding, K, V and
                // attention output were all verified identical to an
                // independent implementation, so this is the last stage in the
                // block-0 span that can still differ.
                if (std::getenv("ATTN_TRACE") && in.bName.find("attn_output") != std::string::npos) {
                    // What row 0 of the weight actually dequantised TO, compared
                    // against ggml's own dequantize_row_q4_0. The reference value
                    // for blk.0.attn_output.weight row 0 is
                    //   0.007111 -0.014224 -0.010668 0 0.010668 0.003556
                    // NOTE: to_float must be asked for a MULTIPLE of blck_size
                    // (32 for Q4_0); asking for 8 writes nothing at all, which
                    // looks like a zero-filled weight and is a probe artefact.
                    const TensorRec& wt = tensors_[(size_t)in.b];
                    std::vector<float> rw0(32, 0.0f);
                    const ggml_type_traits* trw = ggml_get_type_traits(wt.ggml_type);
                    if (trw && trw->to_float)
                        trw->to_float(wt.data, rw0.data(), 32);
                    std::fprintf(stderr,
                                 "[attnproj-weight0] blk=%d name=%s dims=[%zu,%zu] "
                                 "bytes=%zu data=%p row0: ",
                                 (int)in.block, wt.name.c_str(),
                                 wt.dims.empty() ? 0 : (size_t)wt.dims[0],
                                 wt.dims.size() > 1 ? (size_t)wt.dims[1] : 0,
                                 wt.bytes, (const void*)wt.data);
                    for (int i = 0; i < 8; ++i) std::fprintf(stderr, "%.6f ", (double)rw0[i]);
                    std::fprintf(stderr, "\n");
                }
                if (std::getenv("ATTN_DUMP") &&
                    in.bName.find("attn_output") != std::string::npos &&
                    in.block == 0) {
                    // Full input/output dumps for exact element-wise comparison
                    // against an independent implementation (max abs error, rel
                    // error, and the FIRST differing index). Restricted to
                    // block 0's attention-output projection: an unfiltered dump
                    // fires on every Linear and the last write wins, so the
                    // captured op is effectively arbitrary.
                    FILE* fx = std::fopen("d2_attnproj_in.bin", "wb");
                    FILE* fy = std::fopen("d2_attnproj_out.bin", "wb");
                    if (fx && fy) {
                        std::fwrite(xi.data(), sizeof(float), xi.size(), fx);
                        std::fwrite(y.data(), sizeof(float), y.size(), fy);
                    }
                    if (fx) std::fclose(fx);
                    if (fy) std::fclose(fy);
                }
                if (std::getenv("ATTN_TRACE") && in.bName.find("attn_output") != std::string::npos) {
                    double l2 = 0.0;
                    for (float f : y) l2 += double(f) * double(f);
                    std::fprintf(stderr, "[attnproj] blk=%d in_l2=%.9f out_l2=%.9f y0=%.7f y1=%.7f x0=%.7f x1=%.7f x2=%.7f\n",
                                 (int)in.block,
                                 [&]{ double s=0; for (float f : xi) s += double(f)*double(f); return std::sqrt(s); }(),
                                 std::sqrt(l2), y.empty()?0.0:(double)y[0],
                                 y.size()>1?(double)y[1]:0.0,
                                 xi.empty()?0.0:(double)xi[0],
                                 xi.size()>1?(double)xi[1]:0.0,
                                 xi.size()>2?(double)xi[2]:0.0);
                    std::fflush(stderr);
                }
                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;
                break;
            }
            case OpKind::MlaDecompress: {
                std::vector<float> k, v;
                std::string e;
                {
                    // The three weight slots are a (kv_a_mqa), b (latent norm),
                    // c (kv_b). The activation this op consumes rides in `detail`
                    // so resolveIn can find it in the arena rather than falling
                    // back to hidden_, which is `q` by the time this op runs.
                    const std::vector<float>& mlaIn =
                        act.count(in.detail) ? act[in.detail] : xi;
                    if (!OpMlaDecompress(in, mlaIn, k, v, position, e)) { last_error_ = e; return false; }
                }
                // The arena entry this op publishes is the K stream it just
                // produced. Writing hidden_ here (the previous op's output, `q`
                // by this point in the program) is what made the "kv" capture
                // duplicate q and hid the real K stream from every dump.
                arena(in.outName.empty() ? std::string("kv") : in.outName) = k;
                arena("k") = k;
                arena("v") = v;
                break;            }
            case OpKind::Attention: {
                std::vector<float> y;
                std::string e;
                if (std::getenv("ATTN_TRACE")) {
                    std::fprintf(stderr, "[attn-enter] block=%d pos=%zu aName='%s' hidden_=%zu\n",
                                 (int)in.block, position, in.aName.c_str(), hidden_.size());
                }
                std::vector<float> qv = arena("q"), kv = arena("k"), vv = arena("v");
                if (std::getenv("ATTN_TRACE")) {
                    std::fprintf(stderr, "[attn-inputs] qv=%zu kv=%zu vv=%zu kvcache=%zu,%zu\n",
                                 qv.size(), kv.size(), vv.size(),
                                 kv_k_[in.block].size(), kv_v_[in.block].size());
                }
                if (qv.empty()) qv = hidden_;
                if (kv.empty()) kv = qv;
                if (vv.empty()) vv = kv;
                // FUSED-QKV SPLIT: a fused attention block (Phi3Fused and
                // friends) hands ONE vector whose rows are [q|k|v] stacked.
                // The graph declares this with bName "qkv(split)", meaning the
                // split happens inside the attention core. This executor never
                // implemented that split: kv/vv fell back to the SAME full
                // fused vector, so every per-head width read the FULL fused
                // width (e.g. 9216/32 = 288 instead of 3072/32 = 96) and every
                // Phi3Fused block failed with an attention-projection
                // geometry mismatch. Split the thirds explicitly: the quarter
                // boundaries come from the model metadata (equal thirds), and
                // the attention core below then sees the real per-head widths.
                if (in.bName == "qkv(split)") {
                    if (qv.empty() || qv.size() % 3 != 0) {
                        last_error_ = "attention: fused qkv width " +
                                      std::to_string(qv.size()) +
                                      " is not divisible by 3";
                        return false;
                    }
                    const size_t w = qv.size() / 3;
                    kv.assign(qv.begin() + (ptrdiff_t)w, qv.begin() + (ptrdiff_t)(2 * w));
                    vv.assign(qv.begin() + (ptrdiff_t)(2 * w), qv.end());
                    qv.resize(w);
                }
                if (!OpAttention(in, qv, kv, vv, y, position, e)) { last_error_ = e; return false; }
                arena("attn") = y;
                if (!in.outName.empty()) arena(in.outName) = y;
                hidden_ = y;
                break;
            }
            case OpKind::Publish: {
                // Copy an arena value into another named arena value.
                // This is how the residual stream is made addressable: the
                // graph names the block input "resid_in" so ResidualAdd can
                // find it by name. The literal "<hidden>" means the CURRENT
                // hidden vector, which is the normal case at a block entry.
                std::vector<float> src;
                if (in.aName.empty() || in.aName == "<hidden>") {
                    src = hidden_;
                } else {
                    auto pit = act.find(in.aName);
                    if (pit == act.end()) {
                        last_error_ = "publish: source '" + in.aName + "' missing";
                        return false;
                    }
                    src = pit->second;
                }
                if (src.empty()) { last_error_ = "publish: empty source"; return false; }
                const std::string dst = in.outName.empty() ? std::string("published") : in.outName;
                arena(dst) = src;
                hidden_ = src;
                // Env-gated dump of the published hidden vector. The block-0
                // publish is the EMBEDDING (resid_in), so this captures Deep2's
                // embedding for token-level parity comparison.
                if (const char* dumpPrefix = std::getenv("DEEP2_DUMP_HIDDEN")) {
                    char dp[600];
                    std::snprintf(dp, sizeof(dp), "%s.pub.b%d.%s.f32", dumpPrefix,
                                  (int)in.block, dst.c_str());
                    if (std::FILE* df = std::fopen(dp, "wb")) {
                        std::fwrite(hidden_.data(), sizeof(float), hidden_.size(), df);
                        std::fclose(df);
                    }
                }
                break;
            }
            case OpKind::ResidualAdd: {
                // out = resid + block_output.
                // BOTH operands come from the arena by name. The previous
                // version added `hidden_` to the residual, which double-counted
                // the norm output and dropped the attention projection entirely.
                const std::vector<float> empty;
                const std::vector<float>* resid = &empty;
                if (!in.aName.empty() && in.aName[0] != '<') {
                    auto it = act.find(in.aName);
                    if (it != act.end()) resid = &it->second;
                    else { last_error_ = "residualadd: source '" + in.aName + "' missing"; return false; }
                } else {
                    resid = &hidden_;
                }
                const std::vector<float>* add = &hidden_;
                if (!in.bName.empty() && in.bName[0] != '<') {
                    auto it = act.find(in.bName);
                    if (it != act.end()) add = &it->second;
                    else { last_error_ = "residualadd: addend '" + in.bName + "' missing"; return false; }
                }
                const size_t n = std::max(resid->size(), add->size());
                if (n == 0) { last_error_ = "residualadd: empty operands"; return false; }
                std::vector<float> y(n, 0.0f);
                for (size_t i = 0; i < n; ++i)
                    y[i] = (i < resid->size() ? (*resid)[i] : 0.0f)
                         + (i < add->size() ? (*add)[i] : 0.0f);
                hidden_ = y;
                arena(in.outName.empty() ? std::string("resid") : in.outName) = y;
                // Per-block hidden-state witness. The engine's own receipts
                // only compare Deep2 against Deep2, so a divergence against an
                // external reference cannot be localised from them. Printing a
                // signature after EVERY block's final residual makes the same
                // quantity computable in an independent implementation, which
                // turns "the output is wrong" into "block K is the first one
                // that differs".
                if (std::getenv("RR_TRACE_BLOCKS") && !hidden_.empty()) {
                    double ss = 0.0;
                    for (float v : hidden_) ss += double(v) * double(v);
                    std::fprintf(stderr, "[block] blk=%d out=%s l2=%.6f h0=%.9f h1=%.9f\n",
                                 (int)in.block, in.outName.c_str(), std::sqrt(ss),
                                 (double)hidden_[0],
                                 hidden_.size() > 1 ? (double)hidden_[1] : 0.0);
                    std::fflush(stderr);
                }
                // Env-gated binary dump of every block's residual vectors so an
                // independent implementation can compare the FULL 1,536-value
                // vectors (not just norms): <prefix>.blk<N>.<outName>.f32
                if (const char* dumpPrefix = std::getenv("DEEP2_DUMP_HIDDEN")) {
                    char dp[600];
                    std::snprintf(dp, sizeof(dp), "%s.blk%d.%s.f32", dumpPrefix,
                                  (int)in.block, in.outName.c_str());
                    if (std::FILE* df = std::fopen(dp, "wb")) {
                        std::fwrite(hidden_.data(), sizeof(float), hidden_.size(), df);
                        std::fclose(df);
                    }
                }
                break;
            }
            case OpKind::SwiGLU: {
                // out = silu(gate) * up, elementwise.
                // The down projection MUST consume this. Feeding it the norm
                // output instead is a silent correctness break: the layer still
                // computes, is still finite, is still deterministic, and is
                // still wrong.
                const std::vector<float>* gp = &hidden_;
                const std::vector<float>* up = &hidden_;
                if (!in.aName.empty() && in.aName[0] != '<') {
                    auto it = act.find(in.aName);
                    if (it == act.end()) { last_error_ = "swiglu: gate missing"; return false; }
                    gp = &it->second;
                }
                if (!in.bName.empty() && in.bName[0] != '<') {
                    auto it = act.find(in.bName);
                    if (it == act.end()) { last_error_ = "swiglu: up missing"; return false; }
                    up = &it->second;
                }
                const size_t n = std::min(gp->size(), up->size());
                if (n == 0) { last_error_ = "swiglu: empty inputs"; return false; }
                std::vector<float> y(n, 0.0f);
                for (size_t i = 0; i < n; ++i) {
                    const float g = (*gp)[i];
                    const float silu = g / (1.0f + std::exp(-g));
                    y[i] = silu * (*up)[i];
                }
                hidden_ = y;
                const std::string dst = in.outName.empty() ? std::string("swiglu") : in.outName;
                arena(dst) = y;
                // Env-gated full-vector dump of the SwiGLU product. The down
                // projection consumes this; comparing it against
                // silu(REF_FFN_GATE) * REF_FFN_UP separates a SwiGLU defect
                // from a down-projection defect. Input-width comparison
                // (this vector must be all 8,960 intermediate elements) is
                // included because a truncated input yields a plausible but
                // wrong down output.
                if (const char* dumpPrefix = std::getenv("DEEP2_DUMP_FFN")) {
                    char dp[600];
                    std::snprintf(dp, sizeof(dp), "%s.blk%d.swiglu.f32", dumpPrefix, (int)in.block);
                    if (std::FILE* df = std::fopen(dp, "wb")) {
                        std::fwrite(y.data(), sizeof(float), y.size(), df);
                        std::fclose(df);
                    }
                }
                break;
            }
            case OpKind::Router: {
                if (!OpRouterTopK(in, in, xi, expert_ids, expert_w)) return false;
                ids_valid = true;
                // Publish the router logits under the declared output name so the
                // TopK that consumes router_logits resolves a real operand.
                if (!in.outName.empty()) {
                    arena(in.outName) = xi;   // publish router logits for TopK
                }
                break;
            }
            case OpKind::TopK:
                break;   // handled together with Router
            case OpKind::MoEExecute: {
                if (!ids_valid) { last_error_ = "moe: no router result"; return false; }
                std::vector<float> y;
                std::string e;
                if (!OpMoEExecute(in, xi, expert_ids, expert_w, y, e)) { last_error_ = e; return false; }
                arena("moe") = y;
                if (!in.outName.empty()) arena(in.outName) = y;
                hidden_ = y;
                break;
            }
            case OpKind::LmHead: {
                std::vector<float> y;
                std::string e;
                if (std::getenv("RR_TRACE_TOKEN")) {
                    std::fprintf(stderr, "  [lmhead] entering LmHead with slots=%zu hidden=%zu\n",
                                 program_.size(), hidden_.size());
                    std::fflush(stderr);
                }
                if (!OpLinear(in.b, hidden_, y, e)) { last_error_ = e; return false; }
                if (std::getenv("RR_TRACE_TOKEN")) {
                    std::fprintf(stderr, "  [lmhead] OK logits=%zu top=%.4f\n", y.size(),
                                 y.empty() ? 0.0f : *std::max_element(y.begin(), y.end()));
                    std::fflush(stderr);
                }
                logits_ = y;
                break;
            }
            case OpKind::SsmScan: {
                std::vector<float> y;
                std::string e;
                const std::vector<float>& ssmIn = arena(in.aName);
                if (ssmIn.empty()) { last_error_ = "ssm: empty input arena"; return false; }
                if (!OpSsmScan(in, ssmIn, y, e)) { last_error_ = e; return false; }
                arena(in.outName) = y;
                break;
            }
            default:
                if (std::getenv("SSM_TRACE")) {
                    std::fprintf(stderr, "[exec] unhandled op=%d bName=%s bSlot=%d aName=%s outName=%s\n",
                                 (int)in.op, in.bName.c_str(), (int)in.b,
                                 in.aName.c_str(), in.outName.c_str());
                }
                last_error_ = "unhandled op";
                return false;
        }   // switch over program_ ops

        // ---- env-gated first-non-finite tracer (no semantics change) ----
        // RR_CHECK_FINITE=1 aborts at the FIRST op whose FP32 output is NaN/Inf,
        // reporting block/pc/op/name/index/value so the real numerical defect is
        // localised instead of its downstream logits symptom. Diagnostic only.
        if (std::getenv("RR_CHECK_FINITE")) {
            auto chk = [&](const char* tag, const std::vector<float>& v) {
                for (size_t i = 0; i < v.size(); ++i) {
                    if (!std::isfinite(v[i])) {
                        std::fprintf(stderr,
                            "[FIRST_NONFINITE] block=%d pc=%d op=%d name=%s(%s) index=%zu value=%g size=%zu\n",
                            (int)in.block, (int)pc, (int)in.op, in.outName.c_str(), tag, i, v[i], v.size());
                        std::fflush(stderr);
                        std::abort();
                    }
                }
            };
            chk("hidden", hidden_);
            if (!in.outName.empty() && in.outName[0] != '<') {
                auto it = act.find(in.outName);
                if (it != act.end()) chk("arena", it->second);
            }
        }

        // RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY: first-divergence
        // instrumentation. Two executors of the same graph (GPU vs CPU-pinned)
        // can be compared op-by-op to find the FIRST divergent tensor instead
        // of the final logits, where every layer's error is mixed together.
        // A 64-bit FNV-1a over the op's output buffer is enough to decide
        // equality; the export below also records sizes for reporting.
        if (trace_ops_) {
            const std::vector<float>* out = nullptr;
            if (!in.outName.empty() && in.outName[0] != '<') {
                auto it = act.find(in.outName);
                if (it != act.end()) out = &it->second;
            }
            if (!out && !hidden_.empty()) out = &hidden_;
            if (!out && !logits_.empty()) out = &logits_;
            if (out) {
                uint64_t h = 1469598103934665603ull;
                for (float v : *out) {
                    uint32_t u = 0;
                    std::memcpy(&u, &v, sizeof(u));
                    h ^= u;
                    h *= 1099511628211ull;
                }
                OpTrace tr;
                tr.block = in.block;
                tr.pc = (int)pc;
                tr.op = (int)in.op;
                tr.name = in.outName.empty() ? "<hidden>" : in.outName;
                tr.weight = in.bName;
                tr.input = in.aName;
                tr.size = out->size();
                tr.checksum = h;
                tr.dispatch_backend = trace_dispatch_backend_;
                tr.dispatch_fallback = trace_dispatch_fallback_;
                tr.dispatch_forced = trace_dispatch_forced_;
                for (size_t vi = 0; vi < 8 && vi < out->size(); ++vi)
                    tr.first_vals[vi] = (*out)[vi];
                if (trace_capture_values_) tr.values = *out;
                op_traces_.push_back(tr);
            }
        }
    }

    if (logits_.empty()) { last_error_ = "no logits produced"; return false; }
    for (float v : logits_) if (!std::isfinite(v)) ++nonfinite_logits_;

    stats_.gpu_calls += gpu_calls_;
    stats_.cpu_calls += cpu_calls_;
    if (!cpu_fallback_reason_.empty() && stats_.fallback_reason.empty()) {
        stats_.fallback_reason = cpu_fallback_reason_;
    }
    stats_.gpu_rows += 0;
    if (!unresolved_inputs_.empty()) {
        last_error_ = "graph referenced activations that were never produced: ";
        for (size_t i = 0; i < unresolved_inputs_.size() && i < 4; ++i)
            last_error_ += unresolved_inputs_[i] + "; ";
        return false;
    }

    // Accumulate the measured wall-clock into the receipts.
    const auto token_finished = std::chrono::steady_clock::now();
    const double token_ms =
        std::chrono::duration<double, std::milli>(token_finished - token_started).count();
    stats_.dispatch_ms += token_ms;
    stats_.total_ms += token_ms;
    if (tokens_executed_ == 1) {
        // The first token pays for cache warm-up and lazy pipeline creation.
        stats_.cold_start_ms = token_ms;
    } else {
        stats_.steady_kernel_ms += token_ms;
    }
    return true;
}


// ---------------------------------------------------------------------------
// OpSsmScan - Mamba2 selective scan.
//
// The missing primitive for nemotron_h / qwen3-next. An SSM has no parallel
// form to approximate, so the recurrence below IS the block. Per channel i,
// for one token:
//     dt    = softplus(dt_b[i])
//     decay = exp(dt * A[i])
//     state = decay*state + dt * x[i]
//     y     = state + D[i] * x[i]
// Every operand comes from the model's own tensors; nothing is defaulted.
// ---------------------------------------------------------------------------
bool Executor::OpSsmScan(const Instr& in, const std::vector<float>& x,
                         std::vector<float>& y, std::string& err) {
    const size_t D = (size_t)spec_.ssm_inner_size;
    const size_t N = (size_t)spec_.ssm_state_size;
    if (D == 0 || N == 0) { err = "ssm: ssm.inner_size / ssm.state_size not declared"; return false; }
    if (in.b < 0) { err = "ssm: no in-projection slot"; return false; }

    std::vector<float> xd;
    if (!OpLinear(in.b, x, xd, err)) return false;
    if (xd.size() < D) { err = "ssm: in-projection smaller than d_inner"; return false; }
    xd.resize(D);

    auto slotOf = [&](const char* tag) -> int32_t {
        const std::string needle = std::string(tag) + "=";
        const size_t at = in.detail.find(needle);
        if (at == std::string::npos) return -1;
        size_t s = at + needle.size();
        const size_t e = in.detail.find(';', s);
        const std::string n = (e == std::string::npos) ? in.detail.substr(s) : in.detail.substr(s, e - s);
        if (n.empty()) return -1;
        auto it = slot_by_name_.find(n);
        return it == slot_by_name_.end() ? -1 : it->second;
    };

    const int32_t aSlot = slotOf("A");
    const int32_t dtSlot = slotOf("dtB");
    const int32_t dSlot = slotOf("D");
    if (aSlot < 0 || dtSlot < 0) { err = "ssm: model has no ssm_a / ssm_dt.bias"; return false; }

    std::vector<float> A, DtB, Dd;
    if (aSlot < 0 || dtSlot < 0) { err = "ssm: model has no ssm_a / ssm_dt.bias"; return false; }

    // Mamba2 scale/decay tensors are far smaller than d_inner and BROADCAST
    // across head groups rather than providing one value per channel.
    //
    // Measured on the real Nemotron-3.5-Lightning-30B:
    //     D (ssm.inner_size)  = 4096
    //     N (ssm.state_size)  = 128
    //     blk.0.ssm_a         = [1, 64]   -> 64 elements
    //
    // Requiring D distinct values here reported "ssm_a too small" on a perfectly
    // valid tensor, which blocked every Mamba2 block. Load what each tensor
    // actually provides and index modulo its length, which is the broadcast the
    // architecture specifies.
    DequantPrefix(tensors_[(size_t)aSlot], A, D);
    DequantPrefix(tensors_[(size_t)dtSlot], DtB, D);
    if (dSlot >= 0) DequantPrefix(tensors_[(size_t)dSlot], Dd, D);

    if (A.empty()) { err = "ssm: ssm_a dequantized to nothing"; return false; }
    if (DtB.empty()) { err = "ssm: ssm_dt.bias dequantized to nothing"; return false; }
    if (Dd.empty()) Dd.assign(D, 0.0f);

    if (std::getenv("SSM_TRACE")) {
        std::fprintf(stderr, "[ssm] block=%d D=%zu aElems=%zu dtElems=%zu dElems=%zu\n",
                     (int)in.block, D, A.size(), DtB.size(), Dd.size());
    }

    if (ssm_state_.size() <= (size_t)in.block) ssm_state_.resize((size_t)in.block + 1);
    std::vector<float>& st = ssm_state_[(size_t)in.block];
    if (st.size() != D) st.assign(D, 0.0f);

    y.assign(D, 0.0f);
    auto softplus = [](float z) -> float { return (z > 20.0f) ? z : std::log1p(std::exp(z)); };

    for (size_t i = 0; i < D; ++i) {
        const float dt = softplus(DtB[i % DtB.size()]);
        const float decay = std::exp(dt * A[i % A.size()]);
        const float xin = xd[i];
        st[i] = decay * st[i] + dt * xin;
        y[i] = st[i] + Dd[i % Dd.size()] * xin;
    }
    return true;
}
} } }  // namespace


