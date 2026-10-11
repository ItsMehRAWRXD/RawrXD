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

namespace RawrXD { namespace Deep2 { namespace RuntimeGraph {

using Universal::TensorRec;

namespace {

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
    if (findSlot("output.weight") < 0) { stats_.error = "missing output.weight"; return false; }
    if (findSlot("output_norm.weight") < 0) { stats_.error = "missing output_norm.weight"; return false; }

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
            case Universal::Op::MatMul: in.op = OpKind::Linear; break;
            case Universal::Op::Attention: in.op = OpKind::Attention; break;
            case Universal::Op::MlaDecompress: in.op = OpKind::MlaDecompress; break;
            case Universal::Op::Router: in.op = OpKind::Router; break;
            case Universal::Op::TopK: in.op = OpKind::TopK; break;
            case Universal::Op::MoEExecute: in.op = OpKind::MoEExecute; break;
            case Universal::Op::ResidualAdd: in.op = OpKind::ResidualAdd; break;
            case Universal::Op::LmHead: in.op = OpKind::LmHead; break;

            default: in.op = OpKind::Unsupported; break;
        }
        in.block = g.block;
        in.aName = g.a;
        in.bName = g.b;
        in.outName = g.out;
        in.a = nameSlot(g.a);
        in.b = nameSlot(g.b);
        in.c = nameSlot(g.c);
        in.out = nameSlot(g.out);
        in.detail = g.detail;
        program_.push_back(in);
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

void Executor::SetForceCpu(bool force) {
    QuantDot::SetForceCpu(force);
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
    if (wslot < 0) { err = "linear: no weight"; return false; }
    const TensorRec& w = tensors_[(size_t)wslot];
    if (!w.data || w.dims.size() < 2) { err = "linear: bad weight"; return false; }
    const size_t n_in = (size_t)w.dims[0];
    const size_t n_out = (size_t)w.dims[1];
    if (x.size() != n_in) { char b2[192]; std::snprintf(b2, sizeof(b2), "linear: x=%zu n_in=%zu weight=%s dims=[%zu,%zu]", x.size(), n_in, w.name.c_str(), (size_t)w.dims[0], w.dims.size()>1?(size_t)w.dims[1]:0); err = b2; return false; }

    const bool quant = (w.ggml_type == GGML_TYPE_Q4_K || w.ggml_type == GGML_TYPE_Q6_K);
    if (quant && (n_in % 256) == 0) {
        const int kind = (w.ggml_type == GGML_TYPE_Q4_K) ? 0 : 1;
        const size_t rb = (n_in / 256) * (size_t)(kind == 0 ? 144 : 210);
        if (w.bytes < rb * n_out) { err = "linear: weight bytes short"; return false; }
        const ggml_type_traits* tr = ggml_get_type_traits(w.ggml_type);
        // The independent reference decodes ONE packed row at a time. It must
        // not materialise a dequantised [n_out, n_in] float matrix: for a
        // 102400-row output projection that is 4x the encoded size and, when
        // indexed as rows, walks far past the buffer that was actually filled.
        //
        // CRITICAL: the reference must consume the SAME quantised activation
        // the GPU kernel sees. QuantDot hands us the Q8 block layout
        // (273 floats per 256 values: d, qs[256], bsums[16]); dotting with the
        // raw float activation instead would compare quantised-vs-float and
        // report the activation quantisation error, not the kernel's.
        QuantDot::CpuDot cpu =
            [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                const float* q8 = static_cast<const float*>(q8_act);
                static thread_local std::vector<float> rw;
                rw.assign(n_in, 0.0f);
                tr->to_float(row, rw.data(), (int)n_in);
                double acc = 0.0;
                for (size_t b = 0; b < (n_in / 256); ++b) {
                    const float d = q8[b * 273];
                    const float* qs = q8 + b * 273 + 1;
                    const float* wr = rw.data() + b * 256;
                    for (int i = 0; i < 256; ++i)
                        acc += double(wr[i]) * (double(qs[i]) * d);
                }
                return (float)acc;
            };
        y.assign(n_out, 0.0f);
        const bool gpu = QuantDot::DotBlocked(kind, w.data, w.bytes,
                                              x.data(), n_in, y.data(), n_out, cpu);
        if (gpu) { ++gpu_calls_; } else { ++cpu_calls_; }
        return true;
    }

    // Non-k-quant (or non-multiple-of-256) weight: dequantise and dot.
    std::vector<float> wf;
    const size_t got = DequantPrefix(w, wf, n_in * n_out);
    if (got < n_in * n_out) { err = "linear: dequant short"; return false; }
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

bool Executor::OpAttention(const Instr& in, const std::vector<float>& q,
                           const std::vector<float>& k, const std::vector<float>& v,
                           std::vector<float>& y, size_t position, std::string& err) {
    if (spec_.heads == 0) { err = "attention: head_count 0"; return false; }
    const size_t H = (size_t)spec_.heads;
    const size_t hk = (size_t)(spec_.heads_kv ? spec_.heads_kv : spec_.heads);
    const size_t D = spec_.embd / H;
    if (D == 0 || q.size() < spec_.embd || k.size() < spec_.embd / hk * hk) {
        // allow v of different width (MLA value length)
    }
    if (in.block < 0 || (size_t)in.block >= kv_k_.size()) { err = "attention: bad block"; return false; }

    // RoPE on q and k (standard rotate-half with freq_base^(-2i/d)).
    auto rope = [&](std::vector<float>& t, size_t heads, size_t head_dim) {
        if (head_dim == 0 || (head_dim % 2) != 0) return;
        for (size_t h = 0; h < heads; ++h) {
            float* p = t.data() + h * head_dim;
            for (size_t i = 0; i < head_dim; i += 2) {
                const double theta =
                    (double)position *
                    std::pow((double)spec_.rope_freq_base, -2.0 * double(i) / double(head_dim));
                const float c = (float)std::cos(theta), s = (float)std::sin(theta);
                const float a = p[i], b = p[i + 1];
                p[i] = a * c - b * s;
                p[i + 1] = a * s + b * c;
            }
        }
    };
    std::vector<float> qr = q, kr = k;
    rope(qr, H, D);
    rope(kr, hk, k.size() / std::max<size_t>(hk, 1));

    // append to this layer's KV cache
    auto& K = kv_k_[(size_t)in.block];
    auto& V = kv_v_[(size_t)in.block];
    const size_t kvW = k.size();
    const size_t vW = v.size();
    if (K.size() < (position + 1) * kvW) K.resize((position + 1) * kvW, 0.0f);
    if (V.size() < (position + 1) * vW) V.resize((position + 1) * vW, 0.0f);
    std::memcpy(K.data() + position * kvW, kr.data(), kvW * sizeof(float));
    std::memcpy(V.data() + position * vW, v.data(), vW * sizeof(float));

    const size_t T = position + 1;
    const size_t vD = vW / std::max<size_t>(hk, 1);
    y.assign(spec_.embd, 0.0f);
    std::vector<float> scores(T);
    for (size_t h = 0; h < H; ++h) {
        const size_t kg = h / std::max<size_t>((H / hk) ? (H / hk) : 1, 1);
        const float* qp = qr.data() + h * D;
        for (size_t t = 0; t < T; ++t) {
            const float* kp = K.data() + t * kvW + kg * (kvW / hk);
            double acc = 0.0;
            for (size_t d = 0; d < D && d < kvW / hk; ++d) acc += double(qp[d]) * double(kp[d]);
            scores[t] = (float)(acc / std::sqrt((double)std::max<size_t>(D, 1)));
        }
        SoftmaxVec(scores);
        float* op = y.data() + h * D;
        for (size_t t = 0; t < T; ++t) {
            const float* vp = V.data() + t * vW + kg * vD;
            const float s = scores[t];
            for (size_t d = 0; d < D && d < vD; ++d) op[d] += s * vp[d];
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
    const size_t n_exp = rt.dims.size() >= 2 ? (size_t)rt.dims[0] : 0;
    if (n_exp == 0) { last_error_ = "router: bad shape"; return false; }
    std::vector<float> logits;
    if (rt.ggml_type == GGML_TYPE_F32) {
        logits.assign(n_exp, 0.0f);
        std::memcpy(logits.data(), rt.data, std::min(n_exp * 4, rt.bytes));
        // logits are [n_exp, embd]: dot each expert row with x
        std::vector<float> wf;
        DequantPrefix(rt, wf, n_exp * spec_.embd);
        for (size_t e = 0; e < n_exp; ++e) {
            double acc = 0.0;
            for (size_t i = 0; i < spec_.embd && (e * spec_.embd + i) < wf.size(); ++i)
                acc += double(wf[e * spec_.embd + i]) * double(x[i]);
            logits[e] = (float)acc;
        }
    } else {
        std::vector<float> wf;
        DequantPrefix(rt, wf, n_exp * spec_.embd);
        if (wf.size() < n_exp * spec_.embd) { last_error_ = "router: dequant short"; return false; }
        for (size_t e = 0; e < n_exp; ++e) {
            double acc = 0.0;
            for (size_t i = 0; i < spec_.embd; ++i)
                acc += double(wf[e * spec_.embd + i]) * double(x[i]);
            logits.push_back((float)acc);
        }
    }
    if (spec_.expert_used == 0) { last_error_ = "router: expert_used 0"; return false; }
    const size_t kused = (size_t)spec_.expert_used;
    SoftmaxVec(logits);
    std::vector<uint32_t> idx(n_exp);
    for (uint32_t i = 0; i < n_exp; ++i) idx[i] = i;
    std::stable_sort(idx.begin(), idx.end(),
                     [&](uint32_t a, uint32_t b) { return logits[a] > logits[b]; });
    ids.assign(kused, 0);
    w.assign(kused, 0.0f);
    double renorm = 0.0;
    for (size_t i = 0; i < kused; ++i) renorm += logits[idx[i]];
    if (!(renorm > 0.0)) { last_error_ = "router: zero weight"; return false; }
    for (size_t i = 0; i < kused; ++i) {
        ids[i] = idx[i];
        w[i] = (float)(logits[idx[i]] / renorm);
    }
    return true;
}

bool Executor::OpMoEExecute(const Instr& moe, const std::vector<float>& x,
                            const std::vector<uint32_t>& ids, const std::vector<float>& w,
                            std::vector<float>& y, std::string& err) {
    y.assign(spec_.embd, 0.0f);
    // moe.c is the gate expert-tensor slot; moe.a is the arena input
    // ("ffn_norm") and moe.b is the arena choice vector.
    if (moe.c < 0 || moe.c >= (int32_t)tensors_.size()) {
        err = "moe: missing gate expert slot";
        return false;
    }
    const TensorRec& gate = tensors_[(size_t)moe.c];
    // Resolve the sibling expert tensors from the gate's name.
    auto sibling = [&](const char* from, const char* to) -> const TensorRec* {
        std::string n = gate.name;
        const size_t p = n.rfind(from);
        if (p == std::string::npos) return nullptr;
        n.replace(p, std::strlen(from), to);
        auto it = slot_by_name_.find(n);
        return it == slot_by_name_.end() ? nullptr : &tensors_[(size_t)it->second];
    };
    const TensorRec* upT = sibling("ffn_gate_exps.weight", "ffn_up_exps.weight");
    const TensorRec* downT = sibling("ffn_gate_exps.weight", "ffn_down_exps.weight");
    if (!upT || !downT) { err = "moe: up/down expert tensors not found"; return false; }

    const size_t ffn = (size_t)std::max<uint64_t>(spec_.expert_ffn, 1);
    const size_t embd = spec_.embd;
    if (gate.dims.size() < 2 || upT->dims.size() < 2 || downT->dims.size() < 2) {
        err = "moe: expert tensor rank < 2";
        return false;
    }
    std::vector<float> gT, uT, dT;
    DequantPrefix(gate, gT, gate.bytes / 4);
    DequantPrefix(*upT, uT, upT->bytes / 4);
    DequantPrefix(*downT, dT, downT->bytes / 4);
    const size_t gIn = (size_t)gate.dims[0], gOut = (size_t)gate.dims[1];
    const size_t uIn = (size_t)upT->dims[0], uOut = (size_t)upT->dims[1];
    const size_t dIn = (size_t)downT->dims[0], dOut = (size_t)downT->dims[1];
    // Only the experts whose full [in, out] block is present are usable.
    const size_t gE = gT.size() / (gIn * gOut);
    const size_t uE = uT.size() / (uIn * uOut);
    const size_t dE = dT.size() / (dIn * dOut);
    const size_t usableE = std::min(gE, std::min(uE, dE));
    if (usableE == 0) { err = "moe: no dequantised expert blocks available"; return false; }

    std::vector<float> g(ffn), u(ffn), h(ffn);
    for (size_t e = 0; e < ids.size() && e < w.size(); ++e) {
        const uint32_t ex = ids[e];
        if ((size_t)ex >= usableE) continue;
        std::fill(g.begin(), g.end(), 0.0f);
        std::fill(u.begin(), u.end(), 0.0f);
        const float* gp = gT.data() + (size_t)ex * (gIn * gOut);
        const float* up = uT.data() + (size_t)ex * (uIn * uOut);
        const size_t glen = std::min(ffn, gOut);
        const size_t ulen = std::min(ffn, uOut);
        for (size_t j = 0; j < glen; ++j) {
            double acc = 0.0;
            const size_t lim = std::min(gIn, x.size());
            for (size_t i = 0; i < lim; ++i) acc += double(gp[j * gIn + i]) * double(x[i]);
            g[j] = (float)acc;
        }
        for (size_t j = 0; j < ulen; ++j) {
            double acc = 0.0;
            const size_t lim = std::min(uIn, x.size());
            for (size_t i = 0; i < lim; ++i) acc += double(up[j * uIn + i]) * double(x[i]);
            u[j] = (float)acc;
        }
        // SwiGLU: silu(gate) * up
        for (size_t j = 0; j < ffn; ++j) {
            const float s = 1.0f / (1.0f + std::exp(-g[j]));
            h[j] = g[j] * s * u[j];
        }
        const float* dp = dT.data() + (size_t)ex * (dIn * dOut);
        const size_t olen = std::min(embd, dOut);
        for (size_t i = 0; i < olen; ++i) {
            double acc = 0.0;
            const size_t lim = std::min(dIn, ffn);
            for (size_t j = 0; j < lim; ++j) acc += double(dp[i * dIn + j]) * double(h[j]);
            y[i] += w[e] * (float)acc;
        }
    }
    return true;
}

bool Executor::OpMlaDecompress(const Instr& mla, const std::vector<float>& x,
                               std::vector<float>& k_out, std::vector<float>& v_out,
                               size_t position, std::string& err) {
    // MLA: latent = x @ kv_a_mqa ; k = latent @ kv_b (lo); v = latent @ kv_b (hi)
    if (mla.a < 0 || mla.b < 0 || mla.c < 0) { err = "mla: missing weights"; return false; }
    const TensorRec& kvA = tensors_[(size_t)mla.a];
    const TensorRec& norm = tensors_[(size_t)mla.b];
    const TensorRec& kvB = tensors_[(size_t)mla.c];
    const size_t lora = (size_t)std::max<uint64_t>(spec_.kv_lora_rank, 1);
    const size_t kl = (size_t)spec_.key_length;    // 512 = 384 rope + 128 nope
    const size_t vl = (size_t)spec_.value_length;  // 128

    std::vector<float> A, B, nw;
    DequantPrefix(kvA, A, kvA.bytes / 4);
    DequantPrefix(kvB, B, kvB.bytes / 4);
    DequantPrefix(norm, nw, 65536);
    if (A.empty() || B.empty()) { err = "mla: dequant short"; return false; }
    const size_t aIn = (size_t)kvA.dims[0];
    const size_t aOut = kvA.dims.size() > 1 ? (size_t)kvA.dims[1] : lora;
    // The dequantised prefix may be smaller than the whole tensor, so only
    // process the rows that are actually present.
    const size_t usableA = std::min(A.size(), aIn * aOut);
    const size_t rowsA = aIn ? (usableA / aIn) : 0;
    if (rowsA == 0) { err = "mla: no usable rows"; return false; }
    std::vector<float> latent(rowsA, 0.0f);
    for (size_t j = 0; j < rowsA; ++j) {
        double acc = 0.0;
        const size_t lim = std::min(aIn, x.size());
        for (size_t i = 0; i < lim; ++i)
            acc += double(A[j * aIn + i]) * double(x[i]);
        latent[j] = (float)acc;
    }
    const size_t bIn = (size_t)kvB.dims[0];
    const size_t bOut = kvB.dims.size() > 1 ? (size_t)kvB.dims[1] : 0;
    const size_t usableB = std::min(B.size(), bIn * bOut);
    const size_t rowsB = bIn ? (usableB / bIn) : 0;
    if (rowsB == 0) { err = "mla: kv_b unusable"; return false; }
    k_out.assign(kl, 0.0f);
    v_out.assign(vl, 0.0f);
    for (size_t j = 0; j < kl && j < rowsB; ++j) {
        double acc = 0.0;
        const size_t lim = std::min(lora, std::min(bIn, latent.size()));
        for (size_t i = 0; i < lim; ++i)
            acc += double(B[j * bIn + i]) * double(latent[i]);
        k_out[j] = (float)acc;
    }
    // V occupies the tail of kv_b's output dimension in DeepSeek MLA.
    for (size_t j = 0; j < vl; ++j) {
        const size_t col = kl + j;
        if (col >= rowsB) break;
        double acc = 0.0;
        const size_t lim = std::min(lora, std::min(bIn, latent.size()));
        for (size_t i = 0; i < lim; ++i)
            acc += double(B[col * bIn + i]) * double(latent[i]);
        v_out[j] = (float)acc;
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
    position_ = position;

    // Activation arena: SSA values from the runtime graph, keyed by the name
    // the graph gave them. A block's gate and up projections both read
    // "ffn_norm", so an op's DECLARED input is used, not the running hidden.
    std::unordered_map<std::string, std::vector<float>> act;
    auto arena = [&](const std::string& n) -> std::vector<float>& { return act[n]; };
    auto resolveIn = [&](const Instr& i) -> const std::vector<float>& {
        if (!i.aName.empty() && i.aName[0] != '<' && act.count(i.aName))
            return act[i.aName];
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

    for (const auto& in : program_) {
        const std::vector<float>& xi = resolveIn(in);
        switch (in.op) {
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
                std::vector<float> y;
                std::string e;
                if (!OpLinear(in.b, xi, y, e)) { last_error_ = e; return false; }
                arena(in.outName.empty() ? std::string("lin") : in.outName) = y;
                hidden_ = y;
                break;
            }
            case OpKind::MlaDecompress: {
                std::vector<float> k, v;
                std::string e;
                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }
                arena(in.outName.empty() ? std::string("kv") : in.outName) = hidden_;
                arena("k") = k;
                arena("v") = v;
                break;
            }
            case OpKind::Attention: {
                std::vector<float> y;
                std::string e;
                std::vector<float> qv = arena("q"), kv = arena("k"), vv = arena("v");
                if (qv.empty()) qv = hidden_;
                if (kv.empty()) kv = qv;
                if (vv.empty()) vv = kv;
                if (!OpAttention(in, qv, kv, vv, y, position, e)) { last_error_ = e; return false; }
                arena("attn") = y;
                hidden_ = y;
                break;
            }
            case OpKind::ResidualAdd: {
                const std::vector<float> empty;
                const std::vector<float>* resid = &empty;
                if (in.a >= 0) {
                    const std::string an = tensors_[(size_t)in.a].name;
                    auto it = act.find(an);
                    if (it != act.end()) resid = &it->second;
                }
                std::vector<float> y(hidden_.size(), 0.0f);
                for (size_t i = 0; i < hidden_.size(); ++i)
                    y[i] = hidden_[i] + (i < resid->size() ? (*resid)[i] : 0.0f);
                hidden_ = y;
                break;
            }
            case OpKind::Router: {
                if (!OpRouterTopK(in, in, xi, expert_ids, expert_w)) return false;
                ids_valid = true;
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
                hidden_ = y;
                break;
            }
            case OpKind::LmHead: {
                std::vector<float> y;
                std::string e;
                if (!OpLinear(in.b, hidden_, y, e)) { last_error_ = e; return false; }
                logits_ = y;
                break;
            }
            default:
                last_error_ = "unhandled op";
                return false;
        }   // switch over program_ ops
    }

    if (logits_.empty()) { last_error_ = "no logits produced"; return false; }
    for (float v : logits_) if (!std::isfinite(v)) ++nonfinite_logits_;

    stats_.gpu_calls += gpu_calls_;
    stats_.cpu_calls += cpu_calls_;
    stats_.gpu_rows += 0;
    return true;
}

} } }  // namespace
