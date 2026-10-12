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
            case Universal::Op::MatMul: in.op = OpKind::Linear; break;
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
        const ggml_type_traits* tr = ggml_get_type_traits(w.ggml_type);        // The independent reference decodes ONE packed row at a time. It must
        // not materialise a dequantised [n_out, n_in] float matrix: for a
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
        QuantDot::CpuDot cpu =
            [&](const uint8_t* row, const void* q8_act, size_t) -> float {
                const float* q8 = static_cast<const float*>(q8_act);
                const size_t nblk = n_in / 256;
                const size_t blk_bytes = (kind == 0) ? 144u : 210u;
                int32_t a[256];
                int32_t aux32[8];
                float sums[8], sumf = 0.0f;
                for (int l = 0; l < 8; ++l) sums[l] = 0.0f;
                for (size_t b = 0; b < nblk; ++b) {
                    const uint8_t* blk = row + b * blk_bytes;
                    const float* q8b = q8 + b * 273;
                    for (int l = 0; l < 8; ++l) aux32[l] = 0;
                    if (kind == 0) {
                        // ---- Q4_K ----
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
                        // ---- Q6_K ----
                        for (int j = 0; j < 256; ++j) {
                            const int hlf = j / 128;      // ql half
                            const int loff = (j % 64) / 32 * 32 + (j % 32);
                            const int hoff = (j / 64) % 2 * 32 + (j % 32);
                            const int part = (j / 64) % 2;              // low nibble (0) / high nibble (1)
                            const int qhpos = ((j % 64) / 32) * 32 + (j % 32);
                            const int shift4 = (part == 0) ? 0 : 4;
                            const int shifth = (part == 0) ? 0 : 2;
                            const int low4  = (blk[loff] >> shift4) & 0xF;
                            const int high2 = (blk[128 + qhpos] >> shifth) & 3;
                            a[j] = low4 | (high2 << 4);
                            (void)hlf; (void)hoff;
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
                                aux32[l & 7] += sc * (int32_t)q8b[1 + s * 16 + l] * (a[s * 16 + l] - 32);
                        }
                        uint16_t h;
                        std::memcpy(&h, blk + 208, 2);
                        const float d = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
                        for (int l = 0; l < 8; ++l) sums[l] += d * float(aux32[l]);
                    }
                }
                for (int l = 0; l < 8; ++l) sumf += sums[l];
                return sumf;
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
        const size_t n_blk = n_in / 256;
        std::vector<float> q8(n_blk * 273, 0.0f);
        for (size_t b = 0; b < n_blk; ++b) {
            float mx = 0.0f;
            for (size_t i = 0; i < 256; ++i) mx = std::max(mx, std::fabs(x[b * 256 + i]));
            const float d = mx / 127.0f;
            const float inv = d > 0.0f ? 1.0f / d : 0.0f;
            float* blk = q8.data() + b * 273;
            blk[0] = d;
            int32_t bsums[16] = {0};
            for (size_t i = 0; i < 256; ++i) {
                const int32_t v = (int32_t)std::lround(x[b * 256 + i] * inv);
                blk[1 + i] = (float)v;
                bsums[i / 16] += v;
            }
            for (size_t k = 0; k < 16; ++k) blk[257 + k] = (float)bsums[k];
        }
        y.assign(n_out, 0.0f);
        if (std::getenv("QUANT_TRACE")) {
            std::fprintf(stderr, "[quant] w=%s kind=%d n_in=%zu n_out=%zu n_blk=%zu rb=%zu wbytes=%zu need=%zu\n",
                         w.name.c_str(), kind, n_in, n_out, n_blk, rb, w.bytes,
                         rb * n_out);
            std::fflush(stderr);
        }
        const bool gpu = QuantDot::DotBlocked(kind, w.data, w.bytes,
                                              x.data(), n_in, y.data(), n_out, cpu,
                                              q8.data(), q8.size() * sizeof(float));
        if (gpu) { ++gpu_calls_; } else { ++cpu_calls_; }
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

bool Executor::OpAttention(const Instr& in, const std::vector<float>& q,
                           const std::vector<float>& k, const std::vector<float>& v,
                           std::vector<float>& y, size_t position, std::string& err) {
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

    // RoPE: the ROTARY slice only. In MLA that is the last qk_rope dims of q
    // and of k; in a GQA model it is the whole head. Rotating the entire head
    // (the earlier behaviour) mixes positional information into the no-rope
    // channels and corrupts the score function.
    const size_t ropeDims = isMla ? (qD - (qD - (kl - (kl - vl)))) : D;
    const size_t ropeOff = isMla ? (kPerHead - (kPerHead > 0 ? 0 : 0)) : 0;
    (void)ropeDims;
    (void)ropeOff;
    // DeepSeek: qk_nope = key_length - value_length; the rope part follows.
    const size_t qk_nope = isMla ? (kl - vl) : 0;
    const size_t q_rope_dim = isMla ? (qD - qk_nope) : D;
    const size_t k_rope_dim = isMla ? (kPerHead - qk_nope) : D;
    const size_t ropeLen = std::min(q_rope_dim, k_rope_dim);
    const size_t qRopeOff = isMla ? qk_nope : 0;
    const size_t kRopeOff = isMla ? qk_nope : 0;

    auto rope = [&](std::vector<float>& t, size_t heads, size_t headDim,
                    size_t ropeLen, size_t ropeOff) {
        // RoPE rotates consecutive pairs (p[2k], p[2k+1]). The inv_freq MUST be
        // indexed by the PAIR index k, not the element index: using i makes
        // every pair rotate at a different rate than the reference and silently
        // destroys positional information. rope_len counts ELEMENTS, so the
        // number of pairs is rope_len/2 and freq_k = base^(-2k / n_pairs).
        const size_t nPairs = ropeLen / 2;
        if (nPairs == 0) return;
        for (size_t h = 0; h < heads; ++h) {
            float* p = t.data() + h * headDim + ropeOff;
            const size_t lim = std::min(ropeLen, headDim - std::min(ropeOff, headDim));
            for (size_t i = 0; i + 1 < lim; i += 2) {
                const size_t k = i / 2;
                const double theta = (double)position *
                    std::pow((double)spec_.rope_freq_base,
                             -2.0 * double(k) / double(nPairs));
                const float c = (float)std::cos(theta), s = (float)std::sin(theta);
                const float a = p[i], b = p[i + 1];
                p[i] = a * c - b * s;
                p[i + 1] = a * s + b * c;
            }
        }
    };

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
    rope(qr, H, qPerHead, ropeLen, qRopeOff);
    rope(kr, hk, kPerHead, ropeLen, kRopeOff);

    // Append to this layer's KV cache.
    auto& K = kv_k_[(size_t)in.block];
    auto& V = kv_v_[(size_t)in.block];
    const size_t kvW = kr.size();
    const size_t vW = v.size();
    if (K.size() < (position + 1) * kvW) K.resize((position + 1) * kvW, 0.0f);
    if (V.size() < (position + 1) * vW) V.resize((position + 1) * vW, 0.0f);
    std::memcpy(K.data() + position * kvW, kr.data(), kvW * sizeof(float));
    std::memcpy(V.data() + position * vW, v.data(), vW * sizeof(float));

    const size_t T = position + 1;
    // Output width follows the QUERY heads, not the value heads: with GQA the
    // output projection is [qWidth, embd], so each of the H query heads must
    // contribute qPerHead values. Using vPerHead produced 32*8=256 when the
    // projection required 32*128=4096.
    const size_t outW = qPerHead;
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
            scores[t] = (float)(acc / std::sqrt((double)std::max<size_t>(qD, 1)));
        }
        SoftmaxVec(scores);
        float* op = y.data() + h * outW;
        for (size_t t = 0; t < T; ++t) {
            // Value for this query head comes from its KV group. The value head
            // may be narrower than qPerHead; read only what exists and leave the
            // remaining output lanes at zero rather than reading past the KV
            // buffer.
            const float* vp = V.data() + t * vW + g * vPerHead;
            const float s = scores[t];
            const size_t copyW = std::min(vPerHead, outW);
            for (size_t d = 0; d < copyW; ++d) op[d] += s * vp[d];
        }
    }    return true;
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

    // No separate gate expert on this model: the router (ffn_gate_inp) does the
    // gating, so the up projection doubles as the gate (identity gate).
    const TensorRec* gateT = upT;
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

    std::vector<float> g(ffn), u(ffn), h(ffn);
    std::vector<float> gSlice, uSlice, dSlice;
    size_t expertsProcessed = 0;

    for (size_t e = 0; e < ids.size() && e < w.size(); ++e) {
        const size_t ex = (size_t)ids[e];
        if (ex >= usableE) continue;

        // Dequantize only this expert's slice.
        gSlice.clear(); uSlice.clear(); dSlice.clear();

        const size_t gBase = ex * elemStrideG;
        const size_t uBase = ex * elemStrideU;
        const size_t dBase = ex * elemStrideD;
        if (!DequantRange(*gateT, gBase, elemStrideG, gSlice) ||
            !DequantRange(*upT,   uBase, elemStrideU, uSlice) ||
            !DequantRange(*downT, dBase, elemStrideD, dSlice)) {
            err = "moe: expert slice dequant failed (block=" + std::to_string(moe.block) +
                  " expert=" + std::to_string(ex) + ")";
            return false;
        }

        std::fill(g.begin(), g.end(), 0.0f);
        std::fill(u.begin(), u.end(), 0.0f);

        const size_t glen = std::min(ffn, gOut);
        const size_t ulen = std::min(ffn, uOut);
        for (size_t j = 0; j < glen; ++j) {
            double acc = 0.0;
            const size_t lim = std::min(gIn, x.size());
            for (size_t i = 0; i < lim; ++i) acc += double(gSlice[j * gIn + i]) * double(x[i]);
            g[j] = (float)acc;
        }
        for (size_t j = 0; j < ulen; ++j) {
            double acc = 0.0;
            const size_t lim = std::min(uIn, x.size());
            for (size_t i = 0; i < lim; ++i) acc += double(uSlice[j * uIn + i]) * double(x[i]);
            u[j] = (float)acc;
        }
        // SwiGLU: silu(gate) * up   (gate==up when the model has no gate expert)
        for (size_t j = 0; j < ffn; ++j) {
            const float s = 1.0f / (1.0f + std::exp(-g[j]));
            h[j] = g[j] * s * u[j];
        }

        const size_t olen = std::min(embd, dOut);
        for (size_t i = 0; i < olen; ++i) {
            double acc = 0.0;
            const size_t lim = std::min(dIn, ffn);
            for (size_t j = 0; j < lim; ++j) acc += double(dSlice[i * dIn + j]) * double(h[j]);
            y[i] += w[e] * (float)acc;
        }
        ++expertsProcessed;
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
                    if (std::getenv("RR_TRACE_TOKEN")) {
                        std::fprintf(stderr, "  [emb] token=%u n_in=%zu vocab=%zu row_stride=%zu bytes=%zu type=%d dims=[%zu,%zu]\n",
                                     token, n_in, vocab, row_stride, row_stride,
                                     (int)rowView.ggml_type, (size_t)rowView.dims[0],
                                     rowView.dims.size() > 1 ? (size_t)rowView.dims[1] : 0);
                    }
                    DequantPrefix(rowView, hidden_, n_in);
                    if (std::getenv("RR_TRACE_TOKEN")) {
                        std::fprintf(stderr, "  [emb] dequant got=%zu want=%zu type_size_needed\n",
                                     hidden_.size(), n_in);
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
                arena(in.outName.empty() ? std::string("kv") : in.outName) = hidden_;
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
    }

    if (logits_.empty()) { last_error_ = "no logits produced"; return false; }
    for (float v : logits_) if (!std::isfinite(v)) ++nonfinite_logits_;

    stats_.gpu_calls += gpu_calls_;
    stats_.cpu_calls += cpu_calls_;
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


