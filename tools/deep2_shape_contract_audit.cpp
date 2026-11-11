// The shape contract auditor.
//
// A GGUF file states the shape of every tensor it holds. Those shapes are
// not decoration: they say which operation each tensor belongs to, because
// an operation's operands have to agree on their width. A projection's
// input width is the width of what produced it, and its output width is the
// width of what consumes it.
//
// That makes the shapes a static check. This tool reads the tensor
// directory of a model, works out what each block is, and then walks the
// width chain of every block and reports every place where the chain does
// not close.
//
// The rule it applies is the one the Qwen3.5 failure turned on: the
// residual stream has one width, and every norm, projection and mixer in
// the block has to agree with it and with its neighbours. A block whose
// chain does not close is a block the engine will lower to the wrong
// operation, and the failure it produces is not at the offending tensor but
// later, as a width mismatch or a magnitude check somewhere downstream.
//
// It reads the header and the tensor directory. The weight payload is never
// read, so it is cheap on a model of any size.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

// ---- the GGUF reader ------------------------------------------------------

struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t offset = 0;
    // The first dimension is the input of a projection and the second is its
    // output, which is how ggml stores a matrix.
    uint64_t in() const { return dims.size() >= 1 ? dims[0] : 0; }
    uint64_t out() const { return dims.size() >= 2 ? dims[1] : (dims.empty() ? 0 : dims[0]); }
};

struct Kv {
    std::string key;
    std::string value;   // strings and numbers as text; arrays as their count
    bool isString = false;
};

class Gguf {
public:
    bool open(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        uint32_t magic = 0, version = 0;
        if (!read(f, magic) || magic != 0x46554747u) return false;
        if (!read(f, version)) return false;
        if (!read(f, tensorCount_) || !read(f, kvCount_)) return false;
        for (uint64_t i = 0; i < kvCount_; ++i) {
            Kv kv;
            if (!readString(f, kv.key)) return false;
            uint32_t type = 0;
            if (!read(f, type)) return false;
            if (!readValue(f, type, kv)) return false;
            kvs_.emplace_back(std::move(kv));
        }
        for (uint64_t i = 0; i < tensorCount_; ++i) {
            Tensor t;
            if (!readString(f, t.name)) return false;
            uint32_t nDims = 0;
            if (!read(f, nDims)) return false;
            if (nDims > 8) return false;
            t.dims.resize(nDims);
            for (uint32_t d = 0; d < nDims; ++d) {
                if (!read(f, t.dims[d])) return false;
            }
            if (!read(f, t.type)) return false;
            if (!read(f, t.offset)) return false;
            tensors_.push_back(std::move(t));
        }
        return true;
    }

    const std::vector<Tensor>& tensors() const { return tensors_; }
    const std::vector<Kv>& kvs() const { return kvs_; }

    std::string kvString(const std::string& key) const {
        for (const auto& kv : kvs_) if (kv.key == key && kv.isString) return kv.value;
        return {};
    }
    uint64_t kvNumber(const std::string& key, uint64_t fallback = 0) const {
        for (const auto& kv : kvs_) {
            if (kv.key == key && !kv.isString && !kv.value.empty()) {
                try { return std::stoull(kv.value); } catch (...) { return fallback; }
            }
        }
        return fallback;
    }

private:
    static bool read(std::ifstream& f, uint32_t& v) {
        return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof(v)));
    }
    static bool read(std::ifstream& f, uint64_t& v) {
        return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof(v)));
    }
    // The scalar types the key-value section can hold.
    template <typename T>
    static bool readScalar(std::ifstream& f, T& v) {
        return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof(v)));
    }
    static bool readString(std::ifstream& f, std::string& out) {
        uint64_t len = 0;
        if (!read(f, len)) return false;
        // A length that cannot be a string is a corrupt file, and the reader
        // stops rather than trying to allocate it.
        if (len > (1u << 24)) return false;
        out.assign(static_cast<size_t>(len), '\0');
        if (len) return static_cast<bool>(f.read(out.data(), len));
        return true;
    }
    // Reads a value and leaves the cursor after it. The value's text form is
    // kept for the keys that matter, and the others are skipped.
    static bool readValue(std::ifstream& f, uint32_t type, Kv& kv) {
        switch (type) {
            case 0: case 1: { uint8_t v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string((int)v); return true; }
            case 2: case 3: { uint16_t v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            case 4: case 5: { uint32_t v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            case 6: { float v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            case 7: { uint8_t v = 0; if (!readScalar(f, v)) return false; kv.value = v ? "true" : "false"; return true; }
            case 8: { std::string s; if (!readString(f, s)) return false; kv.value = s; kv.isString = true; return true; }
            case 9: {
                uint32_t sub = 0; uint64_t count = 0;
                if (!read(f, sub) || !read(f, count)) return false;
                kv.value = std::to_string(count);
                for (uint64_t i = 0; i < count; ++i) {
                    if (!readValue(f, sub, kv)) return false;
                }
                return true;
            }
            case 10: case 11: { uint64_t v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            case 12: { double v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            default: return false;
        }
    }

    uint64_t tensorCount_ = 0;
    uint64_t kvCount_ = 0;
    std::vector<Tensor> tensors_;
    std::vector<Kv> kvs_;
};

// ---- the block view --------------------------------------------------------

struct Finding {
    std::string severity;   // "VIOLATION" or "NOTE"
    std::string block;
    std::string what;
    std::string detail;
};

struct Auditor {
    std::vector<Finding> findings;
    uint64_t violations = 0;

    void violate(const std::string& block, const std::string& what, const std::string& detail) {
        findings.push_back({ "VIOLATION", block, what, detail });
        ++violations;
    }
    void note(const std::string& block, const std::string& what, const std::string& detail) {
        findings.push_back({ "NOTE", block, what, detail });
    }
};

// The block a tensor belongs to, from its name.
std::string BlockOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return {};
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return {};
    return name.substr(0, dot);
}

// The part of a block a tensor is, without the block prefix.
std::string PartOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return name;
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return name;
    return name.substr(dot + 1);
}

const Tensor* Find(const std::vector<Tensor>& ts, const std::string& name) {
    for (const auto& t : ts) if (t.name == name) return &t;
    return nullptr;
}

// The width a one-dimensional tensor holds.
uint64_t Width(const Tensor* t) {
    if (!t || t->dims.empty()) return 0;
    return t->dims[0];
}

void AuditBlock(const std::vector<Tensor>& all, const std::string& block, Auditor& out) {
    auto get = [&](const std::string& part) -> const Tensor* {
        return Find(all, block + "." + part);
    };

    // The hidden width. The attention norm is over the residual stream, so
    // it states the width of the stream.
    const Tensor* attnNorm = get("attn_norm.weight");
    uint64_t hidden = Width(attnNorm);
    if (hidden == 0) {
        const Tensor* outNorm = Find(all, "output_norm.weight");
        hidden = Width(outNorm);
    }
    if (hidden == 0) return;

    // Every norm over the RESIDUAL stream has to be the hidden width.
    //
    // Not every norm in the block is over the residual stream. The gated
    // hybrid family carries a norm of its own over the recurrent state, and
    // the full attention family carries a norm per head. Those are over
    // their own width and are not the residual's business.
    for (const auto& t : all) {
        if (BlockOf(t.name) != block) continue;
        const std::string part = PartOf(t.name);
        const bool overResidual = (part == "attn_norm.weight" ||
                                   part == "ffn_norm.weight" ||
                                   part == "post_attention_norm.weight");
        if (!overResidual) continue;
        if (t.dims.size() != 1) continue;
        if (t.dims[0] != hidden) {
            out.violate(block, "a norm over the residual stream is not the hidden width",
                        part + " is " + std::to_string(t.dims[0]) +
                        " wide, the residual stream is " + std::to_string(hidden));
        }
    }

    // The gated hybrid family: a fused q/k/v projection, a gate, and an
    // output projection. The mixer's value width is the gate's output
    // width, and the output projection has to take that width in.
    const Tensor* qkv = get("attn_qkv.weight");
    const Tensor* gate = get("attn_gate.weight");
    if (qkv && gate) {
        const uint64_t valueWidth = gate->out();
        if (valueWidth != hidden) {
            // The gate is wider than the stream. That is only correct if
            // there is a projection that brings it back, and that
            // projection has to take the gate's width in.
            const Tensor* outProj = get("ssm_out.weight");
            const Tensor* attnOut = get("attn_output.weight");
            const Tensor* proj = outProj ? outProj : attnOut;
            if (!proj) {
                out.violate(block, "the gated mixer is wider than the residual stream and nothing brings it back",
                            "attn_gate is " + std::to_string(valueWidth) + " wide, the residual stream is " +
                            std::to_string(hidden) + " wide, and there is no output projection");
            } else if (proj->in() != valueWidth) {
                out.violate(block, "the output projection does not take the mixer's width",
                            "the mixer is " + std::to_string(valueWidth) + " wide, the output projection takes " +
                            std::to_string(proj->in()));
            } else if (proj->out() != hidden) {
                out.violate(block, "the output projection does not return to the hidden width",
                            "the output projection is " + std::to_string(proj->out()) + " wide, the residual stream is " +
                            std::to_string(hidden) + " wide");
            }
        }
        // The fused projection has to be able to hold the q, the k and the
        // value, and the value is the gate's width.
        if (qkv->out() < valueWidth) {
            out.violate(block, "the fused projection is too narrow for the value it carries",
                        "attn_qkv is " + std::to_string(qkv->out()) + " wide and the value is " +
                        std::to_string(valueWidth) + " wide");
        }
    }

    // The full attention family: separate q, k and v, and an output
    // projection that has to take the value width in.
    const Tensor* vProj = get("attn_v.weight");
    const Tensor* attnOut = get("attn_output.weight");
    if (vProj && attnOut) {
        // The value width is the output of the v projection.
        const Tensor* vShape = vProj;
        uint64_t valueWidth = 0;
        // attn_v is stored as [in, num_v_heads, head_dim] in some writers
        // and as [in, out] in others; the output projection's input is the
        // authority.
        valueWidth = attnOut->in();
        if (vShape->out() != valueWidth && vShape->dims.size() >= 3) {
            const uint64_t heads = vShape->dims[1];
            const uint64_t headDim = vShape->dims[2];
            if (heads * headDim != valueWidth) {
                out.violate(block, "the value projection and the output projection disagree on the value width",
                            "attn_v is " + std::to_string(heads) + "x" + std::to_string(headDim) +
                            " = " + std::to_string(heads * headDim) + ", the output projection takes " +
                            std::to_string(valueWidth));
            }
        }
        if (attnOut->out() != hidden) {
            out.violate(block, "the attention output projection does not return to the hidden width",
                        "attn_output is " + std::to_string(attnOut->out()) + " wide, the residual stream is " +
                        std::to_string(hidden) + " wide");
        }
    }

    // The feed-forward path: the gate and the up projection share an input,
    // and the down projection takes their width and returns to the hidden.
    const Tensor* ffnGate = get("ffn_gate.weight");
    const Tensor* ffnUp = get("ffn_up.weight");
    const Tensor* ffnDown = get("ffn_down.weight");
    if (ffnGate && ffnUp && ffnDown) {
        if (ffnGate->in() != hidden) {
            out.violate(block, "the feed-forward gate does not take the hidden width",
                        "ffn_gate takes " + std::to_string(ffnGate->in()) + ", the residual stream is " +
                        std::to_string(hidden));
        }
        if (ffnUp->out() != ffnDown->in()) {
            out.violate(block, "the feed-forward up and down projections disagree",
                        "ffn_up is " + std::to_string(ffnUp->out()) + " wide, ffn_down takes " +
                        std::to_string(ffnDown->in()));
        }
        if (ffnDown->out() != hidden) {
            out.violate(block, "the feed-forward down projection does not return to the hidden width",
                        "ffn_down is " + std::to_string(ffnDown->out()) + " wide, the residual stream is " +
                        std::to_string(hidden));
        }
    }

    // The latent attention family: the query and the key and value are
    // compressed, and the value is expanded from a narrow latent.
    //
    // attn_output takes the expanded value in, so the value width is its
    // input width, and the expansion has to come from the value's own
    // projection.
    const Tensor* mlaOut = get("attn_output.weight");
    const Tensor* mlaVb = get("attn_v_b.weight");
    if (mlaOut && mlaVb) {
        if (mlaOut->out() != hidden) {
            out.violate(block, "the attention output projection does not return to the hidden width",
                        "attn_output is " + std::to_string(mlaOut->out()) +
                        " wide, the residual stream is " + std::to_string(hidden) + " wide");
        }
        if (mlaVb->dims.size() >= 3) {
            // The value projection is [latent, head_dim, heads].
            const uint64_t heads = mlaVb->dims[2];
            const uint64_t headDim = mlaVb->dims[1];
            if (heads * headDim != mlaOut->in()) {
                out.violate(block, "the value expansion and the output projection disagree",
                            "attn_v_b expands to " + std::to_string(heads * headDim) +
                            ", the output projection takes " + std::to_string(mlaOut->in()));
            }
        }
    }

    // The recurrent family: the conv is over the mixer's internal width and
    // the output projection has to take that width in.
    const Tensor* ssmOut = get("ssm_out.weight");
    const Tensor* conv = get("ssm_conv1d.weight");
    if (ssmOut && conv) {
        if (conv->dims.size() >= 2 && conv->dims[1] != ssmOut->in()) {
            out.note(block, "the recurrent convolution and the output projection are on different widths",
                     "ssm_conv1d is over " + std::to_string(conv->dims[1]) +
                     " channels, ssm_out takes " + std::to_string(ssmOut->in()));
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: deep2_shape_contract_audit <model.gguf> [model.gguf...]\n");
        return 2;
    }
    int rc = 0;
    for (int a = 1; a < argc; ++a) {
        const std::string path = argv[a];
        Gguf g;
        if (!g.open(path)) {
            // Why the file could not be read. A file that is not there and a
            // file whose header is not a GGUF are different problems and the
            // report has to say which one it is.
            const std::string why = [&] {
                std::ifstream probe(path, std::ios::binary);
                if (!probe.is_open()) return "the file could not be opened";
                uint32_t magic = 0;
                probe.read(reinterpret_cast<char*>(&magic), sizeof(magic));
                if (magic != 0x46554747u) return "the file does not begin with the GGUF magic";
                return "the header or the tensor directory could not be read";
            }();
            std::printf("=== %s ===\n  COULD NOT READ THE HEADER: %s\n\n", path.c_str(), why.c_str());
            rc = 1;
            continue;
        }
        const std::string arch = g.kvString("general.architecture");
        // The block count is not always stated under the general name, and
        // the blocks are countable from the tensors themselves.
        uint64_t blocks = g.kvNumber("general.block_count", 0);
        std::set<std::string> blockNames;
        for (const auto& t : g.tensors()) {
            const std::string b = BlockOf(t.name);
            if (!b.empty()) blockNames.insert(b);
        }
        if (blocks == 0) blocks = blockNames.size();
        std::printf("=== %s ===\n", path.c_str());
        std::printf("  architecture      : %s\n", arch.empty() ? "(none)" : arch.c_str());
        std::printf("  block_count       : %llu\n", static_cast<unsigned long long>(blocks));
        std::printf("  tensors           : %zu\n", g.tensors().size());

        // The block families present, which is the first thing a lowering
        // has to get right.
        //
        // The gated hybrid signature is the FUSED projection AND the gate
        // AND the recurrent coefficients, together. A fused qkv on its own
        // is only a fused qkv: phi-3 has one and is an ordinary dense
        // transformer. Classifying on the fused projection alone is how a
        // model gets lowered to an operation it does not have, which is the
        // same failure the auditor is looking for.
        //
        // There are two gated hybrids and they are not the same operation.
        // One fuses the recurrent input projection into the attention
        // projection and carries a gate; the other has a projection of its
        // own and no gate. They have different internal widths and they
        // have to be lowered differently.
        std::map<std::string, std::string> family;
        for (const auto& t : g.tensors()) {
            const std::string b = BlockOf(t.name);
            if (b.empty()) continue;
            const std::string part = PartOf(t.name);
            const bool hasRecurrent = (part == "ssm_a" || part == "ssm_alpha.weight" ||
                                       part == "ssm_beta.weight" || part == "ssm_dt.bias" ||
                                       part == "ssm_out.weight" || part == "ssm_in.weight" ||
                                       part == "ssm_d");
            const bool hasGate = (part == "attn_gate.weight");
            const bool hasFusedQkv = (part == "attn_qkv.weight");
            const bool hasSsmIn = (part == "ssm_in.weight");
            if (hasFusedQkv && hasGate && hasRecurrent) {
                family[b] = "gated hybrid, fused projection with a gate";
            } else if (hasSsmIn && hasRecurrent) {
                family[b] = "gated hybrid, recurrent with its own input projection";
            } else if (part == "attn_q_a.weight" || part == "attn_kv_a_mqa.weight" ||
                       part == "attn_q_b.weight" || part == "attn_k_b.weight" ||
                       part == "attn_v_b.weight") {
                family[b] = "latent attention (compressed q and kv)";
            } else if (part == "attn_q.weight" || part == "attn_k.weight" ||
                       part == "attn_v.weight") {
                if (family[b].empty()) family[b] = "full attention";
            } else if (hasFusedQkv) {
                if (family[b].empty()) family[b] = "fused qkv, no gate and no recurrent state";
            } else if (part.rfind("ple_", 0) == 0) {
                if (family[b].empty()) family[b] = "per-layer embedding";
            } else if (part.rfind("hc_", 0) == 0) {
                if (family[b].empty()) family[b] = "hyperconnection";
            }
        }
        // A block with no mixer at all is a shared-expert block: the
        // residual carries straight through it.
        for (const auto& b : blockNames) {
            if (family.count(b)) continue;
            bool anyNorm = false;
            for (const auto& t : g.tensors()) {
                if (BlockOf(t.name) != b) continue;
                const std::string part = PartOf(t.name);
                if (part == "attn_norm.weight" || part == "ffn_norm.weight" ||
                    part == "post_attention_norm.weight" || part == "ffn_up.weight" ||
                    part == "ffn_down.weight" || part == "ffn_gate.weight") { anyNorm = true; }
            }
            if (anyNorm) family[b] = "no mixer of its own (shared expert)";
        }
        std::map<std::string, int> familyCount;
        for (const auto& [b, f] : family) ++familyCount[f];
        std::printf("  block families    :");
        for (const auto& [f, n] : familyCount) std::printf("  %d x %s", n, f.c_str());
        std::printf("\n");

        Auditor auditor;
        for (const auto& b : blockNames) AuditBlock(g.tensors(), b, auditor);

        for (const auto& f : auditor.findings) {
            std::printf("  [%s] %s: %s\n", f.severity.c_str(), f.block.c_str(), f.what.c_str());
            std::printf("         %s\n", f.detail.c_str());
        }
        if (auditor.violations == 0) {
            std::printf("  the width chain closes on every block\n");
        } else {
            std::printf("  %llu shape contract violation(s)\n",
                        static_cast<unsigned long long>(auditor.violations));
        }
        std::printf("\n");
        if (auditor.violations) rc = 3;
    }
    return rc;
}
