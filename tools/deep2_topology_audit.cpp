// The per-layer topology audit.
//
// A model's blocks are not all the same. A hybrid model alternates between
// attention blocks and recurrent blocks, and the alternation is not
// necessarily a single transition in the middle: the blocks may be
// interleaved in any pattern, and the pattern is a property of the file, not
// something to be assumed.
//
// So this does not summarise. It records every layer: the kind of mixer it
// has, the normals it carries, the projections it carries and their shapes,
// and the recurrent state it needs. Then it looks at the sequence of layers
// and reports every transition between them, because a transition is where a
// lowering has to change and therefore where a lowering is most likely to
// be wrong.
//
// The state dimensions are derived from the file rather than assumed. The
// value width is what the block's output projection takes, the head count
// is what the decay bias is wide, and the head width is the value width
// divided by the head count. The state is the head count by the key head
// width by the value head width.
//
// It reads the header and the tensor directory. The weight payload is never
// read, so it is cheap on a model of any size, and it touches no device.
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
    uint64_t in() const { return dims.size() >= 1 ? dims[0] : 0; }
    uint64_t out() const { return dims.size() >= 2 ? dims[1] : (dims.empty() ? 0 : dims[0]); }
    std::string shape() const {
        std::string s;
        for (size_t i = 0; i < dims.size(); ++i) {
            if (i) s += "x";
            s += std::to_string(dims[i]);
        }
        return s;
    }
};

struct Kv {
    std::string key;
    std::string value;
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
            for (uint32_t d = 0; d < nDims; ++d) if (!read(f, t.dims[d])) return false;
            if (!read(f, t.type)) return false;
            if (!read(f, t.offset)) return false;
            tensors_.push_back(std::move(t));
        }
        return true;
    }
    const std::vector<Tensor>& tensors() const { return tensors_; }
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
    template <typename T> static bool readScalar(std::ifstream& f, T& v) {
        return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof(v)));
    }
    static bool readString(std::ifstream& f, std::string& out) {
        uint64_t len = 0;
        if (!read(f, len)) return false;
        if (len > (1u << 24)) return false;
        out.assign(static_cast<size_t>(len), '\0');
        if (len) return static_cast<bool>(f.read(out.data(), len));
        return true;
    }
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
                for (uint64_t i = 0; i < count; ++i) if (!readValue(f, sub, kv)) return false;
                return true;
            }
            case 10: case 11: { uint64_t v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            case 12: { double v = 0; if (!readScalar(f, v)) return false; kv.value = std::to_string(v); return true; }
            default: return false;
        }
    }
    uint64_t tensorCount_ = 0, kvCount_ = 0;
    std::vector<Tensor> tensors_;
    std::vector<Kv> kvs_;
};

// ---- the layer ------------------------------------------------------------

enum class Mixer { None, FullAttention, FusedAttention, GatedDelta, GatedDeltaFused, LatentAttention, SharedExpert };

const char* MixerName(Mixer m) {
    switch (m) {
        case Mixer::None: return "none";
        case Mixer::FullAttention: return "full attention";
        case Mixer::FusedAttention: return "fused qkv attention";
        case Mixer::GatedDelta: return "gated delta, own input projection";
        case Mixer::GatedDeltaFused: return "gated delta, fused input projection";
        case Mixer::LatentAttention: return "latent attention";
        case Mixer::SharedExpert: return "no mixer of its own";
    }
    return "?";
}

struct Layer {
    std::string index;
    std::string prefix;
    Mixer mixer = Mixer::None;
    uint64_t hidden = 0;
    uint64_t valueWidth = 0;
    uint64_t numHeads = 0;
    uint64_t headVDim = 0;
    uint64_t headKDim = 0;
    uint64_t stateElements = 0;
    std::vector<std::pair<std::string, std::string>> norms;
    std::vector<std::pair<std::string, std::string>> projections;
    std::vector<std::string> problems;
};

std::string BlockOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return {};
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return {};
    return name.substr(0, dot);
}

std::string PartOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return name;
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return name;
    return name.substr(dot + 1);
}

uint64_t WidthOf(const Tensor* t) {
    if (!t || t->dims.empty()) return 0;
    return t->dims[0];
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: deep2_topology_audit <model.gguf> [--every-layer]\n");
        return 2;
    }
    const std::string path = argv[1];
    const bool everyLayer = (argc > 2 && std::string(argv[2]) == "--every-layer");

    Gguf g;
    if (!g.open(path)) {
        std::printf("COULD NOT READ THE HEADER: %s\n", path.c_str());
        return 1;
    }

    // The blocks, in index order, with the parts each one carries.
    std::map<uint64_t, Layer> layers;
    for (const auto& t : g.tensors()) {
        const std::string block = BlockOf(t.name);
        if (block.empty()) continue;
        const size_t dot = block.find('.');
        uint64_t index = 0;
        try { index = std::stoull(block.substr(4, dot - 4)); } catch (...) { continue; }
        Layer& L = layers[index];
        L.index = block;
        L.prefix = block + ".";
        const std::string part = PartOf(t.name);
        if (part.find("norm") != std::string::npos && t.dims.size() == 1) {
            L.norms.emplace_back(part, t.shape());
        } else if (t.dims.size() >= 2) {
            L.projections.emplace_back(part, t.shape());
        }
    }

    // The mixer of each layer, decided from the parts the layer carries.
    //
    // The decision is made from the SET of parts, never from one tensor:
    // a layer is a gated delta because it has the gate and the recurrent
    // coefficients together, and deciding it from the fused projection alone
    // would call phi-3 a gated delta when it is an ordinary transformer.
    for (auto& [index, L] : layers) {
        std::set<std::string> parts;
        for (const auto& [n, s] : L.norms) parts.insert(n);
        for (const auto& [n, s] : L.projections) parts.insert(n);
        const bool hasQkv      = parts.count("attn_qkv.weight") > 0;
        const bool hasGate     = parts.count("attn_gate.weight") > 0;
        const bool hasSsmIn    = parts.count("ssm_in.weight") > 0;
        const bool hasSsmOut   = parts.count("ssm_out.weight") > 0;
        const bool hasSsmA     = parts.count("ssm_a") > 0;
        const bool hasSsmD     = parts.count("ssm_d") > 0;
        const bool hasRecurrent = hasSsmOut || hasSsmA || hasSsmD;
        const bool hasQa       = parts.count("attn_q_a.weight") > 0 ||
                                 parts.count("attn_kv_a_mqa.weight") > 0;
        const bool hasSeparateQ = parts.count("attn_q.weight") > 0;
        const bool hasFfnGate  = parts.count("ffn_gate.weight") > 0;

        if (hasQa) L.mixer = Mixer::LatentAttention;
        else if (hasRecurrent && hasGate && hasQkv) L.mixer = Mixer::GatedDeltaFused;
        else if (hasRecurrent && hasSsmIn) L.mixer = Mixer::GatedDelta;
        else if (hasSeparateQ) L.mixer = Mixer::FullAttention;
        else if (hasQkv) L.mixer = Mixer::FusedAttention;
        else if (hasFfnGate || !L.norms.empty()) L.mixer = Mixer::SharedExpert;

        // The hidden width: the attention norm is over the residual stream.
        for (const auto& [n, s] : L.norms) {
            if (n == "attn_norm.weight") { L.hidden = WidthOf(nullptr); }
        }
    }

    // The widths, from the tensors themselves.
    std::map<std::string, const Tensor*> byName;
    for (const auto& t : g.tensors()) byName[t.name] = &t;
    for (auto& [index, L] : layers) {
        auto get = [&](const std::string& part) -> const Tensor* {
            auto it = byName.find(L.prefix + part);
            return it == byName.end() ? nullptr : it->second;
        };
        const Tensor* attnNorm = get("attn_norm.weight");
        const Tensor* postNorm = get("post_attention_norm.weight");
        const Tensor* ffnNorm = get("ffn_norm.weight");
        L.hidden = WidthOf(attnNorm ? attnNorm : (postNorm ? postNorm : ffnNorm));

        // The value width: what the block's output projection takes in.
        const Tensor* outProj = get("attn_output.weight");
        if (!outProj) outProj = get("ssm_out.weight");
        if (outProj) L.valueWidth = outProj->in();

        // The head count: the decay bias is one entry per head.
        const Tensor* dtBias = get("ssm_dt.bias");
        if (dtBias && !dtBias->dims.empty()) L.numHeads = dtBias->dims[0];
        if (L.numHeads == 0) {
            const Tensor* ssmA = get("ssm_a");
            if (ssmA && ssmA->dims.size() >= 2) L.numHeads = ssmA->dims[1];
        }
        if (L.numHeads && L.valueWidth) L.headVDim = L.valueWidth / L.numHeads;

        // The key head width: the A and D matrices are square in it. They
        // are written as a one element vector or as a one by N row
        // depending on the converter, so both spellings are read.
        const Tensor* ssmA = get("ssm_a");
        if (ssmA && !ssmA->dims.empty()) {
            L.headKDim = (ssmA->dims.size() >= 2) ? ssmA->dims[ssmA->dims.size() - 1]
                                                  : ssmA->dims[0];
        }
        const Tensor* ssmD = get("ssm_d");
        if (ssmD && !ssmD->dims.empty()) {
            L.headKDim = (ssmD->dims.size() >= 2) ? ssmD->dims[ssmD->dims.size() - 1]
                                                  : ssmD->dims[0];
        }

        if (L.numHeads && L.headKDim && L.headVDim) {
            L.stateElements = L.numHeads * L.headKDim * L.headVDim;
        }

        // The checks that the shapes make possible.
        if (L.hidden) {
            for (const auto& [n, s] : L.norms) {
                if ((n == "attn_norm.weight" || n == "ffn_norm.weight" ||
                     n == "post_attention_norm.weight")) {
                    const uint64_t w = WidthOf(get(n.c_str()));
                    if (w && w != L.hidden) {
                        L.problems.push_back(n + " is " + std::to_string(w) +
                                             " wide, the residual stream is " +
                                             std::to_string(L.hidden));
                    }
                }
            }
        }
        if (L.mixer == Mixer::GatedDelta || L.mixer == Mixer::GatedDeltaFused) {
            if (!L.stateElements) {
                L.problems.push_back("the recurrent state dimensions could not be derived");
            }
            // The mixer is wider than the residual stream, and the output
            // projection is what brings it back. If the block has no
            // projection, the width cannot close.
            if (L.valueWidth && L.hidden && L.valueWidth != L.hidden && !outProj) {
                L.problems.push_back("the mixer is " + std::to_string(L.valueWidth) +
                                     " wide and the residual stream is " +
                                     std::to_string(L.hidden) +
                                     " and there is no output projection to bring it back");
            }
        }
    }

    // The report.
    const std::string arch = g.kvString("general.architecture");
    std::printf("=== %s ===\n", path.c_str());
    std::printf("  architecture : %s\n", arch.empty() ? "(none)" : arch.c_str());
    std::printf("  layers       : %zu\n", layers.size());
    std::printf("  tensors      : %zu\n", g.tensors().size());

    // The census.
    std::map<std::string, int> census;
    for (const auto& [i, L] : layers) census[MixerName(L.mixer)]++;
    std::printf("  mixers       :");
    for (const auto& [m, n] : census) std::printf("  %d x %s", n, m.c_str());
    std::printf("\n");

    // The transitions. A transition is where the lowering has to change,
    // and it is where a lowering is most likely to be wrong, so every one
    // of them is listed.
    std::printf("\n  the layer sequence and its transitions:\n");
    Mixer previous = Mixer::None;
    uint64_t previousIndex = 0;
    bool first = true;
    for (const auto& [i, L] : layers) {
        if (!first && L.mixer != previous) {
            std::printf("    transition at layer %llu: %s -> %s\n",
                        static_cast<unsigned long long>(i),
                        MixerName(previous), MixerName(L.mixer));
        }
        previous = L.mixer;
        previousIndex = i;
        first = false;
    }
    std::printf("    last layer %llu is %s\n", static_cast<unsigned long long>(previousIndex),
                MixerName(previous));

    // The recurrent state, once, because every gated layer of the same
    // shape needs the same one.
    for (const auto& [i, L] : layers) {
        if (L.stateElements) {
            std::printf("\n  recurrent state: %llu heads x %llu key head width x %llu value head width"
                        " = %llu elements per sequence\n",
                        static_cast<unsigned long long>(L.numHeads),
                        static_cast<unsigned long long>(L.headKDim),
                        static_cast<unsigned long long>(L.headVDim),
                        static_cast<unsigned long long>(L.stateElements));
            break;
        }
    }

    // The per-layer detail.
    if (everyLayer) {
        std::printf("\n  layer | mixer | hidden | value | state | problems\n");
        for (const auto& [i, L] : layers) {
            std::printf("  %-6llu | %-38s | %6llu | %6llu | %10llu | %s\n",
                        static_cast<unsigned long long>(i), MixerName(L.mixer),
                        static_cast<unsigned long long>(L.hidden),
                        static_cast<unsigned long long>(L.valueWidth),
                        static_cast<unsigned long long>(L.stateElements),
                        L.problems.empty() ? "" : L.problems.front().c_str());
        }
    }

    // The problems, which are the point of the audit.
    uint64_t problems = 0;
    for (const auto& [i, L] : layers) {
        for (const auto& p : L.problems) {
            std::printf("  [PROBLEM] layer %llu: %s\n",
                        static_cast<unsigned long long>(i), p.c_str());
            ++problems;
        }
    }
    std::printf("\n  %llu layer(s) with a shape problem\n",
                static_cast<unsigned long long>(problems));
    return problems ? 3 : 0;
}
