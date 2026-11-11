// ============================================================================
// ModelOpenCompat.hpp - Deep2 source-only model open compatibility drop
//
// Purpose:
//   Keep model-open failures separated from generation/runtime claims by repairing
//   only facts directly derivable from GGUF metadata, tensor names, tensor shapes,
//   path layout, or GGUF magic. No network, no Ollama, no dependency add.
//
// Use site in Deep2Engine::loadModel():
//   1) before shard/path selection, call ResolveModelOpenPath(...)
//   2) after GGUFLoader::Load succeeds and before config guards, call
//      RepairMetadataFromTensors(firstShard.string(), ggufResult, stderr)
//
// Header-only: no new .obj, no CMake target change required.
// ============================================================================
#pragma once

#include "GGUFLoader.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace Deep2 {
namespace ModelOpenCompat {

struct ResolvedModelOpenPath {
    std::filesystem::path input;
    std::filesystem::path firstShard;
    std::filesystem::path shardDir;
    bool isDirectory = false;
    bool isMultiShard = false;
    bool isBlobDirect = false;
    bool selectedFromDirectory = false;
    std::string note;
    std::string error;
};

struct MetadataRepairReceipt {
    bool changed = false;
    bool inferredArchitecture = false;
    bool inferredVocab = false;
    bool inferredHidden = false;
    bool inferredLayers = false;
    bool inferredIntermediate = false;
    bool inferredHeads = false;
    bool inferredKVHeads = false;
};

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

inline bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool IsMmprojLike(const std::filesystem::path& p) {
    return Lower(p.filename().string()).find("mmproj") != std::string::npos;
}

inline bool HasGgufMagicAtStart(const std::filesystem::path& p) {
    FILE* f = nullptr;
#if defined(_WIN32)
    if (_wfopen_s(&f, p.wstring().c_str(), L"rb") != 0) f = nullptr;
#else
    f = std::fopen(p.string().c_str(), "rb");
#endif
    if (!f) return false;
    unsigned char magic[4] = {0, 0, 0, 0};
    const size_t got = std::fread(magic, 1, 4, f);
    std::fclose(f);
    return got == 4 && magic[0] == 'G' && magic[1] == 'G' &&
           magic[2] == 'U' && magic[3] == 'F';
}

inline bool IsBlobName(const std::filesystem::path& p) {
    const std::string name = Lower(p.filename().string());
    return name.rfind("sha256-", 0) == 0 || name.rfind("sha256:", 0) == 0;
}

inline bool IsModelCandidate(const std::filesystem::path& p) {
    if (IsMmprojLike(p)) return false;
    const std::string ext = Lower(p.extension().string());
    if (ext == ".gguf") return true;
    if (IsBlobName(p)) return HasGgufMagicAtStart(p);
    return false;
}

inline bool SplitStem(const std::filesystem::path& p,
                      std::string& prefix,
                      std::string& suffix,
                      size_t& ordinalWidth) {
    const std::string n = p.filename().string();
    const size_t of = n.find("-of-");
    if (of == std::string::npos || of == 0) return false;
    const size_t dash = n.rfind('-', of - 1);
    if (dash == std::string::npos || dash + 1 >= of) return false;
    const std::string ord = n.substr(dash + 1, of - dash - 1);
    if (ord.empty()) return false;
    for (unsigned char c : ord) {
        if (!std::isdigit(c)) return false;
    }
    prefix = n.substr(0, dash + 1);
    suffix = n.substr(of);
    ordinalWidth = ord.size();
    return true;
}

inline bool IsSplitPath(const std::filesystem::path& p) {
    std::string pre, suf;
    size_t width = 0;
    return SplitStem(p, pre, suf, width);
}

inline std::filesystem::path CanonicalFirstShard(const std::filesystem::path& p) {
    std::string pre, suf;
    size_t width = 0;
    if (!SplitStem(p, pre, suf, width)) return p;
    const std::filesystem::path dir = p.parent_path();
    const std::string firstOrdinal(width > 1 ? width - 1 : 0, '0');
    const std::filesystem::path canonical = dir / (pre + firstOrdinal + "1" + suf);
    std::error_code ec;
    if (std::filesystem::exists(canonical, ec) && !ec) return canonical;
    return p;
}

inline uintmax_t SafeFileSize(const std::filesystem::path& p) {
    std::error_code ec;
    const uintmax_t n = std::filesystem::file_size(p, ec);
    return ec ? 0 : n;
}

inline bool ResolveModelOpenPath(const std::string& rawPath, ResolvedModelOpenPath& out) {
    out = ResolvedModelOpenPath{};
    out.input = std::filesystem::path(rawPath);

    std::error_code ec;
    if (rawPath.empty()) {
        out.error = "empty model path";
        return false;
    }
    if (!std::filesystem::exists(out.input, ec) || ec) {
        out.error = "model path does not exist: " + rawPath;
        return false;
    }

    out.isDirectory = std::filesystem::is_directory(out.input, ec) && !ec;

    if (!out.isDirectory) {
        if (!IsModelCandidate(out.input)) {
            out.error = "file is not a GGUF/model blob candidate: " + rawPath;
            return false;
        }
        out.firstShard = CanonicalFirstShard(out.input);
        out.shardDir = out.firstShard.parent_path();
        out.isMultiShard = IsSplitPath(out.firstShard);
        out.isBlobDirect = IsBlobName(out.firstShard);
        out.note = out.isBlobDirect ? "blob-direct GGUF" :
                   (out.isMultiShard ? "split GGUF first shard" : "single GGUF");
        return true;
    }

    std::vector<std::filesystem::path> candidates;
    for (std::filesystem::directory_iterator it(out.input, ec), end; !ec && it != end; it.increment(ec)) {
        if (ec) break;
        std::error_code typeEc;
        if (it->is_regular_file(typeEc) && !typeEc && IsModelCandidate(it->path())) {
            candidates.push_back(it->path());
        }
    }
    if (candidates.empty()) {
        out.error = "directory contains no GGUF/model blob candidates: " + rawPath;
        return false;
    }
    std::sort(candidates.begin(), candidates.end());

    // Prefer canonical split set when present.
    for (const auto& c : candidates) {
        if (IsSplitPath(c)) {
            out.firstShard = CanonicalFirstShard(c);
            out.shardDir = out.firstShard.parent_path();
            out.isMultiShard = true;
            out.selectedFromDirectory = true;
            out.note = "directory split GGUF first shard";
            return true;
        }
    }

    if (candidates.size() == 1) {
        out.firstShard = candidates.front();
        out.shardDir = out.input;
        out.selectedFromDirectory = true;
        out.note = "directory single GGUF";
        return true;
    }

    // Compatibility fallback for directories containing several standalone quant files:
    // choose the largest GGUF. This only opens the model; it does not promote runtime
    // correctness or generation quality.
    auto best = std::max_element(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        return SafeFileSize(a) < SafeFileSize(b);
    });
    if (best == candidates.end()) {
        out.error = "could not choose model file from directory: " + rawPath;
        return false;
    }
    out.firstShard = *best;
    out.shardDir = out.input;
    out.selectedFromDirectory = true;
    out.note = "directory multi-standalone fallback: selected largest GGUF";
    return true;
}

inline int ExtractBlkIndex(const std::string& name) {
    const std::string needle = "blk.";
    const size_t p = name.find(needle);
    if (p == std::string::npos) return -1;
    size_t i = p + needle.size();
    if (i >= name.size() || !std::isdigit(static_cast<unsigned char>(name[i]))) return -1;
    int v = 0;
    while (i < name.size() && std::isdigit(static_cast<unsigned char>(name[i]))) {
        v = v * 10 + (name[i] - '0');
        ++i;
    }
    return v;
}

inline uint64_t Dim0(const TensorInfo& t) { return t.dimensions.size() >= 1 ? t.dimensions[0] : 0; }
inline uint64_t Dim1(const TensorInfo& t) { return t.dimensions.size() >= 2 ? t.dimensions[1] : 0; }

inline void InferEmbeddingFacts(ModelMetadata& m, const TensorInfo& t, MetadataRepairReceipt& r) {
    const uint64_t d0 = Dim0(t);
    const uint64_t d1 = Dim1(t);
    if (d0 == 0 || d1 == 0) return;

    uint64_t hidden = m.hiddenSize;
    uint64_t vocab = m.vocabSize;

    if (hidden != 0) {
        if (d0 == hidden) vocab = d1;
        else if (d1 == hidden) vocab = d0;
    } else if (vocab != 0) {
        if (d0 == vocab) hidden = d1;
        else if (d1 == vocab) hidden = d0;
    } else {
        vocab = std::max(d0, d1);
        hidden = std::min(d0, d1);
    }

    if (hidden > 0 && hidden <= std::numeric_limits<uint32_t>::max() && m.hiddenSize == 0) {
        m.hiddenSize = static_cast<uint32_t>(hidden);
        r.changed = r.inferredHidden = true;
    }
    if (vocab > 0 && vocab != hidden && vocab <= std::numeric_limits<uint32_t>::max() && m.vocabSize == 0) {
        m.vocabSize = static_cast<uint32_t>(vocab);
        r.changed = r.inferredVocab = true;
    }
}

inline void InferOutputFacts(ModelMetadata& m, const TensorInfo& t, MetadataRepairReceipt& r) {
    const uint64_t d0 = Dim0(t);
    const uint64_t d1 = Dim1(t);
    if (d0 == 0 || d1 == 0) return;
    if (m.vocabSize == 0) {
        const uint64_t vocab = std::max(d0, d1);
        if (vocab <= std::numeric_limits<uint32_t>::max()) {
            m.vocabSize = static_cast<uint32_t>(vocab);
            r.changed = r.inferredVocab = true;
        }
    }
    if (m.hiddenSize == 0) {
        const uint64_t hidden = std::min(d0, d1);
        if (hidden <= std::numeric_limits<uint32_t>::max()) {
            m.hiddenSize = static_cast<uint32_t>(hidden);
            r.changed = r.inferredHidden = true;
        }
    }
}

inline void InferIntermediateFacts(ModelMetadata& m, const TensorInfo& t, MetadataRepairReceipt& r) {
    if (t.dimensions.size() < 2) return;
    const std::string& n = t.name;
    uint64_t inter = 0;
    if (n.find("ffn_down.weight") != std::string::npos ||
        n.find("feed_forward.w2") != std::string::npos) {
        // Prefer down input width when present. Fused gate|up models can expose
        // ffn_up output as 2*inter; ffn_down owns the true intermediate width.
        inter = Dim0(t);
    } else if (m.intermediateSize != 0) {
        return;
    } else if (n.find("ffn_up.weight") != std::string::npos ||
               n.find("ffn_gate.weight") != std::string::npos ||
               n.find("feed_forward.w1") != std::string::npos ||
               n.find("feed_forward.w3") != std::string::npos) {
        inter = Dim1(t); // GGUF linear dims are [input, output]
    }
    if (inter > 0 && inter <= std::numeric_limits<uint32_t>::max()) {
        m.intermediateSize = static_cast<uint32_t>(inter);
        r.changed = r.inferredIntermediate = true;
    }
}

inline void InferHeadFacts(ModelMetadata& m, const TensorInfo& t, MetadataRepairReceipt& r) {
    if (m.hiddenSize == 0 || t.dimensions.size() < 2) return;
    const std::string& n = t.name;
    const uint64_t out = Dim1(t);

    if (m.numHeads == 0 &&
        (n.find("attn_q.weight") != std::string::npos || n.find("attn_qkv.weight") != std::string::npos)) {
        uint64_t qOut = out;
        if (n.find("attn_qkv.weight") != std::string::npos && qOut > m.hiddenSize) {
            qOut = m.hiddenSize; // fused qkv: Q lane is hidden-sized
        }
        if (qOut > 0 && m.keyLength > 0 && (qOut % m.keyLength) == 0) {
            const uint64_t heads = qOut / m.keyLength;
            if (heads > 0 && heads <= std::numeric_limits<uint32_t>::max()) {
                m.numHeads = static_cast<uint32_t>(heads);
                r.changed = r.inferredHeads = true;
            }
        }
    }

    if (m.numKeyValueHeads == 0 && m.numHeads != 0 && m.keyLength > 0 &&
        (n.find("attn_k.weight") != std::string::npos || n.find("attn_v.weight") != std::string::npos)) {
        if (out > 0 && (out % m.keyLength) == 0) {
            const uint64_t kv = out / m.keyLength;
            if (kv > 0 && kv <= m.numHeads && kv <= std::numeric_limits<uint32_t>::max()) {
                m.numKeyValueHeads = static_cast<uint32_t>(kv);
                r.changed = r.inferredKVHeads = true;
            }
        }
    }

    if (m.numKeyValueHeads == 0 && m.numHeads != 0 &&
        n.find("attn_qkv.weight") != std::string::npos && out > m.hiddenSize) {
        uint64_t headDim = m.keyLength;
        if (headDim == 0 && m.numHeads != 0) headDim = m.hiddenSize / m.numHeads;
        if (headDim > 0 && out >= m.hiddenSize) {
            const uint64_t rem = out - m.hiddenSize;
            if (rem > 0 && (rem % (2 * headDim)) == 0) {
                const uint64_t kv = rem / (2 * headDim);
                if (kv > 0 && kv <= m.numHeads && kv <= std::numeric_limits<uint32_t>::max()) {
                    m.numKeyValueHeads = static_cast<uint32_t>(kv);
                    r.changed = r.inferredKVHeads = true;
                }
            }
        }
    }
}

inline void InferArchitectureFromPath(const std::string& path, ModelMetadata& m, MetadataRepairReceipt& r) {
    if (!m.architecture.empty()) return;
    const std::string p = Lower(path);
    if (p.find("deepseek") != std::string::npos) m.architecture = "deepseek2";
    else if (p.find("gemma") != std::string::npos) m.architecture = "gemma3";
    else if (p.find("phi-3") != std::string::npos || p.find("phi3") != std::string::npos) m.architecture = "phi3";
    else if (p.find("qwen3") != std::string::npos) m.architecture = "qwen3";
    else if (p.find("qwen2") != std::string::npos) m.architecture = "qwen2";
    else if (p.find("llama") != std::string::npos) m.architecture = "llama";

    if (!m.architecture.empty()) {
        r.changed = r.inferredArchitecture = true;
    }
}

inline MetadataRepairReceipt RepairMetadataFromTensors(const std::string& modelPath,
                                                       GGUFLoadResult& load,
                                                       FILE* log = nullptr) {
    MetadataRepairReceipt r;
    ModelMetadata& m = load.metadata;

    InferArchitectureFromPath(modelPath, m, r);

    int maxLayer = -1;
    for (const TensorInfo& t : load.tensors) {
        const int li = ExtractBlkIndex(t.name);
        if (li > maxLayer) maxLayer = li;

        if (t.name == "token_embd.weight" ||
            t.name == "token_embeddings.weight" ||
            t.name == "model.embed_tokens.weight") {
            InferEmbeddingFacts(m, t, r);
        } else if (t.name == "output.weight" ||
                   t.name == "lm_head.weight" ||
                   t.name == "model.output.weight") {
            InferOutputFacts(m, t, r);
        } else if (t.name == "output_norm.weight" || t.name == "norm.weight" ||
                   t.name.find("attn_norm.weight") != std::string::npos) {
            if (m.hiddenSize == 0 && Dim0(t) > 0 && Dim0(t) <= std::numeric_limits<uint32_t>::max()) {
                m.hiddenSize = static_cast<uint32_t>(Dim0(t));
                r.changed = r.inferredHidden = true;
            }
        }

        InferIntermediateFacts(m, t, r);
        InferHeadFacts(m, t, r);
    }

    if (m.numLayers == 0 && maxLayer >= 0) {
        m.numLayers = static_cast<uint32_t>(maxLayer + 1);
        r.changed = r.inferredLayers = true;
    }

    if (m.vocabSize == 0 && !m.vocab.empty()) {
        m.vocabSize = static_cast<uint32_t>(m.vocab.size());
        r.changed = r.inferredVocab = true;
    }

    if (m.numKeyValueHeads == 0 && m.numHeads != 0) {
        // Compatibility fallback: MHA is a legal default only after tensor/meta
        // inference had no stronger KV fact. Deep2Engine still validates GQA.
        m.numKeyValueHeads = m.numHeads;
        r.changed = r.inferredKVHeads = true;
    }

    if (log && r.changed) {
        std::fprintf(log,
                     "[ModelOpenCompat] repaired metadata: arch=%d vocab=%d hidden=%d layers=%d inter=%d heads=%d kvHeads=%d\n",
                     r.inferredArchitecture ? 1 : 0,
                     r.inferredVocab ? 1 : 0,
                     r.inferredHidden ? 1 : 0,
                     r.inferredLayers ? 1 : 0,
                     r.inferredIntermediate ? 1 : 0,
                     r.inferredHeads ? 1 : 0,
                     r.inferredKVHeads ? 1 : 0);
    }

    return r;
}

inline bool OpenFactsSufficient(const GGUFLoadResult& load, std::string* whyNot = nullptr) {
    const ModelMetadata& m = load.metadata;
    if (m.vocabSize == 0) {
        if (whyNot) *whyNot = "vocabSize=0";
        return false;
    }
    if (m.hiddenSize == 0) {
        if (whyNot) *whyNot = "hiddenSize=0";
        return false;
    }
    if (m.numLayers == 0) {
        if (whyNot) *whyNot = "numLayers=0";
        return false;
    }
    if (m.numHeads == 0) {
        if (whyNot) *whyNot = "numHeads=0";
        return false;
    }
    if (m.numKeyValueHeads > m.numHeads) {
        if (whyNot) *whyNot = "numKeyValueHeads>numHeads";
        return false;
    }
    return true;
}

} // namespace ModelOpenCompat
} // namespace Deep2
