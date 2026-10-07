#pragma once
/*
    DynamicPersistentModelManifest.hpp

    Header-only/no-new-object helper for RawrXD/Deep2 model digestion.

    Contract:
      - The model path is the only user-supplied stable locator.
      - Every architecture/topology/dimension/quant/authority field is derived
        from the exact file/shard set being opened.
      - Persisted manifests are keyed by model fingerprint, never shared by arch.
      - Runtime observations are emitted as overlays and never rewrite discovery
        authority unless a new digest runs.
*/

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 { struct GGUFLoadResult; struct ModelMetadata; struct ModelWeights; struct EngineConfig; }

namespace rawr::manifest_dyn {

enum class AttentionTopology : uint8_t {
    Unknown = 0,
    SplitQKV,
    FusedQKV,
    ProjectorBlock,
    MLA,
    Blocked
};

enum class FfnTopology : uint8_t {
    Unknown = 0,
    SplitGateUpDown,
    FusedGateUp,
    FusedGateUpDown,
    GemmaStyle,
    Blocked
};

struct TensorFact {
    std::string name;
    std::string role;
    std::string quant;
    std::vector<uint64_t> dims;
    uint64_t bytes = 0;
    uint64_t offset = 0;
};

struct LayerFact {
    uint32_t layer = 0;
    AttentionTopology attention = AttentionTopology::Unknown;
    FfnTopology ffn = FfnTopology::Unknown;
    std::string q;
    std::string k;
    std::string v;
    std::string o;
    std::string qkv;
    std::string projector;
    std::string gate;
    std::string up;
    std::string down;
    bool ready = false;
    std::string blockedAt;
};

struct ManifestFingerprint {
    uint64_t sizeBytes = 0;
    uint64_t writeTime = 0;
    uint64_t tensorNameHash = 1469598103934665603ull;
    uint64_t manifestVersion = 1;
};

struct DynamicManifest {
    std::string modelPath;       // stable locator only
    std::string modelId;         // derived from path/fingerprint
    std::string arch;            // derived from GGUF metadata/tensors
    ManifestFingerprint fp;

    uint64_t vocab = 0;
    uint64_t hidden = 0;
    uint64_t layers = 0;
    uint64_t heads = 0;
    uint64_t kvHeads = 0;
    uint64_t headDim = 0;
    uint64_t intermediate = 0;

    std::map<std::string, uint64_t> quantHistogram;
    std::map<std::string, std::string> root;
    std::vector<LayerFact> layerFacts;

    bool discoveryReady = false;
    bool runtimeOverlay = false;
    std::string blockedAt;
};

inline std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return s;
}

inline bool Contains(const std::string& hay, const char* needle) {
    return Lower(hay).find(needle) != std::string::npos;
}

inline void HashBytes(uint64_t& h, const void* p, size_t n) noexcept {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
}

inline uint64_t FileWriteTimePortable(const std::filesystem::path& p) {
    std::error_code ec;
    auto ft = std::filesystem::last_write_time(p, ec);
    if (ec) return 0;
    return (uint64_t)ft.time_since_epoch().count();
}

inline ManifestFingerprint FingerprintPath(const std::string& path) {
    ManifestFingerprint fp{};
    std::error_code ec;
    std::filesystem::path p(path);
    if (std::filesystem::is_regular_file(p, ec)) {
        fp.sizeBytes = (uint64_t)std::filesystem::file_size(p, ec);
        fp.writeTime = FileWriteTimePortable(p);
        HashBytes(fp.tensorNameHash, path.data(), path.size());
    } else if (std::filesystem::is_directory(p, ec)) {
        std::vector<std::filesystem::path> files;
        for (auto& e : std::filesystem::directory_iterator(p, ec)) {
            if (!e.is_regular_file(ec)) continue;
            auto ep = e.path();
            auto ext = Lower(ep.extension().string());
            auto nm = Lower(ep.filename().string());
            if (ext == ".gguf" || nm.find("sha256-") != std::string::npos)
                files.push_back(ep);
        }
        std::sort(files.begin(), files.end());
        for (const auto& f : files) {
            const std::string s = f.string();
            HashBytes(fp.tensorNameHash, s.data(), s.size());
            fp.sizeBytes += (uint64_t)std::filesystem::file_size(f, ec);
            fp.writeTime ^= FileWriteTimePortable(f);
        }
    }
    return fp;
}

inline std::string SanitizeFileComponent(std::string s) {
    for (char& c : s) {
        if (c == ':' || c == '\\' || c == '/' || c == '*' || c == '?' ||
            c == '"' || c == '<' || c == '>' || c == '|' || c <= 31)
            c = '_';
    }
    if (s.empty()) s = "model";
    return s;
}

inline std::string ManifestCachePath(const std::string& modelPath,
                                     const ManifestFingerprint& fp,
                                     const char* rootDir = nullptr) {
    std::filesystem::path base = rootDir && rootDir[0]
        ? std::filesystem::path(rootDir)
        : std::filesystem::path("evidence") / "RAWRXD_MODEL_MANIFESTS";
    std::ostringstream name;
    name << SanitizeFileComponent(std::filesystem::path(modelPath).filename().string())
         << "." << std::hex << fp.sizeBytes << "." << fp.writeTime
         << ".rmanifest.jsonl";
    return (base / name.str()).string();
}

inline const char* ToString(AttentionTopology t) noexcept {
    switch (t) {
    case AttentionTopology::SplitQKV: return "SPLIT_QKV";
    case AttentionTopology::FusedQKV: return "FUSED_QKV";
    case AttentionTopology::ProjectorBlock: return "PROJECTOR_BLOCK";
    case AttentionTopology::MLA: return "MLA";
    case AttentionTopology::Blocked: return "BLOCKED";
    default: return "UNKNOWN";
    }
}

inline const char* ToString(FfnTopology t) noexcept {
    switch (t) {
    case FfnTopology::SplitGateUpDown: return "SPLIT_GATE_UP_DOWN";
    case FfnTopology::FusedGateUp: return "FUSED_GATE_UP";
    case FfnTopology::FusedGateUpDown: return "FUSED_GATE_UP_DOWN";
    case FfnTopology::GemmaStyle: return "GEMMA_STYLE";
    case FfnTopology::Blocked: return "BLOCKED";
    default: return "UNKNOWN";
    }
}

inline int ParseBlkLayer(const std::string& name) {
    const std::string p = "blk.";
    size_t at = name.find(p);
    if (at == std::string::npos) return -1;
    at += p.size();
    size_t end = at;
    while (end < name.size() && std::isdigit((unsigned char)name[end])) ++end;
    if (end == at || end >= name.size() || name[end] != '.') return -1;
    return std::atoi(name.substr(at, end - at).c_str());
}

inline int ParseHfLayer(const std::string& name) {
    const std::string p = "model.layers.";
    size_t at = name.find(p);
    if (at == std::string::npos) return -1;
    at += p.size();
    size_t end = at;
    while (end < name.size() && std::isdigit((unsigned char)name[end])) ++end;
    if (end == at || end >= name.size() || name[end] != '.') return -1;
    return std::atoi(name.substr(at, end - at).c_str());
}

inline int ParseLayerIndex(const std::string& name) {
    int n = ParseBlkLayer(name);
    if (n >= 0) return n;
    return ParseHfLayer(name);
}

inline void TouchLayer(std::vector<LayerFact>& layers, uint32_t idx) {
    if (layers.size() <= idx) layers.resize((size_t)idx + 1);
    layers[idx].layer = idx;
}

inline void ClassifyTensorName(DynamicManifest& m, const std::string& name) {
    const std::string low = Lower(name);

    // Root aliases: no hardcoded model class, only observed tensor names.
    if (low == "token_embd.weight" || low == "model.embed_tokens.weight" ||
        low == "model.embeddings.weight" || low == "transformer.wte.weight") {
        m.root["embed"] = name;
        return;
    }
    if (low == "output_norm.weight" || low == "model.norm.weight" ||
        low == "norm.weight" || low == "transformer.ln_f.weight") {
        m.root["final_norm"] = name;
        return;
    }
    if (low == "output.weight" || low == "lm_head.weight") {
        m.root["lm_head"] = name;
        return;
    }

    int li = ParseLayerIndex(name);
    if (li < 0) return;
    TouchLayer(m.layerFacts, (uint32_t)li);
    LayerFact& lf = m.layerFacts[(size_t)li];

    if (Contains(low, "attn_qkv.weight") || Contains(low, "query_key_value.weight")) {
        lf.qkv = name;
        lf.attention = AttentionTopology::FusedQKV;
    } else if (Contains(low, "attn_q.weight") || Contains(low, "q_proj.weight")) {
        lf.q = name;
    } else if (Contains(low, "attn_k.weight") || Contains(low, "k_proj.weight")) {
        lf.k = name;
    } else if (Contains(low, "attn_v.weight") || Contains(low, "v_proj.weight")) {
        lf.v = name;
    } else if (Contains(low, "attn_o.weight") || Contains(low, "attn_output.weight") || Contains(low, "o_proj.weight")) {
        lf.o = name;
    } else if (Contains(low, ".proj.weight") && !Contains(low, "q_proj") &&
               !Contains(low, "k_proj") && !Contains(low, "v_proj") &&
               !Contains(low, "o_proj") && !Contains(low, "gate_proj") &&
               !Contains(low, "up_proj") && !Contains(low, "down_proj") &&
               !Contains(low, "model_proj")) {
        // PLE / projector-only token (blk.N.proj.weight). Record separately;
        // FinalizeLayerFacts prefers SplitQKV when q/k/v are also present.
        lf.projector = name;
        if (lf.qkv.empty()) lf.qkv = name;
    } else if (Contains(low, "ffn_gate.weight") || Contains(low, "gate_proj.weight")) {
        lf.gate = name;
    } else if (Contains(low, "ffn_up.weight") || Contains(low, "up_proj.weight")) {
        lf.up = name;
    } else if (Contains(low, "ffn_down.weight") || Contains(low, "down_proj.weight")) {
        lf.down = name;
    } else if (Contains(low, "kv_a") || Contains(low, "q_a") || Contains(low, "kv_b")) {
        lf.attention = AttentionTopology::MLA;
    } else if (Contains(low, "ssm_") || Contains(low, ".ssm.")) {
        /* Hybrid SSM layer (nemotron_h): no attn_q required. */
        if (lf.attention == AttentionTopology::Unknown)
            lf.attention = AttentionTopology::ProjectorBlock; /* reuse: non-attn OK */
    }
}

inline void FinalizeLayerFacts(DynamicManifest& m) {
    uint64_t ready = 0;
    const bool hybrid = Lower(m.arch).find("nemotron") != std::string::npos;
    for (LayerFact& lf : m.layerFacts) {
        // Prefer observed split/fused attention over projector when both exist
        // (Gemma4 E4B: every layer has attn_q/k/v AND blk.N.proj.weight PLE).
        if (!lf.q.empty() && !lf.k.empty() && !lf.v.empty())
            lf.attention = AttentionTopology::SplitQKV;
        else if (!lf.qkv.empty() && lf.projector.empty())
            lf.attention = AttentionTopology::FusedQKV;
        else if (!lf.qkv.empty() && lf.projector == lf.qkv)
            lf.attention = AttentionTopology::ProjectorBlock;
        else if (!lf.projector.empty() && lf.q.empty())
            lf.attention = AttentionTopology::ProjectorBlock;
        else if (lf.attention == AttentionTopology::MLA)
            ; // keep MLA
        else if (lf.attention == AttentionTopology::ProjectorBlock)
            ; // SSM-tagged
        else if (lf.attention == AttentionTopology::Unknown)
            lf.attention = AttentionTopology::Blocked;

        if (!lf.gate.empty() && !lf.up.empty() && !lf.down.empty())
            lf.ffn = FfnTopology::SplitGateUpDown;
        else if (lf.gate.empty() && !lf.up.empty() && !lf.down.empty())
            lf.ffn = FfnTopology::FusedGateUp; /* up+down MLP (nemotron FFN) */
        else if (!lf.gate.empty() || !lf.up.empty() || !lf.down.empty())
            lf.ffn = FfnTopology::Blocked;
        else
            lf.ffn = FfnTopology::Unknown;

        const bool attnOk = lf.attention == AttentionTopology::SplitQKV ||
                            lf.attention == AttentionTopology::FusedQKV ||
                            lf.attention == AttentionTopology::ProjectorBlock ||
                            lf.attention == AttentionTopology::MLA;
        const bool ffnOk = lf.ffn == FfnTopology::SplitGateUpDown ||
                           lf.ffn == FfnTopology::FusedGateUp ||
                           lf.ffn == FfnTopology::FusedGateUpDown ||
                           lf.ffn == FfnTopology::GemmaStyle ||
                           lf.ffn == FfnTopology::Unknown;
        /* Hybrid: FFN-only layer = no attn; SSM-only = Unknown FFN + Projector. */
        const bool hybridOk =
            hybrid && ((attnOk && ffnOk) ||
                       (ffnOk && lf.attention == AttentionTopology::Blocked &&
                        !lf.up.empty()) ||
                       (lf.attention == AttentionTopology::ProjectorBlock));
        lf.ready = hybrid ? (attnOk || hybridOk) && (ffnOk || hybrid) : (attnOk && ffnOk);
        if (hybrid && !lf.up.empty() && !lf.down.empty() &&
            lf.attention == AttentionTopology::Blocked) {
            lf.ready = true; /* FFN-only */
            lf.blockedAt.clear();
            ++ready;
            continue;
        }
        if (hybrid && lf.attention == AttentionTopology::ProjectorBlock) {
            lf.ready = true;
            lf.blockedAt.clear();
            ++ready;
            continue;
        }
        if (!attnOk) lf.blockedAt = "attn_q";
        else if (!ffnOk) lf.blockedAt = "ffn";
        else ++ready;
    }

    m.discoveryReady = !m.layerFacts.empty() && ready == m.layerFacts.size() &&
                       !m.root["embed"].empty();
    if (!m.discoveryReady) {
        if (m.root["embed"].empty()) m.blockedAt = "token_embd";
        else m.blockedAt = "layer_topology";
    }
}

inline std::string JEsc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"':  o += "\\\""; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default: o += c; break;
        }
    }
    return o;
}

inline void WriteManifestJsonl(const DynamicManifest& m, const std::string& outPath) {
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outPath).parent_path(), ec);
    std::ofstream f(outPath, std::ios::binary);
    if (!f) return;

    f << "{\"record\":\"model\",\"model_path\":\"" << JEsc(m.modelPath)
      << "\",\"model_id\":\"" << JEsc(m.modelId)
      << "\",\"arch\":\"" << JEsc(m.arch)
      << "\",\"vocab\":" << m.vocab
      << ",\"hidden\":" << m.hidden
      << ",\"layers\":" << m.layers
      << ",\"heads\":" << m.heads
      << ",\"kv_heads\":" << m.kvHeads
      << ",\"head_dim\":" << m.headDim
      << ",\"intermediate\":" << m.intermediate
      << ",\"size\":" << m.fp.sizeBytes
      << ",\"mtime\":" << m.fp.writeTime
      << ",\"ready\":" << (m.discoveryReady ? 1 : 0)
      << ",\"blocked_at\":\"" << JEsc(m.blockedAt) << "\"}\n";

    for (const auto& kv : m.root) {
        f << "{\"record\":\"root\",\"role\":\"" << JEsc(kv.first)
          << "\",\"tensor\":\"" << JEsc(kv.second) << "\"}\n";
    }

    for (const LayerFact& lf : m.layerFacts) {
        f << "{\"record\":\"layer\",\"layer\":" << lf.layer
          << ",\"attention\":\"" << ToString(lf.attention)
          << "\",\"ffn\":\"" << ToString(lf.ffn)
          << "\",\"q\":\"" << JEsc(lf.q)
          << "\",\"k\":\"" << JEsc(lf.k)
          << "\",\"v\":\"" << JEsc(lf.v)
          << "\",\"o\":\"" << JEsc(lf.o)
          << "\",\"qkv\":\"" << JEsc(lf.qkv)
          << "\",\"projector\":\"" << JEsc(lf.projector)
          << "\",\"gate\":\"" << JEsc(lf.gate)
          << "\",\"up\":\"" << JEsc(lf.up)
          << "\",\"down\":\"" << JEsc(lf.down)
          << "\",\"ready\":" << (lf.ready ? 1 : 0)
          << ",\"blocked_at\":\"" << JEsc(lf.blockedAt) << "\"}\n";
    }
}

inline void EmitSummary(const DynamicManifest& m, FILE* f) {
    if (!f) f = stderr;
    uint64_t split = 0, fused = 0, proj = 0, mla = 0, blocked = 0;
    uint64_t splitFfn = 0, fusedFfn = 0;
    for (const LayerFact& lf : m.layerFacts) {
        switch (lf.attention) {
        case AttentionTopology::SplitQKV: ++split; break;
        case AttentionTopology::FusedQKV: ++fused; break;
        case AttentionTopology::ProjectorBlock: ++proj; break;
        case AttentionTopology::MLA: ++mla; break;
        default: ++blocked; break;
        }
        if (lf.ffn == FfnTopology::SplitGateUpDown) ++splitFfn;
        if (lf.ffn == FfnTopology::FusedGateUp || lf.ffn == FfnTopology::FusedGateUpDown) ++fusedFfn;
    }
    std::fprintf(f,
        "MODEL_DIGESTION_STREAM_BEGIN=1\n"
        "MODEL_PATH=%s\nARCH=%s\n"
        "HIDDEN=%llu LAYERS=%llu HEADS=%llu KV_HEADS=%llu HEAD_DIM=%llu VOCAB=%llu INTERMEDIATE=%llu\n"
        "SPLIT_QKV_LAYERS=%llu FUSED_QKV_LAYERS=%llu PROJECTOR_BLOCK_LAYERS=%llu MLA_LAYERS=%llu BLOCKED_LAYERS=%llu\n"
        "SPLIT_FFN_LAYERS=%llu FUSED_FFN_LAYERS=%llu\n"
        "ROOT_EMBED=%s ROOT_FINAL_NORM=%s ROOT_LM_HEAD=%s\n"
        "MANIFEST_READY=%d BLOCKED_AT=%s\n"
        "AUTHORITY_CLASS=DISCOVERY_ONLY\nPROMOTE=0\n"
        "MODEL_DIGESTION_STREAM_END=1\n",
        m.modelPath.c_str(), m.arch.c_str(),
        (unsigned long long)m.hidden, (unsigned long long)m.layers,
        (unsigned long long)m.heads, (unsigned long long)m.kvHeads,
        (unsigned long long)m.headDim, (unsigned long long)m.vocab,
        (unsigned long long)m.intermediate,
        (unsigned long long)split, (unsigned long long)fused,
        (unsigned long long)proj, (unsigned long long)mla,
        (unsigned long long)blocked,
        (unsigned long long)splitFfn, (unsigned long long)fusedFfn,
        m.root.count("embed") ? m.root.at("embed").c_str() : "",
        m.root.count("final_norm") ? m.root.at("final_norm").c_str() : "",
        m.root.count("lm_head") ? m.root.at("lm_head").c_str() : "",
        m.discoveryReady ? 1 : 0,
        m.blockedAt.empty() ? "NONE" : m.blockedAt.c_str());
    std::fflush(f);
}

// Integration adapter: keep this thin so it can compile beside the current GGUF structs.
// Call after GGUFLoader::Load succeeds and before legacy BindLlamaSchema.
template <class GGUFResultT>
inline DynamicManifest DigestLoadedModel(const std::string& modelPath,
                                         const GGUFResultT& ggufResult,
                                         FILE* f = stderr) {
    DynamicManifest m{};
    m.modelPath = modelPath;
    m.fp = FingerprintPath(modelPath);

    const auto& meta = ggufResult.metadata;
    m.arch = meta.architecture;
    m.vocab = meta.vocabSize;
    m.hidden = meta.hiddenSize;
    m.layers = meta.numLayers;
    m.heads = meta.numHeads;
    m.kvHeads = meta.numKeyValueHeads;
    m.headDim = meta.numHeads ? (meta.hiddenSize / meta.numHeads) : 0;
    m.intermediate = meta.intermediateSize;

    std::ostringstream id;
    id << SanitizeFileComponent(std::filesystem::path(modelPath).filename().string())
       << ":" << std::hex << m.fp.sizeBytes << ":" << m.fp.writeTime;
    m.modelId = id.str();

    // Deep2 GGUFLoadResult::tensors is a vector<TensorInfo> with .name/.type/.dimensions.
    for (const auto& t : ggufResult.tensors) {
        const std::string& name = t.name;
        if (name.empty()) continue;
        HashBytes(m.fp.tensorNameHash, name.data(), name.size());
        ClassifyTensorName(m, name);
        std::ostringstream qt;
        qt << static_cast<unsigned>(t.type);
        m.quantHistogram[qt.str()]++;
    }

    if (m.layers == 0 && !m.layerFacts.empty())
        m.layers = m.layerFacts.size();

    FinalizeLayerFacts(m);
    const char* cacheRoot = std::getenv("RAWRXD_MANIFEST_CACHE");
    if (!cacheRoot || !cacheRoot[0])
        cacheRoot = "G:\\~dev\\rawrxd\\evidence\\RAWRXD_MODEL_MANIFESTS";
    const std::string out = ManifestCachePath(modelPath, m.fp, cacheRoot);
    WriteManifestJsonl(m, out);
    EmitSummary(m, f);
    std::fprintf(f, "MODEL_DIGESTION_STREAM_CACHE=%s\n", out.c_str());
    std::fflush(f);
    return m;
}

inline void EmitRuntimeOverlayBegin(const DynamicManifest& m, const char* runId, FILE* f) {
    if (!f) f = stderr;
    std::fprintf(f,
        "MODEL_RUNTIME_OVERLAY_BEGIN=1\n"
        "MODEL_ID=%s\nRUN_ID=%s\n"
        "OVERLAY_MUTATES_DISCOVERY=0\nAUTHORITY_CLASS=RUNTIME_ONLY\nPROMOTE=0\n",
        m.modelId.c_str(), runId ? runId : "runtime");
}

inline void EmitRuntimeOverlayEnd(const DynamicManifest& m, const char* disposition,
                                  uint64_t tokensCommitted, FILE* f) {
    if (!f) f = stderr;
    std::fprintf(f,
        "MODEL_ID=%s\nTOKENS_COMMITTED=%llu\nRUNTIME_DISPOSITION=%s\n"
        "MODEL_RUNTIME_OVERLAY_END=1\n",
        m.modelId.c_str(), (unsigned long long)tokensCommitted,
        disposition ? disposition : "UNCLASSIFIED");
    std::fflush(f);
}

} // namespace rawr::manifest_dyn
