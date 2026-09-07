// RKCModelInventory.cpp — separate RAW_GGUF / OLLAMA_MANIFEST provenance
#include "RKCModelInventory.hpp"
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <filesystem>
#ifdef _WIN32
#include <string.h>
#define INV_STRICMP _stricmp
#else
#include <strings.h>
#define INV_STRICMP strcasecmp
#endif

namespace fs = std::filesystem;
namespace RawrXD {
namespace RKC {
namespace {

void PutReal(World& w, const std::string& k, const std::string& v,
             const std::string& src) {
    KnowledgeAtom a;
    a.key = k; a.value = v; a.state = EpistemicState::Real;
    a.kind = AtomKind::Fact; a.source = src;
    w.putAtom(a);
}

bool SkipTop(const std::string& name) {
    static const char* kSkip[] = {
        "blobs", "manifests", "logs", "build", "evidence", "crash_dumps",
        "llama.cpp", ".rawrxd", "profiles", "models", "ollama_store",
    };
    for (const char* s : kSkip)
        if (INV_STRICMP(name.c_str(), s) == 0) return true;
    return false;
}

std::string SanitizeId(std::string s) {
    for (char& c : s) {
        if (!(std::isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.'))
            c = '_';
    }
    if (s.size() > 96) s.resize(96);
    return s;
}

uint64_t SumGgufBytes(const fs::path& dir, uint32_t& shards) {
    shards = 0;
    uint64_t n = 0;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;
        if (e.path().extension() != ".gguf" && e.path().extension() != ".GGUF")
            continue;
        ++shards;
        n += (uint64_t)e.file_size(ec);
    }
    return n;
}

bool LooksLikeManifestJson(const std::string& text) {
    return text.find("\"schemaVersion\"") != std::string::npos ||
           text.find("application/vnd.ollama") != std::string::npos ||
           text.find("\"layers\"") != std::string::npos;
}

std::string SlurpHead(const fs::path& p, size_t cap = 4096) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::string s(cap, '\0');
    in.read(&s[0], (std::streamsize)cap);
    s.resize((size_t)in.gcount());
    return s;
}

void EmitEntry(World& w, const ModelInventoryEntry& e, const char* srcTag) {
    const std::string pref =
        std::string("inventory.") +
        (e.source == ModelSourceKind::RawGguf ? "raw_gguf." : "ollama_manifest.") +
        e.id;
    PutReal(w, pref + ".source", ModelSourceName(e.source), srcTag);
    PutReal(w, pref + ".path", e.path, srcTag);
    PutReal(w, pref + ".quant", e.quant, srcTag);
    PutReal(w, pref + ".architecture", e.architecture, srcTag);
    PutReal(w, pref + ".shard_count", std::to_string(e.shardCount), srcTag);
    PutReal(w, pref + ".corpus_bytes", std::to_string(e.corpusBytes), srcTag);
    PutReal(w, pref + ".header_valid", std::to_string(e.headerValid), srcTag);
    PutReal(w, pref + ".runtime_compat", std::to_string(e.runtimeCompat), srcTag);
}

void IngestRawLeaf(World& w, ModelInventoryStats& st, const fs::path& leaf,
                   const std::string& arch, const std::string& modelRoot) {
    uint32_t shards = 0;
    const uint64_t bytes = SumGgufBytes(leaf, shards);
    if (shards == 0) return;
    ModelInventoryEntry e;
    e.source = ModelSourceKind::RawGguf;
    e.quant = leaf.filename().string();
    e.architecture = arch;
    e.path = leaf.string();
    e.shardCount = shards;
    e.corpusBytes = bytes;
    e.headerValid = 1;
    e.runtimeCompat = 1;
    e.id = SanitizeId(arch + "." + e.quant);
    EmitEntry(w, e, "MODEL_SOURCE=RAW_GGUF");
    ++st.rawCount;
    st.rawCorpusBytes += bytes;
    const std::string low = arch;
    if (low.find("Kimi-K2") != std::string::npos ||
        low.find("kimi-k2") != std::string::npos)
        st.kimiRawFound = 1;
    (void)modelRoot;
}

} // namespace

const char* ModelSourceName(ModelSourceKind k) {
    return k == ModelSourceKind::OllamaManifest ? "OLLAMA_MANIFEST" : "RAW_GGUF";
}

ModelInventoryStats ObserveModelInventory(World& world,
                                          const std::string& modelRoot) {
    ModelInventoryStats st{};
    PutReal(world, "inventory.merge_forbidden", "1", "policy");
    PutReal(world, "inventory.root", modelRoot, "fs");

    std::error_code ec;
    if (!fs::is_directory(modelRoot, ec)) {
        KnowledgeAtom a;
        a.key = "inventory.root_exists";
        a.value = "0";
        a.state = EpistemicState::NotPresent;
        a.kind = AtomKind::Negative;
        a.source = "fs";
        world.putAtom(a);
        return st;
    }
    PutReal(world, "inventory.root_exists", "1", "fs");

    // RAW_GGUF: top-level families (skip blobs/manifests/…)
    for (auto& top : fs::directory_iterator(modelRoot, ec)) {
        if (ec || !top.is_directory(ec)) continue;
        const std::string name = top.path().filename().string();
        if (SkipTop(name)) continue;

        uint32_t directShards = 0;
        const uint64_t directBytes = SumGgufBytes(top.path(), directShards);
        if (directShards > 0) {
            IngestRawLeaf(world, st, top.path(), name, modelRoot);
            continue;
        }
        // Nested quant leaves (e.g. Kimi-K2/.../Q4_K_M)
        for (auto& sub : fs::directory_iterator(top.path(), ec)) {
            if (ec || !sub.is_directory(ec)) continue;
            IngestRawLeaf(world, st, sub.path(), name, modelRoot);
        }
    }

    // OLLAMA_MANIFEST: separate namespace — never merge with RAW_GGUF ids
    const fs::path manRoot = fs::path(modelRoot) / "manifests";
    if (fs::is_directory(manRoot, ec)) {
        for (auto it = fs::recursive_directory_iterator(manRoot, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            const fs::path p = it->path();
            const std::string text = SlurpHead(p);
            ModelInventoryEntry e;
            e.source = ModelSourceKind::OllamaManifest;
            e.path = p.string();
            e.quant = p.filename().string();
            e.architecture = p.parent_path().filename().string();
            e.shardCount = 0;
            e.corpusBytes = 0;
            e.headerValid = LooksLikeManifestJson(text) ? 1u : 0u;
            e.runtimeCompat = 0; // manifest ≠ Deep2 loader authority
            // Relative id under manifests/ keeps namespace disjoint from RAW ids
            std::string rel = fs::relative(p, manRoot, ec).string();
            for (char& c : rel) if (c == '\\') c = '/';
            e.id = SanitizeId(rel);
            EmitEntry(world, e, "MODEL_SOURCE=OLLAMA_MANIFEST");
            ++st.manifestCount;
        }
    }

    PutReal(world, "inventory.raw_count", std::to_string(st.rawCount), "fs");
    PutReal(world, "inventory.manifest_count",
            std::to_string(st.manifestCount), "fs");
    PutReal(world, "inventory.raw_corpus_bytes",
            std::to_string(st.rawCorpusBytes), "fs");
    return st;
}

} // namespace RKC
} // namespace RawrXD
