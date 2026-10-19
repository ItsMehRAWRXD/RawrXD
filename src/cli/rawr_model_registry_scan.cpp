// rawr_model_registry_scan.cpp — roots + recursive scan
#include "rawr_model_registry.hpp"
#include "rawr_model_registry_util.hpp"
#include <cstdlib>
#include <cstring>
#include <set>
#include <algorithm>

namespace rawr {

// ============================================================================
// Validation: skip vocabulary-only and invalid test fixtures
// ============================================================================
static bool IsVocabOnlyFile(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return lower.find("vocab") != std::string::npos;
}

static bool IsInvalidTestFixture(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    static const char* invalid[] = {
        "corrupt_header", "metadata_mismatch", "unsupported_quant",
        "proper", "chaos_test", "test2", "frag", "tinyllama_fresh",
        "_test_model", "unlock-125m-q2_k", "codestral22b", "synthetic_moe",
        "ministral3_q4_0", "phi-3-mini-4k-instruct.q4_k_m",
    };
    for (const char* bad : invalid) {
        if (lower.find(bad) != std::string::npos) return true;
    }
    return false;
}

static bool IsValidGGUFFile(const std::string& path) {
    // Reject vocab-only and invalid fixtures by name first
    std::string filename = path;
    size_t slash = filename.find_last_of("\\/");
    if (slash != std::string::npos) filename = filename.substr(slash + 1);
    if (IsVocabOnlyFile(filename)) return false;
    if (IsInvalidTestFixture(filename)) return false;
    // For .gguf extension files, verify GGUF magic at offset 0
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (lower.size() >= 5 && lower.compare(lower.size() - 5, 5, ".gguf") == 0) {
        return Deep2::GgufPath::MagicAtZero(path);
    }
    return true;
}

void ModelRegistry::collectRoots() {
    roots_.clear();
    auto push = [&](const char* r) {
        if (!r || !r[0]) return;
#ifdef _WIN32
        DWORD a = GetFileAttributesA(r);
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY))
            return;
#endif
        for (const auto& e : roots_)
            if (_stricmp(e.c_str(), r) == 0) return;
        roots_.emplace_back(r);
    };
    push("G:\\~dev\\rawrxd");
    push("G:\\~dev\\rawrxd\\models");
    push("G:\\~dev\\rawrxd\\rawrxd_test_models");
    push("G:\\OllamaModels");
    push("F:\\OllamaModels");
    push("F:\\models");
    push("F:\\models\\gguf");
    if (const char* home = std::getenv("USERPROFILE")) {
        std::string p = std::string(home) + "\\.ollama\\models";
        push(p.c_str());
    }
    if (const char* e = std::getenv("RAWR_MODEL_PATH")) push(e);
    if (const char* e = std::getenv("RAWRXD_MODEL_ROOT")) push(e);
}

void ModelRegistry::scanRoots() {
    entries_.clear();
    std::vector<Deep2::rawr_run::LocalModelUnit> units;
    for (const auto& r : roots_)
        Deep2::rawr_run::ScanDirRecursive(r.c_str(), 0, units);

    /* Also surface every local Ollama model:tag as a discoverable entry. */
    Deep2::rawr_run::CollectOllamaModelUnits(units);

    // Deduplicate by canonical resolved path
    std::set<std::string> seenPaths;

    for (const auto& u : units) {
        // Skip invalid files by name
        std::string filename = u.path;
        size_t slash = filename.find_last_of("\\/");
        if (slash != std::string::npos) filename = filename.substr(slash + 1);
        if (IsVocabOnlyFile(filename) || IsInvalidTestFixture(filename)) continue;

        ModelEntry e;
        e.name = u.alias;
        e.tag = "latest";
        e.path = u.path;
        e.shardCount = u.shards ? u.shards : 1;
        e.quantization = regutil::GuessQuant(u.alias.c_str());
        if (u.isDir || e.shardCount > 1) {
            uint32_t n = 0;
            e.sizeBytes = regutil::DirShardBytes(u.path.c_str(), n);
            if (n) e.shardCount = n;
            e.valid = e.sizeBytes > 0;
        } else {
            const char* p = u.path.c_str();
            bool isBlobPath = (std::strstr(p, "\\blobs\\") != nullptr);
            if (isBlobPath || Deep2::GgufPath::IsLoadableModelFile(u.path)) {
                if (!IsValidGGUFFile(u.path)) continue;
                e.valid = regutil::FileStat(u.path.c_str(), e.sizeBytes,
                                            e.modifiedTime);
            } else {
                std::string blob;
                if (Deep2::rawr_run::ResolveOllamaLocalBlob(u.path.c_str(), blob)) {
                    e.path = blob;
                    e.valid = regutil::FileStat(blob.c_str(), e.sizeBytes,
                                                e.modifiedTime);
                    if (e.valid && !Deep2::GgufPath::IsLoadableModelFile(e.path))
                        e.valid = false;
                } else {
                    e.valid = false;
                }
            }
        }
        if (!e.valid || e.path.empty()) continue;
        // Deduplicate by canonical path
        if (!seenPaths.insert(e.path).second) continue;
        e.id = regutil::CheapId(e.path.c_str(), e.sizeBytes, e.modifiedTime);
        if (e.architecture.empty()) e.architecture = "-";
        if (e.quantization.empty()) e.quantization = "-";
        entries_.push_back(std::move(e));
    }
}

} // namespace rawr
