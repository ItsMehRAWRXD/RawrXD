// =============================================================================
// ModelCatalog.hpp — MODEL-CATALOG-001
// =============================================================================
// Single authority for model resolution. All surfaces (CLI, IDE, CEO, agent,
// tests) ask this — they do NOT independently scan disks.
//
// G:\OllamaModels is a FILE STORE only. No Ollama daemon / HTTP dependency.
// Deep2Engine::loadModel(resolved.absolutePath) remains the only load boundary.
// =============================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace rawrxd {
namespace models {

enum class StorageKind {
    Gguf,
    GgufShards,
    OllamaBlob,
    // Finish-hour aliases (same values)
    GgufFile = Gguf,
    GgufShardDirectory = GgufShards
};

inline const char* storageKindName(StorageKind k) {
    switch (k) {
    case StorageKind::Gguf: return "gguf";
    case StorageKind::GgufShards: return "gguf-shard-directory";
    case StorageKind::OllamaBlob: return "ollama-blob-file";
    }
    return "unknown";
}

struct ResolvedModel {
    std::string name; // friendly / query name
    std::string displayName; // filesystem basename (compat)
    std::filesystem::path absolutePath;
    std::filesystem::path path; // finish-hour alias of absolutePath
    StorageKind storageKind = StorageKind::Gguf;
    uint64_t blobOffset = 0;
    std::string sha256; // empty if unknown / not yet hashed
    std::string sourceRoot;
    std::filesystem::path manifestPath;
};

// Finish-hour / drop naming aliases
using ModelStorageKind = StorageKind;

class ModelCatalog {
public:
    static ModelCatalog& instance();

    // Static API used by RawrXD-Agentic / cert harnesses (finish-hour drop shape).
    static std::vector<std::filesystem::path> roots() {
        instance().refreshRoots();
        return instance().m_roots;
    }

    static std::optional<ResolvedModel> resolve(std::string spec) {
        instance().refreshRoots();
        return instance().resolveQuery(spec);
    }

    static std::vector<ResolvedModel> list(std::size_t maxResults = 256) {
        instance().refreshRoots();
        return instance().listModels(maxResults);
    }

    static bool hasGGUFMagic(const std::filesystem::path& path, std::uint64_t offset = 0);
    static std::optional<std::uint64_t> findGGUFOffset(
        const std::filesystem::path& path,
        std::uint64_t maxScanBytes = 64ull * 1024ull * 1024ull);

    // Rebuild root list from env + built-in precedence.
    void refreshRoots();

    // Explicit roots (tests / packaging). Does not clear env-driven roots unless replace=true.
    void setAdditionalRoots(std::vector<std::filesystem::path> roots, bool replace = false);

    const std::vector<std::filesystem::path>& rootsRef() const { return m_roots; }

    // Resolution precedence for `query`:
    //   1) absolute / relative existing path
    //   2) search each root for exact filename, dir name, or friendly match
    //   3) Ollama-style blobs/sha256-* under roots
    //   4) manifests/<name> → blob digest (best-effort)
    std::optional<ResolvedModel> resolveQuery(const std::string& query) const;

    // Enumerate candidate GGUF / shard dirs / blobs under configured roots (shallow+1).
    std::vector<ResolvedModel> listModels(size_t maxCount = 256) const;

    // Built-in precedence (also used by refreshRoots):
    //   RAWRXD_MODEL_ROOT → G:\OllamaModels → D:\OllamaModels →
    //   %USERPROFILE%\.ollama\models → F:\~dev\OllamaModels → other
    static std::vector<std::filesystem::path> defaultRoots();

private:
    ModelCatalog();

    std::optional<ResolvedModel> resolveExistingPath(const std::filesystem::path& p) const;
    std::optional<ResolvedModel> searchRoots(const std::string& query) const;
    std::optional<ResolvedModel> resolveManifestName(const std::string& friendly) const;
    static bool looksLikeSha256BlobName(const std::string& name);
    static std::optional<uint64_t> detectGgufOffset(const std::filesystem::path& path);
    static void syncPathAlias(ResolvedModel& m);

    std::vector<std::filesystem::path> m_roots;
    std::vector<std::filesystem::path> m_extraRoots;
};

} // namespace models
} // namespace rawrxd
