// RKCModelInventory.hpp — RAW_GGUF vs OLLAMA_MANIFEST (never name-merge)
#pragma once
#include "RKCWorld.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace RKC {

enum class ModelSourceKind : uint8_t {
    RawGguf = 1,
    OllamaManifest = 2,
};

struct ModelInventoryEntry {
    ModelSourceKind source = ModelSourceKind::RawGguf;
    std::string id;          // stable inventory id (not a merge key across sources)
    std::string path;
    std::string quant;       // best-effort leaf name
    std::string architecture;// best-effort parent/family token
    uint32_t shardCount = 0;
    uint64_t corpusBytes = 0;
    uint32_t headerValid = 0; // 1 if .gguf present or manifest JSON parses
    uint32_t runtimeCompat = 0; // 1 if RAW_GGUF with shards>0
};

struct ModelInventoryStats {
    uint32_t rawCount = 0;
    uint32_t manifestCount = 0;
    uint64_t rawCorpusBytes = 0;
    uint32_t kimiRawFound = 0;
};

// Ingest modelRoot (default F:\OllamaModels). Skips blobs/ as crawl target.
ModelInventoryStats ObserveModelInventory(World& world, const std::string& modelRoot);

const char* ModelSourceName(ModelSourceKind k);

} // namespace RKC
} // namespace RawrXD
