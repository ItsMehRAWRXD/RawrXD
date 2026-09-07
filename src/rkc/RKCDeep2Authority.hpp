// RKCDeep2Authority.hpp — product model authority: RKC RAW_GGUF → Deep2 only
#pragma once
#include "RKCModelInventory.hpp"
#include "RKCWorld.hpp"
#include <cstdint>
#include <string>

namespace RawrXD {
namespace RKC {

struct Deep2AuthoritySelection {
    bool ok = false;
    std::string id;
    std::string path;
    std::string source; // must be "RAW_GGUF"
    uint32_t shardCount = 0;
    uint64_t corpusBytes = 0;
    const char* reason = "";
};

struct Deep2AuthorityRun {
    bool selected = false;
    bool opened = false;
    bool generated = false;
    bool ollamaRequired = false; // must stay false
    bool localProven = false;
    int32_t genTokenId = -1;
    double tps = 0;
    std::string text;
    std::string path;
    std::string id;
    const char* reason = "";
};

// Resolve inventory id → load path. Manifest IDs are rejected.
Deep2AuthoritySelection SelectDeep2Authority(const World& world,
                                             const std::string& inventoryId);

// Prefer exact id; else first RAW_GGUF with runtime_compat=1 matching needle.
Deep2AuthoritySelection SelectDeep2AuthorityPreferred(
    const World& world, const std::string& preferredId,
    const std::string& needleFallback);

// Open Deep2 on selected RAW path + short native stream (no :11434).
Deep2AuthorityRun AuthorizeDeep2Generate(const Deep2AuthoritySelection& sel,
                                         uint32_t depth, uint32_t tokens,
                                         const char* prompt);

} // namespace RKC
} // namespace RawrXD
