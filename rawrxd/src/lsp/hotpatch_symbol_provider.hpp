// ============================================================================
// hotpatch_symbol_provider.hpp — Symbol provider for LSP hotpatch queries
// Extracted from actual usage in auto_feature_registry.cpp
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Forward-declare PatchResult (defined in multiple core headers).
struct PatchResult;

namespace RawrXD {
namespace LSP {

struct SymbolInfo {
    const char* name     = nullptr;
    const char* detail   = nullptr;
    const char* filePath = nullptr;
    int         line     = 0;
    int         layer    = 0;
};

class HotpatchSymbolProvider {
public:
    static HotpatchSymbolProvider& instance();

    // Return all symbols currently known to the provider.
    std::vector<SymbolInfo> getAllSymbols() const;

    // Rebuild the symbol index (e.g., after a hotpatch is applied).
    PatchResult rebuildIndex();

private:
    HotpatchSymbolProvider() = default;
};

} // namespace LSP
} // namespace RawrXD
