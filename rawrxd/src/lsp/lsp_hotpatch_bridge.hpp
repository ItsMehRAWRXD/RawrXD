// ============================================================================
// lsp_hotpatch_bridge.hpp — LSP bridge for hotpatch integration
// Extracted from actual usage in auto_feature_registry.cpp
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <string>

// Forward-declare PatchResult (defined in multiple core headers).
struct PatchResult;

namespace RawrXD {
namespace LSP {

struct LSPStats {
    std::atomic<uint64_t> requestsHandled    { 0 };
    std::atomic<uint64_t> diagnosticRefreshes{ 0 };
    std::atomic<uint64_t> symbolRebuilds     { 0 };
};

class LSPHotpatchBridge {
public:
    static LSPHotpatchBridge& instance();

    bool isAttached() const { return attached_; }

    LSPStats& getStats() { return stats_; }
    const LSPStats& getStats() const { return stats_; }

    PatchResult detach();
    PatchResult refreshDiagnostics();
    PatchResult rebuildSymbolIndex();

private:
    LSPHotpatchBridge() = default;
    bool attached_ = false;
    LSPStats stats_;
};

} // namespace LSP
} // namespace RawrXD
