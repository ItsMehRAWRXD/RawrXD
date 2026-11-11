// GhostCompletionContext.h — Stub for build compatibility
// Provides minimal GhostCompletionContext for Win32IDE compilation

#pragma once
#include <string>
#include <vector>
#include <optional>

namespace rawrxd {
namespace ghost_completion {

struct GhostCompletionContext {
    std::string filePath;
    int line = 0;
    int column = 0;
    std::vector<std::string> symbolNames;
    std::string surroundingLines;
    std::string language;
    std::string languageId;  // Added for Win32IDE compatibility
    bool lspRunning = false;
    std::string lspSymbolDigest;

    static GhostCompletionContext build(const std::string& path, int ln, int col,
                                         const std::vector<std::string>& syms,
                                         const std::string& surrounding,
                                         const std::string& lang, bool lspOk) {
        GhostCompletionContext ctx;
        ctx.filePath = path;
        ctx.line = ln;
        ctx.column = col;
        ctx.symbolNames = syms;
        ctx.surroundingLines = surrounding;
        ctx.language = lang;
        ctx.lspRunning = lspOk;
        return ctx;
    }
    
    std::string toPromptFragment(size_t maxLen = 4096) const {
        std::string result = filePath + ":" + std::to_string(line) + ":" + std::to_string(column) + "\n";
        result += "Language: " + language + "\n";
        if (!symbolNames.empty()) {
            result += "Symbols: ";
            for (const auto& s : symbolNames) {
                result += s + " ";
            }
            result += "\n";
        }
        result += surroundingLines.substr(0, maxLen);
        return result;
    }
};

// Ghost completion helper functions (stubs)
inline bool tryParseStructuredAiFixFromModelResponse(const std::string& response, std::string& fixPayload, std::string& explanation)
{
    (void)response;
    (void)fixPayload;
    (void)explanation;
    return false; // No-op stub
}

inline bool applyStructuredAiLineDiffsUtf8(const std::string& content, const std::string& diffs, std::string& result)
{
    (void)content;
    (void)diffs;
    (void)result;
    return false; // No-op stub
}

} // namespace ghost_completion
} // namespace rawrxd

// Non-namespaced aliases for legacy code
namespace rag_lite {
    inline void requestBackgroundScan(const char* path) { (void)path; }
    inline std::string buildPromptInjection(const char* content, const char* maxLen) { (void)content; (void)maxLen; return ""; }
}

namespace wal_gutter {
    inline int programmaticMutationDepth() { return 0; }
}

// Pulse cycle counter stub
inline uint64_t PulseGetCycles() { return 0; }

// Telemetry shim stubs (formatPagerLastLoadTelemetryReport is defined in sovereign_pager.h)
namespace sov {
    inline std::string formatPagerTelemetryReport() { return ""; }
}

// Vulkan compute stub - forward declaration (class VulkanCompute is defined in vulkan_compute.h)
// IsFlashAttentionFP8TiledPipelineReady() is a member function of VulkanCompute class

// VirtualAlloc reservation manager stubs
namespace RawrXD {
namespace Compression {
    inline int GetPreferredNumaNode() { return -1; }
    constexpr int kPreferredNumaNodeAuto = -1;
}
}

// IDM_TOOLS_KILL_BUILD_LOCKS stub
constexpr int IDM_TOOLS_KILL_BUILD_LOCKS = 0;

// END OF FILE
