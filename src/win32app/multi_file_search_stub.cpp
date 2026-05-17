// Build-compat shim for legacy WIN32IDE_SOURCES wiring.
// The production implementation lives in src/multi_file_search.cpp.

#include "../../include/multi_file_search.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace {
std::atomic<uint64_t> g_multiFileSearchStubHits{0};
std::atomic<uint64_t> g_multiFileSearchStubQueryBytes{0};
std::atomic<uint64_t> g_multiFileSearchStubEmptyQueryCount{0};
std::atomic<uint64_t> g_multiFileSearchStubRegexEnabledCount{0};
std::atomic<uint64_t> g_multiFileSearchStubCaseSensitiveCount{0};
std::atomic<uint64_t> g_multiFileSearchStubFilterBytes{0};
std::atomic<uint64_t> g_multiFileSearchStubRootBytes{0};
std::atomic<uint64_t> g_multiFileSearchStubLastModeMask{0};

std::string configuredProbeQuery()
{
    if (const char* env = std::getenv("RAWRXD_MULTI_SEARCH_PROBE")) {
        return std::string(env);
    }
    return "anchor-probe";
}

bool envTruthy(const char* name)
{
    const char* v = std::getenv(name);
    if (!v) {
        return false;
    }
    const std::string s(v);
    return s == "1" || s == "true" || s == "TRUE" || s == "on" || s == "ON";
}

std::string configuredFileFilter()
{
    if (const char* env = std::getenv("RAWRXD_MULTI_SEARCH_FILTER")) {
        return std::string(env);
    }
    return "*.cpp,*.h";
}

std::string configuredProjectRoot()
{
    if (const char* env = std::getenv("RAWRXD_MULTI_SEARCH_ROOT")) {
        return std::string(env);
    }
    return "";
}
}

extern "C" void RawrXD_MultiFileSearchStubAnchor() {
    g_multiFileSearchStubHits.fetch_add(1, std::memory_order_relaxed);

    // Functional fallback: route through the real widget and track observable probe telemetry.
    MultiFileSearchWidget widget;
    const std::string root = configuredProjectRoot();
    if (!root.empty()) {
        widget.setProjectRoot(root);
    }
    const std::string filter = configuredFileFilter();
    widget.setFileFilter(filter);

    const bool regexEnabled = envTruthy("RAWRXD_MULTI_SEARCH_REGEX");
    const bool caseSensitive = envTruthy("RAWRXD_MULTI_SEARCH_CASE");
    widget.setUseRegex(regexEnabled);
    widget.setCaseSensitive(caseSensitive);

    const std::string query = configuredProbeQuery();
    widget.setSearchQuery(query);
    const std::string observed = widget.searchQuery();

    g_multiFileSearchStubQueryBytes.store(static_cast<uint64_t>(observed.size()), std::memory_order_relaxed);
    g_multiFileSearchStubFilterBytes.store(static_cast<uint64_t>(widget.fileFilter().size()), std::memory_order_relaxed);
    g_multiFileSearchStubRootBytes.store(static_cast<uint64_t>(widget.projectRoot().size()), std::memory_order_relaxed);
    if (observed.empty()) {
        g_multiFileSearchStubEmptyQueryCount.fetch_add(1, std::memory_order_relaxed);
    }
    if (widget.useRegex()) {
        g_multiFileSearchStubRegexEnabledCount.fetch_add(1, std::memory_order_relaxed);
    }
    if (widget.caseSensitive()) {
        g_multiFileSearchStubCaseSensitiveCount.fetch_add(1, std::memory_order_relaxed);
    }

    uint64_t modeMask = 0;
    if (widget.useRegex()) modeMask |= 0x1ULL;
    if (widget.caseSensitive()) modeMask |= 0x2ULL;
    if (!widget.projectRoot().empty()) modeMask |= 0x4ULL;
    if (!widget.fileFilter().empty()) modeMask |= 0x8ULL;
    g_multiFileSearchStubLastModeMask.store(modeMask, std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_MultiFileSearchStubHitCount() {
    return g_multiFileSearchStubHits.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_MultiFileSearchStubLastQueryBytes() {
    return g_multiFileSearchStubQueryBytes.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_MultiFileSearchStubEmptyQueryCount() {
    return g_multiFileSearchStubEmptyQueryCount.load(std::memory_order_relaxed);
}

extern "C" uint64_t RawrXD_MultiFileSearchStubStats() {
    // [63:56] case_count, [55:48] regex_count, [47:40] empty_count,
    // [39:32] hits, [31:24] mode_mask, [23:16] root_bytes, [15:8] filter_bytes, [7:0] query_bytes
    const uint64_t caseCnt = g_multiFileSearchStubCaseSensitiveCount.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t regexCnt = g_multiFileSearchStubRegexEnabledCount.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t emptyCnt = g_multiFileSearchStubEmptyQueryCount.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t hits = g_multiFileSearchStubHits.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t mode = g_multiFileSearchStubLastModeMask.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t rootBytes = g_multiFileSearchStubRootBytes.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t filterBytes = g_multiFileSearchStubFilterBytes.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t queryBytes = g_multiFileSearchStubQueryBytes.load(std::memory_order_relaxed) & 0xFFu;
    return (caseCnt << 56) | (regexCnt << 48) | (emptyCnt << 40) | (hits << 32) |
           (mode << 24) | (rootBytes << 16) | (filterBytes << 8) | queryBytes;
}
