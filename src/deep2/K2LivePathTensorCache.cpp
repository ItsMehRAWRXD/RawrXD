// K2LivePathTensorCache.cpp — LRU + ownership-split counters
#include "K2LivePathTensorCache.hpp"
#include "K2LivePathOwnership.hpp"
#include <cstdlib>
#include <list>
#include <mutex>
#include <unordered_map>

namespace Deep2 {
namespace {
struct Entry { std::string name; std::vector<uint8_t> bytes; };
std::mutex g_mu;
std::list<Entry> g_lru;
std::unordered_map<std::string, std::list<Entry>::iterator> g_map;
uint64_t g_budget = 256ull << 20, g_bytes = 0, g_bytesPeak = 0;
uint64_t g_hits = 0, g_misses = 0, g_bytesSaved = 0;
uint64_t g_evictN = 0, g_evictBytes = 0;
uint64_t g_pfAcc = 0, g_pfSup = 0, g_pfRes = 0;
uint64_t g_warmBytes = 0, g_outW = 0;
uint32_t g_entriesPeak = 0;
uint64_t g_trampHits = 0, g_trampSaved = 0;
uint64_t g_layerAcq = 0, g_layerHits = 0, g_elasticHits = 0;
uint64_t g_dup = 0, g_dupBytes = 0, g_waitUs = 0;

bool IsMlaAttnSticky(const std::string& name) {
    // Keep host mirror of GPU-pinned MLA weights — kills SHARD_READ after warm.
    if (name.size() < 8 || name.compare(0, 4, "blk.") != 0) return false;
    return name.find(".attn_q_a") != std::string::npos ||
           name.find(".attn_q_b") != std::string::npos ||
           name.find(".attn_kv_a") != std::string::npos ||
           name.find(".attn_k_b") != std::string::npos ||
           name.find(".attn_v_b") != std::string::npos ||
           name.find(".attn_kv_b") != std::string::npos ||
           name.find(".attn_output") != std::string::npos ||
           name.find(".attn_norm") != std::string::npos;
}

bool IsOutputSticky(const std::string& name) {
    return name == "output.weight" || name == "output_norm.weight";
}

bool IsSticky(const std::string& name) {
    return IsMlaAttnSticky(name) || IsOutputSticky(name);
}

void EvictOne() {
    if (g_lru.empty()) return;
    // Never evict pinned output.weight or sticky MLA attn (GPU pin twin).
    for (auto it = g_lru.end(); it != g_lru.begin();) {
        --it;
        if (it->name == "output.weight") continue;
        if (IsSticky(it->name)) continue;
        g_evictBytes += it->bytes.size();
        g_evictN++;
        g_bytes -= it->bytes.size();
        g_map.erase(it->name);
        g_lru.erase(it);
        return;
    }
}
void TouchPeaks() {
    if (g_bytes > g_bytesPeak) g_bytesPeak = g_bytes;
    const uint32_t e = (uint32_t)g_map.size();
    if (e > g_entriesPeak) g_entriesPeak = e;
}
} // namespace

bool K2LiveCache_Wanted() {
    return K2LiveCache_OwnsOutput() || K2LiveCache_OwnsLayer();
}

bool K2LiveCache_LayerHostFillAllowed() {
    if (!K2LiveCache_OwnsLayer()) return false;
    // Layer-only arms: fill freely under budget.
    if (!K2LiveCache_OwnsOutput()) return true;
    // Shared with trampoline: reserve output.weight, then fill an *active*
    // working set (lookahead), not a fictional full-61 stack — that veto
    // forced SHARD_READ every token after warm (reverse-manifest blocker).
    std::lock_guard<std::mutex> lock(g_mu);
    const uint64_t outReserve = g_outW ? g_outW : 963379200ull;
    const uint64_t rem = (g_budget > outReserve) ? (g_budget - outReserve) : 0;
    constexpr uint64_t kPerLayer = 55300000ull;
    uint32_t depth = 61;
    if (const char* e = std::getenv("RAWRXD_K2_LAYERS")) {
        const int d = std::atoi(e);
        if (d > 0 && d <= 128) depth = (uint32_t)d;
    }
    uint32_t la = 3;
    if (const char* e = std::getenv("DEEP2_ELASTIC_LOOKAHEAD")) {
        const int v = std::atoi(e);
        if (v > 0 && v <= 32) la = (uint32_t)v;
    }
    if (la > depth) la = depth;
    // GPU MLA pin owns compute residency — host cache only avoids SHARD I/O.
    // Allow fill when rem covers active WS (or a single layer under pressure).
    const uint64_t need = kPerLayer * (uint64_t)la;
    if (rem >= need) return true;
    return rem >= kPerLayer;
}

void K2LiveCache_Reset(uint64_t budgetBytes) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_lru.clear(); g_map.clear();
    g_bytes = g_bytesPeak = g_hits = g_misses = g_bytesSaved = 0;
    g_evictN = g_evictBytes = g_pfAcc = g_pfSup = g_pfRes = 0;
    g_warmBytes = g_outW = 0; g_entriesPeak = 0;
    g_trampHits = g_trampSaved = g_layerAcq = g_layerHits = g_elasticHits = 0;
    g_dup = g_dupBytes = g_waitUs = 0;
    g_budget = budgetBytes ? budgetBytes : (256ull << 20);
}

void K2LiveCache_Clear() {
    // REQUESTLESS ≠ STATELESS MODEL: drop request-ephemeral only.
    // Sticky MLA attn + output.weight survive generateStream teardown so the
    // timed arm borrows retained bytes (SHARD_ATTN → 0) instead of rereading.
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto it = g_lru.begin(); it != g_lru.end();) {
        if (IsMlaAttnSticky(it->name) || it->name == "output.weight" ||
            it->name == "output_norm.weight") {
            ++it;
            continue;
        }
        g_bytes -= it->bytes.size();
        g_map.erase(it->name);
        it = g_lru.erase(it);
    }
}

bool K2LiveCache_TryGet(const std::string& name, const uint8_t*& data, size_t& n) {
    // Sticky MLA / output readable without LivePath MayCache (retained twin).
    if (!IsSticky(name) && !K2LiveCache_MayCache(name.c_str()))
        return false;
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_map.find(name);
    if (it == g_map.end()) { g_misses++; return false; }
    g_lru.splice(g_lru.begin(), g_lru, it->second);
    data = it->second->bytes.data();
    n = it->second->bytes.size();
    g_hits++;
    return true;
}

bool K2LiveCache_Put(const std::string& name, const uint8_t* data, size_t n) {
    const bool sticky = IsSticky(name);
    // Sticky: allow insert even if LivePath ownership not yet armed.
    if (!sticky && !K2LiveCache_MayCache(name.c_str())) return false;
    if (!data || !n) return false;
    if (!sticky && n > g_budget) return false;
    if (sticky && n > (g_budget ? g_budget : (12288ull << 20)) + (2048ull << 20))
        return false;
    if (!sticky && K2LiveCache_IsLayerName(name.c_str()) &&
        !K2LiveCache_LayerHostFillAllowed())
        return false;
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_budget < (4096ull << 20) && sticky)
        g_budget = 12288ull << 20; // promote floor when first sticky arrives
    if (g_map.count(name)) {
        g_lru.splice(g_lru.begin(), g_lru, g_map[name]);
        g_pfSup++;
        return false; // already live — suppress (not a new acquire)
    }
    while (g_bytes + n > g_budget && !g_lru.empty()) {
        const size_t before = g_map.size();
        EvictOne();
        if (g_map.size() == before) break;
    }
    if (g_bytes + n > g_budget) {
        if (!sticky) return false;
        if (g_bytes + n > g_budget + (2048ull << 20)) return false;
    }
    g_lru.push_front(Entry{name, std::vector<uint8_t>(data, data + n)});
    g_map[name] = g_lru.begin();
    g_bytes += n;
    TouchPeaks();
    return true;
}

bool K2LiveCache_Has(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_map.find(name) != g_map.end();
}

void K2LiveCache_MarkWarm() {
    std::lock_guard<std::mutex> lock(g_mu); g_warmBytes = g_bytes;
}
void K2LiveCache_NotePrefetchAlready(uint64_t n) {
    std::lock_guard<std::mutex> lock(g_mu); g_pfRes += n;
}
void K2LiveCache_NotePrefetchAccepted(uint64_t n) {
    std::lock_guard<std::mutex> lock(g_mu); g_pfAcc += n; g_layerAcq += n;
}
void K2LiveCache_NotePrefetchSuppressed(uint64_t n) {
    std::lock_guard<std::mutex> lock(g_mu); g_pfSup += n;
}
void K2LiveCache_NoteOutputWeight(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(g_mu); g_outW = bytes;
}
void K2LiveCache_NoteBytesSaved(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(g_mu); g_bytesSaved += bytes;
}
void K2LiveCache_NoteTrampOutHit(uint64_t bytesSaved) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_trampHits++; g_trampSaved += bytesSaved; g_bytesSaved += bytesSaved;
}
void K2LiveCache_NoteLayerAcquire() {
    std::lock_guard<std::mutex> lock(g_mu); g_layerAcq++;
}
void K2LiveCache_NoteLayerHit(uint64_t bytesSaved) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_layerHits++; g_elasticHits++; g_bytesSaved += bytesSaved;
}
void K2LiveCache_NoteCombinedDup(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_dup++; g_dupBytes += bytes;
}
void K2LiveCache_NoteCombinedWaitUs(uint64_t us) {
    std::lock_guard<std::mutex> lock(g_mu); g_waitUs += us;
}

K2LiveCacheStats K2LiveCache_Snapshot() {
    std::lock_guard<std::mutex> lock(g_mu);
    K2LiveCacheStats s;
    s.budget = g_budget; s.bytes = g_bytes; s.bytesPeak = g_bytesPeak;
    s.entries = (uint32_t)g_map.size(); s.entriesPeak = g_entriesPeak;
    s.hits = g_hits; s.misses = g_misses; s.bytesSaved = g_bytesSaved;
    s.evictionCount = g_evictN; s.evictionBytes = g_evictBytes;
    s.prefetchAccepted = g_pfAcc; s.prefetchSuppressed = g_pfSup;
    s.prefetchAlreadyResident = g_pfRes;
    s.bytesAfterWarm = g_warmBytes; s.outputWeightBytes = g_outW;
    s.trampOutHits = g_trampHits; s.trampOutBytesSaved = g_trampSaved;
    s.cycloneLayerAcquires = g_layerAcq; s.cycloneLayerHits = g_layerHits;
    s.elasticResidentHits = g_elasticHits;
    s.combinedDupAcquires = g_dup; s.combinedRedundantBytes = g_dupBytes;
    s.combinedWaitUs = g_waitUs;
    return s;
}

uint64_t K2LiveCache_Bytes() { return g_bytes; }
uint64_t K2LiveCache_Hits() { return g_hits; }
uint64_t K2LiveCache_Misses() { return g_misses; }
uint32_t K2LiveCache_Entries() { return (uint32_t)g_map.size(); }
uint64_t K2LiveCache_Budget() { return g_budget; }

} // namespace Deep2
