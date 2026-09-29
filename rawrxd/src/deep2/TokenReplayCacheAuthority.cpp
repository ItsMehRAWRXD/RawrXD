// TokenReplayCacheAuthority.cpp — RAWRXD_TOKEN_REPLAY_CACHE_AUTHORITY_001
#include "TokenReplayCacheAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
namespace rawrxd { namespace cache {
static std::atomic<int> g_promptLookups{0};
static std::atomic<int> g_kvLookups{0};
static std::atomic<int> g_detOutputLookups{0};
static std::atomic<uint32_t> g_replayHits{0};
static std::unordered_map<std::string, bool> g_promptCache;
static std::unordered_map<std::string, bool> g_kvCache;
static std::unordered_map<std::string, bool> g_detCache;
static std::mutex g_cacheMutex;
bool lookupPromptPrefix(const std::string& prompt) {
    g_promptLookups.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_cacheMutex);
    return g_promptCache.count(prompt) > 0;
}
bool lookupKvPrefix(const std::string& kvKey) {
    g_kvLookups.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_cacheMutex);
    return g_kvCache.count(kvKey) > 0;
}
bool lookupDeterministicOutput(const std::string& prompt) {
    g_detOutputLookups.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_cacheMutex);
    return g_detCache.count(prompt) > 0;
}
void recordReplayHit(uint32_t count) { g_replayHits.fetch_add(count); }
void writeReplayReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_TOKEN_REPLAY_CACHE_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "PROMPT_LOOKUPS", g_promptLookups.load());
    rawrxd::receipt::writeKeyValueInt(path, "KV_LOOKUPS", g_kvLookups.load());
    rawrxd::receipt::writeKeyValueInt(path, "DET_OUTPUT_LOOKUPS", g_detOutputLookups.load());
    rawrxd::receipt::writeKeyValueInt(path, "REPLAY_HITS", (int64_t)g_replayHits.load());
    rawrxd::receipt::endGate(path, (g_replayHits.load() > 0) ? "PASS" : "HOLD");
}
}} // namespace rawrxd::cache