// ContextCrystallizationAuthority.cpp — RAWRXD_CONTEXT_CRYSTALLIZATION_AUTHORITY_001
#include "ContextCrystallizationAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
namespace rawrxd { namespace context {
static std::atomic<int> g_crystallized{0};
static std::atomic<int> g_reused{0};
static std::atomic<int> g_reuseMisses{0};
static std::unordered_map<std::string, bool> g_crystalStore;
static std::mutex g_storeMutex;
void crystallize(const std::string& contextId) {
    g_crystallized.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_storeMutex);
    g_crystalStore[contextId] = true;
}
bool reuseCrystallizedSlice(const std::string& contextId) {
    std::lock_guard<std::mutex> lk(g_storeMutex);
    if (g_crystalStore.count(contextId) > 0 && g_crystalStore[contextId]) {
        g_reused.fetch_add(1);
        return true;
    }
    g_reuseMisses.fetch_add(1);
    return false;
}
void writeCrystallizationReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_CONTEXT_CRYSTALLIZATION_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "CONTEXTS_CRYSTALLIZED", g_crystallized.load());
    rawrxd::receipt::writeKeyValueInt(path, "SLICES_REUSED", g_reused.load());
    rawrxd::receipt::writeKeyValueInt(path, "REUSE_MISSES", g_reuseMisses.load());
    rawrxd::receipt::endGate(path, (g_reused.load() > 0) ? "PASS" : "HOLD");
}
}} // namespace rawrxd::context