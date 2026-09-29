// KvPrefixAuthority.cpp — RAWRXD_KV_PREFIX_AUTHORITY_001
#include "KvPrefixAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
namespace rawrxd { namespace kv {
static std::atomic<int> g_saved{0};
static std::atomic<int> g_restored{0};
static std::atomic<int> g_validated{0};
static std::atomic<int> g_validationFails{0};
static std::unordered_map<std::string, std::string> g_prefixStore;
static std::mutex g_storeMutex;
static std::hash<std::string> g_hasher;
std::string fingerprintPrefix(const std::string& prefix) {
    return std::to_string(g_hasher(prefix));
}
bool savePrefix(const std::string& key, const std::string& fingerprint) {
    g_saved.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_storeMutex);
    g_prefixStore[key] = fingerprint;
    return true;
}
bool restorePrefix(const std::string& key) {
    g_restored.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_storeMutex);
    return g_prefixStore.count(key) > 0;
}
bool validatePrefix(const std::string& key, const std::string& expectedFingerprint) {
    g_validated.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_storeMutex);
    auto it = g_prefixStore.find(key);
    if (it == g_prefixStore.end()) { g_validationFails.fetch_add(1); return false; }
    if (it->second != expectedFingerprint) { g_validationFails.fetch_add(1); return false; }
    return true;
}
void writeKvPrefixReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_KV_PREFIX_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "PREFIXES_SAVED", g_saved.load());
    rawrxd::receipt::writeKeyValueInt(path, "PREFIXES_RESTORED", g_restored.load());
    rawrxd::receipt::writeKeyValueInt(path, "PREFIXES_VALIDATED", g_validated.load());
    rawrxd::receipt::writeKeyValueInt(path, "VALIDATION_FAILS", g_validationFails.load());
    rawrxd::receipt::endGate(path, (g_validationFails.load() == 0) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::kv