// ToolRegistryAuthority.cpp — RAWRXD_TOOL_REGISTRY_AUTHORITY_001
#include "ToolRegistryAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
namespace rawrxd { namespace tools {
static std::atomic<int> g_registered{0};
static std::atomic<int> g_resolved{0};
static std::atomic<int> g_invoked{0};
static std::atomic<int> g_resolveFails{0};
static std::atomic<int> g_invokeFails{0};
static std::unordered_map<std::string, bool> g_registry;
static std::mutex g_regMutex;
bool registerTool(const std::string& name) {
    g_registered.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_regMutex);
    g_registry[name] = true;
    return true;
}
bool resolveTool(const std::string& name) {
    g_resolved.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_regMutex);
    if (g_registry.count(name) > 0 && g_registry[name]) return true;
    g_resolveFails.fetch_add(1);
    return false;
}
bool invokeTool(const std::string& name, const std::string& args) {
    g_invoked.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_regMutex);
    if (g_registry.count(name) > 0 && g_registry[name]) return true;
    g_invokeFails.fetch_add(1);
    return false;
}
void writeToolRegistryReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_TOOL_REGISTRY_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "TOOLS_REGISTERED", g_registered.load());
    rawrxd::receipt::writeKeyValueInt(path, "TOOLS_RESOLVED", g_resolved.load());
    rawrxd::receipt::writeKeyValueInt(path, "TOOLS_INVOKED", g_invoked.load());
    rawrxd::receipt::writeKeyValueInt(path, "RESOLVE_FAILS", g_resolveFails.load());
    rawrxd::receipt::writeKeyValueInt(path, "INVOKE_FAILS", g_invokeFails.load());
    rawrxd::receipt::endGate(path, (g_resolveFails.load() == 0 && g_invokeFails.load() == 0) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::tools