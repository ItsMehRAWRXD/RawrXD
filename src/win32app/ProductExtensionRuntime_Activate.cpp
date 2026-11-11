// ProductExtensionRuntime_Activate.cpp — activation + tool entry.
#include "ProductExtensionRuntime_Internal.hpp"

namespace ProductExtensionRuntime {

std::string Activate(const std::string& id) {
    std::lock_guard<std::mutex> lock(Mu());
    ScanUnlocked();
    auto it = Exts().find(id);
    if (it == Exts().end()) {
        for (auto& kv : Exts()) {
            if (kv.second.id == id || kv.second.name == id) {
                it = Exts().find(kv.second.id);
                break;
            }
        }
    }
    if (it == Exts().end()) {
        return "{\"success\":false,\"error\":\"extension_not_found\",\"id\":\"" +
               Escape(id) + "\",\"adapter\":\"product_extension_runtime\"}";
    }
    if (!it->second.enabled) {
        return "{\"success\":false,\"error\":\"extension_disabled\",\"id\":\"" +
               Escape(id) + "\",\"adapter\":\"product_extension_runtime\"}";
    }
    bool ok = SpawnHostUnlocked(it->second);
    if (!ok) {
        return "{\"success\":false,\"error\":\"host_spawn_failed\","
               "\"missing_dependency\":\"RawrXD-ExtensionHost.exe\","
               "\"host_pid\":0,\"id\":\"" + Escape(it->second.id) +
               "\",\"adapter\":\"product_extension_runtime\"}";
    }
    return "{\"success\":true,\"id\":\"" + Escape(it->second.id) +
           "\",\"active\":true,\"host_pid\":" +
           std::to_string(Host().hostPid) +
           ",\"adapter\":\"product_extension_runtime\"}";
}

bool ToolActivate(const std::string& id, std::string& outJson) {
    outJson = Activate(id);
    return outJson.find("\"success\":true") != std::string::npos;
}

} // namespace ProductExtensionRuntime
