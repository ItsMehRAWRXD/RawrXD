// ProductExtensionRuntime_Toggles.cpp — persist enable/disable to disk.
#include "ProductExtensionRuntime_Internal.hpp"
#include <fstream>
#include <sstream>

namespace ProductExtensionRuntime {

bool PersistTogglesUnlocked() {
    std::filesystem::path p(TogglePath());
    if (p.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::trunc);
    if (!f) return false;
    f << "{\"toggles\":{";
    bool first = true;
    for (const auto& [id, e] : Exts()) {
        if (!first) f << ",";
        first = false;
        f << "\"" << Escape(id) << "\":" << (e.enabled ? "true" : "false");
    }
    f << "}}";
    return true;
}

bool LoadTogglesUnlocked() {
    std::ifstream f(TogglePath());
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string text = ss.str();
    for (auto& [id, e] : Exts()) {
        auto key = "\"" + id + "\"";
        auto pos = text.find(key);
        if (pos == std::string::npos) continue;
        auto colon = text.find(':', pos + key.size());
        if (colon == std::string::npos) continue;
        auto t = text.find("true", colon);
        auto fl = text.find("false", colon);
        if (t != std::string::npos && (fl == std::string::npos || t < fl))
            e.enabled = true;
        else if (fl != std::string::npos)
            e.enabled = false;
    }
    return true;
}

std::string Enable(const std::string& id, bool enabled) {
    std::lock_guard<std::mutex> lock(Mu());
    ScanUnlocked();
    auto it = Exts().find(id);
    if (it == Exts().end()) {
        return "{\"success\":false,\"error\":\"extension_not_found\",\"id\":\"" +
               Escape(id) + "\",\"adapter\":\"product_extension_runtime\"}";
    }
    it->second.enabled = enabled;
    bool ok = PersistTogglesUnlocked();
    return std::string("{\"success\":") + (ok ? "true" : "false") +
           ",\"id\":\"" + Escape(id) + "\",\"enabled\":" +
           (enabled ? "true" : "false") + ",\"persisted\":" +
           (ok ? "true" : "false") +
           ",\"adapter\":\"product_extension_runtime\"}";
}

} // namespace ProductExtensionRuntime
