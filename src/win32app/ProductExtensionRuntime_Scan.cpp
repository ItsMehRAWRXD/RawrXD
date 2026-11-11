// ProductExtensionRuntime_Scan.cpp — filesystem discovery (real).
#include "ProductExtensionRuntime_Internal.hpp"

namespace ProductExtensionRuntime {

static void ScanDir(const std::filesystem::path& root) {
    if (!std::filesystem::exists(root) || !std::filesystem::is_directory(root)) return;
    for (const auto& e : std::filesystem::directory_iterator(root)) {
        if (!e.is_directory()) continue;
        ExtRecord rec;
        if (!ReadPackageJson(e.path(), rec)) continue;
        auto& map = Exts();
        auto it = map.find(rec.id);
        if (it != map.end()) {
            rec.enabled = it->second.enabled;
            rec.active = it->second.active;
            rec.processId = it->second.processId;
        }
        map[rec.id] = rec;
    }
}

int ScanUnlocked() {
    // Load toggles AFTER ScanDir — Exts empty at entry makes LoadToggles a
    // no-op (first /scan lied enabled=true; second /list then applied disk).
    const std::string& pr = ProjectRoot();
    const std::string& ed = ExeDir();
    if (!pr.empty()) {
        ScanDir(std::filesystem::path(pr) / "extensions");
        ScanDir(std::filesystem::path(pr) / "evidence" /
                "EXTENSION_RUNTIME_MATRIX_002" / "fixtures" / "extensions");
    }
    if (!ed.empty()) ScanDir(std::filesystem::path(ed) / "extensions");
    LoadTogglesUnlocked();
    Host().extensionsLoaded = static_cast<int>(Exts().size());
    return Host().extensionsLoaded;
}

int Scan() {
    std::lock_guard<std::mutex> lock(Mu());
    return ScanUnlocked();
}

std::string ListJson() {
    std::lock_guard<std::mutex> lock(Mu());
    ScanUnlocked();
    std::string body = "{\"extensions\":[";
    bool first = true;
    for (const auto& [id, e] : Exts()) {
        if (!first) body += ",";
        first = false;
        body += "{\"id\":\"" + Escape(e.id) + "\",\"name\":\"" + Escape(e.name) +
                "\",\"version\":\"" + Escape(e.version) + "\",\"publisher\":\"" +
                Escape(e.publisher) + "\",\"path\":\"" + Escape(e.path) +
                "\",\"enabled\":" + (e.enabled ? "true" : "false") +
                ",\"active\":" + (e.active ? "true" : "false") + "}";
    }
    body += "],\"results\":[],\"total\":" + std::to_string(Exts().size()) +
            ",\"adapter\":\"product_extension_runtime\"}";
    return body;
}

std::vector<ExtRecord> ListRecords() {
    std::lock_guard<std::mutex> lock(Mu());
    ScanUnlocked();
    std::vector<ExtRecord> out;
    out.reserve(Exts().size());
    for (const auto& [id, e] : Exts()) out.push_back(e);
    return out;
}

} // namespace ProductExtensionRuntime
