// ============================================================================
// [SOURCE] win32app\Win32IDE_PromptTemplates.cpp
// FILE: D:\rawrxd\src\win32app\Win32IDE_PromptTemplates.cpp
// ============================================================================

// Win32IDE_PromptTemplates.cpp — Top-50 A4: saved prompts/templates (in-house JSON)
// [CONSOLIDATED] #include "Win32IDE.h"
// [CONSOLIDATED] #include "../core/rawrxd_json.hpp"
// [SYSINCLUDE] #include <fstream>
// [SYSINCLUDE] #include <sstream>
#include <shlobj.h>
// [SYSINCLUDE] #include <vector>

namespace {

std::string getTemplatesPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string base(path);
        base += "\\RawrXD\\prompt_templates.json";
        return base;
    }
    return "prompt_templates.json";
}

} // namespace

std::vector<std::pair<std::string, std::string>> Win32IDE::getPromptTemplates() {
    std::vector<std::pair<std::string, std::string>> out;
    std::ifstream f(getTemplatesPath(), std::ios::binary);
    if (!f) return out;
    std::ostringstream ss;
    ss << f.rdbuf();
    try {
        RawrXD::JsonValue root = RawrXD::JsonValue::parse(ss.str());
        if (!root.is_object() || !root.contains("templates")) return out;
        const auto& arr = root["templates"].get_array();
        for (size_t i = 0; i < arr.size(); i++) {
            const auto& item = arr[i];
            if (!item.is_object() || !item.contains("name") || !item.contains("body")) continue;
            out.emplace_back(item["name"].get_string(), item["body"].get_string());
        }
    } catch (...) {}
    return out;
}

bool Win32IDE::savePromptTemplate(const std::string& name, const std::string& body) {
    auto existing = getPromptTemplates();
    bool found = false;
    for (auto& p : existing) {
        if (p.first == name) { p.second = body; found = true; break; }
    }
    if (!found) existing.emplace_back(name, body);
    RawrXD::JsonArray arr;
    for (const auto& p : existing)
        arr.push_back(RawrXD::JsonObject{{"name", RawrXD::JsonValue(p.first)}, {"body", RawrXD::JsonValue(p.second)}});
    RawrXD::JsonValue root(RawrXD::JsonObject{{"templates", RawrXD::JsonValue(std::move(arr))}});
    std::string dir = getTemplatesPath();
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos) {
        std::string d = dir.substr(0, slash);
        CreateDirectoryA(d.c_str(), nullptr);
    }
    std::ofstream f(dir, std::ios::binary);
    if (!f) return false;
    f << root.dump(true);
    return true;
}
