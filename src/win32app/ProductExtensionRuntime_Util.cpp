// ProductExtensionRuntime_Util.cpp — JSON escape + package.json read.
#include "ProductExtensionRuntime_Internal.hpp"
#include <fstream>
#include <sstream>

namespace ProductExtensionRuntime {

std::string Escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"' || c == '\\') o.push_back('\\');
        if (c == '\n' || c == '\r') { o.push_back(' '); continue; }
        o.push_back(c);
    }
    return o;
}

static std::string JsonStr(const std::string& text, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    auto p = text.find(pat);
    if (p == std::string::npos) return {};
    p = text.find(':', p + pat.size());
    if (p == std::string::npos) return {};
    p = text.find('"', p + 1);
    if (p == std::string::npos) return {};
    auto e = text.find('"', p + 1);
    if (e == std::string::npos) return {};
    return text.substr(p + 1, e - p - 1);
}

bool ReadPackageJson(const std::filesystem::path& dir, ExtRecord& out) {
    auto pkg = dir / "package.json";
    if (!std::filesystem::exists(pkg)) pkg = dir / "extension.json";
    if (!std::filesystem::exists(pkg)) return false;
    std::ifstream f(pkg);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string text = ss.str();
    if (text.empty()) return false;
    out.path = dir.string();
    // Fail-closed: inventing id from dirname for malformed JSON is not a load.
    std::string name = JsonStr(text, "name");
    if (name.empty()) return false;
    out.publisher = JsonStr(text, "publisher");
    if (out.publisher.empty()) out.publisher = "rawrxd";
    out.id = out.publisher + "." + name;
    out.name = JsonStr(text, "displayName");
    if (out.name.empty()) out.name = name;
    out.version = JsonStr(text, "version");
    if (out.version.empty()) out.version = "0.0.1";
    return true;
}

} // namespace ProductExtensionRuntime
