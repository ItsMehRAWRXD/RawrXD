// ExtensionHost.cpp — Extension Host (Batch 5 X04) — real package.json load.
#include "ExtensionHost.h"
#include <fstream>
#include <filesystem>
#include <unordered_map>

struct ExtensionHost::Impl {
    bool running = false;
    std::unordered_map<std::string, std::string> loaded; // id -> path
};

ExtensionHost::ExtensionHost() : impl_(std::make_unique<Impl>()) {}
ExtensionHost::~ExtensionHost() { Stop(); }

bool ExtensionHost::Start() {
    impl_->running = true;
    return true;
}

void ExtensionHost::Stop() {
    impl_->running = false;
    impl_->loaded.clear();
}

bool ExtensionHost::LoadExtension(const std::string& extensionPath) {
    if (!impl_->running) return false;
    namespace fs = std::filesystem;
    fs::path dir(extensionPath);
    fs::path pkg = dir / "package.json";
    if (!fs::exists(pkg)) return false;
    std::ifstream in(pkg.string(), std::ios::binary);
    if (!in) return false;
    std::string json((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    auto grab = [&](const char* key) -> std::string {
        std::string k = std::string("\"") + key + "\"";
        size_t p = json.find(k);
        if (p == std::string::npos) return {};
        p = json.find(':', p);
        if (p == std::string::npos) return {};
        p = json.find('"', p);
        if (p == std::string::npos) return {};
        size_t e = json.find('"', p + 1);
        if (e == std::string::npos) return {};
        return json.substr(p + 1, e - p - 1);
    };
    std::string name = grab("name");
    if (name.empty()) return false;
    std::string pub = grab("publisher");
    std::string id = pub.empty() ? name : (pub + "." + name);
    impl_->loaded[id] = extensionPath;
    return true;
}

void ExtensionHost::UnloadExtension(const std::string& extensionId) {
    impl_->loaded.erase(extensionId);
}
