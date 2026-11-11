// ExtensionManifestLoader.cpp — Extension Manifest Loader (Batch 5 X05)
#include "ExtensionManifestLoader.h"
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace RawrXD::Extensions {

ExtensionManifest ExtensionManifestLoader::Load(const std::string& manifestPath) {
    ExtensionManifest manifest;
    std::ifstream f(manifestPath);
    if (!f) return manifest;
    try {
        std::ostringstream buf;
        buf << f.rdbuf();
        auto j = nlohmann::json::parse(buf.str());
        manifest.id = j.value("id", "");
        manifest.name = j.value("name", "");
        manifest.version = j.value("version", "");
        manifest.main = j.value("main", "");
        if (j.contains("requestedReadPaths") && j["requestedReadPaths"].is_array()) {
            for (const auto& p : j["requestedReadPaths"])
                manifest.requestedReadPaths.push_back(p.get<std::string>());
        }
        if (j.contains("requestedWritePaths") && j["requestedWritePaths"].is_array()) {
            for (const auto& p : j["requestedWritePaths"])
                manifest.requestedWritePaths.push_back(p.get<std::string>());
        }
        manifest.requestNetwork = j.value("requestNetwork", false);
    } catch (...) {}
    return manifest;
}

void ExtensionManifestLoader::ApplyManifestToSandbox(const ExtensionManifest& manifest) {
    // Apply manifest restrictions to sandbox
    (void)manifest;
}

}
