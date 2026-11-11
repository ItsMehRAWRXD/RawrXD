// vsix_loader.cpp — VSIX Package Loader Implementation
#include "vsix_loader.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace ExtensionHost {

std::optional<VSIXManifest> VSIXLoader::Load(const std::filesystem::path& vsixPath) {
    if (!std::filesystem::exists(vsixPath)) return std::nullopt;

    // Create temp directory for extraction
    auto tempDir = std::filesystem::temp_directory_path() / "rawrxd-vsix" / vsixPath.stem();
    std::filesystem::create_directories(tempDir);

    if (!Extract(vsixPath, tempDir)) return std::nullopt;

    // Parse extension manifest
    auto manifest = ParseManifest(tempDir / "extension.vsixmanifest");
    if (!manifest) {
        // Try package.json as fallback
        manifest = ParseManifest(tempDir / "package.json");
    }

    // Clean up temp directory
    std::filesystem::remove_all(tempDir);

    return manifest;
}

bool VSIXLoader::Extract(const std::filesystem::path& vsixPath, const std::filesystem::path& destDir) {
    if (!std::filesystem::exists(vsixPath)) return false;
    std::filesystem::create_directories(destDir);
    return Unzip(vsixPath, destDir);
}

bool VSIXLoader::ValidateSignature(const std::filesystem::path& vsixPath) {
    // TODO: Implement VSIX signature validation
    // Check for .signature and .manifest files in the VSIX
    return true; // Pass for now
}

std::optional<VSIXManifest> VSIXLoader::Peek(const std::filesystem::path& vsixPath) {
    // Read manifest from VSIX without full extraction
    // TODO: Read specific file from ZIP without extracting all
    return Load(vsixPath);
}

bool VSIXLoader::Unzip(const std::filesystem::path& zipPath, const std::filesystem::path& destDir) {
    // TODO: Use miniz or zlib to extract ZIP
    // For now, use PowerShell as fallback
    std::string cmd = "powershell -Command \"Expand-Archive -Path '" +
        zipPath.string() + "' -DestinationPath '" + destDir.string() + "' -Force\"";
    system(cmd.c_str());
    return true;
}

std::optional<VSIXManifest> VSIXLoader::ParseManifest(const std::filesystem::path& manifestPath) {
    if (!std::filesystem::exists(manifestPath)) return std::nullopt;

    std::ifstream file(manifestPath);
    if (!file.is_open()) return std::nullopt;

    VSIXManifest manifest;
    std::string line;

    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"name\"") != std::string::npos) manifest.name = parseStr(line, "name");
        if (line.find("\"publisher\"") != std::string::npos) manifest.publisher = parseStr(line, "publisher");
        if (line.find("\"version\"") != std::string::npos) manifest.version = parseStr(line, "version");
        if (line.find("\"displayName\"") != std::string::npos) manifest.name = parseStr(line, "displayName");
        if (line.find("\"description\"") != std::string::npos) manifest.description = parseStr(line, "description");
        if (line.find("\"engines\"") != std::string::npos) manifest.engineVersion = parseStr(line, "vscode");
    }

    if (manifest.name.empty()) return std::nullopt;
    manifest.id = manifest.publisher.empty() ? manifest.name : manifest.publisher + "." + manifest.name;

    return manifest;
}

} // namespace ExtensionHost
} // namespace RawrXD
