// manifest_parser.cpp — Extension Manifest Parser Implementation
#include "manifest_parser.hpp"
#include <fstream>
#include <sstream>
#include <regex>

namespace RawrXD {
namespace ExtensionHost {

std::optional<ExtensionPackageManifest> ManifestParser::Parse(const std::filesystem::path& manifestPath) {
    if (!std::filesystem::exists(manifestPath)) return std::nullopt;

    std::ifstream file(manifestPath);
    if (!file.is_open()) return std::nullopt;

    std::stringstream buffer;
    buffer << file.rdbuf();
    return ParseFromString(buffer.str());
}

std::optional<ExtensionPackageManifest> ManifestParser::ParseFromString(const std::string& json) {
    ExtensionPackageManifest manifest;

    manifest.name = GetJsonValue(json, "name");
    if (manifest.name.empty()) return std::nullopt;

    manifest.displayName = GetJsonValue(json, "displayName");
    manifest.publisher = GetJsonValue(json, "publisher");
    manifest.version = GetJsonValue(json, "version");
    manifest.description = GetJsonValue(json, "description");
    manifest.main = GetJsonValue(json, "main");
    manifest.icon = GetJsonValue(json, "icon");
    manifest.license = GetJsonValue(json, "license");
    manifest.repository = GetJsonValue(json, "repository");

    manifest.activationEvents = GetJsonArray(json, "activationEvents");
    manifest.categories = GetJsonArray(json, "categories");
    manifest.keywords = GetJsonArray(json, "keywords");
    manifest.extensionDependencies = GetJsonArray(json, "extensionDependencies");
    manifest.extensionPack = GetJsonArray(json, "extensionPack");

    manifest.id = manifest.publisher.empty() ? manifest.name : manifest.publisher + "." + manifest.name;

    return manifest;
}

bool ManifestParser::Validate(const ExtensionPackageManifest& manifest) {
    if (manifest.name.empty()) return false;
    if (manifest.version.empty()) return false;
    return true;
}

bool ManifestParser::IsEngineCompatible(const ExtensionPackageManifest& manifest, const std::string& engineVersion) {
    auto it = manifest.engines.find("vscode");
    if (it == manifest.engines.end()) return true; // No engine requirement

    // Simple version comparison
    // TODO: Implement semver comparison
    return it->second <= engineVersion;
}

std::string ManifestParser::GetJsonValue(const std::string& json, const std::string& key) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return match[1].str();
    }
    return {};
}

std::vector<std::string> ManifestParser::GetJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::regex pattern("\"" + key + "\"\\s*:\\s*\\[([^\\]]+)\\]");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        std::string arrayContent = match[1].str();
        std::regex itemPattern("\"([^\"]+)\"");
        auto begin = std::sregex_iterator(arrayContent.begin(), arrayContent.end(), itemPattern);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            result.push_back((*it)[1].str());
        }
    }
    return result;
}

} // namespace ExtensionHost
} // namespace RawrXD
