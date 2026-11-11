// manifest_parser.hpp — Extension Manifest Parser
#pragma once
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <optional>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Extension Contribution Points
// ============================================================================
struct ContributionPoints {
    std::vector<std::string> commands;
    std::vector<std::string> languages;
    std::vector<std::string> themes;
    std::vector<std::string> snippets;
    std::vector<std::string> keybindings;
    std::vector<std::string> menus;
    std::vector<std::string> views;
    std::vector<std::string> configuration;
};

// ============================================================================
// Extension Package Manifest
// ============================================================================
struct ExtensionPackageManifest {
    std::string id;
    std::string name;
    std::string displayName;
    std::string publisher;
    std::string version;
    std::string description;
    std::string main;           // Entry point JS file
    std::string icon;
    std::string license;
    std::string repository;
    std::vector<std::string> activationEvents;
    std::vector<std::string> categories;
    std::vector<std::string> keywords;
    std::map<std::string, std::string> engines;
    std::vector<std::string> extensionDependencies;
    std::vector<std::string> extensionPack;
    ContributionPoints contributes;
    bool isBuiltin = false;
    bool isPreview = false;
    bool isDeprecated = false;
};

// ============================================================================
// Manifest Parser
// ============================================================================
class ManifestParser {
public:
    // Parse package.json or extension.json
    static std::optional<ExtensionPackageManifest> Parse(const std::filesystem::path& manifestPath);

    // Parse from string
    static std::optional<ExtensionPackageManifest> ParseFromString(const std::string& json);

    // Validate manifest
    static bool Validate(const ExtensionPackageManifest& manifest);

    // Get engine compatibility
    static bool IsEngineCompatible(const ExtensionPackageManifest& manifest, const std::string& engineVersion);

private:
    static std::string GetJsonValue(const std::string& json, const std::string& key);
    static std::vector<std::string> GetJsonArray(const std::string& json, const std::string& key);
};

} // namespace ExtensionHost
} // namespace RawrXD
