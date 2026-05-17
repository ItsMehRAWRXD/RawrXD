// ============================================================================
// extension_manifest_parser.cpp — Extension Manifest (package.json) Parser Implementation
// ============================================================================
// Architecture: C++20 | Win32 | nlohmann/json | Function-pointer callbacks | No exceptions
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "extension_manifest_parser.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Helper Functions
// ============================================================================

static std::string TrimWhitespace(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    size_t end = str.find_last_not_of(" \t\r\n");
    
    if (start == std::string::npos) return "";
    return str.substr(start, end - start + 1);
}

static std::string ToLowerAscii(const std::string& str) {
    std::string result = str;
    for (auto& c : result) {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
    }
    return result;
}

static bool SafeGetString(const json& obj, const std::string& key, std::string& outValue) {
    try {
        if (obj.contains(key) && obj[key].is_string()) {
            outValue = obj[key].get<std::string>();
            return true;
        }
    } catch (...) {
        // JSON access exception
    }
    return false;
}

static bool SafeGetArray(const json& obj, const std::string& key, std::vector<std::string>& outArray) {
    try {
        if (obj.contains(key) && obj[key].is_array()) {
            for (const auto& item : obj[key]) {
                if (item.is_string()) {
                    outArray.push_back(item.get<std::string>());
                }
            }
            return true;
        }
    } catch (...) {
        // JSON access exception
    }
    return false;
}

static bool SafeGetObject(const json& obj, const std::string& key, json& outObj) {
    try {
        if (obj.contains(key) && obj[key].is_object()) {
            outObj = obj[key];
            return true;
        }
    } catch (...) {
        // JSON access exception
    }
    return false;
}

static bool SafeGetBool(const json& obj, const std::string& key, bool& outValue) {
    try {
        if (obj.contains(key) && obj[key].is_boolean()) {
            outValue = obj[key].get<bool>();
            return true;
        }
    } catch (...) {
        // JSON access exception
    }
    return false;
}

// ============================================================================
// Parsing Helpers
// ============================================================================

CommandContribution ExtensionManifestParser::ParseCommand(const json& obj) {
    CommandContribution cmd;
    SafeGetString(obj, "command", cmd.id);
    SafeGetString(obj, "title", cmd.title);
    SafeGetString(obj, "category", cmd.category);
    SafeGetString(obj, "description", cmd.description);
    
    // TODO: Parse keybinding if present
    
    return cmd;
}

LanguageContribution ExtensionManifestParser::ParseLanguage(const json& obj) {
    LanguageContribution lang;
    SafeGetString(obj, "id", lang.id);
    SafeGetArray(obj, "aliases", lang.aliases);
    SafeGetArray(obj, "extensions", lang.extensions);
    SafeGetString(obj, "mimeType", lang.mimeType);
    return lang;
}

KeybindingContribution ExtensionManifestParser::ParseKeybinding(const json& obj) {
    KeybindingContribution kb;
    SafeGetString(obj, "command", kb.command);
    SafeGetString(obj, "key", kb.key);
    SafeGetString(obj, "mac", kb.mac);
    SafeGetString(obj, "linux", kb.linux);
    SafeGetString(obj, "win", kb.win);
    return kb;
}

ThemeContribution ExtensionManifestParser::ParseTheme(const json& obj) {
    ThemeContribution theme;
    SafeGetString(obj, "id", theme.id);
    SafeGetString(obj, "label", theme.label);
    SafeGetString(obj, "uiTheme", theme.uiTheme);
    SafeGetString(obj, "path", theme.path);
    return theme;
}

ViewContribution ExtensionManifestParser::ParseView(const json& obj) {
    ViewContribution view;
    SafeGetString(obj, "id", view.id);
    SafeGetString(obj, "title", view.title);
    SafeGetString(obj, "icon", view.icon);
    SafeGetString(obj, "priority", view.priority);
    return view;
}

void ExtensionManifestParser::ParseMetadata(const json& root, ExtensionManifest& out) {
    SafeGetString(root, "name", out.name);
    SafeGetString(root, "version", out.version);
    SafeGetString(root, "displayName", out.displayName);
    SafeGetString(root, "description", out.description);
    SafeGetString(root, "publisher", out.publisher);
    SafeGetString(root, "author", out.author);
    SafeGetString(root, "license", out.license);
    SafeGetString(root, "main", out.main);
    SafeGetString(root, "icon", out.icon);
    SafeGetString(root, "galleryBanner", out.galleryBanner);
    SafeGetString(root, "repository", out.repository);
    SafeGetString(root, "bugs", out.bugs);
    SafeGetString(root, "homepage", out.homepage);
    
    // Engine / VS Code version
    SafeGetString(root, "engines.vscode", out.vscodeVersion);
    if (out.vscodeVersion.empty()) {
        SafeGetString(root, "engines.VSCode", out.vscodeVersion);
    }
    out.engineVersion = out.vscodeVersion;
    
    // Categories and keywords
    SafeGetArray(root, "categories", out.categories);
    SafeGetArray(root, "keywords", out.keywords);
    
    // Flags
    SafeGetBool(root, "preview", out.preview);
    SafeGetBool(root, "deprecated", out.deprecated);
    
    // Extension kind
    SafeGetString(root, "extensionKind", out.extensionKind);
}

void ExtensionManifestParser::ParseActivationEvents(const json& root, ExtensionManifest& out) {
    SafeGetArray(root, "activationEvents", out.activationEvents);
}

void ExtensionManifestParser::ParseContributions(const json& root, ExtensionManifest& out) {
    json contrib;
    if (!SafeGetObject(root, "contributes", contrib)) {
        return;  // No contributions
    }

    // Parse commands
    try {
        if (contrib.contains("commands") && contrib["commands"].is_array()) {
            for (const auto& cmd : contrib["commands"]) {
                out.contributes.commands.push_back(ParseCommand(cmd));
            }
        }
    } catch (...) {
        // Skip malformed commands
    }

    // Parse languages
    try {
        if (contrib.contains("languages") && contrib["languages"].is_array()) {
            for (const auto& lang : contrib["languages"]) {
                out.contributes.languages.push_back(ParseLanguage(lang));
            }
        }
    } catch (...) {
        // Skip malformed languages
    }

    // Parse keybindings
    try {
        if (contrib.contains("keybindings") && contrib["keybindings"].is_array()) {
            for (const auto& kb : contrib["keybindings"]) {
                out.contributes.keybindings.push_back(ParseKeybinding(kb));
            }
        }
    } catch (...) {
        // Skip malformed keybindings
    }

    // Parse themes
    try {
        if (contrib.contains("themes") && contrib["themes"].is_array()) {
            for (const auto& theme : contrib["themes"]) {
                out.contributes.themes.push_back(ParseTheme(theme));
            }
        }
    } catch (...) {
        // Skip malformed themes
    }

    // Parse configuration
    try {
        if (contrib.contains("configuration") && contrib["configuration"].is_object()) {
            for (auto& [key, val] : contrib["configuration"].items()) {
                if (val.is_string()) {
                    out.contributes.configuration[key] = val.get<std::string>();
                }
            }
        }
    } catch (...) {
        // Skip malformed configuration
    }

    // Parse grammars
    try {
        SafeGetArray(contrib, "grammars", out.contributes.grammars);
    } catch (...) {
        // Skip
    }
}

void ExtensionManifestParser::ParseDependencies(const json& root, ExtensionManifest& out) {
    json depsObj;
    if (SafeGetObject(root, "dependencies", depsObj)) {
        try {
            for (auto& [key, val] : depsObj.items()) {
                if (val.is_string()) {
                    out.dependencies[key] = val.get<std::string>();
                }
            }
        } catch (...) {
            // Skip
        }
    }

    json devDepsObj;
    if (SafeGetObject(root, "devDependencies", devDepsObj)) {
        try {
            for (auto& [key, val] : devDepsObj.items()) {
                if (val.is_string()) {
                    out.devDependencies[key] = val.get<std::string>();
                }
            }
        } catch (...) {
            // Skip
        }
    }
}

// ============================================================================
// Public Parse Methods
// ============================================================================

ManifestParseResult ExtensionManifestParser::Parse(const json& packageJson) {
    auto manifest = std::make_unique<ExtensionManifest>();

    try {
        ParseMetadata(packageJson, *manifest);
        ParseActivationEvents(packageJson, *manifest);
        ParseContributions(packageJson, *manifest);
        ParseDependencies(packageJson, *manifest);

        return ManifestParseResult::Ok(std::move(manifest));
    } catch (const std::exception& e) {
        return ManifestParseResult::Error(std::string("Parse error: ") + e.what());
    }
}

ManifestParseResult ExtensionManifestParser::ParseString(const std::string& jsonString) {
    if (jsonString.empty()) {
        return ManifestParseResult::Error("JSON string is empty");
    }

    try {
        json obj = json::parse(jsonString);
        return Parse(obj);
    } catch (const json::parse_error& e) {
        return ManifestParseResult::Error(std::string("JSON parse error: ") + e.what());
    } catch (const std::exception& e) {
        return ManifestParseResult::Error(std::string("Error: ") + e.what());
    }
}

ManifestParseResult ExtensionManifestParser::ParseFile(const std::string& filePath) {
    if (filePath.empty()) {
        return ManifestParseResult::Error("File path is empty");
    }

    try {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            return ManifestParseResult::Error("Cannot open file: " + filePath);
        }

        json obj;
        file >> obj;
        file.close();

        return Parse(obj);
    } catch (const std::exception& e) {
        return ManifestParseResult::Error(
            std::string("File parse error for ") + filePath + ": " + e.what()
        );
    }
}

bool ExtensionManifestParser::Validate(const ExtensionManifest& manifest,
                                       std::string& outErrorMessage) {
    // Check required fields
    if (manifest.name.empty()) {
        outErrorMessage = "Missing required field: name";
        return false;
    }

    if (manifest.version.empty()) {
        outErrorMessage = "Missing required field: version";
        return false;
    }

    if (manifest.publisher.empty() && manifest.author.empty()) {
        outErrorMessage = "Missing required field: publisher or author";
        return false;
    }

    // TODO: Additional validation rules

    return true;
}

std::vector<std::string> ExtensionManifestParser::ExtractActivationEvents(const json& packageJson) {
    std::vector<std::string> events;
    SafeGetArray(packageJson, "activationEvents", events);
    return events;
}

ExtensionContributions ExtensionManifestParser::ExtractContributions(const json& packageJson) {
    ExtensionContributions contrib;
    ExtensionManifest temp;
    ParseContributions(packageJson, temp);
    return temp.contributes;
}

std::vector<std::string> ExtensionManifestParser::ExtractDependencies(const json& packageJson) {
    std::vector<std::string> deps;
    json depsObj;
    if (SafeGetObject(packageJson, "dependencies", depsObj)) {
        try {
            for (auto& [key, val] : depsObj.items()) {
                deps.push_back(key);
            }
        } catch (...) {
            // Skip
        }
    }
    return deps;
}

// ============================================================================
// Global Helper
// ============================================================================

ManifestParseResult ParseExtensionDirectory(const std::string& extensionDir) {
    if (extensionDir.empty()) {
        return ManifestParseResult::Error("Extension directory is empty");
    }

    fs::path packageJsonPath = extensionDir;
    packageJsonPath /= "package.json";

    if (!fs::exists(packageJsonPath)) {
        return ManifestParseResult::Error("package.json not found in: " + extensionDir);
    }

    return ExtensionManifestParser::ParseFile(packageJsonPath.string());
}

}  // namespace Extensions
}  // namespace RawrXD

// ============================================================================
// End of extension_manifest_parser.cpp
// ============================================================================
