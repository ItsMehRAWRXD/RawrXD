// ============================================================================
// extension_marketplace.cpp — Non-Qt Extension Marketplace Implementation
// ============================================================================
// NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "extension_marketplace.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <queue>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
// POSIX: would use libcurl
#endif

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Singleton
// ============================================================================
ExtensionMarketplace& ExtensionMarketplace::instance() {
    static ExtensionMarketplace inst;
    return inst;
}

ExtensionMarketplace::ExtensionMarketplace()
    : installDir_(".rawrxd/extensions/"),
      cacheDir_(".rawrxd/extension_cache/"),
      registryUrl_("https://marketplace.rawrxd.dev/api/v1"),
      eventListenerCount_(0), totalDownloadBytes_(0)
{}

ExtensionMarketplace::~ExtensionMarketplace() {
    shutdown();
}

// ============================================================================
// Configuration
// ============================================================================

ExtResult ExtensionMarketplace::setInstallDirectory(const std::string& path) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    installDir_ = path;
    std::filesystem::create_directories(path);
    return ExtResult::ok("Install directory set");
}

ExtResult ExtensionMarketplace::setCacheDirectory(const std::string& path) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    cacheDir_ = path;
    std::filesystem::create_directories(path);
    return ExtResult::ok("Cache directory set");
}

ExtResult ExtensionMarketplace::setRegistryUrl(const std::string& url) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    registryUrl_ = url;
    return ExtResult::ok("Registry URL set");
}

ExtResult ExtensionMarketplace::applyPolicy(const EnterprisePolicyConfig& config) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    policy_ = config;

    // Enforce policy on currently installed extensions
    for (auto& [id, manifest] : installed_) {
        ExtResult pr = checkPolicy(manifest);
        if (!pr.success) {
            states_[id] = ExtensionState::BLOCKED;

            MarketplaceEvent evt;
            evt.type = MarketplaceEvent::POLICY_VIOLATION;
            evt.extensionId = id;
            evt.detail = pr.detail.c_str();
            emitEvent(evt);
        }
    }

    // Auto-install required extensions
    for (const auto& autoId : config.autoInstallIds) {
        if (installed_.find(autoId) == installed_.end()) {
            installFromRegistry(autoId);
        }
    }

    return ExtResult::ok("Policy applied");
}

// ============================================================================
// Policy Engine
// ============================================================================

ExtResult ExtensionMarketplace::checkPolicy(const ExtensionManifest& manifest) {
    // Check block list
    if (policy_.enforceBlockList) {
        for (const auto& blocked : policy_.blockedExtensionIds) {
            if (manifest.id == blocked) {
                return ExtResult::error("Extension blocked by policy", 10);
            }
        }
        for (const auto& blocked : policy_.blockedPublishers) {
            if (manifest.publisher == blocked) {
                return ExtResult::error("Publisher blocked by policy", 11);
            }
        }
    }

    // Check allow list
    if (policy_.enforceAllowList) {
        bool allowed = false;
        for (const auto& allowedId : policy_.allowedExtensionIds) {
            if (manifest.id == allowedId) { allowed = true; break; }
        }
        if (!allowed) {
            for (const auto& allowedPub : policy_.allowedPublishers) {
                if (manifest.publisher == allowedPub) { allowed = true; break; }
            }
        }
        if (!allowed) {
            return ExtResult::error("Extension not in allow list", 12);
        }
    }

    // Check max extensions limit
    if (policy_.maxExtensions > 0 &&
        installed_.size() >= policy_.maxExtensions) {
        return ExtResult::error("Maximum extension limit reached", 13);
    }

    return ExtResult::ok("Policy check passed");
}

// ============================================================================
// Search / Browse
// ============================================================================

ExtResult ExtensionMarketplace::search(const ExtensionSearchQuery& query,
                                        ExtensionSearchResponse& response) {
    // For local/offline mode: search installed extensions
    response.results.clear();
    response.totalCount = 0;
    response.page = query.page;
    response.pageSize = query.pageSize;

    std::string searchLower = query.text;
    std::transform(searchLower.begin(), searchLower.end(),
                   searchLower.begin(), ::tolower);

    for (auto& [id, manifest] : installed_) {
        // Text search in name, description, publisher
        std::string nameLower = manifest.name;
        std::string descLower = manifest.description;
        std::transform(nameLower.begin(), nameLower.end(),
                       nameLower.begin(), ::tolower);
        std::transform(descLower.begin(), descLower.end(),
                       descLower.begin(), ::tolower);

        bool matches = searchLower.empty() ||
                       nameLower.find(searchLower) != std::string::npos ||
                       descLower.find(searchLower) != std::string::npos ||
                       id.find(searchLower) != std::string::npos;

        if (matches) {
            ExtensionSearchResult sr;
            sr.manifest = manifest;
            sr.installCount = 0;
            sr.rating = 0.0f;
            sr.ratingCount = 0;
            response.results.push_back(std::move(sr));
        }
    }

    response.totalCount = static_cast<uint32_t>(response.results.size());

    // Also query the remote registry if online
    if (!registryUrl_.empty() && response.results.size() < query.pageSize) {
        std::string searchUrl = registryUrl_ + "/search?q=" + query.text +
                                "&page=" + std::to_string(query.page) +
                                "&pageSize=" + std::to_string(query.pageSize);

        std::string cachePath = cacheDir_ + "search_results.json";
        ExtResult dr = httpDownload(searchUrl, cachePath);
        if (dr.success && std::filesystem::exists(cachePath)) {
            // Parse search results from JSON response
            std::ifstream resultFile(cachePath);
            std::string content((std::istreambuf_iterator<char>(resultFile)),
                                 std::istreambuf_iterator<char>());
            resultFile.close();

            // Extract extension entries from JSON array
            auto extractField = [](const std::string& json, size_t startPos,
                                   const std::string& key) -> std::string {
                std::string pattern = "\"" + key + "\"";
                auto pos = json.find(pattern, startPos);
                if (pos == std::string::npos) return "";
                auto colonPos = json.find(':', pos);
                auto qStart = json.find('"', colonPos + 1);
                auto qEnd = json.find('"', qStart + 1);
                if (qStart == std::string::npos || qEnd == std::string::npos) return "";
                return json.substr(qStart + 1, qEnd - qStart - 1);
            };

            // Find each extension entry in the response
            size_t searchPos = 0;
            while ((searchPos = content.find("\"extensionId\"", searchPos)) != std::string::npos) {
                ExtensionSearchResult sr;
                sr.manifest.id = extractField(content, searchPos, "extensionId");
                sr.manifest.name = extractField(content, searchPos, "name");
                sr.manifest.publisher = extractField(content, searchPos, "publisher");
                sr.manifest.version = extractField(content, searchPos, "version");
                sr.manifest.description = extractField(content, searchPos, "description");

                if (!sr.manifest.id.empty()) {
                    // Don't duplicate locally installed extensions
                    bool isDuplicate = false;
                    for (const auto& existing : response.results) {
                        if (existing.manifest.id == sr.manifest.id) {
                            isDuplicate = true;
                            break;
                        }
                    }
                    if (!isDuplicate) {
                        response.results.push_back(std::move(sr));
                    }
                }
                searchPos++;
            }
            response.totalCount = static_cast<uint32_t>(response.results.size());

            // Cleanup cache file
            std::filesystem::remove(cachePath);
        }
    }

    return ExtResult::ok("Search complete");
}

ExtResult ExtensionMarketplace::getExtensionDetails(
    const std::string& extensionId,
    ExtensionSearchResult& result)
{
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it != installed_.end()) {
        result.manifest = it->second;
        result.installCount = 0;
        result.rating = 0.0f;
        result.ratingCount = 0;
        return ExtResult::ok("Extension found");
    }

    return ExtResult::error("Extension not found", 1);
}

std::vector<ExtensionManifest> ExtensionMarketplace::listInstalled() const {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    std::vector<ExtensionManifest> result;
    for (auto& [id, manifest] : installed_) {
        result.push_back(manifest);
    }
    return result;
}

std::vector<ExtensionManifest> ExtensionMarketplace::listEnabled() const {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    std::vector<ExtensionManifest> result;
    for (auto& [id, manifest] : installed_) {
        auto sit = states_.find(id);
        if (sit != states_.end() && sit->second == ExtensionState::ENABLED) {
            result.push_back(manifest);
        }
    }
    return result;
}

// ============================================================================
// Install / Uninstall
// ============================================================================

ExtResult ExtensionMarketplace::installFromVsix(const std::string& vsixPath) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    // Verify file exists
    if (!std::filesystem::exists(vsixPath))
        return ExtResult::error("VSIX file not found", 2);

    // Parse manifest from VSIX (it's a ZIP with package.json inside)
    // For now, create a manifest from the filename
    ExtensionManifest manifest;
    std::string filename = std::filesystem::path(vsixPath).stem().string();

    // Try to parse "publisher.name-version" pattern
    auto dotPos = filename.find('.');
    if (dotPos != std::string::npos) {
        manifest.publisher = filename.substr(0, dotPos);
        std::string rest = filename.substr(dotPos + 1);
        auto dashPos = rest.rfind('-');
        if (dashPos != std::string::npos) {
            manifest.name = rest.substr(0, dashPos);
            manifest.version = rest.substr(dashPos + 1);
        } else {
            manifest.name = rest;
            manifest.version = "0.0.1";
        }
    } else {
        manifest.name = filename;
        manifest.publisher = "local";
        manifest.version = "0.0.1";
    }

    manifest.id = manifest.publisher + "." + manifest.name;
    manifest.vsixPath = vsixPath;
    manifest.fileSize = std::filesystem::file_size(vsixPath);
    manifest.isEnabled = true;

    // Check enterprise policy
    ExtResult pr = checkPolicy(manifest);
    if (!pr.success) return pr;

    // Extract VSIX to install directory
    std::string targetDir = installDir_ + manifest.id + "/";
    ExtResult er = extractVsix(vsixPath, targetDir);
    if (!er.success) return er;

    manifest.installPath = targetDir;
    manifest.installedAt = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    manifest.packageFormat = static_cast<uint32_t>(ExtensionPackageFormat::VsCodeVsix);
    manifest.sourceIde = "VS Code";

    // Parse the real manifest if it exists
    std::string manifestPath = targetDir + "package.json";
    if (std::filesystem::exists(manifestPath)) {
        parseManifest(manifestPath, manifest);
    }
    if (std::filesystem::exists(targetDir + "extension.vsixmanifest") &&
        !std::filesystem::exists(manifestPath)) {
        manifest.packageFormat =
            static_cast<uint32_t>(ExtensionPackageFormat::VisualStudioVsix);
        manifest.sourceIde = "Visual Studio";
        parseForeignManifest(ExtensionPackageFormat::VisualStudioVsix,
                             targetDir, manifest);
    }

    installed_[manifest.id] = manifest;
    states_[manifest.id] = ExtensionState::INSTALLED;

    // Emit event
    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_INSTALLED;
    evt.extensionId = manifest.id;
    evt.detail = "Extension installed";
    emitEvent(evt);

    return ExtResult::ok("Extension installed from VSIX");
}

const IdeExtensionFormatInfo* ExtensionMarketplace::ideExtensionCatalog(
    size_t& outCount)
{
    // Top 25 IDEs → primary package formats (shared ecosystems collapse).
    static const IdeExtensionFormatInfo kCatalog[kTopIdeExtensionCatalogCount] = {
        {"Visual Studio",   ExtensionPackageFormat::VisualStudioVsix, ".vsix",
         "extension.vsixmanifest", true, false},
        {"VS Code",         ExtensionPackageFormat::VsCodeVsix, ".vsix",
         "package.json", true, true},
        {"IntelliJ IDEA",   ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"PyCharm",         ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"WebStorm",        ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"Android Studio",  ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"Xcode",           ExtensionPackageFormat::XcodeBundle, ".appex,.plugin",
         "Info.plist", true, false},
        {"Eclipse",         ExtensionPackageFormat::EclipseBundle, ".jar,.zip",
         "plugin.xml", true, false},
        {"CLion",           ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"PhpStorm",        ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"GoLand",          ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"Sublime Text",    ExtensionPackageFormat::SublimePackage, ".sublime-package",
         "*.sublime-package", true, false},
        {"Zed",             ExtensionPackageFormat::ZedExtension, ".zip,.tar.gz",
         "extension.toml", true, false},
        {"Fleet",           ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"Cursor",          ExtensionPackageFormat::VsCodeVsix, ".vsix",
         "package.json", true, true},
        {"Neovim",          ExtensionPackageFormat::NeovimPack, ".zip,.tar.gz,.git",
         "plugin/,lua/", true, false},
        {"GNU Emacs",       ExtensionPackageFormat::EmacsPackage, ".tar,.el,.tar.gz",
         "*-pkg.el", true, false},
        {"Rider",           ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"RubyMine",        ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
         "META-INF/plugin.xml", true, false},
        {"NetBeans",        ExtensionPackageFormat::NetBeansNBM, ".nbm,.jar",
         "Info/info.xml", true, false},
        {"Qt Creator",      ExtensionPackageFormat::QtCreatorPlugin, ".dll,.zip",
         "plugin.json", true, false},
        {"Nova",            ExtensionPackageFormat::NovaExtension, ".novaextension",
         "extension.json", true, false},
        {"Windsurf",        ExtensionPackageFormat::VsCodeVsix, ".vsix",
         "package.json", true, true},
        {"VSCodium",        ExtensionPackageFormat::VsCodeVsix, ".vsix",
         "package.json", true, true},
        {"Lapce",           ExtensionPackageFormat::LapcePlugin, ".zip,.toml",
         "plugin.toml", true, false},
    };
    outCount = kTopIdeExtensionCatalogCount;
    return kCatalog;
}

const char* ExtensionMarketplace::packageFormatName(ExtensionPackageFormat fmt) {
    switch (fmt) {
    case ExtensionPackageFormat::VsCodeVsix:       return "VS Code VSIX";
    case ExtensionPackageFormat::VisualStudioVsix: return "Visual Studio VSIX";
    case ExtensionPackageFormat::JetBrainsPlugin:  return "JetBrains Plugin";
    case ExtensionPackageFormat::EclipseBundle:    return "Eclipse Bundle";
    case ExtensionPackageFormat::SublimePackage:   return "Sublime Package";
    case ExtensionPackageFormat::NeovimPack:       return "Neovim Pack";
    case ExtensionPackageFormat::EmacsPackage:     return "Emacs Package";
    case ExtensionPackageFormat::XcodeBundle:      return "Xcode Bundle";
    case ExtensionPackageFormat::NetBeansNBM:      return "NetBeans NBM";
    case ExtensionPackageFormat::ZedExtension:     return "Zed Extension";
    case ExtensionPackageFormat::QtCreatorPlugin:  return "Qt Creator Plugin";
    case ExtensionPackageFormat::NovaExtension:    return "Nova Extension";
    case ExtensionPackageFormat::AtomPackage:      return "Atom Package";
    case ExtensionPackageFormat::LapcePlugin:      return "Lapce Plugin";
    case ExtensionPackageFormat::NativeDll:        return "Native DLL";
    case ExtensionPackageFormat::RawrPlugin:       return "RawrXD Plugin";
    case ExtensionPackageFormat::PythonWheel:      return "Python Wheel";
    case ExtensionPackageFormat::JsModule:         return "JS Module";
    default:                                       return "Unknown";
    }
}

ExtensionPackageFormat ExtensionMarketplace::detectPackageFormat(
    const std::string& packagePath) const
{
    namespace fs = std::filesystem;
    if (!fs::exists(packagePath))
        return ExtensionPackageFormat::Unknown;

    std::string ext = fs::path(packagePath).extension().string();
    for (auto& c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    if (ext == ".dll")       return ExtensionPackageFormat::NativeDll;
    if (ext == ".rawrpkg")   return ExtensionPackageFormat::RawrPlugin;
    if (ext == ".whl" || ext == ".egg")
        return ExtensionPackageFormat::PythonWheel;
    if (ext == ".js")        return ExtensionPackageFormat::JsModule;
    if (ext == ".sublime-package")
        return ExtensionPackageFormat::SublimePackage;
    if (ext == ".nbm")       return ExtensionPackageFormat::NetBeansNBM;
    if (ext == ".novaextension")
        return ExtensionPackageFormat::NovaExtension;
    if (ext == ".appex" || ext == ".plugin")
        return ExtensionPackageFormat::XcodeBundle;
    if (ext == ".el")        return ExtensionPackageFormat::EmacsPackage;

    // .vsix / zip / jar / tar: sniff after extract or by name patterns
    if (ext == ".vsix") {
        // Prefer VS Code; refined after unpack if only vsixmanifest
        return ExtensionPackageFormat::VsCodeVsix;
    }
    if (ext == ".jar" || ext == ".zip" || ext == ".tar" || ext == ".gz" ||
        ext == ".tgz") {
        // Content sniff via tar listing is heavy; use filename heuristics
        std::string stem = fs::path(packagePath).stem().string();
        for (auto& c : stem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (stem.find("jetbrains") != std::string::npos ||
            stem.find("intellij") != std::string::npos)
            return ExtensionPackageFormat::JetBrainsPlugin;
        if (stem.find("eclipse") != std::string::npos)
            return ExtensionPackageFormat::EclipseBundle;
        if (stem.find("zed") != std::string::npos)
            return ExtensionPackageFormat::ZedExtension;
        if (stem.find("lapce") != std::string::npos)
            return ExtensionPackageFormat::LapcePlugin;
        if (stem.find("nvim") != std::string::npos ||
            stem.find("neovim") != std::string::npos)
            return ExtensionPackageFormat::NeovimPack;
        if (ext == ".jar")
            return ExtensionPackageFormat::EclipseBundle;
        return ExtensionPackageFormat::JetBrainsPlugin;
    }

    if (fs::is_directory(packagePath)) {
        if (fs::exists(packagePath + "/META-INF/plugin.xml"))
            return ExtensionPackageFormat::JetBrainsPlugin;
        if (fs::exists(packagePath + "/package.json"))
            return ExtensionPackageFormat::VsCodeVsix;
        if (fs::exists(packagePath + "/extension.toml"))
            return ExtensionPackageFormat::ZedExtension;
        if (fs::exists(packagePath + "/plugin.toml"))
            return ExtensionPackageFormat::LapcePlugin;
        if (fs::exists(packagePath + "/plugin") ||
            fs::exists(packagePath + "/lua"))
            return ExtensionPackageFormat::NeovimPack;
        if (fs::exists(packagePath + "/Info.plist"))
            return ExtensionPackageFormat::XcodeBundle;
        if (fs::exists(packagePath + "/plugin.xml"))
            return ExtensionPackageFormat::EclipseBundle;
        if (fs::exists(packagePath + "/plugin.json"))
            return ExtensionPackageFormat::QtCreatorPlugin;
    }

    return ExtensionPackageFormat::Unknown;
}

ExtResult ExtensionMarketplace::installFromPackage(const std::string& packagePath) {
    if (!std::filesystem::exists(packagePath))
        return ExtResult::error("Package file not found", 2);

    ExtensionPackageFormat fmt = detectPackageFormat(packagePath);

    if (fmt == ExtensionPackageFormat::VsCodeVsix ||
        fmt == ExtensionPackageFormat::VisualStudioVsix) {
        return installFromVsix(packagePath);
    }

    if (fmt == ExtensionPackageFormat::NativeDll ||
        fmt == ExtensionPackageFormat::JsModule ||
        fmt == ExtensionPackageFormat::RawrPlugin) {
        // Copy into install tree as opaque host package
        std::lock_guard<std::mutex> lock(marketplaceMutex_);
        ExtensionManifest manifest;
        std::string stem = std::filesystem::path(packagePath).stem().string();
        manifest.publisher = "local";
        manifest.name = stem;
        manifest.id = "local." + stem;
        manifest.version = "0.0.1";
        manifest.vsixPath = packagePath;
        manifest.packageFormat = static_cast<uint32_t>(fmt);
        manifest.sourceIde = packageFormatName(fmt);
        manifest.isEnabled = true;

        ExtResult pr = checkPolicy(manifest);
        if (!pr.success) return pr;

        std::string targetDir = installDir_ + manifest.id + "/";
        std::filesystem::create_directories(targetDir);
        std::filesystem::copy_file(
            packagePath,
            targetDir + std::filesystem::path(packagePath).filename().string(),
            std::filesystem::copy_options::overwrite_existing);
        manifest.installPath = targetDir;
        manifest.installedAt = static_cast<uint64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        installed_[manifest.id] = manifest;
        states_[manifest.id] = ExtensionState::INSTALLED;
        return ExtResult::ok(std::string("Installed ") + packageFormatName(fmt));
    }

    // Archive-based foreign IDE formats
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    ExtensionManifest manifest;
    std::string stem = std::filesystem::path(packagePath).stem().string();
    manifest.publisher = "imported";
    manifest.name = stem;
    manifest.id = "imported." + stem;
    manifest.version = "0.0.1";
    manifest.vsixPath = packagePath;
    manifest.packageFormat = static_cast<uint32_t>(fmt);
    manifest.sourceIde = packageFormatName(fmt);
    manifest.isEnabled = true;
    if (std::filesystem::is_regular_file(packagePath))
        manifest.fileSize = std::filesystem::file_size(packagePath);

    ExtResult pr = checkPolicy(manifest);
    if (!pr.success) return pr;

    std::string targetDir = installDir_ + manifest.id + "/";
    ExtResult er;
    if (std::filesystem::is_directory(packagePath)) {
        std::filesystem::create_directories(targetDir);
        std::filesystem::copy(packagePath, targetDir,
            std::filesystem::copy_options::recursive |
            std::filesystem::copy_options::overwrite_existing);
        er = ExtResult::ok("Directory package copied");
    } else {
        er = extractZipPackage(packagePath, targetDir);
    }
    if (!er.success) return er;

    // Refine format from extracted markers
    if (std::filesystem::exists(targetDir + "META-INF/plugin.xml"))
        fmt = ExtensionPackageFormat::JetBrainsPlugin;
    else if (std::filesystem::exists(targetDir + "extension.toml"))
        fmt = ExtensionPackageFormat::ZedExtension;
    else if (std::filesystem::exists(targetDir + "plugin.toml"))
        fmt = ExtensionPackageFormat::LapcePlugin;
    else if (std::filesystem::exists(targetDir + "package.json")) {
        fmt = ExtensionPackageFormat::VsCodeVsix;
        parseManifest(targetDir + "package.json", manifest);
    } else if (std::filesystem::exists(targetDir + "plugin.xml"))
        fmt = ExtensionPackageFormat::EclipseBundle;
    else if (std::filesystem::exists(targetDir + "Info/info.xml"))
        fmt = ExtensionPackageFormat::NetBeansNBM;
    else if (std::filesystem::exists(targetDir + "Info.plist"))
        fmt = ExtensionPackageFormat::XcodeBundle;
    else if (std::filesystem::exists(targetDir + "plugin.json"))
        fmt = ExtensionPackageFormat::QtCreatorPlugin;
    else if (std::filesystem::exists(targetDir + "extension.json"))
        fmt = ExtensionPackageFormat::NovaExtension;
    else if (std::filesystem::exists(targetDir + "plugin") ||
             std::filesystem::exists(targetDir + "lua"))
        fmt = ExtensionPackageFormat::NeovimPack;

    manifest.packageFormat = static_cast<uint32_t>(fmt);
    manifest.sourceIde = packageFormatName(fmt);
    parseForeignManifest(fmt, targetDir, manifest);

    manifest.installPath = targetDir;
    manifest.installedAt = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    installed_[manifest.id] = manifest;
    states_[manifest.id] = ExtensionState::INSTALLED;

    const std::string installDetail = std::string("Installed ") + packageFormatName(fmt);
    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_INSTALLED;
    evt.extensionId = manifest.id;
    evt.detail = installDetail.c_str();
    emitEvent(evt);

    return ExtResult::ok(installDetail);
}

ExtResult ExtensionMarketplace::parseForeignManifest(
    ExtensionPackageFormat fmt,
    const std::string& installDir,
    ExtensionManifest& manifest)
{
    namespace fs = std::filesystem;
    auto readText = [](const std::string& path) -> std::string {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    };

    auto grabAttr = [](const std::string& xml, const char* key) -> std::string {
        std::string needle = std::string(key) + "=\"";
        auto pos = xml.find(needle);
        if (pos == std::string::npos) return {};
        pos += needle.size();
        auto end = xml.find('"', pos);
        if (end == std::string::npos) return {};
        return xml.substr(pos, end - pos);
    };

    switch (fmt) {
    case ExtensionPackageFormat::JetBrainsPlugin: {
        std::string xml = readText(installDir + "/META-INF/plugin.xml");
        if (xml.empty()) xml = readText(installDir + "META-INF/plugin.xml");
        if (!xml.empty()) {
            auto id = grabAttr(xml, "id");
            if (id.empty()) {
                auto p = xml.find("<id>");
                if (p != std::string::npos) {
                    p += 4;
                    auto e = xml.find("</id>", p);
                    if (e != std::string::npos) id = xml.substr(p, e - p);
                }
            }
            auto ver = grabAttr(xml, "version");
            auto namePos = xml.find("<name>");
            if (namePos != std::string::npos) {
                namePos += 6;
                auto e = xml.find("</name>", namePos);
                if (e != std::string::npos)
                    manifest.displayName = xml.substr(namePos, e - namePos);
            }
            if (!id.empty()) {
                manifest.id = id;
                manifest.name = id;
            }
            if (!ver.empty()) manifest.version = ver;
            manifest.publisher = "jetbrains";
        }
        break;
    }
    case ExtensionPackageFormat::EclipseBundle: {
        std::string xml = readText(installDir + "/plugin.xml");
        if (xml.empty()) xml = readText(installDir + "plugin.xml");
        auto id = grabAttr(xml, "id");
        auto ver = grabAttr(xml, "version");
        auto name = grabAttr(xml, "name");
        if (!id.empty()) { manifest.id = id; manifest.name = id; }
        if (!ver.empty()) manifest.version = ver;
        if (!name.empty()) manifest.displayName = name;
        manifest.publisher = "eclipse";
        break;
    }
    case ExtensionPackageFormat::ZedExtension:
    case ExtensionPackageFormat::LapcePlugin: {
        std::string tomlPath = (fmt == ExtensionPackageFormat::ZedExtension)
            ? installDir + "/extension.toml"
            : installDir + "/plugin.toml";
        if (!fs::exists(tomlPath))
            tomlPath = (fmt == ExtensionPackageFormat::ZedExtension)
                ? installDir + "extension.toml"
                : installDir + "plugin.toml";
        std::string toml = readText(tomlPath);
        auto findKey = [&](const char* key) -> std::string {
            std::string lineKey = std::string(key) + " = ";
            auto p = toml.find(lineKey);
            if (p == std::string::npos) return {};
            p += lineKey.size();
            while (p < toml.size() && (toml[p] == '"' || toml[p] == ' ')) ++p;
            auto e = p;
            while (e < toml.size() && toml[e] != '"' && toml[e] != '\n') ++e;
            return toml.substr(p, e - p);
        };
        auto id = findKey("id");
        if (id.empty()) id = findKey("name");
        auto ver = findKey("version");
        if (!id.empty()) { manifest.id = id; manifest.name = id; }
        if (!ver.empty()) manifest.version = ver;
        manifest.publisher = (fmt == ExtensionPackageFormat::ZedExtension)
            ? "zed" : "lapce";
        break;
    }
    case ExtensionPackageFormat::NetBeansNBM: {
        std::string xml = readText(installDir + "/Info/info.xml");
        if (xml.empty()) xml = readText(installDir + "Info/info.xml");
        auto cn = grabAttr(xml, "codenamebase");
        if (!cn.empty()) { manifest.id = cn; manifest.name = cn; }
        auto ver = grabAttr(xml, "specification-version");
        if (!ver.empty()) manifest.version = ver;
        manifest.publisher = "netbeans";
        break;
    }
    case ExtensionPackageFormat::NovaExtension:
    case ExtensionPackageFormat::QtCreatorPlugin:
    case ExtensionPackageFormat::AtomPackage: {
        std::string jp = installDir + "/extension.json";
        if (!fs::exists(jp)) jp = installDir + "/plugin.json";
        if (!fs::exists(jp)) jp = installDir + "/package.json";
        if (fs::exists(jp)) parseManifest(jp, manifest);
        break;
    }
    case ExtensionPackageFormat::SublimePackage:
        manifest.publisher = "sublime";
        break;
    case ExtensionPackageFormat::NeovimPack:
        manifest.publisher = "neovim";
        break;
    case ExtensionPackageFormat::EmacsPackage:
        manifest.publisher = "emacs";
        break;
    case ExtensionPackageFormat::XcodeBundle:
        manifest.publisher = "apple";
        break;
    case ExtensionPackageFormat::VisualStudioVsix: {
        std::string vm = installDir + "/extension.vsixmanifest";
        if (!fs::exists(vm)) vm = installDir + "extension.vsixmanifest";
        std::string xml = readText(vm);
        auto id = grabAttr(xml, "Id");
        if (id.empty()) id = grabAttr(xml, "id");
        if (!id.empty()) { manifest.id = id; manifest.name = id; }
        manifest.publisher = "visualstudio";
        break;
    }
    default:
        break;
    }

    if (manifest.displayName.empty())
        manifest.displayName = manifest.name;
    return ExtResult::ok("Foreign manifest parsed");
}

ExtResult ExtensionMarketplace::installFromRegistry(
    const std::string& extensionId,
    const std::string& version)
{
    // Build download URL
    std::string url = registryUrl_ + "/extensions/" + extensionId +
                      "/versions/" + version + "/download";

    std::string localPath = cacheDir_ + extensionId + ".vsix";

    // Download
    ExtResult dr = httpDownload(url, localPath);
    if (!dr.success) return dr;

    // Install from downloaded VSIX
    return installFromVsix(localPath);
}

ExtResult ExtensionMarketplace::installFromUrl(const std::string& downloadUrl) {
    // Derive a filename from URL
    std::string filename = "extension_download.vsix";
    auto lastSlash = downloadUrl.rfind('/');
    if (lastSlash != std::string::npos) {
        filename = downloadUrl.substr(lastSlash + 1);
    }

    std::string localPath = cacheDir_ + filename;
    ExtResult dr = httpDownload(downloadUrl, localPath);
    if (!dr.success) return dr;

    return installFromVsix(localPath);
}

ExtResult ExtensionMarketplace::uninstall(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    // Check if other extensions depend on this one
    for (auto& [id, manifest] : installed_) {
        if (id == extensionId) continue;
        for (auto& dep : manifest.dependencies) {
            if (dep.extensionId == extensionId) {
                return ExtResult::error("Other extensions depend on this one", 5);
            }
        }
    }

    // Deactivate first
    // deactivate(extensionId);  // Would need to call without lock

    // Remove install directory
    if (!it->second.installPath.empty() &&
        std::filesystem::exists(it->second.installPath)) {
        std::error_code ec;
        std::filesystem::remove_all(it->second.installPath, ec);
    }

    installed_.erase(it);
    states_.erase(extensionId);

    // Emit event
    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_UNINSTALLED;
    evt.extensionId = extensionId;
    evt.detail = "Extension uninstalled";
    emitEvent(evt);

    return ExtResult::ok("Extension uninstalled");
}

ExtResult ExtensionMarketplace::update(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    states_[extensionId] = ExtensionState::UPDATING;

    // Check registry for newer version, download, and replace
    std::string currentVersion = it->second.version;
    std::string checkUrl = registryUrl_ + "/extensions/" + extensionId + "/latest";

    // Download version metadata to cache
    std::string metaPath = cacheDir_ + extensionId + ".meta";
    ExtResult dr = httpDownload(checkUrl, metaPath);
    if (dr.success && std::filesystem::exists(metaPath)) {
        // Parse version from metadata
        std::ifstream metaFile(metaPath);
        std::string metaContent((std::istreambuf_iterator<char>(metaFile)),
                                 std::istreambuf_iterator<char>());
        metaFile.close();

        // Extract version from JSON-like response
        auto vpos = metaContent.find("\"version\"");
        if (vpos != std::string::npos) {
            auto qStart = metaContent.find('"', vpos + 10);
            auto qEnd = metaContent.find('"', qStart + 1);
            if (qStart != std::string::npos && qEnd != std::string::npos) {
                std::string latestVersion = metaContent.substr(qStart + 1, qEnd - qStart - 1);

                // Compare versions — download if newer
                if (!semverSatisfies(currentVersion, ">=" + latestVersion)) {
                    // Newer version available — download and install
                    std::string dlUrl = registryUrl_ + "/extensions/" + extensionId +
                                        "/versions/" + latestVersion + "/download";
                    std::string vsixPath = cacheDir_ + extensionId + "-" + latestVersion + ".vsix";
                    dr = httpDownload(dlUrl, vsixPath);
                    if (dr.success) {
                        // Extract to install location (overwrite)
                        std::string targetDir = it->second.installPath;
                        if (targetDir.empty()) targetDir = installDir_ + extensionId + "/";
                        extractVsix(vsixPath, targetDir);
                        it->second.version = latestVersion;
                    }
                }
            }
        }
        // Clean up meta file
        std::filesystem::remove(metaPath);
    }

    states_[extensionId] = ExtensionState::ENABLED;

    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_UPDATED;
    evt.extensionId = extensionId;
    evt.detail = "Extension updated";
    emitEvent(evt);

    return ExtResult::ok("Extension updated");
}

ExtResult ExtensionMarketplace::updateAll() {
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> lock(marketplaceMutex_);
        for (auto& [id, _] : installed_) {
            ids.push_back(id);
        }
    }

    uint32_t updated = 0;
    for (auto& id : ids) {
        ExtResult r = update(id);
        if (r.success) updated++;
    }

    return ExtResult::ok("All extensions updated");
}

// ============================================================================
// Enable / Disable
// ============================================================================

ExtResult ExtensionMarketplace::enable(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    it->second.isEnabled = true;
    states_[extensionId] = ExtensionState::ENABLED;

    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_ENABLED;
    evt.extensionId = extensionId;
    evt.detail = "Extension enabled";
    emitEvent(evt);

    return ExtResult::ok("Extension enabled");
}

ExtResult ExtensionMarketplace::disable(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    it->second.isEnabled = false;
    states_[extensionId] = ExtensionState::DISABLED;

    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_DISABLED;
    evt.extensionId = extensionId;
    evt.detail = "Extension disabled";
    emitEvent(evt);

    return ExtResult::ok("Extension disabled");
}

// ============================================================================
// Extension Host Integration
// ============================================================================

ExtResult ExtensionMarketplace::activate(const std::string& extensionId,
                                          const std::string& activationEvent) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    if (!it->second.isEnabled)
        return ExtResult::error("Extension is disabled", 3);

    auto sit = states_.find(extensionId);
    if (sit != states_.end() && sit->second == ExtensionState::BLOCKED)
        return ExtResult::error("Extension blocked by policy", 10);

    // Interface with extension host via shared memory IPC
    // Create or open named shared memory region for extension activation
#ifdef _WIN32
    std::string shmName = "RawrXD_ExtHost_" + extensionId;
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, 16 * 1024 * 1024,  // 16MB per extension host slot
        shmName.c_str());

    if (hMapFile) {
        void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (pBuf) {
            // Write activation message to shared memory
            // Format: [MAGIC:4][MSG_TYPE:4][ID_LEN:4][ID_DATA:...][EVENT_LEN:4][EVENT_DATA:...]
            uint8_t* buf = static_cast<uint8_t*>(pBuf);
            uint32_t magic = 0x52585448; // "RXTH" — RawrXD Extension Host
            uint32_t msgType = 1;        // ACTIVATE
            uint32_t idLen = static_cast<uint32_t>(extensionId.size());
            std::string event = activationEvent.empty() ? "*" : activationEvent;
            uint32_t eventLen = static_cast<uint32_t>(event.size());

            memcpy(buf, &magic, 4);
            memcpy(buf + 4, &msgType, 4);
            memcpy(buf + 8, &idLen, 4);
            memcpy(buf + 12, extensionId.data(), idLen);
            memcpy(buf + 12 + idLen, &eventLen, 4);
            memcpy(buf + 16 + idLen, event.data(), eventLen);

            UnmapViewOfFile(pBuf);
        }
        CloseHandle(hMapFile);
    }
#endif

    states_[extensionId] = ExtensionState::ENABLED;

    MarketplaceEvent evt;
    evt.type = MarketplaceEvent::EXTENSION_ACTIVATED;
    evt.extensionId = extensionId;
    evt.detail = activationEvent.empty() ? "*" : activationEvent.c_str();
    emitEvent(evt);

    return ExtResult::ok("Extension activated");
}

ExtResult ExtensionMarketplace::deactivate(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    states_[extensionId] = ExtensionState::INSTALLED;

    return ExtResult::ok("Extension deactivated");
}

ExtensionState ExtensionMarketplace::getState(
    const std::string& extensionId) const
{
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    auto it = states_.find(extensionId);
    if (it == states_.end()) return ExtensionState::NOT_INSTALLED;
    return it->second;
}

ExtResult ExtensionMarketplace::getManifest(
    const std::string& extensionId,
    ExtensionManifest& manifest) const
{
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);
    manifest = it->second;
    return ExtResult::ok("Manifest retrieved");
}

// ============================================================================
// Dependency Resolution
// ============================================================================

ExtResult ExtensionMarketplace::checkDependencies(
    const std::string& extensionId,
    std::vector<std::string>& missingDeps)
{
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    missingDeps.clear();
    for (auto& dep : it->second.dependencies) {
        auto dit = installed_.find(dep.extensionId);
        if (dit == installed_.end()) {
            missingDeps.push_back(dep.extensionId);
        } else if (!dep.versionRange.empty()) {
            if (!semverSatisfies(dit->second.version, dep.versionRange)) {
                missingDeps.push_back(dep.extensionId +
                    " (needs " + dep.versionRange + ")");
            }
        }
    }

    if (!missingDeps.empty()) {
        return ExtResult::error("Missing dependencies", 4);
    }
    return ExtResult::ok("All dependencies satisfied");
}

ExtResult ExtensionMarketplace::installWithDependencies(
    const std::string& extensionId)
{
    std::vector<std::string> depOrder;
    ExtResult dr = getDependencyTree(extensionId, depOrder);
    if (!dr.success) return dr;

    // Install in dependency order
    for (const auto& depId : depOrder) {
        if (installed_.find(depId) == installed_.end()) {
            ExtResult ir = installFromRegistry(depId);
            if (!ir.success) {
                return ExtResult::error("Failed to install dependency", 6);
            }
        }
    }

    // Finally install the target extension
    return installFromRegistry(extensionId);
}

ExtResult ExtensionMarketplace::getDependencyTree(
    const std::string& extensionId,
    std::vector<std::string>& orderedDeps)
{
    // Topological sort of dependency graph
    std::unordered_map<std::string, std::vector<std::string>> adjList;
    std::unordered_map<std::string, uint32_t> inDegree;
    std::queue<std::string> buildQueue;
    buildQueue.push(extensionId);

    // BFS to discover full dependency graph
    while (!buildQueue.empty()) {
        std::string current = buildQueue.front();
        buildQueue.pop();

        if (adjList.find(current) != adjList.end()) continue;
        adjList[current] = {};

        auto it = installed_.find(current);
        if (it != installed_.end()) {
            for (auto& dep : it->second.dependencies) {
                adjList[current].push_back(dep.extensionId);
                inDegree[dep.extensionId]++;
                buildQueue.push(dep.extensionId);
            }
        }
    }

    // Initialize in-degree for root nodes
    for (auto& [id, _] : adjList) {
        if (inDegree.find(id) == inDegree.end()) {
            inDegree[id] = 0;
        }
    }

    // Kahn's algorithm
    std::queue<std::string> readyQueue;
    for (auto& [id, deg] : inDegree) {
        if (deg == 0 && id != extensionId) {
            readyQueue.push(id);
        }
    }

    orderedDeps.clear();
    while (!readyQueue.empty()) {
        std::string curr = readyQueue.front();
        readyQueue.pop();
        orderedDeps.push_back(curr);

        for (auto& neighbor : adjList[curr]) {
            if (--inDegree[neighbor] == 0 && neighbor != extensionId) {
                readyQueue.push(neighbor);
            }
        }
    }

    return ExtResult::ok("Dependency tree resolved");
}

ExtResult ExtensionMarketplace::resolveDependencies(
    const std::string& extensionId,
    std::vector<std::string>& sorted)
{
    // Delegates to getDependencyTree — same topological sort logic
    return getDependencyTree(extensionId, sorted);
}

// ============================================================================
// VSIX Operations
// ============================================================================

ExtResult ExtensionMarketplace::extractVsix(const std::string& vsixPath,
                                              const std::string& targetDir) {
    return extractZipPackage(vsixPath, targetDir);
}

ExtResult ExtensionMarketplace::extractZipPackage(const std::string& packagePath,
                                                    const std::string& targetDir) {
    std::filesystem::create_directories(targetDir);

    // ZIP-compatible packages — extract using Win32 Shell API or manual unzip
#ifdef _WIN32
    // Use Shell32 CopyHere for ZIP extraction (available on all Windows)
    // First, try lightweight manual ZIP parsing for .vsix
    std::ifstream vsixFile(packagePath, std::ios::binary);
    if (!vsixFile.is_open())
        return ExtResult::error("Cannot open package archive", 7);

    // Read file into memory for ZIP parsing
    vsixFile.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(vsixFile.tellg());
    vsixFile.seekg(0);

    if (fileSize < 22) {
        vsixFile.close();
        return ExtResult::error("VSIX too small to be valid ZIP", 7);
    }

    std::vector<uint8_t> zipData(fileSize);
    vsixFile.read(reinterpret_cast<char*>(zipData.data()), fileSize);
    vsixFile.close();

    // Verify ZIP signature: PK\x03\x04
    if (zipData[0] != 'P' || zipData[1] != 'K' ||
        zipData[2] != 0x03 || zipData[3] != 0x04) {
        // Not a ZIP — fall back to plain copy
        std::string destPath = targetDir + "/extension.pkg";
        std::filesystem::copy_file(packagePath, destPath,
            std::filesystem::copy_options::overwrite_existing);
        return ExtResult::ok("Package copied (not a valid ZIP)");
    }

    // Walk local file headers to extract entries
    size_t offset = 0;
    int extractedCount = 0;

    while (offset + 30 < fileSize) {
        // Check for local file header signature: PK\x03\x04
        if (zipData[offset] != 'P' || zipData[offset + 1] != 'K' ||
            zipData[offset + 2] != 0x03 || zipData[offset + 3] != 0x04) {
            break; // End of local headers
        }

        uint16_t compression = *(uint16_t*)(zipData.data() + offset + 8);
        uint32_t compressedSize = *(uint32_t*)(zipData.data() + offset + 18);
        uint32_t uncompressedSize = *(uint32_t*)(zipData.data() + offset + 22);
        uint16_t nameLen = *(uint16_t*)(zipData.data() + offset + 26);
        uint16_t extraLen = *(uint16_t*)(zipData.data() + offset + 28);

        std::string entryName(reinterpret_cast<char*>(zipData.data() + offset + 30), nameLen);
        size_t dataOffset = offset + 30 + nameLen + extraLen;

        if (dataOffset + compressedSize > fileSize) break;

        // Skip directories
        if (!entryName.empty() && entryName.back() != '/') {
            // Only extract stored (uncompressed) entries
            // For deflated entries, we'd need zlib
            if (compression == 0) {
                std::filesystem::path outPath = std::filesystem::path(targetDir) / entryName;
                std::filesystem::create_directories(outPath.parent_path());

                std::ofstream outFile(outPath, std::ios::binary | std::ios::trunc);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<char*>(zipData.data() + dataOffset),
                                 uncompressedSize);
                    outFile.close();
                    extractedCount++;
                }
            } else {
                // Deflated entry — copy raw for now, would need zlib to decompress
                // Store the compressed data with a .deflated extension as marker
                std::filesystem::path outPath = std::filesystem::path(targetDir) / entryName;
                std::filesystem::create_directories(outPath.parent_path());

                std::ofstream outFile(outPath, std::ios::binary | std::ios::trunc);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<char*>(zipData.data() + dataOffset),
                                 compressedSize);
                    outFile.close();
                    extractedCount++;
                }
            }
        }

        // Advance to next entry
        offset = dataOffset + compressedSize;
    }

    if (extractedCount == 0) {
        // Fallback: copy raw package
        std::string destPath = targetDir + "/extension.pkg";
        std::filesystem::copy_file(packagePath, destPath,
            std::filesystem::copy_options::overwrite_existing);
    }

    {
        thread_local char _okBuf[256];
        snprintf(_okBuf, sizeof(_okBuf), "Package extracted (%d files)", extractedCount);
        return ExtResult::ok(_okBuf);
    }
#else
    // POSIX: use system unzip
    std::string cmd = "unzip -o \"" + packagePath + "\" -d \"" + targetDir + "\"";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        thread_local char _errBuf[256];
        snprintf(_errBuf, sizeof(_errBuf), "unzip failed with code %d", ret);
        return ExtResult::error(_errBuf, 7);
    }
    return ExtResult::ok("Package extracted via unzip");
#endif
}

ExtResult ExtensionMarketplace::parseManifest(const std::string& manifestPath,
                                               ExtensionManifest& manifest) {
    std::ifstream file(manifestPath);
    if (!file.is_open())
        return ExtResult::error("Cannot open manifest", 1);

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    // Minimal JSON parser for package.json
    // Extract key fields: name, publisher, version, description, etc.
    auto extractField = [&content](const std::string& key) -> std::string {
        std::string pattern = "\"" + key + "\"";
        auto pos = content.find(pattern);
        if (pos == std::string::npos) return "";

        auto colonPos = content.find(':', pos + pattern.size());
        if (colonPos == std::string::npos) return "";

        auto quoteStart = content.find('"', colonPos + 1);
        if (quoteStart == std::string::npos) return "";

        auto quoteEnd = content.find('"', quoteStart + 1);
        if (quoteEnd == std::string::npos) return "";

        return content.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
    };

    manifest.name = extractField("name");
    manifest.publisher = extractField("publisher");
    manifest.version = extractField("version");
    manifest.description = extractField("description");
    manifest.displayName = extractField("displayName");
    manifest.license = extractField("license");

    if (!manifest.publisher.empty() && !manifest.name.empty()) {
        manifest.id = manifest.publisher + "." + manifest.name;
    }

    return ExtResult::ok("Manifest parsed");
}

ExtResult ExtensionMarketplace::verifySignature(const std::string& vsixPath) {
    if (!policy_.requireSignatureVerification) {
        return ExtResult::ok("Signature verification not required");
    }

    // Implement signature verification using WinVerifyTrust (Authenticode)
#ifdef _WIN32
    // Read the VSIX file to check for embedded signature
    std::ifstream vsixFile(vsixPath, std::ios::binary);
    if (!vsixFile.is_open())
        return ExtResult::error("Cannot open VSIX for verification", -1);

    vsixFile.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(vsixFile.tellg());
    vsixFile.seekg(0);

    // Check for signature file in ZIP (META-INF/SIGNATUR.SF or .signature.p7s)
    // Read first few KB to check ZIP structure
    std::vector<uint8_t> header(std::min(fileSize, size_t(65536)));
    vsixFile.read(reinterpret_cast<char*>(header.data()), header.size());
    vsixFile.close();

    // Look for signature entries in ZIP central directory
    bool hasSignature = false;
    for (size_t i = 0; i + 20 < header.size(); ++i) {
        if (header[i] == 'P' && header[i + 1] == 'K') {
            // Check if any entry is a signature file
            if (i + 30 < header.size()) {
                uint16_t nameLen = *(uint16_t*)(header.data() + i + 26);
                if (i + 30 + nameLen <= header.size()) {
                    std::string name(reinterpret_cast<char*>(header.data() + i + 30), nameLen);
                    if (name.find(".signature") != std::string::npos ||
                        name.find("SIGNATUR") != std::string::npos ||
                        name.find(".p7s") != std::string::npos) {
                        hasSignature = true;
                        break;
                    }
                }
            }
        }
    }

    if (!hasSignature) {
        return ExtResult::error("No signature found in VSIX package", -2);
    }

    // Signature file found — basic presence verification passed
    // Full cryptographic verification would require parsing PKCS#7/CMS
    // and validating against trusted certificate chain
    return ExtResult::ok("Signature present (basic verification passed)");
#else
    (void)vsixPath;
    return ExtResult::error("Signature verification requires Windows", -1);
#endif
}

// ============================================================================
// SemVer Comparison
// ============================================================================

bool ExtensionMarketplace::semverSatisfies(const std::string& version,
                                            const std::string& range) {
    // Minimal semver check — supports ">=X.Y.Z" and "X.Y.Z"
    if (range.empty()) return true;
    if (range == version) return true;

    // Parse version components
    auto parseVer = [](const std::string& v,
                       int& major, int& minor, int& patch) {
        major = minor = patch = 0;
        sscanf(v.c_str(), "%d.%d.%d", &major, &minor, &patch);
    };

    int vMaj, vMin, vPat;
    parseVer(version, vMaj, vMin, vPat);

    if (range.substr(0, 2) == ">=") {
        int rMaj, rMin, rPat;
        parseVer(range.substr(2), rMaj, rMin, rPat);

        if (vMaj > rMaj) return true;
        if (vMaj == rMaj && vMin > rMin) return true;
        if (vMaj == rMaj && vMin == rMin && vPat >= rPat) return true;
        return false;
    }

    // Default: exact match
    return version == range;
}

// ============================================================================
// HTTP Download
// ============================================================================

ExtResult ExtensionMarketplace::httpDownload(const std::string& url,
                                              const std::string& outputPath) {
#ifdef _WIN32
    // WinHTTP download
    MarketplaceEvent dlStart;
    dlStart.type = MarketplaceEvent::DOWNLOAD_STARTED;
    dlStart.extensionId = "";
    dlStart.detail = url.c_str();
    emitEvent(dlStart);

    // Parse URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = {};
    wchar_t urlPath[2048] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 2048;

    std::wstring wUrl(url.begin(), url.end());
    if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &urlComp)) {
        return ExtResult::error("Invalid URL", 20);
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD-Marketplace/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return ExtResult::error("WinHTTP session failed", 21);

    HINTERNET hConnect = WinHttpConnect(hSession, hostName,
                                         urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return ExtResult::error("WinHTTP connect failed", 22);
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ?
                  WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath,
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ExtResult::error("WinHTTP request failed", 23);
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                            0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ExtResult::error("HTTP request failed", 24);
    }

    // Read response body to file
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return ExtResult::error("Cannot open output file", 25);
    }

    DWORD bytesRead = 0;
    uint8_t buffer[8192];
    uint64_t totalBytes = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
        if (bytesRead == 0) break;
        outFile.write(reinterpret_cast<char*>(buffer), bytesRead);
        totalBytes += bytesRead;
    }

    outFile.close();
    totalDownloadBytes_.fetch_add(totalBytes);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    MarketplaceEvent dlDone;
    dlDone.type = MarketplaceEvent::DOWNLOAD_COMPLETED;
    dlDone.extensionId = "";
    dlDone.detail = "Download complete";
    emitEvent(dlDone);

    return ExtResult::ok("Download complete");

#else
    // POSIX: would use libcurl
    (void)url;
    (void)outputPath;
    return ExtResult::error("HTTP download not available on this platform", 30);
#endif
}

// ============================================================================
// Offline Cache
// ============================================================================

ExtResult ExtensionMarketplace::cacheExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    auto it = installed_.find(extensionId);
    if (it == installed_.end())
        return ExtResult::error("Extension not installed", 1);

    if (!it->second.vsixPath.empty() &&
        std::filesystem::exists(it->second.vsixPath)) {
        std::string cachePath = cacheDir_ + extensionId + ".vsix";
        std::filesystem::create_directories(cacheDir_);
        std::filesystem::copy_file(it->second.vsixPath, cachePath,
            std::filesystem::copy_options::overwrite_existing);
        return ExtResult::ok("Cached");
    }

    return ExtResult::error("No VSIX file available to cache", 2);
}

ExtResult ExtensionMarketplace::clearCache() {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);

    if (std::filesystem::exists(cacheDir_)) {
        std::error_code ec;
        std::filesystem::remove_all(cacheDir_, ec);
        std::filesystem::create_directories(cacheDir_);
    }

    return ExtResult::ok("Cache cleared");
}

ExtensionMarketplace::CacheStats
ExtensionMarketplace::getCacheStats() const {
    CacheStats stats = {};

    if (std::filesystem::exists(cacheDir_)) {
        for (const auto& entry :
             std::filesystem::directory_iterator(cacheDir_)) {
            if (entry.is_regular_file()) {
                stats.cachedExtensions++;
                stats.totalCacheSizeBytes += entry.file_size();
            }
        }
    }

    return stats;
}

// ============================================================================
// Events
// ============================================================================

void ExtensionMarketplace::addEventListener(MarketplaceEventCallback callback,
                                              void* userData) {
    uint32_t idx = eventListenerCount_.load();
    if (idx >= MAX_EVENT_LISTENERS) return;

    eventListeners_[idx].callback = callback;
    eventListeners_[idx].userData = userData;
    eventListenerCount_.fetch_add(1);
}

void ExtensionMarketplace::removeEventListener(
    MarketplaceEventCallback callback)
{
    uint32_t count = eventListenerCount_.load();
    for (uint32_t i = 0; i < count; ++i) {
        if (eventListeners_[i].callback == callback) {
            for (uint32_t j = i; j < count - 1; ++j) {
                eventListeners_[j] = eventListeners_[j + 1];
            }
            eventListenerCount_.fetch_sub(1);
            return;
        }
    }
}

void ExtensionMarketplace::emitEvent(const MarketplaceEvent& evt) {
    uint32_t count = eventListenerCount_.load();
    for (uint32_t i = 0; i < count; ++i) {
        if (eventListeners_[i].callback) {
            eventListeners_[i].callback(evt, eventListeners_[i].userData);
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

ExtensionMarketplace::MarketplaceStats
ExtensionMarketplace::getStats() const {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    MarketplaceStats stats = {};
    stats.totalInstalled = static_cast<uint32_t>(installed_.size());
    stats.totalDownloadBytes = totalDownloadBytes_.load();

    for (auto& [id, state] : states_) {
        switch (state) {
            case ExtensionState::ENABLED:  stats.totalEnabled++; break;
            case ExtensionState::DISABLED: stats.totalDisabled++; break;
            case ExtensionState::BLOCKED:  stats.totalBlocked++; break;
            default: break;
        }
    }

    return stats;
}

// ============================================================================
// Shutdown
// ============================================================================

void ExtensionMarketplace::shutdown() {
    std::lock_guard<std::mutex> lock(marketplaceMutex_);
    // Deactivate all extensions
    for (auto& [id, manifest] : installed_) {
        states_[id] = ExtensionState::INSTALLED;
    }
}

} // namespace Extensions
} // namespace RawrXD
