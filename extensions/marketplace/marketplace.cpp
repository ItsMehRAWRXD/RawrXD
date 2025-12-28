#include "marketplace.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

namespace Extensions {

ExtensionMarketplace& ExtensionMarketplace::getInstance() {
    static ExtensionMarketplace instance;
    return instance;
}

std::vector<MarketplaceExtension> ExtensionMarketplace::searchExtensions(const std::string& query) {
    if (catalog_.empty()) loadLocalCatalog();
    
    if (query.empty()) return catalog_;
    
    std::vector<MarketplaceExtension> results;
    for (const auto& ext : catalog_) {
        if (ext.info.name.find(query) != std::string::npos ||
            ext.info.description.find(query) != std::string::npos) {
            results.push_back(ext);
        }
    }
    return results;
}

std::vector<MarketplaceExtension> ExtensionMarketplace::getExtensionsByCategory(const std::string& category) {
    std::vector<MarketplaceExtension> results;
    for (const auto& ext : catalog_) {
        if (ext.category == category) {
            results.push_back(ext);
        }
    }
    return results;
}

bool ExtensionMarketplace::downloadExtension(const std::string& id, const std::string& targetDir) {
    auto it = std::find_if(catalog_.begin(), catalog_.end(),
        [&id](const MarketplaceExtension& ext) { return ext.info.id == id; });
    
    if (it == catalog_.end()) return false;
    
    std::string filename = id + ".dll";
    std::string targetPath = targetDir + "\\" + filename;
    
    return downloadFile(it->downloadUrl, targetPath);
}

bool ExtensionMarketplace::installExtension(const std::string& id) {
    std::string extensionsDir = "extensions\\installed";
    std::filesystem::create_directories(extensionsDir);
    
    if (!downloadExtension(id, extensionsDir)) return false;
    
    std::string dllPath = extensionsDir + "\\" + id + ".dll";
    return ExtensionManager::getInstance().loadExtension(dllPath);
}

bool ExtensionMarketplace::uninstallExtension(const std::string& id) {
    ExtensionManager::getInstance().unloadExtension(id);
    
    std::string dllPath = "extensions\\installed\\" + id + ".dll";
    try {
        std::filesystem::remove(dllPath);
        return true;
    } catch (...) {
        return false;
    }
}

void ExtensionMarketplace::loadLocalCatalog() {
    // Sample extensions for testing
    catalog_ = {
        {{"theme-dark", "Dark Theme", "1.0.0", "Professional dark theme", "RawrXD Team", {}}, 
         "https://extensions.rawrxd.com/theme-dark.dll", "Themes", 1500, 4.8f, false},
        
        {{"git-integration", "Git Integration", "2.1.0", "Advanced Git workflow support", "DevTools Inc", {}},
         "https://extensions.rawrxd.com/git-integration.dll", "Version Control", 3200, 4.9f, false},
         
        {{"code-formatter", "Code Formatter", "1.5.2", "Multi-language code formatting", "CodeStyle Ltd", {}},
         "https://extensions.rawrxd.com/code-formatter.dll", "Productivity", 2800, 4.7f, false}
    };
}

bool ExtensionMarketplace::downloadFile(const std::string& url, const std::string& path) {
    HINTERNET hInternet = InternetOpenA("ExtensionDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    std::ofstream file(path, std::ios::binary);
    char buffer[4096];
    DWORD bytesRead;
    
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        file.write(buffer, bytesRead);
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return true;
}

}