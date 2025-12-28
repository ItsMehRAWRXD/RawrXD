#pragma once
#include "../core/extension_manager.h"
#include <string>
#include <vector>
#include <functional>

namespace Extensions {

struct MarketplaceExtension {
    ExtensionInfo info;
    std::string downloadUrl;
    std::string category;
    int downloads;
    float rating;
    bool installed;
};

class ExtensionMarketplace {
public:
    static ExtensionMarketplace& getInstance();
    
    std::vector<MarketplaceExtension> searchExtensions(const std::string& query = "");
    std::vector<MarketplaceExtension> getExtensionsByCategory(const std::string& category);
    
    bool downloadExtension(const std::string& id, const std::string& targetDir);
    bool installExtension(const std::string& id);
    bool uninstallExtension(const std::string& id);
    
    void refreshCatalog();
    
private:
    std::vector<MarketplaceExtension> catalog_;
    std::string marketplaceUrl_ = "https://extensions.rawrxd.com/api/";
    
    void loadLocalCatalog();
    bool downloadFile(const std::string& url, const std::string& path);
};

}