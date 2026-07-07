// Extension Marketplace Manager - Qt-free implementation
#include <iostream>
#include <string>
#include <vector>

class ExtensionMarketplaceManager {
public:
    ExtensionMarketplaceManager() = default;
    
    std::vector<std::string> searchExtensions(const std::string& query) {
        (void)query;
        return {};
    }
    
    bool installExtension(const std::string& id) {
        (void)id;
        std::cout << "Installing extension" << std::endl;
        return true;
    }
};

int main() {
    ExtensionMarketplaceManager manager;
    manager.installExtension("test");
    return 0;
}
