#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Extensions {

struct ExtensionInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::vector<std::string> dependencies;
};

class IExtension {
public:
    virtual ~IExtension() = default;
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual ExtensionInfo getInfo() const = 0;
};

class ExtensionManager {
public:
    static ExtensionManager& getInstance();
    
    bool loadExtension(const std::string& path);
    bool unloadExtension(const std::string& id);
    void loadAllExtensions(const std::string& directory);
    
    std::vector<ExtensionInfo> getLoadedExtensions() const;
    IExtension* getExtension(const std::string& id) const;
    
private:
    std::unordered_map<std::string, std::unique_ptr<IExtension>> extensions_;
    std::unordered_map<std::string, void*> handles_;
};

}