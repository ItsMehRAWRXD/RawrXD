#include "extension_manager.h"
#include <windows.h>
#include <filesystem>
#include <iostream>

namespace Extensions {

ExtensionManager& ExtensionManager::getInstance() {
    static ExtensionManager instance;
    return instance;
}

bool ExtensionManager::loadExtension(const std::string& path) {
    HMODULE handle = LoadLibraryA(path.c_str());
    if (!handle) {
        std::cerr << "Failed to load extension: " << path << std::endl;
        return false;
    }

    typedef IExtension* (*CreateExtensionFunc)();
    CreateExtensionFunc createExtension = (CreateExtensionFunc)GetProcAddress(handle, "createExtension");
    
    if (!createExtension) {
        FreeLibrary(handle);
        std::cerr << "Extension missing createExtension function: " << path << std::endl;
        return false;
    }

    auto extension = std::unique_ptr<IExtension>(createExtension());
    if (!extension || !extension->initialize()) {
        FreeLibrary(handle);
        return false;
    }

    std::string id = extension->getInfo().id;
    extensions_[id] = std::move(extension);
    handles_[id] = handle;
    
    std::cout << "Loaded extension: " << id << std::endl;
    return true;
}

bool ExtensionManager::unloadExtension(const std::string& id) {
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;

    it->second->shutdown();
    extensions_.erase(it);
    
    auto handleIt = handles_.find(id);
    if (handleIt != handles_.end()) {
        FreeLibrary((HMODULE)handleIt->second);
        handles_.erase(handleIt);
    }
    
    return true;
}

void ExtensionManager::loadAllExtensions(const std::string& directory) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() == ".dll") {
            loadExtension(entry.path().string());
        }
    }
}

std::vector<ExtensionInfo> ExtensionManager::getLoadedExtensions() const {
    std::vector<ExtensionInfo> result;
    for (const auto& [id, ext] : extensions_) {
        result.push_back(ext->getInfo());
    }
    return result;
}

IExtension* ExtensionManager::getExtension(const std::string& id) const {
    auto it = extensions_.find(id);
    return it != extensions_.end() ? it->second.get() : nullptr;
}

}