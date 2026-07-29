#pragma once
<<<<<<< HEAD
#include <string>
#include <functional>

class HotReload {
public:
    HotReload() = default;
    bool reloadQuant(const std::string& quantType);
    bool reloadModule(const std::string& moduleName);

    // Callbacks (replace Qt signals)
=======

#include <string>
#include <functional>

class HotReload {
public:
    explicit HotReload();
    
    // Reload quantization library on-the-fly
    bool reloadQuant(const std::string& quantType);
    
    // Reload specific module
    bool reloadModule(const std::string& moduleName);
    
    // Callbacks replacing signals
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::function<void(const std::string&)> onQuantReloaded;
    std::function<void(const std::string&)> onModuleReloaded;
    std::function<void(const std::string&)> onReloadFailed;
};
