#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>

namespace RawrXD {
namespace Extensions {

// Extension manifest (package.json equivalent)
struct ExtensionManifest {
    std::string name;
    std::string version;
    std::string publisher;
    std::string description;
    std::string main;           // Entry point script
    std::vector<std::string> activationEvents;
    std::map<std::string, std::string> contributes;
    bool enabled = true;
};

// Extension context - passed to each extension
class ExtensionContext {
public:
    std::string extensionPath;
    std::string storagePath;
    std::string globalStoragePath;
    
    // VS Code API surface
    class Commands* commands;
    class Window* window;
    class Workspace* workspace;
    class Languages* languages;
    class Debug* debug;
    class Terminal* terminal;
};

// Extension instance
class Extension {
public:
    ExtensionManifest manifest;
    std::unique_ptr<ExtensionContext> context;
    bool isActive = false;
    void* moduleHandle = nullptr;  // QuickJS module
    
    bool Activate();
    bool Deactivate();
};

// Main extension host
class ExtensionHost {
public:
    static ExtensionHost& Instance();
    
    // Lifecycle
    bool Initialize();
    bool Shutdown();
    
    // Extension management
    bool LoadExtension(const std::string& path);
    bool UnloadExtension(const std::string& extensionId);
    bool EnableExtension(const std::string& extensionId);
    bool DisableExtension(const std::string& extensionId);
    
    // Activation
    void ActivateByEvent(const std::string& event);
    void ActivateByCommand(const std::string& command);
    void ActivateByLanguage(const std::string& language);
    
    // VS Code API implementation
    class Commands* GetCommands() { return commands_.get(); }
    class Window* GetWindow() { return window_.get(); }
    class Workspace* GetWorkspace() { return workspace_.get(); }
    
    // Marketplace
    bool InstallFromMarketplace(const std::string& extensionId);
    bool InstallFromVSIX(const std::string& vsixPath);
    
private:
    ExtensionHost() = default;
    ~ExtensionHost() = default;
    
    std::map<std::string, std::unique_ptr<Extension>> extensions_;
    std::mutex extensionsMutex_;
    
    std::unique_ptr<class Commands> commands_;
    std::unique_ptr<class Window> window_;
    std::unique_ptr<class Workspace> workspace_;
    std::unique_ptr<class Languages> languages_;
    std::unique_ptr<class Debug> debug_;
    std::unique_ptr<class Terminal> terminal_;
    
    void* quickJSRuntime_ = nullptr;
    void* quickJSContext_ = nullptr;
};

} // namespace Extensions
} // namespace RawrXD