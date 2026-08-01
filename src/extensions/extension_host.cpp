#include "extension_host.h"
#include <windows.h>
#include <shlwapi.h>
#include <json/json.h>
#include <quickjs/quickjs.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace Extensions {

// Commands API implementation
class Commands {
public:
    using CommandHandler = std::function<void(const std::vector<std::string>&)>;
    
    void RegisterCommand(const std::string& command, CommandHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        commands_[command] = handler;
    }
    
    void ExecuteCommand(const std::string& command, const std::vector<std::string>& args) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = commands_.find(command);
        if (it != commands_.end()) {
            it->second(args);
        }
    }
    
private:
    std::map<std::string, CommandHandler> commands_;
    std::mutex mutex_;
};

// Window API implementation
class Window {
public:
    void ShowInformationMessage(const std::string& message) {
        MessageBoxA(nullptr, message.c_str(), "RawrXD", MB_OK | MB_ICONINFORMATION);
    }
    
    void ShowErrorMessage(const std::string& message) {
        MessageBoxA(nullptr, message.c_str(), "RawrXD", MB_OK | MB_ICONERROR);
    }
};

// Workspace API implementation
class Workspace {
public:
    std::string GetWorkspaceFolder() {
        char path[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, path);
        return std::string(path);
    }
    
    std::vector<std::string> GetTextDocuments() {
        // Return list of open documents
        return {};
    }
};

// Languages API implementation
class Languages {
public:
    void RegisterCompletionProvider(const std::string& language, 
                                    std::function<std::vector<std::string>(const std::string&)> provider) {
        providers_[language] = provider;
    }
    
private:
    std::map<std::string, std::function<std::vector<std::string>(const std::string&)>> providers_;
};

// Debug API implementation
class Debug {
public:
    void RegisterDebugConfigurationProvider(const std::string& type, 
                                           std::function<bool(const std::string&)> provider) {
        providers_[type] = provider;
    }
    
private:
    std::map<std::string, std::function<bool(const std::string&)>> providers_;
};

// Terminal API implementation
class Terminal {
public:
    void CreateTerminal(const std::string& name, const std::string& shellPath) {
        // Create terminal instance
    }
};

// ExtensionHost implementation
ExtensionHost& ExtensionHost::Instance() {
    static ExtensionHost instance;
    return instance;
}

bool ExtensionHost::Initialize() {
    // Initialize QuickJS runtime
    quickJSRuntime_ = JS_NewRuntime();
    if (!quickJSRuntime_) return false;
    
    quickJSContext_ = JS_NewContext(quickJSRuntime_);
    if (!quickJSContext_) {
        JS_FreeRuntime(quickJSRuntime_);
        return false;
    }
    
    // Initialize API implementations
    commands_ = std::make_unique<Commands>();
    window_ = std::make_unique<Window>();
    workspace_ = std::make_unique<Workspace>();
    languages_ = std::make_unique<Languages>();
    debug_ = std::make_unique<Debug>();
    terminal_ = std::make_unique<Terminal>();
    
    // Load all installed extensions
    char extensionsPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, extensionsPath);
    PathAppendA(extensionsPath, "\\RawrXD\\extensions");
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((std::string(extensionsPath) + "\\*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    std::string extPath = std::string(extensionsPath) + "\\" + findData.cFileName;
                    LoadExtension(extPath);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    return true;
}

bool ExtensionHost::Shutdown() {
    // Deactivate all extensions
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    for (auto& [id, ext] : extensions_) {
        ext->Deactivate();
    }
    extensions_.clear();
    
    // Cleanup QuickJS
    if (quickJSContext_) {
        JS_FreeContext(quickJSContext_);
        quickJSContext_ = nullptr;
    }
    if (quickJSRuntime_) {
        JS_FreeRuntime(quickJSRuntime_);
        quickJSRuntime_ = nullptr;
    }
    
    return true;
}

bool ExtensionHost::LoadExtension(const std::string& path) {
    // Read package.json
    std::string packagePath = path + "\\package.json";
    std::ifstream file(packagePath);
    if (!file.is_open()) return false;
    
    std::string jsonStr((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Parse manifest
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(jsonStr, root)) return false;
    
    auto ext = std::make_unique<Extension>();
    ext->manifest.name = root.get("name", "").asString();
    ext->manifest.version = root.get("version", "").asString();
    ext->manifest.publisher = root.get("publisher", "").asString();
    ext->manifest.description = root.get("description", "").asString();
    ext->manifest.main = root.get("main", "extension.js").asString();
    
    const Json::Value& activationEvents = root["activationEvents"];
    for (const auto& event : activationEvents) {
        ext->manifest.activationEvents.push_back(event.asString());
    }
    
    // Create context
    ext->context = std::make_unique<ExtensionContext>();
    ext->context->extensionPath = path;
    ext->context->commands = commands_.get();
    ext->context->window = window_.get();
    ext->context->workspace = workspace_.get();
    
    std::string extId = ext->manifest.publisher + "." + ext->manifest.name;
    
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    extensions_[extId] = std::move(ext);
    
    return true;
}

bool ExtensionHost::UnloadExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->Deactivate();
    extensions_.erase(it);
    return true;
}

bool ExtensionHost::EnableExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->manifest.enabled = true;
    return true;
}

bool ExtensionHost::DisableExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->manifest.enabled = false;
    it->second->Deactivate();
    return true;
}

void ExtensionHost::ActivateByEvent(const std::string& event) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    for (auto& [id, ext] : extensions_) {
        if (!ext->manifest.enabled || ext->isActive) continue;
        
        for (const auto& activationEvent : ext->manifest.activationEvents) {
            if (activationEvent == event || activationEvent == "*") {
                ext->Activate();
                break;
            }
        }
    }
}

void ExtensionHost::ActivateByCommand(const std::string& command) {
    ActivateByEvent("onCommand:" + command);
}

void ExtensionHost::ActivateByLanguage(const std::string& language) {
    ActivateByEvent("onLanguage:" + language);
}

bool ExtensionHost::InstallFromVSIX(const std::string& vsixPath) {
    // Extract VSIX (zip file) to extensions folder
    char extensionsPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, extensionsPath);
    PathAppendA(extensionsPath, "\\RawrXD\\extensions");
    
    // Create directory if needed
    CreateDirectoryA(extensionsPath, nullptr);
    
    // Extract using Windows Shell
    // This is simplified - real implementation would use proper zip extraction
    std::string extractCmd = "powershell -command \"Expand-Archive -Path '\"" + vsixPath + "'\" -DestinationPath '\"" + extensionsPath + "'\"\"";
    system(extractCmd.c_str());
    
    return true;
}

bool Extension::Activate() {
    if (isActive) return true;
    
    // Load and execute extension script
    std::string scriptPath = context->extensionPath + "\\" + manifest.main;
    
    // TODO: Execute in QuickJS context with API bindings
    
    isActive = true;
    return true;
}

bool Extension::Deactivate() {
    if (!isActive) return true;
    
    // Cleanup
    isActive = false;
    return true;
}

} // namespace Extensions
} // namespace RawrXD
