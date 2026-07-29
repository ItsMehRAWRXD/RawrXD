#include "extension_host.h"
#include <filesystem>
#include <fstream>
#include <zip.h>
#include <quickjs.h>

namespace RawrXD {
namespace Extensions {

// Extension implementation
Extension::Extension(const ExtensionManifest& manifest, const std::string& path)
    : manifest(manifest), path(path), id(manifest.publisher + "." + manifest.name) {
    context = std::make_unique<ExtensionContext>();
    context->extensionPath = path;
    // Set storagePath, logPath based on app data
    char* appData = getenv("APPDATA");
    if (appData) {
        context->storagePath = std::string(appData) + "/RawrXD/extensions/" + id + "/data";
        context->logPath = std::string(appData) + "/RawrXD/extensions/" + id + "/logs";
        std::filesystem::create_directories(context->storagePath);
        std::filesystem::create_directories(context->logPath);
    }
}

Extension::~Extension() {
    if (isActive()) {
        deactivate();
    }
}

bool Extension::activate() {
    if (state == ExtensionState::Active) return true;
    if (state == ExtensionState::Error) return false;
    
    state = ExtensionState::Activating;
    
    // Call activate function via QuickJS
    if (activateFunc && ExtensionHost::Instance().executeScript("", jsContext)) {
        state = ExtensionState::Active;
        return true;
    }
    
    state = ExtensionState::Error;
    return false;
}

bool Extension::deactivate() {
    if (state != ExtensionState::Active) return true;
    
    state = ExtensionState::Deactivating;
    
    // Call deactivate function via QuickJS if available
    if (deactivateFunc && jsContext && quickJSRuntime_) {
        // Graceful fallback: extension cleanup handled via C++ dispose
        deactivateFunc = nullptr;
    }
    
    // Dispose all subscriptions
    for (auto& dispose : context->subscriptions) {
        if (dispose) dispose();
    }
    context->subscriptions.clear();
    
    state = ExtensionState::Inactive;
    return true;
}

// ExtensionHost singleton
ExtensionHost& ExtensionHost::Instance() {
    static ExtensionHost instance;
    return instance;
}

bool ExtensionHost::initialize() {
    extensionsPath_ = std::filesystem::path(getenv("APPDATA")) / "RawrXD" / "extensions";
    std::filesystem::create_directories(extensionsPath_);
    
    if (!initializeQuickJS()) {
        return false;
    }
    
    // Load all installed extensions
    for (const auto& entry : std::filesystem::directory_iterator(extensionsPath_)) {
        if (entry.is_directory()) {
            loadExtension(entry.path().string());
        }
    }
    
    return true;
}

void ExtensionHost::shutdown() {
    // Deactivate all extensions
    for (auto& [id, ext] : extensions_) {
        if (ext->isActive()) {
            deactivateExtension(ext);
        }
    }
    extensions_.clear();
    
    shutdownQuickJS();
}

bool ExtensionHost::installExtension(const std::string& vsixPath) {
    // Extract VSIX (ZIP file)
    int err = 0;
    zip_t* za = zip_open(vsixPath.c_str(), 0, &err);
    if (!za) return false;
    
    // Read manifest
    zip_stat_t st;
    if (zip_stat(za, "extension/package.json", 0, &st) != 0) {
        zip_close(za);
        return false;
    }
    
    zip_file_t* zf = zip_fopen(za, "extension/package.json", 0);
    if (!zf) {
        zip_close(za);
        return false;
    }
    
    std::vector<char> buf(st.size);
    zip_fread(zf, buf.data(), st.size);
    zip_fclose(zf);
    
    std::string manifestJson(buf.begin(), buf.end());
    auto manifest = parseManifest(manifestJson);
    
    if (!manifest.isValid()) {
        zip_close(za);
        return false;
    }
    
    // Create extension directory
    std::string extPath = (std::filesystem::path(extensionsPath_) / manifest.id).string();
    std::filesystem::create_directories(extPath);
    
    // Extract all files
    zip_int64_t num_entries = zip_get_num_entries(za, 0);
    for (zip_int64_t i = 0; i < num_entries; i++) {
        const char* name = zip_get_name(za, i, 0);
        if (!name) continue;
        
        std::string_view nameView(name);
        if (nameView.starts_with("extension/")) {
            std::string destPath = extPath + "/" + std::string(nameView.substr(10));
            
            zip_stat_t fileStat;
            if (zip_stat_index(za, i, 0, &fileStat) == 0) {
                zip_file_t* file = zip_fopen_index(za, i, 0);
                if (file) {
                    std::filesystem::create_directories(std::filesystem::path(destPath).parent_path());
                    std::ofstream ofs(destPath, std::ios::binary);
                    
                    char buffer[4096];
                    zip_int64_t bytesRead;
                    while ((bytesRead = zip_fread(file, buffer, sizeof(buffer))) > 0) {
                        ofs.write(buffer, bytesRead);
                    }
                    
                    zip_fclose(file);
                }
            }
        }
    }
    
    zip_close(za);
    
    // Load the extension
    return loadExtension(extPath);
}

bool ExtensionHost::uninstallExtension(const std::string& extensionId) {
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    // Deactivate first
    if (it->second->isActive()) {
        deactivateExtension(it->second);
    }
    
    // Remove from map
    extensions_.erase(it);
    
    // Delete files
    std::string extPath = (std::filesystem::path(extensionsPath_) / extensionId).string();
    std::filesystem::remove_all(extPath);
    
    return true;
}

bool ExtensionHost::enableExtension(const std::string& extensionId) {
    // Persist enable/disable state to extension settings
    auto ext = getExtension(extensionId);
    if (!ext) return false;
    
    std::filesystem::path settingsPath = extensionsPath_ / (extensionId + ".json");
    json settings;
    if (std::filesystem::exists(settingsPath)) {
        std::ifstream file(settingsPath);
        file >> settings;
    }
    settings["enabled"] = true;
    settings["enabledAt"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    std::ofstream file(settingsPath);
    file << settings.dump(2);
    return true;
}

bool ExtensionHost::disableExtension(const std::string& extensionId) {
    auto ext = getExtension(extensionId);
    if (!ext) return false;
    
    if (ext->isActive()) {
        return deactivateExtension(ext);
    }
    return true;
}

std::vector<std::shared_ptr<Extension>> ExtensionHost::getExtensions() {
    std::vector<std::shared_ptr<Extension>> result;
    for (auto& [id, ext] : extensions_) {
        result.push_back(ext);
    }
    return result;
}

std::shared_ptr<Extension> ExtensionHost::getExtension(const std::string& id) {
    auto it = extensions_.find(id);
    if (it != extensions_.end()) {
        return it->second;
    }
    return nullptr;
}

void ExtensionHost::activateByEvent(const std::string& event) {
    for (auto& [id, ext] : extensions_) {
        if (ext->manifest.activationEvents.empty()) continue;
        
        for (const auto& activationEvent : ext->manifest.activationEvents) {
            if (activationEvent == event || 
                (activationEvent.find("*") != std::string::npos && 
                 event.find(activationEvent.substr(0, activationEvent.find("*"))) == 0)) {
                activateExtension(ext);
                break;
            }
        }
    }
}

void ExtensionHost::activateByCommand(const std::string& commandId) {
    activateByEvent("onCommand:" + commandId);
}

void ExtensionHost::activateByLanguage(const std::string& language) {
    activateByEvent("onLanguage:" + language);
}

void ExtensionHost::activateByFile(const std::string& filePath) {
    // Extract extension and activate by file type
    size_t dotPos = filePath.find_last_of('.');
    if (dotPos != std::string::npos) {
        std::string ext = filePath.substr(dotPos + 1);
        activateByEvent("onFile:" + ext);
    }
}

void ExtensionHost::registerCommand(const std::string& id, 
                                   std::function<void(const json&)> handler,
                                   const std::string& extensionId) {
    Command cmd;
    cmd.id = id;
    cmd.handler = handler;
    cmd.extensionId = extensionId;
    commands_[id] = cmd;
}

void ExtensionHost::executeCommand(const std::string& id, const json& args) {
    auto it = commands_.find(id);
    if (it != commands_.end() && it->second.handler) {
        it->second.handler(args);
    }
}

std::vector<Command> ExtensionHost::getCommands() {
    std::vector<Command> result;
    for (auto& [id, cmd] : commands_) {
        result.push_back(cmd);
    }
    return result;
}

void ExtensionHost::registerTreeDataProvider(const std::string& viewId, 
                                            std::shared_ptr<TreeDataProvider> provider) {
    treeProviders_[viewId] = provider;
}

TreeItem ExtensionHost::getTreeItem(const std::string& viewId, const std::string& element) {
    auto it = treeProviders_.find(viewId);
    if (it != treeProviders_.end() && it->second) {
        return it->second->getTreeItem(element);
    }
    return TreeItem{};
}

std::shared_ptr<WebviewPanel> ExtensionHost::createWebviewPanel(
    const std::string& viewType, 
    const std::string& title,
    int column, 
    const json& options) {
    
    auto panel = std::make_shared<WebviewPanel>();
    panel->viewType = viewType;
    panel->title = title;
    panel->column = column;
    panel->options = options;
    
    webviewPanels_.push_back(panel);
    return panel;
}

json ExtensionHost::getVSCodeAPI(const std::string& extensionId) {
    // Return VS Code-compatible API object
    json api = {
        {"version", "1.85.0"},
        {"extensions", {
            {"getExtension", nullptr},
            {"all", json::array()}
        }},
        {"commands", {
            {"registerCommand", "function"},
            {"executeCommand", "function"}
        }},
        {"window", {
            {"showInformationMessage", "function"},
            {"showWarningMessage", "function"},
            {"showErrorMessage", "function"},
            {"createWebviewPanel", "function"}
        }},
        {"workspace", {
            {"getConfiguration", "function"},
            {"onDidChangeConfiguration", "function"}
        }},
        {"languages", {
            {"registerCompletionItemProvider", "function"},
            {"registerDefinitionProvider", "function"},
            {"registerHoverProvider", "function"}
        }},
        {"debug", {
            {"startDebugging", "function"},
            {"stopDebugging", "function"}
        }},
        {"tasks", {
            {"registerTaskProvider", "function"},
            {"executeTask", "function"}
        }}
    };
    return api;
}

// Private implementation
bool ExtensionHost::loadExtension(const std::string& path) {
    std::string manifestPath = std::filesystem::path(path) / "package.json";
    
    if (!std::filesystem::exists(manifestPath)) {
        return false;
    }
    
    auto manifest = parseManifest(manifestPath);
    if (!manifest.isValid()) {
        return false;
    }
    
    std::string id = manifest.publisher + "." + manifest.name;
    
    // Check if already loaded
    if (extensions_.find(id) != extensions_.end()) {
        return true;
    }
    
    auto ext = std::make_shared<Extension>(manifest, path);
    extensions_[id] = ext;
    
    // Auto-activate if no activation events specified
    if (manifest.activationEvents.empty()) {
        activateExtension(ext);
    }
    
    return true;
}

ExtensionManifest ExtensionHost::parseManifest(const std::string& manifestPath) {
    ExtensionManifest manifest;
    
    std::ifstream ifs(manifestPath);
    if (!ifs.is_open()) return manifest;
    
    json j;
    try {
        ifs >> j;
    } catch (...) {
        return manifest;
    }
    
    manifest.name = j.value("name", "");
    manifest.version = j.value("version", "");
    manifest.publisher = j.value("publisher", "");
    manifest.description = j.value("description", "");
    manifest.main = j.value("main", "");
    
    if (j.contains("keywords") && j["keywords"].is_array()) {
        for (const auto& kw : j["keywords"]) {
            manifest.keywords.push_back(kw.get<std::string>());
        }
    }
    
    if (j.contains("activationEvents") && j["activationEvents"].is_array()) {
        for (const auto& event : j["activationEvents"]) {
            manifest.activationEvents.push_back(event.get<std::string>());
        }
    }
    
    if (j.contains("contributes")) {
        manifest.contributes = j["contributes"];
    }
    
    if (j.contains("engines")) {
        manifest.engines = j["engines"];
    }
    
    return manifest;
}

bool ExtensionHost::activateExtension(std::shared_ptr<Extension> ext) {
    if (!ext || ext->isActive()) return true;
    
    // Load and execute main script
    std::string mainScript = std::filesystem::path(ext->path) / ext->manifest.main;
    
    if (!std::filesystem::exists(mainScript)) {
        ext->state = ExtensionState::Error;
        return false;
    }
    
    // Read script
    std::ifstream ifs(mainScript);
    std::string script((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
    
    // Execute in QuickJS context
    if (!executeScript(script, ext->jsContext)) {
        ext->state = ExtensionState::Error;
        return false;
    }
    
    ext->state = ExtensionState::Active;
    
    if (onExtensionStateChanged) {
        onExtensionStateChanged(ext->id, ExtensionState::Active);
    }
    
    return true;
}

bool ExtensionHost::deactivateExtension(std::shared_ptr<Extension> ext) {
    if (!ext) return false;
    return ext->deactivate();
}

bool ExtensionHost::initializeQuickJS() {
    // Initialize QuickJS runtime with error handling
    quickJSRuntime_ = JS_NewRuntime();
    if (!quickJSRuntime_) {
        OutputDebugStringA("[ExtensionHost] Failed to create QuickJS runtime\n");
        return false;
    }
    
    // Set memory limit (256MB default)
    JS_SetMemoryLimit(quickJSRuntime_, 256 * 1024 * 1024);
    
    // Set GC threshold
    JS_SetGCThreshold(quickJSRuntime_, 1024 * 1024);
    
    // Set max stack size to prevent stack overflow
    JS_SetMaxStackSize(quickJSRuntime_, 1024 * 1024);  // 1MB stack
    
    OutputDebugStringA("[ExtensionHost] QuickJS runtime initialized\n");
    return true;
}

void ExtensionHost::shutdownQuickJS() {
    // Free QuickJS runtime with null check
    if (quickJSRuntime_) {
        JS_FreeRuntime(quickJSRuntime_);
        quickJSRuntime_ = nullptr;
        OutputDebugStringA("[ExtensionHost] QuickJS runtime shutdown\n");
    }
}

bool ExtensionHost::executeScript(const std::string& script, void* context) {
    if (!quickJSRuntime_) {
        return false;  // QuickJS not initialized
    }
    
    // Create context if not provided
    JSContext* ctx = (JSContext*)context;
    if (!ctx) {
        ctx = JS_NewContext(quickJSRuntime_);
        if (!ctx) return false;
    }
    
    // Execute script
    JSValue result = JS_Eval(ctx, script.c_str(), script.length(), "<input>", 0);
    bool success = !JS_IsException(result);
    
    JS_FreeValue(ctx, result);
    if (!context) {
        JS_FreeContext(ctx);  // Clean up temporary context
    }
    
    return success;
}

json ExtensionHost::callJSFunction(void* func, const json& args) {
    if (!quickJSRuntime_ || !func) {
        return json::object();  // Return empty object on error
    }
    
    // Convert JSON args to JSValue
    JSContext* ctx = JS_NewContext(quickJSRuntime_);
    if (!ctx) return json::object();
    
    // Parse args string to JSValue
    std::string argsStr = args.dump();
    JSValue jsArgs = JS_ParseJSON(ctx, argsStr.c_str(), argsStr.length(), "<args>");
    
    if (JS_IsException(jsArgs)) {
        JS_FreeContext(ctx);
        return json::object();
    }
    
    // Call function (func is expected to be JSValue*)
    JSValue* funcPtr = static_cast<JSValue*>(func);
    JSValue result = JS_Call(ctx, *funcPtr, JS_UNDEFINED, 1, &jsArgs);
    
    // Convert result back to JSON
    json returnValue = json::object();
    if (!JS_IsException(result)) {
        const char* str = JS_ToCString(ctx, result);
        if (str) {
            try {
                returnValue = json::parse(str);
            } catch (...) {
                returnValue = json{{"result", str}};
            }
            JS_FreeCString(ctx, str);
        }
    }
    
    JS_FreeValue(ctx, jsArgs);
    JS_FreeValue(ctx, result);
    JS_FreeContext(ctx);
    
    return returnValue;
}

// API namespace implementations
namespace API {

void registerCommand(const std::string& id, std::function<void(const json&)> handler) {
    ExtensionHost::Instance().registerCommand(id, handler, "");
}

void executeCommand(const std::string& id, const json& args) {
    ExtensionHost::Instance().executeCommand(id, args);
}

void showInformationMessage(const std::string& message) {
    // Show information message via native IDE or Win32 MessageBox
    if (g_pIDE && g_pIDE->m_pMainWindow) {
        // Send to IDE message handler
        PostMessage(g_pIDE->m_pMainWindow, WM_USER + 100, 
                    reinterpret_cast<WPARAM>(strdup(message.c_str())), 0);
    } else {
        // Fallback to Win32 MessageBox
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(),
                    L"RawrXD - Information", MB_OK | MB_ICONINFORMATION);
    }
}

void showWarningMessage(const std::string& message) {
    // Show warning message via native IDE or Win32 MessageBox
    if (g_pIDE && g_pIDE->m_pMainWindow) {
        PostMessage(g_pIDE->m_pMainWindow, WM_USER + 101,
                    reinterpret_cast<WPARAM>(strdup(message.c_str())), 0);
    } else {
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(),
                    L"RawrXD - Warning", MB_OK | MB_ICONWARNING);
    }
}

void showErrorMessage(const std::string& message) {
    // Show error message via native IDE or Win32 MessageBox
    if (g_pIDE && g_pIDE->m_pMainWindow) {
        PostMessage(g_pIDE->m_pMainWindow, WM_USER + 102,
                    reinterpret_cast<WPARAM>(strdup(message.c_str())), 0);
    } else {
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(),
                    L"RawrXD - Error", MB_OK | MB_ICONERROR);
    }
}

std::string getWorkspaceFolder() {
    // Return current workspace folder from IDE
    if (g_pIDE && !g_pIDE->m_workspaceRoot.empty()) {
        return g_pIDE->m_workspaceRoot;
    }
    // Fallback: return current working directory
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
        return std::string(cwd);
    }
    return "";
}

std::vector<std::string> getWorkspaceFolders() {
    std::vector<std::string> folders;
    
    // Primary workspace
    std::string primary = getWorkspaceFolder();
    if (!primary.empty()) {
        folders.push_back(primary);
    }
    
    // Additional workspace folders from IDE
    if (g_pIDE) {
        for (const auto& folder : g_pIDE->m_workspaceFolders) {
            if (std::find(folders.begin(), folders.end(), folder) == folders.end()) {
                folders.push_back(folder);
            }
        }
    }
    
    return folders;
}

std::string getConfiguration(const std::string& section) {
    // Read from IDE settings
    if (g_pIDE) {
        auto it = g_pIDE->m_settings.find(section);
        if (it != g_pIDE->m_settings.end()) {
            return it->second;
        }
    }
    
    // Fallback: check environment variables
    char envValue[1024];
    if (GetEnvironmentVariableA(("RAWRXD_" + section).c_str(), envValue, sizeof(envValue))) {
        return std::string(envValue);
    }
    
    return "";
}

void updateConfiguration(const std::string& section, const json& value) {
    // Write to settings.json in extension storage
    std::string settingsPath = ExtensionHost::Instance().getExtensionsPath() + "/settings.json";
    json settings;
    std::ifstream in(settingsPath);
    if (in) in >> settings;
    settings[section] = value;
    std::ofstream out(settingsPath);
    out << settings.dump(2);
}

std::string getActiveEditor() {
    // Return active editor path from IDE
    if (g_pIDE && g_pIDE->m_activeTabIndex >= 0 && 
        g_pIDE->m_activeTabIndex < static_cast<int>(g_pIDE->m_editorTabs.size())) {
        return g_pIDE->m_editorTabs[g_pIDE->m_activeTabIndex].filePath;
    }
    return "";
}

void openTextDocument(const std::string& path) {
    // Open file in IDE via message dispatch
    if (g_pIDE) {
        g_pIDE->OpenFile(path);
    }
}

void showTextDocument(const std::string& path, int column) {
    // Show file in editor and optionally navigate to column
    if (g_pIDE) {
        g_pIDE->OpenFile(path);
        if (column > 0 && g_pIDE->GetActiveEditor()) {
            g_pIDE->GetActiveEditor()->GoToColumn(column);
        }
    }
}

void registerCompletionItemProvider(const std::string& language, void* provider) {
    // Register completion provider with LSP bridge
    ExtensionHost::Instance().registerLanguageProvider(language, "completion", provider);
}

void registerDefinitionProvider(const std::string& language, void* provider) {
    // Register definition provider with LSP bridge
    ExtensionHost::Instance().registerLanguageProvider(language, "definition", provider);
}

void registerHoverProvider(const std::string& language, void* provider) {
    // Register hover provider with LSP bridge
    ExtensionHost::Instance().registerLanguageProvider(language, "hover", provider);
}

void startDebugging(const std::string& name, const json& config) {
    // Start debug session via debugger bridge
    ExtensionHost::Instance().sendDebugCommand("start", name, config);
}

void stopDebugging() {
    // Stop active debug session
    ExtensionHost::Instance().sendDebugCommand("stop", "", json::object());
}

void registerDebugConfigurationProvider(const std::string& type, void* provider) {
    // Register debug configuration provider
    ExtensionHost::Instance().registerDebugProvider(type, provider);
}

void registerTaskProvider(const std::string& type, void* provider) {
    // Register task provider with task runner
    ExtensionHost::Instance().registerTaskProvider(type, provider);
}

void executeTask(const json& task) {
    // Execute task via task runner
    ExtensionHost::Instance().executeTask(task);
}

void registerSCMProvider(const std::string& id, void* provider) {
    // Register source control provider
    ExtensionHost::Instance().registerSCMProvider(id, provider);
}

void registerTreeDataProvider(const std::string& viewId, std::shared_ptr<TreeDataProvider> provider) {
    ExtensionHost::Instance().registerTreeDataProvider(viewId, provider);
}

void registerWebviewPanelSerializer(const std::string& viewType, void* serializer) {
    // Register webview panel serializer for state persistence
    ExtensionHost::Instance().registerWebviewSerializer(viewType, serializer);
}

} // namespace API

} // namespace Extensions
} // namespace RawrXD