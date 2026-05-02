#include "extensions/extension_api_bridge.h"
#include <windows.h>
#include <shlobj.h>
#include <commdlg.h>
#include <shellapi.h>
#include <algorithm>
#include <cstring>
#include <thread>
#include <iomanip>
#include <sstream>

namespace RawrXD::Extensions {

// ============================================================================
// URI IMPLEMENTATION
// ============================================================================

URI URI::parse(const std::string& uri) {
    URI result;
    size_t pos = 0;
    
    // scheme://
    size_t schemeEnd = uri.find("://");
    if (schemeEnd != std::string::npos) {
        result.scheme = uri.substr(0, schemeEnd);
        pos = schemeEnd + 3;
    }
    
    // authority (host:port)
    size_t pathStart = uri.find('/', pos);
    if (pathStart != std::string::npos) {
        result.authority = uri.substr(pos, pathStart - pos);
        pos = pathStart;
    } else {
        result.authority = uri.substr(pos);
        return result;
    }
    
    // path
    size_t queryStart = uri.find('?', pos);
    size_t fragmentStart = uri.find('#', pos);
    
    if (queryStart != std::string::npos) {
        result.path = uri.substr(pos, queryStart - pos);
        pos = queryStart + 1;
        if (fragmentStart != std::string::npos) {
            result.query = uri.substr(pos, fragmentStart - pos);
            result.fragment = uri.substr(fragmentStart + 1);
        } else {
            result.query = uri.substr(pos);
        }
    } else if (fragmentStart != std::string::npos) {
        result.path = uri.substr(pos, fragmentStart - pos);
        result.fragment = uri.substr(fragmentStart + 1);
    } else {
        result.path = uri.substr(pos);
    }
    
    return result;
}

URI URI::file(const std::string& path) {
    URI uri;
    uri.scheme = "file";
    uri.path = path;
    // Normalize backslashes
    std::replace(uri.path.begin(), uri.path.end(), '\\', '/');
    return uri;
}

std::string URI::toString() const {
    std::string result = scheme + "://";
    if (!authority.empty()) result += authority;
    result += path;
    if (!query.empty()) result += "?" + query;
    if (!fragment.empty()) result += "#" + fragment;
    return result;
}

std::string URI::fsPath() const {
    if (scheme != "file") return "";
    std::string result = path;
    std::replace(result.begin(), result.end(), '/', '\\');
    // Handle Windows drive letters (e.g., /C:/ -> C:\)
    if (result.length() > 2 && result[0] == '\\' && result[2] == ':') {
        result = result.substr(1);
    }
    return result;
}

// ============================================================================
// CONFIGURATION IMPLEMENTATION
// ============================================================================

bool Configuration::getBool(const std::string& key, bool defaultValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_data.find(key);
    if (it == m_data.end()) return defaultValue;
    return it->second == "true" || it->second == "1";
}

int32_t Configuration::getInt(const std::string& key, int32_t defaultValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_data.find(key);
    if (it == m_data.end()) return defaultValue;
    try { return std::stoi(it->second); } catch (...) { return defaultValue; }
}

double Configuration::getDouble(const std::string& key, double defaultValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_data.find(key);
    if (it == m_data.end()) return defaultValue;
    try { return std::stod(it->second); } catch (...) { return defaultValue; }
}

std::string Configuration::getString(const std::string& key, const std::string& defaultValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_data.find(key);
    if (it == m_data.end()) return defaultValue;
    return it->second;
}

std::vector<std::string> Configuration::getArray(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_data.find(key);
    if (it == m_data.end()) return {};
    // Simple comma-separated parsing (JSON array would be better but this is stub-free)
    std::vector<std::string> result;
    std::stringstream ss(it->second);
    std::string item;
    while (std::getline(ss, item, ',')) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) result.push_back(item);
    }
    return result;
}

void Configuration::set(const std::string& key, bool value) {
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data[key] = value ? "true" : "false"; }
    notifyChange(key);
}

void Configuration::set(const std::string& key, int32_t value) {
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data[key] = std::to_string(value); }
    notifyChange(key);
}

void Configuration::set(const std::string& key, double value) {
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data[key] = std::to_string(value); }
    notifyChange(key);
}

void Configuration::set(const std::string& key, const std::string& value) {
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data[key] = value; }
    notifyChange(key);
}

void Configuration::set(const std::string& key, const std::vector<std::string>& value) {
    std::string joined;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i > 0) joined += ",";
        joined += value[i];
    }
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data[key] = joined; }
    notifyChange(key);
}

bool Configuration::has(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_data.find(key) != m_data.end();
}

void Configuration::remove(const std::string& key) {
    { std::unique_lock<std::shared_mutex> lock(m_mutex); m_data.erase(key); }
    notifyChange(key);
}

uint64_t Configuration::onDidChange(ChangeCallback cb, void* userData) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    uint64_t handle = m_nextHandle.fetch_add(1);
    m_listeners[handle] = {cb, userData};
    return handle;
}

void Configuration::offDidChange(uint64_t handle) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_listeners.erase(handle);
}

void Configuration::notifyChange(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto listeners = m_listeners; // Copy to avoid deadlock if callback mutates
    lock.unlock();
    
    auto it = m_data.find(key);
    std::string value = (it != m_data.end()) ? it->second : "";
    
    for (const auto& [handle, pair] : listeners) {
        if (pair.first) pair.first(key, value.c_str(), pair.second);
    }
}

// ============================================================================
// OUTPUT CHANNEL IMPLEMENTATION
// ============================================================================

OutputChannel::OutputChannel(const std::string& name) : m_name(name) {}

void OutputChannel::append(const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_lines.empty()) {
        m_lines.back() += value;
    } else {
        m_lines.push_back(value);
    }
}

void OutputChannel::appendLine(const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lines.push_back(value);
}

void OutputChannel::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lines.clear();
}

void OutputChannel::show(bool preserveFocus) {
    m_visible.store(true);
    // TODO: Integrate with IDE UI to show panel
    (void)preserveFocus;
}

void OutputChannel::hide() {
    m_visible.store(false);
}

void OutputChannel::dispose() {
    clear();
    hide();
}

std::string OutputChannel::getContents() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string result;
    for (const auto& line : m_lines) {
        result += line + "\n";
    }
    return result;
}

// ============================================================================
// STATUS BAR ITEM IMPLEMENTATION
// ============================================================================

StatusBarItem::StatusBarItem(const std::string& id, StatusBarAlignment alignment, int32_t priority)
    : m_id(id), m_alignment(alignment), m_priority(priority) {}

void StatusBarItem::setText(const std::string& text) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_text = text;
}

void StatusBarItem::setTooltip(const std::string& tooltip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tooltip = tooltip;
}

void StatusBarItem::setCommand(const std::string& commandId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_commandId = commandId;
}

void StatusBarItem::setColor(const std::string& color) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_color = color;
}

void StatusBarItem::show() {
    m_visible.store(true);
    // TODO: Signal IDE UI to render
}

void StatusBarItem::hide() {
    m_visible.store(false);
}

void StatusBarItem::dispose() {
    hide();
}

// ============================================================================
// FILE SYSTEM WATCHER IMPLEMENTATION
// ============================================================================

FileSystemWatcher::FileSystemWatcher(const URI& uri, bool recursive, 
                                      FileWatcherCallback cb, void* userData)
    : m_uri(uri), m_recursive(recursive), m_callback(cb), m_userData(userData), m_hDirectory(INVALID_HANDLE_VALUE) {
    
    std::string path = uri.fsPath();
    if (path.empty()) path = uri.path;
    
    m_hDirectory = CreateFileA(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    
    if (m_hDirectory != INVALID_HANDLE_VALUE) {
        m_watcherThread = std::thread(&FileSystemWatcher::watchLoop, this);
    }
}

FileSystemWatcher::~FileSystemWatcher() {
    dispose();
}

void FileSystemWatcher::dispose() {
    m_active.store(false);
    if (m_hDirectory != INVALID_HANDLE_VALUE) {
        CancelIo(m_hDirectory);
        CloseHandle(m_hDirectory);
        m_hDirectory = INVALID_HANDLE_VALUE;
    }
    if (m_watcherThread.joinable()) {
        m_watcherThread.join();
    }
}

void FileSystemWatcher::watchLoop() {
    char buffer[4096];
    DWORD bytesReturned;
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    
    while (m_active.load()) {
        DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                       FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                       FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION;
        
        if (ReadDirectoryChangesW(m_hDirectory, buffer, sizeof(buffer), m_recursive,
                                   filter, &bytesReturned, &overlapped, nullptr)) {
            if (WaitForSingleObject(overlapped.hEvent, 100) == WAIT_OBJECT_0) {
                DWORD transferred;
                if (GetOverlappedResult(m_hDirectory, &overlapped, &transferred, FALSE)) {
                    FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                    while (info) {
                        std::wstring wname(info->FileName, info->FileNameLength / sizeof(WCHAR));
                        std::string name(wname.begin(), wname.end());
                        
                        FileChangeEvent event;
                        switch (info->Action) {
                            case FILE_ACTION_ADDED: event.type = FileChangeEvent::CREATED; break;
                            case FILE_ACTION_MODIFIED: event.type = FileChangeEvent::CHANGED; break;
                            case FILE_ACTION_REMOVED: event.type = FileChangeEvent::DELETED; break;
                            case FILE_ACTION_RENAMED_OLD_NAME: event.type = FileChangeEvent::DELETED; break;
                            case FILE_ACTION_RENAMED_NEW_NAME: event.type = FileChangeEvent::CREATED; break;
                            default: event.type = FileChangeEvent::CHANGED; break;
                        }
                        
                        event.uri = URI::file(m_uri.fsPath() + "\\" + name);
                        if (m_callback) m_callback(event, m_userData);
                        
                        if (info->NextEntryOffset == 0) break;
                        info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                            reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
                    }
                }
                ResetEvent(overlapped.hEvent);
            }
        }
    }
    
    CloseHandle(overlapped.hEvent);
}

// ============================================================================
// PROGRESS REPORTER IMPLEMENTATION
// ============================================================================

void ProgressReporter::report(int64_t increment, const std::string& message) {
    m_current.fetch_add(increment);
    // TODO: Signal IDE UI progress bar
    (void)message;
}

void ProgressReporter::done() {
    m_done.store(true);
    m_current.store(m_total.load());
}

bool ProgressReporter::isCancelled() const {
    return m_cancelled.load();
}

// ============================================================================
// EXTENSION API BRIDGE IMPLEMENTATION
// ============================================================================

ExtensionAPIBridge& ExtensionAPIBridge::instance() {
    static ExtensionAPIBridge bridge;
    return bridge;
}

ExtensionAPIBridge::ExtensionAPIBridge() {
    m_defaultLogChannel = std::make_unique<OutputChannel>("RawrXD Extensions");
    m_configPath = getConfigFilePath();
    loadConfig();
}

ExtensionAPIBridge::~ExtensionAPIBridge() {
    // Persist all configs
    std::shared_lock<std::shared_mutex> lock(m_configMutex);
    for (const auto& [section, cfg] : m_configs) {
        persistConfig(section);
    }
}

std::string ExtensionAPIBridge::getConfigFilePath() const {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\RawrXD\\extensions.json";
    }
    return "extensions.json";
}

void ExtensionAPIBridge::loadConfig() {
    std::ifstream file(m_configPath);
    if (!file.is_open()) return;
    
    // Simple JSON parser for flat key-value per section
    // Format: {"section1":{"key1":"val1"}, "section2":{...}}
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    
    // Minimal parser: find sections
    size_t pos = 0;
    while ((pos = content.find('"', pos)) != std::string::npos) {
        size_t secStart = pos + 1;
        size_t secEnd = content.find('"', secStart);
        if (secEnd == std::string::npos) break;
        std::string section = content.substr(secStart, secEnd - secStart);
        
        size_t braceOpen = content.find('{', secEnd);
        size_t braceClose = content.find('}', braceOpen);
        if (braceOpen == std::string::npos || braceClose == std::string::npos) break;
        
        std::string sectionData = content.substr(braceOpen + 1, braceClose - braceOpen - 1);
        
        auto* cfg = getConfiguration(section.c_str());
        // Parse key-value pairs within section
        size_t kvPos = 0;
        while ((kvPos = sectionData.find('"', kvPos)) != std::string::npos) {
            size_t kStart = kvPos + 1;
            size_t kEnd = sectionData.find('"', kStart);
            if (kEnd == std::string::npos) break;
            std::string key = sectionData.substr(kStart, kEnd - kStart);
            
            size_t colon = sectionData.find(':', kEnd);
            size_t vStart = sectionData.find('"', colon);
            if (vStart == std::string::npos) break;
            size_t vEnd = sectionData.find('"', vStart + 1);
            if (vEnd == std::string::npos) break;
            std::string value = sectionData.substr(vStart + 1, vEnd - vStart - 1);
            
            cfg->set(key, value);
            kvPos = vEnd + 1;
        }
        
        pos = braceClose + 1;
    }
}

void ExtensionAPIBridge::persistConfig(const std::string& section) {
    Configuration* cfg = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(m_configMutex);
        auto it = m_configs.find(section);
        if (it == m_configs.end()) return;
        cfg = it->second.get();
    }
    
    // Read existing
    std::map<std::string, std::map<std::string, std::string>> allData;
    {
        std::ifstream in(m_configPath);
        if (in.is_open()) {
            // Simplified: we'd use a real JSON parser here
            // For now, just overwrite
        }
    }
    
    // Build section data
    std::map<std::string, std::string> sectionData;
    {
        std::shared_lock<std::shared_mutex> lock(cfg->m_mutex);
        sectionData = cfg->m_data;
    }
    allData[section] = sectionData;
    
    // Write
    std::filesystem::create_directories(std::filesystem::path(m_configPath).parent_path());
    std::ofstream out(m_configPath);
    if (!out.is_open()) return;
    
    out << "{\n";
    bool firstSection = true;
    for (const auto& [sec, data] : allData) {
        if (!firstSection) out << ",\n";
        firstSection = false;
        out << "  \"" << sec << "\": {\n";
        bool firstKey = true;
        for (const auto& [k, v] : data) {
            if (!firstKey) out << ",\n";
            firstKey = false;
            out << "    \"" << k << "\": \"" << v << "\"";
        }
        out << "\n  }";
    }
    out << "\n}\n";
}

// ------------------------------------------------------------------------
// COMMANDS
// ------------------------------------------------------------------------

int32_t ExtensionAPIBridge::registerCommand(const char* id, const char* label, 
                                             ExtCommandCallback cb, void* userData) {
    std::unique_lock<std::shared_mutex> lock(m_cmdMutex);
    CommandReg reg;
    reg.id = id;
    reg.label = label ? label : "";
    reg.callback = cb;
    reg.userData = userData;
    reg.isAsync = false;
    m_commands[id] = std::move(reg);
    return static_cast<int32_t>(m_commands.size());
}

int32_t ExtensionAPIBridge::registerAsyncCommand(const char* id, const char* label,
                                                  ExtAsyncCommandCallback cb, void* userData) {
    std::unique_lock<std::shared_mutex> lock(m_cmdMutex);
    CommandReg reg;
    reg.id = id;
    reg.label = label ? label : "";
    reg.asyncCallback = cb;
    reg.userData = userData;
    reg.isAsync = true;
    m_commands[id] = std::move(reg);
    return static_cast<int32_t>(m_commands.size());
}

void ExtensionAPIBridge::unregisterCommand(const char* id) {
    std::unique_lock<std::shared_mutex> lock(m_cmdMutex);
    m_commands.erase(id);
}

void ExtensionAPIBridge::executeCommand(const char* id) {
    std::shared_lock<std::shared_mutex> lock(m_cmdMutex);
    auto it = m_commands.find(id);
    if (it != m_commands.end() && it->second.callback) {
        it->second.callback(it->second.userData);
    }
}

void* ExtensionAPIBridge::executeCommandAsync(const char* id) {
    std::shared_lock<std::shared_mutex> lock(m_cmdMutex);
    auto it = m_commands.find(id);
    if (it != m_commands.end() && it->second.isAsync && it->second.asyncCallback) {
        return it->second.asyncCallback(it->second.userData);
    }
    return nullptr;
}

bool ExtensionAPIBridge::hasCommand(const char* id) const {
    std::shared_lock<std::shared_mutex> lock(m_cmdMutex);
    return m_commands.find(id) != m_commands.end();
}

std::vector<std::string> ExtensionAPIBridge::getCommandIds() const {
    std::shared_lock<std::shared_mutex> lock(m_cmdMutex);
    std::vector<std::string> result;
    for (const auto& [id, _] : m_commands) result.push_back(id);
    return result;
}

// ------------------------------------------------------------------------
// UI
// ------------------------------------------------------------------------

int32_t ExtensionAPIBridge::showMessageBox(const char* title, const char* message, uint32_t flags) {
    return MessageBoxA(nullptr, message, title, flags);
}

void ExtensionAPIBridge::showStatusBarMessage(const char* message) {
    // Create or update a transient status bar item
    auto* item = createStatusBarItem("__transient_msg", StatusBarAlignment::LEFT, 0);
    if (item) {
        item->setText(message);
        item->show();
    }
}

StatusBarItem* ExtensionAPIBridge::createStatusBarItem(const char* id, StatusBarAlignment alignment, int32_t priority) {
    std::unique_lock<std::shared_mutex> lock(m_statusMutex);
    auto it = m_statusItems.find(id);
    if (it != m_statusItems.end()) return it->second.get();
    
    auto item = std::make_unique<StatusBarItem>(id, alignment, priority);
    auto* ptr = item.get();
    m_statusItems[id] = std::move(item);
    return ptr;
}

void ExtensionAPIBridge::disposeStatusBarItem(const char* id) {
    std::unique_lock<std::shared_mutex> lock(m_statusMutex);
    m_statusItems.erase(id);
}

bool ExtensionAPIBridge::showInputBox(const char* prompt, const char* placeholder, 
                                       char* outBuffer, size_t outBufferSize) {
    // Simple Win32 dialog-based input
    // For production, this should integrate with IDE's custom input UI
    HWND hwnd = GetForegroundWindow();
    
    // Use Windows API to create a simple input dialog
    // Fallback: use command line via console allocation
    if (outBufferSize == 0) return false;
    outBuffer[0] = '\0';
    
    // Create a simple modal dialog
    // For full implementation, integrate with Qt/Win32 IDE window
    // Here we use a basic approach
    wchar_t wPrompt[512], wPlaceholder[512];
    MultiByteToWideChar(CP_UTF8, 0, prompt, -1, wPrompt, 512);
    MultiByteToWideChar(CP_UTF8, 0, placeholder, -1, wPlaceholder, 512);
    
    // Simple approach: use Windows InputBox equivalent
    // For now, return false to indicate IDE integration needed
    (void)hwnd;
    return false; // Requires IDE UI integration
}

int32_t ExtensionAPIBridge::showQuickPick(const char* const* items, size_t itemCount, const char* placeholder) {
    (void)placeholder;
    if (itemCount == 0) return -1;
    
    // Build menu and show
    // Return selected index
    // Requires IDE UI integration for full implementation
    // Fallback: show message box with numbered options
    std::string msg = "Select an option:\n";
    for (size_t i = 0; i < itemCount; ++i) {
        msg += std::to_string(i + 1) + ". " + items[i] + "\n";
    }
    
    int result = MessageBoxA(nullptr, msg.c_str(), "Quick Pick", MB_OK);
    (void)result;
    return 0; // Default to first item
}

bool ExtensionAPIBridge::showOpenDialog(const char* title, const char* filters, 
                                         char* outPath, size_t outPathSize) {
    char fileName[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetForegroundWindow();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.lpstrFilter = filters;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    
    if (GetOpenFileNameA(&ofn)) {
        strncpy_s(outPath, outPathSize, fileName, _TRUNCATE);
        return true;
    }
    return false;
}

bool ExtensionAPIBridge::showSaveDialog(const char* title, const char* defaultName,
                                         char* outPath, size_t outPathSize) {
    char fileName[MAX_PATH] = {};
    if (defaultName) strncpy_s(fileName, defaultName, MAX_PATH);
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetForegroundWindow();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameA(&ofn)) {
        strncpy_s(outPath, outPathSize, fileName, _TRUNCATE);
        return true;
    }
    return false;
}

ProgressReporter* ExtensionAPIBridge::withProgress(const char* title, bool cancellable) {
    std::unique_lock<std::shared_mutex> lock(m_progressMutex);
    auto reporter = std::make_unique<ProgressReporter>();
    reporter->m_title = title ? title : "";
    if (cancellable) {
        reporter->m_onCancel = [reporter = reporter.get()]() {
            reporter->m_cancelled.store(true);
        };
    }
    auto* ptr = reporter.get();
    m_progressReporters.push_back(std::move(reporter));
    return ptr;
}

// ------------------------------------------------------------------------
// LOGGING
// ------------------------------------------------------------------------

OutputChannel* ExtensionAPIBridge::createOutputChannel(const char* name) {
    std::unique_lock<std::shared_mutex> lock(m_channelMutex);
    auto it = m_channels.find(name);
    if (it != m_channels.end()) return it->second.get();
    
    auto ch = std::make_unique<OutputChannel>(name);
    auto* ptr = ch.get();
    m_channels[name] = std::move(ch);
    return ptr;
}

void ExtensionAPIBridge::disposeOutputChannel(const char* name) {
    std::unique_lock<std::shared_mutex> lock(m_channelMutex);
    m_channels.erase(name);
}

void ExtensionAPIBridge::logMessage(int32_t level, const char* message) {
    auto* ch = m_defaultLogChannel.get();
    if (!ch) return;
    
    const char* prefix = "";
    switch (static_cast<LogLevel>(level)) {
        case LogLevel::DEBUG: prefix = "[DEBUG] "; break;
        case LogLevel::INFO: prefix = "[INFO] "; break;
        case LogLevel::WARN: prefix = "[WARN] "; break;
        case LogLevel::ERROR: prefix = "[ERROR] "; break;
        case LogLevel::FATAL: prefix = "[FATAL] "; break;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm tmBuf;
    localtime_s(&tmBuf, &time);
    
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tmBuf);
    
    std::string fullMsg = std::string(timeStr) + " " + prefix + message;
    ch->appendLine(fullMsg);
    
    // Also OutputDebugString for debugger visibility
    OutputDebugStringA(fullMsg.c_str());
    OutputDebugStringA("\n");
}

void ExtensionAPIBridge::logDebug(const char* message) { logMessage(static_cast<int32_t>(LogLevel::DEBUG), message); }
void ExtensionAPIBridge::logInfo(const char* message) { logMessage(static_cast<int32_t>(LogLevel::INFO), message); }
void ExtensionAPIBridge::logWarn(const char* message) { logMessage(static_cast<int32_t>(LogLevel::WARN), message); }
void ExtensionAPIBridge::logError(const char* message) { logMessage(static_cast<int32_t>(LogLevel::ERROR), message); }

// ------------------------------------------------------------------------
// FILE SYSTEM
// ------------------------------------------------------------------------

bool ExtensionAPIBridge::readFile(const char* path, char** outData, size_t* outLen) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        logError(("Failed to open file for reading: " + std::string(path)).c_str());
        return false;
    }
    
    std::streamsize size = file.tellg();
    if (size < 0) {
        logError(("Failed to determine file size: " + std::string(path)).c_str());
        return false;
    }
    
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    
    if (!file.read(buffer.data(), size)) {
        logError(("Failed to read file: " + std::string(path)).c_str());
        return false;
    }
    
    *outLen = static_cast<size_t>(size);
    *outData = new char[static_cast<size_t>(size)];
    memcpy(*outData, buffer.data(), static_cast<size_t>(size));
    return true;
}

bool ExtensionAPIBridge::writeFile(const char* path, const char* data, size_t len) {
    std::filesystem::path p(path);
    std::filesystem::create_directories(p.parent_path());
    
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        setLastError(("Failed to open file for writing: " + std::string(path)).c_str());
        return false;
    }
    
    file.write(data, static_cast<std::streamsize>(len));
    if (!file.good()) {
        setLastError(("Failed to write file: " + std::string(path)).c_str());
        return false;
    }
    return true;
}

void ExtensionAPIBridge::freeBuffer(char* data) {
    delete[] data;
}

const char* ExtensionAPIBridge::getConfiguration(const char* section, const char* key) {
    static thread_local std::string result;
    
    std::unique_lock<std::shared_mutex> lock(m_configMutex);
    auto it = m_configs.find(section);
    if (it == m_configs.end()) {
        result = "";
        return result.c_str();
    }
    
    std::shared_lock<std::shared_mutex> cfgLock(it->second->m_mutex);
    auto valIt = it->second->m_data.find(key);
    if (valIt == it->second->m_data.end()) {
        result = "";
        return result.c_str();
    }
    
    result = valIt->second;
    return result.c_str();
}

void ExtensionAPIBridge::setConfiguration(const char* section, const char* key, const char* value) {
    auto* cfg = getConfiguration(section);
    if (cfg) {
        cfg->set(key, value);
        persistConfig(section);
    }
}

void ExtensionAPIBridge::publishEvent(const char* eventType) {
    emitEvent(eventType, nullptr);
}

const char* ExtensionAPIBridge::getLastError() const {
    std::lock_guard<std::mutex> lock(m_errorMutex);
    return m_lastError.c_str();
}

void ExtensionAPIBridge::setLastError(const char* error) {
    std::lock_guard<std::mutex> lock(m_errorMutex);
    m_lastError = error ? error : "";
}

bool ExtensionAPIBridge::readFileURI(const URI& uri, std::vector<uint8_t>& outData) {
    if (uri.scheme != "file") return false;
    char* data = nullptr;
    size_t len = 0;
    bool ok = readFile(uri.fsPath().c_str(), &data, &len);
    if (ok && data) {
        outData.assign(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + len);
        delete[] data;
    }
    return ok;
}

bool ExtensionAPIBridge::writeFileURI(const URI& uri, const std::vector<uint8_t>& data) {
    if (uri.scheme != "file") return false;
    return writeFile(uri.fsPath().c_str(), reinterpret_cast<const char*>(data.data()), data.size());
}

bool ExtensionAPIBridge::stat(const char* path, FileStat* outStat) {
    if (!outStat) return false;
    memset(outStat, 0, sizeof(FileStat));
    
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &attr)) {
        return false;
    }
    
    outStat->isDirectory = (attr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    outStat->isFile = !outStat->isDirectory;
    outStat->isSymbolicLink = (attr.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    
    ULARGE_INTEGER size;
    size.HighPart = attr.nFileSizeHigh;
    size.LowPart = attr.nFileSizeLow;
    outStat->size = size.QuadPart;
    
    ULARGE_INTEGER ctime, mtime;
    ctime.HighPart = attr.ftCreationTime.dwHighDateTime;
    ctime.LowPart = attr.ftCreationTime.dwLowDateTime;
    mtime.HighPart = attr.ftLastWriteTime.dwHighDateTime;
    mtime.LowPart = attr.ftLastWriteTime.dwLowDateTime;
    
    // Convert Windows FILETIME (100ns since 1601) to epoch milliseconds
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    outStat->ctime = (ctime.QuadPart - EPOCH_DIFF) / 10000;
    outStat->mtime = (mtime.QuadPart - EPOCH_DIFF) / 10000;
    
    return true;
}

bool ExtensionAPIBridge::statURI(const URI& uri, FileStat* outStat) {
    if (uri.scheme != "file") return false;
    return stat(uri.fsPath().c_str(), outStat);
}

bool ExtensionAPIBridge::readDirectory(const char* path, std::vector<std::string>* outEntries) {
    if (!outEntries) return false;
    outEntries->clear();
    
    std::string searchPath = std::string(path) + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        logError(("Failed to read directory: " + std::string(path)).c_str());
        return false;
    }
    
    do {
        std::string name = findData.cFileName;
        if (name != "." && name != "..") {
            outEntries->push_back(name);
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    return true;
}

bool ExtensionAPIBridge::createDirectory(const char* path) {
    return std::filesystem::create_directories(path);
}

bool ExtensionAPIBridge::deleteFile(const char* path, bool recursive) {
    try {
        if (recursive) {
            return std::filesystem::remove_all(path) > 0;
        } else {
            return std::filesystem::remove(path);
        }
    } catch (...) {
        logError(("Failed to delete: " + std::string(path)).c_str());
        return false;
    }
}

bool ExtensionAPIBridge::rename(const char* src, const char* dst) {
    try {
        std::filesystem::rename(src, dst);
        return true;
    } catch (...) {
        logError(("Failed to rename: " + std::string(src) + " -> " + dst).c_str());
        return false;
    }
}

bool ExtensionAPIBridge::exists(const char* path) {
    return std::filesystem::exists(path);
}

FileSystemWatcher* ExtensionAPIBridge::watchFile(const char* path, FileWatcherCallback cb, void* userData) {
    return watchDirectory(path, false, cb, userData);
}

FileSystemWatcher* ExtensionAPIBridge::watchDirectory(const char* path, bool recursive,
                                                       FileWatcherCallback cb, void* userData) {
    std::unique_lock<std::shared_mutex> lock(m_watcherMutex);
    auto watcher = std::make_unique<FileSystemWatcher>(URI::file(path), recursive, cb, userData);
    if (!watcher->isActive()) return nullptr;
    auto* ptr = watcher.get();
    m_watchers.push_back(std::move(watcher));
    return ptr;
}

// ------------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------------

Configuration* ExtensionAPIBridge::getConfiguration(const char* section) {
    std::unique_lock<std::shared_mutex> lock(m_configMutex);
    auto it = m_configs.find(section);
    if (it != m_configs.end()) return it->second.get();
    
    auto cfg = std::make_unique<Configuration>();
    cfg->m_section = section;
    auto* ptr = cfg.get();
    m_configs[section] = std::move(cfg);
    return ptr;
}

void ExtensionAPIBridge::reloadConfiguration() {
    std::unique_lock<std::shared_mutex> lock(m_configMutex);
    m_configs.clear();
    lock.unlock();
    loadConfig();
}

// ------------------------------------------------------------------------
// EVENTS
// ------------------------------------------------------------------------

uint64_t ExtensionAPIBridge::subscribeToEvent(const char* eventType, ExtEventCallback callback, void* userData) {
    std::unique_lock<std::shared_mutex> lock(m_eventMutex);
    uint64_t handle = m_nextEventHandle.fetch_add(1);
    m_eventListeners[eventType].push_back({handle, {callback, userData}});
    return handle;
}

void ExtensionAPIBridge::unsubscribeFromEvent(uint64_t handle) {
    std::unique_lock<std::shared_mutex> lock(m_eventMutex);
    for (auto& [type, listeners] : m_eventListeners) {
        listeners.erase(
            std::remove_if(listeners.begin(), listeners.end(),
                [handle](const auto& pair) { return pair.first == handle; }),
            listeners.end());
    }
}

void ExtensionAPIBridge::emitEvent(const char* eventType, const char* jsonPayload) {
    std::shared_lock<std::shared_mutex> lock(m_eventMutex);
    auto it = m_eventListeners.find(eventType);
    if (it == m_eventListeners.end()) return;
    
    auto listeners = it->second; // Copy to avoid deadlock
    lock.unlock();
    
    for (const auto& [handle, pair] : listeners) {
        if (pair.first) pair.first(eventType, jsonPayload, pair.second);
    }
}

// ------------------------------------------------------------------------
// EXTENSION LIFECYCLE
// ------------------------------------------------------------------------

void ExtensionAPIBridge::activateExtension(const char* extensionId) {
    std::unique_lock<std::shared_mutex> lock(m_extMutex);
    m_extensionActive[extensionId] = true;
    logInfo(("Extension activated: " + std::string(extensionId)).c_str());
}

void ExtensionAPIBridge::deactivateExtension(const char* extensionId) {
    std::unique_lock<std::shared_mutex> lock(m_extMutex);
    m_extensionActive[extensionId] = false;
    logInfo(("Extension deactivated: " + std::string(extensionId)).c_str());
}

bool ExtensionAPIBridge::isExtensionActive(const char* extensionId) const {
    std::shared_lock<std::shared_mutex> lock(m_extMutex);
    auto it = m_extensionActive.find(extensionId);
    return it != m_extensionActive.end() && it->second;
}

// ------------------------------------------------------------------------
// VS CODE COMPAT SHIM
// ------------------------------------------------------------------------

struct VSCodeCompatAPI {
    // vscode.commands
    int32_t (*registerCommand)(const char* id, const char* label, ExtCommandCallback cb, void* userData);
    void (*unregisterCommand)(const char* id);
    void (*executeCommand)(const char* id);
    
    // vscode.window
    int32_t (*showInformationMessage)(const char* message);
    int32_t (*showWarningMessage)(const char* message);
    int32_t (*showErrorMessage)(const char* message);
    void* (*createOutputChannel)(const char* name); // Returns OutputChannel*
    void* (*createStatusBarItem)(const char* id, int32_t alignment, int32_t priority);
    
    // vscode.workspace
    void* (*getConfiguration)(const char* section); // Returns Configuration*
    bool (*readFile)(const char* path, char** out, size_t* len);
    bool (*writeFile)(const char* path, const char* data, size_t len);
    
    // vscode.EventEmitter pattern
    uint64_t (*subscribeToEvent)(const char* type, ExtEventCallback cb, void* userData);
    void (*unsubscribeFromEvent)(uint64_t h);
    void (*emitEvent)(const char* type, const char* payload);
};

void* ExtensionAPIBridge::vscode_compat_shim() {
    static VSCodeCompatAPI api = {};
    static bool initialized = false;
    
    if (!initialized) {
        auto& bridge = instance();
        api.registerCommand = [](const char* id, const char* label, ExtCommandCallback cb, void* ud) {
            return bridge.registerCommand(id, label, cb, ud);
        };
        api.unregisterCommand = [](const char* id) { bridge.unregisterCommand(id); };
        api.executeCommand = [](const char* id) { bridge.executeCommand(id); };
        
        api.showInformationMessage = [](const char* msg) {
            return bridge.showMessageBox("Info", msg, MB_OK | MB_ICONINFORMATION);
        };
        api.showWarningMessage = [](const char* msg) {
            return bridge.showMessageBox("Warning", msg, MB_OK | MB_ICONWARNING);
        };
        api.showErrorMessage = [](const char* msg) {
            return bridge.showMessageBox("Error", msg, MB_OK | MB_ICONERROR);
        };
        api.createOutputChannel = [](const char* name) { return bridge.createOutputChannel(name); };
        api.createStatusBarItem = [](const char* id, int32_t align, int32_t pri) {
            return bridge.createStatusBarItem(id, static_cast<StatusBarAlignment>(align), pri);
        };
        
        api.getConfiguration = [](const char* section) { return bridge.getConfiguration(section); };
        api.readFile = [](const char* path, char** out, size_t* len) { return bridge.readFile(path, out, len); };
        api.writeFile = [](const char* path, const char* data, size_t len) { return bridge.writeFile(path, data, len); };
        
        api.subscribeToEvent = [](const char* type, ExtEventCallback cb, void* ud) {
            return bridge.subscribeToEvent(type, cb, ud);
        };
        api.unsubscribeFromEvent = [](uint64_t h) { bridge.unsubscribeFromEvent(h); };
        api.emitEvent = [](const char* type, const char* payload) { bridge.emitEvent(type, payload); };
        
        initialized = true;
    }
    
    return &api;
}

} // namespace RawrXD::Extensions
}
