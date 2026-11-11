#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <atomic>
#include <vector>
#include <memory>

namespace RawrXD::Extensions {

using CommandCallback = void (*)(void* userData);
using ExtEventCallback = void (*)(const char* eventType, const char* jsonPayload, void* userData);

struct CommandReg {
    std::string id;
    std::string label;
    CommandCallback callback = nullptr;
    void* userData = nullptr;
};

class Configuration {
public:
    const char* getName() const { return m_name.c_str(); }
private:
    std::string m_name;
};

class ExtensionAPIBridge {
public:
    static ExtensionAPIBridge& instance();
    
    // Command registration
    int32_t registerCommand(const char* id, const char* label, CommandCallback cb, void* userData);
    void unregisterCommand(const char* id);
    void executeCommand(const char* id);
    
    // UI integration
    int32_t showMessageBox(const char* title, const char* message, uint32_t flags);
    void showStatusBarMessage(const char* message);
    
    // Logging
    void logMessage(int32_t level, const char* message);
    
    // File operations
    bool readFile(const char* path, char** outData, size_t* outLen);
    bool writeFile(const char* path, const char* data, size_t len);
    
    // Configuration
    const char* getConfiguration(const char* section);
    void reloadConfiguration();
    
    // Event subscription
    uint64_t subscribeToEvent(const char* eventType, ExtEventCallback callback, void* userData);
    void unsubscribeFromEvent(uint64_t handle);
    void emitEvent(const char* eventType, const char* jsonPayload);

private:
    ExtensionAPIBridge();
    ~ExtensionAPIBridge();
    
    std::map<std::string, CommandReg> m_commands;
    mutable std::mutex m_cmdMutex;
    
    mutable std::shared_mutex m_configMutex;
    std::unordered_map<std::string, std::unique_ptr<Configuration>> m_configs;
    std::string m_configPath;
    
    mutable std::shared_mutex m_eventMutex;
    std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::pair<ExtEventCallback, void*>>>> m_eventListeners;
    std::atomic<uint64_t> m_nextEventHandle{1};
};

} // namespace RawrXD::Extensions
