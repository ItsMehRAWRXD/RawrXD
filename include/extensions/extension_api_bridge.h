#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <mutex>
#include <functional>
#include <vector>

namespace RawrXD::Extensions {

using CommandCallback = void (*)(void* userData);

struct CommandReg {
    std::string id;
    std::string label;
    CommandCallback callback = nullptr;
    void* userData = nullptr;
};

struct EventSubscription {
    CommandCallback callback = nullptr;
    void* userData = nullptr;
};

class ExtensionAPIBridge {
public:
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
    void freeBuffer(char* data);  // Crucial for cross-DLL safety
    
    // Configuration (thread-safe persistence)
    const char* getConfiguration(const char* section, const char* key);
    void setConfiguration(const char* section, const char* key, const char* value);
    
    // Event pub/sub system
    void subscribeToEvent(const char* eventType, CommandCallback callback, void* userData);
    void publishEvent(const char* eventType, void* eventData = nullptr);
    
    // Error reporting
    const char* getLastError() const;

private:
    // Command management
    std::map<std::string, CommandReg> m_commands;
    mutable std::mutex m_cmdMutex;
    
    // Event subscriptions
    std::map<std::string, std::vector<EventSubscription>> m_eventSubscriptions;
    mutable std::mutex m_eventMutex;
    
    // Configuration store
    std::map<std::string, std::string> m_configStore;
    mutable std::mutex m_configMutex;
    
    // Error state
    mutable std::string m_lastError;
    mutable std::mutex m_errorMutex;
    
    void setLastError(const char* error);
};

} // namespace RawrXD::Extensions
