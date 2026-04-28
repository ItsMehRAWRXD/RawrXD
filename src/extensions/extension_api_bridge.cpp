#include "extensions/extension_api_bridge.h"
#include <windows.h>
#include <fstream>
#include <vector>

namespace RawrXD::Extensions {
    int32_t ExtensionAPIBridge::registerCommand(const char* id, const char* label, CommandCallback cb, void* userData) {
        std::lock_guard<std::mutex> lock(m_cmdMutex);
        CommandReg reg;
        reg.id = id;
        reg.label = label;
        reg.callback = cb;
        reg.userData = userData;
        m_commands[id] = reg;
        return static_cast<int32_t>(m_commands.size());
    }

    void ExtensionAPIBridge::unregisterCommand(const char* id) {
        std::lock_guard<std::mutex> lock(m_cmdMutex);
        m_commands.erase(id);
    }

    void ExtensionAPIBridge::executeCommand(const char* id) {
        std::lock_guard<std::mutex> lock(m_cmdMutex);
        auto it = m_commands.find(id);
        if (it != m_commands.end() && it->second.callback) {
            it->second.callback(it->second.userData);
        }
    }

    int32_t ExtensionAPIBridge::showMessageBox(const char* title, const char* message, uint32_t flags) {
        return MessageBoxA(nullptr, message, title, flags);
    }

    void ExtensionAPIBridge::showStatusBarMessage(const char* message) {
        // Placeholder - would integrate with IDE status bar
    }

    void ExtensionAPIBridge::logMessage(int32_t level, const char* message) {
        // Placeholder - would route to IDE logger
        OutputDebugStringA(message);
    }

    bool ExtensionAPIBridge::readFile(const char* path, char** outData, size_t* outLen) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size)) return false;
        
        *outLen = size;
        *outData = new char[size];
        memcpy(*outData, buffer.data(), size);
        return true;
    }

    bool ExtensionAPIBridge::writeFile(const char* path, const char* data, size_t len) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write(data, len);
        return file.good();
    }

    const char* ExtensionAPIBridge::getConfiguration(const char* section, const char* key) {
        // Placeholder - would read from config system
        return "";
    }

    void ExtensionAPIBridge::setConfiguration(const char* section, const char* key, const char* value) {
        // Placeholder - would write to config system
    }

    void ExtensionAPIBridge::subscribeToEvent(const char* eventType, CommandCallback callback, void* userData) {
        // Placeholder - would register event subscription
    }
}
