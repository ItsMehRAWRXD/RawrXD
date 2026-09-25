// ============================================================================
// Win32IDE_MCPHooks.h
// ============================================================================
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {

struct MCPMessage {
    enum Type { Read, Write, Socket, WebSocket };
    Type type;
    std::vector<uint8_t> payload;
    uintptr_t hookRVA;
    uint64_t timestamp;
    // JSON-RPC parsed fields
    std::string method;
    std::string requestId;
    std::string paramsJson;
    bool isRequest = false;
    bool isNotification = false;
    bool isResponse = false;
};

enum class CallbackInstallResult { Success, AlreadyInstalled, AllocationFailed, PatchFailed, ModuleNotFound };

struct CallbackState {
    uintptr_t rva = 0;
    uintptr_t absoluteAddr = 0;
    uint8_t originalBytes[32] = {};
    size_t patchedLen = 0;
    bool installed = false;
};

class MCPBridgeManager {
public:
    static MCPBridgeManager& GetInstance();

    bool Initialize(HMODULE targetModule);
    void Shutdown();

    bool WriteJumpRedirect(uintptr_t targetAddr, uintptr_t hookAddr, uint8_t* savedBytes, size_t* savedLen);
    bool RestoreOriginalCode(uintptr_t targetAddr, const uint8_t* savedBytes, size_t savedLen);
    uintptr_t AllocateRedirect(size_t size);

    CallbackInstallResult InstallReadMessageCb();
    CallbackInstallResult InstallWriteMessageCb();
    CallbackInstallResult InstallOnSocketDataCb();
    CallbackInstallResult InstallWebSocketCb();
    CallbackInstallResult InstallAllTransportCbs();

    void UninstallAllCallbacks();
    void UninstallHook(uintptr_t rva);

    MCPMessage ParseMCPBuffer(const uint8_t* buffer, size_t length, uintptr_t hookRVA);

    void OnReadMessage(const uint8_t* buffer, size_t length);
    void OnWriteMessage(const uint8_t* buffer, size_t length);
    void OnSocketData(const uint8_t* data, size_t length, SOCKET sock);
    void OnWebSocketFrame(const uint8_t* frame, size_t length, uint8_t opcode);

    std::vector<MCPMessage> GetRecentMessages(size_t count) const;
    void ClearMessageBuffer();

    void RegisterMethodHandler(const std::string& method, std::function<void(const MCPMessage&)> handler);

private:
    MCPBridgeManager();
    ~MCPBridgeManager();
    bool m_initialized;
    HMODULE m_targetModule;
    uintptr_t m_moduleBase;
    size_t m_messageHead;
    size_t m_totalIntercepted;
    size_t m_bytesRead;
    size_t m_bytesWritten;
    std::vector<MCPMessage> m_messages;
    mutable CRITICAL_SECTION m_cs;
    std::vector<CallbackState> m_installedHooks;
    std::unordered_map<std::string, std::function<void(const MCPMessage&)>> m_methodHandlers;
};

} // namespace RawrXD
