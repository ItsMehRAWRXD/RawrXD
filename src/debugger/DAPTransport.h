// DAPTransport.h
// Phase 25: DAP Adapter - Transport Layer
// ============================================================================
// Handles Content-Length framed JSON-RPC over stdio
// Zero dependencies - uses only Win32 APIs
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace DAP {

// ============================================================================
// DAP Transport Configuration
// ============================================================================
struct DAPTransportConfig {
    HANDLE hInput = nullptr;    // stdin handle
    HANDLE hOutput = nullptr;   // stdout handle
    size_t maxMessageSize = 65536;  // 64KB max message
    DWORD readTimeoutMs = 100;   // Non-blocking read interval
};

// ============================================================================
// DAP Transport
// ============================================================================
class DAPTransport {
public:
    using MessageCallback = std::function<void(const std::string& json)>;
    using ErrorCallback = std::function<void(const std::string& error)>;

    DAPTransport();
    ~DAPTransport();

    // Initialize with configuration
    bool Initialize(const DAPTransportConfig& config);
    void Shutdown();

    // Message I/O
    bool SendMessage(const std::string& json);
    bool SendMessage(const char* json, size_t length);
    
    // Blocking read (for threaded mode)
    std::string ReadMessage();
    bool ReadMessage(std::string& outJson);

    // Event-driven mode
    void SetMessageCallback(MessageCallback callback);
    void SetErrorCallback(ErrorCallback callback);
    void Poll();  // Call periodically in main loop

    // Utility
    static std::string CreateMessage(const std::string& json);
    static bool ParseHeader(const std::string& header, size_t& outLength);

    bool IsInitialized() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Global Transport Access
// ============================================================================
DAPTransport* GetDAPTransport();
bool InitializeDAPTransport();
void ShutdownDAPTransport();

} // namespace DAP
} // namespace RawrXD
