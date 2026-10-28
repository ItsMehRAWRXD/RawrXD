#pragma once
// GATED_STUB — IDE_BRIDGE_STUB_GATE_001
// Not in RawrXD-Win32IDE WIN32IDE_SOURCES (GATED_OMIT). Companion-only via SmokeE2EIPC.
// Bodies return false; do not invent IPC/product PASS. PROMOTE=0.

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

namespace RawrXD::ExtensionHost
{

constexpr const wchar_t* kDefaultPipeName = L"\\\\.\\pipe\\RawrXD_ExtensionHost";

class ExtensionHostIpcBridge
{
public:
    ExtensionHostIpcBridge();
    explicit ExtensionHostIpcBridge(const wchar_t* pipeName);
    ~ExtensionHostIpcBridge();

    // GATED_STUB: always false (was CreateFileW success theater).
    bool Connect();
    void Disconnect();
    bool IsConnected() const;

    bool SendMessage(const std::vector<std::uint8_t>& data);
    bool ReceiveMessage(std::vector<std::uint8_t>& outData, std::uint32_t timeoutMs = 5000);

private:
    std::wstring m_pipeName;
    HANDLE m_pipeHandle = INVALID_HANDLE_VALUE;
    bool m_connected = false;
};

} // namespace RawrXD::ExtensionHost
