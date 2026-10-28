#pragma once
// ExtensionHostIpcBridge — companion named-pipe CLIENT (SmokeE2EIPC).
// GATED_OMIT from RawrXD-Win32IDE WIN32IDE_SOURCES (IDE_BRIDGE_STUB_GATE_001).
// Real CreateFileW + Chat MessageSegmenter framing. Fail-closed on miss.
// Companion RUNTIME ≠ product tip PASS. PROMOTE=0 TIP_CLIMB=HOLD.

#include "Win32IDE_ChatIpcProtocol.h"

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

    ExtensionHostIpcBridge(const ExtensionHostIpcBridge&) = delete;
    ExtensionHostIpcBridge& operator=(const ExtensionHostIpcBridge&) = delete;

    // Client connect: WaitNamedPipeW + CreateFileW. false if no server / error.
    bool ConnectAsClient(const wchar_t* pipeName, std::uint32_t timeoutMs);
    // Legacy alias → ConnectAsClient(m_pipeName, 5000). No silent success.
    bool Connect();
    void Disconnect();
    bool IsConnected() const;

    // Length-prefixed Chat frames via MessageSegmenter (companion smoke).
    bool WriteLogicalMessage(RawrXD::IPC::Chat::ChatMessageType type,
                             const std::string& logicalPayload);
    // Raw typed payload (single or segmented frames).
    bool WriteMessage(std::uint16_t type, const std::uint8_t* data, std::uint32_t len);

    bool SendMessage(const std::vector<std::uint8_t>& data);
    bool ReceiveMessage(std::vector<std::uint8_t>& outData, std::uint32_t timeoutMs = 5000);

private:
    bool WriteAll(const std::uint8_t* data, std::uint32_t len);

    std::wstring m_pipeName;
    HANDLE m_pipeHandle = INVALID_HANDLE_VALUE;
    bool m_connected = false;
};

} // namespace RawrXD::ExtensionHost
