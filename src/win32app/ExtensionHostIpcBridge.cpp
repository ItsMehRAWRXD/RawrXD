// ExtensionHostIpcBridge.cpp — GATED_STUB (IDE_BRIDGE_STUB_GATE_001)
// Win32IDE product link: GATED_OMIT (not in WIN32IDE_SOURCES).
// Linked only via cmake/SmokeE2EIPC.cmake → RawrXD-ExtensionHost companion.
// Match GateMode/SO_*: OutputDebugString + false. Smoke ≠ product PASS.
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0. No Camellia reopen.

#include "ExtensionHostIpcBridge.hpp"
#include <windows.h>

namespace RawrXD::ExtensionHost
{

namespace {
void GateStub(const char* name) {
    char buf[192];
    wsprintfA(buf, "[ExtensionHostIpcBridge] GATED_STUB SYNTHETIC=partial name=%s\n", name);
    OutputDebugStringA(buf);
}
} // namespace

ExtensionHostIpcBridge::ExtensionHostIpcBridge()
    : m_pipeName(kDefaultPipeName)
{
}

ExtensionHostIpcBridge::ExtensionHostIpcBridge(const wchar_t* pipeName)
    : m_pipeName(pipeName ? pipeName : kDefaultPipeName)
{
}

ExtensionHostIpcBridge::~ExtensionHostIpcBridge()
{
    Disconnect();
}

bool ExtensionHostIpcBridge::Connect()
{
    // Was: CreateFileW + return true (stub theater / incomplete vs companion API).
    GateStub("Connect");
    return false;
}

void ExtensionHostIpcBridge::Disconnect()
{
    if (m_pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipeHandle);
        m_pipeHandle = INVALID_HANDLE_VALUE;
    }
    m_connected = false;
}

bool ExtensionHostIpcBridge::IsConnected() const
{
    return false;
}

bool ExtensionHostIpcBridge::SendMessage(const std::vector<std::uint8_t>& data)
{
    (void)data;
    GateStub("SendMessage");
    return false;
}

bool ExtensionHostIpcBridge::ReceiveMessage(std::vector<std::uint8_t>& outData,
                                            std::uint32_t timeoutMs)
{
    (void)outData;
    (void)timeoutMs;
    GateStub("ReceiveMessage");
    return false;
}

} // namespace RawrXD::ExtensionHost
