// ExtensionHostIpcBridge.cpp - Minimal stub implementation
#include "ExtensionHostIpcBridge.hpp"
#include <windows.h>

namespace RawrXD::ExtensionHost
{

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
    if (m_connected || m_pipeHandle != INVALID_HANDLE_VALUE) {
        return true;
    }

    m_pipeHandle = CreateFileW(
        m_pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (m_pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    m_connected = true;
    return true;
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
    return m_connected && m_pipeHandle != INVALID_HANDLE_VALUE;
}

bool ExtensionHostIpcBridge::SendMessage(const std::vector<std::uint8_t>& data)
{
    if (!IsConnected()) {
        return false;
    }

    DWORD bytesWritten = 0;
    return WriteFile(m_pipeHandle, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr) != 0;
}

bool ExtensionHostIpcBridge::ReceiveMessage(std::vector<std::uint8_t>& outData, std::uint32_t timeoutMs)
{
    if (!IsConnected()) {
        return false;
    }

    outData.resize(4096);
    DWORD bytesRead = 0;
    
    if (!ReadFile(m_pipeHandle, outData.data(), static_cast<DWORD>(outData.size()), &bytesRead, nullptr)) {
        return false;
    }

    outData.resize(bytesRead);
    return true;
}

} // namespace RawrXD::ExtensionHost
