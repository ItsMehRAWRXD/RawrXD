// ExtensionHostIpcBridge.cpp — real companion CLIENT IPC (not product tip).
// Linked via cmake/SmokeE2EIPC.cmake → RawrXD-ExtensionHost EXCLUDE_FROM_ALL.
// GATED_OMIT from WIN32IDE_SOURCES. Smoke ≠ product PASS. PROMOTE=0.

#include "ExtensionHostIpcBridge.hpp"

#include <algorithm>
#include <cstring>

namespace RawrXD::ExtensionHost
{

namespace {
void LogBridge(const char* name, const char* detail) {
    char buf[256];
    wsprintfA(buf, "[ExtensionHostIpcBridge] %s %s\n", name, detail ? detail : "");
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

bool ExtensionHostIpcBridge::ConnectAsClient(const wchar_t* pipeName, std::uint32_t timeoutMs)
{
    Disconnect();
    if (pipeName && pipeName[0] != L'\0') {
        m_pipeName = pipeName;
    }
    if (m_pipeName.empty()) {
        m_pipeName = kDefaultPipeName;
    }

    if (!WaitNamedPipeW(m_pipeName.c_str(), timeoutMs == 0 ? 1 : timeoutMs)) {
        LogBridge("ConnectAsClient", "WaitNamedPipeW_FAIL");
        return false;
    }

    m_pipeHandle = CreateFileW(
        m_pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (m_pipeHandle == INVALID_HANDLE_VALUE) {
        LogBridge("ConnectAsClient", "CreateFileW_FAIL");
        return false;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(m_pipeHandle, &mode, nullptr, nullptr)) {
        // Non-fatal on some hosts; keep handle if WriteFile path works.
        LogBridge("ConnectAsClient", "SetNamedPipeHandleState_WARN");
    }

    m_connected = true;
    LogBridge("ConnectAsClient", "OK");
    return true;
}

bool ExtensionHostIpcBridge::Connect()
{
    return ConnectAsClient(m_pipeName.c_str(), 5000);
}

void ExtensionHostIpcBridge::Disconnect()
{
    if (m_pipeHandle != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_pipeHandle);
        CloseHandle(m_pipeHandle);
        m_pipeHandle = INVALID_HANDLE_VALUE;
    }
    m_connected = false;
}

bool ExtensionHostIpcBridge::IsConnected() const
{
    return m_connected && m_pipeHandle != INVALID_HANDLE_VALUE;
}

bool ExtensionHostIpcBridge::WriteAll(const std::uint8_t* data, std::uint32_t len)
{
    if (!IsConnected() || !data || len == 0) {
        return false;
    }
    std::uint32_t sent = 0;
    while (sent < len) {
        DWORD written = 0;
        if (!WriteFile(m_pipeHandle, data + sent, static_cast<DWORD>(len - sent), &written, nullptr) ||
            written == 0) {
            LogBridge("WriteAll", "WriteFile_FAIL");
            return false;
        }
        sent += written;
    }
    return true;
}

bool ExtensionHostIpcBridge::WriteLogicalMessage(RawrXD::IPC::Chat::ChatMessageType type,
                                                 const std::string& logicalPayload)
{
    if (!IsConnected()) {
        LogBridge("WriteLogicalMessage", "NOT_CONNECTED");
        return false;
    }

    RawrXD::IPC::Chat::MessageSegmenter segmenter;
    if (!segmenter.Begin(type, logicalPayload)) {
        LogBridge("WriteLogicalMessage", "Segmenter_Begin_FAIL");
        return false;
    }

    std::vector<std::uint8_t> prefixed;
    while (segmenter.HasNext()) {
        if (!segmenter.NextPrefixedWireBlob(prefixed) || prefixed.empty()) {
            LogBridge("WriteLogicalMessage", "NextPrefixed_FAIL");
            return false;
        }
        if (!WriteAll(prefixed.data(), static_cast<std::uint32_t>(prefixed.size()))) {
            return false;
        }
    }
    FlushFileBuffers(m_pipeHandle);
    return true;
}

bool ExtensionHostIpcBridge::WriteMessage(std::uint16_t type, const std::uint8_t* data,
                                          std::uint32_t len)
{
    if (!IsConnected()) {
        LogBridge("WriteMessage", "NOT_CONNECTED");
        return false;
    }
    if (!data && len > 0) {
        return false;
    }

    const std::string payload(reinterpret_cast<const char*>(data),
                              reinterpret_cast<const char*>(data) + len);
    return WriteLogicalMessage(static_cast<RawrXD::IPC::Chat::ChatMessageType>(type), payload);
}

bool ExtensionHostIpcBridge::SendMessage(const std::vector<std::uint8_t>& data)
{
    if (!IsConnected() || data.empty()) {
        LogBridge("SendMessage", "NOT_CONNECTED_OR_EMPTY");
        return false;
    }
    // Raw bytes only when caller already framed; no invent success on empty write.
    if (!WriteAll(data.data(), static_cast<std::uint32_t>(data.size()))) {
        return false;
    }
    FlushFileBuffers(m_pipeHandle);
    return true;
}

bool ExtensionHostIpcBridge::ReceiveMessage(std::vector<std::uint8_t>& outData,
                                            std::uint32_t timeoutMs)
{
    outData.clear();
    if (!IsConnected()) {
        LogBridge("ReceiveMessage", "NOT_CONNECTED");
        return false;
    }

    // Byte-mode pipe: optional overlapped wait via Peek+Read. Fail-closed on timeout.
    const DWORD deadline = GetTickCount() + (timeoutMs == 0 ? 1 : timeoutMs);
    std::vector<std::uint8_t> acc;
    acc.reserve(4096);

    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(m_pipeHandle, nullptr, 0, nullptr, &avail, nullptr)) {
            LogBridge("ReceiveMessage", "PeekNamedPipe_FAIL");
            return false;
        }
        if (avail > 0) {
            const size_t off = acc.size();
            acc.resize(off + avail);
            DWORD read = 0;
            if (!ReadFile(m_pipeHandle, acc.data() + off, avail, &read, nullptr) || read == 0) {
                LogBridge("ReceiveMessage", "ReadFile_FAIL");
                return false;
            }
            acc.resize(off + read);

            std::vector<std::uint8_t> frame;
            if (RawrXD::IPC::Chat::WireFrameStream::TryExtractFrame(acc, frame) && !frame.empty()) {
                outData = std::move(frame);
                return true;
            }
            // Keep accumulating if length prefix incomplete.
        }

        if (GetTickCount() >= deadline) {
            LogBridge("ReceiveMessage", "TIMEOUT");
            return false;
        }
        Sleep(10);
    }
}

} // namespace RawrXD::ExtensionHost
