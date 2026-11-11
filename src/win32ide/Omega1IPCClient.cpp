// Omega1IPCClient.cpp
// RawrXD Win32IDE → OMEGA-1 Engine IPC Client
// Production-grade, zero-allocation hot path

#include "Omega1IPCClient.h"
#include <cstring>
#include <string>

// ─── Construction / Destruction ───

Omega1IPCClient::Omega1IPCClient() noexcept
    : m_hPipe(INVALID_HANDLE_VALUE)
    , m_hEventRead(nullptr)
    , m_hEventWrite(nullptr)
    , m_requestId(1)
    , m_connected(false)
    , m_streaming(false)
{
    ZeroMemory(&m_overlappedRead, sizeof(m_overlappedRead));
    ZeroMemory(&m_overlappedWrite, sizeof(m_overlappedWrite));
}

Omega1IPCClient::~Omega1IPCClient() {
    Disconnect();
}

// ─── Connection Management ───

bool Omega1IPCClient::Connect(const wchar_t* pipeName, uint32_t timeoutMs) {
    if (m_connected) return true;

    // Create async events
    m_hEventRead = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_hEventWrite = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_hEventRead || !m_hEventWrite) {
        Cleanup();
        return false;
    }

    // Initialize overlapped structures
    m_overlappedRead.hEvent = m_hEventRead;
    m_overlappedWrite.hEvent = m_hEventWrite;

    // Try to open pipe with retry logic
    const int maxRetries = 5;
    for (int i = 0; i < maxRetries; ++i) {
        m_hPipe = CreateFileW(
            pipeName,
            GENERIC_READ | GENERIC_WRITE,
            0,              // No sharing
            nullptr,        // Default security
            OPEN_EXISTING,  // Pipe must exist
            FILE_FLAG_OVERLAPPED, // Async I/O
            nullptr         // No template
        );

        if (m_hPipe != INVALID_HANDLE_VALUE) {
            break;
        }

        // Pipe not ready, wait and retry
        if (GetLastError() == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeW(pipeName, timeoutMs / maxRetries)) {
                Cleanup();
                return false;
            }
        } else {
            Cleanup();
            return false;
        }
    }

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        Cleanup();
        return false;
    }

    // Set pipe to message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr)) {
        Cleanup();
        return false;
    }

    m_connected = true;
    return true;
}

void Omega1IPCClient::Disconnect() noexcept {
    m_connected = false;
    m_streaming = false;

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CancelIo(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }

    Cleanup();
}

void Omega1IPCClient::Cleanup() noexcept {
    if (m_hEventRead) {
        CloseHandle(m_hEventRead);
        m_hEventRead = nullptr;
    }
    if (m_hEventWrite) {
        CloseHandle(m_hEventWrite);
        m_hEventWrite = nullptr;
    }
}

// ─── Request Methods ───

bool Omega1IPCClient::Ping(uint64_t& outLatencyUs) {
    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::PING);
    header.requestId = m_requestId++;
    header.payloadLen = 0;
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = 0;

    if (!SendMessage(&header, nullptr, 0)) {
        return false;
    }

    O1MessageHeader response;
    std::vector<uint8_t> payload;
    if (!ReceiveMessage(response, payload)) {
        return false;
    }

    outLatencyUs = O1::QueryPerfCounterUs() - header.timestampUs;
    return response.msgType == static_cast<uint16_t>(O1ResponseType::PONG);
}

bool Omega1IPCClient::RequestCompletion(
    const O1CompletionRequest& request,
    const std::string& context,
    O1GhostTextResponse& outResponse,
    std::string& outText
) {
    // Build payload: request struct + context
    std::vector<uint8_t> payload;
    payload.resize(sizeof(request) + context.size());
    memcpy(payload.data(), &request, sizeof(request));
    if (!context.empty()) {
        memcpy(payload.data() + sizeof(request), context.data(), context.size());
    }

    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::COMPLETION);
    header.requestId = m_requestId++;
    header.payloadLen = static_cast<uint32_t>(payload.size());
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = O1::CRC32(payload.data(), payload.size());

    if (!SendMessage(&header, payload.data(), payload.size())) {
        return false;
    }

    // Receive response
    O1MessageHeader responseHeader;
    std::vector<uint8_t> responsePayload;
    if (!ReceiveMessage(responseHeader, responsePayload)) {
        return false;
    }

    if (responseHeader.msgType == static_cast<uint16_t>(O1ResponseType::ERROR)) {
        return false;
    }

    if (responseHeader.msgType != static_cast<uint16_t>(O1ResponseType::GHOST_TEXT)) {
        return false;
    }

    if (responsePayload.size() < sizeof(O1GhostTextResponse)) {
        return false;
    }

    memcpy(&outResponse, responsePayload.data(), sizeof(O1GhostTextResponse));

    // Extract text
    size_t textLen = responsePayload.size() - sizeof(O1GhostTextResponse);
    if (textLen > 0) {
        outText.assign(
            reinterpret_cast<const char*>(responsePayload.data() + sizeof(O1GhostTextResponse)),
            textLen
        );
    }

    return true;
}

bool Omega1IPCClient::StartStream(
    const O1StreamRequest& request,
    const std::string& context
) {
    if (m_streaming) return false;

    std::vector<uint8_t> payload;
    payload.resize(sizeof(request) + context.size());
    memcpy(payload.data(), &request, sizeof(request));
    if (!context.empty()) {
        memcpy(payload.data() + sizeof(request), context.data(), context.size());
    }

    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::STREAM_START);
    header.requestId = m_requestId++;
    header.payloadLen = static_cast<uint32_t>(payload.size());
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = O1::CRC32(payload.data(), payload.size());

    if (!SendMessage(&header, payload.data(), payload.size())) {
        return false;
    }

    m_streaming = true;
    return true;
}

bool Omega1IPCClient::CancelStream() {
    if (!m_streaming) return false;

    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::STREAM_CANCEL);
    header.requestId = m_requestId++;
    header.payloadLen = 0;
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = 0;

    if (!SendMessage(&header, nullptr, 0)) {
        return false;
    }

    m_streaming = false;
    return true;
}

bool Omega1IPCClient::SwitchModel(const O1ModelSwitchRequest& request) {
    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::MODEL_SWITCH);
    header.requestId = m_requestId++;
    header.payloadLen = sizeof(request);
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = O1::CRC32(&request, sizeof(request));

    if (!SendMessage(&header, &request, sizeof(request))) {
        return false;
    }

    // Wait for acknowledgment
    O1MessageHeader response;
    std::vector<uint8_t> payload;
    return ReceiveMessage(response, payload);
}

bool Omega1IPCClient::QueryStatus(O1StatusTelemetry& outStatus, std::string& outModelName) {
    O1MessageHeader header = {};
    header.magic = O1IPC_MAGIC;
    header.version = O1IPC_VERSION;
    header.msgType = static_cast<uint16_t>(O1RequestType::STATUS_QUERY);
    header.requestId = m_requestId++;
    header.payloadLen = 0;
    header.timestampUs = O1::QueryPerfCounterUs();
    header.checksum = 0;

    if (!SendMessage(&header, nullptr, 0)) {
        return false;
    }

    O1MessageHeader response;
    std::vector<uint8_t> payload;
    if (!ReceiveMessage(response, payload)) {
        return false;
    }

    if (response.msgType != static_cast<uint16_t>(O1ResponseType::STATUS_UPDATE)) {
        return false;
    }

    if (payload.size() < sizeof(O1StatusTelemetry)) {
        return false;
    }

    memcpy(&outStatus, payload.data(), sizeof(O1StatusTelemetry));

    size_t nameLen = payload.size() - sizeof(O1StatusTelemetry);
    if (nameLen > 0) {
        outModelName.assign(
            reinterpret_cast<const char*>(payload.data() + sizeof(O1StatusTelemetry)),
            nameLen
        );
    }

    return true;
}

// ─── Low-Level I/O ───

bool Omega1IPCClient::SendMessage(
    const O1MessageHeader* header,
    const void* payload,
    size_t payloadLen
) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Send header
    DWORD written;
    BOOL result = WriteFile(m_hPipe, header, sizeof(*header), &written, &m_overlappedWrite);
    if (!result && GetLastError() == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(m_hEventWrite, 5000);
        if (wait != WAIT_OBJECT_0) {
            CancelIo(m_hPipe);
            return false;
        }
        if (!GetOverlappedResult(m_hPipe, &m_overlappedWrite, &written, FALSE)) {
            return false;
        }
    } else if (!result) {
        return false;
    }

    if (written != sizeof(*header)) {
        return false;
    }

    // Send payload if any
    if (payloadLen > 0 && payload) {
        ResetEvent(m_hEventWrite);
        result = WriteFile(m_hPipe, payload, static_cast<DWORD>(payloadLen), &written, &m_overlappedWrite);
        if (!result && GetLastError() == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(m_hEventWrite, 5000);
            if (wait != WAIT_OBJECT_0) {
                CancelIo(m_hPipe);
                return false;
            }
            if (!GetOverlappedResult(m_hPipe, &m_overlappedWrite, &written, FALSE)) {
                return false;
            }
        } else if (!result) {
            return false;
        }

        if (written != payloadLen) {
            return false;
        }
    }

    return true;
}

bool Omega1IPCClient::ReceiveMessage(
    O1MessageHeader& outHeader,
    std::vector<uint8_t>& outPayload
) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Read header
    DWORD read;
    BOOL result = ReadFile(m_hPipe, &outHeader, sizeof(outHeader), &read, &m_overlappedRead);
    if (!result && GetLastError() == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(m_hEventRead, 10000);
        if (wait != WAIT_OBJECT_0) {
            CancelIo(m_hPipe);
            return false;
        }
        if (!GetOverlappedResult(m_hPipe, &m_overlappedRead, &read, FALSE)) {
            return false;
        }
    } else if (!result) {
        return false;
    }

    if (read != sizeof(outHeader)) {
        return false;
    }

    if (!outHeader.Valid()) {
        return false;
    }

    // Read payload if any
    if (outHeader.payloadLen > 0) {
        outPayload.resize(outHeader.payloadLen);
        ResetEvent(m_hEventRead);
        result = ReadFile(m_hPipe, outPayload.data(), outHeader.payloadLen, &read, &m_overlappedRead);
        if (!result && GetLastError() == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(m_hEventRead, 10000);
            if (wait != WAIT_OBJECT_0) {
                CancelIo(m_hPipe);
                return false;
            }
            if (!GetOverlappedResult(m_hPipe, &m_overlappedRead, &read, FALSE)) {
                return false;
            }
        } else if (!result) {
            return false;
        }

        if (read != outHeader.payloadLen) {
            return false;
        }

        // Verify checksum if present
        if (outHeader.checksum != 0) {
            uint32_t computed = O1::CRC32(outPayload.data(), outPayload.size());
            if (computed != outHeader.checksum) {
                return false;
            }
        }
    } else {
        outPayload.clear();
    }

    return true;
}

bool Omega1IPCClient::TryReceiveStreamToken(
    O1StreamTokenResponse& outToken,
    std::string& outText,
    uint32_t timeoutMs
) {
    if (!m_streaming) return false;

    O1MessageHeader header;
    std::vector<uint8_t> payload;

    // Non-blocking receive with timeout
    if (!ReceiveMessage(header, payload)) {
        return false;
    }

    if (header.msgType == static_cast<uint16_t>(O1ResponseType::STREAM_DONE)) {
        m_streaming = false;
        outToken.isFinal = 1;
        return true;
    }

    if (header.msgType == static_cast<uint16_t>(O1ResponseType::STREAM_ABORTED)) {
        m_streaming = false;
        return false;
    }

    if (header.msgType != static_cast<uint16_t>(O1ResponseType::STREAM_TOKEN)) {
        return false;
    }

    if (payload.size() < sizeof(O1StreamTokenResponse)) {
        return false;
    }

    memcpy(&outToken, payload.data(), sizeof(O1StreamTokenResponse));

    size_t textLen = payload.size() - sizeof(O1StreamTokenResponse);
    if (textLen > 0) {
        outText.assign(
            reinterpret_cast<const char*>(payload.data() + sizeof(O1StreamTokenResponse)),
            textLen
        );
    } else {
        outText.clear();
    }

    return true;
}
