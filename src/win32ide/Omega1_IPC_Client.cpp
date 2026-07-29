// ============================================================================
// Omega1 IPC Client Implementation
// Non-blocking named pipe + SHM ring buffer
// ============================================================================

#include "Omega1_IPC_Client.h"
#include <string>
#include <vector>

namespace RawrXD {
namespace Omega1 {

// ============================================================================
// IPCClient Implementation
// ============================================================================

IPCClient::IPCClient() = default;

IPCClient::~IPCClient() {
    Disconnect();
}

bool IPCClient::Connect() {
    if (m_connected) return true;

    // Connect named pipe
    if (!ConnectPipe()) {
        return false;
    }

    // Connect shared memory
    if (!ConnectSHM()) {
        Disconnect();
        return false;
    }

    m_connected = true;
    m_running = true;

    // Start worker thread for async reading
    m_hWorkerThread = CreateThread(nullptr, 0, WorkerThreadProc, this, 0, nullptr);
    if (!m_hWorkerThread) {
        Disconnect();
        return false;
    }

    return true;
}

void IPCClient::Disconnect() {
    m_running = false;
    m_connected = false;

    // Signal data ready event to unblock worker
    if (m_hDataReady) {
        SetEvent(m_hDataReady);
    }

    // Wait for worker thread
    if (m_hWorkerThread) {
        WaitForSingleObject(m_hWorkerThread, 1000);
        CloseHandle(m_hWorkerThread);
        m_hWorkerThread = nullptr;
    }

    // Cleanup handles
    if (m_pSHM) {
        UnmapViewOfFile(m_pSHM);
        m_pSHM = nullptr;
    }
    if (m_hSHM) {
        CloseHandle(m_hSHM);
        m_hSHM = nullptr;
    }
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
    if (m_hDataReady) {
        CloseHandle(m_hDataReady);
        m_hDataReady = nullptr;
    }

    m_pSHMHeader = nullptr;
    m_pRingBuffer = nullptr;
}

bool IPCClient::ConnectPipe() {
    // Try to connect to existing pipe
    m_hPipe = CreateFileW(
        OMEGA1_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, // Non-blocking
        nullptr
    );

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        // Pipe not available - OMEGA-1 server not running
        return false;
    }

    // Set pipe to message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr)) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}

bool IPCClient::ConnectSHM() {
    // Open existing shared memory
    m_hSHM = OpenFileMappingW(
        FILE_MAP_READ,
        FALSE,
        OMEGA1_SHM_NAME
    );

    if (!m_hSHM) {
        // SHM not available
        return false;
    }

    // Map view
    m_pSHM = MapViewOfFile(m_hSHM, FILE_MAP_READ, 0, 0, OMEGA1_SHM_SIZE);
    if (!m_pSHM) {
        CloseHandle(m_hSHM);
        m_hSHM = nullptr;
        return false;
    }

    // Verify header
    m_pSHMHeader = (Omega1SHMHeader*)m_pSHM;
    if (m_pSHMHeader->magic != OMEGA1_MAGIC_SHM) {
        UnmapViewOfFile(m_pSHM);
        m_pSHM = nullptr;
        CloseHandle(m_hSHM);
        m_hSHM = nullptr;
        return false;
    }

    // Ring buffer starts after header
    m_pRingBuffer = (uint8_t*)m_pSHM + sizeof(Omega1SHMHeader);

    // Open data ready event
    m_hDataReady = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, OMEGA1_EVENT_NAME);

    return true;
}

bool IPCClient::SendRequest(Omega1MsgType type, const void* payload, size_t payloadSize) {
    if (!m_connected || m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Build request
    Omega1RequestHeader header{};
    header.magic = OMEGA1_MAGIC_REQUEST;
    header.version = OMEGA1_PROTOCOL_VERSION;
    header.type = type;
    header.requestId = m_nextRequestId++;
    header.payloadSize = (uint32_t)payloadSize;

    // Send header
    DWORD written;
    if (!WriteFile(m_hPipe, &header, sizeof(header), &written, nullptr)) {
        return false;
    }

    // Send payload if any
    if (payload && payloadSize > 0) {
        if (!WriteFile(m_hPipe, payload, (DWORD)payloadSize, &written, nullptr)) {
            return false;
        }
    }

    // Flush
    FlushFileBuffers(m_hPipe);

    return true;
}

bool IPCClient::SendRequest(Omega1MsgType type) {
    return SendRequest(type, nullptr, 0);
}

bool IPCClient::RequestCompletion(const wchar_t* context, const wchar_t* systemPrompt,
                                 uint32_t maxTokens, float temperature, float topP) {
    if (!context) return false;

    // Build request payload
    size_t contextLen = wcslen(context);
    size_t sysPromptLen = systemPrompt ? wcslen(systemPrompt) : 0;
    size_t totalSize = sizeof(Omega1CompletionRequest) + (contextLen + 1) * sizeof(wchar_t);

    std::vector<uint8_t> payload(totalSize);
    auto* req = (Omega1CompletionRequest*)payload.data();

    req->maxTokens = maxTokens;
    req->temperature = temperature;
    req->topP = topP;
    req->contextLinesBefore = 50;  // Configurable
    req->contextLinesAfter = 10;

    if (systemPrompt) {
        wcsncpy(req->systemPrompt, systemPrompt, 511);
        req->systemPrompt[511] = L'\0';
    } else {
        req->systemPrompt[0] = L'\0';
    }

    // Copy context after struct
    wchar_t* contextDest = (wchar_t*)(payload.data() + sizeof(Omega1CompletionRequest));
    memcpy(contextDest, context, (contextLen + 1) * sizeof(wchar_t));

    m_currentRequestId = m_nextRequestId;
    return SendRequest(Omega1MsgType::REQUEST_COMPLETION, payload.data(), totalSize);
}

bool IPCClient::CancelGeneration() {
    return SendRequest(Omega1MsgType::CANCEL_GENERATION);
}

bool IPCClient::LoadModel(const wchar_t* modelPath) {
    if (!modelPath) return false;
    size_t len = (wcslen(modelPath) + 1) * sizeof(wchar_t);
    return SendRequest(Omega1MsgType::LOAD_MODEL, modelPath, len);
}

bool IPCClient::UnloadModel() {
    return SendRequest(Omega1MsgType::UNLOAD_MODEL);
}

bool IPCClient::GetStatus() {
    return SendRequest(Omega1MsgType::GET_STATUS);
}

bool IPCClient::SetParameters(float temperature, float topP) {
    // Pack into simple struct
    struct Params { float temp; float topP; };
    Params p = { temperature, topP };
    return SendRequest(Omega1MsgType::SET_PARAMETERS, &p, sizeof(p));
}

DWORD WINAPI IPCClient::WorkerThreadProc(LPVOID param) {
    auto* client = (IPCClient*)param;
    client->WorkerThread();
    return 0;
}

void IPCClient::WorkerThread() {
    // Worker thread reads from pipe and processes responses
    while (m_running) {
        Omega1RequestHeader header;
        DWORD read;

        // Read header (blocking)
        BOOL result = ReadFile(m_hPipe, &header, sizeof(header), &read, nullptr);
        if (!result || read != sizeof(header)) {
            // Pipe disconnected
            if (m_errorCallback) {
                m_errorCallback(Omega1Status::ERROR_PIPE_DISCONNECTED, L"Pipe disconnected");
            }
            m_connected = false;
            break;
        }

        // Verify magic
        if (header.magic != OMEGA1_MAGIC_REQUEST) {
            continue;
        }

        // Read payload if any
        std::vector<uint8_t> payload;
        if (header.payloadSize > 0) {
            payload.resize(header.payloadSize);
            if (!ReadFile(m_hPipe, payload.data(), header.payloadSize, &read, nullptr)) {
                continue;
            }
        }

        // Process response
        ProcessResponse(header, payload.data());
    }
}

void IPCClient::ProcessResponse(const Omega1RequestHeader& header, const uint8_t* payload) {
    switch (header.type) {
    case Omega1MsgType::COMPLETION_TOKEN: {
        if (payload && header.payloadSize >= sizeof(Omega1TokenResponse)) {
            auto* resp = (Omega1TokenResponse*)payload;
            // Token data is in SHM, read from ring buffer
            ProcessRingBuffer();
        }
        break;
    }

    case Omega1MsgType::COMPLETION_DONE: {
        if (m_tokenCallback) {
            m_tokenCallback(L"", 0, true);
        }
        break;
    }

    case Omega1MsgType::STATUS_RESPONSE: {
        if (payload && header.payloadSize >= sizeof(Omega1StatusResponse)) {
            memcpy(&m_cachedStatus, payload, sizeof(m_cachedStatus));
            if (m_telemetryCallback) {
                m_telemetryCallback(m_cachedStatus);
            }
        }
        break;
    }

    case Omega1MsgType::ERROR_RESPONSE: {
        if (payload && header.payloadSize >= sizeof(Omega1ErrorResponse)) {
            auto* err = (Omega1ErrorResponse*)payload;
            if (m_errorCallback) {
                m_errorCallback(err->code, err->message);
            }
        }
        break;
    }

    case Omega1MsgType::TELEMETRY_UPDATE: {
        if (payload && header.payloadSize >= sizeof(Omega1StatusResponse)) {
            memcpy(&m_cachedStatus, payload, sizeof(m_cachedStatus));
            if (m_telemetryCallback) {
                m_telemetryCallback(m_cachedStatus);
            }
        }
        break;
    }
    }
}

void IPCClient::ProcessRingBuffer() {
    if (!m_pSHMHeader || !m_pRingBuffer) return;

    // Read new entries from ring buffer
    uint32_t readIdx = m_pSHMHeader->readIndex;
    uint32_t writeIdx = m_pSHMHeader->writeIndex;

    while (readIdx != writeIdx) {
        // Read entry at readIdx
        Omega1RingEntry* entry = (Omega1RingEntry*)(m_pRingBuffer + readIdx);

        if (entry->type == 0 && m_tokenCallback) { // Token
            const wchar_t* tokenData = (const wchar_t*)((uint8_t*)entry + sizeof(Omega1RingEntry));
            m_tokenCallback(tokenData, entry->length / sizeof(wchar_t), false);
        }

        // Advance read index
        size_t entrySize = sizeof(Omega1RingEntry) + entry->length;
        readIdx = (readIdx + (uint32_t)entrySize) % OMEGA1_RING_SIZE;
    }

    // Update shared read index
    m_pSHMHeader->readIndex = readIdx;
}

void IPCClient::Poll() {
    // Called from main thread - process any pending ring buffer data
    ProcessRingBuffer();
}

bool IPCClient::WaitForCompletion(DWORD timeoutMs) {
    // Simple implementation - wait for completion flag
    // In production, use an event
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        Poll();
        Sleep(10);
    }
    return true;
}

// ============================================================================
// GhostTextIntegration Implementation
// ============================================================================

GhostTextIntegration::GhostTextIntegration(IPCClient& client) : m_client(client) {
    // Set up callbacks
    client.SetTokenCallback([this](const wchar_t* token, size_t len, bool isFinal) {
        OnToken(token, len, isFinal);
    });
    client.SetErrorCallback([this](Omega1Status code, const wchar_t* msg) {
        OnError(code, msg);
    });
}

void GhostTextIntegration::TriggerCompletion(HWND hEditor) {
    if (m_generating) {
        Cancel();
    }

    // Get editor text (simplified - would need actual editor integration)
    // For now, use placeholder
    const wchar_t* context = L"// Current editor context\nint main() {\n    ";
    const wchar_t* systemPrompt = L"You are a coding assistant. Complete the code.";

    m_accumulatedText.clear();
    m_generating = true;
    m_currentRequestId = 0; // Will be set by RequestCompletion

    m_client.RequestCompletion(context, systemPrompt, 256, 0.7f, 0.9f);
}

void GhostTextIntegration::Cancel() {
    if (m_generating) {
        m_client.CancelGeneration();
        m_generating = false;
        m_accumulatedText.clear();
    }
}

void GhostTextIntegration::Clear() {
    m_accumulatedText.clear();
    m_generating = false;
}

void GhostTextIntegration::OnToken(const wchar_t* token, size_t len, bool isFinal) {
    if (len > 0) {
        m_accumulatedText.append(token, len);
    }
    if (isFinal) {
        m_generating = false;
    }
}

void GhostTextIntegration::OnError(Omega1Status code, const wchar_t* message) {
    m_generating = false;
    m_accumulatedText.clear();
}

} // namespace Omega1
} // namespace RawrXD
