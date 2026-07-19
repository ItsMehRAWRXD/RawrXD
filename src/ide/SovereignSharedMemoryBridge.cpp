// ============================================================================
// SovereignSharedMemoryBridge.cpp
// High-performance shared memory bridge implementation
// ============================================================================

#include "SovereignSharedMemoryBridge.hpp"
#include <cstdarg>
#include <cstdio>

namespace RawrXD {
namespace IDE {

SovereignSharedMemoryBridge::SovereignSharedMemoryBridge()
    : m_hMapFile(NULL)
    , m_hRequestEvent(NULL)
    , m_hResponseEvent(NULL)
    , m_shm(nullptr)
    , m_connected(false)
    , m_isServer(false)
    , m_sequence(0)
    , m_lastTransportLatencyUs(0)
    , m_totalRequests(0)
    , m_cancelledRequests(0)
{
    m_lastError[0] = '\0';
}

SovereignSharedMemoryBridge::~SovereignSharedMemoryBridge()
{
    Detach();
}

bool SovereignSharedMemoryBridge::CreateEvents(const char* baseName)
{
    // Generate event names from base name
    snprintf(m_requestEventName, sizeof(m_requestEventName), "%s_Request", baseName);
    snprintf(m_responseEventName, sizeof(m_responseEventName), "%s_Response", baseName);
    
    // Global namespace for cross-process communication
    char globalRequest[72];
    char globalResponse[72];
    snprintf(globalRequest, sizeof(globalRequest), "Global\\%s", m_requestEventName);
    snprintf(globalResponse, sizeof(globalResponse), "Global\\%s", m_responseEventName);
    
    if (m_isServer) {
        // Server creates events
        m_hRequestEvent = CreateEventA(NULL, FALSE, FALSE, globalRequest);
        m_hResponseEvent = CreateEventA(NULL, FALSE, FALSE, globalResponse);
    } else {
        // Client opens events
        m_hRequestEvent = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, globalRequest);
        m_hResponseEvent = OpenEventA(SYNCHRONIZE, FALSE, globalResponse);
    }
    
    if (!m_hRequestEvent || !m_hResponseEvent) {
        SetError("Failed to %s events: %lu", m_isServer ? "create" : "open", GetLastError());
        return false;
    }
    
    return true;
}

bool SovereignSharedMemoryBridge::AttachToRuntime(const char* shmName)
{
    if (m_connected) {
        SetError("Already connected");
        return false;
    }
    
    m_isServer = false;
    
    // Open existing shared memory
    char globalName[72];
    snprintf(globalName, sizeof(globalName), "Global\\%s", shmName);
    
    m_hMapFile = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, globalName);
    if (!m_hMapFile) {
        // Try local namespace
        m_hMapFile = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, shmName);
        if (!m_hMapFile) {
            SetError("Failed to open shared memory '%s': %lu", shmName, GetLastError());
            return false;
        }
    }
    
    // Map view of file
    m_shm = (SovereignSharedMemory*)MapViewOfFile(
        m_hMapFile,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(SovereignSharedMemory)
    );
    
    if (!m_shm) {
        SetError("Failed to map view: %lu", GetLastError());
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
        return false;
    }
    
    // Verify magic number
    if (m_shm->magic.load() != 0x52415752) {
        SetError("Invalid magic number: expected 0x52415752, got 0x%08X", m_shm->magic.load());
        UnmapViewOfFile(m_shm);
        m_shm = nullptr;
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
        return false;
    }
    
    // Open synchronization events
    if (!CreateEvents(shmName)) {
        UnmapViewOfFile(m_shm);
        m_shm = nullptr;
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
        return false;
    }
    
    m_connected = true;
    return true;
}

bool SovereignSharedMemoryBridge::CreateRuntime(const char* shmName)
{
    if (m_connected) {
        SetError("Already connected");
        return false;
    }
    
    m_isServer = true;
    
    // Create shared memory
    char globalName[72];
    snprintf(globalName, sizeof(globalName), "Global\\%s", shmName);
    
    m_hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(SovereignSharedMemory),
        globalName
    );
    
    if (!m_hMapFile) {
        // Try local namespace
        m_hMapFile = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            sizeof(SovereignSharedMemory),
            shmName
        );
        
        if (!m_hMapFile) {
            SetError("Failed to create shared memory: %lu", GetLastError());
            return false;
        }
    }
    
    // Map view of file
    m_shm = (SovereignSharedMemory*)MapViewOfFile(
        m_hMapFile,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(SovereignSharedMemory)
    );
    
    if (!m_shm) {
        SetError("Failed to map view: %lu", GetLastError());
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
        return false;
    }
    
    // Initialize shared memory
    memset(m_shm, 0, sizeof(SovereignSharedMemory));
    m_shm->magic.store(0x52415752);      // 'RAWR'
    m_shm->version.store(1);
    m_shm->sequence.store(0);
    m_shm->status.store(STATUS_IDLE);
    
    // Create synchronization events
    if (!CreateEvents(shmName)) {
        UnmapViewOfFile(m_shm);
        m_shm = nullptr;
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
        return false;
    }
    
    m_connected = true;
    return true;
}

void SovereignSharedMemoryBridge::Detach()
{
    if (m_shm) {
        UnmapViewOfFile(m_shm);
        m_shm = nullptr;
    }
    
    if (m_hMapFile) {
        CloseHandle(m_hMapFile);
        m_hMapFile = NULL;
    }
    
    if (m_hRequestEvent) {
        CloseHandle(m_hRequestEvent);
        m_hRequestEvent = NULL;
    }
    
    if (m_hResponseEvent) {
        CloseHandle(m_hResponseEvent);
        m_hResponseEvent = NULL;
    }
    
    m_connected = false;
}

bool SovereignSharedMemoryBridge::WaitForResponse(int timeoutMs)
{
    DWORD result = WaitForSingleObject(m_hResponseEvent, timeoutMs);
    
    if (result == WAIT_TIMEOUT) {
        SetError("Request timed out after %d ms", timeoutMs);
        return false;
    }
    
    if (result != WAIT_OBJECT_0) {
        SetError("Wait failed: %lu", GetLastError());
        return false;
    }
    
    return true;
}

bool SovereignSharedMemoryBridge::RequestCompletion(
    const std::string& prompt,
    const std::string& modelPath,
    int maxTokens,
    float temperature,
    std::string& outResponse,
    float& outConfidence,
    int timeoutMs)
{
    if (!m_connected || !m_shm) {
        SetError("Not connected to runtime");
        return false;
    }
    
    // Wait for idle state
    int waitCount = 0;
    while (m_shm->status.load() == STATUS_PROCESSING && waitCount < 100) {
        Sleep(10);
        waitCount++;
    }
    
    if (m_shm->status.load() == STATUS_PROCESSING) {
        SetError("Runtime busy");
        return false;
    }
    
    // Prepare request
    m_sequence++;
    m_shm->sequence.store(m_sequence);
    m_shm->requestType = REQ_TYPE_COMPLETION;
    m_shm->maxTokens = maxTokens;
    m_shm->temperature = static_cast<uint32_t>(temperature * 100);
    m_shm->flags = 0;
    
    // Copy model path
    strncpy(m_shm->modelPath, modelPath.c_str(), sizeof(m_shm->modelPath) - 1);
    m_shm->modelPath[sizeof(m_shm->modelPath) - 1] = '\0';
    
    // Copy prompt (truncate if necessary)
    size_t promptLen = prompt.length();
    if (promptLen >= sizeof(m_shm->prompt)) {
        promptLen = sizeof(m_shm->prompt) - 1;
    }
    memcpy(m_shm->prompt, prompt.c_str(), promptLen);
    m_shm->prompt[promptLen] = '\0';
    m_shm->promptLength = static_cast<uint32_t>(promptLen);
    
    // Clear response area
    m_shm->responseLength = 0;
    m_shm->response[0] = '\0';
    
    // Set status to processing and signal runtime
    m_shm->status.store(STATUS_PROCESSING);
    m_shm->requestTimestamp = GetTickCount64();
    
    SetEvent(m_hRequestEvent);
    
    // Wait for response
    if (!WaitForResponse(timeoutMs)) {
        m_shm->status.store(STATUS_TIMEOUT);
        return false;
    }
    
    // Check result status
    uint32_t status = m_shm->status.load();
    if (status == STATUS_ERROR) {
        SetError("Runtime reported error");
        return false;
    }
    
    if (status != STATUS_COMPLETE) {
        SetError("Unexpected status: %u", status);
        return false;
    }
    
    // Extract response
    outResponse = std::string(m_shm->response, m_shm->responseLength);
    outConfidence = m_shm->confidence;
    
    return true;
}

bool SovereignSharedMemoryBridge::SendHeartbeat(int timeoutMs)
{
    if (!m_connected || !m_shm) {
        return false;
    }
    
    // Simple check: verify magic is still valid
    if (m_shm->magic.load() != 0x52415752) {
        SetError("Shared memory corrupted");
        return false;
    }
    
    // Check if runtime is responsive by looking at sequence
    uint32_t oldSeq = m_shm->sequence.load();
    
    // Send ping request
    m_shm->requestType = 0;  // Ping
    m_shm->status.store(STATUS_PROCESSING);
    SetEvent(m_hRequestEvent);
    
    // Wait briefly for any response
    DWORD result = WaitForSingleObject(m_hResponseEvent, timeoutMs);
    
    if (result != WAIT_OBJECT_0) {
        SetError("Heartbeat timeout");
        return false;
    }
    
    return true;
}

void SovereignSharedMemoryBridge::GetStats(uint32_t& cacheHits, uint32_t& cacheMisses, uint64_t& latencyUs)
{
    if (!m_connected || !m_shm) {
        cacheHits = 0;
        cacheMisses = 0;
        latencyUs = 0;
        return;
    }
    
    cacheHits = m_shm->cacheHits;
    cacheMisses = m_shm->cacheMisses;
    
    if (m_shm->responseTimestamp > m_shm->requestTimestamp) {
        latencyUs = (m_shm->responseTimestamp - m_shm->requestTimestamp) * 1000;
    } else {
        latencyUs = 0;
    }
}

void SovereignSharedMemoryBridge::SetError(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(m_lastError, sizeof(m_lastError), fmt, args);
    va_end(args);
    
    OutputDebugStringA("[SovereignSharedMemoryBridge] ");
    OutputDebugStringA(m_lastError);
    OutputDebugStringA("\n");
}

} // namespace IDE
} // namespace RawrXD
