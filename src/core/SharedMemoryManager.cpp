// ============================================================================
// RawrXD Shared Memory Manager - Phase 1 Implementation
// Cross-process session state with lock-free MPMC ring buffer
// ============================================================================

#include "SharedMemoryManager.hpp"
#include <cstdio>

namespace RawrXD {

// FNV-1a hash for event type hashing
static uint32_t FNV1aHash(const char* str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= static_cast<uint32_t>(*str++);
        hash *= 16777619u;
    }
    return hash;
}

SharedMemoryManager::SharedMemoryManager(const std::wstring& name) 
    : m_name(name) {
    
    // Create or open file mapping
    m_hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,    // Use paging file
        nullptr,                 // Default security
        PAGE_READWRITE,          // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        static_cast<DWORD>(ARENA_SIZE), // Maximum object size (low-order DWORD)
        m_name.c_str());         // Name of mapping object

    if (m_hMapFile == nullptr) {
        m_lastError = SharedMemoryError::CreationFailed;
        return;
    }

    // Check if we created it or opened existing
    m_isCreator = (GetLastError() != ERROR_ALREADY_EXISTS);

    // Map view of file
    m_arena = static_cast<UnifiedSessionStateArena*>(
        MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, ARENA_SIZE)
    );

    if (m_arena == nullptr) {
        m_lastError = SharedMemoryError::ViewFailed;
        CloseHandle(m_hMapFile);
        m_hMapFile = nullptr;
        return;
    }

    m_lastError = SharedMemoryError::Success;
    printf("[SharedMemoryManager] %s shared memory: %ls\n", 
           m_isCreator ? "Created" : "Opened", m_name.c_str());
}

SharedMemoryManager::~SharedMemoryManager() {
    if (m_arena) {
        UnmapViewOfFile(m_arena);
        m_arena = nullptr;
    }
    if (m_hMapFile) {
        CloseHandle(m_hMapFile);
        m_hMapFile = nullptr;
    }
    printf("[SharedMemoryManager] Cleaned up shared memory\n");
}

bool SharedMemoryManager::InitializeArena() {
    if (!m_arena) return false;
    if (!m_isCreator) {
        printf("[SharedMemoryManager] Only creator can initialize arena\n");
        return false;
    }

    // Zero-initialize the entire arena
    ZeroMemory(m_arena, ARENA_SIZE);

    // Initialize atomic indices using Interlocked* for consistency
    InterlockedExchange(&m_arena->headIndex, 0);
    InterlockedExchange(&m_arena->tailIndex, 0);

    // Initialize event ring sequence numbers
    for (size_t i = 0; i < UnifiedSessionStateArena::SLOT_COUNT; ++i) {
        m_arena->eventRing[i].sequence = 0;
        m_arena->eventRing[i].eventType = 0;
        m_arena->eventRing[i].payloadLength = 0;
        ZeroMemory(m_arena->eventRing[i].payload, sizeof(m_arena->eventRing[i].payload));
    }

    // Set default execution mode
    m_arena->currentExecutionMode = 1; // GUI mode default

    printf("[SharedMemoryManager] Arena initialized (%zu slots)\n", 
           UnifiedSessionStateArena::SLOT_COUNT);
    return true;
}

bool SharedMemoryManager::PushEvent(uint32_t eventType, const void* data, uint32_t dataLen) {
    if (!m_arena) return false;
    if (dataLen > 256) return false; // Payload size limit

    // Get current head position atomically
    long currentHead = InterlockedCompareExchange(&m_arena->headIndex, 0, 0);
    long nextHead = (currentHead + 1) % UnifiedSessionStateArena::SLOT_COUNT;

    // Check if buffer is full (head would overwrite tail)
    long currentTail = InterlockedCompareExchange(&m_arena->tailIndex, 0, 0);
    if (nextHead == currentTail) {
        // Buffer full - advance tail to drop oldest event
        InterlockedCompareExchange(&m_arena->tailIndex, 
            (currentTail + 1) % UnifiedSessionStateArena::SLOT_COUNT, currentTail);
    }

    // Get slot and write event
    size_t slotIdx = static_cast<size_t>(currentHead % UnifiedSessionStateArena::SLOT_COUNT);
    SharedEventFrame& slot = m_arena->eventRing[slotIdx];

    // Write event data (single writer, no lock needed for slot)
    uint64_t newSeq = slot.sequence + 1;
    if (newSeq == 0) newSeq = 1; // Avoid 0 sequence

    slot.sequence = newSeq;
    slot.eventType = eventType;
    slot.payloadLength = dataLen;
    if (dataLen > 0 && data) {
        CopyMemory(slot.payload, data, dataLen);
    }

    // Memory barrier to ensure write completes before index update
    _mm_sfence();

    // Advance head atomically
    InterlockedExchange(&m_arena->headIndex, nextHead);

    return true;
}

bool SharedMemoryManager::PopEvent(SharedEventFrame& outFrame) {
    if (!m_arena) return false;

    // Get current tail position
    long currentTail = InterlockedCompareExchange(&m_arena->tailIndex, 0, 0);
    long currentHead = InterlockedCompareExchange(&m_arena->headIndex, 0, 0);

    // Check if buffer is empty
    if (currentTail == currentHead) {
        return false; // Empty
    }

    // Get slot
    size_t slotIdx = static_cast<size_t>(currentTail % UnifiedSessionStateArena::SLOT_COUNT);
    SharedEventFrame& slot = m_arena->eventRing[slotIdx];

    // Copy event data
    outFrame.sequence = slot.sequence;
    outFrame.eventType = slot.eventType;
    outFrame.payloadLength = slot.payloadLength;
    CopyMemory(outFrame.payload, slot.payload, sizeof(outFrame.payload));

    // Advance tail atomically
    long nextTail = (currentTail + 1) % UnifiedSessionStateArena::SLOT_COUNT;
    InterlockedExchange(&m_arena->tailIndex, nextTail);

    return true;
}

uint64_t SharedMemoryManager::GetCurrentSequence() const {
    if (!m_arena) return 0;
    
    // Read head index atomically
    long head = InterlockedCompareExchange(
        const_cast<volatile long*>(&m_arena->headIndex), 0, 0);
    
    if (head == 0) return 0;
    
    size_t slotIdx = static_cast<size_t>((head - 1) % UnifiedSessionStateArena::SLOT_COUNT);
    return m_arena->eventRing[slotIdx].sequence;
}

void SharedMemoryManager::SetWorkingDirectory(const wchar_t* path) {
    if (!m_arena || !path) return;
    wcsncpy(m_arena->currentWorkingDirectory, path, MAX_PATH - 1);
    m_arena->currentWorkingDirectory[MAX_PATH - 1] = L'\0';
}

void SharedMemoryManager::SetActiveFile(const wchar_t* path) {
    if (!m_arena || !path) return;
    wcsncpy(m_arena->activeFilePath, path, MAX_PATH - 1);
    m_arena->activeFilePath[MAX_PATH - 1] = L'\0';
}

void SharedMemoryManager::SetActiveModel(const char* modelHash, uint32_t vramBytes) {
    if (!m_arena || !modelHash) return;
    strncpy(m_arena->activeModelHash, modelHash, 64);
    m_arena->activeModelHash[64] = '\0';
    m_arena->activeModelVRAMUsageBytes = vramBytes;
}

void SharedMemoryManager::SetExecutionMode(uint32_t mode) {
    if (!m_arena) return;
    m_arena->currentExecutionMode = mode;
}

void SharedMemoryManager::GetWorkingDirectory(wchar_t* outPath, size_t maxLen) const {
    if (!m_arena || !outPath || maxLen == 0) return;
    wcsncpy(outPath, m_arena->currentWorkingDirectory, maxLen - 1);
    outPath[maxLen - 1] = L'\0';
}

void SharedMemoryManager::GetActiveFile(wchar_t* outPath, size_t maxLen) const {
    if (!m_arena || !outPath || maxLen == 0) return;
    wcsncpy(outPath, m_arena->activeFilePath, maxLen - 1);
    outPath[maxLen - 1] = L'\0';
}

void SharedMemoryManager::GetActiveModel(char* outHash, uint32_t& outVram) const {
    if (!m_arena || !outHash) return;
    strncpy(outHash, m_arena->activeModelHash, 65);
    outHash[64] = '\0';
    outVram = m_arena->activeModelVRAMUsageBytes;
}

uint32_t SharedMemoryManager::GetExecutionMode() const {
    if (!m_arena) return 0;
    return m_arena->currentExecutionMode;
}

const wchar_t* SharedMemoryManager::GetLastErrorString() const {
    switch (m_lastError) {
        case SharedMemoryError::Success: return L"Success";
        case SharedMemoryError::AlreadyExists: return L"Shared memory already exists";
        case SharedMemoryError::CreationFailed: return L"Failed to create shared memory";
        case SharedMemoryError::MappingFailed: return L"Failed to create file mapping";
        case SharedMemoryError::ViewFailed: return L"Failed to map view of file";
        case SharedMemoryError::InvalidSize: return L"Invalid shared memory size";
        case SharedMemoryError::AccessDenied: return L"Access denied";
        default: return L"Unknown error";
    }
}

} // namespace RawrXD
