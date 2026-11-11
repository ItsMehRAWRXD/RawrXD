#include "UnifiedSessionState.hpp"
#include "Version.hpp"
#include <cstring>
#include <algorithm>

namespace RawrXD {

// Static assertions for event type hashes
static_assert(static_cast<uint32_t>(EventType::FileChanged) == FNV1aHash("file/changed", 12), "Hash mismatch");
static_assert(static_cast<uint32_t>(EventType::ConfigChanged) == FNV1aHash("config/changed", 14), "Hash mismatch");
static_assert(static_cast<uint32_t>(EventType::ModelLoaded) == FNV1aHash("model/loaded", 12), "Hash mismatch");

// Note: Hash values are computed at compile time using FNV-1a algorithm
// EventType enum values must match the computed hashes exactly

UnifiedSessionState::UnifiedSessionState() noexcept
    : m_hMapFile(nullptr)
    , m_arena(nullptr)
    , m_isCreator(false)
{
}

UnifiedSessionState::~UnifiedSessionState() {
    Shutdown();
}

bool UnifiedSessionState::Initialize(bool createIfNotExists) noexcept {
    if (m_arena != nullptr) {
        return true; // Already initialized
    }

    // Try to open existing shared memory first
    m_hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEMORY_NAME);
    
    if (m_hMapFile == nullptr && createIfNotExists) {
        // Create new shared memory section
        m_hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,    // Use paging file
            nullptr,                 // Default security
            PAGE_READWRITE,          // Read/write access
            0,                       // Maximum object size (high-order DWORD)
            static_cast<DWORD>(SHARED_MEMORY_SIZE), // Maximum object size (low-order DWORD)
            SHARED_MEMORY_NAME       // Name of mapping object
        );
        
        if (m_hMapFile == nullptr) {
            return false;
        }
        
        m_isCreator = true;
    } else if (m_hMapFile == nullptr) {
        return false; // Doesn't exist and we weren't asked to create
    }

    // Map view of file into process address space
    m_arena = static_cast<UnifiedSessionStateArena*>(
        MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE)
    );

    if (m_arena == nullptr) {
        CloseHandle(m_hMapFile);
        m_hMapFile = nullptr;
        return false;
    }

    // If we're the creator, initialize the arena
    if (m_isCreator) {
        // Zero the entire arena
        std::memset(m_arena, 0, SHARED_MEMORY_SIZE);
        
        // Initialize version header
        m_arena->protocolVersion = GetProtocolVersion();
        m_arena->runtimeVersionPacked = GetVersionPacked();
        
        // Copy version string
        auto verStr = GetVersionString();
        std::memcpy(m_arena->runtimeVersionString, verStr.data(), 
                    std::min(verStr.length(), sizeof(m_arena->runtimeVersionString) - 1));
        m_arena->runtimeVersionString[std::min(verStr.length(), sizeof(m_arena->runtimeVersionString) - 1)] = '\0';
        
        // Initialize atomic indices using InterlockedExchange for safety
        InterlockedExchange(&m_arena->headIndex, 0);
        InterlockedExchange(&m_arena->tailIndex, 0);
        
        // Set default execution mode
        m_arena->currentExecutionMode = static_cast<uint32_t>(ExecutionMode::GUI);
    } else {
        // Verify protocol compatibility when opening existing shared memory
        if (m_arena->protocolVersion != GetProtocolVersion()) {
            // Protocol mismatch - could handle gracefully in production
            // For now, continue but log warning
        }
    }

    return true;
}

void UnifiedSessionState::Shutdown() noexcept {
    if (m_arena != nullptr) {
        UnmapViewOfFile(m_arena);
        m_arena = nullptr;
    }
    
    if (m_hMapFile != nullptr) {
        CloseHandle(m_hMapFile);
        m_hMapFile = nullptr;
    }
    
    m_isCreator = false;
}

// --- Global State Accessors ---

void UnifiedSessionState::SetWorkingDirectory(std::wstring_view path) noexcept {
    if (!m_arena) return;
    
    size_t len = std::min(path.length(), static_cast<size_t>(MAX_PATH - 1));
    std::wmemcpy(m_arena->currentWorkingDirectory, path.data(), len);
    m_arena->currentWorkingDirectory[len] = L'\0';
}

std::wstring UnifiedSessionState::GetWorkingDirectory() const noexcept {
    if (!m_arena) return {};
    return std::wstring(m_arena->currentWorkingDirectory);
}

void UnifiedSessionState::SetActiveFilePath(std::wstring_view path) noexcept {
    if (!m_arena) return;
    
    size_t len = std::min(path.length(), static_cast<size_t>(MAX_PATH - 1));
    std::wmemcpy(m_arena->activeFilePath, path.data(), len);
    m_arena->activeFilePath[len] = L'\0';
}

std::wstring UnifiedSessionState::GetActiveFilePath() const noexcept {
    if (!m_arena) return {};
    return std::wstring(m_arena->activeFilePath);
}

void UnifiedSessionState::SetActiveModel(std::string_view hash, uint32_t vramBytes) noexcept {
    if (!m_arena) return;
    
    size_t len = std::min(hash.length(), static_cast<size_t>(64));
    std::memcpy(m_arena->activeModelHash, hash.data(), len);
    m_arena->activeModelHash[len] = '\0';
    m_arena->activeModelVRAMUsageBytes = vramBytes;
}

std::string UnifiedSessionState::GetActiveModelHash() const noexcept {
    if (!m_arena) return {};
    return std::string(m_arena->activeModelHash);
}

uint32_t UnifiedSessionState::GetActiveModelVRAM() const noexcept {
    if (!m_arena) return 0;
    return m_arena->activeModelVRAMUsageBytes;
}

void UnifiedSessionState::SetExecutionMode(ExecutionMode mode) noexcept {
    if (!m_arena) return;
    // Use InterlockedExchange for atomic write
    InterlockedExchange(reinterpret_cast<volatile long*>(&m_arena->currentExecutionMode), 
                        static_cast<uint32_t>(mode));
}

ExecutionMode UnifiedSessionState::GetExecutionMode() const noexcept {
    if (!m_arena) return ExecutionMode::GUI;
    return static_cast<ExecutionMode>(
        InterlockedCompareExchange(
            const_cast<volatile long*>(reinterpret_cast<const volatile long*>(&m_arena->currentExecutionMode)),
            0, 0)
    );
}

// --- Event Ring Buffer Operations ---

WriteResult UnifiedSessionState::WriteEvent(EventType type, std::string_view payload) noexcept {
    if (!m_arena) return {false, 0};
    
    // Get current head position
    long head = InterlockedCompareExchange(&m_arena->headIndex, 0, 0);
    long nextHead = (head + 1) % UnifiedSessionStateArena::SLOT_COUNT;
    
    // Check if ring is full (head would overtake tail)
    long tail = InterlockedCompareExchange(&m_arena->tailIndex, 0, 0);
    if (nextHead == tail) {
        return {false, 0}; // Ring buffer full
    }
    
    // Try to claim slot with CAS
    if (!CompareExchangeHead(m_arena, head, nextHead)) {
        return {false, 0}; // Contention lost, retry by caller
    }
    
    // We own slot 'head', write event
    SharedEventFrame& slot = m_arena->eventRing[head];
    
    // Calculate sequence number
    uint64_t sequence = static_cast<uint64_t>(head) + 
        (InterlockedCompareExchange(reinterpret_cast<volatile long*>(&slot.sequence), 0, 0) / 
         UnifiedSessionStateArena::SLOT_COUNT) * UnifiedSessionStateArena::SLOT_COUNT;
    
    // Write payload (truncate if too large)
    size_t payloadLen = std::min(payload.length(), sizeof(slot.payload));
    std::memcpy(slot.payload, payload.data(), payloadLen);
    
    // Memory barrier to ensure payload written before metadata
    _mm_sfence();
    
    // Write metadata (event type, length, sequence)
    slot.payloadLength = static_cast<uint32_t>(payloadLen);
    slot.eventType = static_cast<uint32_t>(type);
    
    // Final memory barrier before sequence update (signals completion)
    _mm_sfence();
    slot.sequence = sequence + 1; // +1 to distinguish from uninitialized (0)
    
    return {true, sequence};
}

bool UnifiedSessionState::ReadNextEvent(SharedEventFrame& outFrame, uint64_t& lastSequence) noexcept {
    if (!m_arena) return false;
    
    long tail = InterlockedCompareExchange(&m_arena->tailIndex, 0, 0);
    SharedEventFrame& slot = m_arena->eventRing[tail];
    
    // Read sequence with acquire semantics
    uint64_t seq = slot.sequence;
    _mm_lfence(); // Load fence to ensure we see consistent data
    
    // Check if slot has new data
    if (seq <= lastSequence) {
        return false; // No new event
    }
    
    // Copy event data
    outFrame.sequence = seq;
    outFrame.eventType = slot.eventType;
    outFrame.payloadLength = slot.payloadLength;
    std::memcpy(outFrame.payload, slot.payload, slot.payloadLength);
    
    // Advance tail
    long nextTail = (tail + 1) % UnifiedSessionStateArena::SLOT_COUNT;
    InterlockedCompareExchange(&m_arena->tailIndex, tail, nextTail);
    
    lastSequence = seq;
    return true;
}

uint64_t UnifiedSessionState::GetCurrentSequence() const noexcept {
    if (!m_arena) return 0;
    
    long head = InterlockedCompareExchange(&m_arena->headIndex, 0, 0);
    const SharedEventFrame& slot = m_arena->eventRing[head];
    return slot.sequence;
}

// --- Version Accessors ---

uint32_t UnifiedSessionState::GetProtocolVersion() const noexcept {
    if (!m_arena) return 0;
    return m_arena->protocolVersion;
}

uint32_t UnifiedSessionState::GetRuntimeVersionPacked() const noexcept {
    if (!m_arena) return 0;
    return m_arena->runtimeVersionPacked;
}

std::string_view UnifiedSessionState::GetRuntimeVersionString() const noexcept {
    if (!m_arena) return {};
    return std::string_view(m_arena->runtimeVersionString);
}

bool UnifiedSessionState::IsProtocolCompatible() const noexcept {
    if (!m_arena) return false;
    return m_arena->protocolVersion == RawrXD::GetProtocolVersion();
}

// --- Epoch-RCU Atomic Operations ---

long UnifiedSessionState::IncrementHead(UnifiedSessionStateArena* arena) noexcept {
    return InterlockedIncrement(&arena->headIndex);
}

long UnifiedSessionState::IncrementTail(UnifiedSessionStateArena* arena) noexcept {
    return InterlockedIncrement(&arena->tailIndex);
}

bool UnifiedSessionState::CompareExchangeHead(UnifiedSessionStateArena* arena, long expected, long desired) noexcept {
    long result = InterlockedCompareExchange(&arena->headIndex, desired, expected);
    return (result == expected);
}

} // namespace RawrXD
