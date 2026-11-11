#pragma once
#include "SharedSessionLayout.hpp"
#include <string>
#include <expected>

namespace RawrXD {

// Result types for shared memory operations
enum class SharedMemoryError {
    Success = 0,
    AlreadyExists,
    CreationFailed,
    MappingFailed,
    ViewFailed,
    InvalidSize,
    AccessDenied,
    Unknown
};

// Shared memory manager for cross-process session state
class SharedMemoryManager {
public:
    // Default shared memory name for RawrXD sessions
    static constexpr const wchar_t* DEFAULT_SESSION_NAME = L"RawrXD_UnifiedSession_v1";
    
    // Size of the shared memory arena
    static constexpr size_t ARENA_SIZE = sizeof(UnifiedSessionStateArena);
    
    // Constructor - creates or opens shared memory
    explicit SharedMemoryManager(const std::wstring& name = DEFAULT_SESSION_NAME);
    ~SharedMemoryManager();
    
    // Disable copy/move
    SharedMemoryManager(const SharedMemoryManager&) = delete;
    SharedMemoryManager& operator=(const SharedMemoryManager&) = delete;
    SharedMemoryManager(SharedMemoryManager&&) = delete;
    SharedMemoryManager& operator=(SharedMemoryManager&&) = delete;
    
    // Initialize the arena (call once by creator)
    bool InitializeArena();
    
    // Get pointer to arena (valid after construction)
    UnifiedSessionStateArena* GetArena() const { return m_arena; }
    
    // Check if this instance is the creator (first to open)
    bool IsCreator() const { return m_isCreator; }
    
    // Atomic ring buffer operations using Win32 Interlocked* intrinsics
    // Push event to ring buffer - thread-safe, lock-free
    bool PushEvent(uint32_t eventType, const void* data, uint32_t dataLen);
    
    // Pop event from ring buffer - thread-safe, lock-free
    bool PopEvent(SharedEventFrame& outFrame);
    
    // Get current sequence number (atomic read)
    uint64_t GetCurrentSequence() const;
    
    // Update IDE state (working directory, active file)
    void SetWorkingDirectory(const wchar_t* path);
    void SetActiveFile(const wchar_t* path);
    void SetActiveModel(const char* modelHash, uint32_t vramBytes);
    void SetExecutionMode(uint32_t mode);
    
    // Read IDE state
    void GetWorkingDirectory(wchar_t* outPath, size_t maxLen) const;
    void GetActiveFile(wchar_t* outPath, size_t maxLen) const;
    void GetActiveModel(char* outHash, uint32_t& outVram) const;
    uint32_t GetExecutionMode() const;
    
    // Error handling
    SharedMemoryError GetLastError() const { return m_lastError; }
    const wchar_t* GetLastErrorString() const;
    
private:
    HANDLE m_hMapFile = nullptr;
    UnifiedSessionStateArena* m_arena = nullptr;
    std::wstring m_name;
    bool m_isCreator = false;
    SharedMemoryError m_lastError = SharedMemoryError::Success;
    
    // Helper to get slot index from sequence
    static size_t SequenceToSlot(uint64_t seq) {
        return static_cast<size_t>(seq % UnifiedSessionStateArena::SLOT_COUNT);
    }
};

} // namespace RawrXD
