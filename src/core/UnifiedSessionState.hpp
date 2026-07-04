#pragma once
#include "SharedSessionLayout.hpp"
#include <string_view>
#include <optional>
#include <string>

namespace RawrXD {

// Forward declarations
class SharedEventWriter;
class SharedEventReader;

// Execution modes for the IDE
enum class ExecutionMode : uint32_t {
    GUI = 1,
    CLI = 2,
    Headless = 3
};

// Event types (FNV-1a hashed at compile time)
enum class EventType : uint32_t {
    FileChanged = 0xDD552210,       // fnv1a("file/changed")
    ConfigChanged = 0x35382E9C,     // fnv1a("config/changed")
    ModelLoaded = 0xB76D1DA6,       // fnv1a("model/loaded")
    ModelUnloaded = 0x12DDD52D,     // fnv1a("model/unloaded")
    WorkingDirChanged = 0x2ED827CC,  // fnv1a("workdir/changed")
    CommandExecuted = 0xE587EF7A,    // fnv1a("command/executed")
    Shutdown = 0xE8C51B5F,          // fnv1a("system/shutdown")
    
    // Codex/GPT subsystem events
    CodexStreamStarted = 0x8F4A2B1C,   // fnv1a("codex/stream/started")
    CodexStreamChunk = 0x3E7D8A9F,     // fnv1a("codex/stream/chunk")
    CodexStreamCompleted = 0xC5B1E4D2, // fnv1a("codex/stream/completed")
    CodexStreamError = 0xA9F3C7E8,     // fnv1a("codex/stream/error")
    CodexRequestSubmitted = 0x7B2D5F1A // fnv1a("codex/request/submitted")
};

// Result of event write operation
struct WriteResult {
    bool success;
    uint64_t sequence;
};

// Main shared session state manager
class UnifiedSessionState {
public:
    // Shared memory name for cross-process discovery
    static constexpr wchar_t SHARED_MEMORY_NAME[] = L"RawrXD_UnifiedSessionState_v1";
    static constexpr size_t SHARED_MEMORY_SIZE = sizeof(UnifiedSessionStateArena);

    UnifiedSessionState() noexcept;
    ~UnifiedSessionState();

    // Disable copy/move - handles are unique
    UnifiedSessionState(const UnifiedSessionState&) = delete;
    UnifiedSessionState& operator=(const UnifiedSessionState&) = delete;
    UnifiedSessionState(UnifiedSessionState&&) = delete;
    UnifiedSessionState& operator=(UnifiedSessionState&&) = delete;

    // Initialize shared memory (create if first, open if exists)
    bool Initialize(bool createIfNotExists = true) noexcept;
    
    // Shutdown and cleanup
    void Shutdown() noexcept;

    // Check if initialized
    bool IsInitialized() const noexcept { return m_arena != nullptr; }

    // --- Global State Accessors ---
    
    // Working directory (thread-safe, atomic read/write)
    void SetWorkingDirectory(std::wstring_view path) noexcept;
    std::wstring GetWorkingDirectory() const noexcept;
    
    // Active file path
    void SetActiveFilePath(std::wstring_view path) noexcept;
    std::wstring GetActiveFilePath() const noexcept;
    
    // Model telemetry
    void SetActiveModel(std::string_view hash, uint32_t vramBytes) noexcept;
    std::string GetActiveModelHash() const noexcept;
    uint32_t GetActiveModelVRAM() const noexcept;
    
    // Execution mode
    void SetExecutionMode(ExecutionMode mode) noexcept;
    ExecutionMode GetExecutionMode() const noexcept;

    // --- Event Ring Buffer Operations ---
    
    // Write event to ring buffer (MPMC safe)
    WriteResult WriteEvent(EventType type, std::string_view payload) noexcept;
    
    // Read next event from ring buffer (returns false if no new events)
    bool ReadNextEvent(SharedEventFrame& outFrame, uint64_t& lastSequence) noexcept;
    
    // Get current sequence number for snapshot
    uint64_t GetCurrentSequence() const noexcept;

    // --- Version Accessors ---
    
    // Get protocol version from shared memory
    uint32_t GetProtocolVersion() const noexcept;
    
    // Get runtime version from shared memory
    uint32_t GetRuntimeVersionPacked() const noexcept;
    std::string_view GetRuntimeVersionString() const noexcept;
    
    // Check if connected process has compatible protocol
    bool IsProtocolCompatible() const noexcept;

    // Direct arena access for advanced use
    UnifiedSessionStateArena* GetArena() noexcept { return m_arena; }
    const UnifiedSessionStateArena* GetArena() const noexcept { return m_arena; }

private:
    HANDLE m_hMapFile;
    UnifiedSessionStateArena* m_arena;
    bool m_isCreator;
    
    // Epoch-RCU style atomic operations
    static long IncrementHead(UnifiedSessionStateArena* arena) noexcept;
    static long IncrementTail(UnifiedSessionStateArena* arena) noexcept;
    static bool CompareExchangeHead(UnifiedSessionStateArena* arena, long expected, long desired) noexcept;
};

// Compile-time FNV-1a hash for event type constants
constexpr uint32_t FNV1aHash(const char* str, size_t len) noexcept {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

constexpr uint32_t operator""_event(const char* str, size_t len) noexcept {
    return FNV1aHash(str, len);
}

} // namespace RawrXD
