#pragma once
#include "SharedSessionLayout.hpp"
#include <cstdint>
#include <cstring>
#include <string_view>

// Compile-time FNV-1a 32-bit hash
constexpr uint32_t HashFNV1a(std::string_view str) noexcept {
    uint32_t hash = 2166136261u;
    for (char c : str) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

// Predefined command hashes (compile-time)
namespace CommandHashes {
    constexpr uint32_t FILE_CHANGED = HashFNV1a("file/changed");
    constexpr uint32_t CONFIG_CHANGED = HashFNV1a("config/changed");
    constexpr uint32_t MODEL_LOADED = HashFNV1a("model/loaded");
    constexpr uint32_t MODEL_UNLOADED = HashFNV1a("model/unloaded");
    constexpr uint32_t WORKDIR_CHANGED = HashFNV1a("workdir/changed");
    constexpr uint32_t COMMAND_EXECUTED = HashFNV1a("command/executed");
    constexpr uint32_t SYSTEM_SHUTDOWN = HashFNV1a("system/shutdown");
}

struct CommandContext {
    uint32_t eventId;
    const void* payload;
    size_t payloadLen;
    uint64_t timestamp;
    uint32_t sourceComponent; // IDE, CLI, GUI, etc.
};

using CommandHandler = void(*)(const CommandContext& ctx);

struct CommandEntry {
    uint32_t commandHash;
    CommandHandler handler;
    bool occupied;
    
    CommandEntry() : commandHash(0), handler(nullptr), occupied(false) {}
};

class CommandRouter {
public:
    // Power-of-2 size for fast modulo via bitmask
    static constexpr size_t TABLE_SIZE = 256;
    static constexpr size_t TABLE_MASK = TABLE_SIZE - 1;
    static constexpr size_t MAX_COMMANDS = 128;
    
    CommandRouter();
    ~CommandRouter() = default;
    
    // Disable copy/move
    CommandRouter(const CommandRouter&) = delete;
    CommandRouter& operator=(const CommandRouter&) = delete;
    CommandRouter(CommandRouter&&) = delete;
    CommandRouter& operator=(CommandRouter&&) = delete;
    
    // Register a command handler (thread-safe, called at init)
    bool Register(uint32_t hash, CommandHandler handler);
    
    // Route command to handler (lock-free, O(1) average)
    void Route(uint32_t hash, const CommandContext& ctx) const;
    
    // Convenience: Route from SharedEventFrame
    void RouteEvent(const SharedEventFrame& frame) const;
    
    // Get handler for hash (for testing)
    CommandHandler GetHandler(uint32_t hash) const;
    
    // Stats
    size_t GetRegisteredCount() const { return m_commandCount; }
    size_t GetTableSize() const { return TABLE_SIZE; }
    
private:
    CommandEntry m_table[TABLE_SIZE];
    alignas(64) volatile long m_commandCount = 0;
    
    // Open addressing: probe sequence
    static size_t ProbeSequence(uint32_t hash, size_t attempt) {
        // Linear probing with stride (cache-friendly)
        return (hash + attempt) & TABLE_MASK;
    }
    
    // Find slot for hash (for insert or lookup)
    size_t FindSlot(uint32_t hash) const;
    size_t FindInsertSlot(uint32_t hash);
};

// Global router instance (defined in .cpp)
extern CommandRouter g_CommandRouter;

// Convenience registration macros
#define REGISTER_COMMAND(name, handler) \
    g_CommandRouter.Register(CommandHashes::name, handler)

#define ROUTE_EVENT(frame) \
    g_CommandRouter.RouteEvent(frame)
