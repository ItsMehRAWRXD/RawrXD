#pragma once
#include "UnifiedSessionState.hpp"
#include "IDEEventBus.hpp"
#include <functional>
#include <string_view>
#include <optional>

namespace RawrXD {

// Command result
struct CommandResult {
    bool success;
    int exitCode;
    std::string_view message;
};

// Command handler type
using CommandHandler = std::function<CommandResult(std::string_view args)>;

// Compile-time FNV-1a hash for command routing
constexpr uint64_t FNV1aHash64(const char* str, size_t len) noexcept {
    uint64_t hash = 0xcbf29ce484222325;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= 0x100000001b3;
    }
    return hash;
}

constexpr uint64_t operator""_cmd(const char* str, size_t len) noexcept {
    return FNV1aHash64(str, len);
}

// Command router for unified CLI/GUI/API command system
class IDECommandRouter {
public:
    IDECommandRouter() noexcept;
    ~IDECommandRouter();

    // Disable copy/move
    IDECommandRouter(const IDECommandRouter&) = delete;
    IDECommandRouter& operator=(const IDECommandRouter&) = delete;
    IDECommandRouter(IDECommandRouter&&) = delete;
    IDECommandRouter& operator=(IDECommandRouter&&) = delete;

    // Initialize with session state and event bus
    bool Initialize(UnifiedSessionState* session, IDEEventBus* eventBus) noexcept;
    void Shutdown() noexcept;

    // --- Command Registration ---
    
    // Register command handler (compile-time hash recommended)
    void RegisterCommand(uint64_t hash, std::string_view name, CommandHandler handler) noexcept;
    
    // Convenience template for string literal
    template<size_t N>
    void RegisterCommand(const char (&name)[N], CommandHandler handler) noexcept {
        RegisterCommand(FNV1aHash64(name, N - 1), std::string_view(name, N - 1), std::move(handler));
    }

    // --- Command Execution ---
    
    // Execute command by hash (O(1) lookup)
    CommandResult Execute(uint64_t hash, std::string_view args) noexcept;
    
    // Execute command by name (computes hash then O(1) lookup)
    CommandResult Execute(std::string_view name, std::string_view args) noexcept;
    
    // Parse and execute command string (e.g., "file/open main.cpp")
    CommandResult ExecuteParsed(std::string_view commandLine) noexcept;

    // --- Command Discovery ---
    
    // List all registered commands
    void ListCommands() const noexcept;
    
    // Get command help
    std::string_view GetCommandHelp(std::string_view name) const noexcept;
    
    // Check if command exists
    bool HasCommand(uint64_t hash) const noexcept;
    bool HasCommand(std::string_view name) const noexcept;

    // Check if initialized
    bool IsInitialized() const noexcept { return m_session != nullptr; }

private:
    static constexpr size_t MAX_COMMANDS = 256;
    
    struct CommandEntry {
        uint64_t hash;
        std::string_view name;
        CommandHandler handler;
        bool active;
    };
    
    UnifiedSessionState* m_session;
    IDEEventBus* m_eventBus;
    CommandEntry m_commands[MAX_COMMANDS];
    size_t m_commandCount;
    
    // Hash table for O(1) lookup
    static constexpr size_t HASH_TABLE_SIZE = 512;
    struct HashSlot {
        uint64_t hash;
        size_t index; // Index into m_commands
        bool occupied;
    };
    HashSlot m_hashTable[HASH_TABLE_SIZE];
    
    size_t FindCommandIndex(uint64_t hash) const noexcept;
    size_t FindHashSlot(uint64_t hash) const noexcept;
};

// Global router accessor
IDECommandRouter* GetGlobalCommandRouter() noexcept;
void SetGlobalCommandRouter(IDECommandRouter* router) noexcept;

// Predefined command hashes (compile-time)
namespace CommandHashes {
    constexpr uint64_t FileOpen = "file/open"_cmd;
    constexpr uint64_t FileClose = "file/close"_cmd;
    constexpr uint64_t FileSave = "file/save"_cmd;
    constexpr uint64_t ModelLoad = "model/load"_cmd;
    constexpr uint64_t ModelUnload = "model/unload"_cmd;
    constexpr uint64_t ModelStatus = "model/status"_cmd;
    constexpr uint64_t ExecCommand = "exec"_cmd;
    constexpr uint64_t Help = "help"_cmd;
    constexpr uint64_t Version = "version"_cmd;
    constexpr uint64_t Status = "status"_cmd;
    constexpr uint64_t Quit = "quit"_cmd;
}

} // namespace RawrXD
