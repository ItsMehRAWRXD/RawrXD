#include "IDECommandRouter.hpp"
#include "Version.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {

// Global router instance
static IDECommandRouter* g_globalRouter = nullptr;

IDECommandRouter* GetGlobalCommandRouter() noexcept {
    return g_globalRouter;
}

void SetGlobalCommandRouter(IDECommandRouter* router) noexcept {
    g_globalRouter = router;
}

IDECommandRouter::IDECommandRouter() noexcept
    : m_session(nullptr)
    , m_eventBus(nullptr)
    , m_commandCount(0)
{
    // Clear hash table
    for (auto& slot : m_hashTable) {
        slot.occupied = false;
    }
    
    // Clear command entries
    for (auto& cmd : m_commands) {
        cmd.active = false;
    }
}

IDECommandRouter::~IDECommandRouter() {
    Shutdown();
}

bool IDECommandRouter::Initialize(UnifiedSessionState* session, IDEEventBus* eventBus) noexcept {
    if (!session || !session->IsInitialized()) {
        return false;
    }
    
    m_session = session;
    m_eventBus = eventBus;
    
    // Register built-in commands
    RegisterCommand(CommandHashes::Help, "help", [this](std::string_view) {
        ListCommands();
        return CommandResult{true, 0, "Help displayed"};
    });
    
    RegisterCommand(CommandHashes::Version, "version", [](std::string_view) {
        auto ver = GetVersionString();
        wprintf(L"RawrXD %hs\n", ver.data());
        return CommandResult{true, 0, ver.data()};
    });
    
    RegisterCommand(CommandHashes::Status, "status", [this](std::string_view) {
        if (!m_session) {
            return CommandResult{false, 1, "No session"};
        }
        
        auto cwd = m_session->GetWorkingDirectory();
        auto file = m_session->GetActiveFilePath();
        
        wprintf(L"Working Directory: %s\n", cwd.empty() ? L"(none)" : cwd.c_str());
        wprintf(L"Active File: %s\n", file.empty() ? L"(none)" : file.c_str());
        wprintf(L"Protocol: %u\n", m_session->GetProtocolVersion());
        
        return CommandResult{true, 0, "Status displayed"};
    });
    
    RegisterCommand(CommandHashes::Quit, "quit", [](std::string_view) {
        // Signal shutdown via event bus if available
        if (auto* bus = GetGlobalEventBus()) {
            bus->PublishShutdown();
        }
        return CommandResult{true, 0, "Shutdown requested"};
    });
    
    // Set as global router
    if (!g_globalRouter) {
        SetGlobalCommandRouter(this);
    }
    
    return true;
}

void IDECommandRouter::Shutdown() noexcept {
    if (g_globalRouter == this) {
        SetGlobalCommandRouter(nullptr);
    }
    
    m_session = nullptr;
    m_eventBus = nullptr;
    m_commandCount = 0;
}

void IDECommandRouter::RegisterCommand(uint64_t hash, std::string_view name, CommandHandler handler) noexcept {
    if (m_commandCount >= MAX_COMMANDS) return;
    if (HasCommand(hash)) return; // Already registered
    
    // Add to command array
    size_t index = m_commandCount++;
    m_commands[index].hash = hash;
    m_commands[index].name = name;
    m_commands[index].handler = std::move(handler);
    m_commands[index].active = true;
    
    // Add to hash table
    size_t slot = FindHashSlot(hash);
    m_hashTable[slot].hash = hash;
    m_hashTable[slot].index = index;
    m_hashTable[slot].occupied = true;
}

CommandResult IDECommandRouter::Execute(uint64_t hash, std::string_view args) noexcept {
    size_t index = FindCommandIndex(hash);
    if (index >= MAX_COMMANDS || !m_commands[index].active) {
        return CommandResult{false, 1, "Unknown command"};
    }
    
    // Publish command executed event
    if (m_eventBus) {
        m_eventBus->PublishCommandExecuted(m_commands[index].name);
    }
    
    return m_commands[index].handler(args);
}

CommandResult IDECommandRouter::Execute(std::string_view name, std::string_view args) noexcept {
    uint64_t hash = FNV1aHash64(name.data(), name.length());
    return Execute(hash, args);
}

CommandResult IDECommandRouter::ExecuteParsed(std::string_view commandLine) noexcept {
    // Parse command line: "command arg1 arg2"
    size_t spacePos = commandLine.find(' ');
    
    std::string_view cmd;
    std::string_view args;
    
    if (spacePos == std::string_view::npos) {
        cmd = commandLine;
        args = {};
    } else {
        cmd = commandLine.substr(0, spacePos);
        args = commandLine.substr(spacePos + 1);
    }
    
    return Execute(cmd, args);
}

void IDECommandRouter::ListCommands() const noexcept {
    wprintf(L"Available commands:\n");
    for (size_t i = 0; i < m_commandCount; ++i) {
        if (m_commands[i].active) {
            wprintf(L"  %hs\n", m_commands[i].name.data());
        }
    }
}

std::string_view IDECommandRouter::GetCommandHelp(std::string_view name) const noexcept {
    uint64_t hash = FNV1aHash64(name.data(), name.length());
    size_t index = FindCommandIndex(hash);
    
    if (index < MAX_COMMANDS && m_commands[index].active) {
        return m_commands[index].name;
    }
    
    return {};
}

bool IDECommandRouter::HasCommand(uint64_t hash) const noexcept {
    return FindCommandIndex(hash) < MAX_COMMANDS;
}

bool IDECommandRouter::HasCommand(std::string_view name) const noexcept {
    uint64_t hash = FNV1aHash64(name.data(), name.length());
    return HasCommand(hash);
}

size_t IDECommandRouter::FindCommandIndex(uint64_t hash) const noexcept {
    size_t slot = FindHashSlot(hash);
    if (m_hashTable[slot].occupied && m_hashTable[slot].hash == hash) {
        return m_hashTable[slot].index;
    }
    return MAX_COMMANDS; // Not found
}

size_t IDECommandRouter::FindHashSlot(uint64_t hash) const noexcept {
    // Simple linear probing
    size_t slot = hash % HASH_TABLE_SIZE;
    
    for (size_t i = 0; i < HASH_TABLE_SIZE; ++i) {
        size_t probe = (slot + i) % HASH_TABLE_SIZE;
        if (!m_hashTable[probe].occupied || m_hashTable[probe].hash == hash) {
            return probe;
        }
    }
    
    return 0; // Table full (shouldn't happen with reasonable usage)
}

} // namespace RawrXD
