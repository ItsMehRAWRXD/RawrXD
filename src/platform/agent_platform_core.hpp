//============================================================================
// agent_platform_core.hpp
// RawrXD Agent Platform Layer - Core Definitions
//============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <json/json.h>

namespace RawrXD {
namespace Platform {

//============================================================================
// Enums and Constants
//============================================================================

enum class AgentMode {
    ASK,        // Read-only Q&A
    PLAN,       // Creates execution graph, no side effects
    EDIT,       // Produces patches/file changes
    AGENT,      // Full autonomous execution
    CHAT,       // General conversation
    REVIEW      // Inspects diffs/telemetry/logs
};

enum class Permission {
    READ_ONLY = 0,
    FILE_EDIT = 1,
    EXECUTE = 2,
    AUTONOMOUS = 3
};

enum class ToolSource {
    BUILTIN,
    EXTENSION,
    MCP_SERVER,
    COMMUNITY,
    CUSTOM
};

enum class SessionState {
    ACTIVE,
    PAUSED,
    COMPLETED,
    ERROR
};

//============================================================================
// Forward Declarations
//============================================================================

class AgentSession;
class ToolRegistry;
class ExtensionRegistry;
class ModelRegistry;
class MCPBridge;
class ModeRouter;
class MultiAgentOrchestrator;
class SovereignIDE;

//============================================================================
// Utility Functions
//============================================================================

inline std::string AgentModeToString(AgentMode mode) {
    switch (mode) {
        case AgentMode::ASK: return "ask";
        case AgentMode::PLAN: return "plan";
        case AgentMode::EDIT: return "edit";
        case AgentMode::AGENT: return "agent";
        case AgentMode::CHAT: return "chat";
        case AgentMode::REVIEW: return "review";
        default: return "unknown";
    }
}

inline AgentMode StringToAgentMode(const std::string& str) {
    if (str == "ask") return AgentMode::ASK;
    if (str == "plan") return AgentMode::PLAN;
    if (str == "edit") return AgentMode::EDIT;
    if (str == "agent") return AgentMode::AGENT;
    if (str == "chat") return AgentMode::CHAT;
    if (str == "review") return AgentMode::REVIEW;
    return AgentMode::ASK;
}

inline std::string PermissionToString(Permission perm) {
    switch (perm) {
        case Permission::READ_ONLY: return "read_only";
        case Permission::FILE_EDIT: return "file_edit";
        case Permission::EXECUTE: return "execute";
        case Permission::AUTONOMOUS: return "autonomous";
        default: return "unknown";
    }
}

//============================================================================
// Event System
//============================================================================

struct PlatformEvent {
    std::string type;
    std::string source;
    Json::Value data;
    std::chrono::system_clock::time_point timestamp;
    
    PlatformEvent() : timestamp(std::chrono::system_clock::now()) {}
    
    PlatformEvent(const std::string& t, const std::string& s, const Json::Value& d)
        : type(t), source(s), data(d), timestamp(std::chrono::system_clock::now()) {}
};

using EventHandler = std::function<void(const PlatformEvent&)>;

class EventBus {
public:
    void Subscribe(const std::string& event_type, EventHandler handler);
    void Publish(const PlatformEvent& event);
    void Publish(const std::string& type, const std::string& source, const Json::Value& data);
    
private:
    std::mutex mutex_;
    std::map<std::string, std::vector<EventHandler>> handlers_;
};

} // namespace Platform
} // namespace RawrXD
