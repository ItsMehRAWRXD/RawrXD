#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
}

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
};

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
}

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <future>

namespace RawrXD {

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string schema;  // JSON schema for parameters
    std::string category;
    bool requiresConfirmation = false;
    int timeoutSeconds = 30;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
}

struct ToolCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string callId;
    std::chrono::system_clock::time_point timestamp;
}

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
    std::string toolName;
}

class ToolRegistry {
public:
    ToolRegistry() = default;
    ~ToolRegistry() = default;

    // Deleted copy/assign, movable
    ToolRegistry(const ToolRegistry&) = delete;
    ToolRegistry& operator=(const ToolRegistry&) = delete;
    ToolRegistry(ToolRegistry&&) = default;
    ToolRegistry& operator=(ToolRegistry&&) = default;

    // Tool registration
    bool registerTool(const ToolDefinition& definition);
    bool unregisterTool(const std::string& name);
    bool hasTool(const std::string& name) const;
    std::vector<ToolDefinition> getAllTools() const;
    std::optional<ToolDefinition> getTool(const std::string& name) const;

    // Tool execution
    ToolResult executeTool(const std::string& name, const std::string& arguments);
    ToolResult executeToolAsync(const ToolCall& call);

    // Tool metadata
    std::vector<ToolDefinition> getToolsByCategory(const std::string& category) const;
    std::vector<std::string> getToolNames() const;
    bool isToolAvailable(const std::string& name) const;

    // Statistics
    struct ToolStats {
        std::string name;
        uint64_t callCount = 0;
        uint64_t successCount = 0;
        uint64_t errorCount = 0;
        std::chrono::milliseconds totalDuration{0};
        std::chrono::milliseconds avgDuration{0};
        std::chrono::system_clock::time_point lastUsed;
        std::string lastError;
    };
    std::optional<ToolStats> getToolStats(const std::string& name) const;
    std::vector<ToolStats> getAllStats() const;

    // Tool lifecycle
    bool enableTool(const std::string& name);
    bool disableTool(const std::string& name);
    bool isToolEnabled(const std::string& name) const;

private:
    struct ToolEntry {
        ToolDefinition definition;
        std::atomic<bool> enabled{true};
        std::atomic<uint64_t> callCount{0};
        std::atomic<uint64_t> successCount{0};
        std::atomic<uint64_t> errorCount{0};
        std::chrono::nanoseconds totalDuration{0};
        std::string lastError;
        std::mutex mutex;
    };

    std::unordered_map<std::string, ToolEntry> m_tools;
    std::mutex m_registryMutex;
    std::atomic<uint64_t> m_totalCalls{0};
    std::atomic<uint64_t> m_totalErrors{0};
};

} // namespace RawrXD