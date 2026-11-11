#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <mutex>
#include <map>
#include <queue>
#include <thread>
#include <optional>
#include <future>

namespace RawrXD {

struct AgentConfig {
    std::string modelPath;
    std::string modelName;
    int maxContextLength = 4096;
    float temperature = 0.7f;
    float topP = 0.9f;
    int maxTokens = 2048;
    int numThreads = 4;
    bool useGpu = false;
    std::string deviceId = "0";
};

struct AgentState {
    enum Type {
        Idle,
        Thinking,
        Executing,
        Waiting,
        Error,
        Completed
    };
    
    Type current = Type::Idle;
    std::string currentTask;
    std::string currentStep;
    int progress = 0;
    std::string errorMessage;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point updatedAt;
};

class AgentLoop {
public:
    AgentLoop() = default;
    virtual ~AgentLoop() = default;

    // Deleted copy/assign, movable
    AgentLoop(const AgentLoop&) = delete;
    AgentLoop& operator=(const AgentLoop&) = delete;
    AgentLoop(AgentLoop&&) = default;
    AgentLoop& operator=(AgentLoop&&) = default;

    // Core lifecycle
    virtual bool initialize(const AgentConfig& config) = 0;
    virtual void shutdown() = 0;
    virtual bool isRunning() const = 0;

    // Task execution
    virtual bool submitTask(const std::string& task, const std::string& context = "") = 0;
    virtual bool cancelCurrentTask() = 0;
    virtual bool waitForCompletion(std::chrono::milliseconds timeout = std::chrono::seconds(30)) = 0;

    // State observation
    virtual AgentState getState() const = 0;
    std::string getLastError() const;
    
    // Event callbacks
    using TaskCallback = std::function<void(const std::string&, bool)>;
    void setTaskCallback(TaskCallback callback);
    
    // Configuration
    virtual void setConfig(const AgentConfig& config) = 0;
    virtual AgentConfig getConfig() const = 0;

protected:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shouldStop{false};
    std::mutex m_stateMutex;
    AgentState m_state;
    std::string m_lastError;
    std::function<void(const std::string&, bool)> m_taskCallback;
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD {

struct AgentConfig {
    std::string modelPath;
    std::string modelName;
    int maxContextLength = 4096;
    float temperature = 0.7f;
    float topP = 0.9f;
    int maxTokens = 2048;
    int numThreads = 4;
    bool useGpu = false;
    std::string deviceId = "0";
};

struct AgentState {
    enum Type {
        Idle,
        Thinking,
        Executing,
        Waiting,
        Error,
        Completed
    };
    
    Type current = Type::Idle;
    std::string currentTask;
    std::string currentStep;
    int progress = 0;
    std::string errorMessage;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point updatedAt;
};

class AgentLoop {
public:
    AgentLoop() = default;
    virtual ~AgentLoop() = default;

    // Deleted copy/assign, movable
    AgentLoop(const AgentLoop&) = delete;
    AgentLoop& operator=(const AgentLoop&) = delete;
    AgentLoop(AgentLoop&&) = default;
    AgentLoop& operator=(AgentLoop&&) = default;

    // Core lifecycle
    virtual bool initialize(const AgentConfig& config) = 0;
    virtual void shutdown() = 0;
    virtual bool isRunning() const = 0;

    // Task execution
    virtual bool submitTask(const std::string& task, const std::string& context = "") = 0;
    virtual bool cancelCurrentTask() = 0;
    virtual bool waitForCompletion(std::chrono::milliseconds timeout = std::chrono::seconds(30)) = 0;

    // State observation
    virtual struct AgentState getState() const = 0;
    std::string getLastError() const;
    
    // Event callbacks
    using TaskCallback = std::function<void(const std::string&, bool)>;
    void setTaskCallback(std::function<void(const std::string&, bool)> callback);
    
    // Configuration
    virtual void setConfig(const AgentConfig& config) = 0;
    virtual struct AgentConfig getConfig() const = 0;

protected:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shouldStop{false};
    std::mutex m_stateMutex;
    struct AgentState {
        std::string current = "Idle";
        std::string currentTask;
        std::string currentStep;
        int progress = 0;
        std::string errorMessage;
        std::chrono::system_clock::time_point startedAt;
        std::chrono::system_clock::time_point updatedAt;
    } m_state;
    std::string m_lastError;
    std::function<void(const std::string&, bool)> m_taskCallback;
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD {

struct AgentConfig {
    std::string modelPath;
    std::string modelName;
    int maxContextLength = 4096;
    float temperature = 0.7f;
    float topP = 0.9f;
    int maxTokens = 2048;
    int numThreads = 4;
    bool useGpu = false;
    std::string deviceId = "0";
};

struct AgentState {
    enum Type {
        Idle,
        Thinking,
        Executing,
        Waiting,
        Error,
        Completed
    };
    
    Type current = Type::Idle;
    std::string currentTask;
    std::string currentStep;
    int progress = 0;
    std::string errorMessage;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point updatedAt;
};

class AgentLoop {
public:
    AgentLoop() = default;
    virtual ~AgentLoop() = default;

    // Deleted copy/assign, movable
    AgentLoop(const AgentLoop&) = delete;
    AgentLoop& operator=(const AgentLoop&) = delete;
    AgentLoop(AgentLoop&&) = default;
    AgentLoop& operator=(AgentLoop&&) = default;

    // Core lifecycle
    virtual bool initialize(const AgentConfig& config) = 0;
    virtual void shutdown() = 0;
    virtual bool isRunning() const = 0;

    // Task execution
    virtual bool submitTask(const std::string& task, const std::string& context = "") = 0;
    virtual bool cancelCurrentTask() = 0;
    virtual bool waitForCompletion(std::chrono::milliseconds timeout = std::chrono::seconds(30)) = 0;

    // State observation
    virtual struct AgentState getState() const = 0;
    std::string getLastError() const;
    
    // Event callbacks
    using TaskCallback = std::function<void(const std::string&, bool)>;
    void setTaskCallback(std::function<void(const std::string&, bool)> callback);
    
    // Configuration
    virtual void setConfig(const AgentConfig& config) = 0;
    virtual struct AgentConfig getConfig() const = 0;

protected:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shouldStop{false};
    std::mutex m_stateMutex;
    struct AgentState {
        std::string current = "Idle";
        std::string currentTask;
        std::string currentStep;
        int progress = 0;
        std::string errorMessage;
        std::chrono::system_clock::time_point startedAt;
        std::chrono::system_clock::time_point updatedAt;
    } m_state;
    std::string m_lastError;
    std::function<void(const std::string&, bool)> m_taskCallback;
};

} // namespace RawrXD

#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD {

struct AgentConfig {
    std::string modelPath;
    std::string modelName;
    int maxContextLength = 4096;
    float temperature = 0.7f;
    float topP = 0.9f;
    int maxTokens = 2048;
    int numThreads = 4;
    bool useGpu = false;
    std::string deviceId = "0";
};

struct AgentState {
    enum Type {
        Idle,
        Thinking,
        Executing,
        Waiting,
        Error,
        Completed
    };
    
    Type current = Type::Idle;
    std::string currentTask;
    std::string currentStep;
    int progress = 0;
    std::string errorMessage;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point updatedAt;
};

class AgentLoop {
public:
    AgentLoop() = default;
    virtual ~AgentLoop() = default;

    // Deleted copy/assign, movable
    AgentLoop(const AgentLoop&) = delete;
    AgentLoop& operator=(const AgentLoop&) = delete;
    AgentLoop(AgentLoop&&) = default;
    AgentLoop& operator=(AgentLoop&&) = default;

    // Core lifecycle
    virtual bool initialize(const AgentConfig& config) = 0;
    virtual void shutdown() = 0;
    virtual bool isRunning() const = 0;

    // Task execution
    virtual bool submitTask(const std::string& task, const std::string& context = "") = 0;
    virtual bool cancelCurrentTask() = 0;
    virtual bool waitForCompletion(std::chrono::milliseconds timeout = std::chrono::seconds(30)) = 0;

    // State observation
    virtual struct AgentState getState() const = 0;
    std::string getLastError() const;
    
    // Event callbacks
    using TaskCallback = std::function<void(const std::string&, bool)>;
    void setTaskCallback(TaskCallback callback);
    
    // Configuration
    virtual void setConfig(const AgentConfig& config) = 0;
    virtual struct AgentConfig getConfig() const = 0;

protected:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shouldStop{false};
    std::mutex m_stateMutex;
    struct AgentState {
        std::string current = "Idle";
        std::string currentTask;
        std::string currentStep;
        int progress = 0;
        std::string errorMessage;
        std::chrono::system_clock::time_point startedAt;
        std::chrono::system_clock::time_point updatedAt;
    } m_state;
    std::string m_lastError;
    std::function<void(const std::string&, bool)> m_taskCallback;
};

} // namespace RawrXD