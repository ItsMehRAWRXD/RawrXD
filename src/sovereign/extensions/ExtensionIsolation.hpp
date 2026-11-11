// ============================================================================
// ExtensionIsolation.hpp - Extension Process Isolation & Sandbox
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct ExtensionIsolationConfig {
    bool enableProcessIsolation = true;
    bool enableMemoryLimit = true;
    size_t maxMemoryMB = 512;
    uint64_t maxCPUTimeMs = 30000;
    bool enableNetworkRestriction = true;
    std::vector<std::string> allowedDomains;
    bool enableFilesystemRestriction = true;
    std::vector<std::string> allowedPaths;
    bool enableCrashRecovery = true;
    uint32_t maxRestarts = 3;
};

class ExtensionIsolation {
public:
    ExtensionIsolation();
    ~ExtensionIsolation();

    bool Initialize(const ExtensionIsolationConfig& config);
    void Shutdown();

    bool LaunchExtension(const std::string& id, const std::string& executable);
    bool TerminateExtension(const std::string& id);
    bool IsExtensionAlive(const std::string& id) const;
    bool RestartExtension(const std::string& id);

    bool SendMessage(const std::string& id, const std::string& message);
    std::string ReceiveMessage(const std::string& id);

    void SetCrashHandler(std::function<void(const std::string&, int)> handler);
    void SetMessageHandler(std::function<void(const std::string&, const std::string&)> handler);

    struct IsolationStats {
        uint64_t totalExtensions;
        uint64_t activeExtensions;
        uint64_t crashedExtensions;
        uint64_t restarts;
        uint64_t messagesSent;
        uint64_t messagesReceived;
    };
    IsolationStats GetStats() const { return stats_; }

private:
    struct ExtensionProcess {
        std::string id;
        void* processHandle;
        void* stdinPipe;
        void* stdoutPipe;
        uint64_t startTime;
        int restartCount;
        bool alive;
    };
    std::unordered_map<std::string, ExtensionProcess> extensions_;
    ExtensionIsolationConfig config_;
    IsolationStats stats_;
    mutable std::mutex mutex_;
    
    std::function<void(const std::string&, int)> crashHandler_;
    std::function<void(const std::string&, const std::string&)> messageHandler_;
};

} // namespace Sovereign
