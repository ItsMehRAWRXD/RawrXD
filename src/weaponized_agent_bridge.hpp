#pragma once
#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace RawrXD {

class WeaponizedAgentBridge {
public:
    struct MissionResult {
        bool success = false;
        std::string output;
        std::vector<std::string> filesCreated;
        std::string gitDiff;
        std::string error;
    };

    using StreamCallback = std::function<void(const std::string&)>;
    
    WeaponizedAgentBridge();
    ~WeaponizedAgentBridge();
    
    bool initialize(const std::string& agentScriptPath = "");
    void shutdown();
    MissionResult executeMission(const std::string& missionType, const std::string& missionParams = "");
    MissionResult executeCommand(const std::string& command);
    void setStreamCallback(StreamCallback cb);
    int64_t getRemainingTime() const;
    
private:
    std::string m_agentScriptPath;
    std::atomic<bool> m_initialized{false};
    std::atomic<int64_t> m_ttlMs{120000};
    std::atomic<int64_t> m_startTime{0};
    StreamCallback m_streamCallback;
    
    MissionResult executeNodeScript(const std::string& scriptPath, const std::string& args);
    static std::string detectAgentScriptPath();
    static std::string escapeCommand(const std::string& cmd);
};

} // namespace RawrXD
