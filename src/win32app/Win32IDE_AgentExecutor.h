#pragma once

#include <string>
#include <vector>
#include <memory>
#include "Win32IDE_AgentExecutionFSM.h"

class GGUFLoader;
class Win32IDE;
class AgenticBridge;

// Product agent task entry. Never invents success — dispatches real Bridge/Loop.
class Win32IDE_AgentExecutor {
private:
    std::unique_ptr<GGUFLoader> loader_;
    bool initialized_ = false;
    Win32IDE* ide_ = nullptr;
    AgenticBridge* bridge_ = nullptr;

public:
    Win32IDE_AgentExecutor();
    ~Win32IDE_AgentExecutor();

    void Bind(Win32IDE* ide, AgenticBridge* bridge);
    bool Initialize();
    // taskName: "ask" | "loop" | "autonomous" | "tool" | "plan"
    // Returns false on missing bind, unknown task, or dispatch failure.
    bool ExecuteAgentTask(const std::string& taskName,
                          const std::vector<std::string>& params);
    bool LoadModel(const std::string& modelPath);
    void Cleanup();

    RawrXD::AgentExecState GetState() const {
        return RawrXD::ProductAgentFSM().state();
    }
};
