#pragma once

#include <string>
#include <vector>
#include <memory>

// Forward declaration
class GGUFLoader;

class Win32IDE_AgentExecutor {
private:
    std::unique_ptr<GGUFLoader> loader_;
    bool initialized_;
    
public:
    Win32IDE_AgentExecutor();
    ~Win32IDE_AgentExecutor();
    
    bool Initialize();
    bool ExecuteAgentTask(const std::string& taskName, const std::vector<std::string>& params);
    bool LoadModel(const std::string& modelPath);
    void Cleanup();
};
