#pragma once
#include <string>
#include <vector>

struct AgentToolCall {
    std::string name;
    std::string arguments;
    std::string workerId;
};

struct AgentRunResult {
    std::string text;
    std::string toolLog;
    int iterations = 0;
    int toolCalls = 0;
};

bool AgentParseToolCalls(const std::string& text, std::vector<AgentToolCall>& out);
std::vector<std::string> AgentToolNames();
std::string AgentExecTool(const std::string& name, const std::string& arguments,
                          std::string* workerId);
void AgentBindManager(void* manager);
void AgentBindWorker(void* ctx,
                     std::string (*spawn)(void*, const char*, const char*),
                     bool (*wait)(void*, const char*, int),
                     std::string (*result)(void*, const char*),
                     const char* (*state)(void*, const char*));
std::string AgentSpawnWorker(const std::string& arguments, std::string* workerId);
std::string AgentJoinWorkers(const std::vector<std::string>& ids);
std::string AgentRunCommand(const std::string& name, const std::string& arguments);
AgentRunResult AgentRunLoop(const std::string& prompt, int maxIter, int maxTokens,
                            void* ctx, std::string (*infer)(void*, const std::string&, int));
/* Shared production /api/agent/run body (GUI LocalServer + local headless). */
int AgentHttpRun(const std::string& body, bool modelReady, void* subAgentMgr,
                 std::string* outJson);
