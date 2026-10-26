#include "AgentProduct.hpp"
#include "AgentSession.hpp"

AgentRunResult AgentRunLoop(const std::string& prompt, int maxIter, int maxTokens,
                            void* ctx, std::string (*infer)(void*, const std::string&, int)) {
    AgentRunResult run;
    if (maxIter < 1) maxIter = 1;
    if (maxIter > 16) maxIter = 16;
    if (maxTokens < 1) maxTokens = 1;
    if (maxTokens > 8192) maxTokens = 8192;
    std::string current = prompt;
    if (!infer) { run.text = "infer_unavailable"; return run; }
    for (int i = 0; i < maxIter; ++i) {
        if (AgentSessionCancelled()) { run.text += "\ncancelled"; break; }
        ++run.iterations;
        run.text = infer(ctx, current, maxTokens);
        std::vector<AgentToolCall> calls;
        if (!AgentParseToolCalls(run.text, calls)) return run;
        std::vector<std::string> workers;
        std::string obs;
        for (auto& call : calls) {
            ++run.toolCalls;
            std::string id;
            obs += call.name + " " + AgentExecTool(call.name, call.arguments, &id) + "\n";
            if (!id.empty()) workers.push_back(id);
        }
        if (!workers.empty()) obs += AgentJoinWorkers(workers);
        run.toolLog += obs;
        current = prompt + "\ntool_results:\n" + obs;
    }
    return run;
}
