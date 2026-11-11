#pragma once
// AutonomousAgenticPipelineCoordinator — Stub header for compilation
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {

class AutonomousAgenticPipelineCoordinator {
public:
    using BuildPromptFn = std::function<std::string(const std::string&)>;
    using RouteLLMFn = std::function<std::string(const std::string&)>;
    using OnTokenFn = std::function<void(const std::string&, bool)>;
    using AppendRendererFn = std::function<void(const std::string&)>;
    using DequeueTaskFn = std::function<bool(std::wstring*, int*)>;

    AutonomousAgenticPipelineCoordinator() = default;
    ~AutonomousAgenticPipelineCoordinator() = default;

    void setBuildPrompt(BuildPromptFn fn) { m_buildPrompt = fn; }
    void setRouteLLM(RouteLLMFn fn) { m_routeLLM = fn; }
    void setOnToken(OnTokenFn fn) { m_onToken = fn; }
    void setAppendRenderer(AppendRendererFn fn) { m_appendRenderer = fn; }
    void setExternalAgentCoordinator(void* coord) { m_agentCoordinator = coord; }
    void setDequeueTaskFn(DequeueTaskFn fn) { m_dequeueTask = fn; }
    void setContextWindowSize(int size) { m_contextWindowSize = size; }

private:
    BuildPromptFn m_buildPrompt;
    RouteLLMFn m_routeLLM;
    OnTokenFn m_onToken;
    AppendRendererFn m_appendRenderer;
    DequeueTaskFn m_dequeueTask;
    void* m_agentCoordinator = nullptr;
    int m_contextWindowSize = 8192;
};

} // namespace RawrXD
