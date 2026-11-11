// pipeline.cpp — Task Pipeline (Composite Workflows)
#include "task_runner.hpp"
#include <algorithm>

namespace RawrXD {
namespace Tasks {

// ============================================================================
// Pipeline Stage
// ============================================================================
struct PipelineStage {
    std::string name;
    std::vector<std::string> taskLabels;  // Tasks to run in parallel
    bool continueOnError = false;
    int maxRetries = 0;
};

// ============================================================================
// Pipeline Definition
// ============================================================================
struct PipelineDefinition {
    std::string name;
    std::string description;
    std::vector<PipelineStage> stages;
    bool stopOnFailure = true;
    bool parallelStages = false;
};

// ============================================================================
// Pipeline Runner
// ============================================================================
class PipelineRunner {
public:
    static PipelineRunner& Get();

    // Define a pipeline
    void DefinePipeline(const PipelineDefinition& pipeline);

    // Run a pipeline
    bool RunPipeline(const std::string& name);

    // Get pipeline status
    struct PipelineStatus {
        std::string name;
        bool running = false;
        bool succeeded = false;
        int currentStage = 0;
        int totalStages = 0;
        std::vector<std::string> completedTasks;
        std::vector<std::string> failedTasks;
    };
    PipelineStatus GetStatus(const std::string& name) const;

    // Cancel pipeline
    bool CancelPipeline(const std::string& name);

    // List defined pipelines
    std::vector<PipelineDefinition> ListPipelines() const;

    // Events
    using PipelineEventCallback = std::function<void(const std::string& name, const std::string& stage)>;
    void OnStageStarted(PipelineEventCallback callback) { m_onStageStarted = callback; }
    void OnStageCompleted(PipelineEventCallback callback) { m_onStageCompleted = callback; }
    void OnPipelineCompleted(std::function<void(const std::string& name, bool success)> callback) {
        m_onPipelineCompleted = callback;
    }

private:
    PipelineRunner() = default;
    void ExecuteStage(const PipelineDefinition& pipeline, size_t stageIndex);

    std::map<std::string, PipelineDefinition> m_pipelines;
    std::map<std::string, PipelineStatus> m_statuses;
    std::atomic<bool> m_cancelled{false};

    PipelineEventCallback m_onStageStarted;
    PipelineEventCallback m_onStageCompleted;
    std::function<void(const std::string&, bool)> m_onPipelineCompleted;
    mutable std::mutex m_mutex;
};

PipelineRunner& PipelineRunner::Get() {
    static PipelineRunner instance;
    return instance;
}

void PipelineRunner::DefinePipeline(const PipelineDefinition& pipeline) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pipelines[pipeline.name] = pipeline;
}

bool PipelineRunner::RunPipeline(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_pipelines.find(name);
    if (it == m_pipelines.end()) return false;

    m_cancelled = false;
    PipelineStatus status;
    status.name = name;
    status.running = true;
    status.totalStages = static_cast<int>(it->second.stages.size());
    m_statuses[name] = status;

    // Run pipeline in background
    std::thread([this, name]() {
        auto it = m_pipelines.find(name);
        if (it == m_pipelines.end()) return;

        bool success = true;
        for (size_t i = 0; i < it->second.stages.size() && !m_cancelled; i++) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_statuses[name].currentStage = static_cast<int>(i);
            }

            if (m_onStageStarted) m_onStageStarted(name, it->second.stages[i].name);

            // Execute tasks in this stage
            bool stageSuccess = true;
            for (const auto& taskLabel : it->second.stages[i].taskLabels) {
                if (m_cancelled) break;

                auto& runner = TaskRunner();
                auto* result = runner.RunTask(taskLabel);

                // Wait for completion (polling)
                while (result && result->state == TaskState::Running) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    result = runner.GetResult(result->taskId);
                }

                if (result && result->state == TaskState::Succeeded) {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_statuses[name].completedTasks.push_back(taskLabel);
                } else {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_statuses[name].failedTasks.push_back(taskLabel);
                    stageSuccess = false;
                }
            }

            if (m_onStageCompleted) m_onStageCompleted(name, it->second.stages[i].name);

            if (!stageSuccess && it->second.stopOnFailure) {
                success = false;
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_statuses[name].running = false;
            m_statuses[name].succeeded = success;
        }

        if (m_onPipelineCompleted) m_onPipelineCompleted(name, success);
    }).detach();

    return true;
}

PipelineRunner::PipelineStatus PipelineRunner::GetStatus(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_statuses.find(name);
    return it != m_statuses.end() ? it->second : PipelineStatus{};
}

bool PipelineRunner::CancelPipeline(const std::string& name) {
    m_cancelled = true;
    return true;
}

std::vector<PipelineDefinition> PipelineRunner::ListPipelines() const {
    std::vector<PipelineDefinition> pipelines;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [name, pipeline] : m_pipelines) {
        pipelines.push_back(pipeline);
    }
    return pipelines;
}

} // namespace Tasks
} // namespace RawrXD
