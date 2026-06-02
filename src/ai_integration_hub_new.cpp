#include "ai_integration_hub.h"
#include "ai_model_caller.h" // ModelCaller
#include "BackendOrchestrator.h"

#include <condition_variable>
#include <iostream>
#include <mutex>

namespace RawrXD {

BackendLaneType AIIntegrationHub::laneFromMetadata(const std::string& metadata, BackendLaneType fallbackLane)
{
    if (metadata.find("\"backend_lane_code\":1") != std::string::npos)
    {
        return BackendLaneType::TitanHost;
    }
    if (metadata.find("\"backend_lane_code\":2") != std::string::npos)
    {
        return BackendLaneType::NativeDll;
    }
    if (metadata.find("\"backend_lane_code\":3") != std::string::npos)
    {
        return BackendLaneType::StandaloneExe;
    }

    if (metadata.find("\"backend\":\"standalone_exe\"") != std::string::npos)
    {
        return BackendLaneType::StandaloneExe;
    }
    if (metadata.find("\"backend\":\"titan_host\"") != std::string::npos)
    {
        return BackendLaneType::TitanHost;
    }
    if (metadata.find("\"backend\":\"native_dll\"") != std::string::npos)
    {
        return BackendLaneType::NativeDll;
    }
    return fallbackLane;
}

AIIntegrationHub::AIIntegrationHub()
{
    // Non-owning shared_ptr wrapper over singleton orchestrator.
    m_orchestrator = std::shared_ptr<BackendOrchestrator>(&BackendOrchestrator::Instance(),
                                                           [](BackendOrchestrator*) {});
    if (m_orchestrator && !m_orchestrator->IsInitialized())
    {
        m_orchestrator->Initialize();
    }
    if (m_orchestrator)
    {
        m_activeLane = (m_orchestrator->GetActiveBackend() == BackendKind::Titan) ? BackendLaneType::TitanHost
                                                                                   : BackendLaneType::NativeDll;
    }
}
AIIntegrationHub::~AIIntegrationHub() {}

std::vector<Completion> AIIntegrationHub::getCompletions(const std::string& bufferName, const std::string& prefix, const std::string& suffix, int cursorOffset) {
    (void)cursorOffset;

    std::cout << "[AIIntegrationHub] Dispatching completion request. lane="
              << BackendLaneTypeName(m_activeLane) << std::endl;

    std::vector<Completion> results;

    if (m_orchestrator && m_orchestrator->IsInitialized())
    {
        std::string prompt = "<|fim_prefix|>" + prefix + "<|fim_suffix|>" + suffix + "<|fim_middle|>";

        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        std::string completionPayload;
        std::string metadata;

        InferRequest req{};
        req.prompt = prompt;
        req.tenant_id = bufferName;
        req.max_tokens = 64;
        req.priority = RequestPriority::Normal;
        if (m_activeLane == BackendLaneType::TitanHost)
        {
            req.preferred_backend = BackendKind::Titan;
        }
        req.complete_cb = [&](const std::string& completion, const std::string& meta)
        {
            std::lock_guard<std::mutex> lock(mtx);
            completionPayload = completion;
            metadata = meta;
            done = true;
            cv.notify_one();
        };

        m_orchestrator->Enqueue(std::move(req));

        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait_for(lock, std::chrono::milliseconds(30000), [&]() { return done; });
        }

        if (done && !completionPayload.empty())
        {
            BackendLaneType fallbackLane =
                (m_orchestrator->GetActiveBackend() == BackendKind::Titan) ? BackendLaneType::TitanHost
                                                                            : BackendLaneType::NativeDll;
            const BackendLaneType usedLane = laneFromMetadata(metadata, fallbackLane);
            m_activeLane = usedLane;

            results.push_back({completionPayload, 1.0f, usedLane});
            return results;
        }
    }

    // Fallback for early startup or orchestrator failures.
    std::string fileType = "cpp";
    std::string context = bufferName;
    auto callerCompletions = ::ModelCaller::generateCompletion(prefix, suffix, fileType, context, 1);
    for (const auto& c : callerCompletions)
    {
        results.push_back({c.text, c.score, m_activeLane});
    }

    return results;
}

std::string AIIntegrationHub::generateTests(const std::string& code) {
    return ::ModelCaller::generateCode("Generate unit tests for this code", "cpp", code);
}

std::string AIIntegrationHub::findBugs(const std::string& code) {
    // ModelCaller doesn't have explicit findBugs, reuse generateCode
    return ::ModelCaller::generateCode("Analyze for bugs and security issues", "cpp", code);
}

std::string AIIntegrationHub::optimizeCode(const std::string& code) {
    return ::ModelCaller::generateRewrite(code, "Optimize this code for performance", "cpp");
}

}
