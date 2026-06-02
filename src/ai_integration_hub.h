#pragma once
#include <string>
#include <vector>
#include <memory>
#include "universal_model_router.h"
#include "backend_lane_type.h"

namespace RawrXD {

class BackendOrchestrator;

struct Completion {
    std::string text;
    float score;
    BackendLaneType sourceLane = BackendLaneType::Unknown;
};

class AIIntegrationHub {
    UniversalModelRouter m_router;
    std::shared_ptr<BackendOrchestrator> m_orchestrator;
    BackendLaneType m_activeLane = BackendLaneType::Unknown;

    static BackendLaneType laneFromMetadata(const std::string& metadata, BackendLaneType fallbackLane);

public:
    AIIntegrationHub();
    ~AIIntegrationHub();

    void setPreferredLane(BackendLaneType lane) { m_activeLane = lane; }
    BackendLaneType getActiveLane() const { return m_activeLane; }
    std::string getActiveLaneDescription() const { return BackendLaneTypeName(m_activeLane); }

    std::vector<Completion> getCompletions(const std::string& bufferName, const std::string& prefix, const std::string& suffix, int cursorOffset);
    
    // Additional features
    std::string generateTests(const std::string& code);
    std::string findBugs(const std::string& code);
    std::string optimizeCode(const std::string& code);
};

}
