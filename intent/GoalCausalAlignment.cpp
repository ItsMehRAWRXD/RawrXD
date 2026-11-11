#include "intent/GoalCausalAlignment.hpp"
#include "intent/IntentModel.hpp"
#include "causal/CausalGraph.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;
static double currentAlignmentScore = 1.0;

void GoalCausalAlignment::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
    currentAlignmentScore = 1.0;
}

void GoalCausalAlignment::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Recalculate alignment score
    auto intent = IntentModel::GetCurrentIntent();
    auto identity = IdentityCore::Get();
    
    if (!intent.value("goal", "").empty()) {
        // Check if intent aligns with identity values
        bool aligned = true;
        currentAlignmentScore = aligned ? 1.0 : 0.5;
    }
}

bool GoalCausalAlignment::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json GoalCausalAlignment::CheckAlignment() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto intent = IntentModel::GetCurrentIntent();
    auto identity = IdentityCore::Get();
    
    nlohmann::json result = {
        {"intent_goal", intent.value("goal", "")},
        {"identity_version", identity.value("version", "")},
        {"alignment_score", currentAlignmentScore},
        {"aligned", currentAlignmentScore > 0.7}
    };
    
    return result;
}

double GoalCausalAlignment::GetAlignmentScore() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentAlignmentScore;
}

nlohmann::json GoalCausalAlignment::GetMisalignments() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json misalignments = nlohmann::json::array();
    
    if (currentAlignmentScore < 0.7) {
        misalignments.push_back({
            {"type", "intent_identity_mismatch"},
            {"severity", "medium"},
            {"score", currentAlignmentScore}
        });
    }
    
    return misalignments;
}

void GoalCausalAlignment::Realign() {
    std::lock_guard<std::mutex> lock(s_mutex);
    currentAlignmentScore = std::min(1.0, currentAlignmentScore + 0.2);
}

nlohmann::json GoalCausalAlignment::GenerateCorrectionPlan() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json plan = {
        {"steps", nlohmann::json::array()},
        {"estimated_success", currentAlignmentScore}
    };
    
    if (currentAlignmentScore < 0.7) {
        plan["steps"].push_back("review_identity_values");
        plan["steps"].push_back("adjust_intent_parameters");
        plan["steps"].push_back("validate_alignment");
    }
    
    return plan;
}
