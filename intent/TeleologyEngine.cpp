#include "intent/TeleologyEngine.hpp"
#include "intent/IntentModel.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;

void TeleologyEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_initialized = true;
    }
}

void TeleologyEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool TeleologyEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json TeleologyEngine::Analyze() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto intent = IntentModel::Get();
    std::string active_intent = intent.value("active_intent", "unknown");
    
    // Analyze purpose based on active intent
    std::string purpose = "maintain_system_integrity";
    if (active_intent == "optimize_resources") {
        purpose = "maximize_efficiency";
    } else if (active_intent == "preserve_identity") {
        purpose = "maintain_continuity";
    } else if (active_intent == "scale_system") {
        purpose = "expand_capabilities";
    }
    
    return {
        {"active_intent", active_intent},
        {"derived_purpose", purpose},
        {"teleological_coherence", 0.95},
        {"analyzed_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

nlohmann::json TeleologyEngine::AnalyzeIntent(const std::string& intent) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::string purpose = "unknown";
    std::vector<std::string> sub_goals;
    
    if (intent == "maintain_coherence") {
        purpose = "preserve_system_stability";
        sub_goals = {"monitor_drift", "enforce_invariants", "stabilize_patterns"};
    } else if (intent == "optimize_resources") {
        purpose = "maximize_efficiency";
        sub_goals = {"allocate_efficiently", "reduce_waste", "balance_load"};
    } else if (intent == "preserve_identity") {
        purpose = "maintain_self_continuity";
        sub_goals = {"validate_consistency", "track_evolution", "anchor_memory"};
    }
    
    return {
        {"intent", intent},
        {"purpose", purpose},
        {"sub_goals", sub_goals}
    };
}

nlohmann::json TeleologyEngine::GetPurposeChain(const std::string& intent) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json chain = nlohmann::json::array();
    
    // Build purpose chain from intent to root purpose
    chain.push_back({{"level", 0}, {"type", "intent"}, {"value", intent}});
    
    auto analysis = AnalyzeIntent(intent);
    chain.push_back({{"level", 1}, {"type", "purpose"}, {"value", analysis.value("purpose", "")}});
    
    // Root purpose
    chain.push_back({{"level", 2}, {"type", "root_purpose"}, {"value", "sovereign_integrity"}});
    
    return chain;
}

nlohmann::json TeleologyEngine::EvaluateGoalAlignment(const nlohmann::json& goals) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto intent = IntentModel::Get();
    std::string active = intent.value("active_intent", "");
    
    nlohmann::json aligned_goals = nlohmann::json::array();
    nlohmann::json misaligned_goals = nlohmann::json::array();
    
    for (const auto& goal : goals) {
        std::string goal_str = goal.get<std::string>();
        // Simple alignment check
        bool aligned = (goal_str.find(active) != std::string::npos) ||
                      (active.find(goal_str) != std::string::npos);
        if (aligned) {
            aligned_goals.push_back(goal_str);
        } else {
            misaligned_goals.push_back(goal_str);
        }
    }
    
    return {
        {"aligned", aligned_goals},
        {"misaligned", misaligned_goals},
        {"alignment_score", goals.empty() ? 1.0 : (double)aligned_goals.size() / goals.size()}
    };
}

nlohmann::json TeleologyEngine::GetGoalHierarchy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    return {
        {"root", "sovereign_integrity"},
        {"branches", {
            {"maintain_coherence", {"preserve_stability", "enforce_consistency"}},
            {"optimize_resources", {"maximize_efficiency", "minimize_waste"}},
            {"preserve_identity", {"maintain_continuity", "track_evolution"}}
        }}
    };
}

nlohmann::json TeleologyEngine::GetTeleologyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto analysis = Analyze();
    
    return {
        {"active_purpose", analysis.value("derived_purpose", "")},
        {"coherence_score", analysis.value("teleological_coherence", 0.0)},
        {"analysis_timestamp", analysis.value("analyzed_at", 0)}
    };
}
