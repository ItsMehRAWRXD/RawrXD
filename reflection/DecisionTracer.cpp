#include "reflection/DecisionTracer.hpp"
#include <mutex>
#include <vector>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> decisionHistory;
static int decisionCounter = 0;

void DecisionTracer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        decisionHistory.clear();
        decisionCounter = 0;
        s_initialized = true;
    }
}

void DecisionTracer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool DecisionTracer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void DecisionTracer::TraceDecision(const nlohmann::json& decision) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    nlohmann::json trace = decision;
    trace["id"] = "decision_" + std::to_string(++decisionCounter);
    trace["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    decisionHistory.push_back(trace);
    
    // Limit history size
    if (decisionHistory.size() > 1000) {
        decisionHistory.erase(decisionHistory.begin());
    }
}

nlohmann::json DecisionTracer::GetDecisionTrace(const std::string& decisionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    for (const auto& decision : decisionHistory) {
        if (decision.value("id", "") == decisionId) {
            return decision;
        }
    }
    return nlohmann::json{};
}

nlohmann::json DecisionTracer::GetDecisionHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return decisionHistory;
}

nlohmann::json DecisionTracer::AnalyzeDecisionPatterns() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json patterns = {
        {"total_decisions", decisionHistory.size()},
        {"decision_types", nlohmann::json::object()},
        {"average_decision_time_ms", 0.0}
    };
    
    // Count decision types
    for (const auto& decision : decisionHistory) {
        std::string type = decision.value("type", "unknown");
        patterns["decision_types"][type] = patterns["decision_types"].value(type, 0).get<int>() + 1;
    }
    
    return patterns;
}

nlohmann::json DecisionTracer::GetDecisionMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"total_decisions", decisionHistory.size()},
        {"decision_counter", decisionCounter},
        {"recent_decisions", decisionHistory.size() > 10 ? 
            nlohmann::json(decisionHistory.end() - 10, decisionHistory.end()) :
            decisionHistory}
    };
}
