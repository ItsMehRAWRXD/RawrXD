#include "communication/ExplanationGenerator.hpp"
#include "reflection/DecisionTracer.hpp"
#include "reflection/BeliefAnalyzer.hpp"
#include "prediction/RiskAssessor.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> explanationHistory;

void ExplanationGenerator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        explanationHistory.clear();
        s_initialized = true;
    }
}

void ExplanationGenerator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool ExplanationGenerator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

std::string ExplanationGenerator::ExplainDecision(const std::string& decisionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    auto decision = DecisionTracer::GetDecisionTrace(decisionId);
    if (decision.empty()) {
        return "Decision '" + decisionId + "' not found in history.";
    }
    
    std::string explanation = "I made this decision because ";
    
    if (decision.contains("reasoning")) {
        explanation += decision["reasoning"].get<std::string>();
    } else if (decision.contains("type")) {
        explanation += "it was a " + decision["type"].get<std::string>() + " decision";
    } else {
        explanation += "it aligned with my current goals and values";
    }
    
    // Store explanation
    explanationHistory.push_back({
        {"type", "decision"},
        {"id", decisionId},
        {"explanation", explanation}
    });
    
    if (explanationHistory.size() > 100) {
        explanationHistory.erase(explanationHistory.begin());
    }
    
    return explanation;
}

std::string ExplanationGenerator::ExplainBelief(const std::string& belief) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    auto confidence = BeliefAnalyzer::GetBeliefConfidence(belief);
    double conf = confidence.value("confidence", 0.0);
    
    std::string explanation = "I believe " + belief + " with ";
    explanation += std::to_string(static_cast<int>(conf * 100)) + "% confidence. ";
    
    if (conf > 0.8) {
        explanation += "This is a well-established belief based on consistent evidence.";
    } else if (conf > 0.5) {
        explanation += "This belief is supported by moderate evidence.";
    } else {
        explanation += "This belief is tentative and requires more evidence.";
    }
    
    return explanation;
}

std::string ExplanationGenerator::ExplainAction(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string actionName = action.value("action", "this action");
    std::string explanation = "I am taking " + actionName + " ";
    
    // Assess risk
    auto risk = RiskAssessor::AssessRisk(action);
    if (risk.value("acceptable", true)) {
        explanation += "because it is within acceptable risk parameters ";
    } else {
        explanation += "despite elevated risk ";
    }
    
    explanation += "and aligns with my current intent.";
    
    return explanation;
}

std::string ExplanationGenerator::GenerateContextualExplanation(const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string explanation = "Based on the current context: ";
    
    if (context.contains("situation")) {
        explanation += context["situation"].get<std::string>() + ". ";
    }
    
    if (context.contains("urgency")) {
        std::string urgency = context["urgency"].get<std::string>();
        if (urgency == "high") {
            explanation += "This requires immediate attention. ";
        } else if (urgency == "low") {
            explanation += "This can be addressed at a normal pace. ";
        }
    }
    
    explanation += "My recommended approach is to proceed with caution while monitoring outcomes.";
    
    return explanation;
}

nlohmann::json ExplanationGenerator::GetExplanationHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return explanationHistory;
}
