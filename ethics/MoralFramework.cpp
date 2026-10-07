#include "ethics/MoralFramework.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<MoralFramework::Principle> s_activePrinciples;
static std::map<MoralFramework::Principle, double> s_principleWeights;
static size_t s_evaluationCount = 0;

void MoralFramework::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        // Default principles
        s_activePrinciples = {
            Principle::UTILITARIANISM,
            Principle::DEONTOLOGY,
            Principle::JUSTICE,
            Principle::AUTONOMY
        };
        
        // Equal weights by default
        for (auto p : s_activePrinciples) {
            s_principleWeights[p] = 1.0 / s_activePrinciples.size();
        }
        
        s_evaluationCount = 0;
        s_initialized = true;
    }
}

void MoralFramework::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool MoralFramework::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json MoralFramework::EvaluateAction(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json evaluation;
    evaluation["action"] = action;
    evaluation["evaluated_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    double totalScore = 0.0;
    nlohmann::json principleScores = nlohmann::json::object();
    
    for (auto principle : s_activePrinciples) {
        double score = CalculateMoralScore(action, principle);
        principleScores[std::to_string(static_cast<int>(principle))] = score;
        totalScore += score * s_principleWeights[principle];
    }
    
    evaluation["principle_scores"] = principleScores;
    evaluation["weighted_score"] = totalScore;
    evaluation["is_permissible"] = totalScore > 0.5;
    
    s_evaluationCount++;
    return evaluation;
}

nlohmann::json MoralFramework::EvaluateOutcome(const nlohmann::json& outcome) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Evaluate outcome based on utilitarian principles
    double utility = outcome.value("utility", 0.0);
    double harm = outcome.value("harm", 0.0);
    int affectedCount = outcome.value("affected_count", 1);
    
    double netUtility = (utility - harm) / affectedCount;
    
    return {
        {"outcome", outcome},
        {"net_utility", netUtility},
        {"is_beneficial", netUtility > 0},
        {"evaluated_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

double MoralFramework::CalculateMoralScore(const nlohmann::json& action, Principle principle) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    switch (principle) {
        case Principle::UTILITARIANISM:
            // Score based on expected utility
            return action.value("expected_utility", 0.5);
            
        case Principle::DEONTOLOGY:
            // Score based on rule compliance
            return action.value("rule_compliant", true) ? 1.0 : 0.0;
            
        case Principle::VIRTUE_ETHICS:
            // Score based on virtuousness
            return action.value("virtuous", 0.5);
            
        case Principle::CARE_ETHICS:
            // Score based on care for relationships
            return action.value("cares_for_others", 0.5);
            
        case Principle::JUSTICE:
            // Score based on fairness
            return action.value("fair", 0.5);
            
        case Principle::AUTONOMY:
            // Score based on respect for autonomy
            return action.value("respects_autonomy", 0.5);
            
        default:
            return 0.5;
    }
}

void MoralFramework::SetActivePrinciples(const std::vector<Principle>& principles) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_activePrinciples = principles;
    
    // Rebalance weights
    double weight = 1.0 / principles.size();
    s_principleWeights.clear();
    for (auto p : principles) {
        s_principleWeights[p] = weight;
    }
}

nlohmann::json MoralFramework::GetActivePrinciples() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    
    for (auto principle : s_activePrinciples) {
        nlohmann::json p;
        p["id"] = static_cast<int>(principle);
        p["weight"] = s_principleWeights[principle];
        result.push_back(p);
    }
    
    return result;
}

nlohmann::json MoralFramework::GetFrameworkMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"active_principles", s_activePrinciples.size()},
        {"evaluations", s_evaluationCount},
        {"principles_configured", s_principleWeights.size()}
    };
}
