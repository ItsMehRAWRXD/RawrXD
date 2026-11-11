#include "creativity/SolutionInnovator.hpp"
#include "creativity/IdeaGenerator.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_solutionHistory;
static size_t s_innovationCount = 0;

void SolutionInnovator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_solutionHistory.clear();
        s_innovationCount = 0;
        s_initialized = true;
    }
}

void SolutionInnovator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool SolutionInnovator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json SolutionInnovator::FindNovelSolution(const nlohmann::json& problem) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string problemType = problem.value("type", "general");
    
    // Generate ideas for this problem
    auto ideas = IdeaGenerator::GenerateIdeas(problemType, 3);
    
    // Select best idea based on novelty and utility
    nlohmann::json bestIdea;
    double bestScore = 0.0;
    
    for (const auto& idea : ideas) {
        double score = idea.value("novelty_score", 0.0) * 0.4 + 
                      idea.value("utility_score", 0.0) * 0.6;
        if (score > bestScore) {
            bestScore = score;
            bestIdea = idea;
        }
    }
    
    nlohmann::json solution = {
        {"id", "solution_" + std::to_string(s_solutionHistory.size())},
        {"problem", problem},
        {"approach", bestIdea},
        {"innovation_score", bestScore},
        {"created_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"status", "proposed"}
    };
    
    s_solutionHistory.push_back(solution);
    s_innovationCount++;
    
    return solution;
}

nlohmann::json SolutionInnovator::AdaptSolution(const nlohmann::json& solution, const nlohmann::json& newContext) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json adapted = solution;
    adapted["id"] = "solution_" + std::to_string(s_solutionHistory.size());
    adapted["parent"] = solution.value("id", "");
    adapted["context"] = newContext;
    adapted["adapted_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    adapted["adaptation_score"] = 0.8; // Placeholder
    
    s_solutionHistory.push_back(adapted);
    return adapted;
}

nlohmann::json SolutionInnovator::SynthesizeSolution(const std::vector<nlohmann::json>& partialSolutions) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json synthesized = {
        {"id", "solution_" + std::to_string(s_solutionHistory.size())},
        {"type", "synthesized"},
        {"components", nlohmann::json::array()},
        {"created_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    double totalScore = 0.0;
    for (const auto& partial : partialSolutions) {
        synthesized["components"].push_back(partial.value("id", ""));
        totalScore += partial.value("innovation_score", 0.0);
    }
    
    synthesized["innovation_score"] = partialSolutions.empty() ? 0.0 : 
                                       totalScore / partialSolutions.size();
    
    s_solutionHistory.push_back(synthesized);
    s_innovationCount++;
    return synthesized;
}

nlohmann::json SolutionInnovator::GetInnovationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    double totalScore = 0.0;
    for (const auto& sol : s_solutionHistory) {
        totalScore += sol.value("innovation_score", 0.0);
    }
    
    size_t count = s_solutionHistory.size();
    return {
        {"total_solutions", count},
        {"total_innovations", s_innovationCount},
        {"avg_innovation_score", count > 0 ? totalScore / count : 0.0},
        {"innovation_rate", s_innovationCount / 3600.0}
    };
}

nlohmann::json SolutionInnovator::GetSolutionHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_solutionHistory;
}
