#include "creativity/IdeaGenerator.hpp"
#include <mutex>
#include <random>
#include <sstream>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_ideaHistory;
static std::mt19937 s_rng;

void IdeaGenerator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_ideaHistory.clear();
        s_rng.seed(std::random_device{}());
        s_initialized = true;
    }
}

void IdeaGenerator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic idea generation based on current context
    // In a real implementation, this would use learned patterns
}

bool IdeaGenerator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json IdeaGenerator::GenerateIdeas(const std::string& topic, int count) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json::array();
    
    nlohmann::json ideas = nlohmann::json::array();
    
    std::vector<std::string> approaches = {
        "combination", "mutation", "analogy", "inversion", "abstraction"
    };
    
    for (int i = 0; i < count; ++i) {
        std::uniform_int_distribution<int> dist(0, approaches.size() - 1);
        std::string approach = approaches[dist(s_rng)];
        
        nlohmann::json idea = {
            {"id", "idea_" + std::to_string(s_ideaHistory.size() + i)},
            {"topic", topic},
            {"approach", approach},
            {"generated_at", std::chrono::system_clock::now().time_since_epoch().count()},
            {"novelty_score", 0.5 + (s_rng() % 50) / 100.0},
            {"utility_score", 0.5 + (s_rng() % 50) / 100.0}
        };
        
        ideas.push_back(idea);
        s_ideaHistory.push_back(idea);
    }
    
    // Keep history bounded
    if (s_ideaHistory.size() > 1000) {
        s_ideaHistory.erase(s_ideaHistory.begin(), s_ideaHistory.begin() + 100);
    }
    
    return ideas;
}

nlohmann::json IdeaGenerator::CombineIdeas(const nlohmann::json& ideaA, const nlohmann::json& ideaB) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json combined = {
        {"id", "idea_" + std::to_string(s_ideaHistory.size())},
        {"type", "combined"},
        {"sources", {ideaA.value("id", ""), ideaB.value("id", "")}},
        {"generated_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"novelty_score", 0.7 + (s_rng() % 30) / 100.0},
        {"utility_score", (ideaA.value("utility_score", 0.5) + ideaB.value("utility_score", 0.5)) / 2.0}
    };
    
    s_ideaHistory.push_back(combined);
    return combined;
}

nlohmann::json IdeaGenerator::MutateIdea(const nlohmann::json& idea) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double novelty = idea.value("novelty_score", 0.5);
    double mutationFactor = 0.1 + (s_rng() % 20) / 100.0;
    
    nlohmann::json mutated = idea;
    mutated["id"] = "idea_" + std::to_string(s_ideaHistory.size());
    mutated["type"] = "mutated";
    mutated["parent"] = idea.value("id", "");
    mutated["novelty_score"] = std::min(1.0, novelty + mutationFactor);
    mutated["generated_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    s_ideaHistory.push_back(mutated);
    return mutated;
}

double IdeaGenerator::EvaluateNovelty(const nlohmann::json& idea) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    // Compare against idea history
    double maxSimilarity = 0.0;
    std::string ideaStr = idea.dump();
    
    for (const auto& historical : s_ideaHistory) {
        // Simple string similarity
        std::string histStr = historical.dump();
        size_t common = 0;
        for (size_t i = 0; i < std::min(ideaStr.size(), histStr.size()); ++i) {
            if (ideaStr[i] == histStr[i]) common++;
        }
        double similarity = static_cast<double>(common) / std::max(ideaStr.size(), histStr.size());
        maxSimilarity = std::max(maxSimilarity, similarity);
    }
    
    return 1.0 - maxSimilarity; // Novelty is inverse of similarity
}

double IdeaGenerator::EvaluateUtility(const nlohmann::json& idea) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    // Simple utility heuristic based on approach type
    std::string approach = idea.value("approach", "");
    if (approach == "combination") return 0.8;
    if (approach == "mutation") return 0.7;
    if (approach == "analogy") return 0.75;
    if (approach == "inversion") return 0.6;
    if (approach == "abstraction") return 0.85;
    return 0.5;
}

nlohmann::json IdeaGenerator::GetIdeaMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    double totalNovelty = 0.0;
    double totalUtility = 0.0;
    
    for (const auto& idea : s_ideaHistory) {
        totalNovelty += idea.value("novelty_score", 0.0);
        totalUtility += idea.value("utility_score", 0.0);
    }
    
    size_t count = s_ideaHistory.size();
    return {
        {"total_ideas", count},
        {"avg_novelty", count > 0 ? totalNovelty / count : 0.0},
        {"avg_utility", count > 0 ? totalUtility / count : 0.0},
        {"generation_rate", count / 3600.0} // Ideas per hour (assuming tick is ~1s)
    };
}
