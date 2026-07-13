#include "learning/PolicyOptimizer.hpp"
#include "learning/ExperienceReplay.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static nlohmann::json currentPolicy;
static int optimizationSteps = 0;
static double averageReward = 0.0;

void PolicyOptimizer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        currentPolicy = {
            {"version", "1.0"},
            {"rules", nlohmann::json::array()}
        };
        optimizationSteps = 0;
        averageReward = 0.0;
        s_initialized = true;
    }
}

void PolicyOptimizer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Sample experiences and update policy
    auto samples = ExperienceReplay::SampleExperiences(32);
    for (const auto& exp : samples) {
        UpdatePolicy(exp);
    }
}

bool PolicyOptimizer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void PolicyOptimizer::UpdatePolicy(const nlohmann::json& experience) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    optimizationSteps++;
    
    // Simple policy update based on reward
    if (experience.contains("reward")) {
        double reward = experience["reward"].get<double>();
        averageReward = 0.99 * averageReward + 0.01 * reward;
        
        // Store successful actions in policy
        if (reward > 0 && experience.contains("action")) {
            currentPolicy["rules"].push_back({
                {"action", experience["action"]},
                {"context", experience.value("state", nlohmann::json{})},
                {"reward", reward}
            });
        }
    }
}

nlohmann::json PolicyOptimizer::GetPolicy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentPolicy;
}

nlohmann::json PolicyOptimizer::SelectAction(const nlohmann::json& state) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Simple action selection: find matching rule
    for (const auto& rule : currentPolicy["rules"]) {
        if (rule.contains("context") && rule["context"] == state) {
            return rule["action"];
        }
    }
    
    // Default: explore
    return {{"action", "explore"}, {"reason", "no_matching_policy"}};
}

nlohmann::json PolicyOptimizer::GetOptimizationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"optimization_steps", optimizationSteps},
        {"average_reward", averageReward},
        {"policy_rules", currentPolicy["rules"].size()}
    };
}
