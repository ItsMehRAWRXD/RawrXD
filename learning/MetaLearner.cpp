#include "learning/MetaLearner.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;
static nlohmann::json learningStrategy;
static int tasksLearned = 0;
static double adaptationRate = 0.1;

void MetaLearner::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        learningStrategy = {
            {"learning_rate", 0.01},
            {"exploration_rate", 0.1},
            {"batch_size", 32},
            {"adaptation_enabled", true}
        };
        tasksLearned = 0;
        adaptationRate = 0.1;
        s_initialized = true;
    }
}

void MetaLearner::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic strategy adaptation
}

bool MetaLearner::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void MetaLearner::LearnToLearn(const nlohmann::json& task) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    tasksLearned++;
    
    // Adapt strategy based on task type
    if (task.contains("type")) {
        std::string type = task["type"].get<std::string>();
        if (type == "fast") {
            learningStrategy["learning_rate"] = 0.05;
        } else if (type == "stable") {
            learningStrategy["learning_rate"] = 0.005;
        }
    }
}

nlohmann::json MetaLearner::GetLearningStrategy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return learningStrategy;
}

nlohmann::json MetaLearner::AdaptStrategy(const nlohmann::json& performance) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Adapt based on performance
    if (performance.contains("accuracy")) {
        double accuracy = performance["accuracy"].get<double>();
        if (accuracy < 0.5) {
            // Increase exploration
            learningStrategy["exploration_rate"] = 
                std::min(0.5, learningStrategy["exploration_rate"].get<double>() * 1.1);
        } else if (accuracy > 0.9) {
            // Decrease exploration, exploit more
            learningStrategy["exploration_rate"] = 
                std::max(0.01, learningStrategy["exploration_rate"].get<double>() * 0.9);
        }
    }
    
    return learningStrategy;
}

nlohmann::json MetaLearner::GetMetaMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"tasks_learned", tasksLearned},
        {"adaptation_rate", adaptationRate},
        {"current_strategy", learningStrategy}
    };
}
