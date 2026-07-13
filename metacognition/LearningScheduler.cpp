#include "metacognition/LearningScheduler.hpp"
#include <mutex>
#include <queue>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_learningQueue;
static size_t s_completedCount = 0;

void LearningScheduler::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_learningQueue.clear();
        s_completedCount = 0;
        s_initialized = true;
    }
}

void LearningScheduler::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Process highest priority learning tasks
    std::string highestPriorityTopic;
    int highestPriority = -1;
    
    for (auto& [topic, task] : s_learningQueue) {
        if (task.value("status", "") == "pending") {
            int priority = task.value("priority", 0);
            if (priority > highestPriority) {
                highestPriority = priority;
                highestPriorityTopic = topic;
            }
        }
    }
    
    if (!highestPriorityTopic.empty()) {
        s_learningQueue[highestPriorityTopic]["status"] = "in_progress";
        // In a real implementation, this would trigger actual learning
        s_learningQueue[highestPriorityTopic]["status"] = "completed";
        s_learningQueue[highestPriorityTopic]["completed_at"] = 
            std::chrono::system_clock::now().time_since_epoch().count();
        s_completedCount++;
    }
}

bool LearningScheduler::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void LearningScheduler::ScheduleLearning(const std::string& topic, int priority) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_learningQueue[topic] = {
        {"topic", topic},
        {"priority", priority},
        {"status", "pending"},
        {"scheduled_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

void LearningScheduler::PrioritizeLearning(const std::vector<std::string>& topics) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    int priority = static_cast<int>(topics.size());
    for (const auto& topic : topics) {
        if (s_learningQueue.find(topic) != s_learningQueue.end()) {
            s_learningQueue[topic]["priority"] = priority;
        }
        priority--;
    }
}

nlohmann::json LearningScheduler::GetLearningSchedule() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [topic, task] : s_learningQueue) {
        result.push_back(task);
    }
    return result;
}

nlohmann::json LearningScheduler::GetScheduleMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t pending = 0, inProgress = 0, completed = 0;
    for (const auto& [topic, task] : s_learningQueue) {
        std::string status = task.value("status", "");
        if (status == "pending") pending++;
        else if (status == "in_progress") inProgress++;
        else if (status == "completed") completed++;
    }
    
    return {
        {"total_scheduled", s_learningQueue.size()},
        {"pending", pending},
        {"in_progress", inProgress},
        {"completed", completed},
        {"completion_rate", s_learningQueue.empty() ? 0.0 : 
                           static_cast<double>(completed) / s_learningQueue.size()}
    };
}
