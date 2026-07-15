#include "sovereign/PlanetaryScheduler.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/RoutingHeuristicsEngine.hpp"
#include <mutex>
#include <queue>
#include <algorithm>

namespace PlanetaryScheduler {
    static std::mutex g_mutex;
    static std::map<std::string, std::map<ResourceType, ResourceOffer>> g_resources;
    static std::map<uint64_t, TaskSpec> g_pendingTasks;
    static std::map<uint64_t, ScheduleDecision> g_completedSchedules;
    static ScheduleCallback g_scheduleCb;
    static OfferCallback g_offerCb;
    static uint64_t g_nextTaskId = 1;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("planetary_task_submit", OnFabricMessage);
        Fabric::Instance().RegisterHandler("planetary_resource_offer", OnFabricMessage);
        Fabric::Instance().RegisterHandler("planetary_schedule_result", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_PlanetarySchedulerInit, {{"timestamp", Beaconism::GetTimestamp()}});
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    void SubmitTask(const TaskSpec& task) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pendingTasks[task.id] = task;

        nlohmann::json msg = {
            {"type", "planetary_task_submit"},
            {"task_id", task.id},
            {"priority", static_cast<int>(task.priority)},
            {"deadline", task.deadline},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_TaskSubmitted, {
            {"task_id", task.id},
            {"priority", static_cast<int>(task.priority)}
        });
    }

    void CancelTask(uint64_t taskId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pendingTasks.erase(taskId);

        Beaconism::Emit(Beaconism::BEACON_TaskCancelled, {{"task_id", taskId}});
    }

    void RegisterResourceOffer(const ResourceOffer& offer) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_resources[offer.nodeId][offer.type] = offer;

        if (g_offerCb) g_offerCb(offer);

        nlohmann::json msg = {
            {"type", "planetary_resource_offer"},
            {"node", offer.nodeId},
            {"resource_type", static_cast<int>(offer.type)},
            {"capacity", offer.capacity},
            {"utilization", offer.utilization},
            {"timestamp", offer.timestamp}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_ResourceOffer, {
            {"node", offer.nodeId},
            {"type", static_cast<int>(offer.type)},
            {"capacity", offer.capacity}
        });
    }

    void WithdrawResourceOffer(const std::string& nodeId, ResourceType type) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_resources.find(nodeId);
        if (it != g_resources.end()) {
            it->second.erase(type);
        }
    }

    ScheduleDecision ScheduleTask(uint64_t taskId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        ScheduleDecision decision;
        decision.taskId = taskId;
        decision.confidence = 0.0f;
        decision.scheduledAt = Beaconism::GetTimestamp();

        auto taskIt = g_pendingTasks.find(taskId);
        if (taskIt == g_pendingTasks.end()) return decision;

        const auto& task = taskIt->second;
        float bestScore = -1.0f;

        for (const auto& [nodeId, resources] : g_resources) {
            if (!task.preferredNodes.empty() &&
                std::find(task.preferredNodes.begin(), task.preferredNodes.end(), nodeId) == task.preferredNodes.end()) {
                continue;
            }

            float score = 0.0f;
            float totalCost = 0.0f;
            bool canSchedule = true;

            for (const auto& [reqType, reqAmount] : task.requirements) {
                auto resIt = resources.find(reqType);
                if (resIt == resources.end() || resIt->second.capacity - resIt->second.utilization < reqAmount) {
                    canSchedule = false;
                    break;
                }
                float available = resIt->second.capacity - resIt->second.utilization;
                score += available / (reqAmount + 0.001f);
                totalCost += resIt->second.cost * reqAmount;
            }

            if (canSchedule && score > bestScore) {
                bestScore = score;
                decision.assignedNode = nodeId;
                decision.estimatedCost = totalCost;
                decision.confidence = std::min(1.0f, score / task.requirements.size());
            }
        }

        if (!decision.assignedNode.empty()) {
            g_completedSchedules[taskId] = decision;
            g_pendingTasks.erase(taskId);

            if (g_scheduleCb) g_scheduleCb(decision);

            nlohmann::json msg = {
                {"type", "planetary_schedule_result"},
                {"task_id", taskId},
                {"node", decision.assignedNode},
                {"cost", decision.estimatedCost},
                {"confidence", decision.confidence}
            };
            Fabric::Instance().BroadcastJSON(msg);

            Beaconism::Emit(Beaconism::BEACON_TaskScheduled, {
                {"task_id", taskId},
                {"node", decision.assignedNode},
                {"confidence", decision.confidence}
            });
        }

        return decision;
    }

    std::vector<ScheduleDecision> ScheduleBatch(const std::vector<uint64_t>& taskIds) {
        std::vector<ScheduleDecision> results;
        for (uint64_t taskId : taskIds) {
            results.push_back(ScheduleTask(taskId));
        }
        return results;
    }

    void RegisterScheduleCallback(ScheduleCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_scheduleCb = cb;
    }

    void RegisterOfferCallback(OfferCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_offerCb = cb;
    }

    std::map<std::string, std::map<ResourceType, ResourceOffer>> GetResourceMap() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_resources;
    }

    std::vector<TaskSpec> GetPendingTasks() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<TaskSpec> result;
        for (const auto& [id, task] : g_pendingTasks) {
            result.push_back(task);
        }
        return result;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "planetary_task_submit") {
            TaskSpec task;
            task.id = msg.value("task_id", 0ULL);
            task.priority = static_cast<TaskPriority>(msg.value("priority", 2));
            task.deadline = msg.value("deadline", 0ULL);
            g_pendingTasks[task.id] = task;
        }
        else if (type == "planetary_resource_offer") {
            ResourceOffer offer;
            offer.nodeId = msg.value("node", "");
            offer.type = static_cast<ResourceType>(msg.value("resource_type", 0));
            offer.capacity = msg.value("capacity", 0.0f);
            offer.utilization = msg.value("utilization", 0.0f);
            offer.timestamp = msg.value("timestamp", 0ULL);
            g_resources[offer.nodeId][offer.type] = offer;
        }
        else if (type == "planetary_schedule_result") {
            Beaconism::Emit(Beaconism::BEACON_ScheduleResultRemote, {
                {"task_id", msg.value("task_id", 0ULL)},
                {"node", msg.value("node", "")},
                {"confidence", msg.value("confidence", 0.0f)}
            });
        }
    }

    bool PlanetaryScheduler::IsReady() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }

    // Alias for audit compatibility
    ScheduleDecision PlanetaryScheduler::Schedule(uint64_t taskId) {
        return ScheduleTask(taskId);
    }
}
