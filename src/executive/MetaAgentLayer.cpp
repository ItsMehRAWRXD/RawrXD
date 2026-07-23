// ============================================================
// MetaAgentLayer.cpp - Implementation
// ============================================================

#include "MetaAgentLayer.hpp"
#include "ExecutiveDirector.hpp"

namespace RawrXD::Executive {

// MissionDirector
void MissionDirector::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[MissionDirector] Initialized\n");
}
void MissionDirector::execute() {
    // Evaluate pending missions and decide which to pursue
}
void MissionDirector::shutdown() {
    printf("[MissionDirector] Shutdown\n");
}

float MissionDirector::evaluateMissionPriority(const Mission& mission) { 
    return static_cast<float>(mission.priority); 
}

bool MissionDirector::shouldPursueMission(const Mission& mission) { 
    return mission.state != Mission::State::Aborted && 
           mission.state != Mission::State::Failed;
}

std::vector<uint64_t> MissionDirector::selectMissionsForExecution(const std::vector<Mission>& candidates) {
    std::vector<uint64_t> selected;
    for (const auto& m : candidates) {
        if (shouldPursueMission(m)) {
            selected.push_back(m.id);
        }
    }
    return selected;
}

void MissionDirector::onMissionSubmitted(const Mission& mission) {
    printf("[MissionDirector] Mission #%llu submitted\n", (unsigned long long)mission.id);
}
void MissionDirector::onMissionCompleted(uint64_t missionId, bool success) {
    printf("[MissionDirector] Mission #%llu %s\n", 
           (unsigned long long)missionId, success ? "completed" : "failed");
}
void MissionDirector::onMissionFailed(uint64_t missionId, const std::string& reason) {
    printf("[MissionDirector] Mission #%llu failed: %s\n", 
           (unsigned long long)missionId, reason.c_str());
}

// Scheduler
void Scheduler::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[Scheduler] Initialized\n");
}
void Scheduler::execute() {
    // Process mission queue
}
void Scheduler::shutdown() {
    printf("[Scheduler] Shutdown\n");
}

void Scheduler::usePriorityScheduling() { 
    currentAlgorithm_ = "priority"; 
    printf("[Scheduler] Using priority scheduling\n");
}
void Scheduler::useDeadlineScheduling() { 
    currentAlgorithm_ = "deadline"; 
    printf("[Scheduler] Using deadline scheduling\n");
}
void Scheduler::useFairScheduling() { 
    currentAlgorithm_ = "fair"; 
    printf("[Scheduler] Using fair scheduling\n");
}
void Scheduler::useLearningBasedScheduling() { 
    currentAlgorithm_ = "learning"; 
    printf("[Scheduler] Using learning-based scheduling\n");
}

void Scheduler::enqueueMission(const Mission& mission) {
    std::lock_guard<std::mutex> lock(mutex_);
    missionQueue_.push_back(mission);
    printf("[Scheduler] Mission #%llu enqueued\n", (unsigned long long)mission.id);
}

std::optional<Mission> Scheduler::dequeueNextMission() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (missionQueue_.empty()) return std::nullopt;
    
    // Sort by priority
    if (currentAlgorithm_ == "priority") {
        std::sort(missionQueue_.begin(), missionQueue_.end(),
            [](const Mission& a, const Mission& b) {
                return static_cast<int>(a.priority) < static_cast<int>(b.priority);
            });
    }
    
    Mission next = missionQueue_.front();
    missionQueue_.erase(missionQueue_.begin());
    return next;
}

void Scheduler::reprioritizeMission(uint64_t missionId, float newPriority) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& m : missionQueue_) {
        if (m.id == missionId) {
            m.priority = static_cast<Mission::Priority>(
                std::max(0.0f, std::min(4.0f, newPriority)));
            break;
        }
    }
}

bool Scheduler::canPreempt(const Mission& running, const Mission& candidate) {
    return static_cast<int>(candidate.priority) < static_cast<int>(running.priority);
}

void Scheduler::preemptMission(uint64_t missionId) {
    printf("[Scheduler] Mission #%llu preempted\n", (unsigned long long)missionId);
}

// Negotiator
void Negotiator::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[Negotiator] Initialized\n");
}
void Negotiator::execute() {}
void Negotiator::shutdown() {
    printf("[Negotiator] Shutdown\n");
}

std::vector<Negotiator::Conflict> Negotiator::detectConflicts() { 
    std::vector<Conflict> conflicts;
    if (!director_) return conflicts;
    
    // Check for resource conflicts between active missions
    // Two missions conflict if they require the same exclusive resource
    auto missions1 = director_->getActiveMissions();
    for (size_t i = 0; i < missions1.size(); ++i) {
        for (size_t j = i + 1; j < missions1.size(); ++j) {
            const auto& m1 = missions1[i];
            const auto& m2 = missions1[j];
            // Check for overlapping resource requirements
            for (const auto& res1 : m1.requiredResources) {
                for (const auto& res2 : m2.requiredResources) {
                    if (res1 == res2 && !res1.empty()) {
                        Conflict conflict;
                        conflict.conflictId = nextConflictId_.fetch_add(1);
                        conflict.missionId1 = m1.id;
                        conflict.missionId2 = m2.id;
                        conflict.conflictType = "resource_contention";
                        conflict.description = "Both missions require resource: " + res1;
                        conflicts.push_back(conflict);
                    }
                }
            }
        }
    }
    return conflicts;
}

std::string Negotiator::resolveConflict(const Conflict& conflict) {
    printf("[Negotiator] Resolving conflict #%llu between missions #%llu and #%llu\n",
           (unsigned long long)conflict.conflictId,
           (unsigned long long)conflict.missionId1,
           (unsigned long long)conflict.missionId2);
    return "compromise";
}

bool Negotiator::negotiateResourceAccess(uint64_t missionId, const std::string& resourceId) {
    printf("[Negotiator] Mission #%llu requesting resource: %s\n",
           (unsigned long long)missionId, resourceId.c_str());
    return true;
}

Negotiator::Compromise Negotiator::generateCompromise(const Conflict& conflict) {
    Compromise c;
    c.missionId1 = conflict.missionId1;
    c.missionId2 = conflict.missionId2;
    c.adjustedPlan = "shared_access";
    c.satisfactionScore1 = 0.7f;
    c.satisfactionScore2 = 0.7f;
    return c;
}

// Critic
void Critic::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[Critic] Initialized\n");
}
void Critic::execute() {}
void Critic::shutdown() {
    printf("[Critic] Shutdown\n");
}

Critic::PerformanceReview Critic::evaluateMission(uint64_t missionId) {
    PerformanceReview review;
    review.missionId = missionId;
    review.efficiencyScore = 0.8f;
    review.qualityScore = 0.85f;
    review.resourceEfficiency = 0.75f;
    return review;
}

std::vector<Critic::PerformanceReview> Critic::evaluateRecentMissions(size_t count) {
    std::vector<PerformanceReview> reviews;
    if (!director_) return reviews;
    
    auto missions = director_->getRecentMissions(count);
    for (const auto& mission : missions) {
        reviews.push_back(evaluateMission(mission.id));
    }
    return reviews;
}

std::vector<std::string> Critic::detectPerformanceIssues() { 
    std::vector<std::string> issues;
    if (!director_) return issues;
    
    auto reviews = evaluateRecentMissions(10);
    for (const auto& review : reviews) {
        if (review.efficiencyScore < 0.6f) {
            issues.push_back("Mission " + std::to_string(review.missionId) + ": low efficiency (" + 
                           std::to_string(static_cast<int>(review.efficiencyScore * 100)) + "%)");
        }
        if (review.qualityScore < 0.6f) {
            issues.push_back("Mission " + std::to_string(review.missionId) + ": low quality (" + 
                           std::to_string(static_cast<int>(review.qualityScore * 100)) + "%)");
        }
    }
    return issues;
}

std::vector<std::string> Critic::detectResourceWaste() { 
    std::vector<std::string> waste;
    if (!director_) return waste;
    
    auto reviews = evaluateRecentMissions(10);
    for (const auto& review : reviews) {
        if (review.resourceEfficiency < 0.5f) {
            waste.push_back("Mission " + std::to_string(review.missionId) + ": resource efficiency low (" + 
                          std::to_string(static_cast<int>(review.resourceEfficiency * 100)) + "%)");
        }
    }
    return waste;
}

std::vector<std::string> Critic::detectRepeatedFailures() { 
    std::vector<std::string> failures;
    if (!director_) return failures;
    
    auto missions = director_->getFailedMissions(20);
    std::unordered_map<std::string, int> failureCounts;
    for (const auto& mission : missions) {
        failureCounts[mission.description]++;
    }
    
    for (const auto& [desc, count] : failureCounts) {
        if (count >= 3) {
            failures.push_back("Repeated failure pattern (" + std::to_string(count) + " times): " + desc);
        }
    }
    return failures;
}

Critic::SystemHealth Critic::assessSystemHealth() {
    SystemHealth health;
    health.overallScore = 0.95f;
    return health;
}

// Teacher
void Teacher::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[Teacher] Initialized\n");
}
void Teacher::execute() {}
void Teacher::shutdown() {
    printf("[Teacher] Shutdown\n");
}

void Teacher::extractLessons(uint64_t missionId) {
    printf("[Teacher] Extracting lessons from mission #%llu\n", (unsigned long long)missionId);
}

void Teacher::updateAgentModel(uint64_t agentId, const std::vector<std::string>& lessons) {
    printf("[Teacher] Updating agent #%llu model with %zu lessons\n",
           (unsigned long long)agentId, lessons.size());
}

void Teacher::transferSkills(uint64_t fromAgentId, uint64_t toAgentId) {
    printf("[Teacher] Transferring skills from agent #%llu to #%llu\n",
           (unsigned long long)fromAgentId, (unsigned long long)toAgentId);
}

void Teacher::generalizeWorkflow(const std::string& specificWorkflowId) {
    printf("[Teacher] Generalizing workflow: %s\n", specificWorkflowId.c_str());
}

std::vector<Teacher::TrainingExample> Teacher::generateTrainingSet(uint64_t agentId) {
    std::vector<TrainingExample> examples;
    if (!director_) return examples;
    
    // Generate training examples from successful missions
    auto missions = director_->getCompletedMissions(10);
    for (const auto& mission : missions) {
        TrainingExample ex;
        ex.input = "Mission: " + mission.description;
        ex.expectedOutput = "Success";
        ex.weight = mission.confidence;
        examples.push_back(ex);
    }
    
    // Generate examples from failed missions
    auto failed = director_->getFailedMissions(5);
    for (const auto& mission : failed) {
        TrainingExample ex;
        ex.input = "Mission: " + mission.description;
        ex.expectedOutput = "Failure - review required";
        ex.weight = 0.5f;
        examples.push_back(ex);
    }
    
    return examples;
}

// ResourceManager
void ResourceManager::initialize(ExecutiveDirector* director) { 
    director_ = director; 
    printf("[ResourceManager] Initialized\n");
}
void ResourceManager::execute() {}
void ResourceManager::shutdown() {
    printf("[ResourceManager] Shutdown\n");
}

bool ResourceManager::allocateResource(uint64_t missionId, const std::string& resourceType, size_t amount) {
    std::lock_guard<std::mutex> lock(mutex_);
    ResourceAllocation alloc;
    alloc.allocationId = nextAllocationId_++;
    alloc.missionId = missionId;
    alloc.resourceType = resourceType;
    alloc.amount = amount;
    alloc.allocatedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    allocations_.push_back(alloc);
    printf("[ResourceManager] Allocated %zu %s to mission #%llu (alloc #%llu)\n",
           amount, resourceType.c_str(), (unsigned long long)missionId, 
           (unsigned long long)alloc.allocationId);
    return true;
}

void ResourceManager::releaseResource(uint64_t allocationId) {
    std::lock_guard<std::mutex> lock(mutex_);
    allocations_.erase(
        std::remove_if(allocations_.begin(), allocations_.end(),
            [allocationId](const ResourceAllocation& a) { 
                return a.allocationId == allocationId; 
            }),
        allocations_.end()
    );
}

std::vector<ResourceManager::ResourceAllocation> ResourceManager::getActiveAllocations() {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocations_;
}

bool ResourceManager::isResourceAvailable(const std::string& resourceType, size_t amount) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t allocated = 0;
    for (const auto& alloc : allocations_) {
        if (alloc.resourceType == resourceType) {
            allocated += alloc.amount;
        }
    }
    return (allocated + amount) <= 1000000; // Arbitrary limit
}

size_t ResourceManager::getAvailableResource(const std::string& resourceType) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t allocated = 0;
    for (const auto& alloc : allocations_) {
        if (alloc.resourceType == resourceType) {
            allocated += alloc.amount;
        }
    }
    return 1000000 > allocated ? 1000000 - allocated : 0;
}

void ResourceManager::rebalanceResources() {
    printf("[ResourceManager] Rebalancing resources...\n");
}

void ResourceManager::predictResourceNeeds(uint64_t missionId) {
    printf("[ResourceManager] Predicting resource needs for mission #%llu\n", 
           (unsigned long long)missionId);
}

// MetaAgentLayer
bool MetaAgentLayer::initialize(ExecutiveDirector* director) {
    director_ = director;
    missionDirector_.initialize(director);
    scheduler_.initialize(director);
    negotiator_.initialize(director);
    critic_.initialize(director);
    teacher_.initialize(director);
    resourceManager_.initialize(director);
    printf("[MetaAgentLayer] All meta-agents initialized\n");
    return true;
}

void MetaAgentLayer::executeAll() {
    missionDirector_.execute();
    scheduler_.execute();
    negotiator_.execute();
    critic_.execute();
    teacher_.execute();
    resourceManager_.execute();
}

void MetaAgentLayer::shutdown() {
    missionDirector_.shutdown();
    scheduler_.shutdown();
    negotiator_.shutdown();
    critic_.shutdown();
    teacher_.shutdown();
    resourceManager_.shutdown();
    printf("[MetaAgentLayer] All meta-agents shutdown\n");
}

void MetaAgentLayer::registerAgent(const RegisteredAgent& agent) {
    std::lock_guard<std::mutex> lock(mutex_);
    registeredAgents_.push_back(agent);
    printf("[MetaAgentLayer] Agent #%llu registered: %s\n",
           (unsigned long long)agent.agentId, agent.name.c_str());
}

void MetaAgentLayer::unregisterAgent(uint64_t agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    registeredAgents_.erase(
        std::remove_if(registeredAgents_.begin(), registeredAgents_.end(),
            [agentId](const RegisteredAgent& a) { return a.agentId == agentId; }),
        registeredAgents_.end()
    );
}

std::vector<RegisteredAgent> MetaAgentLayer::findAgentsForCapability(const std::string& capability) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RegisteredAgent> results;
    for (const auto& agent : registeredAgents_) {
        for (const auto& cap : agent.capabilities) {
            if (cap.name == capability) {
                results.push_back(agent);
                break;
            }
        }
    }
    return results;
}

std::vector<RegisteredAgent> MetaAgentLayer::getAllAgents() {
    std::lock_guard<std::mutex> lock(mutex_);
    return registeredAgents_;
}

} // namespace RawrXD::Executive
