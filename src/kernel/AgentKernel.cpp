// Sovereign Agent Kernel - Implementation
// The orchestration layer that transforms multiple autonomous agents
// from competing processes into coordinated workers.

#include "AgentKernel.hpp"
#include "../intent/intent_abi.hpp"
#include "../guardrails/patch_firewall.hpp"
#include "../hotpatch/patch_transaction.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Kernel {

// ============================================================================
// Utility Functions
// ============================================================================

const char* ResourceTypeToString(ResourceType type) {
    switch (type) {
        case ResourceType::TERMINAL: return "TERMINAL";
        case ResourceType::COMPILER: return "COMPILER";
        case ResourceType::DEBUGGER: return "DEBUGGER";
        case ResourceType::FILESYSTEM: return "FILESYSTEM";
        case ResourceType::GPU: return "GPU";
        case ResourceType::KV_CACHE: return "KV_CACHE";
        case ResourceType::BUILD_SLOT: return "BUILD_SLOT";
        case ResourceType::HOTPATCH: return "HOTPATCH";
        case ResourceType::SYMBOL_TABLE: return "SYMBOL_TABLE";
        case ResourceType::TELEMETRY: return "TELEMETRY";
        default: return "UNKNOWN";
    }
}

static std::string GenerateTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// ============================================================================
// ResourceLease Implementation
// ============================================================================

bool ResourceLease::IsExpired() const {
    auto now = std::chrono::steady_clock::now();
    return now > expires;
}

bool ResourceLease::HasCapability(const std::string& cap) const {
    if (cap == "read") return capabilities.canRead;
    if (cap == "write") return capabilities.canWrite;
    if (cap == "execute") return capabilities.canExecute;
    if (cap == "delegate") return capabilities.canDelegate;
    if (cap == "terminate") return capabilities.canTerminate;
    return false;
}

void ResourceLease::Heartbeat() {
    lastHeartbeat.store(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

std::string ResourceLease::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"leaseId\":" << leaseId << ",";
    ss << "\"owner\":" << owner << ",";
    ss << "\"resourceType\":\"" << ResourceTypeToString(resourceType) << "\",";
    ss << "\"resourceId\":" << resourceId << ",";
    ss << "\"purpose\":\"" << purpose << "\",";
    ss << "\"associatedIntent\":" << associatedIntent << ",";
    ss << "\"isActive\":" << (isActive.load() ? "true" : "false");
    ss << "}";
    return ss.str();
}

// ============================================================================
// BeaconEvent Implementation
// ============================================================================

std::string BeaconEvent::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"eventId\":" << eventId << ",";
    ss << "\"type\":" << static_cast<uint32_t>(type) << ",";
    ss << "\"timestamp\":\"" << GenerateTimestamp() << "\",";
    ss << "\"sourceAgent\":" << sourceAgent << ",";
    ss << "\"associatedIntent\":" << associatedIntent << ",";
    ss << "\"metadata\":{";
    bool first = true;
    for (const auto& [key, value] : metadata) {
        if (!first) ss << ",";
        ss << "\"" << key << "\":\"" << value << "\"";
        first = false;
    }
    ss << "}}";
    return ss.str();
}

BeaconEvent BeaconEvent::FromJson(const std::string& json) {
    // Simplified parsing - in production use nlohmann/json
    BeaconEvent event;
    // TODO: Implement full JSON parsing
    return event;
}

// ============================================================================
// AgentSession Implementation
// ============================================================================

void AgentSession::AcquireLease(std::shared_ptr<ResourceLease> lease) {
    std::lock_guard<std::mutex> lock(leaseMutex);
    activeLeases.push_back(lease->leaseId);
}

void AgentSession::ReleaseLease(LeaseId leaseId) {
    std::lock_guard<std::mutex> lock(leaseMutex);
    auto it = std::remove(activeLeases.begin(), activeLeases.end(), leaseId);
    activeLeases.erase(it, activeLeases.end());
}

bool AgentSession::HasLease(ResourceType type) const {
    std::lock_guard<std::mutex> lock(leaseMutex);
    for (LeaseId leaseId : activeLeases) {
        auto lease = ResourceScheduler::Instance().GetLease(leaseId);
        if (lease && lease->resourceType == type && lease->isActive.load()) {
            return true;
        }
    }
    return false;
}

std::vector<std::shared_ptr<ResourceLease>> AgentSession::GetActiveLeases() const {
    std::lock_guard<std::mutex> lock(leaseMutex);
    std::vector<std::shared_ptr<ResourceLease>> result;
    for (LeaseId leaseId : activeLeases) {
        auto lease = ResourceScheduler::Instance().GetLease(leaseId);
        if (lease && lease->isActive.load()) {
            result.push_back(lease);
        }
    }
    return result;
}

// ============================================================================
// ResourceScheduler Implementation
// ============================================================================

ResourceScheduler& ResourceScheduler::Instance() {
    static ResourceScheduler instance;
    return instance;
}

std::shared_ptr<ResourceLease> ResourceScheduler::AcquireLease(
    AgentId agent,
    ResourceType type,
    ResourceId specificResource,
    LeaseCapabilities caps,
    std::chrono::seconds duration,
    const std::string& purpose,
    IntentId intent
) {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    // Check if resource is available
    if (specificResource != 0) {
        for (const auto& [id, lease] : leases_) {
            if (lease->resourceType == type && 
                lease->resourceId == specificResource &&
                lease->isActive.load() &&
                !lease->IsExpired()) {
                // Resource is taken - add to wait queue
                std::lock_guard<std::mutex> wqLock(waitQueueMutex_);
                waitQueues_[type].push(agent);
                return nullptr;
            }
        }
    }
    
    // Create new lease
    auto lease = std::make_shared<ResourceLease>();
    lease->leaseId = nextLeaseId_++;
    lease->owner = agent;
    lease->resourceType = type;
    lease->resourceId = specificResource != 0 ? specificResource : lease->leaseId;
    lease->capabilities = caps;
    lease->acquired = std::chrono::steady_clock::now();
    lease->expires = lease->acquired + duration;
    lease->purpose = purpose;
    lease->associatedIntent = intent;
    lease->isActive.store(true);
    
    // Store lease
    leases_[lease->leaseId] = lease;
    resourceIndex_[type].push_back(lease->leaseId);
    
    // Emit beacon
    BeaconEvent event;
    event.eventId = 0; // Will be set by bus
    event.type = BeaconType::RESOURCE_ACQUIRED;
    event.timestamp = std::chrono::steady_clock::now();
    event.sourceAgent = agent;
    event.associatedIntent = intent;
    event.metadata["leaseId"] = std::to_string(lease->leaseId);
    event.metadata["resourceType"] = ResourceTypeToString(type);
    event.metadata["purpose"] = purpose;
    BEACON_BUS.Publish(std::move(event));
    
    return lease;
}

bool ResourceScheduler::ReleaseLease(LeaseId leaseId, AgentId agent) {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    auto it = leases_.find(leaseId);
    if (it == leases_.end()) return false;
    
    auto& lease = it->second;
    if (lease->owner != agent) return false; // Can only release own leases
    
    lease->isActive.store(false);
    
    // Remove from resource index
    auto& vec = resourceIndex_[lease->resourceType];
    vec.erase(std::remove(vec.begin(), vec.end(), leaseId), vec.end());
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::RESOURCE_RELEASED;
    event.sourceAgent = agent;
    event.associatedIntent = lease->associatedIntent;
    event.metadata["leaseId"] = std::to_string(leaseId);
    BEACON_BUS.Publish(std::move(event));
    
    return true;
}

bool ResourceScheduler::ExtendLease(LeaseId leaseId, std::chrono::seconds extension) {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    auto it = leases_.find(leaseId);
    if (it == leases_.end()) return false;
    
    auto& lease = it->second;
    if (!lease->isActive.load()) return false;
    
    lease->expires += extension;
    lease->Heartbeat();
    return true;
}

std::shared_ptr<ResourceLease> ResourceScheduler::GetLease(LeaseId leaseId) const {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    auto it = leases_.find(leaseId);
    if (it != leases_.end()) return it->second;
    return nullptr;
}

std::vector<std::shared_ptr<ResourceLease>> ResourceScheduler::GetLeasesForAgent(AgentId agent) const {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    std::vector<std::shared_ptr<ResourceLease>> result;
    for (const auto& [id, lease] : leases_) {
        if (lease->owner == agent && lease->isActive.load()) {
            result.push_back(lease);
        }
    }
    return result;
}

std::vector<std::shared_ptr<ResourceLease>> ResourceScheduler::GetLeasesForResource(ResourceType type) const {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    std::vector<std::shared_ptr<ResourceLease>> result;
    auto it = resourceIndex_.find(type);
    if (it != resourceIndex_.end()) {
        for (LeaseId leaseId : it->second) {
            auto lease = GetLease(leaseId);
            if (lease && lease->isActive.load()) {
                result.push_back(lease);
            }
        }
    }
    return result;
}

bool ResourceScheduler::IsResourceAvailable(ResourceType type, ResourceId specificResource) const {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    auto it = resourceIndex_.find(type);
    if (it == resourceIndex_.end()) return true;
    
    for (LeaseId leaseId : it->second) {
        auto lease = GetLease(leaseId);
        if (lease && lease->isActive.load() && !lease->IsExpired()) {
            if (specificResource == 0 || lease->resourceId == specificResource) {
                return false;
            }
        }
    }
    return true;
}

std::vector<AgentId> ResourceScheduler::GetWaitingAgents(ResourceType type) const {
    std::lock_guard<std::mutex> lock(waitQueueMutex_);
    std::vector<AgentId> result;
    auto it = waitQueues_.find(type);
    if (it != waitQueues_.end()) {
        auto tempQueue = it->second;
        while (!tempQueue.empty()) {
            result.push_back(tempQueue.front());
            tempQueue.pop();
        }
    }
    return result;
}

void ResourceScheduler::EmergencyRevokeAll(AgentId agent) {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    for (auto& [id, lease] : leases_) {
        if (lease->owner == agent && lease->isActive.load()) {
            lease->isActive.store(false);
            
            BeaconEvent event;
            event.type = BeaconType::RESOURCE_RELEASED;
            event.sourceAgent = agent;
            event.metadata["leaseId"] = std::to_string(lease->leaseId);
            event.metadata["reason"] = "emergency_revoke";
            BEACON_BUS.Publish(std::move(event));
        }
    }
}

void ResourceScheduler::EmergencyRevokeResource(ResourceType type) {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    auto it = resourceIndex_.find(type);
    if (it != resourceIndex_.end()) {
        for (LeaseId leaseId : it->second) {
            auto lease = GetLease(leaseId);
            if (lease && lease->isActive.load()) {
                lease->isActive.store(false);
            }
        }
        it->second.clear();
    }
}

void ResourceScheduler::PruneExpiredLeases() {
    std::lock_guard<std::mutex> lock(leasesMutex_);
    
    std::vector<LeaseId> toRemove;
    for (auto& [id, lease] : leases_) {
        if (lease->IsExpired() && lease->isActive.load()) {
            lease->isActive.store(false);
            toRemove.push_back(id);
            
            BeaconEvent event;
            event.type = BeaconType::RESOURCE_RELEASED;
            event.sourceAgent = lease->owner;
            event.metadata["leaseId"] = std::to_string(id);
            event.metadata["reason"] = "expired";
            BEACON_BUS.Publish(std::move(event));
        }
    }
    
    for (LeaseId id : toRemove) {
        leases_.erase(id);
    }
}

void ResourceScheduler::StartHeartbeatMonitor() {
    monitorRunning_.store(true);
    monitorThread_ = std::thread([this]() {
        while (monitorRunning_.load()) {
            PruneExpiredLeases();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    });
}

void ResourceScheduler::StopHeartbeatMonitor() {
    monitorRunning_.store(false);
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

// ============================================================================
// BeaconBus Implementation
// ============================================================================

BeaconBus& BeaconBus::Instance() {
    static BeaconBus instance;
    return instance;
}

void BeaconBus::Start() {
    running_.store(true);
    dispatchThread_ = std::thread(&BeaconBus::DispatchLoop, this);
}

void BeaconBus::Stop() {
    running_.store(false);
    queueCv_.notify_all();
    if (dispatchThread_.joinable()) {
        dispatchThread_.join();
    }
}

void BeaconBus::Publish(BeaconEvent&& event) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        event.eventId = totalPublished_.fetch_add(1);
        event.timestamp = std::chrono::steady_clock::now();
        eventQueue_.push(std::move(event));
    }
    queueCv_.notify_one();
}

void BeaconBus::Publish(BeaconType type, AgentId source, const std::string& jsonPayload) {
    BeaconEvent event;
    event.type = type;
    event.sourceAgent = source;
    // TODO: Parse jsonPayload into metadata
    Publish(std::move(event));
}

uint64_t BeaconBus::Subscribe(BeaconType type, BeaconHandler handler) {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    uint64_t id = nextSubscriptionId_++;
    subscriptions_[id] = {type, handler};
    return id;
}

uint64_t BeaconBus::SubscribeAll(BeaconHandler handler) {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    uint64_t id = nextSubscriptionId_++;
    globalSubscriptions_[id] = handler;
    return id;
}

void BeaconBus::Unsubscribe(uint64_t subscriptionId) {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    subscriptions_.erase(subscriptionId);
    globalSubscriptions_.erase(subscriptionId);
}

void BeaconBus::DispatchLoop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        queueCv_.wait(lock, [this]() { return !eventQueue_.empty() || !running_.load(); });
        
        if (!running_.load()) break;
        
        BeaconEvent event = std::move(eventQueue_.front());
        eventQueue_.pop();
        lock.unlock();
        
        // Store in history
        {
            std::lock_guard<std::mutex> hlock(historyMutex_);
            history_.push_back(event);
            if (history_.size() > MAX_HISTORY) {
                history_.erase(history_.begin());
            }
        }
        
        // Dispatch to subscribers
        std::lock_guard<std::mutex> slock(subscriptionsMutex_);
        for (const auto& [id, sub] : subscriptions_) {
            if (sub.first == event.type) {
                sub.second(event);
            }
        }
        for (const auto& [id, handler] : globalSubscriptions_) {
            handler(event);
        }
    }
}

std::vector<BeaconEvent> BeaconBus::GetHistory(uint64_t maxEvents) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<BeaconEvent> result;
    uint64_t count = std::min(maxEvents, static_cast<uint64_t>(history_.size()));
    result.insert(result.end(), history_.end() - count, history_.end());
    return result;
}

std::vector<BeaconEvent> BeaconBus::GetHistoryForAgent(AgentId agent, uint64_t maxEvents) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<BeaconEvent> result;
    for (const auto& event : history_) {
        if (event.sourceAgent == agent) {
            result.push_back(event);
        }
    }
    if (result.size() > maxEvents) {
        result.erase(result.begin(), result.begin() + (result.size() - maxEvents));
    }
    return result;
}

std::vector<BeaconEvent> BeaconBus::GetHistoryForIntent(IntentId intent) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<BeaconEvent> result;
    for (const auto& event : history_) {
        if (event.associatedIntent == intent) {
            result.push_back(event);
        }
    }
    return result;
}

void BeaconBus::ClearHistory() {
    std::lock_guard<std::mutex> lock(historyMutex_);
    history_.clear();
}

uint64_t BeaconBus::GetActiveSubscriptions() const {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    return subscriptions_.size() + globalSubscriptions_.size();
}

// ============================================================================
// IntentQueue Implementation
// ============================================================================

IntentQueue& IntentQueue::Instance() {
    static IntentQueue instance;
    return instance;
}

void IntentQueue::Enqueue(IntentRequest&& intent) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        intent.state = IntentRequest::State::QUEUED;
        queue_.push(std::move(intent));
    }
    cv_.notify_one();
}

std::optional<IntentRequest> IntentQueue::Dequeue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    if (queue_.empty()) {
        return std::nullopt;
    }
    IntentRequest intent = std::move(const_cast<IntentRequest&>(queue_.top()));
    queue_.pop();
    return intent;
}

size_t IntentQueue::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return queue_.size();
}

size_t IntentQueue::GetCountForAgent(AgentId agent) const {
    std::lock_guard<std::mutex> lock(queueMutex_);

    // Iterate through priority queue to count intents for agent
    // Note: This is O(n) - in production, maintain a separate index
    size_t count = 0;
    auto tempQueue = queue_;
    while (!tempQueue.empty()) {
        if (tempQueue.top().sourceAgent == agent) {
            count++;
        }
        tempQueue.pop();
    }
    return count;
}

std::vector<IntentRequest> IntentQueue::GetPendingIntents() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    std::vector<IntentRequest> result;
    auto tempQueue = queue_;
    while (!tempQueue.empty()) {
        result.push_back(std::move(const_cast<IntentRequest&>(tempQueue.top())));
        tempQueue.pop();
    }
    return result;
}

void IntentQueue::CancelIntent(IntentId intentId) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Priority queue doesn't support direct removal
    // Strategy: Rebuild queue without the canceled intent
    std::vector<IntentRequest> remaining;
    remaining.reserve(queue_.size());
    
    // Extract all intents except the one to cancel
    bool found = false;
    while (!queue_.empty()) {
        auto intent = std::move(const_cast<IntentRequest&>(queue_.top()));
        queue_.pop();
        
        if (intent.intentId == intentId) {
            found = true;
            // Log cancellation
            printf("[IntentQueue] Canceled intent %llu\n", (unsigned long long)intentId);
        } else {
            remaining.push_back(std::move(intent));
        }
    }
    
    // Rebuild queue
    for (auto& intent : remaining) {
        queue_.push(std::move(intent));
    }
    
    if (!found) {
        printf("[IntentQueue] Intent %u not found for cancellation\n", intentId);
    }
}

void IntentQueue::CancelAllForAgent(AgentId agent) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Priority queue doesn't support bulk removal
    // Strategy: Rebuild queue without canceled agent's intents
    std::vector<IntentRequest> remaining;
    remaining.reserve(queue_.size());
    
    // Extract all intents not belonging to the agent
    while (!queue_.empty()) {
        auto intent = std::move(const_cast<IntentRequest&>(queue_.top()));
        queue_.pop();
        if (intent.sourceAgent != agent) {
            remaining.push_back(std::move(intent));
        }
    }

    // Rebuild queue
    for (auto& intent : remaining) {
        queue_.push(std::move(intent));
    }

    // Log cancellation
    size_t canceledCount = remaining.size() < queue_.size() ? 0 : queue_.size() - remaining.size();
    if (canceledCount > 0) {
        printf("[IntentQueue] Canceled %zu intents for agent %llu\n", canceledCount, (unsigned long long)agent);
    }
}

void IntentQueue::Reprioritize(IntentId intentId, IntentPriority newPriority) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Priority queue doesn't support direct modification
    // Strategy: Rebuild queue with updated priority
    std::vector<IntentRequest> intents;
    intents.reserve(queue_.size());
    bool found = false;
    
    // Extract all intents
    while (!queue_.empty()) {
        auto intent = std::move(const_cast<IntentRequest&>(queue_.top()));
        queue_.pop();
        
        // Update priority if this is the target intent
        if (intent.intentId == intentId) {
            intent.priority = newPriority;
            intent.submitted = std::chrono::steady_clock::now();
            found = true;
        }
        
        intents.push_back(std::move(intent));
    }
    
    // Rebuild queue
    for (auto& intent : intents) {
        queue_.push(std::move(intent));
    }
    
    if (found) {
        printf("[IntentQueue] Reprioritized intent %u to priority %d\n", 
               intentId, static_cast<int>(newPriority));
    }
}

void IntentQueue::PruneStaleIntents(std::chrono::minutes maxAge) {
    // TODO: Implement
}

// ============================================================================
// AgentKernel Implementation
// ============================================================================

AgentKernel& AgentKernel::Instance() {
    static AgentKernel instance;
    return instance;
}

bool AgentKernel::Initialize() {
    if (running_.load()) return false;
    
    // Start subsystems
    BEACON_BUS.Start();
    RESOURCE_SCHEDULER.StartHeartbeatMonitor();
    
    startTime_ = std::chrono::steady_clock::now();
    running_.store(true);
    
    // Start main loop
    mainLoopThread_ = std::thread(&AgentKernel::MainLoop, this);
    
    // Emit startup beacon
    BeaconEvent event;
    event.type = BeaconType::KERNEL_STARTED;
    event.sourceAgent = 0;
    event.metadata["version"] = "1.0.0";
    event.metadata["maxAgents"] = std::to_string(maxConcurrentAgents_.load());
    BEACON_BUS.Publish(std::move(event));
    
    return true;
}

void AgentKernel::Shutdown() {
    if (!running_.load()) return;
    
    running_.store(false);
    
    if (mainLoopThread_.joinable()) {
        mainLoopThread_.join();
    }
    
    RESOURCE_SCHEDULER.StopHeartbeatMonitor();
    BEACON_BUS.Stop();
    
    // Emit shutdown beacon
    BeaconEvent event;
    event.type = BeaconType::KERNEL_SHUTDOWN;
    event.sourceAgent = 0;
    BEACON_BUS.Publish(std::move(event));
}

AgentId AgentKernel::RegisterAgent(const std::string& type, const std::string& backend) {
    std::lock_guard<std::mutex> lock(agentsMutex_);
    
    AgentId id = nextAgentId_++;
    auto session = std::make_shared<AgentSession>();
    session->agentId = id;
    session->agentType = type;
    session->modelBackend = backend;
    session->created = std::chrono::steady_clock::now();
    session->isActive.store(true);
    
    agents_[id] = session;
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::AGENT_REGISTERED;
    event.sourceAgent = id;
    event.metadata["agentType"] = type;
    event.metadata["backend"] = backend;
    BEACON_BUS.Publish(std::move(event));
    
    return id;
}

void AgentKernel::UnregisterAgent(AgentId agent) {
    {
        std::lock_guard<std::mutex> lock(agentsMutex_);
        auto it = agents_.find(agent);
        if (it != agents_.end()) {
            it->second->isActive.store(false);
            agents_.erase(it);
        }
    }
    
    // Revoke all leases
    RESOURCE_SCHEDULER.EmergencyRevokeAll(agent);
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::AGENT_UNREGISTERED;
    event.sourceAgent = agent;
    BEACON_BUS.Publish(std::move(event));
}

std::shared_ptr<AgentSession> AgentKernel::GetAgent(AgentId agent) const {
    std::lock_guard<std::mutex> lock(agentsMutex_);
    auto it = agents_.find(agent);
    if (it != agents_.end()) return it->second;
    return nullptr;
}

std::vector<AgentId> AgentKernel::GetActiveAgents() const {
    std::lock_guard<std::mutex> lock(agentsMutex_);
    std::vector<AgentId> result;
    for (const auto& [id, agent] : agents_) {
        if (agent->isActive.load()) {
            result.push_back(id);
        }
    }
    return result;
}

IntentId AgentKernel::SubmitIntent(AgentId agent, IntentRequest&& intent) {
    intent.intentId = totalIntentsProcessed_.fetch_add(1) + 1;
    intent.sourceAgent = agent;
    intent.submitted = std::chrono::steady_clock::now();
    intent.state = IntentRequest::State::PENDING;
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::INTENT_QUEUED;
    event.sourceAgent = agent;
    event.associatedIntent = intent.intentId;
    event.metadata["intentType"] = intent.intentType;
    event.metadata["priority"] = std::to_string(static_cast<uint32_t>(intent.priority));
    BEACON_BUS.Publish(std::move(event));
    
    // Queue the intent
    INTENT_QUEUE.Enqueue(std::move(intent));
    
    return intent.intentId;
}

void AgentKernel::MainLoop() {
    while (running_.load()) {
        if (paused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Try to get next intent
        auto intentOpt = INTENT_QUEUE.Dequeue();
        if (!intentOpt) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        IntentRequest intent = std::move(*intentOpt);
        ProcessIntent(intent);
    }
}

void AgentKernel::ProcessIntent(IntentRequest& intent) {
    // Update state
    intent.state = IntentRequest::State::WAITING_RESOURCES;
    
    // Emit beacon
    BeaconEvent startEvent;
    startEvent.type = BeaconType::INTENT_STARTED;
    startEvent.sourceAgent = intent.sourceAgent;
    startEvent.associatedIntent = intent.intentId;
    BEACON_BUS.Publish(std::move(startEvent));
    
    // Acquire resources
    if (!AcquireResourcesForIntent(intent)) {
        // Failed to acquire resources - requeue or fail
        BeaconEvent failEvent;
        failEvent.type = BeaconType::INTENT_FAILED;
        failEvent.sourceAgent = intent.sourceAgent;
        failEvent.associatedIntent = intent.intentId;
        failEvent.metadata["reason"] = "resource_acquisition_failed";
        BEACON_BUS.Publish(std::move(failEvent));
        return;
    }
    
    // Execute intent
    intent.state = IntentRequest::State::EXECUTING;
    
    // TODO: Route to appropriate execution handler based on intent type
    // This is where Intent ABI -> PatchFirewall -> Execution happens
    
    // For now, simulate execution
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Complete
    intent.state = IntentRequest::State::COMPLETED;
    totalIntentsProcessed_++;
    
    // Release resources
    ReleaseResourcesForIntent(intent);
    
    // Emit completion beacon
    BeaconEvent completeEvent;
    completeEvent.type = BeaconType::INTENT_COMPLETED;
    completeEvent.sourceAgent = intent.sourceAgent;
    completeEvent.associatedIntent = intent.intentId;
    BEACON_BUS.Publish(std::move(completeEvent));
}

bool AgentKernel::AcquireResourcesForIntent(IntentRequest& intent) {
    // Get agent session
    auto agent = GetAgent(intent.sourceAgent);
    if (!agent) return false;
    
    // Acquire each required resource
    for (ResourceType resType : intent.requiredResources) {
        auto lease = RESOURCE_SCHEDULER.AcquireLease(
            intent.sourceAgent,
            resType,
            0, // Any resource of this type
            LeaseCapabilities::FullAccess(),
            std::chrono::seconds(300), // 5 minute lease
            "Intent execution: " + intent.intentType,
            intent.intentId
        );
        
        if (!lease) {
            // Failed to acquire - release what we got
            ReleaseResourcesForIntent(intent);
            return false;
        }
        
        agent->AcquireLease(lease);
    }
    
    return true;
}

void AgentKernel::ReleaseResourcesForIntent(const IntentRequest& intent) {
    auto agent = GetAgent(intent.sourceAgent);
    if (!agent) return;
    
    auto leases = agent->GetActiveLeases();
    for (const auto& lease : leases) {
        if (lease->associatedIntent == intent.intentId) {
            RESOURCE_SCHEDULER.ReleaseLease(lease->leaseId, intent.sourceAgent);
            agent->ReleaseLease(lease->leaseId);
        }
    }
}

void AgentKernel::PauseExecution() {
    paused_.store(true);
}

void AgentKernel::ResumeExecution() {
    paused_.store(false);
}

void AgentKernel::EmergencyStop(const std::string& reason) {
    paused_.store(true);
    
    // Revoke all resources
    for (int i = 0; i < static_cast<int>(ResourceType::COUNT); ++i) {
        RESOURCE_SCHEDULER.EmergencyRevokeResource(static_cast<ResourceType>(i));
    }
    
    // Emit emergency beacon
    BeaconEvent event;
    event.type = BeaconType::KERNEL_SHUTDOWN;
    event.sourceAgent = 0;
    event.metadata["reason"] = reason;
    event.metadata["emergency"] = "true";
    BEACON_BUS.Publish(std::move(event));
}

AgentKernel::KernelStatus AgentKernel::GetStatus() const {
    KernelStatus status;
    status.running = running_.load();
    status.activeAgents = GetActiveAgents().size();
    status.pendingIntents = INTENT_QUEUE.GetPendingCount();
    status.activeLeases = RESOURCE_SCHEDULER.GetLeasesForAgent(0).size(); // TODO: Count all
    status.totalIntentsProcessed = totalIntentsProcessed_.load();
    status.totalEventsPublished = BEACON_BUS.GetTotalEventsPublished();
    
    auto now = std::chrono::steady_clock::now();
    status.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime_);
    
    return status;
}

std::string AgentKernel::GetStatusJson() const {
    auto status = GetStatus();
    std::stringstream ss;
    ss << "{";
    ss << "\"running\":" << (status.running ? "true" : "false") << ",";
    ss << "\"activeAgents\":" << status.activeAgents << ",";
    ss << "\"pendingIntents\":" << status.pendingIntents << ",";
    ss << "\"activeLeases\":" << status.activeLeases << ",";
    ss << "\"totalIntentsProcessed\":" << status.totalIntentsProcessed << ",";
    ss << "\"totalEventsPublished\":" << status.totalEventsPublished << ",";
    ss << "\"uptimeMs\":" << status.uptime.count();
    ss << "}";
    return ss.str();
}

void AgentKernel::SetMaxConcurrentAgents(size_t max) {
    maxConcurrentAgents_.store(max);
}

void AgentKernel::SetIntentTimeout(std::chrono::seconds timeout) {
    intentTimeout_ = timeout;
}

void AgentKernel::SetLeaseHeartbeatInterval(std::chrono::seconds interval) {
    leaseHeartbeatInterval_ = interval;
}

// ============================================================================
// ScopedResourceLease Implementation
// ============================================================================

ScopedResourceLease::ScopedResourceLease(AgentId agent, ResourceType type,
                                         std::chrono::seconds duration,
                                         const std::string& purpose) {
    lease_ = RESOURCE_SCHEDULER.AcquireLease(agent, type, 0,
                                             LeaseCapabilities::FullAccess(),
                                             duration, purpose, 0);
}

ScopedResourceLease::~ScopedResourceLease() {
    if (lease_) {
        RESOURCE_SCHEDULER.ReleaseLease(lease_->leaseId, lease_->owner);
    }
}

} // namespace Kernel
} // namespace RawrXD
