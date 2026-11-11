/*===========================================================================
 * SovereignRPC_AdmissionController.cpp
 *
 * Implementation of local admission controller
 *
 * Key invariant: GhostText never blocks on network I/O
 *===========================================================================*/

#include "SovereignRPC_AdmissionController.hpp"
#include "SovereignRPC_Scheduler.hpp"
#include <thread>
#include <chrono>

namespace RawrXD {
namespace RPC {

/*===========================================================================
 * Admission Controller Implementation
 *===========================================================================*/

AdmissionController& AdmissionController::Instance() {
    static AdmissionController instance;
    return instance;
}

void AdmissionController::Initialize(const LocalCapacity& localCapacity) {
    localCapacity_ = localCapacity;
    running_ = true;

    // Start local queue processor
    localQueueProcessor_ = std::thread([this]() {
        ProcessLocalQueue();
    });
}

RoutingDecision AdmissionController::Route(const InferenceRequest& request) {
    auto start = std::chrono::steady_clock::now();

    // Fast path: Check local GPU availability
    if (localCapacity_.CanExecuteLocal(request)) {
        auto end = std::chrono::steady_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        RoutingDecision decision;
        decision.path = RoutingDecision::Path::LocalGPU;
        decision.estimatedWaitMs = 0;
        decision.reason = "Local GPU with resident model";
        decision.metadata.schedulingLatencyUs = latency;
        decision.metadata.requestedQuant = Deep2::QuantTypeToString(request.preferredFormat);
        decision.metadata.executedQuant = decision.metadata.requestedQuant;

        // Execute asynchronously
        ExecuteLocal(request);

        return decision;
    }

    // Apply routing policy
    return ApplyPolicy(request);
}

RoutingDecision AdmissionController::ApplyPolicy(const InferenceRequest& request) {
    RoutingDecision decision;
    decision.metadata.requestedQuant = Deep2::QuantTypeToString(request.preferredFormat);

    switch (policy_) {
        case RoutingPolicy::PreferLocal: {
            // Try local CPU if GPU busy
            if (localCapacity_.cpuAvailable.load()) {
                decision.path = RoutingDecision::Path::LocalCPU;
                decision.estimatedWaitMs = localCapacity_.localQueueDepth.load() * 50;
                decision.reason = "Local CPU execution (GPU busy)";
                decision.metadata.executedQuant = decision.metadata.requestedQuant;
                return QueueLocal(request);
            }

            // Fall through to remote
            [[fallthrough]];
        }

        case RoutingPolicy::PreferRemote: {
            // Always try remote first to keep local free
            auto schedulerDecision = RPCScheduler::Instance().Schedule(request);

            if (schedulerDecision.action == SchedulingDecision::Action::Route ||
                schedulerDecision.action == SchedulingDecision::Action::Fallback) {
                decision.path = RoutingDecision::Path::RemoteNode;
                decision.targetNodeId = schedulerDecision.targetNodeId;
                decision.estimatedWaitMs = schedulerDecision.estimatedLatencyMs;
                decision.reason = schedulerDecision.reason;
                decision.metadata.executedQuant = Deep2::QuantTypeToString(schedulerDecision.selectedFormat);
                if (schedulerDecision.action == SchedulingDecision::Action::Fallback) {
                    decision.metadata.fallbackReason = schedulerDecision.reason;
                }

                DispatchRemote(request, schedulerDecision.targetNodeId);
                return decision;
            }

            // Remote failed, queue locally
            decision.path = RoutingDecision::Path::QueuedLocal;
            decision.reason = "Remote unavailable, queued locally";
            return QueueLocal(request);
        }

        case RoutingPolicy::Balanced: {
            // Compare queue depths
            uint32_t localDepth = localCapacity_.localQueueDepth.load();
            auto clusterStatus = RPCScheduler::Instance().GetClusterStatus();

            if (clusterStatus.healthyNodes > 0 && localDepth > 5) {
                // Remote has capacity, local is busy
                auto schedulerDecision = RPCScheduler::Instance().Schedule(request);
                if (schedulerDecision.action == SchedulingDecision::Action::Route) {
                    decision.path = RoutingDecision::Path::RemoteNode;
                    decision.targetNodeId = schedulerDecision.targetNodeId;
                    decision.estimatedWaitMs = schedulerDecision.estimatedLatencyMs;
                    decision.reason = "Load balanced to remote";
                    DispatchRemote(request, schedulerDecision.targetNodeId);
                    return decision;
                }
            }

            // Default to local
            decision.path = RoutingDecision::Path::LocalCPU;
            return QueueLocal(request);
        }

        case RoutingPolicy::LatencyOptimized: {
            // Estimate latency for each path
            uint32_t localLatency = localCapacity_.localQueueDepth.load() * 50 +
                                   (1000 / std::max(localCapacity_.localTokensPerSecond.load(), 1u));

            auto schedulerDecision = RPCScheduler::Instance().Schedule(request);
            uint32_t remoteLatency = (schedulerDecision.action == SchedulingDecision::Action::Route)
                ? schedulerDecision.estimatedLatencyMs + 5  // +5ms network overhead
                : UINT32_MAX;

            if (remoteLatency < localLatency && schedulerDecision.action == SchedulingDecision::Action::Route) {
                decision.path = RoutingDecision::Path::RemoteNode;
                decision.targetNodeId = schedulerDecision.targetNodeId;
                decision.estimatedWaitMs = remoteLatency;
                decision.reason = "Remote path has lower latency";
                DispatchRemote(request, schedulerDecision.targetNodeId);
            } else {
                decision.path = RoutingDecision::Path::LocalCPU;
                decision.estimatedWaitMs = localLatency;
                decision.reason = "Local path has lower latency";
                QueueLocal(request);
            }

            return decision;
        }
    }

    // Should not reach here
    decision.path = RoutingDecision::Path::Rejected;
    decision.reason = "No valid routing path";
    return decision;
}

std::future<InferenceResult> AdmissionController::ExecuteLocal(const InferenceRequest& request) {
    auto promise = std::make_shared<std::promise<InferenceResult>>();
    auto future = promise->get_future();

    // Spawn local execution thread
    std::thread([promise, request]() {
        // Simulate local execution
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        InferenceResult result;
        result.success = true;
        result.tokensGenerated = request.maxTokens;
        result.inferenceTimeUs = 50000;

        promise->set_value(result);
    }).detach();

    return future;
}

RoutingDecision AdmissionController::QueueLocal(const InferenceRequest& request) {
    std::lock_guard<std::mutex> lock(queueMutex_);

    localQueue_.push(request);
    uint32_t position = localQueue_.size();

    RoutingDecision decision;
    decision.path = RoutingDecision::Path::QueuedLocal;
    decision.queuePosition = position;
    decision.estimatedWaitMs = position * 50;  // 50ms per request estimate
    decision.reason = "Queued for local execution";

    return decision;
}

void AdmissionController::DispatchRemote(const InferenceRequest& request,
                                        const std::string& nodeId) {
    // Async dispatch - don't wait
    std::thread([request, nodeId]() {
        // This would call ZeroMQ transport
        // For now, simulate async completion
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Notify completion via callback
        InferenceResult result;
        result.success = true;
        result.tokensGenerated = request.maxTokens;

        // Store result for pickup
        AsyncInferenceManager::Instance().SubmitWithCallback(
            request,
            [result](const InferenceResult& res, const RoutingDecision::ExecutionMetadata& meta) {
                (void)res;
                (void)meta;
                // Callback handled by IDE
            }
        );
    }).detach();
}

void AdmissionController::ProcessLocalQueue() {
    while (running_) {
        std::unique_lock<std::mutex> lock(queueMutex_);

        if (!localQueue_.empty()) {
            auto request = localQueue_.front();
            localQueue_.pop();
            lock.unlock();

            // Execute locally
            ExecuteLocal(request);
        } else {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

AdmissionController::QueueStatus AdmissionController::GetQueueStatus() const {
    std::lock_guard<std::mutex> lock(queueMutex_);

    QueueStatus status;
    status.localQueueDepth = localQueue_.size();
    status.remoteQueueDepth = 0;  // TODO: Track remote queue
    status.totalPending = status.localQueueDepth + status.remoteQueueDepth;
    status.avgWaitTimeMs = status.localQueueDepth * 50;

    return status;
}

void AdmissionController::UpdateLocalCapacity(const LocalCapacity& capacity) {
    localCapacity_ = capacity;
}

/*===========================================================================
 * Async Inference Manager Implementation
 *===========================================================================*/

AsyncInferenceManager& AsyncInferenceManager::Instance() {
    static AsyncInferenceManager instance;
    return instance;
}

std::future<InferenceResult> AsyncInferenceManager::Submit(const InferenceRequest& request) {
    auto promise = std::make_shared<std::promise<InferenceResult>>();
    auto future = promise->get_future();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_[request.requestId] = promise;
    }

    // Route through admission controller
    auto decision = AdmissionController::Instance().Route(request);

    if (decision.path == RoutingDecision::Path::Rejected) {
        InferenceResult result;
        result.success = false;
        result.errorMessage = "Request rejected: " + decision.reason;
        promise->set_value(result);
    }

    return future;
}

void AsyncInferenceManager::SubmitWithCallback(const InferenceRequest& request,
                                               CompletionCallback callback) {
    // Store callback and execute
    auto future = Submit(request);

    // Spawn watcher thread
    std::thread([future = std::move(future), callback]() mutable {
        try {
            auto result = future.get();
            RoutingDecision::ExecutionMetadata meta;  // TODO: Populate
            callback(result, meta);
        } catch (...) {
            InferenceResult result;
            result.success = false;
            result.errorMessage = "Exception during inference";
            RoutingDecision::ExecutionMetadata meta;
            callback(result, meta);
        }
    }).detach();
}

bool AsyncInferenceManager::Cancel(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pending_.find(requestId);
    if (it != pending_.end()) {
        InferenceResult result;
        result.success = false;
        result.errorMessage = "Cancelled by user";
        it->second->set_value(result);
        pending_.erase(it);
        return true;
    }
    return false;
}

AsyncInferenceManager::RequestStatus AsyncInferenceManager::GetStatus(
    const std::string& requestId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.find(requestId) != pending_.end()) {
        return RequestStatus::Pending;
    }
    return RequestStatus::Completed;  // Or failed/cancelled
}

} // namespace RPC
} // namespace RawrXD

/*===========================================================================
 * C API Implementation
 *===========================================================================*/

extern "C" {

using namespace RawrXD::RPC;

__declspec(dllexport)
int SovereignAdmission_Init(int routingPolicy) {
    AdmissionController::Instance().Initialize(LocalCapacity{});
    AdmissionController::Instance().SetRoutingPolicy(
        static_cast<AdmissionController::RoutingPolicy>(routingPolicy));
    return 1;
}

__declspec(dllexport)
int SovereignAdmission_Route(const char* modelHash, uint64_t modelParams,
                             int preferredQuant, int* outPath,
                             char* outNodeId, size_t nodeIdSize,
                             uint32_t* outQueuePosition, uint32_t* outWaitMs) {
    InferenceRequest request;
    request.modelHash = modelHash;
    request.modelParams = modelParams;
    request.preferredFormat = static_cast<Deep2::QuantType>(preferredQuant);

    auto decision = AdmissionController::Instance().Route(request);

    *outPath = static_cast<int>(decision.path);
    *outQueuePosition = decision.queuePosition;
    *outWaitMs = decision.estimatedWaitMs;

    if (!decision.targetNodeId.empty()) {
        strncpy_s(outNodeId, nodeIdSize, decision.targetNodeId.c_str(), _TRUNCATE);
    }

    return (decision.path != RoutingDecision::Path::Rejected) ? 1 : 0;
}

__declspec(dllexport)
int SovereignAdmission_IsModelResident(const char* modelHash) {
    return AdmissionController::Instance().IsModelResident(modelHash) ? 1 : 0;
}

__declspec(dllexport)
void SovereignAdmission_GetQueueStatus(uint32_t* outLocalDepth,
                                      uint32_t* outRemoteDepth,
                                      uint32_t* outAvgWaitMs) {
    auto status = AdmissionController::Instance().GetQueueStatus();
    *outLocalDepth = status.localQueueDepth;
    *outRemoteDepth = status.remoteQueueDepth;
    *outAvgWaitMs = status.avgWaitTimeMs;
}

} // extern "C"
