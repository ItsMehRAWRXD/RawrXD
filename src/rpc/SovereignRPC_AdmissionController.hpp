/*===========================================================================
 * SovereignRPC_AdmissionController.hpp
 *
 * Local admission controller for Ghost Text fast path
 *
 * Design: Scheduler sits OFF the GhostText critical path
 *
 * Flow:
 *   GhostText Request
 *       |
 *       v
 *   AdmissionController::Route()
 *       |
 *       +-- Local GPU available? --> Execute locally (fast path)
 *       |
 *       +-- Local CPU only? --> Queue for local execution
 *       |
 *       +-- Remote nodes available? --> Async RPC dispatch
 *       |
 *       +-- All paths congested? --> Queue with position feedback
 *
 * Key: GhostText never blocks on network I/O
 *===========================================================================*/

#pragma once

#include "SovereignRPC_Scheduler.hpp"
#include <atomic>
#include <queue>
#include <future>

namespace RawrXD {
namespace RPC {

/*===========================================================================
 * Routing Decision
 *===========================================================================*/
struct RoutingDecision {
    enum class Path {
        LocalGPU,       // Fast path - local Vulkan/Metal/CUDA
        LocalCPU,       // Local CPU inference (slow but available)
        RemoteNode,     // RPC to worker node
        QueuedLocal,    // Queued for local execution
        QueuedRemote,   // Queued for remote execution
        Rejected        // All paths congested
    };

    Path path;
    std::string targetNodeId;      // For RemoteNode
    uint32_t queuePosition;        // For Queued*
    uint32_t estimatedWaitMs;      // User-facing ETA
    std::string reason;            // Debug/analysis

    // For response metadata
    struct ExecutionMetadata {
        std::string requestedQuant;
        std::string executedQuant;
        std::string fallbackReason;
        uint64_t schedulingLatencyUs;
        uint64_t queueWaitMs;
        uint64_t inferenceTimeMs;
    };
    ExecutionMetadata metadata;
};

/*===========================================================================
 * Local Capacity Tracker
 *===========================================================================*/
struct LocalCapacity {
    std::atomic<bool> gpuAvailable{true};
    std::atomic<bool> cpuAvailable{true};
    std::atomic<uint32_t> localQueueDepth{0};
    std::atomic<uint32_t> localTokensPerSecond{0};
    std::atomic<uint64_t> localFreeVRAM{0};
    std::vector<std::string> locallyLoadedModels;
    mutable std::mutex mutex_;

    bool CanExecuteLocal(const InferenceRequest& request) const {
        if (gpuAvailable.load() && localFreeVRAM.load() > 1000) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& model : locallyLoadedModels) {
                if (model == request.modelHash) {
                    return true;  // Model resident
                }
            }
        }
        return false;
    }

    bool IsModelResident(const std::string& modelHash) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::find(locallyLoadedModels.begin(),
                        locallyLoadedModels.end(),
                        modelHash) != locallyLoadedModels.end();
    }
};

/*===========================================================================
 * Admission Controller
 * GhostText-facing interface (never blocks on network)
 *===========================================================================*/
class AdmissionController {
public:
    static AdmissionController& Instance();

    // Initialize with local capacity
    void Initialize(const LocalCapacity& localCapacity);

    // Main routing entry point (called from GhostText)
    // Returns immediately with routing decision
    // Actual execution happens asynchronously
    RoutingDecision Route(const InferenceRequest& request);

    // Execute locally (fast path)
    // Returns future for async result
    std::future<InferenceResult> ExecuteLocal(const InferenceRequest& request);

    // Queue for local execution
    RoutingDecision QueueLocal(const InferenceRequest& request);

    // Dispatch to remote node (async)
    void DispatchRemote(const InferenceRequest& request,
                       const std::string& nodeId);

    // Get current queue status
    struct QueueStatus {
        uint32_t localQueueDepth;
        uint32_t remoteQueueDepth;
        uint32_t totalPending;
        uint32_t avgWaitTimeMs;
    };
    QueueStatus GetQueueStatus() const;

    // Update local capacity (called by local runtime)
    void UpdateLocalCapacity(const LocalCapacity& capacity);

    // Set routing policy
    enum class RoutingPolicy {
        PreferLocal,      // Try local first, then remote
        PreferRemote,     // Offload to remote, keep local free
        Balanced,         // Load balance based on queue depth
        LatencyOptimized  // Choose lowest latency path
    };
    void SetRoutingPolicy(RoutingPolicy policy) { policy_ = policy; }

private:
    AdmissionController() = default;

    // Internal queue management
    std::queue<InferenceRequest> localQueue_;
    std::queue<InferenceRequest> remoteQueue_;
    mutable std::mutex queueMutex_;

    LocalCapacity localCapacity_;
    RoutingPolicy policy_ = RoutingPolicy::PreferLocal;

    // Queue processing threads
    std::thread localQueueProcessor_;
    std::atomic<bool> running_{false};

    void ProcessLocalQueue();
    RoutingDecision ApplyPolicy(const InferenceRequest& request);
};

/*===========================================================================
 * Async Inference Interface
 * Non-blocking GhostText integration
 *===========================================================================*/
class AsyncInferenceManager {
public:
    static AsyncInferenceManager& Instance();

    // Submit request and get future
    std::future<InferenceResult> Submit(const InferenceRequest& request);

    // Submit with callback (for UI updates)
    using CompletionCallback = std::function<void(const InferenceResult&, const RoutingDecision::ExecutionMetadata&)>;
    void SubmitWithCallback(const InferenceRequest& request, CompletionCallback callback);

    // Cancel pending request
    bool Cancel(const std::string& requestId);

    // Get request status
    enum class RequestStatus {
        Pending,
        Routing,
        Queued,
        Executing,
        Completed,
        Failed,
        Cancelled
    };
    RequestStatus GetStatus(const std::string& requestId) const;

private:
    AsyncInferenceManager() = default;
    std::unordered_map<std::string, std::shared_ptr<std::promise<InferenceResult>>> pending_;
    mutable std::mutex mutex_;
};

} // namespace RPC
} // namespace RawrXD

/*===========================================================================
 * C API for IDE Integration
 *===========================================================================*/

extern "C" {

// Initialize admission controller
__declspec(dllexport)
int SovereignAdmission_Init(int routingPolicy);

// Route request (non-blocking)
__declspec(dllexport)
int SovereignAdmission_Route(const char* modelHash, uint64_t modelParams,
                             int preferredQuant, int* outPath,
                             char* outNodeId, size_t nodeIdSize,
                             uint32_t* outQueuePosition, uint32_t* outWaitMs);

// Check if model is resident locally
__declspec(dllexport)
int SovereignAdmission_IsModelResident(const char* modelHash);

// Get queue status
__declspec(dllexport)
void SovereignAdmission_GetQueueStatus(uint32_t* outLocalDepth,
                                      uint32_t* outRemoteDepth,
                                      uint32_t* outAvgWaitMs);

} // extern "C"
