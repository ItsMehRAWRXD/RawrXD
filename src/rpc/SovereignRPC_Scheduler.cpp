/*===========================================================================
 * SovereignRPC_Scheduler.cpp
 *
 * Implementation of VRAM-aware distributed RPC scheduler
 *
 * Scheduling Algorithm:
 *   1. Filter: Nodes supporting requested format
 *   2. Filter: Nodes with sufficient VRAM
 *   3. Score:  latency_weight * distance + load_weight * utilization
 *   4. Select: Highest score wins
 *   5. Fallback: Try lower quantization if no nodes available
 *===========================================================================*/

#include "SovereignRPC_Scheduler.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>

namespace RawrXD {
namespace RPC {

/*===========================================================================
 * RPC Scheduler Implementation
 *===========================================================================*/

RPCScheduler& RPCScheduler::Instance() {
    static RPCScheduler instance;
    return instance;
}

void RPCScheduler::Initialize(FallbackPolicy policy) {
    fallbackPolicy_ = policy;
    // Start background cleanup thread
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            CleanupStaleNodes();
        }
    }).detach();
}

void RPCScheduler::RegisterNode(const NodeCapabilities& caps) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[caps.nodeId] = caps;
}

void RPCScheduler::UpdateNode(const std::string& nodeId, const NodeCapabilities& caps) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[nodeId] = caps;
}

void RPCScheduler::RemoveNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(nodeId);
}

void RPCScheduler::NodeHeartbeat(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        it->second.lastHeartbeat = std::chrono::steady_clock::now();
        it->second.healthy = true;
    }
}

SchedulingDecision RPCScheduler::Schedule(const InferenceRequest& request) {
    auto start = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    ++metrics_.totalRequests;

    // Try preferred format first
    std::string bestNode = FindBestNode(request, request.preferredFormat);

    if (!bestNode.empty()) {
        auto end = std::chrono::steady_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        metrics_.avgSchedulingLatencyUs = 
            (metrics_.avgSchedulingLatencyUs * (metrics_.routedRequests) + latency) 
            / (metrics_.routedRequests + 1);
        ++metrics_.routedRequests;

        return SchedulingDecision{
            SchedulingDecision::Action::Route,
            bestNode,
            request.preferredFormat,
            "Node selected based on VRAM capacity and load",
            50,  // estimated latency
            0
        };
    }

    // No node available for preferred format - try fallback
    return TryFallback(request);
}

std::string RPCScheduler::FindBestNode(const InferenceRequest& request, Deep2::QuantType format) {
    std::string bestNodeId;
    double bestScore = -1.0;

    for (const auto& [nodeId, node] : nodes_) {
        // Filter 1: Must support format
        if (!node.SupportsFormat(format)) continue;

        // Filter 2: Must have enough VRAM
        if (!node.HasEnoughVRAM(request.modelParams, format)) continue;

        // Filter 3: Must be healthy
        if (!node.healthy) continue;

        // Score node
        double score = ScoreNode(node, request);
        if (score > bestScore) {
            bestScore = score;
            bestNodeId = nodeId;
        }
    }

    return bestNodeId;
}

double RPCScheduler::ScoreNode(const NodeCapabilities& node, const InferenceRequest& request) {
    // Scoring weights
    const double LOAD_WEIGHT = 0.4;
    const double LATENCY_WEIGHT = 0.3;
    const double THROUGHPUT_WEIGHT = 0.3;

    // Load score (lower load = higher score)
    double loadScore = 1.0 - node.currentLoad;

    // Latency score (based on tokens/sec, higher = better)
    double latencyScore = std::min(node.tokensPerSecond / 100.0, 1.0);

    // Throughput score (based on free VRAM, more = better for large batches)
    double vramRatio = static_cast<double>(node.freeVRAM_MB) / node.totalVRAM_MB;
    double throughputScore = vramRatio;

    // Combine scores
    return LOAD_WEIGHT * loadScore + 
           LATENCY_WEIGHT * latencyScore + 
           THROUGHPUT_WEIGHT * throughputScore;
}

SchedulingDecision RPCScheduler::TryFallback(const InferenceRequest& request) {
    switch (fallbackPolicy_) {
        case FallbackPolicy::Downgrade: {
            // Try format downgrade chain: Q6 -> Q5 -> Q4
            std::vector<Deep2::QuantType> fallbackChain = {
                Deep2::QuantType::Q6_K,
                Deep2::QuantType::Q5_K_M,
                Deep2::QuantType::Q4_K_M
            };

            for (auto fmt : fallbackChain) {
                if (fmt == request.preferredFormat) continue;
                if (fmt < request.minimumFormat) continue;  // Don't go below minimum

                std::string node = FindBestNode(request, fmt);
                if (!node.empty()) {
                    ++metrics_.fallbackRequests;
                    return SchedulingDecision{
                        SchedulingDecision::Action::Fallback,
                        node,
                        fmt,
                        "Downgraded from " + std::string(Deep2::QuantTypeToString(request.preferredFormat)) +
                        " to " + std::string(Deep2::QuantTypeToString(fmt)),
                        100,  // slightly higher latency
                        0
                    };
                }
            }
            break;
        }

        case FallbackPolicy::QueueAndWait: {
            ++metrics_.queuedRequests;
            return SchedulingDecision{
                SchedulingDecision::Action::Queue,
                "",
                request.preferredFormat,
                "No nodes available, queued for retry",
                0,
                static_cast<uint32_t>(metrics_.queuedRequests)
            };
        }

        case FallbackPolicy::Reject:
        default:
            break;
    }

    // No fallback available - reject
    ++metrics_.rejectedRequests;
    return SchedulingDecision{
        SchedulingDecision::Action::Reject,
        "",
        request.preferredFormat,
        "No nodes available with required format and VRAM",
        0,
        0
    };
}

void RPCScheduler::CleanupStaleNodes() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(60);

    for (auto it = nodes_.begin(); it != nodes_.end();) {
        if (now - it->second.lastHeartbeat > timeout) {
            it->second.healthy = false;
            // Actually remove after 5 minutes
            if (now - it->second.lastHeartbeat > std::chrono::seconds(300)) {
                it = nodes_.erase(it);
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
}

RPCScheduler::ClusterStatus RPCScheduler::GetClusterStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ClusterStatus status = {};

    for (const auto& [nodeId, node] : nodes_) {
        ++status.totalNodes;
        if (node.healthy) {
            ++status.healthyNodes;
            status.totalVRAM_MB += node.totalVRAM_MB;
            status.freeVRAM_MB += node.freeVRAM_MB;
            status.aggregateTPS += node.tokensPerSecond;
        }
    }

    return status;
}

} // namespace RPC
} // namespace RawrXD

/*===========================================================================
 * C API Implementation
 *===========================================================================*/

extern "C" {

using namespace RawrXD::RPC;

__declspec(dllexport)
int SovereignRPC_Init(const char* bindAddress, int fallbackPolicy) {
    (void)bindAddress;  // TODO: Initialize gRPC server
    auto policy = static_cast<FallbackPolicy>(fallbackPolicy);
    RPCScheduler::Instance().Initialize(policy);
    return 1;
}

__declspec(dllexport)
int SovereignRPC_RegisterNode(const char* nodeId, const char* address,
                               uint64_t vramMB, int* supportedFormats, int numFormats) {
    NodeCapabilities caps;
    caps.nodeId = nodeId;
    caps.address = address;
    caps.totalVRAM_MB = vramMB;
    caps.freeVRAM_MB = vramMB;  // Initially all free
    caps.healthy = true;
    caps.lastHeartbeat = std::chrono::steady_clock::now();

    for (int i = 0; i < numFormats; ++i) {
        caps.supportedFormats.push_back(static_cast<Deep2::QuantType>(supportedFormats[i]));
    }

    RPCScheduler::Instance().RegisterNode(caps);
    return 1;
}

__declspec(dllexport)
int SovereignRPC_Schedule(const char* modelHash, uint64_t modelParams,
                          int preferredFormat, int minFormat,
                          char* outNodeId, size_t nodeIdSize,
                          int* outSelectedFormat) {
    InferenceRequest request;
    request.modelHash = modelHash;
    request.modelParams = modelParams;
    request.preferredFormat = static_cast<Deep2::QuantType>(preferredFormat);
    request.minimumFormat = static_cast<Deep2::QuantType>(minFormat);

    auto decision = RPCScheduler::Instance().Schedule(request);

    if (decision.action == SchedulingDecision::Action::Route ||
        decision.action == SchedulingDecision::Action::Fallback) {
        strncpy_s(outNodeId, nodeIdSize, decision.targetNodeId.c_str(), _TRUNCATE);
        *outSelectedFormat = static_cast<int>(decision.selectedFormat);
        return 1;
    }

    return 0;  // Failed to schedule
}

__declspec(dllexport)
void SovereignRPC_GetClusterStatus(uint32_t* outTotalNodes, uint32_t* outHealthyNodes,
                                   uint64_t* outTotalVRAM, uint64_t* outFreeVRAM) {
    auto status = RPCScheduler::Instance().GetClusterStatus();
    *outTotalNodes = status.totalNodes;
    *outHealthyNodes = status.healthyNodes;
    *outTotalVRAM = status.totalVRAM_MB;
    *outFreeVRAM = status.freeVRAM_MB;
}

} // extern "C"
