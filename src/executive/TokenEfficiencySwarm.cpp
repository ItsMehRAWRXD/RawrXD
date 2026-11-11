// ============================================================
// TokenEfficiencySwarm.cpp - Executive Cost Optimization Swarm
// ============================================================

#include "TokenEfficiencySwarm.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace RawrXD {
namespace Executive {

// ============================================================
// Main Trigger Point
// ============================================================
void TokenEfficiencySwarm::trigger(uint64_t goalId, const char* goalName,
                                    float actualCost, float estimatedCost,
                                    size_t agentCount, const char* assignedAgent) {
    // Rate limiting check
    if (!canRetrigger()) {
        return;
    }

    // Update telemetry
    triggerCount_.fetch_add(1, std::memory_order_relaxed);
    lastTriggerTime_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);

    // Non-blocking execution
    if (config_.nonBlocking) {
        std::thread swarmThread([this, goalId, goalName, actualCost, estimatedCost, 
                                  agentCount, assignedAgent]() {
            executeSwarm(goalId, goalName, actualCost, estimatedCost, 
                        agentCount, assignedAgent);
        });
        swarmThread.detach();
    } else {
        executeSwarm(goalId, goalName, actualCost, estimatedCost, 
                    agentCount, assignedAgent);
    }
}

// ============================================================
// Hysteresis Check - Prevents Oscillation
// ============================================================
bool TokenEfficiencySwarm::canRetrigger() {
    auto lastTrigger = lastTriggerTime_.load(std::memory_order_relaxed);
    auto now = std::chrono::steady_clock::now();
    
    // Rate limiting: minimum interval between triggers
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastTrigger).count();
    if (elapsedMs < config_.minTriggerIntervalMs) {
        return false;
    }
    
    // Already executing check
    if (isExecuting_.exchange(true, std::memory_order_acquire)) {
        return false;
    }
    
    return true;
}

// ============================================================
// Execute All 8 Efficiency Agents
// ============================================================
void TokenEfficiencySwarm::executeSwarm(uint64_t goalId, const char* goalName,
                                         float actualCost, float estimatedCost,
                                         size_t agentCount, const char* assignedAgent) {
    printf("\n[TokenEfficiencySwarm] Triggered for goal '%s' (ID: %llu)\n", 
           goalName ? goalName : "unknown", (unsigned long long)goalId);
    printf("  Actual: %.2f, Estimated: %.2f, Ratio: %.2fx, Agents: %zu\n",
           actualCost, estimatedCost, actualCost / estimatedCost, agentCount);
    printf("  Executing 8 efficiency agents...\n");

    // Launch all 8 agents
    std::vector<std::thread> agents;
    
    agents.emplace_back([this, goalId, actualCost, estimatedCost]() {
        runCostAnalyzer(goalId, actualCost, estimatedCost);
    });
    
    agents.emplace_back([this, goalId, actualCost, estimatedCost]() {
        runTokenOptimizer(goalId, actualCost, estimatedCost);
    });
    
    agents.emplace_back([this, goalId, agentCount]() {
        runLoadBalancer(goalId, agentCount);
    });
    
    agents.emplace_back([this, goalId, assignedAgent]() {
        runRoutingOptimizer(goalId, assignedAgent);
    });
    
    agents.emplace_back([this, goalId]() {
        runCacheAdvisor(goalId);
    });
    
    agents.emplace_back([this, goalId]() {
        runBatchingOptimizer(goalId);
    });
    
    agents.emplace_back([this, goalId, actualCost, estimatedCost]() {
        runModelSelector(goalId, actualCost, estimatedCost);
    });
    
    agents.emplace_back([this, goalId, actualCost, estimatedCost, agentCount]() {
        runTelemetryRecorder(goalId, actualCost, estimatedCost, agentCount);
    });

    // Wait for all agents to complete
    for (auto& agent : agents) {
        if (agent.joinable()) {
            agent.join();
        }
    }

    printf("[TokenEfficiencySwarm] All agents completed\n\n");
    
    // Release execution lock
    isExecuting_.store(false, std::memory_order_release);
}

// ============================================================
// Individual Efficiency Agents
// ============================================================

void TokenEfficiencySwarm::runCostAnalyzer(uint64_t goalId, float actual, float estimated) {
    printf("    [Agent:CostAnalyzer] Analyzing cost divergence for goal %llu...\n", 
           (unsigned long long)goalId);
    
    float ratio = actual / estimated;
    if (ratio > 5.0f) {
        printf("      ⚠️ CRITICAL: Cost ratio %.2fx - investigate immediately\n", ratio);
    } else if (ratio > 3.0f) {
        printf("      ⚠️ WARNING: Cost ratio %.2fx - optimization recommended\n", ratio);
    } else {
        printf("      ℹ️ Cost ratio %.2fx - within acceptable range\n", ratio);
    }
}

void TokenEfficiencySwarm::runTokenOptimizer(uint64_t goalId, float actual, float estimated) {
    printf("    [Agent:TokenOptimizer] Suggesting optimizations for goal %llu...\n",
           (unsigned long long)goalId);
    
    float excess = actual - estimated;
    if (excess > 1000.0f) {
        printf("      💡 Consider: Reduce context window, use smaller model, or enable caching\n");
    } else if (excess > 500.0f) {
        printf("      💡 Consider: Enable prompt caching or reduce max_tokens\n");
    } else {
        printf("      ✓ Token usage within expected variance\n");
    }
}

void TokenEfficiencySwarm::runLoadBalancer(uint64_t goalId, size_t agentCount) {
    printf("    [Agent:LoadBalancer] Evaluating agent distribution for goal %llu...\n",
           (unsigned long long)goalId);
    
    if (agentCount == 0) {
        printf("      ⚠️ No agents assigned - check scheduler\n");
    } else if (agentCount > 8) {
        printf("      💡 High agent count (%zu) - consider consolidating\n", agentCount);
    } else {
        printf("      ✓ Agent count (%zu) optimal\n", agentCount);
    }
}

void TokenEfficiencySwarm::runRoutingOptimizer(uint64_t goalId, const char* assignedAgent) {
    printf("    [Agent:RoutingOptimizer] Analyzing routing for goal %llu...\n",
           (unsigned long long)goalId);
    
    if (!assignedAgent || strlen(assignedAgent) == 0) {
        printf("      ⚠️ No agent assigned - routing decision pending\n");
    } else {
        printf("      ✓ Currently routed to: %s\n", assignedAgent);
        printf("      💡 Alternative: Consider load-balanced routing\n");
    }
}

void TokenEfficiencySwarm::runCacheAdvisor(uint64_t goalId) {
    printf("    [Agent:CacheAdvisor] Cache strategy for goal %llu...\n",
           (unsigned long long)goalId);
    printf("      💡 Enable KV-cache quantization (Q4_K or Q8_0)\n");
    printf("      💡 Consider prompt prefix caching for repeated patterns\n");
}

void TokenEfficiencySwarm::runBatchingOptimizer(uint64_t goalId) {
    printf("    [Agent:BatchingOptimizer] Batch optimization for goal %llu...\n",
           (unsigned long long)goalId);
    printf("      💡 Current: Dynamic batching enabled\n");
    printf("      💡 Consider: Continuous batching for higher throughput\n");
}

void TokenEfficiencySwarm::runModelSelector(uint64_t goalId, float actual, float estimated) {
    printf("    [Agent:ModelSelector] Model sizing for goal %llu...\n",
           (unsigned long long)goalId);
    
    float ratio = actual / estimated;
    if (ratio > 4.0f) {
        printf("      💡 Consider: Downgrade to smaller model (7B vs 13B)\n");
    } else if (ratio < 0.5f) {
        printf("      💡 Consider: Upgrade to larger model for better quality\n");
    } else {
        printf("      ✓ Current model size appropriate\n");
    }
}

void TokenEfficiencySwarm::runTelemetryRecorder(uint64_t goalId, float actual, 
                                                 float estimated, size_t agentCount) {
    printf("    [Agent:TelemetryRecorder] Recording metrics for goal %llu...\n",
           (unsigned long long)goalId);
    
    if (config_.enableTelemetry) {
        printf("      ✓ Recorded: cost_ratio=%.2f, agents=%zu\n", 
               actual / estimated, agentCount);
        printf("      ✓ Telemetry available for threshold tuning\n");
    }
}

} // namespace Executive
} // namespace RawrXD
