// ============================================================
// EfficiencyBridge.hpp - Minimal Bridge: Executive → ProxyHotpatcher
// ============================================================
// Wires Executive cost tracking into existing ProxyHotpatcher validator system
// WITHOUT modifying ProxyHotpatcher. Uses function pointers only.
//
// Total new code: ~20 lines
// ============================================================

#pragma once

#include "TokenEfficiencySwarm.hpp"
#include <cstddef>
#include <cstdint>

namespace RawrXD {

// ============================================================
// Cost-Aware Context Extension
// ============================================================
struct EfficiencyBridgeContext {
    // Existing proxy context fields (mirrors whatever ProxyHotpatcher uses)
    const char* requestText;
    const char* responseText;
    size_t requestLen;
    size_t responseLen;
    
    // NEW: Cost fields populated from Executive
    float actualCost;
    float estimatedCost;
    size_t agentCount;
    uint64_t goalId;
    const char* goalName;
    const char* assignedAgent;
};

// ============================================================
// Bridge Validator - Registered with existing ProxyHotpatcher
// ============================================================
// This function conforms to the existing validator signature
// used by ProxyHotpatcher (void* context → PatchResult)
//
// To register with ProxyHotpatcher:
//   ProxyHotpatcher::getInstance().addValidator(
//       "efficiency_bridge", efficiencyBridgeValidator);
//
// Or via Win32IDE command ID 9012 (Custom Validator)
// ============================================================

// PatchResult-compatible return structure (simplified)
struct BridgePatchResult {
    bool success;
    const char* message;
    
    static BridgePatchResult ok(const char* msg) { 
        return {true, msg}; 
    }
    static BridgePatchResult error(const char* msg) { 
        return {false, msg}; 
    }
};

// The bridge validator - callable via function pointer
inline BridgePatchResult efficiencyBridgeValidator(void* rawCtx) {
    auto* ctx = static_cast<EfficiencyBridgeContext*>(rawCtx);
    
    // Null check
    if (!ctx) {
        return BridgePatchResult::error("null_context");
    }
    
    // Prevent divide-by-zero
    if (ctx->estimatedCost <= 0.0f) {
        return BridgePatchResult::ok("no_estimate");
    }
    
    // Get swarm configuration
    auto& swarm = Executive::TokenEfficiencySwarm::getInstance();
    const auto& config = swarm.getConfig();
    
    // THE ONE-LINER: Check if cost exceeds threshold
    if (ctx->actualCost > config.triggerThreshold * ctx->estimatedCost) {
        // Fire efficiency swarm (non-blocking)
        swarm.trigger(
            ctx->goalId,
            ctx->goalName,
            ctx->actualCost,
            ctx->estimatedCost,
            ctx->agentCount,
            ctx->assignedAgent
        );
        
        return BridgePatchResult::ok("efficiency_swarm_triggered");
    }
    
    return BridgePatchResult::ok("within_threshold");
}

// ============================================================
// C-API for function pointer compatibility
// ============================================================
extern "C" {
    // Function pointer type matching ProxyHotpatcher expectations
    typedef BridgePatchResult (*BridgeValidatorFn)(void*);
    
    // Export the validator function
    inline BridgePatchResult EfficiencyBridgeValidator(void* ctx) {
        return efficiencyBridgeValidator(ctx);
    }
    
    // Get function pointer for registration
    inline BridgeValidatorFn GetEfficiencyBridgeValidator() {
        return EfficiencyBridgeValidator;
    }
}

// ============================================================
// ONE-LINE INSTALLATION
// ============================================================
// 
// From AutonomousLoop ACT phase:
//
//   EfficiencyBridgeContext ctx;
//   ctx.actualCost = actionResults.tokensConsumed;
//   ctx.estimatedCost = plan.estimatedCost;
//   ctx.agentCount = scheduler.getActiveAgentCount();
//   ctx.goalId = currentGoalId;
//   ctx.goalName = currentGoalName;
//   ctx.assignedAgent = currentAgentRole;
//
//   auto result = efficiencyBridgeValidator(&ctx);
//
// ============================================================

} // namespace RawrXD
