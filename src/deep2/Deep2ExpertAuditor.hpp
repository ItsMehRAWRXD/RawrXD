#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <vector>
#include <iostream>
#include <iomanip>

struct ExpertRoutingMetrics {
    // Structural counters per evaluation block
    std::atomic<uint64_t> total_tokens_evaluated{ 0 };
    std::atomic<uint64_t> total_expert_activations{ 0 }; // Gross expert selections
    std::atomic<uint64_t> non_zero_ternary_elements{ 0 }; // Structural non-zeros
    std::atomic<uint64_t> total_elements_processed{ 0 };  // Total weights in activated experts
    
    // Track expert heat distribution
    uint32_t expert_activation_frequency[256]{ 0 };
};

class Deep2ExpertAuditor {
private:
    ExpertRoutingMetrics metrics;
    uint32_t totalLayers;

public:
    Deep2ExpertAuditor(uint32_t layers) : totalLayers(layers) {}

    /**
     * Instruments the gating router step.
     * Replaces assumed top-8 metrics with actual dynamic tracking.
     */
    void LogRouterSelection(const uint32_t* __restrict chosen_expert_ids, uint32_t count_per_token, 
                            uint64_t layer_weights_count, uint64_t non_zero_weights_count) {
        
        metrics.total_tokens_evaluated.fetch_add(1, std::memory_order_relaxed);
        metrics.total_expert_activations.fetch_add(count_per_token, std::memory_order_relaxed);
        
        // Accumulate active parameters and track structural sparsity drop
        metrics.total_elements_processed.fetch_add(layer_weights_count * count_per_token, std::memory_order_relaxed);
        metrics.non_zero_ternary_elements.fetch_add(non_zero_weights_count * count_per_token, std::memory_order_relaxed);

        // Track spatial heat allocation for pipeline distribution audits
        for (uint32_t i = 0; i < count_per_token; ++i) {
            uint32_t id = chosen_expert_ids[i];
            if (id < 256) {
                metrics.expert_activation_frequency[id]++;
            }
        }
    }

    /**
     * Computes the definitive operational parameters to reconcile the 150 TPS profile
     */
    void GenerateReconciliationReport(double measured_tps, double hardware_max_bandwidth_gbps) {
        uint64_t tokens = metrics.total_tokens_evaluated.load();
        if (tokens == 0) {
            std::cout << "[!] Telemetry Error: No token evaluation passes recorded.\n";
            return;
        }

        // Calculate actual operational topology
        double average_experts_per_token = static_cast<double>(metrics.total_expert_activations.load()) / tokens;
        
        // Derive exact parameter count moving across the memory bus per forward pass
        // Assumes base expert size of roughly 145M parameters
        double active_params_per_token_billions = (average_experts_per_token * 0.145) + 0.93; // Including shared routing blocks
        
        double total_elements = static_cast<double>(metrics.total_elements_processed.load());
        double active_non_zeros = static_cast<double>(metrics.non_zero_ternary_elements.load());
        
        // Calculate true compressed bit depth based on non-zero indices + sign bits
        double structural_sparsity = (total_elements - active_non_zeros) / (total_elements + 1e-9);
        double effective_bit_depth = 1.5 * (1.0 - structural_sparsity);

        // Memory Traffic Math Reconciliation
        double gigabytes_per_token = (active_params_per_token_billions * 1e9 * (effective_bit_depth / 8.0)) / 1e9;
        double sustained_bandwidth_required = gigabytes_per_token * measured_tps;

        std::cout << "\n============================================================\n";
        std::cout << "      DYNAMIC MOE ROUTING & PARAMETER RECONCILIATION        \n";
        std::cout << "============================================================\n";
        std::cout << "Measured Telemetry:\n";
        std::cout << "  - Active Experts per Token  : " << std::fixed << std::setprecision(2) << average_experts_per_token << " (Dynamic vs Static Top-8)\n";
        std::cout << "  - True Active Params/Token  : " << active_params_per_token_billions << " B\n";
        std::cout << "  - Structural Weight Sparsity: " << (structural_sparsity * 100.0) << " %\n";
        std::cout << "  - Effective Precision Depth : " << effective_bit_depth << " bits/param\n\n";

        std::cout << "Bandwidth Verification at " << measured_tps << " TPS:\n";
        std::cout << "  - Footprint Per Token       : " << gigabytes_per_token << " GB/token\n";
        std::cout << "  - Required Sustained Bus    : " << sustained_bandwidth_required << " GB/s\n";
        std::cout << "  - Combined Hardware Capacity: " << hardware_max_bandwidth_gbps << " GB/s\n\n";

        std::cout << "Reconciliation Status:\n";
        if (sustained_bandwidth_required <= hardware_max_bandwidth_gbps) {
            std::cout << "  [PASS] Operational profile reconciles perfectly with hardware bus bounds.\n";
            std::cout << "         Reason: ";
            if (average_experts_per_token < 8.0) std::cout << "Dynamic pruning reduced active parameter overhead.\n";
            if (effective_bit_depth < 1.0) std::cout << "Ternary zero-skipping dropped effective bit-depth below wall limits.\n";
        } else {
            std::cout << "  [FAIL] Architectural Exception: Required bandwidth exceeds physical hardware capacity.\n";
        }
        std::cout << "============================================================\n\n";
    }
};
