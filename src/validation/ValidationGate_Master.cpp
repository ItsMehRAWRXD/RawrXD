// ============================================================================
// ValidationGate_Master.cpp - Master Validation Gate Registry Implementation
// ============================================================================

#include "ValidationGate_Master.h"
#include <cstdio>
#include <algorithm>

namespace RawrXD {
namespace Validation {

// Singleton instance
ValidationGateRegistry& ValidationGateRegistry::Instance() {
    static ValidationGateRegistry instance;
    return instance;
}

void ValidationGateRegistry::RegisterGate(std::shared_ptr<IValidationGate> gate) {
    if (gate) {
        gates_[gate->GetId()] = gate;
    }
}

void ValidationGateRegistry::UnregisterGate(const std::string& gateId) {
    gates_.erase(gateId);
}

std::shared_ptr<IValidationGate> ValidationGateRegistry::GetGate(const std::string& gateId) {
    auto it = gates_.find(gateId);
    if (it != gates_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<IValidationGate>> ValidationGateRegistry::GetAllGates() {
    std::vector<std::shared_ptr<IValidationGate>> result;
    for (const auto& [id, gate] : gates_) {
        result.push_back(gate);
    }
    
    // Sort by gate ID
    std::sort(result.begin(), result.end(), 
        [](const auto& a, const auto& b) {
            return a->GetId() < b->GetId();
        });
    
    return result;
}

std::vector<std::shared_ptr<IValidationGate>> ValidationGateRegistry::GetGatesByStatus(GateStatus status) {
    std::vector<std::shared_ptr<IValidationGate>> result;
    for (const auto& [id, gate] : gates_) {
        if (gate->GetStatus() == status) {
            result.push_back(gate);
        }
    }
    return result;
}

ValidationResult ValidationGateRegistry::RunGate(const std::string& gateId) {
    auto gate = GetGate(gateId);
    if (gate) {
        return gate->Execute();
    }
    
    ValidationResult result;
    result.gateId = gateId;
    result.passed = false;
    result.message = "Gate not found: " + gateId;
    return result;
}

ValidationResult ValidationGateRegistry::RunAllGates() {
    ValidationResult result;
    result.gateId = "ALL";
    result.passed = true;
    
    auto gates = GetAllGates();
    int passed = 0;
    int failed = 0;
    int not_impl = 0;
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║           RawrXD Validation Gate Suite Execution                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\nTotal gates registered: %zu\n\n", gates.size());
    
    for (const auto& gate : gates) {
        if (gate->GetStatus() == GateStatus::NOT_IMPLEMENTED) {
            printf("[%s] %s - SKIPPED (Not Implemented)\n", 
                   gate->GetId().c_str(), gate->GetName().c_str());
            not_impl++;
            continue;
        }
        
        auto gateResult = gate->Execute();
        
        if (gateResult.passed) {
            passed++;
        } else {
            failed++;
            result.passed = false;
        }
        
        result.durationMs += gateResult.durationMs;
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                      Summary                                     ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:    %3zu                                                  ║\n", gates.size());
    printf("║  Passed:   %3d  ✓                                                ║\n", passed);
    printf("║  Failed:   %3d  %s                                               ║\n", failed, failed > 0 ? "✗" : " ");
    printf("║  Skipped:  %3d  -                                                ║\n", not_impl);
    printf("║  Time:      %.2f ms                                              ║\n", result.durationMs);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    result.message = std::to_string(passed) + "/" + std::to_string(gates.size()) + " gates passed";
    return result;
}

ValidationResult ValidationGateRegistry::RunGatesUpTo(const std::string& gateId) {
    ValidationResult result;
    result.gateId = "UPTO_" + gateId;
    result.passed = true;
    
    auto gates = GetAllGates();
    
    for (const auto& gate : gates) {
        auto gateResult = gate->Execute();
        result.durationMs += gateResult.durationMs;
        
        if (!gateResult.passed) {
            result.passed = false;
        }
        
        if (gate->GetId() == gateId) {
            break;
        }
    }
    
    return result;
}

void ValidationGateRegistry::PrintRegistryStatus() {
    auto gates = GetAllGates();
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║           RawrXD Validation Gate Registry Status                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    const char* statusNames[] = {
        "NOT IMPLEMENTED",
        "IN PROGRESS",
        "IMPLEMENTED",
        "CERTIFIED",
        "FAILED"
    };
    
    for (const auto& gate : gates) {
        const char* status = statusNames[static_cast<int>(gate->GetStatus())];
        printf("  %-10s %-30s [%s]\n", 
               gate->GetId().c_str(), 
               gate->GetName().c_str(),
               status);
    }
    
    printf("\nTotal: %zu gates\n", gates.size());
}

} // namespace Validation
} // namespace RawrXD
