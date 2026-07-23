// ============================================================================
// ValidationRunner.cpp - Standalone Validation Gate Runner
// ============================================================================
// Usage: ValidationRunner [options]
//   --all              Run all validation gates
//   --gate VAL-XXX     Run specific gate
//   --upto VAL-XXX     Run gates up to and including VAL-XXX
//   --list             List all registered gates
//   --status           Show registry status
// ============================================================================

#include "ValidationGate_Master.h"
#include "gates/VAL001_CoreInferenceGate.h"
#include "gates/VAL002_ModelLoadingGate.h"
#include "gates/VAL003_TokenizerGate.h"
#include "gates/VAL004_KVCacheGate.h"
#include "gates/VAL005_SamplingGate.h"
#include "gates/VAL006_QuantizationGate.h"
#include "gates/VAL007_MemoryManagementGate.h"
#include "gates/VAL008_ThreadingGate.h"
#include "gates/VAL009_ErrorHandlingGate.h"
#include "gates/VAL010_Through_VAL023.h"
#include "gates/VAL039_Plus_Gates.h"
#include "gates/VAL051_Through_VAL060_Win32IDE.h"
#include "gates/TokenEfficiencySwarm.h"
#include "gates/VAL061_TokenEstimatorSwarmGate.h"
#include "gates/VAL062_SwarmIntegrationGate.h"

#include <cstdio>
#include <cstring>

using namespace RawrXD::Validation;

void PrintUsage(const char* program) {
    printf("Usage: %s [options]\n", program);
    printf("\nOptions:\n");
    printf("  --all              Run all validation gates\n");
    printf("  --gate VAL-XXX     Run specific gate\n");
    printf("  --upto VAL-XXX     Run gates up to and including VAL-XXX\n");
    printf("  --list             List all registered gates\n");
    printf("  --status           Show registry status\n");
    printf("  --help             Show this help message\n");
}

int main(int argc, char** argv) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrXD Sovereign Inference System - Validation Suite        ║\n");
    printf("║     Version 1.0.0 - Production Validation Framework              ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    auto& registry = ValidationGateRegistry::Instance();
    
    if (strcmp(argv[1], "--help") == 0) {
        PrintUsage(argv[0]);
        return 0;
    }
    
    // Register VAL-061 Token Estimator Swarm Gate
    registry.Register(std::make_unique<VAL061_TokenEstimatorSwarmGate>());
    
    // Register VAL-062 Swarm Integration Gate
    registry.Register(std::make_unique<VAL062_SwarmIntegrationGate>());
    
    if (strcmp(argv[1], "--list") == 0) {
        auto gates = registry.GetAllGates();
        printf("\nRegistered Validation Gates:\n");
        printf("============================\n\n");
        for (const auto& gate : gates) {
            printf("  %-10s %-35s %s\n", 
                   gate->GetId().c_str(),
                   gate->GetName().c_str(),
                   gate->GetDescription().c_str());
        }
        printf("\nTotal: %zu gates\n", gates.size());
        return 0;
    }
    
    if (strcmp(argv[1], "--status") == 0) {
        registry.PrintRegistryStatus();
        return 0;
    }
    
    if (strcmp(argv[1], "--all") == 0) {
        auto result = registry.RunAllGates();
        return result.passed ? 0 : 1;
    }
    
    if (strcmp(argv[1], "--gate") == 0) {
        if (argc < 3) {
            printf("Error: --gate requires a gate ID (e.g., VAL-001)\n");
            return 1;
        }
        auto result = registry.RunGate(argv[2]);
        printf("\nResult: %s\n", result.passed ? "PASSED" : "FAILED");
        printf("Message: %s\n", result.message.c_str());
        printf("Duration: %.2f ms\n", result.durationMs);
        return result.passed ? 0 : 1;
    }
    
    if (strcmp(argv[1], "--upto") == 0) {
        if (argc < 3) {
            printf("Error: --upto requires a gate ID (e.g., VAL-010)\n");
            return 1;
        }
        auto result = registry.RunGatesUpTo(argv[2]);
        printf("\nResult: %s\n", result.passed ? "PASSED" : "FAILED");
        printf("Message: %s\n", result.message.c_str());
        printf("Duration: %.2f ms\n", result.durationMs);
        return result.passed ? 0 : 1;
    }
    
    printf("Error: Unknown option '%s'\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
}
