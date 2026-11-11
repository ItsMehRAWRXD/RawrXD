//==============================================================================
// cli_main.cpp
// Sovereign CLI - Complete Integration Entry Point
//
// Phase 7C.2 - Full Stack Integration:
// - Titan Runtime
// - MASM Backend (Phase 7A/7B kernels)
// - Reference Backend (validation)
// - Intrinsics Backend (AVX2/AVX-512)
// - Kernel Registry (auto-selection)
// - Graph Runner v2 (orchestration)
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// Include all backend headers
#include "src/core/execution/KernelRegistry.hpp"
#include "src/core/execution/MASMBackend.hpp"
#include "src/core/execution/ReferenceBackend.hpp"
#include "src/core/execution/IntrinsicsBackend.hpp"
#include "src/core/execution/SovereignGraphRunner_v2.hpp"

using namespace sovereign;

//==============================================================================
// CLI Commands
//==============================================================================
void printUsage(const char* program) {
    printf("Sovereign CLI - Phase 7C.2 Complete Integration\n");
    printf("Usage: %s [command] [options]\n\n", program);
    printf("Commands:\n");
    printf("  --test              Run integration tests\n");
    printf("  --benchmark         Run performance benchmarks\n");
    printf("  --validate          Validate MASM vs Reference\n");
    printf("  --info              Show system info\n");
    printf("  --help              Show this help\n");
}

void showSystemInfo() {
    printf("==============================================================================\n");
    printf("Sovereign System Information\n");
    printf("==============================================================================\n\n");
    
    // Initialize registry
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Register all backends
    auto masm = std::make_unique<MASMBackend>();
    auto ref = std::make_unique<ReferenceBackend>();
    auto intr = std::make_unique<IntrinsicsBackend>();
    
    uint32_t masmId = registry.RegisterBackend(std::move(masm));
    uint32_t refId = registry.RegisterBackend(std::move(ref));
    uint32_t intrId = registry.RegisterBackend(std::move(intr));
    
    // Show registered backends
    auto backends = registry.ListBackends();
    printf("Registered Backends: %zu\n\n", backends.size());
    
    for (auto& [id, info] : backends) {
        printf("  [%u] %s\n", id, info.name.c_str());
        printf("       Version: %s\n", info.version.c_str());
        printf("       Capabilities: ");
        if (HasCapability(info.capabilities, BackendCapability::REFERENCE))
            printf("REFERENCE ");
        if (HasCapability(info.capabilities, BackendCapability::INTRINSICS))
            printf("INTRINSICS ");
        if (HasCapability(info.capabilities, BackendCapability::MASM))
            printf("MASM ");
        printf("\n\n");
    }
    
    printf("==============================================================================\n");
}

int runIntegrationTest() {
    printf("==============================================================================\n");
    printf("Phase 7C.2 Integration Test\n");
    printf("==============================================================================\n\n");
    
    int passed = 0;
    int total = 0;
    
    // Test 1: Kernel Registry
    printf("[Test 1] Kernel Registry... ");
    KernelRegistry& registry = KernelRegistry::Instance();
    auto masm = std::make_unique<MASMBackend>();
    if (masm->Initialize()) {
        uint32_t id = registry.RegisterBackend(std::move(masm));
        printf("PASS (Backend ID: %u)\n", id);
        passed++;
    } else {
        printf("FAIL (MASM backend not initialized)\n");
    }
    total++;
    
    // Test 2: MASM Backend Availability
    printf("[Test 2] MASM Backend... ");
    auto testMasm = std::make_unique<MASMBackend>();
    if (testMasm->Initialize()) {
        auto info = testMasm->GetInfo();
        printf("PASS (%s, %zu kernels)\n", info.name.c_str(), info.supportedKernels.size());
        passed++;
    } else {
        printf("FAIL (not available)\n");
    }
    total++;
    
    // Test 3: Reference Backend
    printf("[Test 3] Reference Backend... ");
    auto ref = std::make_unique<ReferenceBackend>();
    if (ref->Initialize()) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
    }
    total++;
    
    // Test 4: Intrinsics Backend
    printf("[Test 4] Intrinsics Backend... ");
    auto intr = std::make_unique<IntrinsicsBackend>();
    if (intr->Initialize()) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
    }
    total++;
    
    // Test 5: Graph Runner
    printf("[Test 5] Graph Runner v2... ");
    SovereignGraphRunner_v2 runner;
    if (runner.Initialize()) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
    }
    total++;
    
    printf("\n==============================================================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("==============================================================================\n");
    
    return (passed == total) ? 0 : 1;
}

int runBenchmark() {
    printf("==============================================================================\n");
    printf("Phase 7C.2 Performance Benchmark\n");
    printf("==============================================================================\n\n");
    
    // Initialize backends
    KernelRegistry& registry = KernelRegistry::Instance();
    
    auto masm = std::make_unique<MASMBackend>();
    auto ref = std::make_unique<ReferenceBackend>();
    auto intr = std::make_unique<IntrinsicsBackend>();
    
    if (masm->Initialize()) registry.RegisterBackend(std::move(masm));
    if (ref->Initialize()) registry.RegisterBackend(std::move(ref));
    if (intr->Initialize()) registry.RegisterBackend(std::move(intr));
    
    printf("Backends registered. Ready for benchmarking.\n");
    printf("(Full benchmark implementation would run kernel comparisons here)\n\n");
    
    return 0;
}

int runValidation() {
    printf("==============================================================================\n");
    printf("Phase 7C.2 Numerical Validation\n");
    printf("MASM vs Reference Backend\n");
    printf("==============================================================================\n\n");
    
    // Initialize both backends
    MASMBackend masm;
    ReferenceBackend ref;
    
    if (!masm.Initialize()) {
        printf("ERROR: MASM backend not available\n");
        return 1;
    }
    
    if (!ref.Initialize()) {
        printf("ERROR: Reference backend not available\n");
        return 1;
    }
    
    printf("Both backends initialized.\n");
    printf("(Full validation would compare outputs here)\n\n");
    
    return 0;
}

//==============================================================================
// Main Entry Point
//==============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 0;
    }
    
    const char* command = argv[1];
    
    if (strcmp(command, "--test") == 0) {
        return runIntegrationTest();
    } else if (strcmp(command, "--benchmark") == 0) {
        return runBenchmark();
    } else if (strcmp(command, "--validate") == 0) {
        return runValidation();
    } else if (strcmp(command, "--info") == 0) {
        showSystemInfo();
        return 0;
    } else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        printUsage(argv[0]);
        return 0;
    } else {
        printf("Unknown command: %s\n\n", command);
        printUsage(argv[0]);
        return 1;
    }
}
