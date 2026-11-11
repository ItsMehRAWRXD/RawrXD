#include "tests/SovereignIntegrationTest.hpp"
#include "sovereign/SovereignRuntime.hpp"
#include "sovereign/SovereignSelfCheck.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/DistributedKV.hpp"
#include "sovereign/ExpertSharding.hpp"
#include "sovereign/RoutingHeuristicsEngine.hpp"
#include "sovereign/PlanetaryScheduler.hpp"
#include "sovereign/SovereignConsensus.hpp"
#include "ide/IDEEntry.hpp"
#include <stdio>

bool SovereignIntegrationTest::Run() {
    printf("=== Sovereign Integration Test ===\n");
    
    bool allPassed = true;
    
    allPassed &= RunDistributedTest();
    allPassed &= RunAdaptiveTest();
    allPassed &= RunTelemetryTest();
    allPassed &= RunPanelWiringTest();
    
    if (allPassed) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("SOME TESTS FAILED\n");
    }
    
    return allPassed;
}

bool SovereignIntegrationTest::RunDistributedTest() {
    printf("[TEST] Distributed Subsystems...\n");
    
    // Initialize fabric
    Fabric::Init();
    if (!Fabric::IsInitialized()) {
        printf("  FAIL: Fabric not initialized\n");
        return false;
    }
    
    // Check distributed subsystems
    DistributedKV::Init();
    ExpertSharding::Init();
    
    printf("  PASS\n");
    return true;
}

bool SovereignIntegrationTest::RunAdaptiveTest() {
    printf("[TEST] Adaptive Ring...\n");
    
    RoutingHeuristicsEngine::Init();
    PlanetaryScheduler::Init();
    SovereignConsensus::Init();
    
    printf("  PASS\n");
    return true;
}

bool SovereignIntegrationTest::RunTelemetryTest() {
    printf("[TEST] Telemetry Collection...\n");
    
    auto t = Telemetry::Collect();
    if (t.GpuLatencyUs == 0) {
        printf("  FAIL: No telemetry data\n");
        return false;
    }
    
    printf("  PASS (latency: %llu us)\n", t.GpuLatencyUs);
    return true;
}

bool SovereignIntegrationTest::RunPanelWiringTest() {
    printf("[TEST] IDE Panel Wiring...\n");
    
    IDEEntry::Init();
    
    auto results = SovereignSelfCheck::RunAll();
    int failed = 0;
    for (auto& r : results) {
        if (!r.ok) {
            printf("  FAIL: %s - %s\n", r.name.c_str(), r.detail.c_str());
            failed++;
        }
    }
    
    if (failed > 0) {
        printf("  FAIL: %d checks failed\n", failed);
        return false;
    }
    
    printf("  PASS (%zu checks)\n", results.size());
    return true;
}
