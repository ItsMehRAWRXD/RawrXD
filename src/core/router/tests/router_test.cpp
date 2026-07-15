// router_test.cpp
// Unit tests for Layer 1: Capability Router

#include "../router.h"
#include <cassert>
#include <iostream>

using namespace rawrxd::router;

void TestBackendRegistration() {
    std::cout << "Test: BackendRegistration..." << std::endl;
    
    CapabilityRouter router;
    
    BackendInfo info;
    info.id = 1;
    info.name = "NexusBridge";
    info.state = BackendState::Healthy;
    info.supported_architectures = {"llama2", "qwen2"};
    info.max_batch_size = 32;
    info.memory_available = 16ULL * 1024 * 1024 * 1024; // 16GB
    info.avg_latency = std::chrono::milliseconds(50);
    info.success_rate = 0.95f;
    info.current_load = 0.3f;
    info.cost_per_token = 0.0001f;
    
    assert(router.RegisterBackend(info));
    
    auto retrieved = router.GetBackendInfo(1);
    assert(retrieved.has_value());
    assert(retrieved->name == "NexusBridge");
    
    std::cout << "  PASSED" << std::endl;
}

void TestRouting() {
    std::cout << "Test: Routing..." << std::endl;
    
    CapabilityRouter router;
    
    // Register two backends
    BackendInfo nexus;
    nexus.id = 1;
    nexus.name = "NexusBridge";
    nexus.state = BackendState::Healthy;
    nexus.supported_architectures = {"llama2"};
    nexus.avg_latency = std::chrono::milliseconds(50);
    nexus.success_rate = 0.95f;
    nexus.current_load = 0.3f;
    nexus.cost_per_token = 0.0002f;
    router.RegisterBackend(nexus);
    
    BackendInfo local;
    local.id = 2;
    local.name = "LocalGGUF";
    local.state = BackendState::Healthy;
    local.supported_architectures = {"llama2"};
    local.avg_latency = std::chrono::milliseconds(100);
    local.success_rate = 0.99f;
    local.current_load = 0.1f;
    local.cost_per_token = 0.0f;
    router.RegisterBackend(local);
    
    // Create capability and work spec
    CapabilityToken cap;
    cap.hash = 12345;
    cap.permissions = 0xFFFFFFFF;
    cap.expiry = std::chrono::steady_clock::now() + std::chrono::hours(1);
    
    WorkSpec work;
    work.model_architecture = "llama2";
    work.estimated_tokens = 100;
    work.priority = 1;
    work.strategy = RoutingStrategy::LatencyOptimized;
    
    // Route should select NexusBridge (lower latency)
    auto decision = router.Route(cap, work);
    assert(decision.has_value());
    assert(decision->backend == 1); // NexusBridge
    assert(decision->confidence > 0.0f);
    
    std::cout << "  PASSED" << std::endl;
}

void TestCanRoute() {
    std::cout << "Test: CanRoute..." << std::endl;
    
    CapabilityRouter router;
    
    CapabilityToken cap;
    cap.hash = 12345;
    cap.permissions = 0xFFFFFFFF;
    cap.expiry = std::chrono::steady_clock::now() + std::chrono::hours(1);
    
    WorkSpec work;
    work.model_architecture = "llama2";
    
    // Should not be able to route without backends
    assert(!router.CanRoute(cap, work));
    
    // Add backend
    BackendInfo info;
    info.id = 1;
    info.name = "TestBackend";
    info.state = BackendState::Healthy;
    info.supported_architectures = {"llama2"};
    router.RegisterBackend(info);
    
    // Now should be able to route
    assert(router.CanRoute(cap, work));
    
    // But not for unsupported architecture
    work.model_architecture = "unsupported";
    assert(!router.CanRoute(cap, work));
    
    std::cout << "  PASSED" << std::endl;
}

int main() {
    std::cout << "=== RawrXD Router Tests ===" << std::endl;
    std::cout << std::endl;
    
    try {
        TestBackendRegistration();
        TestRouting();
        TestCanRoute();
        
        std::cout << std::endl;
        std::cout << "All tests PASSED!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test FAILED: " << e.what() << std::endl;
        return 1;
    }
}
