// =============================================================================
// RawRamXD_Phase7B3_AutonomousTest.cpp
// Test program for Phase 7B.3 acceptance gates A1-A6
// =============================================================================

#include "RawRamXD_Phase7B2_TopologyValidated.hpp"
#include "RawRamXD_Phase7B3_AutonomousPlacement.hpp"
#include <iostream>
#include <iomanip>

using namespace RawRamXD;
using namespace RawRamXD::Phase7B3;

// Create a simple topology for testing
FabricTopology CreateTestTopology() {
    FabricTopology topology;
    
    // Node 0: GPU0 (RX 7800 XT)
    GPUDeviceIdentity node0;
    node0.deviceId = 0;
    wcscpy_s(node0.name, L"AMD Radeon RX 7800 XT");
    node0.pciBusPath = "PCI\\VEN_1002&DEV_747e";
    node0.adapterLuid.LowPart = 0x12345678;
    node0.adapterLuid.HighPart = 0x9ABCDEF0;
    node0.vendorId = 0x1002; // AMD
    node0.deviceId_pci = 0x747E;
    node0.revision = 0;
    node0.dedicatedVRAM = 16978546688ULL; // 15.8 GB
    node0.sharedSystemMemory = 0;
    node0.budget = 16106127360ULL; // 15.0 GB
    node0.currentUsage = 15106127360ULL; // ~14.1 GB used
    node0.availableForReservation = 0;
    node0.nodeCount = 1;
    node0.nodeMask = 1;
    topology.nodes.push_back(node0);
    
    // Node 1: GPU1 (iGPU)
    GPUDeviceIdentity node1;
    node1.deviceId = 1;
    wcscpy_s(node1.name, L"AMD Radeon(TM) Graphics");
    node1.pciBusPath = "PCI\\VEN_1002&DEV_164e";
    node1.adapterLuid.LowPart = 0x87654321;
    node1.adapterLuid.HighPart = 0x0FEDCBA9;
    node1.vendorId = 0x1002; // AMD
    node1.deviceId_pci = 0x164E;
    node1.revision = 0;
    node1.dedicatedVRAM = 536870912ULL; // 0.5 GB
    node1.sharedSystemMemory = 33554432000ULL; // 31.3 GB shared
    node1.budget = 33554432000ULL; // 31.3 GB (shared)
    node1.currentUsage = 268435456ULL; // 0.25 GB used
    node1.availableForReservation = 0;
    node1.nodeCount = 1;
    node1.nodeMask = 2;
    topology.nodes.push_back(node1);
    
    // Link: Infinity Fabric between GPUs
    TopologyLink link;
    link.srcNode = 0;
    link.dstNode = 1;
    link.linkType = LinkType::INFINITY_FABRIC;
    link.linkWidth = 16; // x16
    link.linkSpeed = 16; // 16 GT/s (Gen4)
    link.theoreticalBandwidth = 200ULL * 1024 * 1024 * 1024; // 200 GB/s
    link.measuredBandwidth = 160ULL * 1024 * 1024 * 1024; // 160 GB/s
    link.latencyNs = 6250; // 6.25 us
    link.isSymmetric = true;
    topology.links.push_back(link);
    
    return topology;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    std::cout << "=================================================================" << std::endl;
    std::cout << "  RawRamXD Phase 7B.3: Autonomous Placement Engine" << std::endl;
    std::cout << "  Acceptance Gates A1-A6" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    // Create test topology
    auto topology = CreateTestTopology();
    
    std::cout << "Test Topology:" << std::endl;
    std::cout << "  Nodes: " << topology.nodes.size() << std::endl;
    std::cout << "  Links: " << topology.links.size() << std::endl;
    std::cout << "  Bandwidth: " << (topology.links[0].measuredBandwidth / (1024ULL * 1024 * 1024)) << " GB/s" << std::endl;
    std::cout << std::endl;
    
    // Initialize scheduler
    AutonomousFabricScheduler scheduler;
    if (!scheduler.Initialize(topology)) {
        std::cerr << "Failed to initialize scheduler" << std::endl;
        return 1;
    }
    
    std::cout << "Scheduler initialized successfully" << std::endl;
    std::cout << std::endl;
    
    // Run acceptance gates
    AcceptanceGateResults results = RunAllAcceptanceGates(&scheduler);
    
    // Print detailed results
    std::cout << std::endl;
    std::cout << "Detailed Results:" << std::endl;
    std::cout << "  A1 - Predict before miss:      " << (results.a1_predict_before_miss ? "PASS" : "FAIL") << std::endl;
    std::cout << "  A2 - Reduce cold penalty:        " << (results.a2_reduce_penalty ? "PASS" : "FAIL") << std::endl;
    std::cout << "  A3 - Maintain TPS under pressure: " << (results.a3_maintain_tps ? "PASS" : "FAIL") << std::endl;
    std::cout << "  A4 - Multi-GPU balancing:        " << (results.a4_multi_gpu_balance ? "PASS" : "FAIL") << std::endl;
    std::cout << "  A5 - Autonomous recovery:        " << (results.a5_autonomous_recovery ? "PASS" : "FAIL") << std::endl;
    std::cout << "  A6 - Export decisions:           " << (results.a6_export_decisions ? "PASS" : "FAIL") << std::endl;
    std::cout << std::endl;
    
    // Get scheduler status
    auto status = scheduler.GetStatus();
    std::cout << "Scheduler Status:" << std::endl;
    std::cout << "  Initialized: " << (status.is_initialized ? "YES" : "NO") << std::endl;
    std::cout << "  Tensors managed: " << status.tensors_managed << std::endl;
    std::cout << "  Pending migrations: " << status.pending_migrations << std::endl;
    std::cout << "  Current TPS: " << status.current_tps << std::endl;
    std::cout << "  VRAM Pressure GPU0: " << status.vram_pressure_gpu0 << std::endl;
    std::cout << "  VRAM Pressure GPU1: " << status.vram_pressure_gpu1 << std::endl;
    std::cout << std::endl;
    
    // Test placement recommendations
    std::cout << "Testing Placement Recommendations:" << std::endl;
    
    // Register some tensors
    for (int i = 0; i < 5; i++) {
        scheduler.RegisterTensor(2000 + i, 1024ULL * 1024 * 100, ResidencyTier::NVME_SSD);
    }
    
    // Simulate tensor accesses
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 10; j++) {
            scheduler.NotifyTensorAccess(2000 + i, j);
        }
    }
    
    // Get recommendations
    auto recommendations = scheduler.GetPlacementRecommendations();
    std::cout << "  Generated " << recommendations.size() << " placement recommendations" << std::endl;
    
    for (size_t i = 0; i < std::min(size_t(3), recommendations.size()); i++) {
        const auto& rec = recommendations[i];
        std::cout << "    Tensor " << rec.tensor_id << ": " 
                  << ResidencyTierToString(rec.source_tier) << " -> "
                  << ResidencyTierToString(rec.target_tier)
                  << " (cost: " << std::fixed << std::setprecision(3) << rec.total_cost << ")"
                  << (rec.should_migrate ? " [MIGRATE]" : " [STAY]") << std::endl;
    }
    std::cout << std::endl;
    
    // Test pre-inference pass
    std::cout << "Testing Pre-Inference Placement Pass:" << std::endl;
    
    std::vector<LayerExecutionPlan> plan;
    for (int i = 0; i < 5; i++) {
        LayerExecutionPlan layer;
        layer.layer_id = i;
        layer.estimated_compute_time_ms = 15.0f + i * 2.0f;
        layer.weight_tensors.push_back(3000 + i);
        plan.push_back(layer);
    }
    
    scheduler.RunPreInferencePass(plan);
    std::cout << std::endl;
    
    // Final summary
    std::cout << "=================================================================" << std::endl;
    std::cout << "  Phase 7B.3 Complete!" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Key Achievements:" << std::endl;
    std::cout << "  - Tensor Residency Predictor: Predicts optimal placement" << std::endl;
    std::cout << "  - Autonomous Placement Solver: Cost-based decision engine" << std::endl;
    std::cout << "  - Pre-Inference Pass: Hides migration behind compute" << std::endl;
    std::cout << "  - Fabric Scheduler: Unified multi-GPU management" << std::endl;
    std::cout << std::endl;
    std::cout << "Next: Phase 7C - Predictive Memory Intelligence" << std::endl;
    std::cout << std::endl;
    
    return (results.passed_count == results.total_count) ? 0 : 1;
}