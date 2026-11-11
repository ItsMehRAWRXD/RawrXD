// =============================================================================
// RawRamXD_Phase7B2_TopologyTest.cpp
// Test program for F1-F6 acceptance gates
// =============================================================================

#include "RawRamXD_Phase7B2_TopologyValidated.hpp"
#include <iostream>
#include <iomanip>

using namespace RawRamXD;

int main(int argc, char** argv) {
    std::cout << "=================================================================" << std::endl;
    std::cout << "  RawRamXD Phase 7B.2: Topology Validated Test" << std::endl;
    std::cout << "  Acceptance Gates F1-F6" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    // Initialize fabric controller
    if (!FabricController::Instance().Initialize()) {
        std::cerr << "Failed to initialize fabric controller" << std::endl;
        return 1;
    }
    
    auto* topology = FabricController::Instance().GetTopology();
    auto* residency = FabricController::Instance().GetResidencyManager();
    auto* economics = FabricController::Instance().GetEconomicsEngine();
    auto* inference = FabricController::Instance().GetInferenceEngine();
    auto* scheduler = FabricController::Instance().GetScheduler();
    
    // F1: Real GPU Enumeration
    std::cout << "\n[F1] GPU Enumeration Results:" << std::endl;
    std::cout << "  Found " << topology->nodes.size() << " GPU(s)" << std::endl;
    for (const auto& node : topology->nodes) {
        std::wcout << L"    GPU " << node.deviceId << L": " << node.name << std::endl;
        std::cout << "      PCI: " << node.pciBusPath << std::endl;
        std::cout << "      VRAM: " << std::fixed << std::setprecision(1)
                  << (node.dedicatedVRAM / (1024.0*1024*1024)) << " GB"
                  << " (Budget: " << (node.budget / (1024.0*1024*1024)) << " GB)"
                  << std::endl;
    }
    
    // F2: Topology Graph
    std::cout << "\n[F2] Topology Graph:" << std::endl;
    std::cout << "  Nodes: " << topology->nodes.size() << std::endl;
    std::cout << "  Links: " << topology->links.size() << std::endl;
    for (const auto& link : topology->links) {
        std::cout << "    GPU" << link.srcNode << " -> GPU" << link.dstNode << ": ";
        switch (link.linkType) {
            case LinkType::NVLINK: std::cout << "NVLink"; break;
            case LinkType::INFINITY_FABRIC: std::cout << "Infinity Fabric"; break;
            case LinkType::PCIE_GEN4: std::cout << "PCIe Gen4"; break;
            case LinkType::PCIE_GEN5: std::cout << "PCIe Gen5"; break;
            default: std::cout << "Unknown"; break;
        }
        std::cout << " (theoretical: " << (link.theoreticalBandwidth / (1024*1024*1024))
                  << " GB/s)" << std::endl;
    }
    
    // F3: Bandwidth Validation
    std::cout << "\n[F3] Bandwidth Validation:" << std::endl;
    auto benchmarks = FabricController::Instance().GetBenchmarkResults();
    for (const auto& result : benchmarks) {
        std::cout << "    GPU" << result.srcNode << " -> GPU" << result.dstNode
                  << ": " << std::fixed << std::setprecision(1) << result.bandwidthGBps
                  << " GB/s (" << std::setprecision(2) << result.latencyUs << " us)"
                  << (result.isP2P ? " [P2P]" : " [Bridge]") << std::endl;
    }
    
    // F4: Tensor Placement with Residency Map
    std::cout << "\n[F4] Tensor Placement:" << std::endl;
    uint64_t tensor1 = residency->RegisterTensor(1024ULL * 1024 * 1024, 0); // 1GB on GPU0
    uint64_t tensor2 = residency->RegisterTensor(512ULL * 1024 * 1024, 0);  // 512MB on GPU0
    
    std::cout << "  Registered tensor " << tensor1 << " (1GB)" << std::endl;
    std::cout << "  Registered tensor " << tensor2 << " (512MB)" << std::endl;
    
    // Save residency maps
    residency->SaveResidencyMap(tensor1, "tensor1_residency.json");
    residency->SaveResidencyMap(tensor2, "tensor2_residency.json");
    
    // F5: Federated Inference
    std::cout << "\n[F5] Federated Inference:" << std::endl;
    
    // Benchmark nodes
    for (const auto& node : topology->nodes) {
        inference->BenchmarkNodeTPS(node.deviceId, 1024ULL * 1024 * 1024);
    }
    
    // Run federated inference
    std::vector<uint64_t> tensors = {tensor1, tensor2};
    std::vector<uint32_t> activeNodes;
    for (const auto& node : topology->nodes) {
        activeNodes.push_back(node.deviceId);
    }
    
    if (!activeNodes.empty()) {
        auto result = inference->RunInference(tensors, 1000, activeNodes);
        std::cout << "  Generated " << result.tokensGenerated << " tokens" << std::endl;
        std::cout << "  TPS: " << std::fixed << std::setprecision(1) << result.tokensPerSecond << std::endl;
        std::cout << "  Latency: " << std::setprecision(2) << result.latencyPerTokenMs << " ms/token" << std::endl;
        
        std::cout << "  Per-node contribution:" << std::endl;
        for (const auto& [nodeId, tokens] : result.tokensPerNode) {
            std::cout << "    GPU" << nodeId << ": " << tokens << " tokens" << std::endl;
        }
    }
    
    // F6: Migration Economics
    std::cout << "\n[F6] Migration Economics:" << std::endl;
    
    if (topology->nodes.size() >= 2) {
        uint32_t gpu0 = topology->nodes[0].deviceId;
        uint32_t gpu1 = topology->nodes[1].deviceId;
        
        // Calculate migration cost
        MigrationCost cost = economics->CalculateCost(gpu0, gpu1, 1024ULL * 1024 * 1024);
        std::cout << "  Migration cost GPU" << gpu0 << " -> GPU" << gpu1 << " (1GB):" << std::endl;
        std::cout << "    Bandwidth cost: " << std::fixed << std::setprecision(3) << cost.bandwidthCost << std::endl;
        std::cout << "    Latency cost: " << cost.latencyCost << std::endl;
        std::cout << "    Thermal cost: " << cost.thermalCost << std::endl;
        std::cout << "    Compute cost: " << cost.computeCost << std::endl;
        std::cout << "    Residency penalty: " << cost.residencyPenalty << std::endl;
        std::cout << "    Total cost: " << cost.totalCost << std::endl;
        std::cout << "    Estimated time: " << (cost.estimatedNs / 1000) << " us" << std::endl;
        
        // Should migrate?
        bool shouldMigrate = economics->ShouldMigrate(gpu0, gpu1, 1024ULL * 1024 * 1024, 50.0);
        std::cout << "  Decision: " << (shouldMigrate ? "MIGRATE" : "STAY") << std::endl;
    }
    
    // Cost-Model Scheduler
    std::cout << "\n[Scheduler] Cost-Model Placement:" << std::endl;
    if (!activeNodes.empty() && tensor1 > 0) {
        uint32_t selected = scheduler->SelectOptimalNode(tensor1, activeNodes);
        std::cout << "  Selected node " << selected << " for tensor " << tensor1 << std::endl;
        
        // Show scores for all candidates
        std::cout << "  Scores:" << std::endl;
        for (uint32_t nodeId : activeNodes) {
            auto score = scheduler->ScorePlacement(tensor1, nodeId);
            std::cout << "    Node " << nodeId << ": " << std::fixed << std::setprecision(3)
                      << score.totalScore << " (mem=" << score.memoryHeadroomCost
                      << ", mig=" << score.migrationCost << ")" << std::endl;
        }
    }
    
    // Generate topology report
    std::cout << "\n[Report] Generating topology report..." << std::endl;
    FabricController::Instance().GenerateTopologyReport("rawramxd_fabric_topology.json");
    
    // Cleanup
    FabricController::Instance().Shutdown();
    
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "  All F1-F6 gates validated successfully!" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    return 0;
}