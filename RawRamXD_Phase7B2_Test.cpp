// =============================================================================
// RawRamXD_Phase7B2_Test.cpp
// Test program for Multi-GPU Fabric Federation
// =============================================================================

#include "RawRamXD_Phase7B2_MultiGPU_Federation.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace RawRamXD;

// =============================================================================
// Test Functions
// =============================================================================

bool Test_Federation_Initialize() {
    std::cout << "\n[Test] Federation Initialize..." << std::endl;
    
    if (!FabricFederation::Instance().Initialize()) {
        std::cerr << "  FAILED: Could not initialize federation" << std::endl;
        return false;
    }
    
    std::cout << "  PASSED: Federation initialized" << std::endl;
    return true;
}

bool Test_GPU_Enumeration() {
    std::cout << "\n[Test] GPU Enumeration..." << std::endl;
    
    auto gpus = FabricFederation::Instance().GetAllGPUs();
    if (gpus.empty()) {
        std::cerr << "  FAILED: No GPUs detected" << std::endl;
        return false;
    }
    
    std::cout << "  Detected " << gpus.size() << " GPU(s):" << std::endl;
    for (auto* gpu : gpus) {
        std::wcout << L"    GPU " << gpu->deviceId << L": " << gpu->name << std::endl;
        std::cout << "      VRAM: " << std::fixed << std::setprecision(1)
                  << (gpu->vramTotalBytes / (1024.0 * 1024 * 1024)) << " GB" << std::endl;
        std::cout << "      Vendor: ";
        switch (gpu->vendor) {
            case GPUVendor::AMD: std::cout << "AMD"; break;
            case GPUVendor::NVIDIA: std::cout << "NVIDIA"; break;
            case GPUVendor::INTEL: std::cout << "Intel"; break;
            default: std::cout << "Unknown"; break;
        }
        std::cout << std::endl;
    }
    
    std::cout << "  PASSED: GPU enumeration" << std::endl;
    return true;
}

bool Test_Peer_Access_Query() {
    std::cout << "\n[Test] Peer Access Query..." << std::endl;
    
    auto* peerManager = FabricFederation::Instance().GetPeerAccessManager();
    if (!peerManager) {
        std::cerr << "  FAILED: Peer access manager not available" << std::endl;
        return false;
    }
    
    auto gpus = FabricFederation::Instance().GetAllGPUs();
    if (gpus.size() >= 2) {
        std::cout << "  Peer access capabilities:" << std::endl;
        for (size_t i = 0; i < gpus.size(); i++) {
            for (size_t j = 0; j < gpus.size(); j++) {
                if (i == j) continue;
                
                auto access = peerManager->QueryPeerAccess(gpus[i]->deviceId, gpus[j]->deviceId);
                std::cout << "    GPU " << gpus[i]->deviceId << " -> GPU " << gpus[j]->deviceId << ": ";
                switch (access) {
                    case PeerAccessType::INFINITY: std::cout << "AMD Infinity Fabric"; break;
                    case PeerAccessType::NVLINK: std::cout << "NVIDIA NVLink"; break;
                    case PeerAccessType::DIRECT: std::cout << "Direct P2P"; break;
                    case PeerAccessType::BRIDGE: std::cout << "Bridge (system RAM)"; break;
                    default: std::cout << "None"; break;
                }
                std::cout << std::endl;
            }
        }
    } else {
        std::cout << "  (Single GPU system - P2P not applicable)" << std::endl;
    }
    
    std::cout << "  PASSED: Peer access query" << std::endl;
    return true;
}

bool Test_Memory_Allocation() {
    std::cout << "\n[Test] Memory Allocation..." << std::endl;
    
    auto* node = FabricFederation::Instance().GetLocalNode();
    if (!node) {
        std::cerr << "  FAILED: Local node not available" << std::endl;
        return false;
    }
    
    auto gpus = node->GetGPUs();
    if (gpus.empty()) {
        std::cerr << "  FAILED: No GPUs available" << std::endl;
        return false;
    }
    
    // Allocate 1GB on first GPU
    size_t allocSize = 1024ULL * 1024 * 1024;
    uint64_t handle = node->AllocateVRAM(gpus[0]->deviceId, allocSize);
    
    if (handle == 0) {
        std::cerr << "  FAILED: Could not allocate VRAM" << std::endl;
        return false;
    }
    
    std::cout << "  Allocated " << (allocSize / (1024 * 1024)) << " MB on GPU " 
              << gpus[0]->deviceId << std::endl;
    
    // Free allocation
    node->FreeVRAM(gpus[0]->deviceId, handle);
    std::cout << "  Freed allocation" << std::endl;
    
    std::cout << "  PASSED: Memory allocation" << std::endl;
    return true;
}

bool Test_Scheduler_Policies() {
    std::cout << "\n[Test] Scheduler Policies..." << std::endl;
    
    auto* scheduler = FabricFederation::Instance().GetScheduler();
    if (!scheduler) {
        std::cerr << "  FAILED: Scheduler not available" << std::endl;
        return false;
    }
    
    // Test different policies
    std::cout << "  Testing policies:" << std::endl;
    
    scheduler->SetPolicy(MultiGPUScheduler::SchedulePolicy::ROUND_ROBIN);
    std::cout << "    - Round Robin" << std::endl;
    
    scheduler->SetPolicy(MultiGPUScheduler::SchedulePolicy::LOAD_BALANCED);
    std::cout << "    - Load Balanced" << std::endl;
    
    scheduler->SetPolicy(MultiGPUScheduler::SchedulePolicy::PERFORMANCE);
    std::cout << "    - Performance" << std::endl;
    
    scheduler->SetPolicy(MultiGPUScheduler::SchedulePolicy::RESIDENCY);
    std::cout << "    - Residency" << std::endl;
    
    scheduler->SetPolicy(MultiGPUScheduler::SchedulePolicy::COST_OPTIMIZED);
    std::cout << "    - Cost Optimized" << std::endl;
    
    // Test GPU selection
    auto gpus = FabricFederation::Instance().GetAllGPUs();
    if (!gpus.empty()) {
        std::vector<uint32_t> gpuIds;
        for (auto* gpu : gpus) {
            gpuIds.push_back(gpu->deviceId);
        }
        
        uint32_t selected = scheduler->SelectOptimalGPU(1024 * 1024 * 1024, gpuIds);
        std::cout << "  Selected GPU " << selected << " for 1GB tensor" << std::endl;
    }
    
    std::cout << "  PASSED: Scheduler policies" << std::endl;
    return true;
}

bool Test_Federation_Stats() {
    std::cout << "\n[Test] Federation Statistics..." << std::endl;
    
    auto& federation = FabricFederation::Instance();
    
    std::cout << "  Federation Stats:" << std::endl;
    std::cout << "    Nodes: " << federation.GetNodeCount() << std::endl;
    std::cout << "    GPUs: " << federation.GetGPUCount() << std::endl;
    std::cout << "    Total VRAM: " << std::fixed << std::setprecision(1)
              << (federation.GetTotalVRAM() / (1024.0 * 1024 * 1024)) << " GB" << std::endl;
    std::cout << "    Available VRAM: " << std::setprecision(1)
              << (federation.GetAvailableVRAM() / (1024.0 * 1024 * 1024)) << " GB" << std::endl;
    std::cout << "    Allocated: " << std::setprecision(1)
              << (federation.GetTotalAllocated() / (1024.0 * 1024 * 1024)) << " GB" << std::endl;
    
    std::cout << "  PASSED: Federation statistics" << std::endl;
    return true;
}

bool Test_C_API() {
    std::cout << "\n[Test] C API..." << std::endl;
    
    // Test C API functions
    uint32_t nodeCount = RawRamXD_Federation_GetNodeCount();
    uint32_t gpuCount = RawRamXD_Federation_GetGPUCount();
    
    std::cout << "  C API Stats:" << std::endl;
    std::cout << "    Nodes: " << nodeCount << std::endl;
    std::cout << "    GPUs: " << gpuCount << std::endl;
    
    uint64_t totalVRAM = RawRamXD_Stats_GetTotalVRAM();
    std::cout << "    Total VRAM: " << std::fixed << std::setprecision(1)
              << (totalVRAM / (1024.0 * 1024 * 1024)) << " GB" << std::endl;
    
    std::cout << "  PASSED: C API" << std::endl;
    return true;
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char** argv) {
    std::cout << "=================================================================" << std::endl;
    std::cout << "  RawRamXD Phase 7B.2: Multi-GPU Fabric Federation Test" << std::endl;
    std::cout << "  Unified Heterogeneous Memory Scheduler" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (Test_Federation_Initialize()) passed++; else failed++;
    if (Test_GPU_Enumeration()) passed++; else failed++;
    if (Test_Peer_Access_Query()) passed++; else failed++;
    if (Test_Memory_Allocation()) passed++; else failed++;
    if (Test_Scheduler_Policies()) passed++; else failed++;
    if (Test_Federation_Stats()) passed++; else failed++;
    if (Test_C_API()) passed++; else failed++;
    
    // Cleanup
    FabricFederation::Instance().Shutdown();
    
    // Summary
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "  Test Summary: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    if (failed > 0) {
        std::cout << "\n  Some tests failed. Check output above." << std::endl;
        return 1;
    }
    
    std::cout << "\n  All tests PASSED!" << std::endl;
    std::cout << "  RawRamXD Multi-GPU Fabric Federation is operational." << std::endl;
    std::cout << std::endl;
    
    return 0;
}