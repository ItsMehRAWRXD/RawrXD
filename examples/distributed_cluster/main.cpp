/**
 * RawrXD Distributed Cluster Example
 * 
 * Demonstrates how to set up a distributed inference cluster
 * with automatic node discovery and load balancing.
 */

#include <rawrxd/RawrXD.hpp>
#include <rawrxd/distributed/ClusterManager.hpp>
#include <iostream>
#include <thread>
#include <chrono>

using namespace rawrxd;
using namespace std::chrono_literals;

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Distributed Cluster Example\n";
    std::cout << "==================================\n\n";

    // Parse command line
    std::string nodeId = (argc > 1) ? argv[1] : "node-1";
    std::string coordinator = (argc > 2) ? argv[2] : "";
    bool isCoordinator = coordinator.empty();

    // Initialize runtime
    auto runtime = Runtime::Create();
    
    RuntimeConfig config;
    config.nodeId = nodeId;
    config.enableDistributed = true;
    
    if (!runtime->Initialize(config)) {
        std::cerr << "Failed to initialize runtime\n";
        return 1;
    }

    std::cout << "✓ Runtime initialized (Node: " << nodeId << ")\n";

    // Get cluster manager
    auto clusterManager = runtime->GetClusterManager();
    if (!clusterManager) {
        std::cerr << "Distributed support not available\n";
        return 1;
    }

    // Configure cluster
    ClusterConfig clusterConfig;
    clusterConfig.nodeId = nodeId;
    clusterConfig.isCoordinator = isCoordinator;
    clusterConfig.coordinatorAddress = isCoordinator ? "" : coordinator;
    clusterConfig.discoveryPort = 7945;
    clusterConfig.heartbeatInterval = 5s;
    clusterConfig.failureTimeout = 30s;

    if (!clusterManager->Initialize(clusterConfig)) {
        std::cerr << "Failed to initialize cluster manager\n";
        return 1;
    }

    std::cout << "✓ Cluster manager initialized\n";
    std::cout << "  Role: " << (isCoordinator ? "Coordinator" : "Worker") << "\n";
    std::cout << "  Discovery Port: " << clusterConfig.discoveryPort << "\n\n";

    // Start cluster
    if (!clusterManager->Start()) {
        std::cerr << "Failed to start cluster\n";
        return 1;
    }

    std::cout << "✓ Cluster started\n\n";

    // Main loop - display cluster status
    std::cout << "Cluster Status (Ctrl+C to exit):\n";
    std::cout << "--------------------------------\n";

    bool running = true;
    while (running) {
        auto status = clusterManager->GetStatus();
        
        std::cout << "\rNodes: " << status.activeNodes << "/" << status.totalNodes
                  << " | Load: " << status.clusterLoad << "%"
                  << " | Tasks: " << status.pendingTasks << "/" << status.completedTasks
                  << "    " << std::flush;

        std::this_thread::sleep_for(1s);
    }

    // Shutdown
    std::cout << "\n\nShutting down...\n";
    clusterManager->Stop();
    runtime->Shutdown();
    
    std::cout << "✓ Shutdown complete\n";
    return 0;
}