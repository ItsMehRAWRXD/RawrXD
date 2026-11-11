// Phase D.5: Multi-Region Federation Integration
// Main Federation Runtime
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignGlobalLoadBalancer.hpp"
#include "SovereignCrossRegionReplication.hpp"
#include "SovereignGlobalConsensus.hpp"
#include "SovereignDisasterRecovery.hpp"
#include "SovereignLatencyOptimizer.hpp"
#include <memory>
#include <functional>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Federation Configuration
// ============================================================================

struct FederationConfig {
    // Identity
    std::string local_region_id;
    std::string federation_name;
    
    // Component configs
    GlobalLoadBalancer::Config load_balancer;
    CrossRegionReplication::Config replication;
    GlobalConsensusEngine::Config consensus;
    FailoverCoordinator::Config failover;
    BackupOrchestrator::Config backup;
    EdgeCacheManager::Config cache;
    SmartRouter::Config router;
    DataLocalityManager::Config locality;
    LatencyMonitorV2::Config latency;
    
    // Federation topology
    std::vector<RegionEndpoint> member_regions;
    std::vector<WitnessNode> witness_nodes;
    
    // Operational settings
    bool enable_auto_failover = true;
    bool enable_geo_routing = true;
    bool enable_crdt = true;
    int sync_interval_ms = 1000;
};

// ============================================================================
// Federation Runtime
// ============================================================================

class FederationRuntime {
public:
    explicit FederationRuntime(const FederationConfig& config);
    ~FederationRuntime();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Region management
    bool JoinFederation(const RegionEndpoint& region);
    bool LeaveFederation(const std::string& region_id);
    std::vector<RegionEndpoint> GetFederationMembers() const;
    
    // Global operations
    RoutingDecision RouteRequest(const std::string& client_ip);
    GlobalCommit ProposeGlobal(const GlobalProposal& proposal);
    bool ReplicateGlobally(const CRDTState& state);
    
    // Disaster recovery
    std::string InitiateFailover(const std::string& failed_region);
    bool TriggerBackup(const std::string& policy_id);
    std::string RestoreFromBackup(const std::string& backup_id,
                                    const std::string& target_region);
    
    // Cache operations
    bool CacheData(const std::string& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> GetCachedData(const std::string& key);
    bool InvalidateCache(const std::string& pattern);
    
    // Health and status
    struct FederationStatus {
        bool healthy = false;
        int healthy_regions = 0;
        int total_regions = 0;
        bool has_quorum = false;
        std::string leader_region;
        int64_t replication_lag_ms = 0;
        double avg_latency_ms = 0.0;
        std::vector<std::string> warnings;
    };
    FederationStatus GetStatus() const;
    
    // Statistics
    struct FederationStats {
        int64_t requests_routed = 0;
        int64_t global_commits = 0;
        int64_t cross_region_replications = 0;
        int64_t cache_hits = 0;
        int64_t cache_misses = 0;
        int64_t failovers = 0;
        double avg_routing_latency_ms = 0.0;
        double avg_consensus_time_ms = 0.0;
    };
    FederationStats GetStats() const;
    
    // Callbacks
    using FederationEventCallback = std::function<void(const std::string& event_type,
                                                          const std::map<std::string, std::string>& details)>;
    void OnFederationEvent(FederationEventCallback cb);
    
private:
    FederationConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    
    // Subsystems
    std::unique_ptr<GlobalLoadBalancer> load_balancer_;
    std::unique_ptr<CrossRegionReplication> replication_;
    std::unique_ptr<GlobalConsensusEngine> consensus_;
    std::unique_ptr<FailoverCoordinator> failover_;
    std::unique_ptr<BackupOrchestrator> backup_;
    std::unique_ptr<EdgeCacheManager> cache_;
    std::unique_ptr<SmartRouter> router_;
    std::unique_ptr<DataLocalityManager> locality_;
    std::unique_ptr<LatencyMonitorV2> latency_;
    std::unique_ptr<WitnessCoordinator> witness_;
    std::unique_ptr<SplitBrainDetector> split_brain_;
    
    FederationEventCallback on_event_;
    
    void SetupEventHandlers();
    void EmitEvent(const std::string& type, 
                   const std::map<std::string, std::string>& details);
};

// ============================================================================
// Federation Test Framework
// ============================================================================

class FederationTestFramework {
public:
    struct TestScenario {
        std::string name;
        std::string description;
        int region_count = 3;
        std::vector<std::string> fault_injections;
        std::function<bool(FederationRuntime*)> validation;
        int timeout_ms = 120000;
    };
    
    struct TestResult {
        std::string scenario_name;
        bool passed = false;
        int64_t duration_ms = 0;
        std::string error_message;
    };
    
    // Test scenarios
    static TestScenario MultiRegionConsensusTest();
    static TestScenario CrossRegionReplicationTest();
    static TestScenario FailoverTest();
    static TestScenario SplitBrainRecoveryTest();
    static TestScenario LatencyOptimizationTest();
    static TestScenario CacheCoherenceTest();
    static TestScenario WitnessFailureTest();
    static TestScenario BackupRestoreTest();
    
    // Execution
    TestResult RunScenario(const TestScenario& scenario);
    std::vector<TestResult> RunAllScenarios();
    
    // Utilities
    static std::vector<std::unique_ptr<FederationRuntime>> 
        CreateTestFederation(int region_count);
    static void PartitionRegions(std::vector<FederationRuntime*>& partitioned);
    static void HealPartition(std::vector<FederationRuntime*>& partitioned);
};

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<FederationRuntime> CreateFederationRuntime(
    const FederationConfig& config);

bool ValidateFederationConfig(const FederationConfig& config);

} // namespace Federation
} // namespace Sovereign
